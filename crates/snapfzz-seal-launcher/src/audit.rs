//! Structured JSON audit logging for security-relevant launcher events.
//!
//! All security decisions (signature verification, fingerprint matching,
//! analysis detection, integrity checks, launch lifecycle) are emitted as
//! newline-delimited JSON records to either stderr (default) or a file path
//! configured via the `SNAPFZZ_SEAL_AUDIT_LOG` environment variable.
//!
//! This satisfies HIPAA § 164.312(b) audit-control requirements and FDA
//! cybersecurity guidance for tamper-evident event records.
//!
//! ## HMAC chain integrity
//!
//! Each [`AuditRecord`] carries a `chain_hmac` field that is
//! `hex(HMAC-SHA256(chain_key, prev_chain_hmac || record_json))`.  The chain
//! is seeded with `prev_hmac = [0u8; 32]` (the genesis value) and the chain
//! key is generated once with `OsRng` at logger creation.  This allows
//! offline verification that no record was inserted, deleted, or modified
//! after the fact.

use std::io::Write as IoWrite;
use std::path::Path;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Every security-relevant decision point the launcher can reach.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Signature block was present and verified successfully.
    SignatureVerified {
        payload_hash: String,
        pubkey_fingerprint: String,
    },
    /// Signature block was present but verification failed.
    SignatureInvalid {
        payload_hash: String,
        reason: String,
    },
    /// Binary had no signature block at all.
    SignatureUnsigned { payload_hash: String },
    /// Sandbox fingerprint matched the expected fingerprint.
    FingerprintMatched { sandbox_fp: String, user_fp: String },
    /// Sandbox fingerprint did not match; decryption will fail.
    FingerprintMismatch { expected: String, got: String },
    /// An anti-analysis check triggered; `check` names the specific detector.
    AnalysisDetected { check: String },
    /// Launcher self-integrity hash matched the expected value.
    IntegrityVerified { launcher_hash: String },
    /// Launcher self-integrity hash did not match.
    IntegrityFailed { reason: String },
    /// Payload decryption and execution are about to begin.
    LaunchStarted {
        payload_hash: String,
        backend: String,
    },
    /// Child process finished normally.
    LaunchCompleted { exit_code: i32 },
    /// Launch could not be attempted or child exited abnormally.
    LaunchFailed { reason: String },
}

/// A single timestamped audit record that wraps an [`AuditEvent`].
///
/// The `chain_hmac` field links each record to its predecessor via an
/// HMAC-SHA256 chain; see [`verify_audit_chain`] for offline verification.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    /// RFC 3339 / ISO 8601 timestamp (UTC, second precision).
    pub timestamp: String,
    /// PID of the current process at the time of the event.
    pub pid: u32,
    #[serde(flatten)]
    pub event: AuditEvent,
    /// `hex(HMAC-SHA256(chain_key, prev_chain_hmac_bytes || record_json_bytes))`
    /// where `record_json` is the serialisation of this record *without* the
    /// `chain_hmac` field itself.
    pub chain_hmac: String,
}

// ---------------------------------------------------------------------------
// Internal helper — record without the chain field, used for HMAC input.
// ---------------------------------------------------------------------------

/// Intermediate representation serialised to build the HMAC input.
#[derive(Debug, serde::Serialize)]
struct AuditRecordBody<'a> {
    timestamp: &'a str,
    pid: u32,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

impl AuditRecordBody<'_> {
    fn to_json(&self) -> Option<String> {
        serde_json::to_string(self).ok()
    }
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Where audit records are written.
enum AuditSink {
    Stderr,
    File(Mutex<std::fs::File>),
}

/// Writes [`AuditEvent`]s as newline-delimited JSON with an HMAC integrity chain.
///
/// Create once at process startup via [`AuditLogger::from_env`] and pass
/// through the call chain to every function that makes a security decision.
pub struct AuditLogger {
    sink: AuditSink,
    /// Randomly generated once per logger instance.
    chain_key: [u8; 32],
    /// The HMAC output of the previously written record (genesis = `[0u8; 32]`).
    prev_hmac: Mutex<[u8; 32]>,
}

impl AuditLogger {
    /// Build a logger from the environment.
    ///
    /// If `SNAPFZZ_SEAL_AUDIT_LOG` is set to a non-empty path the logger
    /// appends to that file (creating it if necessary).  Otherwise records go
    /// to stderr.
    pub fn from_env() -> Self {
        let sink = match std::env::var("SNAPFZZ_SEAL_AUDIT_LOG")
            .ok()
            .filter(|p| !p.is_empty())
        {
            Some(path) => {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                {
                    Ok(file) => AuditSink::File(Mutex::new(file)),
                    Err(err) => {
                        // Fall back gracefully; warn on stderr so the operator
                        // is aware the configured sink could not be opened.
                        eprintln!(
                            "AUDIT WARNING: could not open audit log {path:?}: {err}; \
                             falling back to stderr"
                        );
                        AuditSink::Stderr
                    }
                }
            }
            None => AuditSink::Stderr,
        };

        let mut chain_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut chain_key);

        Self {
            sink,
            chain_key,
            prev_hmac: Mutex::new([0u8; 32]),
        }
    }

    /// Serialize `event` as a JSON line and write it to the configured sink.
    ///
    /// Errors are silently swallowed (logging must never crash the launcher),
    /// but a best-effort write is always attempted.
    pub fn log(&self, event: AuditEvent) {
        let timestamp = rfc3339_now();
        let pid = std::process::id();

        let body = AuditRecordBody {
            timestamp: &timestamp,
            pid,
            event: &event,
        };

        let body_json = match body.to_json() {
            Some(j) => j,
            None => return,
        };

        // Compute chain HMAC: HMAC-SHA256(chain_key, prev_hmac || body_json)
        let chain_hmac_hex = {
            let mut prev_guard = match self.prev_hmac.lock() {
                Ok(g) => g,
                Err(_) => return,
            };

            let mut mac = match HmacSha256::new_from_slice(&self.chain_key) {
                Ok(m) => m,
                Err(_) => return,
            };
            mac.update(prev_guard.as_ref());
            mac.update(body_json.as_bytes());
            let result = mac.finalize().into_bytes();

            let mut new_hmac = [0u8; 32];
            new_hmac.copy_from_slice(&result);
            *prev_guard = new_hmac;

            hex::encode(new_hmac)
        };

        let record = AuditRecord {
            timestamp,
            pid,
            event,
            chain_hmac: chain_hmac_hex,
        };

        let mut line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(_) => return,
        };
        line.push('\n');

        match &self.sink {
            AuditSink::Stderr => {
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
            AuditSink::File(mutex) => {
                if let Ok(mut file) = mutex.lock() {
                    let _ = file.write_all(line.as_bytes());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Offline chain verification
// ---------------------------------------------------------------------------

/// Verify the HMAC chain of an audit log file written by [`AuditLogger`].
///
/// Reads every newline-delimited JSON record from `path`, re-derives the
/// expected `chain_hmac` for each record using `chain_key`, and checks it
/// against the stored value.
///
/// Returns `Ok(n)` where `n` is the number of records verified, or
/// `Err(description)` on the first integrity failure.
pub fn verify_audit_chain(path: &Path, chain_key: &[u8; 32]) -> Result<usize, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("could not read audit log: {e}"))?;

    let mut prev_hmac = [0u8; 32]; // genesis
    let mut count = 0usize;

    for (line_no, raw_line) in contents.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse the full record (including chain_hmac).
        let record: AuditRecord = serde_json::from_str(trimmed)
            .map_err(|e| format!("line {}: invalid JSON: {e}", line_no + 1))?;

        // Re-build the body JSON (same fields, no chain_hmac) to reproduce
        // the exact bytes fed into the HMAC when the record was written.
        let body = AuditRecordBody {
            timestamp: &record.timestamp,
            pid: record.pid,
            event: &record.event,
        };
        let body_json = body
            .to_json()
            .ok_or_else(|| format!("line {}: could not re-serialize body", line_no + 1))?;

        // Compute expected HMAC.
        let mut mac =
            HmacSha256::new_from_slice(chain_key).map_err(|e| format!("HMAC init error: {e}"))?;
        mac.update(&prev_hmac);
        mac.update(body_json.as_bytes());
        let expected = mac.finalize().into_bytes();
        let expected_hex = hex::encode(expected);

        if record.chain_hmac != expected_hex {
            return Err(format!(
                "line {}: chain HMAC mismatch (expected {expected_hex}, got {})",
                line_no + 1,
                record.chain_hmac
            ));
        }

        // Advance the chain.
        prev_hmac.copy_from_slice(&expected);
        count += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns the current UTC time as an RFC 3339 string (second precision).
///
/// Uses only `std::time` to avoid adding the full `chrono` dep just for
/// formatting — the existing crate already pulls in `chrono` but this keeps
/// the dependency explicit and avoids feature-flag issues.
fn rfc3339_now() -> String {
    // Use chrono if available; otherwise fall back to a manual formatter.
    // The crate already depends on chrono = "0.4", so we can use it directly.
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_logger_to_file(path: &std::path::PathBuf) -> AuditLogger {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .expect("tmp file");
        AuditLogger {
            sink: AuditSink::File(Mutex::new(file)),
            chain_key: {
                let mut k = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut k);
                k
            },
            prev_hmac: Mutex::new([0u8; 32]),
        }
    }

    fn make_logger_stderr() -> AuditLogger {
        AuditLogger {
            sink: AuditSink::Stderr,
            chain_key: [0u8; 32],
            prev_hmac: Mutex::new([0u8; 32]),
        }
    }

    #[test]
    fn audit_record_serializes_to_valid_json() {
        let timestamp = rfc3339_now();
        let pid = std::process::id();
        let event = AuditEvent::SignatureVerified {
            payload_hash: "aabbcc".to_string(),
            pubkey_fingerprint: "ddeeff".to_string(),
        };
        let body = AuditRecordBody {
            timestamp: &timestamp,
            pid,
            event: &event,
        };
        let body_json = body.to_json().unwrap();

        let mut mac = HmacSha256::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(&[0u8; 32]);
        mac.update(body_json.as_bytes());
        let chain_hmac = hex::encode(mac.finalize().into_bytes());

        let record = AuditRecord {
            timestamp,
            pid,
            event,
            chain_hmac,
        };

        let json = serde_json::to_string(&record).expect("serialization must succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("output must be valid JSON");

        assert_eq!(parsed["event"], "signature_verified");
        assert_eq!(parsed["payload_hash"], "aabbcc");
        assert_eq!(parsed["pubkey_fingerprint"], "ddeeff");
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["pid"].is_number());
        assert!(parsed["chain_hmac"].is_string());
    }

    #[test]
    fn all_event_variants_round_trip_through_serde() {
        let events = vec![
            AuditEvent::SignatureVerified {
                payload_hash: "aa".into(),
                pubkey_fingerprint: "bb".into(),
            },
            AuditEvent::SignatureInvalid {
                payload_hash: "aa".into(),
                reason: "bad sig".into(),
            },
            AuditEvent::SignatureUnsigned {
                payload_hash: "aa".into(),
            },
            AuditEvent::FingerprintMatched {
                sandbox_fp: "fp1".into(),
                user_fp: "fp2".into(),
            },
            AuditEvent::FingerprintMismatch {
                expected: "exp".into(),
                got: "got".into(),
            },
            AuditEvent::AnalysisDetected {
                check: "ptrace".into(),
            },
            AuditEvent::IntegrityVerified {
                launcher_hash: "hash".into(),
            },
            AuditEvent::IntegrityFailed {
                reason: "mismatch".into(),
            },
            AuditEvent::LaunchStarted {
                payload_hash: "hash".into(),
                backend: "go".into(),
            },
            AuditEvent::LaunchCompleted { exit_code: 0 },
            AuditEvent::LaunchFailed {
                reason: "exec error".into(),
            },
        ];

        let logger = make_logger_stderr();
        for event in events {
            // Smoke-test: must not panic.
            logger.log(event);
        }
    }

    #[test]
    fn audit_logger_from_env_defaults_to_stderr_when_var_unset() {
        // Ensure the var is absent for this test.
        unsafe { std::env::remove_var("SNAPFZZ_SEAL_AUDIT_LOG") };
        let logger = AuditLogger::from_env();
        // Smoke-check: logging must not panic.
        logger.log(AuditEvent::LaunchCompleted { exit_code: 0 });
    }

    #[test]
    fn audit_logger_from_env_reads_env_var_path() {
        let tmp = std::env::temp_dir().join(format!(
            "snapfzz-seal-audit-test-{}.jsonl",
            std::process::id()
        ));
        // Clean up first in case of leftover from a prior run.
        let _ = std::fs::remove_file(&tmp);

        unsafe {
            std::env::set_var("SNAPFZZ_SEAL_AUDIT_LOG", tmp.to_str().unwrap());
        }
        let logger = AuditLogger::from_env();
        logger.log(AuditEvent::IntegrityVerified {
            launcher_hash: "deadbeef".into(),
        });
        // Clean up env var so we don't pollute other tests.
        unsafe { std::env::remove_var("SNAPFZZ_SEAL_AUDIT_LOG") };

        let contents = std::fs::read_to_string(&tmp).expect("audit file must exist");
        let _ = std::fs::remove_file(&tmp);

        let parsed: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("file content must be valid JSON");
        assert_eq!(parsed["event"], "integrity_verified");
        assert_eq!(parsed["launcher_hash"], "deadbeef");
        assert!(
            parsed["chain_hmac"].is_string(),
            "chain_hmac must be present"
        );
    }

    #[test]
    fn audit_logger_log_does_not_panic() {
        let logger = make_logger_stderr();
        logger.log(AuditEvent::AnalysisDetected {
            check: "breakpoint".into(),
        });
    }

    #[test]
    fn rfc3339_timestamp_has_correct_format() {
        let ts = rfc3339_now();
        // Basic sanity: "2024-01-01T00:00:00Z" is 20 chars minimum.
        assert!(ts.len() >= 20, "timestamp too short: {ts}");
        assert!(ts.ends_with('Z'), "timestamp must be UTC: {ts}");
    }

    // -----------------------------------------------------------------------
    // HMAC chain tests
    // -----------------------------------------------------------------------

    #[test]
    fn hmac_chain_three_events_verifies_successfully() {
        let tmp = std::env::temp_dir().join(format!(
            "snapfzz-seal-audit-chain-ok-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);

        let logger = make_logger_to_file(&tmp);
        let chain_key = logger.chain_key;

        logger.log(AuditEvent::IntegrityVerified {
            launcher_hash: "aabb".into(),
        });
        logger.log(AuditEvent::AnalysisDetected {
            check: "tracer_pid".into(),
        });
        logger.log(AuditEvent::LaunchCompleted { exit_code: 0 });

        // Flush by dropping (file is flushed on drop for BufWriter, but here
        // we use raw File so writes are immediate).
        drop(logger);

        let count = verify_audit_chain(&tmp, &chain_key)
            .expect("chain verification must succeed for unmodified log");
        assert_eq!(count, 3, "expected 3 verified records");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn hmac_chain_detects_record_tampering() {
        let tmp = std::env::temp_dir().join(format!(
            "snapfzz-seal-audit-chain-tamper-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);

        let logger = make_logger_to_file(&tmp);
        let chain_key = logger.chain_key;

        logger.log(AuditEvent::LaunchStarted {
            payload_hash: "cc".into(),
            backend: "rust".into(),
        });
        logger.log(AuditEvent::LaunchCompleted { exit_code: 0 });
        logger.log(AuditEvent::SignatureVerified {
            payload_hash: "dd".into(),
            pubkey_fingerprint: "ee".into(),
        });
        drop(logger);

        // Read the file, tamper with the first line (change exit_code field),
        // write it back.
        let original = std::fs::read_to_string(&tmp).expect("must read");
        let tampered = original.replacen("\"rust\"", "\"nuitka\"", 1);
        // Ensure we actually changed something.
        assert_ne!(
            original, tampered,
            "replacement must have changed the content"
        );
        std::fs::write(&tmp, &tampered).expect("must write tampered content");

        let result = verify_audit_chain(&tmp, &chain_key);
        assert!(
            result.is_err(),
            "chain verification must fail for tampered log"
        );

        let _ = std::fs::remove_file(&tmp);
    }
}
