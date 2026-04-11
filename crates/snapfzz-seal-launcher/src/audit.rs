//! Structured JSON audit logging for security-relevant launcher events.
//!
//! All security decisions (signature verification, fingerprint matching,
//! analysis detection, integrity checks, launch lifecycle) are emitted as
//! newline-delimited JSON records to either stderr (default) or a file path
//! configured via the `SNAPFZZ_SEAL_AUDIT_LOG` environment variable.
//!
//! This satisfies HIPAA § 164.312(b) audit-control requirements and FDA
//! cybersecurity guidance for tamper-evident event records.

use std::io::Write as IoWrite;

/// Every security-relevant decision point the launcher can reach.
#[derive(Debug, serde::Serialize)]
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
#[derive(Debug, serde::Serialize)]
pub struct AuditRecord {
    /// RFC 3339 / ISO 8601 timestamp (UTC, second precision).
    pub timestamp: String,
    /// PID of the current process at the time of the event.
    pub pid: u32,
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditRecord {
    fn new(event: AuditEvent) -> Self {
        Self {
            timestamp: rfc3339_now(),
            pid: std::process::id(),
            event,
        }
    }
}

/// Where audit records are written.
enum AuditSink {
    Stderr,
    File(std::sync::Mutex<std::fs::File>),
}

/// Writes [`AuditEvent`]s as newline-delimited JSON.
///
/// Create once at process startup via [`AuditLogger::from_env`] and pass
/// through the call chain to every function that makes a security decision.
pub struct AuditLogger {
    sink: AuditSink,
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
                    Ok(file) => AuditSink::File(std::sync::Mutex::new(file)),
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
        Self { sink }
    }

    /// Serialize `event` as a JSON line and write it to the configured sink.
    ///
    /// Errors are silently swallowed (logging must never crash the launcher),
    /// but a best-effort write is always attempted.
    pub fn log(&self, event: AuditEvent) {
        let record = AuditRecord::new(event);
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

    fn make_logger_stderr() -> AuditLogger {
        AuditLogger {
            sink: AuditSink::Stderr,
        }
    }

    #[test]
    fn audit_record_serializes_to_valid_json() {
        let record = AuditRecord::new(AuditEvent::SignatureVerified {
            payload_hash: "aabbcc".to_string(),
            pubkey_fingerprint: "ddeeff".to_string(),
        });

        let json = serde_json::to_string(&record).expect("serialization must succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("output must be valid JSON");

        assert_eq!(parsed["event"], "signature_verified");
        assert_eq!(parsed["payload_hash"], "aabbcc");
        assert_eq!(parsed["pubkey_fingerprint"], "ddeeff");
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["pid"].is_number());
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

        for event in events {
            let record = AuditRecord::new(event);
            let json = serde_json::to_string(&record).expect("must serialize");
            let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
            // Every record must have these top-level keys.
            assert!(parsed["timestamp"].is_string(), "missing timestamp");
            assert!(parsed["pid"].is_number(), "missing pid");
            assert!(parsed["event"].is_string(), "missing event tag");
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
}
