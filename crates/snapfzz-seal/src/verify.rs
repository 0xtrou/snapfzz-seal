use std::{fmt, fs, path::PathBuf};

/// Errors produced by `run()`.
///
/// The variant determines the process exit code chosen by `main`:
/// - `Operational`  → exit 1  (I/O failure, bad args, file not found, malformed key)
/// - `SecurityEvent`→ exit 2  (signature invalid — potential tampering)
/// - `Unsigned`     → exit 3  (no signature present — policy violation)
#[derive(Debug)]
pub enum VerifyError {
    Operational(String),
    SecurityEvent(String),
    Unsigned(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Operational(msg) => write!(f, "operational error: {msg}"),
            VerifyError::SecurityEvent(msg) => write!(f, "SECURITY EVENT: {msg}"),
            VerifyError::Unsigned(msg) => write!(f, "policy violation: {msg}"),
        }
    }
}

impl std::error::Error for VerifyError {}

// Allow mapping Box<dyn Error> from low-level operations into Operational.
impl From<Box<dyn std::error::Error>> for VerifyError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        VerifyError::Operational(e.to_string())
    }
}

impl From<std::io::Error> for VerifyError {
    fn from(e: std::io::Error) -> Self {
        VerifyError::Operational(e.to_string())
    }
}

impl From<std::array::TryFromSliceError> for VerifyError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        VerifyError::Operational(e.to_string())
    }
}

impl From<hex::FromHexError> for VerifyError {
    fn from(e: hex::FromHexError) -> Self {
        VerifyError::Operational(e.to_string())
    }
}

#[derive(clap::Args)]
#[command(name = "verify", about = "Verify builder binary signature")]
pub struct Cli {
    #[arg(long)]
    pub binary: PathBuf,
    #[arg(long)]
    pub pubkey: Option<PathBuf>,
    /// Allow unsigned binaries (e.g. for local dev builds).
    /// Prints a loud warning to stderr and exits with code 3 (policy violation).
    /// NOT available in release builds — gate with feature "allow-unsigned".
    #[cfg(feature = "allow-unsigned")]
    #[arg(long)]
    pub allow_unsigned: bool,
}

pub fn run(cli: Cli) -> Result<(), VerifyError> {
    let binary = fs::read(&cli.binary)?;
    if binary.len() < 100 || &binary[binary.len() - 100..binary.len() - 96] != b"ASL\x02" {
        #[cfg(feature = "allow-unsigned")]
        if cli.allow_unsigned {
            eprintln!(
                "WARNING: unsigned binary — --allow-unsigned passed, exiting 3 (policy violation)"
            );
            return Err(VerifyError::Unsigned(
                "unsigned binary: no ASL\\x02 signature marker found (--allow-unsigned acknowledged)"
                    .into(),
            ));
        }
        return Err(VerifyError::Unsigned(
            "unsigned binary: no ASL\\x02 signature marker found".into(),
        ));
    }
    let data = &binary[..binary.len() - 100];
    let sig: [u8; 64] = binary[binary.len() - 96..binary.len() - 32].try_into()?;
    let embedded: [u8; 32] = binary[binary.len() - 32..].try_into()?;
    let using_embedded = cli.pubkey.is_none();
    let pubkey = cli
        .pubkey
        .map_or(Ok(embedded), |path| decode32(path, "public key"))?;

    let valid = snapfzz_seal_core::signing::verify(&pubkey, data, &sig)
        .map_err(|e| VerifyError::Operational(e.to_string()))?;
    if valid {
        if using_embedded {
            println!("VALID (TOFU: using embedded key — use --pubkey for pinned builder identity)");
        } else {
            println!("VALID (pinned to explicit public key)");
        }
        Ok(())
    } else {
        Err(VerifyError::SecurityEvent(
            "invalid signature: binary may have been tampered with".into(),
        ))
    }
}

fn decode32(path: impl AsRef<std::path::Path>, label: &str) -> Result<[u8; 32], VerifyError> {
    let raw = fs::read_to_string(path).map_err(|e| VerifyError::Operational(e.to_string()))?;
    let bytes = hex::decode(raw.trim())?;
    bytes
        .try_into()
        .map_err(|_| VerifyError::Operational(format!("{label} must be 32 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct ParseCli {
        #[command(flatten)]
        cli: Cli,
    }
    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("snapfzz-seal-{name}-{}", std::process::id()))
    }

    #[test]
    fn cli_maps_args() {
        let p = ParseCli::parse_from(["t", "--binary", "b", "--pubkey", "k"]).cli;
        assert_eq!(p.binary, PathBuf::from("b"));
        assert_eq!(p.pubkey, Some(PathBuf::from("k")));
    }

    /// Unsigned binary → `Unsigned` variant (exit 3).
    #[test]
    fn unsigned_binary_returns_unsigned_error() {
        let dir = tmp("verify-u");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("app.bin");
        fs::write(&bin, b"plain").unwrap();
        let err = run(Cli {
            binary: bin,
            pubkey: None,
            #[cfg(feature = "allow-unsigned")]
            allow_unsigned: false,
        })
        .expect_err("unsigned binary should fail");
        assert!(
            matches!(err, VerifyError::Unsigned(_)),
            "expected Unsigned variant, got: {err}"
        );
        assert!(
            err.to_string().contains("unsigned"),
            "error should mention 'unsigned', got: {err}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// Tampered binary → `SecurityEvent` variant (exit 2).
    #[test]
    fn signed_binary_with_tampered_payload_returns_security_event() {
        let dir = tmp("verify-invalid-signature");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = snapfzz_seal_core::signing::keygen();
        let sig = snapfzz_seal_core::signing::sign(&secret, b"payload").unwrap();

        let bin = dir.join("app.bin");
        fs::write(
            &bin,
            [b"payload-tampered".as_slice(), b"ASL\x02", &sig, &public].concat(),
        )
        .unwrap();

        let err = run(Cli {
            binary: bin,
            pubkey: None,
            #[cfg(feature = "allow-unsigned")]
            allow_unsigned: false,
        })
        .expect_err("tampered binary should fail");
        assert!(
            matches!(err, VerifyError::SecurityEvent(_)),
            "expected SecurityEvent variant, got: {err}"
        );
        assert!(
            err.to_string().contains("invalid signature"),
            "error should mention 'invalid signature', got: {err}"
        );

        let _ = fs::remove_dir_all(dir);
    }

    /// Valid signed binary → `Ok(())` (exit 0).
    #[test]
    fn signed_binary_verifies() {
        let dir = tmp("verify-s");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (secret, public) = snapfzz_seal_core::signing::keygen();
        let sig = snapfzz_seal_core::signing::sign(&secret, b"payload").unwrap();
        let bin = dir.join("app.bin");
        fs::write(
            &bin,
            [b"payload".as_slice(), b"ASL\x02", &sig, &public].concat(),
        )
        .unwrap();
        assert!(
            run(Cli {
                binary: bin,
                pubkey: None,
                #[cfg(feature = "allow-unsigned")]
                allow_unsigned: false,
            })
            .is_ok()
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// Valid signed binary with explicit pinned pubkey file → `Ok(())` (exit 0).
    #[test]
    fn signed_binary_verifies_with_explicit_pubkey_file() {
        let dir = tmp("verify-explicit-pubkey");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = snapfzz_seal_core::signing::keygen();
        let sig = snapfzz_seal_core::signing::sign(&secret, b"payload").unwrap();

        let bin = dir.join("app.bin");
        fs::write(
            &bin,
            [b"payload".as_slice(), b"ASL\x02", &sig, &public].concat(),
        )
        .unwrap();

        let pubkey_path = dir.join("builder_public.key");
        fs::write(&pubkey_path, hex::encode(public)).unwrap();

        assert!(
            run(Cli {
                binary: bin,
                pubkey: Some(pubkey_path),
                #[cfg(feature = "allow-unsigned")]
                allow_unsigned: false,
            })
            .is_ok()
        );

        let _ = fs::remove_dir_all(dir);
    }

    /// Malformed/short pubkey file → `Operational` variant (exit 1).
    #[test]
    fn run_errors_when_pubkey_file_is_not_32_bytes() {
        let dir = tmp("verify-bad-pubkey");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = snapfzz_seal_core::signing::keygen();
        let sig = snapfzz_seal_core::signing::sign(&secret, b"payload").unwrap();

        let bin = dir.join("app.bin");
        fs::write(
            &bin,
            [b"payload".as_slice(), b"ASL\x02", &sig, &public].concat(),
        )
        .unwrap();

        let bad_pubkey = dir.join("bad.pub");
        fs::write(&bad_pubkey, "abcd").unwrap();

        let err = run(Cli {
            binary: bin,
            pubkey: Some(bad_pubkey),
            #[cfg(feature = "allow-unsigned")]
            allow_unsigned: false,
        })
        .expect_err("short pubkey should fail");

        assert!(
            matches!(err, VerifyError::Operational(_)),
            "expected Operational variant, got: {err}"
        );
        assert!(err.to_string().contains("public key must be 32 bytes"));

        let _ = fs::remove_dir_all(dir);
    }
}
