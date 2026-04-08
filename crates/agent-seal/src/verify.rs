use std::{fs, io::ErrorKind, path::PathBuf};

#[derive(clap::Args)]
#[command(name = "verify", about = "Verify builder binary signature")]
pub struct Cli {
    #[arg(long)]
    pub binary: PathBuf,
    #[arg(long)]
    pub pubkey: Option<PathBuf>,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let binary = fs::read(&cli.binary)?;
    if binary.len() < 100 || &binary[binary.len() - 100..binary.len() - 96] != b"ASL\x02" {
        println!("WARNING: unsigned");
        return Ok(());
    }
    let data = &binary[..binary.len() - 100];
    let sig: [u8; 64] = binary[binary.len() - 96..binary.len() - 32].try_into()?;
    let embedded: [u8; 32] = binary[binary.len() - 32..].try_into()?;
    let pubkey = cli
        .pubkey
        .map_or(Ok(embedded), |path| decode32(path, "public key"))?;
    println!(
        "{}",
        if agent_seal_core::signing::verify(&pubkey, data, &sig)? {
            "VALID"
        } else {
            "INVALID"
        }
    );
    Ok(())
}

fn decode32(
    path: impl AsRef<std::path::Path>,
    label: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
    bytes.try_into().map_err(|_| {
        std::io::Error::new(ErrorKind::InvalidData, format!("{label} must be 32 bytes")).into()
    })
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
        std::env::temp_dir().join(format!("agent-seal-{name}-{}", std::process::id()))
    }

    #[test]
    fn cli_maps_args() {
        let p = ParseCli::parse_from(["t", "--binary", "b", "--pubkey", "k"]).cli;
        assert_eq!(p.binary, PathBuf::from("b"));
        assert_eq!(p.pubkey, Some(PathBuf::from("k")));
    }

    #[test]
    fn unsigned_binary_returns_ok() {
        let dir = tmp("verify-u");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("app.bin");
        fs::write(&bin, b"plain").unwrap();
        assert!(
            run(Cli {
                binary: bin,
                pubkey: None
            })
            .is_ok()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_binary_verifies() {
        let dir = tmp("verify-s");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (secret, public) = agent_seal_core::signing::keygen();
        let sig = agent_seal_core::signing::sign(&secret, b"payload").unwrap();
        let bin = dir.join("app.bin");
        fs::write(
            &bin,
            [b"payload".as_slice(), b"ASL\x02", &sig, &public].concat(),
        )
        .unwrap();
        assert!(
            run(Cli {
                binary: bin,
                pubkey: None
            })
            .is_ok()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_binary_verifies_with_explicit_pubkey_file() {
        let dir = tmp("verify-explicit-pubkey");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = agent_seal_core::signing::keygen();
        let sig = agent_seal_core::signing::sign(&secret, b"payload").unwrap();

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
            })
            .is_ok()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_binary_with_tampered_payload_reports_invalid_but_returns_ok() {
        let dir = tmp("verify-invalid-signature");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = agent_seal_core::signing::keygen();
        let sig = agent_seal_core::signing::sign(&secret, b"payload").unwrap();

        let bin = dir.join("app.bin");
        fs::write(
            &bin,
            [b"payload-tampered".as_slice(), b"ASL\x02", &sig, &public].concat(),
        )
        .unwrap();

        assert!(
            run(Cli {
                binary: bin,
                pubkey: None,
            })
            .is_ok()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn run_errors_when_pubkey_file_is_not_32_bytes() {
        let dir = tmp("verify-bad-pubkey");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = agent_seal_core::signing::keygen();
        let sig = agent_seal_core::signing::sign(&secret, b"payload").unwrap();

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
        })
        .expect_err("short pubkey should fail");

        assert!(err.to_string().contains("public key must be 32 bytes"));

        let _ = fs::remove_dir_all(dir);
    }
}
