use std::{fs, io::ErrorKind, path::PathBuf};

#[derive(clap::Args)]
#[command(name = "sign", about = "Sign a builder binary")]
pub struct Cli {
    #[arg(long)]
    pub key: PathBuf,
    #[arg(long)]
    pub binary: PathBuf,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let secret = decode32(&cli.key, "secret key")?;
    let parent = cli.key.parent().ok_or(std::io::Error::new(
        ErrorKind::InvalidInput,
        "key has no parent",
    ))?;
    let public = decode32(parent.join("builder_public.key"), "public key")?;
    let mut binary = fs::read(&cli.binary)?;
    let sig = agent_seal_core::signing::sign(&secret, &binary)?;
    binary.extend_from_slice(b"ASL\x02");
    binary.extend_from_slice(&sig);
    binary.extend_from_slice(&public);
    fs::write(&cli.binary, binary)?;
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
        let p = ParseCli::parse_from(["t", "--key", "k", "--binary", "b"]).cli;
        assert_eq!(p.key, PathBuf::from("k"));
        assert_eq!(p.binary, PathBuf::from("b"));
    }

    #[test]
    fn run_appends_valid_block() {
        let dir = tmp("sign");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (secret, public) = agent_seal_core::signing::keygen();
        fs::write(dir.join("builder_secret.key"), hex::encode(secret)).unwrap();
        fs::write(dir.join("builder_public.key"), hex::encode(public)).unwrap();
        let bin = dir.join("app.bin");
        let payload = b"payload".to_vec();
        fs::write(&bin, &payload).unwrap();
        run(Cli {
            key: dir.join("builder_secret.key"),
            binary: bin.clone(),
        })
        .unwrap();
        let out = fs::read(bin).unwrap();
        assert_eq!(&out[out.len() - 100..out.len() - 96], b"ASL\x02");
        let sig: [u8; 64] = out[out.len() - 96..out.len() - 32].try_into().unwrap();
        assert!(agent_seal_core::signing::verify(&public, &payload, &sig).unwrap());
        let _ = fs::remove_dir_all(dir);
    }
}
