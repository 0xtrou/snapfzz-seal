use std::{fs, path::PathBuf};

#[derive(clap::Args)]
#[command(name = "keygen", about = "Generate builder signing keys")]
pub struct Cli {
    #[arg(long, default_value = "~/.agent-seal/keys")]
    pub keys_dir: PathBuf,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let dir = expand(cli.keys_dir);
    let (secret, public) = agent_seal_core::signing::keygen();
    fs::create_dir_all(&dir)?;
    let secret_path = dir.join("builder_secret.key");
    let public_path = dir.join("builder_public.key");
    fs::write(&secret_path, hex::encode(secret))?;
    fs::write(&public_path, hex::encode(public))?;
    println!("secret: {}", secret_path.display());
    println!("public: {}", public_path.display());
    println!("builder id: {}", &hex::encode(public)[..16]);
    Ok(())
}

fn expand(dir: PathBuf) -> PathBuf {
    let s = dir.to_string_lossy();
    if (s == "~" || s.starts_with("~/")) && std::env::var_os("HOME").is_some() {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        return if s == "~" { home } else { home.join(&s[2..]) };
    }
    dir
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
    fn cli_defaults_keys_dir() {
        assert_eq!(
            ParseCli::parse_from(["t"]).cli.keys_dir,
            PathBuf::from("~/.agent-seal/keys")
        );
    }

    #[test]
    fn run_writes_hex_key_files() {
        let dir = tmp("keygen");
        let _ = fs::remove_dir_all(&dir);
        run(Cli {
            keys_dir: dir.clone(),
        })
        .expect("keygen should succeed");
        assert_eq!(
            fs::read_to_string(dir.join("builder_secret.key"))
                .unwrap()
                .trim()
                .len(),
            64
        );
        assert_eq!(
            fs::read_to_string(dir.join("builder_public.key"))
                .unwrap()
                .trim()
                .len(),
            64
        );
        let _ = fs::remove_dir_all(dir);
    }
}
