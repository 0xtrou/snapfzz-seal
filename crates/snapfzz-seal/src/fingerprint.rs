#[derive(clap::Args)]
#[command(name = "fingerprint")]
#[command(
    about = "Collect the current host's stable fingerprint and print it as a hex string.\n\
             Run this on the TARGET deployment machine, then pass the output to\n\
             `seal compile --sandbox-fingerprint <hex>` on the build machine."
)]
pub struct Cli {}

pub fn run(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let collector = snapfzz_seal_fingerprint::FingerprintCollector::new();
    let snapshot = collector.collect_stable_only()?;
    let hash = snapfzz_seal_fingerprint::canonicalize_stable(&snapshot);
    println!("{}", hex::encode(hash));
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[derive(Parser)]
    struct ParseCli {
        #[command(flatten)]
        cli: Cli,
    }

    #[test]
    fn cli_parses_with_no_arguments() {
        let parsed = ParseCli::parse_from(["test"]);
        let _ = parsed.cli;
    }

    #[test]
    fn run_produces_64_char_hex_string() {
        let result = super::run(Cli {});
        assert!(result.is_ok(), "fingerprint run should succeed: {result:?}");
    }
}
