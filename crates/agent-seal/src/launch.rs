#[derive(clap::Args)]
#[command(name = "launch")]
#[command(about = "Launch a sealed agent")]
pub struct Cli {
    #[arg(long)]
    pub payload: Option<String>,
    #[arg(long, value_enum, default_value_t = FingerprintMode::Stable)]
    pub fingerprint_mode: FingerprintMode,
    #[arg(long)]
    pub user_fingerprint: Option<String>,
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum FingerprintMode {
    Stable,
    Session,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let launcher_cli = agent_seal_launcher::Cli {
        payload: cli.payload,
        fingerprint_mode: match cli.fingerprint_mode {
            FingerprintMode::Stable => agent_seal_launcher::FingerprintMode::Stable,
            FingerprintMode::Session => agent_seal_launcher::FingerprintMode::Session,
        },
        user_fingerprint: cli.user_fingerprint,
        verbose: cli.verbose,
    };
    agent_seal_launcher::run(launcher_cli).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{Cli, FingerprintMode, run};
    use clap::Parser;

    #[derive(Parser)]
    struct ParseCli {
        #[command(flatten)]
        cli: Cli,
    }

    fn launch_cli(mode: FingerprintMode) -> Cli {
        Cli {
            payload: Some("/definitely/missing/payload.asl".to_string()),
            fingerprint_mode: mode,
            user_fingerprint: None,
            verbose: false,
        }
    }

    #[test]
    fn cli_defaults_fingerprint_mode_to_stable() {
        let parsed = ParseCli::parse_from(["test", "--payload", "./payload.asl"]);

        assert_eq!(parsed.cli.fingerprint_mode, FingerprintMode::Stable);
        assert_eq!(parsed.cli.payload.as_deref(), Some("./payload.asl"));
        assert_eq!(parsed.cli.user_fingerprint, None);
        assert!(!parsed.cli.verbose);
    }

    #[test]
    fn cli_maps_all_launch_args() {
        let parsed = ParseCli::parse_from([
            "test",
            "--payload",
            "./payload.asl",
            "--fingerprint-mode",
            "session",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "--verbose",
        ]);

        assert_eq!(parsed.cli.fingerprint_mode, FingerprintMode::Session);
        assert_eq!(
            parsed.cli.user_fingerprint.as_deref(),
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
        assert!(parsed.cli.verbose);
    }

    #[test]
    fn run_errors_for_nonexistent_payload_in_stable_mode() {
        let result = run(launch_cli(FingerprintMode::Stable));

        assert!(result.is_err());
    }

    #[test]
    fn run_errors_for_nonexistent_payload_in_session_mode() {
        let result = run(launch_cli(FingerprintMode::Session));

        assert!(result.is_err());
    }
}
