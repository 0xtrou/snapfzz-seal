pub mod assemble;
pub mod backend;
pub mod compile;
pub mod decoys;
pub mod embed;
pub mod whitebox_embed;

use clap::{Parser, ValueEnum};
use snapfzz_seal_core::{error::SealError, secret::generate_master_secret, types::AgentMode};
use snapfzz_seal_fingerprint::{FingerprintCollector, canonical::canonicalize_stable};
use std::{path::PathBuf, str::FromStr};

use crate::backend::{CompileBackend, GoBackend, NuitkaBackend, PyInstallerBackend};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliBackend {
    Nuitka,
    Pyinstaller,
    Go,
}

#[derive(Debug, Parser)]
#[command(name = "snapfzz-seal-compiler")]
#[command(about = "Snapfzz Seal compiler")]
pub struct Cli {
    #[arg(long)]
    pub project: PathBuf,
    #[arg(long)]
    pub user_fingerprint: String,
    #[arg(
        long,
        default_value = "auto",
        help = "64-hex sandbox identity. 'auto' collects the current environment's stable fingerprint. Provide a hex string to bind to a specific sandbox."
    )]
    pub sandbox_fingerprint: String,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, value_enum, default_value_t = CliBackend::Nuitka)]
    pub backend: CliBackend,
    #[arg(long, value_enum, default_value_t = CliMode::Batch)]
    pub mode: CliMode,
    #[arg(long)]
    pub launcher: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliMode {
    Batch,
    Interactive,
}

impl From<CliMode> for AgentMode {
    fn from(mode: CliMode) -> Self {
        match mode {
            CliMode::Batch => AgentMode::Batch,
            CliMode::Interactive => AgentMode::Interactive,
        }
    }
}

pub fn run(cli: Cli) -> Result<(), SealError> {
    let launcher_path = resolve_launcher_path(cli.launcher)?;

    let user_fingerprint = parse_hex_32(&cli.user_fingerprint, "user fingerprint")?;
    let stable_fingerprint_hash = if cli.sandbox_fingerprint == "auto" {
        let collector = FingerprintCollector::new();
        let snapshot = collector.collect_stable_only().map_err(|e| {
            SealError::InvalidInput(format!("failed to collect sandbox fingerprint: {}", e))
        })?;
        canonicalize_stable(&snapshot)
    } else {
        parse_hex_32(&cli.sandbox_fingerprint, "sandbox fingerprint")?
    };

    let master_secret = generate_master_secret();
    let output_parent = cli
        .output
        .parent()
        .ok_or_else(|| SealError::InvalidInput("output path has no parent".to_string()))?
        .to_path_buf();

    std::fs::create_dir_all(&output_parent)?;

    let backend: Box<dyn CompileBackend> = match cli.backend {
        CliBackend::Nuitka => Box::new(NuitkaBackend),
        CliBackend::Pyinstaller => Box::new(PyInstallerBackend),
        CliBackend::Go => Box::new(GoBackend),
    };

    let backend_name = backend.name().to_string();

    let compiled_binary =
        compile::compile_agent_with_backend(&cli.project, &output_parent, backend.as_ref())?;

    let assembled = assemble::assemble(&assemble::AssembleConfig {
        agent_elf_path: compiled_binary,
        launcher_path,
        master_secret,
        stable_fingerprint_hash,
        user_fingerprint,
        mode: cli.mode.into(),
        backend_name,
    })?;

    std::fs::write(&cli.output, &assembled)?;
    println!(
        "compiled and assembled binary: {} ({} bytes)",
        cli.output.display(),
        assembled.len()
    );

    Ok(())
}

fn resolve_launcher_path(cli_launcher: Option<PathBuf>) -> Result<PathBuf, SealError> {
    if let Some(path) = cli_launcher {
        return Ok(path);
    }

    let raw = std::env::var("SNAPFZZ_SEAL_LAUNCHER_PATH").map_err(|_| {
        SealError::InvalidInput(
            "launcher path missing: use --launcher or SNAPFZZ_SEAL_LAUNCHER_PATH".to_string(),
        )
    })?;

    PathBuf::from_str(&raw)
        .map_err(|_| SealError::InvalidInput("invalid launcher path".to_string()))
}

fn parse_hex_32(input: &str, label: &str) -> Result<[u8; 32], SealError> {
    let decoded = hex::decode(input)
        .map_err(|err| SealError::InvalidInput(format!("invalid {label} hex: {err}")))?;
    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(format!(
            "{label} must be exactly 64 hex chars"
        )));
    }

    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_launcher_path_prefers_cli_arg() {
        let cli_path = PathBuf::from("/tmp/from-cli");
        let resolved = resolve_launcher_path(Some(cli_path.clone()))
            .expect("cli launcher path should be returned directly");
        assert_eq!(resolved, cli_path);
    }

    #[test]
    fn resolve_launcher_path_reads_env_when_cli_missing() {
        if std::env::var_os("SNAPFZZ_SEAL_TEST_RESOLVE_FROM_ENV_CHILD").is_some() {
            let resolved = resolve_launcher_path(None)
                .expect("env launcher path should be used when cli arg missing");
            assert_eq!(resolved, PathBuf::from("/tmp/from-env-only"));
            return;
        }

        let current_exe = std::env::current_exe().expect("current test binary path should resolve");
        let output = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg("tests::resolve_launcher_path_reads_env_when_cli_missing")
            .env("SNAPFZZ_SEAL_TEST_RESOLVE_FROM_ENV_CHILD", "1")
            .env("SNAPFZZ_SEAL_LAUNCHER_PATH", "/tmp/from-env-only")
            .output()
            .expect("child test process should execute");

        assert!(
            output.status.success(),
            "child process should pass: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn resolve_launcher_path_errors_when_missing_everywhere() {
        if std::env::var_os("SNAPFZZ_SEAL_TEST_RESOLVE_MISSING_CHILD").is_some() {
            let err = resolve_launcher_path(None)
                .expect_err("missing cli and env launcher path should error");
            match err {
                SealError::InvalidInput(message) => {
                    assert!(message.contains("launcher path missing"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
            return;
        }

        let current_exe = std::env::current_exe().expect("current test binary path should resolve");
        let output = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg("tests::resolve_launcher_path_errors_when_missing_everywhere")
            .env("SNAPFZZ_SEAL_TEST_RESOLVE_MISSING_CHILD", "1")
            .env_remove("SNAPFZZ_SEAL_LAUNCHER_PATH")
            .output()
            .expect("child test process should execute");

        assert!(
            output.status.success(),
            "child process should pass: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn parse_hex_32_accepts_valid_input() {
        let valid = "ab".repeat(32);
        let parsed =
            parse_hex_32(&valid, "user fingerprint").expect("valid 64-char hex should parse");
        assert_eq!(parsed.len(), 32);
        assert_eq!(parsed[0], 0xab);
    }

    #[test]
    fn parse_hex_32_rejects_too_short_input() {
        let err =
            parse_hex_32("aa", "user fingerprint").expect_err("short hex input should be rejected");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("must be exactly 64 hex chars"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_hex_32_rejects_invalid_hex_chars() {
        let err = parse_hex_32("gggg", "sandbox fingerprint")
            .expect_err("non-hex input should be rejected");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid sandbox fingerprint hex"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_hex_32_rejects_empty_input() {
        let err =
            parse_hex_32("", "sandbox fingerprint").expect_err("empty input should be rejected");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("must be exactly 64 hex chars"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_errors_when_output_has_no_parent() {
        let cli = Cli {
            project: PathBuf::from("/tmp/project"),
            user_fingerprint: "11".repeat(32),
            sandbox_fingerprint: "22".repeat(32),
            output: PathBuf::new(),
            backend: CliBackend::Nuitka,
            mode: CliMode::Batch,
            launcher: Some(PathBuf::from("/tmp/launcher")),
        };

        let err = run(cli).expect_err("output without parent should fail before compilation");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("output path has no parent"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_errors_when_launcher_missing() {
        if std::env::var_os("SNAPFZZ_SEAL_TEST_RUN_MISSING_LAUNCHER_CHILD").is_some() {
            let cli = Cli {
                project: PathBuf::from("/tmp/project"),
                user_fingerprint: "11".repeat(32),
                sandbox_fingerprint: "22".repeat(32),
                output: std::env::temp_dir().join("snapfzz-seal-output.bin"),
                backend: CliBackend::Nuitka,
                mode: CliMode::Batch,
                launcher: None,
            };

            let err = run(cli).expect_err("missing launcher path should fail immediately");
            match err {
                SealError::InvalidInput(message) => {
                    assert!(message.contains("launcher path missing"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
            return;
        }

        let current_exe = std::env::current_exe().expect("current test binary path should resolve");
        let output = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg("tests::run_errors_when_launcher_missing")
            .env("SNAPFZZ_SEAL_TEST_RUN_MISSING_LAUNCHER_CHILD", "1")
            .env_remove("SNAPFZZ_SEAL_LAUNCHER_PATH")
            .output()
            .expect("child test process should execute");

        assert!(
            output.status.success(),
            "child process should pass: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn parse_hex_32_accepts_uppercase_hex() {
        let valid = "AB".repeat(32);
        let parsed =
            parse_hex_32(&valid, "user fingerprint").expect("uppercase 64-char hex should parse");
        assert_eq!(parsed[0], 0xAB);
    }

    #[test]
    fn run_rejects_invalid_user_fingerprint_before_compilation() {
        let cli = Cli {
            project: PathBuf::from("/tmp/project"),
            user_fingerprint: "not-hex".to_string(),
            sandbox_fingerprint: "22".repeat(32),
            output: std::env::temp_dir().join("snapfzz-seal-output-invalid-user.bin"),
            backend: CliBackend::Nuitka,
            mode: CliMode::Batch,
            launcher: Some(PathBuf::from("/tmp/launcher")),
        };

        let err =
            run(cli).expect_err("invalid user fingerprint should fail before backend execution");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid user fingerprint hex"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_rejects_invalid_sandbox_fingerprint_when_not_auto() {
        let cli = Cli {
            project: PathBuf::from("/tmp/project"),
            user_fingerprint: "11".repeat(32),
            sandbox_fingerprint: "bad-sandbox-hex".to_string(),
            output: std::env::temp_dir().join("snapfzz-seal-output-invalid-sandbox.bin"),
            backend: CliBackend::Nuitka,
            mode: CliMode::Batch,
            launcher: Some(PathBuf::from("/tmp/launcher")),
        };

        let err =
            run(cli).expect_err("invalid sandbox fingerprint should fail when value is not auto");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid sandbox fingerprint hex"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_accepts_auto_sandbox_and_maps_pyinstaller_backend() {
        let cli = Cli {
            project: PathBuf::from("/"),
            user_fingerprint: "11".repeat(32),
            sandbox_fingerprint: "auto".to_string(),
            output: std::env::temp_dir().join("snapfzz-seal-output-auto-sandbox.bin"),
            backend: CliBackend::Pyinstaller,
            mode: CliMode::Batch,
            launcher: Some(PathBuf::from("/tmp/launcher")),
        };

        let err = run(cli).expect_err("compilation should fail for invalid project path");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid project path"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_maps_nuitka_backend_and_propagates_compilation_error() {
        let cli = Cli {
            project: PathBuf::from("/"),
            user_fingerprint: "11".repeat(32),
            sandbox_fingerprint: "22".repeat(32),
            output: std::env::temp_dir().join("snapfzz-seal-output-nuitka-path.bin"),
            backend: CliBackend::Nuitka,
            mode: CliMode::Batch,
            launcher: Some(PathBuf::from("/tmp/launcher")),
        };

        let err = run(cli).expect_err("compilation should fail for invalid project path");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid project path"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
