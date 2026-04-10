#[derive(clap::Args)]
#[command(name = "compile")]
#[command(about = "Compile and seal an agent")]
pub struct Cli {
    #[arg(long)]
    pub project: std::path::PathBuf,
    #[arg(long)]
    pub user_fingerprint: String,
    #[arg(long, default_value = "auto")]
    pub sandbox_fingerprint: String,
    #[arg(long)]
    pub output: std::path::PathBuf,
    #[arg(long)]
    pub launcher: Option<std::path::PathBuf>,
    #[arg(long, value_enum, default_value_t = CompileBackend::Nuitka)]
    pub backend: CompileBackend,
    #[arg(long, value_enum, default_value_t = CompileMode::Batch)]
    pub mode: CompileMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum CompileMode {
    Batch,
    Interactive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum CompileBackend {
    Nuitka,
    Pyinstaller,
    Go,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let backend = match cli.backend {
        CompileBackend::Nuitka => snapfzz_seal_compiler::CliBackend::Nuitka,
        CompileBackend::Pyinstaller => snapfzz_seal_compiler::CliBackend::Pyinstaller,
        CompileBackend::Go => snapfzz_seal_compiler::CliBackend::Go,
    };
    let mode = match cli.mode {
        CompileMode::Batch => snapfzz_seal_compiler::CliMode::Batch,
        CompileMode::Interactive => snapfzz_seal_compiler::CliMode::Interactive,
    };
    let compiler_cli = snapfzz_seal_compiler::Cli {
        project: cli.project,
        user_fingerprint: cli.user_fingerprint,
        sandbox_fingerprint: cli.sandbox_fingerprint,
        output: cli.output,
        launcher: cli.launcher,
        backend,
        mode,
    };
    snapfzz_seal_compiler::run(compiler_cli).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, CompileBackend, CompileMode, run};

    #[derive(Parser)]
    struct ParseCli {
        #[command(flatten)]
        cli: Cli,
    }

    fn compile_cli(backend: CompileBackend) -> Cli {
        Cli {
            project: std::path::PathBuf::from("/definitely/missing/project"),
            user_fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            sandbox_fingerprint: "auto".to_string(),
            output: std::env::temp_dir().join("snapfzz-seal-test-output.asl"),
            launcher: None,
            backend,
            mode: CompileMode::Batch,
        }
    }

    #[test]
    fn cli_maps_arguments_and_defaults_backend() {
        let parsed = ParseCli::parse_from([
            "test",
            "--project",
            "./agent",
            "--user-fingerprint",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--output",
            "./out.asl",
        ]);

        assert_eq!(parsed.cli.project, std::path::PathBuf::from("./agent"));
        assert_eq!(parsed.cli.sandbox_fingerprint, "auto");
        assert_eq!(parsed.cli.output, std::path::PathBuf::from("./out.asl"));
        assert_eq!(parsed.cli.launcher, None);
        assert_eq!(parsed.cli.backend, CompileBackend::Nuitka);
    }

    #[test]
    fn cli_maps_optional_launcher_and_pyinstaller_backend() {
        let parsed = ParseCli::parse_from([
            "test",
            "--project",
            "./agent",
            "--user-fingerprint",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--output",
            "./out.asl",
            "--launcher",
            "./launcher",
            "--backend",
            "pyinstaller",
            "--sandbox-fingerprint",
            "manual",
        ]);

        assert_eq!(
            parsed.cli.launcher,
            Some(std::path::PathBuf::from("./launcher"))
        );
        assert_eq!(parsed.cli.backend, CompileBackend::Pyinstaller);
        assert_eq!(parsed.cli.sandbox_fingerprint, "manual");
    }

    #[test]
    fn run_errors_for_nonexistent_project_with_nuitka_backend() {
        let result = run(compile_cli(CompileBackend::Nuitka));

        assert!(result.is_err());
    }

    #[test]
    fn run_errors_for_nonexistent_project_with_pyinstaller_backend() {
        let result = run(compile_cli(CompileBackend::Pyinstaller));

        assert!(result.is_err());
    }

    #[test]
    fn run_errors_for_nonexistent_project_with_go_backend() {
        let result = run(compile_cli(CompileBackend::Go));

        assert!(result.is_err());
    }
}
