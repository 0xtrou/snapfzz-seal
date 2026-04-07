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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum CompileBackend {
    Nuitka,
    Pyinstaller,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let backend = match cli.backend {
        CompileBackend::Nuitka => agent_seal_compiler::CliBackend::Nuitka,
        CompileBackend::Pyinstaller => agent_seal_compiler::CliBackend::Pyinstaller,
    };
    let compiler_cli = agent_seal_compiler::Cli {
        project: cli.project,
        user_fingerprint: cli.user_fingerprint,
        sandbox_fingerprint: cli.sandbox_fingerprint,
        output: cli.output,
        launcher: cli.launcher,
        backend,
    };
    agent_seal_compiler::run(compiler_cli).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{Cli, CompileBackend, run};

    fn compile_cli(backend: CompileBackend) -> Cli {
        Cli {
            project: std::path::PathBuf::from("/definitely/missing/project"),
            user_fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            sandbox_fingerprint: "auto".to_string(),
            output: std::env::temp_dir().join("agent-seal-test-output.asl"),
            launcher: None,
            backend,
        }
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
}
