#[derive(clap::Args)]
#[command(name = "server")]
#[command(about = "Start the Agent Seal orchestration server")]
pub struct Cli {
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub bind: String,
    #[arg(long, default_value = "./.agent-seal/compile")]
    pub compile_dir: std::path::PathBuf,
    #[arg(long, default_value = "./.agent-seal/output")]
    pub output_dir: std::path::PathBuf,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::fs::create_dir_all(&cli.compile_dir).await?;
            tokio::fs::create_dir_all(&cli.output_dir).await?;
            let state = agent_seal_server::state::ServerState::new(cli.compile_dir, cli.output_dir);
            let app = agent_seal_server::create_app(state);
            let addr: std::net::SocketAddr = cli.bind.parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("agent-seal server listening on {}", addr);
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
            Ok(())
        })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, run};
    use clap::Parser;

    #[derive(Parser)]
    struct ParseCli {
        #[command(flatten)]
        cli: Cli,
    }

    #[test]
    fn cli_uses_expected_defaults() {
        let parsed = ParseCli::parse_from(["test"]);

        assert_eq!(parsed.cli.bind, "0.0.0.0:9090");
        assert_eq!(
            parsed.cli.compile_dir,
            std::path::PathBuf::from("./.agent-seal/compile")
        );
        assert_eq!(
            parsed.cli.output_dir,
            std::path::PathBuf::from("./.agent-seal/output")
        );
    }

    #[test]
    fn run_returns_error_for_invalid_bind_address_after_runtime_setup() {
        let base =
            std::env::temp_dir().join(format!("agent-seal-server-test-{}", std::process::id()));
        let compile_dir = base.join("compile");
        let output_dir = base.join("output");

        let result = run(Cli {
            bind: "definitely-not-an-address".to_string(),
            compile_dir: compile_dir.clone(),
            output_dir: output_dir.clone(),
        });

        assert!(result.is_err());
        assert!(compile_dir.exists());
        assert!(output_dir.exists());

        let _ = std::fs::remove_dir_all(base);
    }
}
