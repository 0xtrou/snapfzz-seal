#[derive(clap::Args)]
#[command(name = "proxy")]
#[command(about = "Start the Agent Seal LLM proxy")]
pub struct Cli {
    #[arg(long)]
    pub provider_key: String,
    #[arg(long, default_value = "openai")]
    pub provider: String,
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub bind: String,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let state = agent_seal_proxy::state::ProxyState::new(cli.provider_key, cli.provider);
            let app = agent_seal_proxy::create_app(state);
            let addr: std::net::SocketAddr = cli.bind.parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("agent-seal proxy listening on {}", addr);
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
        let parsed = ParseCli::parse_from(["test", "--provider-key", "pk_test"]);

        assert_eq!(parsed.cli.provider_key, "pk_test");
        assert_eq!(parsed.cli.provider, "openai");
        assert_eq!(parsed.cli.bind, "0.0.0.0:8080");
    }

    #[test]
    fn cli_maps_all_args() {
        let parsed = ParseCli::parse_from([
            "test",
            "--provider-key",
            "pk_live",
            "--provider",
            "anthropic",
            "--bind",
            "127.0.0.1:19080",
        ]);

        assert_eq!(parsed.cli.provider_key, "pk_live");
        assert_eq!(parsed.cli.provider, "anthropic");
        assert_eq!(parsed.cli.bind, "127.0.0.1:19080");
    }

    #[test]
    fn run_returns_error_for_invalid_bind_address_after_runtime_setup() {
        let result = run(Cli {
            provider_key: "pk_test".to_string(),
            provider: "openai".to_string(),
            bind: "definitely-not-an-address".to_string(),
        });

        assert!(result.is_err());
    }
}
