use std::net::SocketAddr;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "agent-seal-proxy")]
struct Cli {
    #[arg(long = "provider-key")]
    provider_key: String,

    #[arg(long = "provider", default_value = "openai")]
    provider: String,

    #[arg(long = "bind", default_value = "0.0.0.0:8080")]
    bind: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let cli = Cli::parse();
    let state = agent_seal_proxy::state::ProxyState::new(cli.provider_key, cli.provider);
    let app = agent_seal_proxy::try_create_app(state)?;

    let bind_addr: SocketAddr = cli.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!("agent-seal-proxy listening on {}", bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
    use super::shutdown_signal;

    #[tokio::test]
    async fn shutdown_signal_is_cancellable() {
        let task = tokio::spawn(shutdown_signal());
        tokio::task::yield_now().await;
        task.abort();
        let join_err = task
            .await
            .expect_err("aborted task should return join error");
        assert!(join_err.is_cancelled());
    }
}
