use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "agent-seal-server")]
struct Cli {
    #[arg(long = "bind", default_value = "127.0.0.1:9090")]
    bind: String,

    #[arg(long = "compile-dir", default_value = "./.agent-seal/compile")]
    compile_dir: PathBuf,

    #[arg(long = "output-dir", default_value = "./.agent-seal/output")]
    output_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let cli = Cli::parse();

    tokio::fs::create_dir_all(&cli.compile_dir).await?;
    tokio::fs::create_dir_all(&cli.output_dir).await?;

    let state = agent_seal_server::state::ServerState::new(cli.compile_dir, cli.output_dir);
    let app = agent_seal_server::create_app(state);

    let bind_addr: SocketAddr = cli.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!("agent-seal-server listening on {}", bind_addr);

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
