use clap::{Parser, Subcommand};

mod compile;
mod keygen;
mod launch;
mod server;
mod sign;
mod verify;

#[derive(Parser)]
#[command(name = "seal")]
#[command(about = "Snapfzz Seal — encrypted sandbox-bound agent delivery")]
#[command(version, long_version = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Compile(compile::Cli),
    Keygen(keygen::Cli),
    Launch(launch::Cli),
    Server(server::Cli),
    Sign(sign::Cli),
    Verify(verify::Cli),
}

fn main() {
    let cli = Cli::parse();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    match cli.command {
        Command::Verify(cli) => {
            // `seal verify` uses structured exit codes:
            //   0 — signature valid and verified
            //   1 — operational error (I/O, bad args, malformed key)
            //   2 — security event: signature invalid / binary tampered
            //   3 — policy violation: unsigned binary
            if let Err(err) = verify::run(cli) {
                eprintln!("{err}");
                let code = match err {
                    verify::VerifyError::Operational(_) => 1,
                    verify::VerifyError::SecurityEvent(_) => 2,
                    verify::VerifyError::Unsigned(_) => 3,
                };
                std::process::exit(code);
            }
        }
        other => {
            let result: Result<(), Box<dyn std::error::Error>> = match other {
                Command::Compile(cli) => compile::run(cli),
                Command::Keygen(cli) => keygen::run(cli),
                Command::Launch(cli) => launch::run(cli),
                Command::Server(cli) => server::run(cli),
                Command::Sign(cli) => sign::run(cli),
                Command::Verify(_) => unreachable!(),
            };
            if let Err(err) = result {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
}
