use clap::{Parser, Subcommand};

mod compile;
mod fingerprint;
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
    Fingerprint(fingerprint::Cli),
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

    // `seal verify` uses structured exit codes:
    //   0 — signature valid and verified
    //   1 — operational error (I/O, bad args, malformed key)
    //   2 — security event: signature invalid / binary tampered
    //   3 — policy violation: unsigned binary
    if let Command::Verify(cli) = cli.command {
        if let Err(err) = verify::run(cli) {
            eprintln!("{err}");
            let code = match err {
                verify::VerifyError::Operational(_) => 1,
                verify::VerifyError::SecurityEvent(_) => 2,
                verify::VerifyError::Unsigned(_) => 3,
            };
            std::process::exit(code);
        }
        return;
    }

    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Command::Compile(cli) => compile::run(cli),
        Command::Fingerprint(cli) => fingerprint::run(cli),
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
