mod cmd;
mod common;

use clap::Parser as _;

/// Signs a JSON-LD document with the RsaSignature2017 suite of Linked Data Signatures
#[derive(clap::Parser)]
#[command(version)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Signs a JSON-LD document
    Sign(cmd::sign::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Sign(args) => cmd::sign::main(args).await,
    }
}
