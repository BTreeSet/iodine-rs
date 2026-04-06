use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "iodine-rs")]
#[command(about = "IPv4-over-DNS tunnel rewrite scaffold")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Debug, Subcommand)]
enum Mode {
    /// Client mode compatible with iodine behavior
    Iodine(iodine_rs::client::ClientArgs),
    /// Server mode compatible with iodined behavior
    Iodined(iodine_rs::server::ServerArgs),
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.mode {
        Mode::Iodine(args) => iodine_rs::client::run(args).await,
        Mode::Iodined(args) => iodine_rs::server::run(args).await,
    }
}
