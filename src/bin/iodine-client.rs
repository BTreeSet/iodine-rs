use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "iodine-client")]
struct Cli {
    #[command(flatten)]
    args: iodine_rs::client::ClientArgs,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    iodine_rs::client::run(cli.args).await;
}
