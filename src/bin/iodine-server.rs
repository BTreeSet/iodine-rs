use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "iodine-server")]
struct Cli {
    #[command(flatten)]
    args: iodine_rs::server::ServerArgs,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    iodine_rs::server::run(cli.args).await;
}
