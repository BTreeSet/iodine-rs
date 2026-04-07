use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "iodine-server")]
struct Cli {
    #[command(flatten)]
    args: iodine_rs::server::ServerArgs,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    iodine_rs::server::run(cli.args).await;
}
