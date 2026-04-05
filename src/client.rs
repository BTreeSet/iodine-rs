use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct ClientArgs {
    #[arg(long)]
    pub topdomain: Option<String>,
    #[arg(long)]
    pub nameserver: Option<String>,
}

pub fn run(_args: ClientArgs) -> ! {
    unimplemented!("client mode (iodine) not implemented in milestone 1")
}
