use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct ServerArgs {
    #[arg(long)]
    pub topdomain: Option<String>,
    #[arg(long)]
    pub bind_addr: Option<String>,
}

pub fn run(_args: ServerArgs) -> ! {
    unimplemented!("server mode (iodined) not implemented in milestone 1")
}
