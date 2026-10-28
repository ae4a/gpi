use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener, TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, short)]
    out_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    Ok(())
}
