use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener, TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use tokio_tun::Tun;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, short)]
    name: String,

    #[arg(long, short)]
    out_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let tun = Tun::builder()
        .name(&args.name)
        .packet_info()
        .up()
        .mtu(2000)
        .queues(1)
        .build()?
        .pop();

    let mut buf = [0u8; 2048];

    loop {
        // tun.recv()
    }
}
