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
    #[arg(long, short, default_value_t = ":8080".to_string())]
    in_addr: String,

    #[arg(long, short)]
    out_addr: String,
}

async fn pump(mut r: OwnedReadHalf, mut w: OwnedWriteHalf, lable: &str) -> Result<()> {
    let mut buf: [u8; 2048] = [0; 2048];

    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        println!("{lable} {n}");
        w.write(&buf[..n]).await?;
    }

    Ok(())
}

async fn handle(client: TcpStream, out_addr: &str) -> Result<()> {
    let server = TcpStream::connect(&out_addr).await?;

    let (cr, cw) = client.into_split();
    let (sr, sw) = server.into_split();

    tokio::try_join!(
        pump(cr, sw, "client->server"),
        pump(sr, cw, "server->client")
    )?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let listenner = TcpListener::bind(args.in_addr).await?;

    loop {
        let (socket, _) = listenner.accept().await?;
        let out_addr = args.out_addr.clone();

        tokio::spawn(async move {
            if let Err(e) = handle(socket, &out_addr).await {
                println!("GOT ERR for {} connection: {}", out_addr, e);
            }
        });
    }
}
