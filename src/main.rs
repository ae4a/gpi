use tokio::net;

use clap::Parser;
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, short, default_value_t = ":8080".to_string())]
    in_addr: String,

    #[arg(long, short)]
    out_addr: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let listenner = net::TcpListener::bind(args.in_addr).await?;

    loop {
        let socket = listenner.accept().await?;

        tokio::spawn(async move {
            println!("{:?}", socket);
        });
    }
}
