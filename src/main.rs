use anyhow::{Result, bail};
use clap::Parser;
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

    let mut tun: Vec<Tun> = Tun::builder()
        .name(&args.name)
        .packet_info()
        .up()
        .mtu(2000)
        .queues(1)
        .build()?;

    let Some(tun) = tun.pop() else {
        bail!("failed to get tun");
    };

    let mut buf = [0u8; 2048];

    loop {
        let n = tun.recv(&mut buf).await?;

        // Expect at least 4 bytes from packet_info
        if n < 4 {
            continue;
        }

        let pkt = &buf[..n];

        let flags = u16::from_be_bytes([pkt[0], pkt[1]]);
        let proto = u16::from_be_bytes([pkt[3], pkt[4]]);

        if flags & 1 == 0 {
            bail!("buffer size seems to be too small - packet is cut");
        }

        match proto {
            0x0800 if n >= 20 => {
                if pkt[0] >> 4 != 4 {
                    println!(
                        "Packet proto is IpV4 though in packet it is {}",
                        pkt[0] >> 4
                    );
                    continue;
                }

                // Just some info to print out
                let len = u16::from_be_bytes([pkt[2], pkt[3]]);
                let id = u16::from_be_bytes([pkt[4], pkt[5]]);
                let protocol = pkt[9];
                let src_ip = format!("{}.{}.{}.{}", pkt[12], pkt[13], pkt[14], pkt[15]);
                let dest_ip = format!("{}.{}.{}.{}", pkt[16], pkt[17], pkt[18], pkt[19]);
                println!("{src_ip}->{dest_ip} ({protocol}) {id} [{len}]");
            }
            0x86DD => {
                println!("IpV6 is unimplemeted");
            }
            def => {
                println!("{def} proto is unimplemeted");
            }
        }
    }
}
