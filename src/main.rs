use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use std::thread;
use tun_rs::SyncDevice;

mod args;
mod setup;

fn main() -> Result<()> {
    let args = args::Args::parse();

    setup::env(&args)?;
    println!("env set up");

    let dev1 = Arc::new(setup::tun(&args.root_tun)?);

    println!("dev1 created");

    let ns_tun = args.ns_tun.clone();
    let dev2 = Arc::new(setup::in_netns(&args.ns, move || setup::tun(&ns_tun))?);

    println!("dev2 created");

    let (dev1_c, dev2_c) = (dev1.clone(), dev2.clone());
    let t1 = thread::spawn(move || forward(dev1_c, dev2_c));
    let t2 = thread::spawn(move || forward(dev2, dev1));

    println!("starting forwarding...");

    t1.join().unwrap()?;
    t2.join().unwrap()?;

    Ok(())
}

fn forward(src: Arc<SyncDevice>, dst: Arc<SyncDevice>) -> Result<()> {
    let mut buf = [0u8; 2048];

    loop {
        let n = src.recv(&mut buf)?;
        if n == 0 {
            break Ok(());
        }

        dst.send(&buf[..n])?;
    }
}
