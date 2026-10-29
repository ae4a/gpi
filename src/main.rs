use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use std::thread;

mod args;
mod forwarder;
mod setup;

use forwarder::Forwarder;

fn main() -> Result<()> {
    let args = args::Args::parse();

    setup::env(&args)?;
    println!("env set up");

    let dev1 = Arc::new(setup::tun(&args.root_tun)?);
    println!("root ns tun created");

    let ns_tun = args.ns_tun.clone();
    let dev2 = Arc::new(setup::in_netns(&args.ns, move || setup::tun(&ns_tun))?);
    println!("ns tun created");

    let (dev1_c, dev2_c) = (dev1.clone(), dev2.clone());
    let t1 = thread::spawn(move || Forwarder::new(dev1_c, dev2_c).forward());
    let t2 = thread::spawn(move || Forwarder::new(dev2, dev1).forward_with_analize());

    println!("starting forwarding...");

    t1.join().unwrap()?;
    t2.join().unwrap()?;

    setup::close(&args)?;

    Ok(())
}
