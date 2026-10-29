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

    let root_tun = Arc::new(setup::tun(&args.root_tun)?);
    println!("root ns tun created");

    let ns_tun = args.ns_tun.clone();
    let ns_tun = Arc::new(setup::in_netns(&args.ns, move || setup::tun(&ns_tun))?);
    println!("ns tun created");

    let (root_tun_c, ns_tun_c) = (root_tun.clone(), ns_tun.clone());
    let t1 = thread::spawn(move || Forwarder::new(root_tun_c, ns_tun_c).forward());
    let t2 = thread::spawn(move || Forwarder::new(ns_tun, root_tun).forward_with_analize());

    println!("starting forwarding...");

    t1.join().unwrap()?;
    t2.join().unwrap()?;

    setup::close(&args)?;

    Ok(())
}
