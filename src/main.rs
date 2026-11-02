use anyhow::Result;
use clap::Parser;
use std::sync::Mutex;
use std::sync::{Arc, atomic::AtomicBool};
use std::thread;
use std::time::Duration;
use tun_rs::{InterruptEvent, SyncDevice};

mod args;
mod pkt_filter;
mod setup;

use pkt_filter::{PktFilter, SimplePktFilter};

fn main() -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let args = args::Args::parse();
    let _env = setup::EnvSetup::env(&args)?;

    let event = Arc::new(InterruptEvent::new()?);

    // CTRL-C handler
    {
        let running = running.clone();
        let event = event.clone();
        ctrlc::set_handler(move || {
            println!("Cleaning");
            running.store(false, std::sync::atomic::Ordering::SeqCst);
            let _ = event.trigger();

            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_secs(5));
                eprintln!("shutdown timed out, forcing exit");
                std::process::exit(1);
            });
        })
        .expect("Failed to clean up");
    }

    println!("env set up");

    let root_tun = Arc::new(setup::tun(&args.root_tun)?);
    println!("root ns tun created");

    let ns_tun = args.ns_tun.clone();
    let ns_tun = Arc::new(setup::in_netns(&args.ns, move || setup::tun(&ns_tun))?);
    println!("ns tun created");

    let conn_store = pkt_filter::new_conn_store();
    let cfg = pkt_filter::Config {
        dns: args.dns,
        sni: args.sni,
    };

    let t1 = {
        let (root_tun, ns_tun) = (root_tun.clone(), ns_tun.clone());
        let running = running.clone();
        let event = event.clone();
        let conn_store = conn_store.clone();
        let cfg = cfg.clone();

        thread::spawn(move || {
            forward_and_filter(
                running,
                event,
                root_tun,
                ns_tun,
                SimplePktFilter::new(cfg, conn_store, true),
                "root->ns",
            )
        })
    };
    let t2 = {
        let running = running.clone();
        let event = event.clone();
        let (root_tun, ns_tun) = (root_tun.clone(), ns_tun.clone());
        let conn_store = conn_store.clone();
        let cfg = cfg.clone();

        thread::spawn(move || {
            forward_and_filter(
                running,
                event,
                ns_tun,
                root_tun,
                SimplePktFilter::new(cfg, conn_store, false),
                "ns->root",
            )
        })
    };

    println!("starting forwarding...");

    t1.join().unwrap()?;
    t2.join().unwrap()?;

    Ok(())
}

fn forward(
    r: Arc<AtomicBool>,
    e: Arc<InterruptEvent>,
    src: Arc<SyncDevice>,
    dst: Arc<SyncDevice>,
    label: &str,
) -> Result<()> {
    let mut buf = [0u8; 2048];

    while r.load(std::sync::atomic::Ordering::SeqCst) {
        let n = src.recv_intr(&mut buf, &e)?;
        if n == 0 {
            return Ok(());
        }

        log_pkt(&buf[..n], label);

        dst.send(&buf[..n])?;
    }

    Ok(())
}

fn forward_and_filter(
    r: Arc<AtomicBool>,
    e: Arc<InterruptEvent>,
    src: Arc<SyncDevice>,
    dst: Arc<SyncDevice>,
    f: impl PktFilter,
    label: &str,
) -> Result<()> {
    let mut buf = [0u8; 2048];

    while r.load(std::sync::atomic::Ordering::SeqCst) {
        let n = src.recv_intr(&mut buf, &e)?;
        if n == 0 {
            return Ok(());
        }

        log_pkt(&buf[..n], label);

        if let Err(err) = f.filter(&buf[..n]) {
            println!("Packet droped: {err:#}");
            continue;
        }

        dst.send(&buf[..n])?;
    }

    Ok(())
}

fn log_pkt(pkt: &[u8], label: &str) {
    if pkt.len() < 4 {
        return;
    }

    match pkt[0] >> 4 {
        4 if pkt.len() >= 20 => {
            let len = u16::from_be_bytes([pkt[2], pkt[3]]);
            let src_ip = format!("{}.{}.{}.{}", pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst_ip = format!("{}.{}.{}.{}", pkt[16], pkt[17], pkt[18], pkt[19]);
            let proto = pkt[9];
            println!("{label} --- IpV4 {}->{} ({len})", src_ip, dst_ip);
        }
        6 => {
            // println!("IpV6 is not yet supported for analize");
        }
        ver => {
            println!("{label} --- unknown ip packet version: {ver}")
        }
    }
}
