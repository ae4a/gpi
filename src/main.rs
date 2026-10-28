use anyhow::{Result, anyhow, bail};
use clap::Parser;
use tun_rs::{DeviceBuilder, SyncDevice};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, short)]
    ns1: String,
    #[arg(long, short)]
    name1: String,
    #[arg(long, short)]
    ip1: String,

    #[arg(long, short)]
    ns2: String,
    #[arg(long, short)]
    name2: String,
    #[arg(long, short)]
    ip2: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (name1, ip1) = (args.name1.clone(), args.ip1.clone());
    let _dev1 = in_netns(&args.ns1, move || make_tun(&name1, &ip1));
    let (name2, ip2) = (args.name1.clone(), args.ip1.clone());
    let _dev2 = in_netns(&args.ns1, move || make_tun(&name2, &ip2));

    Ok(())
}

fn make_tun(name: &str, ip: &str) -> Result<SyncDevice> {
    Ok(DeviceBuilder::new()
        .ipv4(ip, 24, None)
        .name(name)
        .mtu(2000)
        .build_sync()?)
}

fn in_netns<T, F>(ns: &str, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let path = format!("/var/run/netns/{ns}");
    std::thread::spawn(move || {
        let nsf = std::fs::File::open(path)?;
        nix::sched::setns(&nsf, nix::sched::CloneFlags::CLONE_NEWNS)?;
        f()
    })
    .join()
    .map_err(|_| anyhow!("{ns} thread panicked"))?
}
