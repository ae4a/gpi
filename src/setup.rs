pub use crate::args::Args;
use anyhow::{Context, Result, anyhow, bail};
use std::thread;
use tun_rs::{DeviceBuilder, SyncDevice};

pub struct EnvSetup {
    ns: String,
    root_tun: String,
    ns_tun: String,
}

impl EnvSetup {
    pub fn env(args: &Args) -> Result<EnvSetup> {
        let root_cidr = format!("{}/24", &args.root_ip);
        let ns_cidr = format!("{}/24", &args.ns_ip);

        // namespace
        // cmd("ip", &["netns", "add", &args.ns])?;

        // root side
        cmd(
            "ip",
            &["tuntap", "add", "dev", &args.root_tun, "mode", "tun"],
        )?;
        cmd("ip", &["addr", "add", &root_cidr, "dev", &args.root_tun])?;
        cmd(
            "ip",
            &[
                "link",
                "set",
                &args.root_tun,
                "mtu",
                &args.mtu.to_string(),
                "up",
            ],
        )?;
        cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
        cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                &args.eth,
                "-j",
                "MASQUERADE",
            ],
        )?;

        // ns side
        cmd(
            "ip",
            &[
                "netns",
                "exec",
                &args.ns,
                "ip",
                "tuntap",
                "add",
                "dev",
                &args.ns_tun,
                "mode",
                "tun",
            ],
        )?;
        cmd(
            "ip",
            &[
                "netns",
                "exec",
                &args.ns,
                "ip",
                "addr",
                "add",
                &ns_cidr,
                "dev",
                &args.ns_tun,
            ],
        )?;
        cmd(
            "ip",
            &[
                "netns",
                "exec",
                &args.ns,
                "ip",
                "link",
                "set",
                &args.ns_tun,
                "mtu",
                &args.mtu.to_string(),
                "up",
            ],
        )?;
        cmd(
            "ip",
            &[
                "netns",
                "exec",
                &args.ns,
                "ip",
                "route",
                "add",
                "default",
                "dev",
                &args.ns_tun,
            ],
        )?;

        // DNS for the namespace
        let dir = format!("/etc/netns/{}", &args.ns);
        std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {dir}"))?;
        std::fs::write(
            format!("{dir}/resolv.conf"),
            format!("nameserver {}\n", &args.dns),
        )
        .context("write resolv.conf")?;

        Ok(EnvSetup {
            ns: args.ns.clone(),
            root_tun: args.root_tun.clone(),
            ns_tun: args.ns_tun.clone(),
        })
    }
}

impl Drop for EnvSetup {
    fn drop(&mut self) {
        let res = || -> Result<()> {
            // root side
            cmd("ip", &["link", "delete", "dev", &self.root_tun])?;

            // ns side
            cmd(
                "ip",
                &[
                    "netns",
                    "exec",
                    &self.ns,
                    "ip",
                    "link",
                    "delete",
                    "dev",
                    &self.ns_tun,
                ],
            )?;

            println!("Cleaned up");
            Ok(())
        }();
        if let Err(err) = res {
            println!("Failed to clean up: {err}")
        }
    }
}

fn cmd(program: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program}"))?;

    if !out.status.success() {
        bail!(
            "command {program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    Ok(())
}

pub fn tun(name: &str) -> Result<SyncDevice> {
    Ok(DeviceBuilder::new().name(name).build_sync()?)
}

pub fn in_netns<T, F>(ns: &str, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let path = format!("/var/run/netns/{ns}");
    println!("{path}");
    let r = thread::spawn(move || {
        let nsf = std::fs::File::open(path)?;
        nix::sched::setns(&nsf, nix::sched::CloneFlags::CLONE_NEWNET).with_context(|| "setns")?;
        f()
    })
    .join()
    .map_err(|_| anyhow!("{ns} thread panicked"))?
    .with_context(|| "in {ns}");

    println!("ok");
    r
}
