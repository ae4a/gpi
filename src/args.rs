use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long, default_value = "tun0")]
    pub root_tun: String,
    #[arg(long, default_value = "10.0.0.1")]
    pub root_ip: String,

    #[arg(long, default_value = "ns2")]
    pub ns: String,
    #[arg(long, default_value = "tun2")]
    pub ns_tun: String,
    #[arg(long, default_value = "10.0.0.2")]
    pub ns_ip: String,

    #[arg(long)]
    pub eth: String,
    #[arg(long, default_value = "1600")]
    pub mtu: u16,
    #[arg(long, default_value = "1.1.1.1")]
    pub default_dns: String,

    // Flags for filters
    #[arg(long)]
    pub dns: bool,
    #[arg(long)]
    pub sni: bool,
}
