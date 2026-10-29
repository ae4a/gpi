use anyhow::{Result, bail};
use std::sync::Arc;
use tun_rs::SyncDevice;

pub struct Forwarder {
    src: Arc<SyncDevice>,
    dst: Arc<SyncDevice>,
}

impl Forwarder {
    pub fn new(src: Arc<SyncDevice>, dst: Arc<SyncDevice>) -> Forwarder {
        Forwarder { src, dst }
    }

    pub fn forward(&mut self) -> Result<()> {
        let mut buf = [0u8; 2048];

        loop {
            let n = self.src.recv(&mut buf)?;
            if n == 0 {
                break Ok(());
            }

            self.dst.send(&buf[..n])?;
            println!("forwarded {n}")
        }
    }

    pub fn forward_with_analize(&mut self) -> Result<()> {
        let mut buf = [0u8; 2048];

        loop {
            let n = self.src.recv(&mut buf)?;
            if n == 0 {
                break Ok(());
            }

            if let Err(err) = self.analize(&buf[..n]) {
                println!("Packet droped: {err}");
                continue;
            }

            self.dst.send(&buf[..n])?;
            println!("forwarded {n}")
        }
    }

    fn analize(&mut self, pkt: &[u8]) -> Result<()> {
        if pkt.len() < 4 {
            bail!("packet must be at least 4 bytes long");
        }

        match pkt[0] >> 4 {
            4 if pkt.len() >= 20 => {
                let len = u16::from_be_bytes([pkt[2], pkt[3]]);
                let src_ip = format!("{}.{}.{}.{}", pkt[12], pkt[13], pkt[14], pkt[15]);
                let dst_ip = format!("{}.{}.{}.{}", pkt[16], pkt[17], pkt[18], pkt[19]);
                println!("IpV4 {}->{} ({len})", src_ip, dst_ip);
            }
            6 => {
                println!("IpV6 is not yet supported for analize");
            }
            ver => {
                println!("unknown ip packet version: {ver}")
            }
        }

        Ok(())
    }
}
