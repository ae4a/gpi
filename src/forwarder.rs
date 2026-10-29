use anyhow::Result;
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
        Ok(())
    }
}
