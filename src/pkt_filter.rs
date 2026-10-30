use anyhow::{Result, bail};

pub trait PktFilter {
    fn filter(&mut self, pkt: &[u8]) -> Result<()>;
}

pub struct SimplePktFilter {}

impl SimplePktFilter {
    pub fn new() -> impl PktFilter {
        SimplePktFilter {}
    }
}

impl PktFilter for SimplePktFilter {
    fn filter(&mut self, pkt: &[u8]) -> Result<()> {
        if pkt.len() < 4 {
            bail!("packet must be at least 4 bytes long");
        }

        match pkt[0] >> 4 {
            4 if pkt.len() >= 20 => {
                let len = u16::from_be_bytes([pkt[2], pkt[3]]);
                let src_ip = format!("{}.{}.{}.{}", pkt[12], pkt[13], pkt[14], pkt[15]);
                let dst_ip = format!("{}.{}.{}.{}", pkt[16], pkt[17], pkt[18], pkt[19]);
            }
            6 => {}
            _ver => {}
        }

        Ok(())
    }
}
