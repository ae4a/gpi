use std::{collections::HashMap, sync::Mutex};

use anyhow::{Context, Result, anyhow, bail};

const IP_HEADER_MIN_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const DNS_HEADER_SIZE: usize = 12;

pub trait PktFilter {
    fn filter(&self, pkt: &[u8]) -> Result<()>;
}

// enum ConnState {
//     TcpSyn,
//     TcpSynAck,
//     TcpAck,
// }

pub struct SimplePktFilter {
    // state: Mutex<HashMap<String, ConnState>>,
    traiters: Vec<String>,
}

impl SimplePktFilter {
    pub fn new() -> impl PktFilter {
        SimplePktFilter {
            // state: Mutex::new(HashMap::new()),
            traiters: Vec::from(["youtube".to_string()]),
        }
    }

    fn filter_udp(&self, pkt: &[u8]) -> Result<()> {
        // println!("udp");
        let dst_port = u16::from_be_bytes([pkt[2], pkt[3]]);

        let pkt = &pkt[UDP_HEADER_SIZE..];

        if dst_port == 53 && pkt.len() >= 12 {
            self.filter_dns(pkt).with_context(|| "DNS: ")?;
        }
        Ok(())
    }

    fn filter_dns(&self, pkt: &[u8]) -> Result<()> {
        // Check QR bit: 0 - request, 1 - response
        if pkt[2] & 0x80 != 0 {
            return Ok(());
        }
        if let Some(addr) = self.try_get_dns(&pkt[DNS_HEADER_SIZE..]) {
            // println!("{addr}");
            for s in self.traiters.iter() {
                if addr.contains(s) {
                    bail!("found {s}");
                }
            }
        }

        Ok(())
    }

    fn try_get_dns(&self, pkt: &[u8]) -> Option<String> {
        let mut name = String::new();
        let mut i = 0;

        println!("{}", String::from_utf8_lossy(pkt));

        loop {
            let n = usize::from(*pkt.get(i)?);
            i += 1;

            if n == 0 {
                break; // end of QNAME
            }
            if n > 63 {
                return None; // pointer or invalid label
            }
            let label = pkt.get(i..i + n)?;
            if !label.iter().all(|b| b.is_ascii_graphic()) {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(std::str::from_utf8(label).ok()?);
            if name.len() > 253 {
                return None;
            }
            i += n;
        }

        if name.is_empty() {
            return None; // root query "."
        }
        Some(name)
    }
}

impl PktFilter for SimplePktFilter {
    fn filter(&self, pkt: &[u8]) -> Result<()> {
        if pkt.len() < 4 {
            bail!("packet must be at least 4 bytes long");
        }

        match pkt[0] >> 4 {
            4 if pkt.len() >= IP_HEADER_MIN_SIZE => {
                // IpV4 header 20 bytes
                let len = u16::from_be_bytes([pkt[2], pkt[3]]);
                let header_len = usize::from((pkt[0] & 0xf) * 4);
                // let src_ip = format!("{}.{}.{}.{}", pkt[12], pkt[13], pkt[14], pkt[15]);
                // let dst_ip = format!("{}.{}.{}.{}", pkt[16], pkt[17], pkt[18], pkt[19]);
                let proto = pkt[9];

                let pkt = &pkt[header_len..];
                match proto {
                    // UDP header 8 bytes
                    17 if pkt.len() >= UDP_HEADER_SIZE => {
                        return self.filter_udp(pkt);
                    }
                    // TCP header 20 bytes
                    6 if pkt.len() >= 20 => {
                        println!("tcp");
                    }
                    1 => {
                        println!("icmp");
                    }
                    _ => {
                        println!("unknown proto {proto}");
                    }
                }

                // test
                // let mut m = self.state.lock().map_err(|_| anyhow!("mutex poisoned"))?;
                // m.insert(src_ip, ConnState::TcpHandShake);
            }
            6 => {}
            _ver => {}
        }

        Ok(())
    }
}
