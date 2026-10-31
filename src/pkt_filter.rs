use anyhow::{Context, Result, anyhow, bail};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::{collections::HashMap, sync::Mutex};

const IP_HEADER_MIN_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const DNS_HEADER_SIZE: usize = 12;
const TCP_HEADER_MIN_SIZE: usize = 20;

pub trait PktFilter {
    fn filter(&self, pkt: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpState {
    Invalid,
    Empty,
    TcpSyn,
    TcpAck,
    TcpSynAck,
    Data,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TlsState {
    Invalid,
    Empty,
    HelloClient,
    Data,
}

#[derive(Debug, Clone)]
pub struct ConnRecord {
    i: usize,
    tcp: TcpState,
    tls: TlsState,
}

struct ConnId<'a> {
    ips: (&'a [u8], &'a [u8]),
    ports: Option<(&'a [u8], &'a [u8])>,
}

impl<'a> ConnId<'a> {
    fn new(src: &'a [u8], dst: &'a [u8]) -> ConnId<'a> {
        ConnId {
            ips: (src, dst),
            ports: None,
        }
    }

    fn set_ports(&mut self, src: &'a [u8], dst: &'a [u8]) {
        self.ports = Some((src, dst));
    }

    fn hash(self, reverse_dir: bool) -> Result<u64> {
        let Some(ports) = self.ports else {
            bail!("require ports for id");
        };

        let mut buf = [0u8; 12];

        if reverse_dir {
            buf[0..4].copy_from_slice(self.ips.1);
            buf[4..8].copy_from_slice(self.ips.0);
            buf[8..10].copy_from_slice(ports.1);
            buf[10..12].copy_from_slice(ports.0);
        } else {
            buf[0..4].copy_from_slice(self.ips.0);
            buf[4..8].copy_from_slice(self.ips.1);
            buf[8..10].copy_from_slice(ports.0);
            buf[10..12].copy_from_slice(ports.1);
        }

        let mut h = DefaultHasher::new();
        buf.hash(&mut h);
        Ok(h.finish())
    }
}

pub type ConnRecordStore = Arc<Mutex<HashMap<u64, ConnRecord>>>;

pub fn new_conn_store() -> ConnRecordStore {
    Arc::new(Mutex::new(HashMap::new()))
}

pub struct SimplePktFilter {
    reverse_dir: bool, // In which direction packet is travaling - for id purpose
    conns: ConnRecordStore,
    traiters: Vec<String>,
}

impl SimplePktFilter {
    pub fn new(reverse_dir: bool, conn_store: ConnRecordStore) -> impl PktFilter {
        SimplePktFilter {
            reverse_dir,
            conns: conn_store,
            traiters: Vec::from(["youtube".to_string()]),
        }
    }

    fn filter_tls(&self, pkt: &[u8], conn: &mut ConnRecord) -> Result<()> {
        println!("Got to tls!!");
        Ok(())
    }

    fn filter_tcp<'a>(&self, pkt: &'a [u8], mut id: ConnId<'a>) -> Result<()> {
        println!("-----");
        let hlen = usize::from(pkt[12] & 0x0f);
        let ack = (pkt[13] & 0x02) == 1;
        let syn = (pkt[13] & 0x0f) == 1;

        println!("{hlen} {ack} {syn}");

        // Get connection id
        id.set_ports(&pkt[0..2], &pkt[2..4]);
        let id = id.hash(self.reverse_dir)?;

        println!("id: {id}");

        // Get conn record
        let mut conns = self.conns.lock().map_err(|_| anyhow!("lock poisoned"))?;
        let mut conn = match conns.get(&id) {
            Some(c) => c.clone(),
            None => ConnRecord {
                i: 0,
                tcp: TcpState::Empty,
                tls: TlsState::Empty,
            },
        };

        // Resolve tcp state
        conn.tcp = match conn.tcp {
            TcpState::Empty if syn && !ack => TcpState::TcpSyn,
            TcpState::TcpSyn if !syn && ack => TcpState::TcpAck,
            TcpState::TcpAck if syn && ack => TcpState::TcpSynAck,
            TcpState::TcpSynAck => TcpState::Data,
            _ => TcpState::Invalid,
        };

        println!("TCP conn({}): {:?}", self.reverse_dir, conn);

        // Send it to tls check there is payload
        if conn.tcp == TcpState::TcpSynAck || conn.tcp == TcpState::Data && pkt.len() - hlen > 0 {
            self.filter_tls(&pkt[hlen..], &mut conn)?;
        }

        conn.i += 1;
        conns.insert(id, conn);

        println!("-----");
        Ok(())
    }

    fn filter_udp(&self, pkt: &[u8]) -> Result<()> {
        // println!("udp");
        let dst_port = u16::from_be_bytes([pkt[2], pkt[3]]);

        let pkt = &pkt[UDP_HEADER_SIZE..];

        if dst_port == 53 && pkt.len() >= 12 {
            self.filter_dns(pkt).with_context(|| "DNS")?;
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

                let id = ConnId::new(&pkt[12..16], &pkt[16..20]);

                let pkt = &pkt[header_len..];
                match proto {
                    // UDP header 8 bytes
                    17 if pkt.len() >= UDP_HEADER_SIZE => {
                        return self.filter_udp(pkt);
                    }
                    // TCP header 20 bytes
                    6 if pkt.len() >= TCP_HEADER_MIN_SIZE => {
                        return self.filter_tcp(pkt, id);
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

fn hash<T: Hash>(value: &T) -> u64 {
    let mut h = DefaultHasher::new();
    value.hash(&mut h);
    h.finish()
}
