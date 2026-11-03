use anyhow::{Context, Result, anyhow, bail};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::{collections::HashMap, sync::Mutex};

const IP_HEADER_MIN_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const DNS_HEADER_SIZE: usize = 12;
const TCP_HEADER_MIN_SIZE: usize = 20;
const TLS_RECORD_HEADER_SIZE: usize = 5;
const TLS_HANDSHAKE_MIN_SIZE: usize = 4;

pub trait PktFilter {
    fn filter(&self, pkt: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpState {
    Invalid,
    Empty,
    Syn,
    Ack,
    SynAck,
    Data,
    Fin1,
    Fin1Ack,
    Fin2,
    Closed,
}

#[derive(Debug, Clone)]
pub struct ConnRecord {
    id: u64,
    i: usize, // Packet counter -  with data
    tcp: TcpState,
    tls: bool, // Is tls detected
    traiter: bool,
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

#[derive(Debug, Clone)]
pub struct Config {
    pub dns: bool,
    pub sni: bool,
}

pub struct SimplePktFilter {
    pub reverse_dir: bool, // In which direction packet is travaling - for id purpose
    cfg: Config,

    conns: ConnRecordStore,
    traiters: Vec<String>,
}

impl SimplePktFilter {
    pub fn new(cfg: Config, conn_store: ConnRecordStore, reverse_dir: bool) -> impl PktFilter {
        SimplePktFilter {
            cfg,
            reverse_dir,

            conns: conn_store,
            traiters: Vec::from(["youtube".to_string(), "google.com".to_string()]),
        }
    }

    fn find_traiters(&self, suspect: &str) -> Option<&str> {
        for s in self.traiters.iter() {
            if suspect.contains(s) {
                return Some(s);
            }
        }
        None
    }

    fn filter_tls_handshake_clienthello(&self, pkt: &[u8], conn: &mut ConnRecord) -> Result<()> {
        // Skip data until extensions
        let mut i = 0usize; // Just for ease of use and uniformness

        // Version + Random
        i += 32 + 2;

        // Skip session ID and its len
        if i >= pkt.len() {
            println!("tls clienthello is too short 1");
            return Ok(());
        }
        let sid_len = usize::from(pkt[i]);
        i += sid_len + 1;

        // Skip sipher suites and their len
        if i + 1 >= pkt.len() {
            println!("tls clienthello is too short 2");
            return Ok(());
        }
        let ss_len = usize::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
        i += ss_len + 2;

        // Skip compression methods and their len
        if i >= pkt.len() {
            println!("tls clienthello is too short 3");
            return Ok(());
        }
        let methods_len = usize::from(pkt[i]);
        i += methods_len + 1;

        // Read extensions len
        if i >= pkt.len() {
            println!("tls clienthello is too short 4");
            return Ok(());
        }
        let ext_len = usize::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
        i += 2;
        let end = (i + ext_len).min(pkt.len());

        while i + 4 < end {
            let t = usize::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
            let len = usize::from(u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]));

            // println!("looking extension: {t}");

            i += 4;

            // server_name
            if t == 0x0000 {
                let pkt = &pkt[i..i + len];
                if pkt.len() < 5 || pkt[2] != 0 {
                    println!("unluck");
                    return Ok(());
                }
                let n = usize::from(u16::from_be_bytes([pkt[3], pkt[4]]));
                let name = &pkt[5..5 + n];
                let Ok(host) = std::str::from_utf8(name) else {
                    println!("Failed to prase str");
                    return Ok(());
                };
                if self.cfg.sni {
                    if let Some(host) = self.find_traiters(host) {
                        conn.traiter = true;

                        bail!("found traiter host: {host}");
                    };
                }
                println!("SNI HOST: {host}");
            }

            i += len;
        }

        Ok(())
    }

    fn filter_tls_handshake(&self, pkt: &[u8], conn: &mut ConnRecord) -> Result<()> {
        if pkt.len() < TLS_HANDSHAKE_MIN_SIZE {
            return Ok(());
        }
        let msg = pkt[0];
        let len = usize::from_be_bytes([0, 0, 0, 0, 0, pkt[1], pkt[2], pkt[3]]);

        if len > pkt.len() - 4 {
            println!("tls len is less then the package")
        }

        // Tmp
        match msg {
            0x01 => {
                println!("ClientHello");
                self.filter_tls_handshake_clienthello(&pkt[4..], conn)?;
            }
            0x02 => println!("ServerHello"),
            0x04 => println!("SessionTicket"),
            0x05 => println!("EndOfEarlyData"),
            0x08 => println!("EncryptedExtensions"),
            0x0b => println!("Certificate"),
            0x0d => println!("CertificateRequest"),
            0x0f => println!("CertificateVerify"),
            0x14 => println!("Fnished"),
            0x18 => println!("KeyUpdate"),
            _ => (),
        }

        Ok(())
    }

    fn filter_app(&self, pkt: &[u8], conn: &mut ConnRecord) -> Result<()> {
        // println!("APP...");
        if conn.i == 0 {
            println!("Looking for tls");
            // Look for ClientHello
            if pkt.len() < TLS_RECORD_HEADER_SIZE {
                return Ok(());
            }

            let content_type = pkt[0];
            let (v1, v2) = (pkt[1], pkt[2]);
            let len = usize::from(u16::from_be_bytes([pkt[3], pkt[4]]));

            if content_type == 0x16 && v1 == 0x03 && v2 <= 4 {
                // Handshake
                println!("TLS detected!!");
                conn.tls = true;
                println!("TLS Handshake Len: {len}");
                if TLS_RECORD_HEADER_SIZE + len > pkt.len() {
                    println!(
                        "tls record {} is longer then pkt len {}",
                        TLS_RECORD_HEADER_SIZE + len,
                        pkt.len()
                    );
                }
                self.filter_tls_handshake(
                    &pkt[TLS_RECORD_HEADER_SIZE..(TLS_RECORD_HEADER_SIZE + len).min(pkt.len())],
                    conn,
                )?;
            }
            return Ok(());
        }

        if conn.tls {
            if pkt.len() < TLS_RECORD_HEADER_SIZE {
                return Ok(());
            }

            let content_type = pkt[0];
            match content_type {
                0x14 => println!("TLS change spypher"),
                0x15 => println!("TLS alert"),
                0x16 => println!("TLS handshake"),
                0x17 => println!("TLS application data"),
                _ => println!("TLS unknown"),
            }
        }

        // if conn.i != 0 {
        //     println!("Unencrypted data #{}", conn.i);
        //     return Ok(());
        // }

        // println!("No ClientHello detected");
        Ok(())
    }

    fn filter_tcp<'a>(&self, pkt: &'a [u8], mut id: ConnId<'a>) -> Result<()> {
        // println!("-----");
        let hlen = usize::from(pkt[12] >> 4) * 4;
        let ack = (pkt[13] & 0x10) != 0;
        let syn = (pkt[13] & 0x02) != 0;
        let fin = (pkt[13] & 0x01) != 0;

        // Get connection id
        id.set_ports(&pkt[0..2], &pkt[2..4]);
        let id = id.hash(self.reverse_dir)?;

        // Get conn record
        let mut conns = self.conns.lock().map_err(|_| anyhow!("lock poisoned"))?;
        let mut conn = match conns.get(&id) {
            Some(c) => c.clone(),
            None => {
                println!("New TLS conn {id}");
                ConnRecord {
                    id: id,
                    i: 0,
                    tcp: TcpState::Empty,
                    tls: false,
                    traiter: false,
                }
            }
        };

        if conn.traiter {
            bail!("traiter");
        }

        // Resolve tcp state
        conn.tcp = match conn.tcp {
            // Handshake
            TcpState::Empty if syn && !ack => TcpState::Syn,
            TcpState::Syn if syn && ack => TcpState::SynAck,
            TcpState::SynAck if !syn && ack => TcpState::Ack,
            TcpState::Ack if ack => TcpState::Data,
            // Shutdown
            TcpState::Data if fin && ack => TcpState::Fin1,
            TcpState::Fin1 if fin && ack => TcpState::Fin2,
            TcpState::Fin1 if ack => TcpState::Fin1Ack,
            TcpState::Fin1Ack if fin && ack => TcpState::Fin2,
            TcpState::Fin2 if ack => TcpState::Closed,

            // Data transfer and invalid
            TcpState::Data if ack => TcpState::Data,
            _ => TcpState::Invalid,
        };

        // println!("TCP conn(dir: {}): {:?}", self.reverse_dir, conn);

        // Send it to tls check there is payload

        let mut res: Result<()> = Ok(());

        if pkt.len() - hlen > 0 {
            res = self.filter_app(&pkt[hlen..], &mut conn);
            conn.i += 1;
        }

        conns.insert(id, conn);
        res
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
            if self.cfg.dns {
                if let Some(host) = self.find_traiters(&addr) {
                    bail!("found traiter host: {host}");
                };
            }
            println!("DNS: {addr}");
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
