//! Packet statistics: protocol hierarchy and distribution, traffic over
//! time, packet sizes, talkers, conversations and ports.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::capture::Packet;
use crate::dissect::{ACK, FIN, RST, SYN};

/// Distinct talkers / conversations / ports counted.
const MAX_KEYS: usize = 100_000;
const MAX_BUCKETS: usize = 240;

/// Packet size classes: (label, largest size).
pub const SIZES: [(&str, u32); 8] = [
    ("≤ 64", 64),
    ("65–128", 128),
    ("129–256", 256),
    ("257–512", 512),
    ("513–1024", 1024),
    ("1025–1518", 1518),
    ("1519–9018", 9018),
    ("> 9018", u32::MAX),
];

#[derive(Clone, Debug, Default)]
pub struct Node {
    pub packets: u64,
    pub bytes: u64,
    pub children: BTreeMap<&'static str, Node>,
}

/// One row of the flattened hierarchy.
pub struct HierRow {
    pub depth: usize,
    pub name: &'static str,
    pub packets: u64,
    pub bytes: u64,
}

impl Node {
    fn flatten(&self, depth: usize, out: &mut Vec<HierRow>) {
        let mut kids: Vec<_> = self.children.iter().collect();
        kids.sort_by_key(|(n, c)| (std::cmp::Reverse(c.packets), **n));
        for (name, c) in kids {
            out.push(HierRow {
                depth,
                name,
                packets: c.packets,
                bytes: c.bytes,
            });
            c.flatten(depth + 1, out);
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Talker {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Conv {
    pub packets: u64,
    pub bytes: u64,
    pub first: f64,
    pub last: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Bucket {
    pub packets: u64,
    pub bytes: u64,
}

/// Traffic over time in equal buckets that widen as the capture grows.
#[derive(Clone, Debug)]
pub struct Series {
    pub width: f64,
    pub start: f64,
    pub buckets: Vec<Bucket>,
}

impl Default for Series {
    fn default() -> Self {
        Series {
            width: 0.1,
            start: f64::NAN,
            buckets: Vec::new(),
        }
    }
}

impl Series {
    fn add(&mut self, ts: f64, len: u64) {
        if !ts.is_finite() {
            return;
        }
        if self.start.is_nan() {
            self.start = ts;
        }
        // Slightly out-of-order timestamps count in the first bucket.
        let rel = (ts - self.start).max(0.0);
        while rel / self.width >= MAX_BUCKETS as f64 {
            self.width *= 2.0;
            let merged = self
                .buckets
                .chunks(2)
                .map(|c| Bucket {
                    packets: c.iter().map(|b| b.packets).sum(),
                    bytes: c.iter().map(|b| b.bytes).sum(),
                })
                .collect();
            self.buckets = merged;
        }
        let i = (rel / self.width) as usize;
        if self.buckets.len() <= i {
            self.buckets.resize(i + 1, Bucket::default());
        }
        self.buckets[i].packets += 1;
        self.buckets[i].bytes += len;
    }
}

/// Address and port (0 = none).
pub type Endpoint = (IpAddr, u16);

pub fn endpoint(e: Endpoint) -> String {
    match e {
        (ip, 0) => ip.to_string(),
        e => crate::streams::endpoint(e),
    }
}

#[derive(Default)]
pub struct PacketStats {
    pub packets: u64,
    pub bytes: u64,
    pub first: Option<f64>,
    pub last: f64,
    pub root: Node,
    /// Innermost protocol → packets, bytes.
    pub protos: HashMap<String, (u64, u64)>,
    pub talkers: HashMap<IpAddr, Talker>,
    pub convs: HashMap<(Endpoint, Endpoint, &'static str), Conv>,
    /// (transport, service port) → packets, bytes.
    pub ports: HashMap<(&'static str, u16), (u64, u64)>,
    pub sizes: [u64; 8],
    pub min_size: u32,
    pub max_size: u32,
    pub unicast: u64,
    pub multicast: u64,
    pub broadcast: u64,
    /// SYN, SYN/ACK, FIN, RST
    pub flags: [u64; 4],
    pub by_signature: u64,
    pub by_port: u64,
    pub series: Series,
}

impl PacketStats {
    pub fn add(&mut self, p: &Packet) {
        let len = p.len as u64;
        self.packets += 1;
        self.bytes += len;
        self.first = Some(self.first.map_or(p.ts, |f| f.min(p.ts)));
        self.last = self.last.max(p.ts);
        self.series.add(p.ts, len);
        let i = SIZES.iter().position(|(_, m)| p.len <= *m).unwrap_or(7);
        self.sizes[i] += 1;
        self.max_size = self.max_size.max(p.len);
        self.min_size = if self.packets == 1 {
            p.len
        } else {
            self.min_size.min(p.len)
        };

        let mut n = &mut self.root;
        for name in &p.d.path {
            n = n.children.entry(name).or_default();
            n.packets += 1;
            n.bytes += len;
        }
        match self.protos.get_mut(&p.d.proto) {
            Some(e) => {
                e.0 += 1;
                e.1 += len;
            }
            None => {
                self.protos.insert(p.d.proto.clone(), (1, len));
            }
        }
        match p.d.how {
            Some(crate::appproto::How::Signature) => self.by_signature += 1,
            Some(_) => self.by_port += 1,
            None => {}
        }

        match &p.d.eth_dst {
            Some(m) if m == "ff:ff:ff:ff:ff:ff" => self.broadcast += 1,
            // Lowest bit of the first byte: group address.
            Some(m) if u8::from_str_radix(&m[..2], 16).is_ok_and(|b| b & 1 == 1) => {
                self.multicast += 1
            }
            Some(_) => self.unicast += 1,
            None => match p.d.dst_ip {
                Some(ip) if ip.is_multicast() => self.multicast += 1,
                Some(IpAddr::V4(ip)) if ip.is_broadcast() => self.broadcast += 1,
                _ => self.unicast += 1,
            },
        }
        if let Some(f) = p.d.tcp_flags {
            if f & SYN != 0 {
                self.flags[(f & ACK != 0) as usize] += 1;
            }
            if f & FIN != 0 {
                self.flags[2] += 1;
            }
            if f & RST != 0 {
                self.flags[3] += 1;
            }
        }
        let (Some(s), Some(d)) = (p.d.src_ip, p.d.dst_ip) else {
            return;
        };
        for (ip, tx) in [(s, true), (d, false)] {
            if self.talkers.len() >= MAX_KEYS && !self.talkers.contains_key(&ip) {
                continue;
            }
            let t = self.talkers.entry(ip).or_default();
            if tx {
                t.tx_packets += 1;
                t.tx_bytes += len;
            } else {
                t.rx_packets += 1;
                t.rx_bytes += len;
            }
        }
        let a = (s, p.d.src_port.unwrap_or(0));
        let b = (d, p.d.dst_port.unwrap_or(0));
        let t = p.d.transport.unwrap_or("IP");
        // Direction-independent key.
        let key = if a <= b { (a, b, t) } else { (b, a, t) };
        if self.convs.len() < MAX_KEYS || self.convs.contains_key(&key) {
            let c = self.convs.entry(key).or_insert(Conv {
                first: p.ts,
                ..Default::default()
            });
            c.packets += 1;
            c.bytes += len;
            c.last = c.last.max(p.ts);
        }
        if let (Some(sp), Some(dp)) = (p.d.src_port, p.d.dst_port) {
            // The lower port is taken as the service.
            let k = (t, sp.min(dp));
            if self.ports.len() < MAX_KEYS || self.ports.contains_key(&k) {
                let e = self.ports.entry(k).or_default();
                e.0 += 1;
                e.1 += len;
            }
        }
    }

    pub fn duration(&self) -> f64 {
        self.first.map(|f| (self.last - f).max(0.0)).unwrap_or(0.0)
    }

    pub fn hierarchy(&self) -> Vec<HierRow> {
        let mut out = Vec::new();
        self.root.flatten(0, &mut out);
        out
    }

    /// Protocols by packet count.
    pub fn distribution(&self) -> Vec<(&str, u64, u64)> {
        let mut v: Vec<_> = self
            .protos
            .iter()
            .map(|(n, (p, b))| (n.as_str(), *p, *b))
            .collect();
        v.sort_by_key(|x| (std::cmp::Reverse(x.1), x.0));
        v
    }

    /// Busiest bucket as packets/s and bits/s.
    pub fn peak(&self) -> (f64, f64) {
        let w = self.series.width;
        let max = |f: fn(&Bucket) -> u64| self.series.buckets.iter().map(f).max().unwrap_or(0);
        (
            max(|b| b.packets) as f64 / w,
            max(|b| b.bytes) as f64 * 8.0 / w,
        )
    }

    /// Plain-text report (Copy button, command line).
    pub fn report(&self) -> String {
        use crate::capture_view::{human_bits, human_bytes};
        use std::fmt::Write;
        let mut o = String::new();
        let dur = self.duration();
        let pct = |n: u64| n as f64 * 100.0 / self.packets.max(1) as f64;
        let _ = writeln!(
            o,
            "Packets {}   Bytes {}   Duration {dur:.3} s",
            self.packets, self.bytes
        );
        if dur > 0.0 {
            let (pp, pb) = self.peak();
            let _ = writeln!(
                o,
                "Average {:.1} pkt/s, {}/s   Peak {pp:.0} pkt/s, {}/s",
                self.packets as f64 / dur,
                human_bits(self.bytes as f64 * 8.0 / dur),
                human_bits(pb)
            );
        }
        let _ = writeln!(
            o,
            "Unicast {}   Multicast {}   Broadcast {}",
            self.unicast, self.multicast, self.broadcast
        );
        let _ = writeln!(
            o,
            "Application protocols identified by content {}, by port only {}",
            self.by_signature, self.by_port
        );
        let _ = writeln!(o, "\nProtocol hierarchy");
        for r in self.hierarchy() {
            let name = format!("{}{}", "  ".repeat(r.depth + 1), r.name);
            let _ = writeln!(
                o,
                "{name:<36} {:>9} {:>6.1}% {:>10}",
                r.packets,
                pct(r.packets),
                human_bytes(r.bytes)
            );
        }
        let _ = writeln!(o, "\nPacket sizes");
        for ((n, _), c) in SIZES.iter().zip(self.sizes) {
            let _ = writeln!(o, "  {n:<34} {c:>9} {:>6.1}%", pct(c));
        }
        let _ = writeln!(o, "\nTop talkers");
        let mut t: Vec<_> = self.talkers.iter().collect();
        t.sort_by_key(|(ip, t)| (std::cmp::Reverse(t.tx_bytes + t.rx_bytes), **ip));
        for (ip, t) in t.into_iter().take(10) {
            let _ = writeln!(
                o,
                "  {:<40} sent {:>10}  received {:>10}",
                ip.to_string(),
                human_bytes(t.tx_bytes),
                human_bytes(t.rx_bytes)
            );
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn series_widens_without_losing_packets() {
        let mut s = Series::default();
        for i in 0..5000 {
            s.add(1000.0 + i as f64 * 0.37, 10);
        }
        // A timestamp before the start must not underflow.
        s.add(999.0, 10);
        assert!(s.buckets.len() <= MAX_BUCKETS);
        assert_eq!(s.buckets.iter().map(|b| b.packets).sum::<u64>(), 5001);
        assert_eq!(s.buckets.iter().map(|b| b.bytes).sum::<u64>(), 50010);
    }

    #[test]
    fn hierarchy_sizes_and_cast() {
        use crate::dissect::SYN;
        let mut st = PacketStats::default();
        for (no, f) in [
            crate::streams::tests::frame(true, 1, 0, SYN, b""),
            crate::streams::tests::frame(true, 2, 0, ACK, b"GET / HTTP/1.1\r\n\r\n"),
        ]
        .into_iter()
        .enumerate()
        {
            st.add(&Packet {
                no,
                ts: no as f64,
                len: f.len() as u32,
                linktype: 1,
                d: crate::dissect::dissect(1, &f),
                data: f,
                ..Default::default()
            });
        }
        let rows = st.hierarchy();
        let names: Vec<_> = rows.iter().map(|r| (r.depth, r.name, r.packets)).collect();
        assert_eq!(
            names,
            [
                (0, "Ethernet", 2),
                (1, "IPv4", 2),
                (2, "TCP", 2),
                (3, "HTTP", 1)
            ]
        );
        assert_eq!(st.flags[0], 1);
        assert_eq!(st.ports[&("TCP", 80)].0, 2);
        assert_eq!(st.unicast, 2);
        assert_eq!(st.sizes.iter().sum::<u64>(), 2);
        assert_eq!(st.by_signature, 1);
        assert!(st.report().contains("HTTP"));
    }
}
