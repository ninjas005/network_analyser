//! Packet dissector for the capture analyser: link layer (Ethernet, VLAN,
//! MPLS, PPPoE, Linux cooked, loopback, raw IP), ARP, LLDP, IPv4/IPv6,
//! ICMP/ICMPv6, TCP, UDP and tunnels (GRE, IP-in-IP, VXLAN). Application
//! protocols are in [`crate::appproto`].

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::appproto::{self, App, DnsMsg, How};

thread_local! {
    /// Skip the layer fields (see [`dissect_brief`]).
    static BRIEF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Encapsulation levels decoded before giving up.
const MAX_DEPTH: usize = 12;

#[derive(Clone, Debug, Default)]
pub struct Layer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

impl Layer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
        }
    }
    pub fn f(&mut self, k: &str, v: impl ToString) -> &mut Self {
        if !BRIEF.get() {
            self.fields.push((k.to_string(), v.to_string()));
        }
        self
    }
}

/// TCP header values needed for reassembly and handshake analysis.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TcpInfo {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// Payload length on the wire (may be more than was captured).
    pub len: u32,
    pub opts: TcpOpts,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TcpOpts {
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_ok: bool,
    pub sack_blocks: u8,
    pub timestamps: bool,
    pub fast_open: bool,
    pub mptcp: bool,
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

#[derive(Clone, Debug, Default)]
pub struct Dissected {
    pub src: String,
    pub dst: String,
    /// Highest decoded protocol, e.g. "TCP", "DNS", "Modbus/TCP".
    pub proto: String,
    pub info: String,
    pub layers: Vec<Layer>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// "TCP" / "UDP" / "ICMP"… for conversation grouping.
    pub transport: Option<&'static str>,
    pub eth_src: Option<String>,
    pub eth_dst: Option<String>,
    pub tcp_flags: Option<u8>,
    /// Protocols from the outside in, for the protocol hierarchy.
    pub path: Vec<&'static str>,
    pub tcp: Option<TcpInfo>,
    /// Captured TCP / UDP payload as (offset, length) in the frame.
    pub payload: (u32, u32),
    /// How the application protocol was recognised.
    pub how: Option<How>,
    pub dns: Option<Box<DnsMsg>>,
    /// Start address of the frame, to find the payload offset.
    pub(crate) base: usize,
    pub(crate) depth: usize,
}

impl Dissected {
    fn set(&mut self, proto: &'static str, info: String) {
        self.proto = proto.to_string();
        self.info = info;
        if self.path.last() != Some(&proto) {
            self.path.push(proto);
        }
    }

    fn app(&mut self, a: App) {
        self.layers.extend(a.layers);
        self.how = Some(a.how);
        self.dns = a.dns;
        self.set(a.proto, a.info);
    }

    fn mark_payload(&mut self, p: &[u8]) {
        self.payload = (
            (p.as_ptr() as usize).wrapping_sub(self.base) as u32,
            p.len() as u32,
        );
    }

    /// Enter another encapsulation level; false when nested too deeply.
    fn enter(&mut self, name: &'static str) -> bool {
        self.depth += 1;
        self.path.push(name);
        self.depth <= MAX_DEPTH
    }
}

pub fn linktype_name(lt: i32) -> &'static str {
    match lt {
        0 => "BSD loopback",
        1 => "Ethernet",
        12 | 14 | 101 => "Raw IP",
        105 => "802.11",
        113 => "Linux cooked",
        127 => "802.11 radiotap",
        228 => "Raw IPv4",
        229 => "Raw IPv6",
        276 => "Linux cooked v2",
        _ => "Unknown link type",
    }
}

/// [`dissect`] without the layer details: addresses, protocol, summary and
/// everything the analysis needs, at a fraction of the cost.
pub fn dissect_brief(linktype: i32, data: &[u8]) -> Dissected {
    BRIEF.set(true);
    let mut d = dissect(linktype, data);
    BRIEF.set(false);
    d.layers = Vec::new();
    d
}

pub fn dissect(linktype: i32, data: &[u8]) -> Dissected {
    let mut d = Dissected {
        base: data.as_ptr() as usize,
        proto: linktype_name(linktype).into(),
        info: format!("{} bytes", data.len()),
        ..Default::default()
    };
    match linktype {
        1 => ethernet(data, &mut d),
        0 => {
            // 4-byte address family in host byte order of the capturing machine.
            if data.len() >= 4 {
                let fam = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let fam = if fam > 0xffff { fam.swap_bytes() } else { fam };
                let mut l = Layer::new("Loopback");
                l.f("Family", fam);
                d.layers.push(l);
                d.path.push("Loopback");
                match fam {
                    2 => ipv4(&data[4..], &mut d),
                    24 | 28 | 30 => ipv6(&data[4..], &mut d),
                    _ => {}
                }
            }
        }
        12 | 14 | 101 | 228 | 229 => raw_ip(data, &mut d),
        113 => {
            if data.len() >= 16 {
                let mut l = Layer::new("Linux cooked capture");
                l.f(
                    "Packet type",
                    sll_pkttype(u16::from_be_bytes([data[0], data[1]])),
                );
                let alen = (u16::from_be_bytes([data[4], data[5]]) as usize).min(8);
                if alen == 6 {
                    l.f("Source", mac(&data[6..12]));
                    d.src = mac(&data[6..12]);
                }
                d.layers.push(l);
                d.path.push("Linux cooked");
                ethertype(
                    u16::from_be_bytes([data[14], data[15]]),
                    &data[16..],
                    &mut d,
                );
            }
        }
        276 if data.len() >= 20 => {
            let mut l = Layer::new("Linux cooked capture v2");
            l.f(
                "Interface index",
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            );
            l.f("Packet type", sll_pkttype(data[10] as u16));
            if data[11] == 6 {
                l.f("Source", mac(&data[12..18]));
                d.src = mac(&data[12..18]);
            }
            d.layers.push(l);
            d.path.push("Linux cooked");
            ethertype(u16::from_be_bytes([data[0], data[1]]), &data[20..], &mut d);
        }
        _ => {}
    }
    if d.path.is_empty() {
        d.path.push(linktype_name(linktype));
    }
    d
}

/// Payload bytes of a dissected frame.
#[cfg(test)]
pub fn payload<'a>(d: &Dissected, data: &'a [u8]) -> &'a [u8] {
    let (o, l) = (d.payload.0 as usize, d.payload.1 as usize);
    data.get(o..o + l).unwrap_or(&[])
}

fn sll_pkttype(t: u16) -> &'static str {
    match t {
        0 => "to us",
        1 => "broadcast",
        2 => "multicast",
        3 => "to another host",
        4 => "sent by us",
        _ => "unknown",
    }
}

fn raw_ip(data: &[u8], d: &mut Dissected) {
    match data.first().map(|b| b >> 4) {
        Some(4) => ipv4(data, d),
        Some(6) => ipv6(data, d),
        _ => {}
    }
}

fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn ethernet(data: &[u8], d: &mut Dissected) {
    if data.len() < 14 {
        d.set("Ethernet", "truncated frame".into());
        return;
    }
    let dst = mac(&data[0..6]);
    let src = mac(&data[6..12]);
    d.path.push("Ethernet");
    let mut l = Layer::new("Ethernet II");
    l.f("Destination", &dst).f("Source", &src);
    if !BRIEF.get()
        && let Some(v) = crate::netinfo::mac_vendor(&src)
    {
        l.f("Source vendor", v);
    }
    d.eth_src = Some(src.clone());
    d.eth_dst = Some(dst.clone());
    d.src = src;
    d.dst = if data[0..6] == [0xff; 6] {
        "Broadcast".into()
    } else {
        dst
    };
    let mut et = be16(data, 12);
    let mut off = 14;
    let mut vlan = false;
    while (et == 0x8100 || et == 0x88a8) && data.len() >= off + 4 {
        l.f("VLAN", be16(data, off) & 0x0fff)
            .f("VLAN priority", data[off] >> 5);
        vlan = true;
        et = be16(data, off + 2);
        off += 4;
    }
    l.f("Type", format!("0x{et:04x}"));
    d.layers.push(l);
    if vlan {
        d.path.push("VLAN");
    }
    if et <= 1500 {
        // 802.3 length field: LLC follows (STP, CDP…).
        let mut llc = Layer::new("802.3 LLC");
        llc.f("Length", et);
        if data.len() >= off + 3 {
            llc.f("DSAP", format!("0x{:02x}", data[off]))
                .f("SSAP", format!("0x{:02x}", data[off + 1]));
            if data[off] == 0x42 {
                d.layers.push(llc);
                stp(&data[off + 3..], d);
                return;
            }
            // SNAP, Cisco OUI
            if data[off] == 0xaa && data.get(off + 3..off + 6) == Some(&[0, 0, 0x0c]) {
                d.layers.push(llc);
                match data.get(off + 6..off + 8) {
                    Some([0x20, 0x00]) => d.set("CDP", "Cisco Discovery Protocol".into()),
                    Some([0x01, 0x0b]) => d.set("STP", "Per-VLAN Spanning Tree BPDU".into()),
                    _ => d.set("LLC", "Cisco SNAP frame".into()),
                }
                return;
            }
        }
        d.layers.push(llc);
        d.set("LLC", format!("802.3 frame, length {et}"));
        return;
    }
    ethertype(et, &data[off..], d);
}

fn stp(b: &[u8], d: &mut Dissected) {
    let kind = match (b.get(2), b.get(3)) {
        (_, Some(0x80)) => "Topology change",
        (Some(0), _) => "Spanning Tree BPDU",
        (Some(2), _) => "Rapid Spanning Tree BPDU",
        (Some(3), _) => "Multiple Spanning Tree BPDU",
        _ => "Spanning Tree BPDU",
    };
    let mut info = kind.to_string();
    if b.len() >= 25 {
        let bridge = |o: usize| format!("{}/{}", be16(b, o), mac(&b[o + 2..o + 8]));
        let mut l = Layer::new("Spanning Tree");
        l.f("Root bridge", bridge(5))
            .f("Root path cost", be32(b, 13))
            .f("Bridge", bridge(17));
        let _ = write!(info, ", root {}", bridge(5));
        d.layers.push(l);
    }
    d.set("STP", info);
}

fn lldp(mut b: &[u8], d: &mut Dissected) {
    let mut l = Layer::new("LLDP");
    let mut info = String::new();
    while b.len() >= 2 {
        let h = be16(b, 0);
        let (t, n) = (h >> 9, (h & 0x1ff) as usize);
        let Some(v) = b.get(2..2 + n) else { break };
        let text = || {
            String::from_utf8_lossy(v)
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
        };
        let id = |mac_type: u8| match v.first() {
            Some(x) if *x == mac_type && v.len() == 7 => mac(&v[1..]),
            Some(_) => String::from_utf8_lossy(&v[1..])
                .chars()
                .filter(|c| !c.is_control())
                .collect(),
            None => String::new(),
        };
        match t {
            0 => break,
            1 => {
                l.f("Chassis", id(4));
            }
            2 => {
                l.f("Port", id(3));
            }
            3 if n == 2 => {
                l.f("TTL", be16(v, 0));
            }
            4 => {
                l.f("Port description", text());
            }
            5 => {
                info = text();
                l.f("System name", &info);
            }
            6 => {
                l.f("System description", text());
            }
            _ => {}
        }
        b = &b[2 + n..];
    }
    d.layers.push(l);
    d.set(
        "LLDP",
        if info.is_empty() {
            "Link Layer Discovery Protocol".into()
        } else {
            format!("System {info}")
        },
    );
}

fn pppoe(et: u16, b: &[u8], d: &mut Dissected) {
    if et == 0x8863 {
        let t = match b.get(1) {
            Some(0x09) => "Discovery initiation",
            Some(0x07) => "Discovery offer",
            Some(0x19) => "Session request",
            Some(0x65) => "Session confirmation",
            Some(0xa7) => "Terminate",
            _ => "Discovery",
        };
        return d.set("PPPoE", t.into());
    }
    if b.len() < 8 || !d.enter("PPPoE") {
        return d.set("PPPoE", "PPP over Ethernet".into());
    }
    let mut l = Layer::new("PPPoE session");
    l.f("Session", format!("0x{:04x}", be16(b, 2)));
    d.layers.push(l);
    match be16(b, 6) {
        0x0021 => ipv4(&b[8..], d),
        0x0057 => ipv6(&b[8..], d),
        0xc021 => d.set("PPP", "Link control (LCP)".into()),
        0xc023 => d.set("PPP", "Authentication (PAP, clear text)".into()),
        0xc223 => d.set("PPP", "Authentication (CHAP)".into()),
        0x8021 | 0x8057 => d.set("PPP", "Network control (IPCP)".into()),
        p => d.set("PPP", format!("protocol 0x{p:04x}")),
    }
}

fn mpls(mut b: &[u8], d: &mut Dissected) {
    let mut l = Layer::new("MPLS");
    let mut bottom = false;
    while b.len() >= 4 && !bottom {
        let e = be32(b, 0);
        l.f("Label", format!("{} (TTL {})", e >> 12, e & 0xff));
        bottom = e & 0x100 != 0;
        b = &b[4..];
    }
    d.layers.push(l);
    if !d.enter("MPLS") {
        return;
    }
    d.proto = "MPLS".into();
    d.info = "MPLS".into();
    raw_ip(b, d);
}

fn ethertype(et: u16, data: &[u8], d: &mut Dissected) {
    if d.depth > MAX_DEPTH {
        return;
    }
    match et {
        0x0800 => ipv4(data, d),
        0x86dd => ipv6(data, d),
        0x0806 => arp(data, d),
        0x88cc => lldp(data, d),
        0x8847 | 0x8848 => mpls(data, d),
        0x6558 => ethernet(data, d),
        0x88e5 => d.set("MACsec", "encrypted frame".into()),
        0x8809 => d.set("LACP", "Slow protocols (LACP)".into()),
        0x888e => d.set("EAPOL", "802.1X authentication".into()),
        0x8892 => d.set("PROFINET", "PROFINET real-time".into()),
        0x88a4 => d.set("EtherCAT", "EtherCAT frame".into()),
        0x8863 | 0x8864 => pppoe(et, data, d),
        0x88f7 => d.set("PTP", "Precision Time Protocol".into()),
        _ => d.set("Ethernet", format!("EtherType 0x{et:04x}")),
    }
}

fn arp(data: &[u8], d: &mut Dissected) {
    if data.len() < 28 {
        d.set("ARP", "truncated".into());
        return;
    }
    let op = be16(data, 6);
    let sha = mac(&data[8..14]);
    let spa = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
    let tpa = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
    let mut l = Layer::new("ARP");
    l.f(
        "Opcode",
        if op == 1 {
            "request (1)"
        } else if op == 2 {
            "reply (2)"
        } else {
            "other"
        },
    )
    .f("Sender MAC", &sha)
    .f("Sender IP", spa)
    .f("Target MAC", mac(&data[18..24]))
    .f("Target IP", tpa);
    d.layers.push(l);
    let info = match op {
        1 if spa == tpa => format!("Gratuitous ARP for {spa}"),
        1 => format!("Who has {tpa}? Tell {spa}"),
        2 => format!("{spa} is at {sha}"),
        _ => format!("opcode {op}"),
    };
    d.set("ARP", info);
}

fn ip_proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        _ => "IP",
    }
}

fn ipv4(data: &[u8], d: &mut Dissected) {
    if data.len() < 20 {
        d.set("IPv4", "truncated".into());
        return;
    }
    if !d.enter("IPv4") {
        return;
    }
    let ihl = ((data[0] & 0x0f) as usize * 4).max(20);
    // 0 = filled in later by the network card (segmentation offload).
    let wire = match be16(data, 2) as usize {
        0 => data.len(),
        n => n,
    };
    let total = wire.clamp(ihl, data.len().max(ihl));
    let proto = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let flags = be16(data, 6);
    let frag_off = (flags & 0x1fff) * 8;
    let mf = flags & 0x2000 != 0;
    let mut l = Layer::new("Internet Protocol v4");
    l.f("Source", src)
        .f("Destination", dst)
        .f("TTL", data[8])
        .f("Protocol", format!("{} ({proto})", ip_proto_name(proto)))
        .f("Total length", be16(data, 2))
        .f("Identification", format!("0x{:04x}", be16(data, 4)))
        .f("DSCP", data[1] >> 2);
    if flags & 0x4000 != 0 {
        l.f("Flags", "Don't fragment");
    }
    if mf || frag_off > 0 {
        l.f("Fragment offset", frag_off);
    }
    d.layers.push(l);
    d.src = src.to_string();
    d.dst = dst.to_string();
    d.src_ip = Some(src.into());
    d.dst_ip = Some(dst.into());
    let payload = data.get(ihl..total.min(data.len())).unwrap_or(&[]);
    if frag_off > 0 {
        d.set(
            "IPv4",
            format!("Fragment ({} at offset {frag_off})", ip_proto_name(proto)),
        );
        return;
    }
    if mf {
        // Only the first fragment has the transport header; don't let the
        // stream tracker treat it as a whole segment.
        transport(proto, payload, d, false, payload.len());
        d.tcp = None;
        d.info.push_str(" [first fragment]");
        return;
    }
    transport(proto, payload, d, false, wire.saturating_sub(ihl));
}

fn ipv6(data: &[u8], d: &mut Dissected) {
    if data.len() < 40 {
        d.set("IPv6", "truncated".into());
        return;
    }
    if !d.enter("IPv6") {
        return;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());
    let mut next = data[6];
    let mut l = Layer::new("Internet Protocol v6");
    l.f("Source", src)
        .f("Destination", dst)
        .f("Hop limit", data[7])
        .f("Payload length", be16(data, 4))
        .f("Flow label", format!("0x{:05x}", be32(data, 0) & 0xfffff));
    let mut off = 40;
    let mut fragment = None;
    // Skip extension headers: hop-by-hop, routing, fragment, destination.
    while matches!(next, 0 | 43 | 44 | 60) && data.len() >= off + 8 {
        let len = if next == 44 {
            8
        } else {
            (data[off + 1] as usize + 1) * 8
        };
        l.f("Extension header", next);
        if next == 44 {
            let f = be16(data, off + 2);
            if f & 0xfff9 != 0 {
                fragment = Some(f & 0xfff8);
            }
        }
        next = data[off];
        off += len;
    }
    l.f("Next header", format!("{} ({next})", ip_proto_name(next)));
    d.layers.push(l);
    d.src = src.to_string();
    d.dst = dst.to_string();
    d.src_ip = Some(src.into());
    d.dst_ip = Some(dst.into());
    let wire = match be16(data, 4) as usize {
        0 => data.len(),
        n => n + 40,
    };
    let payload = data.get(off..wire.min(data.len())).unwrap_or(&[]);
    match fragment {
        Some(o) if o > 0 => d.set(
            "IPv6",
            format!("Fragment ({} at offset {o})", ip_proto_name(next)),
        ),
        Some(_) => {
            transport(next, payload, d, true, payload.len());
            d.tcp = None;
            d.info.push_str(" [first fragment]");
        }
        None => transport(next, payload, d, true, wire.saturating_sub(off)),
    }
}

fn gre(p: &[u8], d: &mut Dissected) {
    d.transport = Some("GRE");
    if p.len() < 4 || !d.enter("GRE") {
        return d.set("GRE", "truncated".into());
    }
    let (f, et) = (be16(p, 0), be16(p, 2));
    let mut off = 4;
    for bit in [0x8000, 0x2000, 0x1000] {
        if f & bit != 0 {
            off += 4;
        }
    }
    // Enhanced GRE (PPTP) has an optional acknowledgment.
    if f & 7 == 1 && f & 0x80 != 0 {
        off += 4;
    }
    let mut l = Layer::new("Generic Routing Encapsulation");
    l.f("Protocol", format!("0x{et:04x}"));
    d.layers.push(l);
    d.proto = "GRE".into();
    d.info = format!("GRE, protocol 0x{et:04x}");
    ethertype(et, p.get(off..).unwrap_or(&[]), d);
}

/// `wire` is the payload length according to the IP header.
fn transport(proto: u8, p: &[u8], d: &mut Dissected, v6: bool, wire: usize) {
    match proto {
        6 => tcp(p, d, wire),
        17 => udp(p, d),
        4 => ipv4(p, d),
        41 => ipv6(p, d),
        47 => gre(p, d),
        1 => icmp(p, d),
        58 => icmpv6(p, d),
        2 => {
            d.transport = Some("IGMP");
            let t = match p.first() {
                Some(0x11) => "Membership query",
                Some(0x16) => "v2 Membership report",
                Some(0x17) => "Leave group",
                Some(0x22) => "v3 Membership report",
                _ => "IGMP",
            };
            d.set("IGMP", t.into());
        }
        _ => {
            d.transport = Some(ip_proto_name(proto));
            let name = ip_proto_name(proto);
            let name = if name == "IP" {
                if v6 { "IPv6" } else { "IPv4" }
            } else {
                name
            };
            d.set(name, format!("protocol {proto}, {} bytes", p.len()));
        }
    }
}

fn icmp(p: &[u8], d: &mut Dissected) {
    d.transport = Some("ICMP");
    if p.len() < 4 {
        d.set("ICMP", "truncated".into());
        return;
    }
    let (t, c) = (p[0], p[1]);
    let name = match (t, c) {
        (0, _) => "Echo reply".to_string(),
        (8, _) => "Echo request".to_string(),
        (3, 0) => "Destination unreachable: network".into(),
        (3, 1) => "Destination unreachable: host".into(),
        (3, 3) => "Destination unreachable: port".into(),
        (3, 4) => "Fragmentation needed".into(),
        (3, 13) => "Destination unreachable: administratively prohibited".into(),
        (3, c) => format!("Destination unreachable (code {c})"),
        (5, _) => "Redirect".into(),
        (11, _) => "Time exceeded (TTL)".into(),
        (t, c) => format!("type {t} code {c}"),
    };
    let mut l = Layer::new("ICMP");
    l.f("Type", t).f("Code", c);
    let mut info = name;
    if matches!(t, 0 | 8) && p.len() >= 8 {
        l.f("Identifier", be16(p, 4)).f("Sequence", be16(p, 6));
        let _ = write!(info, " id={} seq={}", be16(p, 4), be16(p, 6));
    }
    if t == 3 && c == 4 && p.len() >= 8 {
        l.f("Next-hop MTU", be16(p, 6));
        let _ = write!(info, " (MTU {})", be16(p, 6));
    }
    d.layers.push(l);
    if matches!(t, 3 | 5 | 11 | 12)
        && let Some(q) = p.get(8..).and_then(quoted4)
    {
        let _ = write!(info, ": {q}");
        let mut l = Layer::new("Quoted packet");
        l.f("Original", q);
        d.layers.push(l);
    }
    d.set("ICMP", info);
}

/// The packet quoted inside an ICMP error.
fn quoted4(b: &[u8]) -> Option<String> {
    if b.len() < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0f) as usize * 4).max(20);
    let s = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let t = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    Some(match b.get(ihl..ihl + 4) {
        Some(q) if matches!(b[9], 6 | 17) => format!(
            "{} {s}:{} → {t}:{}",
            ip_proto_name(b[9]),
            be16(q, 0),
            be16(q, 2)
        ),
        _ => format!("{} {s} → {t}", ip_proto_name(b[9])),
    })
}

fn icmpv6(p: &[u8], d: &mut Dissected) {
    d.transport = Some("ICMPv6");
    let Some(&t) = p.first() else { return };
    let name = match t {
        1 => "Destination unreachable",
        2 => "Packet too big",
        3 => "Time exceeded",
        128 => "Echo request",
        129 => "Echo reply",
        130..=132 | 143 => "Multicast listener",
        133 => "Router solicitation",
        134 => "Router advertisement",
        135 => "Neighbor solicitation",
        136 => "Neighbor advertisement",
        137 => "Redirect",
        _ => "ICMPv6",
    };
    let mut info = name.to_string();
    if matches!(t, 135 | 136) && p.len() >= 24 {
        let target = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
        let _ = write!(info, " for {target}");
    }
    let mut l = Layer::new("ICMPv6");
    l.f("Type", t).f("Code", p.get(1).copied().unwrap_or(0));
    d.layers.push(l);
    d.set("ICMPv6", info);
}

pub fn tcp_flags(f: u8) -> String {
    let names = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ];
    names
        .iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

fn port_label(port: u16) -> String {
    let s = crate::netinfo::service_name(port);
    if s.is_empty() {
        port.to_string()
    } else {
        format!("{port} ({s})")
    }
}

fn tcp_options(mut b: &[u8], l: &mut Layer) -> TcpOpts {
    let mut o = TcpOpts::default();
    while let Some(&k) = b.first() {
        match k {
            0 => break,
            1 => {
                b = &b[1..];
                continue;
            }
            _ => {}
        }
        let n = b.get(1).copied().unwrap_or(0) as usize;
        if n < 2 || n > b.len() {
            break;
        }
        let v = &b[2..n];
        match (k, v.len()) {
            (2, 2) => {
                o.mss = Some(be16(v, 0));
                l.f("MSS", be16(v, 0));
            }
            (3, 1) => {
                o.wscale = Some(v[0].min(14));
                l.f(
                    "Window scale",
                    format!("{} (×{})", v[0], 1u32 << v[0].min(14)),
                );
            }
            (4, 0) => {
                o.sack_ok = true;
                l.f("SACK", "permitted");
            }
            (5, n) => {
                o.sack_blocks = (n / 8) as u8;
                for c in v.as_chunks::<8>().0 {
                    l.f("SACK block", format!("{}–{}", be32(c, 0), be32(c, 4)));
                }
            }
            (8, 8) => {
                o.timestamps = true;
                l.f(
                    "Timestamps",
                    format!("value {}, echo {}", be32(v, 0), be32(v, 4)),
                );
            }
            (34, _) => {
                o.fast_open = true;
                l.f("Fast Open", "cookie");
            }
            (30, _) => {
                o.mptcp = true;
                l.f("Multipath TCP", "present");
            }
            _ => {}
        }
        b = &b[n..];
    }
    o
}

fn tcp(p: &[u8], d: &mut Dissected, wire: usize) {
    d.transport = Some("TCP");
    d.path.push("TCP");
    if p.len() < 20 {
        d.set("TCP", "truncated".into());
        return;
    }
    let (sp, dp) = (be16(p, 0), be16(p, 2));
    let seq = be32(p, 4);
    let ack = be32(p, 8);
    let hl = ((p[12] >> 4) as usize * 4).max(20);
    let flags = p[13];
    let win = be16(p, 14);
    let payload = p.get(hl..).unwrap_or(&[]);
    // Payload length on the wire, also when the snap length cut the packet.
    let len = wire.saturating_sub(hl).max(payload.len());
    d.src_port = Some(sp);
    d.dst_port = Some(dp);
    d.tcp_flags = Some(flags);
    let mut l = Layer::new("Transmission Control Protocol");
    l.f("Source port", port_label(sp))
        .f("Destination port", port_label(dp))
        .f("Flags", tcp_flags(flags))
        .f("Sequence", seq)
        .f("Acknowledgment", ack)
        .f("Window", win)
        .f("Payload", format!("{len} bytes"));
    let opts = tcp_options(p.get(20..hl).unwrap_or(&[]), &mut l);
    d.layers.push(l);
    d.tcp = Some(TcpInfo {
        seq,
        ack,
        flags,
        window: win,
        len: len as u32,
        opts,
    });
    d.mark_payload(payload);
    d.set(
        "TCP",
        format!(
            "{sp} → {dp} [{}] seq={seq}{} win={win} len={len}",
            tcp_flags(flags),
            if flags & ACK != 0 {
                format!(" ack={ack}")
            } else {
                String::new()
            },
        ),
    );
    if !payload.is_empty()
        && let Some(a) = appproto::tcp(payload, sp, dp)
    {
        d.app(a);
    }
}

fn udp(p: &[u8], d: &mut Dissected) {
    d.transport = Some("UDP");
    d.path.push("UDP");
    if p.len() < 8 {
        d.set("UDP", "truncated".into());
        return;
    }
    let (sp, dp) = (be16(p, 0), be16(p, 2));
    // The datagram may be shorter than the IP payload.
    let end = match be16(p, 4) as usize {
        n if n >= 8 => n.min(p.len()),
        _ => p.len(),
    };
    let payload = &p[8..end];
    d.src_port = Some(sp);
    d.dst_port = Some(dp);
    let mut l = Layer::new("User Datagram Protocol");
    l.f("Source port", port_label(sp))
        .f("Destination port", port_label(dp))
        .f("Length", be16(p, 4));
    d.layers.push(l);
    d.mark_payload(payload);
    d.set("UDP", format!("{sp} → {dp} len={}", payload.len()));
    if dp == 4789 && payload.len() > 8 && payload[0] & 0x08 != 0 && d.enter("VXLAN") {
        let mut l = Layer::new("VXLAN");
        l.f("Network identifier", be32(payload, 4) >> 8);
        d.layers.push(l);
        d.proto = "VXLAN".into();
        ethernet(&payload[8..], d);
        return;
    }
    if !payload.is_empty()
        && let Some(a) = appproto::udp(payload, sp, dp)
    {
        d.app(a);
    }
}

/// Bytes from pasted text: plain hex, or a hex dump with offsets and an ASCII
/// column (this app, Wireshark, `hexdump -C`, `xxd`, `tcpdump -x`).
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('|').next().unwrap_or("").replace(',', " ");
        let is_hex = |t: &str| !t.is_empty() && t.bytes().all(|c| c.is_ascii_hexdigit());
        let mut tok: Vec<&str> = line.split_whitespace().collect();
        let mut limit = usize::MAX;
        if tok.len() > 1 {
            let t = tok[0].strip_prefix("0x").unwrap_or(tok[0]);
            let colon = t.ends_with(':') && t.matches(':').count() == 1;
            let t = t.trim_end_matches(':');
            let next_pair = tok[1].len() == 2 && is_hex(tok[1]);
            if is_hex(t) && t.len() >= 4 && (colon || next_pair) {
                tok.remove(0);
                limit = out.len() + 16;
            }
        }
        for t in tok {
            let t = t.strip_prefix("0x").unwrap_or(t).replace([':', '-'], "");
            if out.len() >= limit {
                break;
            }
            if !is_hex(&t) || t.len() % 2 != 0 {
                if limit != usize::MAX {
                    // ASCII column
                    break;
                }
                return Err(format!("not hexadecimal: \"{t}\""));
            }
            for i in (0..t.len()).step_by(2) {
                out.push(u8::from_str_radix(&t[i..i + 2], 16).map_err(|e| e.to_string())?);
            }
        }
    }
    Ok(out)
}

/// Classic hex dump: offset, 16 hex bytes, ASCII.
pub fn hexdump(data: &[u8]) -> Vec<String> {
    data.chunks(16)
        .enumerate()
        .map(|(i, c)| {
            let hex: Vec<String> = c.iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = c
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:04x}  {:<48}  {ascii}", i * 16, hex.join(" "))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4(proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
        let total = (20 + l4.len()) as u16;
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[
            0, 1, 0x40, 0, 64, proto, 0, 0, 192, 168, 1, 10, 192, 168, 1, 1,
        ]);
        f.extend_from_slice(l4);
        f
    }

    #[test]
    fn arp_request() {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0x08, 0x06]);
        f.extend_from_slice(&[
            0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1,
        ]);
        let d = dissect(1, &f);
        assert_eq!(d.proto, "ARP");
        assert_eq!(d.info, "Who has 10.0.0.1? Tell 10.0.0.5");
        assert_eq!(d.dst, "Broadcast");
    }

    #[test]
    fn tcp_syn() {
        let mut tcp = vec![
            0xc0, 0x00, 0x00, 0x16, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ];
        let d = dissect(1, &eth_ipv4(6, &tcp));
        assert_eq!(d.proto, "TCP");
        assert!(d.info.contains("49152 → 22 [SYN]"), "{}", d.info);
        assert_eq!(d.src, "192.168.1.10");
        tcp[13] = 0x18;
        tcp.extend_from_slice(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
        let d = dissect(1, &eth_ipv4(6, &tcp));
        assert_eq!(d.proto, "HTTP");
        assert_eq!(d.info, "GET /index.html HTTP/1.1");
    }

    #[test]
    fn modbus_tcp() {
        let mut tcp = vec![
            0xc0, 0x00, 0x01, 0xf6, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
        ];
        tcp.extend(crate::modbus::tcp_frame(7, 1, &[3, 0, 0, 0, 10]));
        let d = dissect(1, &eth_ipv4(6, &tcp));
        assert_eq!(d.proto, "Modbus/TCP");
        assert!(d.info.contains("Read Holding Registers"), "{}", d.info);
    }

    #[test]
    fn dns_query() {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        dns.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        let mut udp = vec![0xd4, 0x31, 0, 53, 0, (8 + dns.len()) as u8, 0, 0];
        udp.extend(dns);
        let d = dissect(1, &eth_ipv4(17, &udp));
        assert_eq!(d.proto, "DNS");
        assert_eq!(d.info, "Query 0x1234 A example.com");
    }

    #[test]
    fn raw_ipv4_and_hexdump() {
        let f = eth_ipv4(1, &[8, 0, 0, 0, 0, 7, 0, 3]);
        let d = dissect(101, &f[14..]);
        assert_eq!(d.proto, "ICMP");
        assert_eq!(d.info, "Echo request id=7 seq=3");
        assert_eq!(hexdump(&[0x41; 17]).len(), 2);
    }

    #[test]
    fn pasted_hex() {
        let data: Vec<u8> = (0..40).map(|i| i * 5).collect();
        assert_eq!(parse_hex(&hexdump(&data).join("\n")).unwrap(), data);
        assert_eq!(
            parse_hex("45:00 00-3c,0x01").unwrap(),
            [0x45, 0, 0, 0x3c, 1]
        );
        assert_eq!(
            parse_hex("\t0x0000:  4500 003c 1c46  E..<.F").unwrap(),
            [0x45, 0, 0, 0x3c, 0x1c, 0x46]
        );
        assert_eq!(
            parse_hex("00000000  45 00 00 3c  be ef 00 01  |E..<....|").unwrap(),
            [0x45, 0, 0, 0x3c, 0xbe, 0xef, 0, 1]
        );
        assert!(parse_hex("hello").is_err());
        assert!(parse_hex("").unwrap().is_empty());
    }

    #[test]
    fn padding_options_and_path() {
        // SYN with MSS, SACK permitted, window scale 7; Ethernet padding.
        let tcp = [
            0xc0, 0x00, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x80, 0x02, 0xff, 0xff, 0, 0, 0, 0, 2,
            4, 5, 0xb4, 4, 2, 3, 3, 7, 0, 0, 0,
        ];
        let mut f = eth_ipv4(6, &tcp);
        f.extend([0; 10]);
        let d = dissect(1, &f);
        let t = d.tcp.unwrap();
        assert_eq!((t.opts.mss, t.opts.wscale), (Some(1460), Some(7)));
        assert!(t.opts.sack_ok && !t.opts.timestamps);
        assert_eq!((t.len, d.payload.1), (0, 0));
        assert_eq!(d.path, ["Ethernet", "IPv4", "TCP"]);
    }

    #[test]
    fn payload_range_inside_gre() {
        let mut tcp = vec![
            0xc0, 0x00, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
        ];
        tcp.extend(b"GET / HTTP/1.1\r\n\r\n");
        let inner = &eth_ipv4(6, &tcp)[14..];
        let mut g = vec![0, 0, 0x08, 0];
        g.extend(inner);
        let f = eth_ipv4(47, &g);
        let d = dissect(1, &f);
        assert_eq!(d.path, ["Ethernet", "IPv4", "GRE", "IPv4", "TCP", "HTTP"]);
        assert_eq!(payload(&d, &f), b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn icmp_error_names_the_original_flow() {
        let mut q = vec![3, 3, 0, 0, 0, 0, 0, 0];
        q.extend(&eth_ipv4(17, &[0xd4, 0x31, 0, 53, 0, 8, 0, 0])[14..]);
        let d = dissect(1, &eth_ipv4(1, &q));
        assert!(
            d.info
                .ends_with("port: UDP 192.168.1.10:54321 → 192.168.1.1:53"),
            "{}",
            d.info
        );
    }

    /// The release build aborts on panic, so malformed traffic must never
    /// cause one.
    #[test]
    fn malformed_frames_never_panic() {
        let mut seeds: Vec<Vec<u8>> = Vec::new();
        let th = [
            0xc0, 0x00, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
        ];
        for (port, body) in [
            (502u16, crate::modbus::tcp_frame(7, 1, &[3, 0, 0, 0, 10])),
            (
                443,
                b"\x16\x03\x01\x00\x40\x01\x00\x00\x3c\x03\x03".repeat(6),
            ),
            (
                1883,
                b"\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04abcd".to_vec(),
            ),
            (
                445,
                b"\0\0\0\x40\xfeSMB\x40\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0".to_vec(),
            ),
            (
                102,
                b"\x03\0\0\x19\x02\xf0\x80\x32\x01\0\0\0\0\0\x08\0\0\xf0".to_vec(),
            ),
            (4840, b"HELF\x20\0\0\0\0\0\0\0".to_vec()),
            (44818, vec![0x6f; 40]),
            (2404, vec![0x68, 4, 7, 0, 0, 0]),
        ] {
            let mut t = th.to_vec();
            t[2..4].copy_from_slice(&port.to_be_bytes());
            t.extend(body);
            seeds.push(eth_ipv4(6, &t));
        }
        let mut dns = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        dns.extend_from_slice(b"\x07example\x03com\0\0\x01\0\x01");
        dns.extend_from_slice(b"\xc0\x0c\0\x06\0\x01\0\0\0\x3c\0\x18\xc0\x0c\xc0\x0c");
        dns.extend([0; 20]);
        for port in [
            53u16, 67, 69, 123, 137, 161, 319, 443, 500, 514, 547, 1812, 1900, 4789, 5004, 5683,
            47808, 51820,
        ] {
            let mut u = vec![0xd4, 0x31];
            u.extend(port.to_be_bytes());
            u.extend([1, 40, 0, 0]);
            u.extend(&dns);
            u.resize(300, 0x55);
            if port == 67 {
                u[8 + 236..8 + 240].copy_from_slice(&[99, 130, 83, 99]);
            }
            seeds.push(eth_ipv4(17, &u));
        }
        for p in [1u8, 2, 4, 41, 47, 58, 89] {
            seeds.push(eth_ipv4(p, &[3; 64]));
        }
        for et in [
            0x86ddu16, 0x0806, 0x88cc, 0x8864, 0x8863, 0x8847, 0x8100, 0x0026,
        ] {
            let mut f = vec![0x11; 12];
            f.extend(et.to_be_bytes());
            f.extend([0x42, 0x42, 3].repeat(40));
            seeds.push(f);
        }
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for s in &seeds {
            for n in 0..s.len() {
                for lt in [0, 1, 101, 113, 276] {
                    let _ = dissect(lt, &s[..n]);
                }
            }
            for _ in 0..3000 {
                let mut m = s.clone();
                for _ in 0..1 + rnd() % 6 {
                    let i = rnd() as usize % m.len();
                    m[i] = rnd() as u8;
                }
                m.truncate(1 + rnd() as usize % m.len());
                let d = dissect(1, &m);
                let _ = payload(&d, &m);
            }
        }
    }
}
