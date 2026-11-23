//! Packet dissector for the capture analyser: link layer (Ethernet, VLAN,
//! Linux cooked, loopback, raw IP), ARP, IPv4/IPv6, ICMP/ICMPv6, TCP, UDP,
//! and the common application protocols (DNS/mDNS, DHCP, NTP, SSDP, HTTP,
//! TLS SNI, SSH, MQTT, Modbus/TCP).

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::modbus;

#[derive(Clone, Debug, Default)]
pub struct Layer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

impl Layer {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
        }
    }
    fn f(&mut self, k: &str, v: impl ToString) -> &mut Self {
        self.fields.push((k.to_string(), v.to_string()));
        self
    }
}

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
}

impl Dissected {
    fn set(&mut self, proto: &str, info: String) {
        self.proto = proto.to_string();
        self.info = info;
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

pub fn dissect(linktype: i32, data: &[u8]) -> Dissected {
    let mut d = Dissected {
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
            ethertype(u16::from_be_bytes([data[0], data[1]]), &data[20..], &mut d);
        }
        _ => {}
    }
    d
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
    let mut l = Layer::new("Ethernet II");
    l.f("Destination", &dst).f("Source", &src);
    let vendor = crate::netinfo::mac_vendor(&src);
    if let Some(v) = &vendor {
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
    while (et == 0x8100 || et == 0x88a8) && data.len() >= off + 4 {
        l.f("VLAN", be16(data, off) & 0x0fff);
        et = be16(data, off + 2);
        off += 4;
    }
    l.f("Type", format!("0x{et:04x}"));
    d.layers.push(l);
    if et <= 1500 {
        // 802.3 length field: LLC follows (STP, CDP…).
        let mut llc = Layer::new("802.3 LLC");
        llc.f("Length", et);
        if data.len() >= off + 3 {
            llc.f("DSAP", format!("0x{:02x}", data[off]))
                .f("SSAP", format!("0x{:02x}", data[off + 1]));
            if data[off] == 0x42 {
                d.set("STP", "Spanning Tree BPDU".into());
                d.layers.push(llc);
                return;
            }
        }
        d.layers.push(llc);
        d.set("LLC", format!("802.3 frame, length {et}"));
        return;
    }
    ethertype(et, &data[off..], d);
}

fn ethertype(et: u16, data: &[u8], d: &mut Dissected) {
    match et {
        0x0800 => ipv4(data, d),
        0x86dd => ipv6(data, d),
        0x0806 => arp(data, d),
        0x88cc => d.set("LLDP", "Link Layer Discovery Protocol".into()),
        0x888e => d.set("EAPOL", "802.1X authentication".into()),
        0x8892 => d.set("PROFINET", "PROFINET real-time".into()),
        0x88a4 => d.set("EtherCAT", "EtherCAT frame".into()),
        0x8863 | 0x8864 => d.set("PPPoE", "PPP over Ethernet".into()),
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
    let ihl = ((data[0] & 0x0f) as usize * 4).max(20);
    let total = (be16(data, 2) as usize).clamp(ihl, data.len().max(ihl));
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
    transport(proto, payload, d, false);
}

fn ipv6(data: &[u8], d: &mut Dissected) {
    if data.len() < 40 {
        d.set("IPv6", "truncated".into());
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
    // Skip extension headers: hop-by-hop, routing, fragment, destination.
    while matches!(next, 0 | 43 | 44 | 60) && data.len() >= off + 8 {
        let len = if next == 44 {
            8
        } else {
            (data[off + 1] as usize + 1) * 8
        };
        l.f("Extension header", next);
        next = data[off];
        off += len;
    }
    l.f("Next header", format!("{} ({next})", ip_proto_name(next)));
    d.layers.push(l);
    d.src = src.to_string();
    d.dst = dst.to_string();
    d.src_ip = Some(src.into());
    d.dst_ip = Some(dst.into());
    transport(next, data.get(off..).unwrap_or(&[]), d, true);
}

fn transport(proto: u8, p: &[u8], d: &mut Dissected, v6: bool) {
    match proto {
        6 => tcp(p, d),
        17 => udp(p, d),
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
    d.layers.push(l);
    d.set("ICMP", info);
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

fn tcp_flags(f: u8) -> String {
    let names = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
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

fn tcp(p: &[u8], d: &mut Dissected) {
    d.transport = Some("TCP");
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
        .f("Payload", format!("{} bytes", payload.len()));
    d.layers.push(l);
    d.set(
        "TCP",
        format!(
            "{sp} → {dp} [{}] seq={seq}{} win={win} len={}",
            tcp_flags(flags),
            if flags & 0x10 != 0 {
                format!(" ack={ack}")
            } else {
                String::new()
            },
            payload.len()
        ),
    );
    if payload.is_empty() {
        return;
    }
    let either = |port: u16| sp == port || dp == port;
    if either(502) {
        let lines = modbus::decode_tcp(payload, Some(dp == 502));
        if !lines.is_empty() {
            let mut l = Layer::new("Modbus/TCP");
            for (i, s) in lines.iter().enumerate() {
                l.f(&format!("ADU {}", i + 1), s);
            }
            d.layers.push(l);
            d.set("Modbus/TCP", lines.join(" | "));
            return;
        }
    }
    if let Some(sni) = tls(payload, d) {
        d.set("TLS", sni);
        return;
    }
    if let Some(line) = http(payload, d) {
        d.set("HTTP", line);
        return;
    }
    if payload.starts_with(b"SSH-") {
        let line = first_line(payload);
        d.layers.push({
            let mut l = Layer::new("SSH");
            l.f("Banner", &line);
            l
        });
        d.set("SSH", line);
        return;
    }
    if either(1883)
        && let Some(&b) = payload.first()
    {
        let t = match b >> 4 {
            1 => "CONNECT",
            2 => "CONNACK",
            3 => "PUBLISH",
            4 => "PUBACK",
            8 => "SUBSCRIBE",
            9 => "SUBACK",
            12 => "PINGREQ",
            13 => "PINGRESP",
            14 => "DISCONNECT",
            _ => "MQTT",
        };
        d.set("MQTT", t.into());
        return;
    }
    if either(53) && payload.len() > 2 {
        dns(&payload[2..], d, "DNS");
        return;
    }
    for (port, name) in [
        (21, "FTP"),
        (25, "SMTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (23, "Telnet"),
    ] {
        if either(port) {
            d.set(name, first_line(payload));
            return;
        }
    }
    if either(445) || either(139) {
        d.set("SMB", format!("{} bytes", payload.len()));
    } else if either(3389) {
        d.set("RDP", format!("{} bytes", payload.len()));
    }
}

fn first_line(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(&b[..b.len().min(200)]);
    s.lines()
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

fn http(p: &[u8], d: &mut Dissected) -> Option<String> {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"HTTP/1.",
        b"CONNECT ",
    ];
    if !METHODS.iter().any(|m| p.starts_with(m)) {
        return None;
    }
    let text = String::from_utf8_lossy(&p[..p.len().min(2048)]);
    let mut l = Layer::new("Hypertext Transfer Protocol");
    let line = first_line(p);
    l.f("Line", &line);
    for h in text.lines().skip(1).take_while(|h| !h.is_empty()).take(12) {
        if let Some((k, v)) = h.split_once(':') {
            l.f(k.trim(), v.trim());
        }
    }
    d.layers.push(l);
    Some(line)
}

/// TLS record: report handshake type and, for a ClientHello, the SNI.
fn tls(p: &[u8], d: &mut Dissected) -> Option<String> {
    if p.len() < 6 || !matches!(p[0], 0x14..=0x17) || p[1] != 3 || p[2] > 4 {
        return None;
    }
    let ver = match p[2] {
        1 => "1.0",
        2 => "1.1",
        3 => "1.2",
        _ => "1.x",
    };
    let mut l = Layer::new("Transport Layer Security");
    l.f("Record version", format!("TLS {ver}"));
    let info = match p[0] {
        0x16 => {
            let hs = match p[5] {
                1 => "Client Hello",
                2 => "Server Hello",
                11 => "Certificate",
                12 => "Server Key Exchange",
                14 => "Server Hello Done",
                16 => "Client Key Exchange",
                4 => "New Session Ticket",
                _ => "Handshake",
            };
            l.f("Handshake", hs);
            match (p[5] == 1).then(|| client_hello_sni(&p[5..])).flatten() {
                Some(sni) => {
                    l.f("Server name (SNI)", &sni);
                    format!("{hs}, SNI={sni}")
                }
                None => hs.to_string(),
            }
        }
        0x14 => "Change Cipher Spec".into(),
        0x15 => "Alert".into(),
        _ => "Application data".into(),
    };
    d.layers.push(l);
    Some(info)
}

fn client_hello_sni(h: &[u8]) -> Option<String> {
    // type(1) len(3) version(2) random(32) sid
    let mut pos = 4 + 2 + 32;
    let sid = *h.get(pos)? as usize;
    pos += 1 + sid;
    let cs = u16::from_be_bytes([*h.get(pos)?, *h.get(pos + 1)?]) as usize;
    pos += 2 + cs;
    let cm = *h.get(pos)? as usize;
    pos += 1 + cm;
    let ext_end = pos + 2 + u16::from_be_bytes([*h.get(pos)?, *h.get(pos + 1)?]) as usize;
    pos += 2;
    while pos + 4 <= ext_end.min(h.len()) {
        let t = u16::from_be_bytes([h[pos], h[pos + 1]]);
        let len = u16::from_be_bytes([h[pos + 2], h[pos + 3]]) as usize;
        if t == 0 {
            // list len(2) type(1) name len(2) name
            let n = u16::from_be_bytes([*h.get(pos + 7)?, *h.get(pos + 8)?]) as usize;
            return h
                .get(pos + 9..pos + 9 + n)
                .map(|b| String::from_utf8_lossy(b).into());
        }
        pos += 4 + len;
    }
    None
}

fn udp(p: &[u8], d: &mut Dissected) {
    d.transport = Some("UDP");
    if p.len() < 8 {
        d.set("UDP", "truncated".into());
        return;
    }
    let (sp, dp) = (be16(p, 0), be16(p, 2));
    let payload = &p[8..];
    d.src_port = Some(sp);
    d.dst_port = Some(dp);
    let mut l = Layer::new("User Datagram Protocol");
    l.f("Source port", port_label(sp))
        .f("Destination port", port_label(dp))
        .f("Length", be16(p, 4));
    d.layers.push(l);
    d.set("UDP", format!("{sp} → {dp} len={}", payload.len()));
    let either = |port: u16| sp == port || dp == port;
    if either(5353) {
        dns(payload, d, "mDNS");
    } else if either(53) || either(5355) {
        dns(payload, d, if either(5355) { "LLMNR" } else { "DNS" });
    } else if either(67) || either(68) {
        dhcp(payload, d);
    } else if either(123) && !payload.is_empty() {
        let mode = payload[0] & 7;
        let m = match mode {
            3 => "client",
            4 => "server",
            5 => "broadcast",
            _ => "other",
        };
        d.set("NTP", format!("NTPv{} {m}", (payload[0] >> 3) & 7));
    } else if either(1900) {
        let line = first_line(payload);
        let st = String::from_utf8_lossy(payload).lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.eq_ignore_ascii_case("ST") || k.eq_ignore_ascii_case("NT"))
                .then(|| v.trim().to_string())
        });
        d.set(
            "SSDP",
            match st {
                Some(st) => format!("{line} — {st}"),
                None => line,
            },
        );
    } else if either(137) {
        d.set("NBNS", "NetBIOS name service".into());
    } else if either(138) {
        d.set("NetBIOS-DGM", "NetBIOS datagram".into());
    } else if either(161) || either(162) {
        d.set(
            "SNMP",
            if either(162) {
                "trap".into()
            } else {
                "request/response".into()
            },
        );
    } else if either(514) {
        d.set("Syslog", first_line(payload));
    } else if either(443) && payload.first().is_some_and(|b| b & 0x80 != 0) {
        d.set("QUIC", "QUIC long header".into());
    } else if either(443) {
        d.set("QUIC", "QUIC".into());
    } else if either(502) {
        let lines = modbus::decode_tcp(payload, Some(dp == 502));
        if !lines.is_empty() {
            d.set("Modbus/UDP", lines.join(" | "));
        }
    } else if either(47808) {
        d.set("BACnet", format!("{} bytes", payload.len()));
    } else if either(2222) || either(44818) {
        d.set("EtherNet/IP", format!("{} bytes", payload.len()));
    } else if either(3702) {
        d.set("WS-Discovery", format!("{} bytes", payload.len()));
    }
}

fn dns_type(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        47 => "NSEC".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        t => format!("TYPE{t}"),
    }
}

fn dns_name(pkt: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *pkt.get(pos)? as usize;
        if len == 0 {
            end.get_or_insert(pos + 1);
            break;
        }
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(pos + 2);
            pos = ((len & 0x3f) << 8) | *pkt.get(pos + 1)? as usize;
            continue;
        }
        labels.push(String::from_utf8_lossy(pkt.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    Some((labels.join("."), end?))
}

fn dns(p: &[u8], d: &mut Dissected, proto: &str) {
    if p.len() < 12 {
        return;
    }
    let id = be16(p, 0);
    let flags = be16(p, 2);
    let is_resp = flags & 0x8000 != 0;
    let rcode = flags & 0xf;
    let (qd, an) = (be16(p, 4), be16(p, 6));
    let mut l = Layer::new(if proto == "mDNS" {
        "Multicast DNS"
    } else {
        "Domain Name System"
    });
    l.f("Transaction ID", format!("0x{id:04x}"))
        .f("Type", if is_resp { "response" } else { "query" })
        .f("Questions", qd)
        .f("Answers", an);
    let mut pos = 12;
    let mut questions = Vec::new();
    for _ in 0..qd.min(8) {
        let Some((name, next)) = dns_name(p, pos) else {
            break;
        };
        if next + 4 > p.len() {
            break;
        }
        let t = dns_type(be16(p, next));
        l.f("Query", format!("{name} {t}"));
        questions.push(format!("{t} {name}"));
        pos = next + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..an.min(16) {
        let Some((name, next)) = dns_name(p, pos) else {
            break;
        };
        if next + 10 > p.len() {
            break;
        }
        let t = be16(p, next);
        let rdlen = be16(p, next + 8) as usize;
        let rd = next + 10;
        let Some(rdata) = p.get(rd..rd + rdlen) else {
            break;
        };
        let val = match t {
            1 if rdlen == 4 => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
            28 if rdlen == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap()).to_string(),
            5 | 12 | 2 => dns_name(p, rd).map(|(n, _)| n).unwrap_or_default(),
            _ => format!("{rdlen} bytes"),
        };
        l.f("Answer", format!("{name} {} {val}", dns_type(t)));
        answers.push(format!("{} {val}", dns_type(t)));
        pos = rd + rdlen;
    }
    d.layers.push(l);
    let rc = match rcode {
        0 => "",
        2 => " SERVFAIL",
        3 => " NXDOMAIN",
        5 => " REFUSED",
        _ => " error",
    };
    let info = if is_resp {
        format!(
            "Response 0x{id:04x}{rc} {}{}{}",
            questions.join(", "),
            if answers.is_empty() { "" } else { " → " },
            answers
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!("Query 0x{id:04x} {}", questions.join(", "))
    };
    d.set(proto, info);
}

fn dhcp(p: &[u8], d: &mut Dissected) {
    if p.len() < 240 || p[236..240] != [99, 130, 83, 99] {
        d.set("DHCP", "BOOTP".into());
        return;
    }
    let mut l = Layer::new("DHCP");
    let yiaddr = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    l.f("Client MAC", mac(&p[28..34]))
        .f("Transaction", format!("0x{:08x}", be32(p, 4)));
    let mut msg = "DHCP".to_string();
    let mut host = None;
    let mut pos = 240;
    while pos + 1 < p.len() && p[pos] != 255 {
        if p[pos] == 0 {
            pos += 1;
            continue;
        }
        let (code, len) = (p[pos], p[pos + 1] as usize);
        let Some(v) = p.get(pos + 2..pos + 2 + len) else {
            break;
        };
        match code {
            53 if len == 1 => {
                msg = match v[0] {
                    1 => "Discover",
                    2 => "Offer",
                    3 => "Request",
                    4 => "Decline",
                    5 => "ACK",
                    6 => "NAK",
                    7 => "Release",
                    8 => "Inform",
                    _ => "DHCP",
                }
                .into();
            }
            12 => host = Some(String::from_utf8_lossy(v).into_owned()),
            _ => {}
        }
        pos += 2 + len;
    }
    l.f("Message", &msg);
    if !yiaddr.is_unspecified() {
        l.f("Your IP", yiaddr);
    }
    if let Some(h) = &host {
        l.f("Hostname", h);
    }
    d.layers.push(l);
    let mut info = format!("DHCP {msg}");
    if !yiaddr.is_unspecified() {
        let _ = write!(info, " {yiaddr}");
    }
    if let Some(h) = host {
        let _ = write!(info, " ({h})");
    }
    d.set("DHCP", info);
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
        tcp.extend(modbus::tcp_frame(7, 1, &[3, 0, 0, 0, 10]));
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
}
