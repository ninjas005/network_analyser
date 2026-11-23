//! DHCPv4: message parsing with decoded options, extraction from captured
//! frames, and a DHCPDISCOVER frame for actively finding DHCP servers
//! (injected through pcap, so the OS DHCP client on port 68 is untouched).

use std::net::Ipv4Addr;

pub const MAGIC: [u8; 4] = [99, 130, 83, 99];

#[derive(Clone, Debug, PartialEq)]
pub struct DhcpOption {
    pub code: u8,
    pub name: &'static str,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct Message {
    /// 1 = BOOTREQUEST (client), 2 = BOOTREPLY (server)
    pub op: u8,
    pub xid: u32,
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: String,
    pub msg_type: Option<u8>,
    pub server_id: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub lease_secs: Option<u32>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub domain: Option<String>,
    /// Parameter request list (client) as option codes.
    pub requested: Vec<u8>,
    pub options: Vec<DhcpOption>,
}

pub fn msg_type_name(t: u8) -> &'static str {
    match t {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        9 => "FORCERENEW",
        10 => "LEASEQUERY",
        _ => "UNKNOWN",
    }
}

pub fn option_name(code: u8) -> &'static str {
    match code {
        1 => "Subnet mask",
        2 => "Time offset",
        3 => "Router",
        4 => "Time server",
        6 => "DNS servers",
        7 => "Log server",
        12 => "Host name",
        15 => "Domain name",
        17 => "Root path",
        26 => "Interface MTU",
        28 => "Broadcast address",
        31 => "Router discovery",
        33 => "Static route",
        42 => "NTP servers",
        43 => "Vendor specific",
        44 => "NetBIOS name servers",
        46 => "NetBIOS node type",
        47 => "NetBIOS scope",
        50 => "Requested IP",
        51 => "Lease time",
        52 => "Option overload",
        53 => "Message type",
        54 => "Server identifier",
        55 => "Parameter request list",
        56 => "Message",
        57 => "Max message size",
        58 => "Renewal time (T1)",
        59 => "Rebinding time (T2)",
        60 => "Vendor class",
        61 => "Client identifier",
        66 => "TFTP server name",
        67 => "Boot file name",
        77 => "User class",
        80 => "Rapid commit",
        81 => "Client FQDN",
        82 => "Relay agent information",
        93 => "Client architecture",
        97 => "Client UUID",
        108 => "IPv6-only preferred",
        114 => "Captive portal",
        116 => "Auto-configure",
        119 => "Domain search",
        121 => "Classless static route",
        125 => "Vendor-identifying vendor specific",
        138 => "CAPWAP AC",
        150 => "TFTP servers (Cisco)",
        249 => "Classless static route (MS)",
        252 => "WPAD URL",
        _ => "Option",
    }
}

fn ip_list(v: &[u8]) -> Vec<Ipv4Addr> {
    v.as_chunks::<4>()
        .0
        .iter()
        .map(|c| Ipv4Addr::from(*c))
        .collect()
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v)
        .trim_end_matches('\0')
        .to_string()
}

pub fn duration(s: u32) -> String {
    if s == u32::MAX {
        return "infinite".into();
    }
    let (d, h, m) = (s / 86400, s % 86400 / 3600, s % 3600 / 60);
    match (d, h, m) {
        (0, 0, _) => format!("{s} s ({m} min)"),
        (0, _, _) => format!("{s} s ({h} h {m} min)"),
        _ => format!("{s} s ({d} d {h} h)"),
    }
}

fn routes(v: &[u8]) -> String {
    // RFC 3442: width, significant octets of destination, router.
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let w = v[i] as usize;
        let n = w.div_ceil(8);
        let Some(dst) = v.get(i + 1..i + 1 + n) else {
            break;
        };
        let Some(gw) = v.get(i + 1 + n..i + 5 + n) else {
            break;
        };
        let mut d = [0u8; 4];
        d[..n].copy_from_slice(dst);
        out.push(format!(
            "{}/{w} via {}",
            Ipv4Addr::from(d),
            Ipv4Addr::new(gw[0], gw[1], gw[2], gw[3])
        ));
        i += 5 + n;
    }
    out.join(", ")
}

fn decode_option(code: u8, v: &[u8]) -> String {
    match code {
        1 | 28 | 50 | 54 if v.len() == 4 => Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string(),
        3 | 4 | 6 | 7 | 42 | 44 | 150 => ip_list(v)
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        12 | 15 | 17 | 56 | 60 | 66 | 67 | 114 | 252 => text(v),
        26 | 57 if v.len() == 2 => u16::from_be_bytes([v[0], v[1]]).to_string(),
        51 | 58 | 59 | 108 if v.len() == 4 => {
            duration(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
        }
        53 if v.len() == 1 => format!("{} ({})", msg_type_name(v[0]), v[0]),
        55 => v
            .iter()
            .map(|c| format!("{c} {}", option_name(*c)))
            .collect::<Vec<_>>()
            .join(", "),
        61 if v.len() == 7 && v[0] == 1 => format!("MAC {}", mac(&v[1..])),
        61 | 97 => v
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        81 if v.len() > 3 => format!("flags {:#04x} {}", v[0], text(&v[3..])),
        82 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i + 2 <= v.len() {
                let (sub, l) = (v[i], v[i + 1] as usize);
                let val = v.get(i + 2..i + 2 + l).unwrap_or(&[]);
                let shown = if val.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                    text(val)
                } else {
                    val.iter().map(|b| format!("{b:02x}")).collect::<String>()
                };
                parts.push(format!(
                    "{}={shown}",
                    match sub {
                        1 => "circuit-id",
                        2 => "remote-id",
                        5 => "link-selection",
                        _ => "sub",
                    }
                ));
                i += 2 + l;
            }
            parts.join(" ")
        }
        93 if v.len() == 2 => match u16::from_be_bytes([v[0], v[1]]) {
            0 => "x86 BIOS".into(),
            6 => "x86 UEFI".into(),
            7 | 9 => "x64 UEFI".into(),
            10 => "ARM32 UEFI".into(),
            11 => "ARM64 UEFI".into(),
            n => n.to_string(),
        },
        116 if v.len() == 1 => if v[0] == 1 { "enabled" } else { "disabled" }.into(),
        119 => {
            // Domain search: DNS name list with compression into this option.
            let mut out = Vec::new();
            let mut pos = 0;
            while pos < v.len() {
                match crate::dns::read_name(v, pos) {
                    Some((n, next)) if next > pos => {
                        out.push(n.trim_end_matches('.').to_string());
                        pos = next;
                    }
                    _ => break,
                }
            }
            out.join(", ")
        }
        121 | 249 => routes(v),
        _ if !v.is_empty() && v.iter().all(|b| b.is_ascii_graphic() || *b == b' ') => text(v),
        _ => v
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn parse(p: &[u8]) -> Option<Message> {
    if p.len() < 240 || p[236..240] != MAGIC {
        return None;
    }
    let ip = |i: usize| Ipv4Addr::new(p[i], p[i + 1], p[i + 2], p[i + 3]);
    let hlen = (p[2] as usize).min(16);
    let mut m = Message {
        op: p[0],
        xid: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        secs: u16::from_be_bytes([p[8], p[9]]),
        broadcast: p[10] & 0x80 != 0,
        ciaddr: ip(12),
        yiaddr: ip(16),
        siaddr: ip(20),
        giaddr: ip(24),
        chaddr: mac(&p[28..28 + hlen]),
        msg_type: None,
        server_id: None,
        requested_ip: None,
        hostname: None,
        vendor_class: None,
        lease_secs: None,
        routers: Vec::new(),
        dns: Vec::new(),
        subnet_mask: None,
        domain: None,
        requested: Vec::new(),
        options: Vec::new(),
    };
    let mut i = 240;
    while i < p.len() {
        let code = p[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let Some(&len) = p.get(i + 1) else { break };
        let Some(v) = p.get(i + 2..i + 2 + len as usize) else {
            break;
        };
        match code {
            53 if len == 1 => m.msg_type = Some(v[0]),
            54 if len == 4 => m.server_id = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            50 if len == 4 => m.requested_ip = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            1 if len == 4 => m.subnet_mask = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            51 if len == 4 => m.lease_secs = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            3 => m.routers = ip_list(v),
            6 => m.dns = ip_list(v),
            12 => m.hostname = Some(text(v)),
            15 => m.domain = Some(text(v)),
            60 => m.vendor_class = Some(text(v)),
            55 => m.requested = v.to_vec(),
            _ => {}
        }
        m.options.push(DhcpOption {
            code,
            name: option_name(code),
            value: decode_option(code, v),
        });
        i += 2 + len as usize;
    }
    Some(m)
}

/// Where a UDP datagram sits inside a captured frame.
pub struct Udp<'a> {
    pub src_mac: Option<String>,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

/// IPv4/UDP payload of an Ethernet (+VLAN), Linux cooked or raw-IP frame.
pub fn udp_payload(linktype: i32, f: &[u8]) -> Option<Udp<'_>> {
    let (mut off, mut et, src_mac) = match linktype {
        1 => {
            let m = mac(f.get(6..12)?);
            (14, u16::from_be_bytes([*f.get(12)?, *f.get(13)?]), Some(m))
        }
        113 => (
            16,
            u16::from_be_bytes([*f.get(14)?, *f.get(15)?]),
            f.get(6..12).map(mac),
        ),
        276 => (
            20,
            u16::from_be_bytes([*f.first()?, *f.get(1)?]),
            f.get(12..18).map(mac),
        ),
        12 | 14 | 101 | 228 => (0, 0x0800, None),
        _ => return None,
    };
    while et == 0x8100 || et == 0x88a8 {
        et = u16::from_be_bytes([*f.get(off + 2)?, *f.get(off + 3)?]);
        off += 4;
    }
    if et != 0x0800 {
        return None;
    }
    let ip = f.get(off..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let udp = ip.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }
    let ulen = (u16::from_be_bytes([udp[4], udp[5]]) as usize).clamp(8, udp.len());
    Some(Udp {
        src_mac,
        src: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        sport: u16::from_be_bytes([udp[0], udp[1]]),
        dport: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..ulen],
    })
}

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = b
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A complete Ethernet frame carrying a broadcast DHCPDISCOVER from `mac`.
/// The broadcast flag is set so offers come back as broadcasts we can
/// capture; no REQUEST follows, so no lease is taken.
pub fn discover_frame(mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut d = vec![0u8; 240];
    d[0] = 1; // BOOTREQUEST
    d[1] = 1; // Ethernet
    d[2] = 6;
    d[4..8].copy_from_slice(&xid.to_be_bytes());
    d[10] = 0x80; // broadcast flag
    d[28..34].copy_from_slice(&mac);
    d[236..240].copy_from_slice(&MAGIC);
    d.extend_from_slice(&[53, 1, 1]); // DISCOVER
    d.extend_from_slice(&[61, 7, 1]);
    d.extend_from_slice(&mac);
    d.extend_from_slice(&[55, 10, 1, 3, 6, 15, 26, 28, 42, 51, 54, 119]);
    d.extend_from_slice(&[60, 16]);
    d.extend_from_slice(b"network-analyser");
    d.push(255);
    while d.len() < 300 {
        d.push(0);
    }
    let udp_len = (8 + d.len()) as u16;
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&67u16.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum optional for IPv4
    udp.extend_from_slice(&d);
    let mut ip = vec![0x45, 0x10];
    ip.extend_from_slice(&(20 + udp_len).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255]);
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&mac);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend(ip);
    f.extend(udp);
    f
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, b) in m.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_roundtrip() {
        let mac = [0x02, 0, 0, 0, 0, 0x42];
        let f = discover_frame(mac, 0xdeadbeef);
        let u = udp_payload(1, &f).unwrap();
        assert_eq!((u.sport, u.dport), (68, 67));
        assert_eq!(u.dst, Ipv4Addr::BROADCAST);
        let m = parse(u.payload).unwrap();
        assert_eq!(m.xid, 0xdeadbeef);
        assert_eq!(m.msg_type, Some(1));
        assert!(m.broadcast);
        assert_eq!(m.chaddr, "02:00:00:00:00:42");
        assert_eq!(m.vendor_class.as_deref(), Some("network-analyser"));
        // IP header checksum verifies to zero.
        assert_eq!(checksum(&f[14..34]), 0);
    }

    #[test]
    fn offer_options() {
        let mut p = vec![0u8; 240];
        p[0] = 2;
        p[16..20].copy_from_slice(&[192, 168, 1, 50]);
        p[236..240].copy_from_slice(&MAGIC);
        p.extend_from_slice(&[
            53, 1, 2, 54, 4, 192, 168, 1, 1, 51, 4, 0, 1, 0x51, 0x80, 3, 4, 192, 168, 1, 1,
        ]);
        p.extend_from_slice(&[
            6, 8, 1, 1, 1, 1, 8, 8, 8, 8, 121, 8, 24, 10, 0, 0, 192, 168, 1, 254, 255,
        ]);
        let m = parse(&p).unwrap();
        assert_eq!(m.msg_type, Some(2));
        assert_eq!(m.yiaddr, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(m.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(m.lease_secs, Some(86400));
        assert_eq!(m.dns.len(), 2);
        let route = m.options.iter().find(|o| o.code == 121).unwrap();
        assert_eq!(route.value, "10.0.0.0/24 via 192.168.1.254");
        assert_eq!(duration(86400), "86400 s (1 d 0 h)");
    }

    #[test]
    fn macs() {
        assert_eq!(
            parse_mac("aa-bb-cc-dd-ee-ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac("aabb.ccdd.eeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert!(parse_mac("aa:bb").is_none());
    }
}
