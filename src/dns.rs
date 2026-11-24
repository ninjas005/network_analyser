//! DNS client: build queries, parse responses (all common record types),
//! UDP with TCP fallback on truncation, EDNS0 with the DNSSEC-OK bit, the
//! system's configured servers, and reverse (PTR) names.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

pub const TYPES: &[(&str, u16)] = &[
    ("A", 1),
    ("AAAA", 28),
    ("CNAME", 5),
    ("MX", 15),
    ("NS", 2),
    ("TXT", 16),
    ("SOA", 6),
    ("SRV", 33),
    ("PTR", 12),
    ("CAA", 257),
    ("HTTPS", 65),
    ("SVCB", 64),
    ("NAPTR", 35),
    ("DS", 43),
    ("DNSKEY", 48),
    ("RRSIG", 46),
    ("NSEC", 47),
    ("TLSA", 52),
    ("SSHFP", 44),
    ("ANY", 255),
];

pub fn type_name(t: u16) -> String {
    TYPES
        .iter()
        .find(|(_, v)| *v == t)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| {
            if t == 41 {
                "OPT".into()
            } else {
                format!("TYPE{t}")
            }
        })
}

pub fn parse_type(s: &str) -> Option<u16> {
    let s = s.trim().to_ascii_uppercase();
    TYPES
        .iter()
        .find(|(n, _)| *n == s)
        .map(|(_, v)| *v)
        .or_else(|| s.strip_prefix("TYPE")?.parse().ok())
}

pub fn rcode_name(r: u16) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        9 => "NOTAUTH",
        16 => "BADVERS",
        _ => "RCODE?",
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Clone, Debug, Default)]
pub struct Response {
    pub rcode: u16,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_available: bool,
    /// DNSSEC-validated by the resolver (AD bit).
    pub authentic: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub edns_udp_size: Option<u16>,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub struct Query {
    pub name: String,
    pub qtype: u16,
    pub server: SocketAddr,
    pub tcp: bool,
    pub timeout: Duration,
    pub recursion: bool,
    /// EDNS0 DO bit: ask for DNSSEC records.
    pub dnssec: bool,
}

#[derive(Clone, Debug)]
pub struct Answer {
    pub response: Response,
    pub rtt: Duration,
    pub server: SocketAddr,
    pub via_tcp: bool,
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    let name = name.trim().trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("invalid name '{name}'"));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

pub fn build_query(
    id: u16,
    name: &str,
    qtype: u16,
    recursion: bool,
    dnssec: bool,
) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&(if recursion { 0x0100u16 } else { 0 }).to_be_bytes());
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // QD=1 AN=0 NS=0 AR=1 (OPT)
    encode_name(name, &mut q)?;
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    // EDNS0 OPT: root name, type 41, UDP size 1232, ext-rcode/version 0, DO flag.
    q.push(0);
    q.extend_from_slice(&41u16.to_be_bytes());
    q.extend_from_slice(&1232u16.to_be_bytes());
    q.extend_from_slice(&[0, 0]);
    q.extend_from_slice(&(if dnssec { 0x8000u16 } else { 0 }).to_be_bytes());
    q.extend_from_slice(&[0, 0]);
    Ok(q)
}

fn be16(p: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]))
}

fn be32(p: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *p.get(i)?,
        *p.get(i + 1)?,
        *p.get(i + 2)?,
        *p.get(i + 3)?,
    ]))
}

/// Read a (possibly compressed) name; returns it and the offset after it.
pub fn read_name(p: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *p.get(pos)? as usize;
        if len == 0 {
            end.get_or_insert(pos + 1);
            break;
        }
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(pos + 2);
            pos = ((len & 0x3f) << 8) | *p.get(pos + 1)? as usize;
            continue;
        }
        let raw = p.get(pos + 1..pos + 1 + len)?;
        labels.push(
            raw.iter()
                .map(|&b| {
                    if b.is_ascii_graphic() {
                        (b as char).to_string()
                    } else {
                        format!("\\{b:03}")
                    }
                })
                .collect(),
        );
        pos += 1 + len;
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".") + "."
    };
    Some((name, end?))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn type_bitmap(mut b: &[u8]) -> String {
    let mut types = Vec::new();
    while b.len() >= 2 {
        let (win, len) = (b[0] as u16, b[1] as usize);
        let Some(bits) = b.get(2..2 + len) else { break };
        for (i, byte) in bits.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    types.push(type_name(win * 256 + (i * 8 + bit) as u16));
                }
            }
        }
        b = &b[2 + len..];
    }
    types.join(" ")
}

fn svc_params(p: &[u8], mut pos: usize, end: usize) -> String {
    let mut out = Vec::new();
    while pos + 4 <= end {
        let (Some(key), Some(len)) = (be16(p, pos), be16(p, pos + 2)) else {
            break;
        };
        let Some(v) = p.get(pos + 4..pos + 4 + len as usize) else {
            break;
        };
        out.push(match key {
            1 => {
                let mut alpn = Vec::new();
                let mut i = 0;
                while i < v.len() {
                    let l = v[i] as usize;
                    alpn.push(
                        String::from_utf8_lossy(v.get(i + 1..i + 1 + l).unwrap_or(&[]))
                            .into_owned(),
                    );
                    i += 1 + l;
                }
                format!("alpn={}", alpn.join(","))
            }
            3 => format!("port={}", be16(v, 0).unwrap_or(0)),
            4 => format!(
                "ipv4hint={}",
                v.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| Ipv4Addr::from(*c).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            6 => format!(
                "ipv6hint={}",
                v.as_chunks::<16>()
                    .0
                    .iter()
                    .map(|c| Ipv6Addr::from(*c).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            5 => "ech=…".into(),
            k => format!("key{k}={}", hex(v)),
        });
        pos += 4 + len as usize;
    }
    out.join(" ")
}

/// Presentation form of the RDATA at `pos..pos+len`.
pub fn rdata(p: &[u8], rtype: u16, pos: usize, len: usize) -> String {
    let end = pos + len;
    let Some(d) = p.get(pos..end) else {
        return "<truncated>".into();
    };
    let name_at = |at: usize| {
        read_name(p, at)
            .map(|(n, _)| n)
            .unwrap_or_else(|| "<bad name>".into())
    };
    match rtype {
        1 if len == 4 => Ipv4Addr::new(d[0], d[1], d[2], d[3]).to_string(),
        28 if len == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(d).unwrap()).to_string(),
        2 | 5 | 12 | 39 => name_at(pos),
        15 => format!("{} {}", be16(p, pos).unwrap_or(0), name_at(pos + 2)),
        16 | 99 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < d.len() {
                let l = d[i] as usize;
                parts.push(format!(
                    "\"{}\"",
                    String::from_utf8_lossy(d.get(i + 1..i + 1 + l).unwrap_or(&[]))
                ));
                i += 1 + l;
            }
            parts.join(" ")
        }
        6 => {
            let Some((mname, n1)) = read_name(p, pos) else {
                return "<bad SOA>".into();
            };
            let Some((rname, n2)) = read_name(p, n1) else {
                return "<bad SOA>".into();
            };
            let v: Vec<String> = (0..5)
                .filter_map(|i| be32(p, n2 + i * 4))
                .map(|x| x.to_string())
                .collect();
            format!("{mname} {rname} {}", v.join(" "))
        }
        33 => format!(
            "{} {} {} {}",
            be16(p, pos).unwrap_or(0),
            be16(p, pos + 2).unwrap_or(0),
            be16(p, pos + 4).unwrap_or(0),
            name_at(pos + 6)
        ),
        257 if len >= 2 => {
            let tl = d[1] as usize;
            format!(
                "{} {} \"{}\"",
                d[0],
                String::from_utf8_lossy(d.get(2..2 + tl).unwrap_or(&[])),
                String::from_utf8_lossy(d.get(2 + tl..).unwrap_or(&[]))
            )
        }
        43 if len >= 4 => format!(
            "{} {} {} {}",
            be16(d, 0).unwrap_or(0),
            d[2],
            d[3],
            hex(&d[4..])
        ),
        48 if len >= 4 => {
            let flags = be16(d, 0).unwrap_or(0);
            let role = match flags {
                257 => " (KSK)",
                256 => " (ZSK)",
                _ => "",
            };
            let key = b64(&d[4..]);
            let short = if key.len() > 40 {
                format!("{}…", &key[..40])
            } else {
                key
            };
            format!("{flags}{role} {} {} {short}", d[2], d[3])
        }
        46 if len >= 18 => {
            let signer = name_at(pos + 18);
            format!(
                "{} alg {} labels {} ttl {} expires {} inception {} tag {} {signer}",
                type_name(be16(d, 0).unwrap_or(0)),
                d[2],
                d[3],
                be32(d, 4).unwrap_or(0),
                be32(d, 8).map(unix_date).unwrap_or_default(),
                be32(d, 12).map(unix_date).unwrap_or_default(),
                be16(d, 16).unwrap_or(0)
            )
        }
        47 => match read_name(p, pos) {
            Some((next, after)) => {
                format!("{next} {}", type_bitmap(p.get(after..end).unwrap_or(&[])))
            }
            None => "<bad NSEC>".into(),
        },
        52 if len >= 3 => format!("{} {} {} {}", d[0], d[1], d[2], hex(&d[3..])),
        44 if len >= 2 => format!("{} {} {}", d[0], d[1], hex(&d[2..])),
        64 | 65 if len >= 3 => match read_name(p, pos + 2) {
            Some((target, after)) => format!(
                "{} {target} {}",
                be16(d, 0).unwrap_or(0),
                svc_params(p, after, end)
            ),
            None => hex(d),
        },
        35 if len >= 4 => {
            // order pref "flags" "service" "regexp" replacement
            let mut i = 4;
            let mut strs = Vec::new();
            for _ in 0..3 {
                let l = *d.get(i).unwrap_or(&0) as usize;
                strs.push(format!(
                    "\"{}\"",
                    String::from_utf8_lossy(d.get(i + 1..i + 1 + l).unwrap_or(&[]))
                ));
                i += 1 + l;
            }
            format!(
                "{} {} {} {}",
                be16(d, 0).unwrap_or(0),
                be16(d, 2).unwrap_or(0),
                strs.join(" "),
                name_at(pos + i)
            )
        }
        _ => format!("\\# {len} {}", hex(d)),
    }
}

/// UTC date from a 32-bit Unix timestamp (RRSIG times).
pub fn unix_date(t: u32) -> String {
    let days = t as i64 / 86400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{}-{m:02}-{d:02}", if m <= 2 { y + 1 } else { y })
}

pub fn parse_response(p: &[u8]) -> Result<Response, String> {
    if p.len() < 12 {
        return Err("response too short".into());
    }
    let flags = be16(p, 2).unwrap();
    let mut r = Response {
        rcode: flags & 0x000f,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_available: flags & 0x0080 != 0,
        authentic: flags & 0x0020 != 0,
        size: p.len(),
        ..Default::default()
    };
    let counts = [
        be16(p, 4).unwrap(),
        be16(p, 6).unwrap(),
        be16(p, 8).unwrap(),
        be16(p, 10).unwrap(),
    ];
    let mut pos = 12;
    for _ in 0..counts[0] {
        let (_, next) = read_name(p, pos).ok_or("bad question")?;
        pos = next + 4;
    }
    for (section, &n) in counts[1..].iter().enumerate() {
        for _ in 0..n {
            let (name, next) = read_name(p, pos).ok_or("bad record name")?;
            let rtype = be16(p, next).ok_or("truncated record")?;
            let class = be16(p, next + 2).ok_or("truncated record")?;
            let ttl = be32(p, next + 4).ok_or("truncated record")?;
            let len = be16(p, next + 8).ok_or("truncated record")? as usize;
            let start = next + 10;
            if start + len > p.len() {
                return Err("truncated record data".into());
            }
            pos = start + len;
            if rtype == 41 {
                r.edns_udp_size = Some(class);
                // Extended RCODE lives in the TTL's high byte.
                r.rcode |= ((ttl >> 24) as u16) << 4;
                continue;
            }
            let rec = Record {
                name,
                rtype,
                ttl,
                data: rdata(p, rtype, start, len),
            };
            match section {
                0 => r.answers.push(rec),
                1 => r.authority.push(rec),
                _ => r.additional.push(rec),
            }
        }
    }
    Ok(r)
}

fn exchange_udp(q: &[u8], server: SocketAddr, wait: Duration) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let s = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(wait)).ok();
    s.connect(server).map_err(|e| format!("{server}: {e}"))?;
    let id = [q[0], q[1]];
    let mut buf = vec![0u8; 4096];
    for _attempt in 0..2 {
        s.send(q).map_err(|e| format!("{server}: {e}"))?;
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            match s.recv(&mut buf) {
                Ok(n) if n >= 2 && buf[..2] == id => return Ok(buf[..n].to_vec()),
                Ok(_) => continue, // stale/foreign answer
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) => return Err(format!("{server}: {e}")),
            }
        }
    }
    Err(format!("no response from {server}"))
}

fn exchange_tcp(q: &[u8], server: SocketAddr, wait: Duration) -> Result<Vec<u8>, String> {
    let mut s =
        TcpStream::connect_timeout(&server, wait).map_err(|e| format!("{server} (TCP): {e}"))?;
    s.set_read_timeout(Some(wait)).ok();
    s.set_write_timeout(Some(wait)).ok();
    let mut msg = (q.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(q);
    s.write_all(&msg).map_err(|e| e.to_string())?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len)
        .map_err(|e| format!("{server} (TCP): {e}"))?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)
        .map_err(|e| format!("{server} (TCP): {e}"))?;
    Ok(buf)
}

fn random_id() -> u16 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (t ^ (t >> 16) ^ std::process::id()) as u16
}

/// Blocking query. Falls back to TCP when the UDP answer is truncated.
pub fn query(q: &Query) -> Result<Answer, String> {
    let id = random_id();
    let msg = build_query(id, &q.name, q.qtype, q.recursion, q.dnssec)?;
    let t = Instant::now();
    let mut via_tcp = q.tcp;
    let raw = if q.tcp {
        exchange_tcp(&msg, q.server, q.timeout)?
    } else {
        exchange_udp(&msg, q.server, q.timeout)?
    };
    let mut resp = parse_response(&raw)?;
    if resp.truncated && !q.tcp {
        via_tcp = true;
        resp = parse_response(&exchange_tcp(&msg, q.server, q.timeout)?)?;
    }
    Ok(Answer {
        response: resp,
        rtt: t.elapsed(),
        server: q.server,
        via_tcp,
    })
}

/// "8.8.8.8", "1.1.1.1:5353", "[2606:4700::1111]:53", "dns.google".
pub fn parse_server(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = s.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => {
            (h, p.parse().unwrap_or(53))
        }
        _ => (s, 53),
    };
    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| format!("server '{s}': {e}"))?
        .next()
        .ok_or_else(|| format!("server '{s}' has no address"))
}

pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::new();
            for b in v6.octets().iter().rev() {
                let _ = write!(s, "{:x}.{:x}.", b & 0xf, b >> 4);
            }
            s + "ip6.arpa"
        }
    }
}

/// Resolvers configured on this machine (best effort, per OS).
pub fn system_servers() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    #[cfg(unix)]
    {
        if let Ok(t) = std::fs::read_to_string("/etc/resolv.conf") {
            for l in t.lines() {
                if let Some(rest) = l.trim().strip_prefix("nameserver")
                    && let Ok(ip) = rest.trim().split('%').next().unwrap_or("").parse()
                {
                    out.push(ip);
                }
            }
        }
        if cfg!(target_os = "macos")
            && let Ok(o) = crate::platform::command("scutil").arg("--dns").output()
        {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                if let Some((k, v)) = l.split_once(':')
                    && k.trim().starts_with("nameserver[")
                    && let Ok(ip) = v.trim().parse()
                {
                    out.push(ip);
                }
            }
        }
    }
    #[cfg(windows)]
    {
        // Locale-independent, unlike ipconfig's labels.
        if let Ok(o) = crate::platform::command("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses",
            ])
            .output()
        {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                if let Ok(ip) = l.trim().parse() {
                    out.push(ip);
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|ip| seen.insert(*ip));
    out
}

/// Upstream servers behind systemd-resolved's 127.0.0.53 stub (Linux).
pub fn resolved_upstreams() -> Vec<IpAddr> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let Ok(o) = crate::platform::command("resolvectl").arg("dns").output() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for l in String::from_utf8_lossy(&o.stdout).lines() {
        if let Some((_, v)) = l.split_once(':') {
            for w in v.split_whitespace() {
                if let Ok(ip) = w.split('#').next().unwrap_or("").parse::<IpAddr>()
                    && !out.contains(&ip)
                {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// Well-known public resolvers offered in the UI.
pub const PUBLIC_RESOLVERS: &[(&str, &str)] = &[
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let q = build_query(0x1234, "example.com", 1, true, true).unwrap();
        assert_eq!(&q[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&q[12..25], b"\x07example\x03com\x00");
        // OPT with DO bit
        assert_eq!(
            &q[q.len() - 11..],
            &[0, 0, 41, 4, 0xd0, 0, 0, 0x80, 0, 0, 0]
        );
        assert!(build_query(1, "a..b", 1, true, false).is_err());
    }

    #[test]
    fn parse_answers() {
        // Response: example.com A 93.184.216.34, MX 10 mail.example.com (compressed)
        let mut p = vec![0x12, 0x34, 0x81, 0xa0, 0, 1, 0, 2, 0, 0, 0, 0];
        p.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        p.extend_from_slice(&[
            0xc0, 12, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34,
        ]);
        p.extend_from_slice(&[
            0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 9, 0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12,
        ]);
        let r = parse_response(&p).unwrap();
        assert!(r.recursion_available && r.authentic && !r.authoritative);
        assert_eq!(r.answers[0].data, "93.184.216.34");
        assert_eq!(r.answers[0].ttl, 3600);
        assert_eq!(r.answers[1].data, "10 mail.example.com.");
        assert_eq!(r.answers[1].name, "example.com.");
    }

    #[test]
    fn names_and_types() {
        assert_eq!(
            reverse_name("192.0.2.5".parse().unwrap()),
            "5.2.0.192.in-addr.arpa"
        );
        assert!(
            reverse_name("2001:db8::1".parse().unwrap()).ends_with(".8.b.d.0.1.0.0.2.ip6.arpa")
        );
        assert_eq!(parse_type("aaaa"), Some(28));
        assert_eq!(parse_type("TYPE99"), Some(99));
        assert_eq!(type_name(257), "CAA");
        assert_eq!(parse_server("1.1.1.1").unwrap().port(), 53);
        assert_eq!(parse_server("[::1]:5353").unwrap().port(), 5353);
        assert_eq!(unix_date(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn live_localhost_resolver_if_any() {
        // Real query against the system resolver; skipped offline.
        let Some(server) = system_servers().first().copied() else {
            return;
        };
        let q = Query {
            name: "localhost".into(),
            qtype: 1,
            server: SocketAddr::new(server, 53),
            tcp: false,
            timeout: Duration::from_millis(800),
            recursion: true,
            dnssec: false,
        };
        let _ = query(&q); // must not panic whatever the network says
    }
}
