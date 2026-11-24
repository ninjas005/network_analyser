//! Application-protocol identification and decoding for the packet dissector.
//! Content signatures are tried first, so a service on an unusual port is
//! still recognised; well-known ports are the fallback. The result says which
//! of the two it was.

use std::net::Ipv4Addr;

use crate::dissect::Layer;
use crate::modbus;

/// How a protocol was recognised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum How {
    Signature,
    Port(u16),
}

impl How {
    pub fn text(self) -> String {
        match self {
            How::Signature => "content signature".into(),
            How::Port(p) => format!("port {p} (content not verified)"),
        }
    }
}

pub struct App {
    pub proto: &'static str,
    pub info: String,
    pub layers: Vec<Layer>,
    pub how: How,
    pub dns: Option<Box<DnsMsg>>,
}

impl App {
    fn new(proto: &'static str, info: impl Into<String>, how: How) -> Self {
        App {
            proto,
            info: info.into(),
            layers: Vec::new(),
            how,
            dns: None,
        }
    }
    fn with(mut self, l: Layer) -> Self {
        self.layers.push(l);
        self
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DnsRecord {
    pub section: &'static str,
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Clone, Debug, Default)]
pub struct DnsMsg {
    pub id: u16,
    pub response: bool,
    pub rcode: u16,
    pub truncated: bool,
    pub authoritative: bool,
    pub authentic: bool,
    /// (name without the final dot, type)
    pub questions: Vec<(String, u16)>,
    pub records: Vec<DnsRecord>,
}

impl DnsMsg {
    pub fn answers(&self) -> impl Iterator<Item = &DnsRecord> {
        self.records.iter().filter(|r| r.section == "Answer")
    }
}

// ---------------------------------------------------------------- helpers

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn be24(b: &[u8], i: usize) -> Option<usize> {
    let s = b.get(i..i + 3)?;
    Some((s[0] as usize) << 16 | (s[1] as usize) << 8 | s[2] as usize)
}
fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}
fn le16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn le32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// Printable text: control characters become spaces.
fn clean(b: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&b[..b.len().min(max)])
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn first_line(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == b'\n').unwrap_or(b.len());
    clean(&b[..end], 200)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Port-identified protocol that carries text lines.
fn line_app(proto: &'static str, p: &[u8], how: How) -> App {
    let line = first_line(p);
    let mut l = Layer::new(proto);
    for x in p.split(|c| *c == b'\n').take(12) {
        let t = clean(x, 300);
        if !t.is_empty() {
            l.f("Line", t);
        }
    }
    App::new(proto, line, how).with(l)
}

// ---------------------------------------------------------------- TCP

pub const HTTP_METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Starts with an HTTP/1.x request line or status line.
pub fn is_http(p: &[u8]) -> bool {
    if p.starts_with(b"HTTP/1.") {
        return true;
    }
    let Some(m) = HTTP_METHODS
        .iter()
        .find(|m| p.starts_with(m.as_bytes()) && p.get(m.len()) == Some(&b' '))
    else {
        return false;
    };
    // The request line must say HTTP/1 (if its end is in this data), so
    // RTSP / SIP OPTIONS are not mistaken for HTTP.
    match p.iter().position(|c| *c == b'\n') {
        Some(e) => p[..e].windows(7).any(|w| w == b"HTTP/1."),
        None => p.len() > m.len() + 1,
    }
}

pub fn tcp(p: &[u8], sp: u16, dp: u16) -> Option<App> {
    tcp_signature(p, sp, dp).or_else(|| tcp_port(p, sp, dp))
}

fn tcp_signature(p: &[u8], sp: u16, dp: u16) -> Option<App> {
    const S: How = How::Signature;
    if let Some(a) = tls(p, "TLS") {
        return Some(a);
    }
    if p.starts_with(b"PRI * HTTP/2.0") {
        return Some(App::new("HTTP/2", "Connection preface", S));
    }
    if is_http(p) {
        return Some(http(p));
    }
    if p.starts_with(b"SSH-") {
        let line = first_line(p);
        let mut l = Layer::new("SSH");
        l.f("Banner", &line);
        return Some(App::new("SSH", line, S).with(l));
    }
    let line_has = |tag: &[u8]| {
        let e = p
            .iter()
            .position(|c| *c == b'\n')
            .unwrap_or(p.len().min(512));
        p[..e].windows(tag.len()).any(|w| w == tag)
    };
    if line_has(b"RTSP/1.0") {
        return Some(line_app("RTSP", p, S));
    }
    if line_has(b"SIP/2.0") {
        return Some(line_app("SIP", p, S));
    }
    if let Some(a) = smb(p) {
        return Some(a);
    }
    if p.len() >= 7 && p[0] == 3 && p[1] == 0 && be16(p, 2).is_some_and(|n| n >= 7) {
        // TPKT + COTP
        if p[5] == 0xf0 && p.get(7) == Some(&0x32) {
            return Some(s7(&p[7..]));
        }
        if p[5] == 0xe0 || p[5] == 0xd0 {
            let t = if p[5] == 0xe0 {
                "Connection request"
            } else {
                "Connection confirm"
            };
            let rdp = p.windows(8).any(|w| w == b"mstshash") || sp == 3389 || dp == 3389;
            return Some(App::new(if rdp { "RDP" } else { "COTP" }, t, S));
        }
    }
    if p.len() >= 8
        && matches!(
            &p[..3],
            b"HEL" | b"ACK" | b"ERR" | b"OPN" | b"MSG" | b"CLO" | b"RHE"
        )
        && matches!(p[3], b'F' | b'C' | b'A')
        && le32(p, 4).is_some_and(|n| (8..1 << 24).contains(&n))
    {
        let t = match &p[..3] {
            b"HEL" => "Hello",
            b"ACK" => "Acknowledge",
            b"ERR" => "Error",
            b"OPN" => "Open secure channel",
            b"CLO" => "Close secure channel",
            b"RHE" => "Reverse hello",
            _ => "Message",
        };
        let mut l = Layer::new("OPC UA");
        l.f("Message", t).f("Size", le32(p, 4).unwrap_or(0));
        if matches!(&p[..3], b"OPN" | b"MSG" | b"CLO")
            && let Some(ch) = le32(p, 8)
        {
            l.f("Secure channel", ch);
        }
        if &p[..3] == b"HEL"
            && let Some(u) = p.get(32..)
        {
            l.f("Endpoint", clean(u, 200));
        }
        return Some(App::new("OPC UA", t, S).with(l));
    }
    if p.len() >= 19 && p[..16] == [0xff; 16] {
        let t = match p[18] {
            1 => "OPEN",
            2 => "UPDATE",
            3 => "NOTIFICATION",
            4 => "KEEPALIVE",
            _ => "message",
        };
        return Some(App::new("BGP", t, S));
    }
    if p.len() >= 10 && p[0] == 0x05 && p[1] == 0x64 && p[2] >= 5 {
        let mut l = Layer::new("DNP3");
        l.f("Destination", le16(p, 4)?).f("Source", le16(p, 6)?);
        return Some(App::new("DNP3", format!("{} → {}", le16(p, 6)?, le16(p, 4)?), S).with(l));
    }
    if p.starts_with(b"RFB 00") {
        return Some(line_app("VNC", p, S));
    }
    if p.starts_with(b"\x13BitTorrent protocol") {
        return Some(App::new("BitTorrent", "Handshake", S));
    }
    if p.starts_with(b"AMQP") && p.len() >= 8 {
        return Some(App::new(
            "AMQP",
            format!("Protocol header {}.{}.{}", p[5], p[6], p[7]),
            S,
        ));
    }
    if p.first() == Some(&0x10)
        && p.len() > 10
        && p[..12.min(p.len())].windows(4).any(|w| w == b"MQTT")
    {
        return mqtt(p, S);
    }
    if p.len() > 6 && p[3] == 0 && p[4] == 10 && p[5].is_ascii_digit() && sp == 3306 {
        let v = p[5..].split(|c| *c == 0).next().unwrap_or(&[]);
        return Some(App::new(
            "MySQL",
            format!("Server greeting {}", clean(v, 60)),
            S,
        ));
    }
    if p.len() >= 8 && be32(p, 0) == Some(p.len() as u32) {
        match be32(p, 4) {
            Some(0x0003_0000) => return Some(App::new("PostgreSQL", "Startup message", S)),
            Some(80877103) => return Some(App::new("PostgreSQL", "SSL request", S)),
            _ => {}
        }
    }
    if matches!(p.first(), Some(b'*' | b'+' | b'-' | b'$' | b':')) && (sp == 6379 || dp == 6379) {
        return Some(redis(p));
    }
    None
}

fn tcp_port(p: &[u8], sp: u16, dp: u16) -> Option<App> {
    let either = |port: u16| sp == port || dp == port;
    if either(502) {
        let lines = modbus::decode_tcp(p, Some(dp == 502));
        if !lines.is_empty() {
            let mut l = Layer::new("Modbus/TCP");
            for (i, s) in lines.iter().enumerate() {
                l.f(&format!("ADU {}", i + 1), s);
            }
            return Some(App::new("Modbus/TCP", lines.join(" | "), How::Port(502)).with(l));
        }
    }
    if either(53) {
        // Two length bytes, then the message.
        let n = be16(p, 0)? as usize;
        let body = p.get(2..)?;
        return dns(&body[..n.min(body.len())], "DNS", How::Port(53));
    }
    if either(1883) {
        return mqtt(p, How::Port(1883));
    }
    if either(2404) && p.len() >= 6 && p[0] == 0x68 {
        let t = match p[2] & 3 {
            3 => match p[2] {
                0x07 => "U STARTDT act",
                0x0b => "U STARTDT con",
                0x13 => "U STOPDT act",
                0x23 => "U STOPDT con",
                0x43 => "U TESTFR act",
                0x83 => "U TESTFR con",
                _ => "U frame",
            }
            .to_string(),
            1 => "S acknowledge".to_string(),
            _ => format!(
                "I frame, type {}",
                p.get(6).map_or("?".into(), |t| t.to_string())
            ),
        };
        return Some(App::new("IEC 104", t, How::Port(2404)));
    }
    if either(44818) && p.len() >= 24 {
        return Some(enip(p, How::Port(44818)));
    }
    for (port, name) in [
        (21, "FTP"),
        (25, "SMTP"),
        (587, "SMTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (23, "Telnet"),
        (6667, "IRC"),
    ] {
        if either(port) {
            return Some(line_app(name, p, How::Port(port)));
        }
    }
    for (port, name) in [
        (445, "SMB"),
        (139, "SMB"),
        (3389, "RDP"),
        (389, "LDAP"),
        (88, "Kerberos"),
        (22, "SSH"),
        (5432, "PostgreSQL"),
        (3306, "MySQL"),
        (1433, "TDS"),
        (2049, "NFS"),
        (4840, "OPC UA"),
        (102, "COTP"),
        (20000, "DNP3"),
    ] {
        if either(port) {
            return Some(App::new(
                name,
                format!("{} bytes", p.len()),
                How::Port(port),
            ));
        }
    }
    None
}

fn redis(p: &[u8]) -> App {
    let words: Vec<String> = p
        .split(|c| *c == b'\n')
        .map(|l| clean(l, 80))
        .filter(|l| !l.is_empty() && !l.starts_with('$') && !l.starts_with('*'))
        .take(6)
        .collect();
    App::new("Redis", words.join(" "), How::Signature)
}

fn http(p: &[u8]) -> App {
    let text = String::from_utf8_lossy(&p[..p.len().min(8192)]);
    let mut l = Layer::new("Hypertext Transfer Protocol");
    let line = first_line(p);
    l.f("Line", &line);
    for h in text.lines().skip(1).take_while(|h| !h.is_empty()).take(40) {
        if let Some((k, v)) = h.split_once(':') {
            l.f(k.trim(), clean(v.as_bytes(), 400));
        }
    }
    App::new("HTTP", line, How::Signature).with(l)
}

fn smb(p: &[u8]) -> Option<App> {
    let h = p.get(4..)?;
    if p[0] != 0 || h.len() < 5 {
        return None;
    }
    if &h[..4] == b"\xffSMB" {
        return Some(App::new(
            "SMB",
            format!("SMBv1 command 0x{:02x} (obsolete version)", h[4]),
            How::Signature,
        ));
    }
    if &h[..4] == b"\xfdSMB" {
        return Some(App::new("SMB", "SMB3 encrypted message", How::Signature));
    }
    if &h[..4] != b"\xfeSMB" {
        return None;
    }
    let cmd = match le16(h, 12)? {
        0 => "Negotiate",
        1 => "Session setup",
        2 => "Logoff",
        3 => "Tree connect",
        4 => "Tree disconnect",
        5 => "Create",
        6 => "Close",
        7 => "Flush",
        8 => "Read",
        9 => "Write",
        10 => "Lock",
        11 => "Ioctl",
        13 => "Echo",
        14 => "Query directory",
        15 => "Change notify",
        16 => "Query info",
        17 => "Set info",
        _ => "command",
    };
    let resp = le32(h, 16)? & 1 == 1;
    let status = le32(h, 8)?;
    let mut l = Layer::new("SMB2");
    l.f("Command", cmd)
        .f("Direction", if resp { "response" } else { "request" });
    if resp {
        l.f("Status", format!("0x{status:08x}"));
    }
    let info = format!("{cmd} {}", if resp { "response" } else { "request" });
    Some(App::new("SMB", info, How::Signature).with(l))
}

fn s7(p: &[u8]) -> App {
    let t = match p.get(1) {
        Some(1) => "Job",
        Some(2) => "Ack",
        Some(3) => "Ack data",
        Some(7) => "User data",
        _ => "PDU",
    };
    let head = if matches!(p.get(1), Some(2 | 3)) {
        12
    } else {
        10
    };
    let f = match p.get(head) {
        Some(0x04) => "Read variable",
        Some(0x05) => "Write variable",
        Some(0xf0) => "Setup communication",
        Some(0x28) => "PLC control",
        Some(0x29) => "PLC stop",
        Some(0x1a..=0x1c) => "Download",
        Some(0x1d..=0x1f) => "Upload",
        _ => "",
    };
    let info = format!("{t} {f}").trim().to_string();
    let mut l = Layer::new("S7comm");
    l.f("Type", t).f("Function", f);
    App::new("S7comm", info, How::Signature).with(l)
}

fn enip(p: &[u8], how: How) -> App {
    let t = match le16(p, 0) {
        Some(0x04) => "List services",
        Some(0x63) => "List identity",
        Some(0x64) => "List interfaces",
        Some(0x65) => "Register session",
        Some(0x66) => "Unregister session",
        Some(0x6f) => "Send RR data",
        Some(0x70) => "Send unit data",
        _ => "message",
    };
    let mut l = Layer::new("EtherNet/IP");
    l.f("Command", t);
    if let (Some(s), Some(st)) = (le32(p, 4), le32(p, 8)) {
        l.f("Session", format!("0x{s:08x}")).f("Status", st);
    }
    App::new("EtherNet/IP", t, how).with(l)
}

fn mqtt(p: &[u8], how: How) -> Option<App> {
    let b = *p.first()?;
    let (mut len, mut shift, mut i) = (0usize, 0, 1);
    loop {
        let x = *p.get(i)?;
        len |= ((x & 0x7f) as usize) << shift;
        i += 1;
        if x & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 21 {
            return None;
        }
    }
    let t = match b >> 4 {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        15 => "AUTH",
        _ => return None,
    };
    let body = &p[i..];
    let mut l = Layer::new("MQTT");
    l.f("Message", t).f("Remaining length", len);
    let mut info = t.to_string();
    let s = |at: usize| -> Option<(String, usize)> {
        let n = be16(body, at)? as usize;
        Some((clean(body.get(at + 2..at + 2 + n)?, 200), at + 2 + n))
    };
    match b >> 4 {
        1 => {
            if let Some((_, at)) = s(0) {
                if let Some(v) = body.get(at) {
                    l.f(
                        "Version",
                        match v {
                            3 => "3.1",
                            4 => "3.1.1",
                            5 => "5.0",
                            _ => "?",
                        },
                    );
                }
                if let Some(f) = body.get(at + 1) {
                    l.f("User name", if f & 0x80 != 0 { "present" } else { "no" });
                }
                // 5.0 has properties before the client ID.
                if body.get(at) != Some(&5)
                    && let Some((id, _)) = s(at + 4)
                {
                    l.f("Client ID", &id);
                    info = format!("CONNECT {id}");
                }
            }
        }
        2 => {
            if let Some(c) = body.get(1) {
                l.f("Return code", c);
                info = format!("CONNACK code {c}");
            }
        }
        3 => {
            if let Some((topic, _)) = s(0) {
                l.f("Topic", &topic)
                    .f("QoS", (b >> 1) & 3)
                    .f("Retain", b & 1 == 1);
                info = format!("PUBLISH {topic}");
            }
        }
        8 => {
            if let Some((topic, _)) = s(2).filter(|(t, _)| !t.is_empty()) {
                l.f("Topic filter", &topic);
                info = format!("SUBSCRIBE {topic}");
            }
        }
        _ => {}
    }
    Some(App::new("MQTT", info, how).with(l))
}

// ---------------------------------------------------------------- TLS

pub fn tls_version(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        0xfeff => "DTLS 1.0".into(),
        0xfefd => "DTLS 1.2".into(),
        0xfefc => "DTLS 1.3".into(),
        v => format!("0x{v:04x}"),
    }
}

fn cipher_name(c: u16) -> String {
    let n = match c {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xc009 => "ECDHE-ECDSA-AES128-SHA",
        0xc00a => "ECDHE-ECDSA-AES256-SHA",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",
        0xc023 => "ECDHE-ECDSA-AES128-SHA256",
        0xc027 => "ECDHE-RSA-AES128-SHA256",
        0x009c => "RSA-AES128-GCM-SHA256",
        0x009d => "RSA-AES256-GCM-SHA384",
        0x002f => "RSA-AES128-SHA",
        0x0035 => "RSA-AES256-SHA",
        0x003c => "RSA-AES128-SHA256",
        0x000a => "RSA-3DES-EDE-SHA (weak)",
        0x0005 => "RSA-RC4-128-SHA (broken)",
        0x0004 => "RSA-RC4-128-MD5 (broken)",
        _ => return format!("0x{c:04x}"),
    };
    format!("{n} (0x{c:04x})")
}

/// Fields of a hello message's extensions block.
#[derive(Default)]
struct Exts {
    sni: Option<String>,
    alpn: Vec<String>,
    versions: Vec<u16>,
    count: usize,
}

fn extensions(b: &[u8], server: bool) -> Exts {
    let mut e = Exts::default();
    let mut i = 0;
    while let (Some(t), Some(n)) = (be16(b, i), be16(b, i + 2)) {
        let Some(v) = b.get(i + 4..i + 4 + n as usize) else {
            break;
        };
        e.count += 1;
        match t {
            0 if !server => {
                if let Some(n) = be16(v, 3) {
                    e.sni = v
                        .get(5..5 + n as usize)
                        .map(|x| clean(x, 255))
                        .filter(|s| !s.is_empty());
                }
            }
            16 => {
                let mut at = 2;
                while let Some(&l) = v.get(at) {
                    let Some(x) = v.get(at + 1..at + 1 + l as usize) else {
                        break;
                    };
                    e.alpn.push(clean(x, 60));
                    at += 1 + l as usize;
                }
            }
            43 if server => e.versions.extend(be16(v, 0)),
            43 => {
                let mut at = 1;
                while let Some(x) = be16(v, at) {
                    // Skip GREASE values.
                    if x & 0x0f0f != 0x0a0a {
                        e.versions.push(x);
                    }
                    at += 2;
                }
            }
            _ => {}
        }
        i += 4 + n as usize;
    }
    e
}

/// Server name in a TLS ClientHello record.
pub fn client_hello_sni(p: &[u8]) -> Option<String> {
    if p.first() != Some(&0x16) || p.get(5) != Some(&1) {
        return None;
    }
    hello(p.get(9..)?, false).and_then(|h| h.ext.sni)
}

struct Hello {
    version: u16,
    ciphers: Vec<u16>,
    ext: Exts,
}

/// Body of a ClientHello / ServerHello (after the handshake header).
fn hello(h: &[u8], server: bool) -> Option<Hello> {
    let version = be16(h, 0)?;
    let mut i = 34;
    i += 1 + *h.get(i)? as usize;
    let mut ciphers = Vec::new();
    if server {
        ciphers.push(be16(h, i)?);
        i += 3;
    } else {
        let n = be16(h, i)? as usize;
        let c = h.get(i + 2..i + 2 + n)?;
        ciphers.extend(
            c.as_chunks::<2>()
                .0
                .iter()
                .map(|x| u16::from_be_bytes([x[0], x[1]]))
                .filter(|x| x & 0x0f0f != 0x0a0a),
        );
        i += 2 + n;
        i += 1 + *h.get(i)? as usize;
    }
    let ext = match be16(h, i) {
        Some(n) => {
            let b = h.get(i + 2..).unwrap_or(&[]);
            // Large hellos continue in the next segment: use what is here.
            extensions(&b[..b.len().min(n as usize)], server)
        }
        None => Exts::default(),
    };
    Some(Hello {
        version,
        ciphers,
        ext,
    })
}

fn alert_text(level: u8, code: u8) -> String {
    let t = match code {
        0 => "close notify",
        10 => "unexpected message",
        20 => "bad record MAC",
        40 => "handshake failure",
        42 => "bad certificate",
        43 => "unsupported certificate",
        44 => "certificate revoked",
        45 => "certificate expired",
        46 => "certificate unknown",
        47 => "illegal parameter",
        48 => "unknown CA",
        49 => "access denied",
        50 => "decode error",
        51 => "decrypt error",
        70 => "protocol version",
        71 => "insufficient security",
        80 => "internal error",
        86 => "inappropriate fallback",
        90 => "user cancelled",
        109 => "missing extension",
        112 => "unrecognised name",
        116 => "certificate required",
        120 => "no application protocol",
        _ => "alert",
    };
    format!("{} {t}", if level == 2 { "fatal" } else { "warning" })
}

fn tls(p: &[u8], proto: &'static str) -> Option<App> {
    if p.len() < 6 || !matches!(p[0], 0x14..=0x17) || p[1] != 3 || p[2] > 4 {
        return None;
    }
    let mut l = Layer::new("Transport Layer Security");
    l.f("Record version", tls_version(be16(p, 1)?));
    let mut parts: Vec<String> = Vec::new();
    let mut at = 0;
    let mut encrypted = false;
    // Walk every complete record start in this segment.
    while parts.len() < 8 {
        let Some(h) = p.get(at..at + 5) else { break };
        if !matches!(h[0], 0x14..=0x17) || h[1] != 3 {
            break;
        }
        let n = be16(h, 3)? as usize;
        let body = p.get(at + 5..).unwrap_or(&[]);
        let body = &body[..body.len().min(n)];
        let part = match h[0] {
            0x14 => {
                encrypted = true;
                "Change Cipher Spec".to_string()
            }
            0x15 if !encrypted && n == 2 && body.len() == 2 => {
                let t = format!("Alert: {}", alert_text(body[0], body[1]));
                l.f("Alert", alert_text(body[0], body[1]));
                t
            }
            0x15 => "Encrypted alert".into(),
            0x16 if !encrypted => tls_handshake(body, &mut l),
            0x16 => "Encrypted handshake".into(),
            _ => "Application data".into(),
        };
        if parts.last() != Some(&part) {
            parts.push(part);
        }
        at += 5 + n;
    }
    if parts.is_empty() {
        return None;
    }
    Some(App::new(proto, parts.join(", "), How::Signature).with(l))
}

fn tls_handshake(mut b: &[u8], l: &mut Layer) -> String {
    let mut out: Vec<String> = Vec::new();
    while let (Some(&t), Some(n)) = (b.first(), be24(b, 1)) {
        let rest = &b[4..];
        let body = &rest[..rest.len().min(n)];
        let name = match t {
            0 => "Hello Request",
            1 => "Client Hello",
            2 => "Server Hello",
            4 => "New Session Ticket",
            8 => "Encrypted Extensions",
            11 => "Certificate",
            12 => "Server Key Exchange",
            13 => "Certificate Request",
            14 => "Server Hello Done",
            15 => "Certificate Verify",
            16 => "Client Key Exchange",
            20 => "Finished",
            22 => "Certificate Status",
            _ => {
                if out.is_empty() {
                    out.push("Encrypted handshake".into());
                }
                break;
            }
        };
        l.f("Handshake", name);
        let mut text = name.to_string();
        match t {
            1 | 2 => {
                if let Some(h) = hello(body, t == 2) {
                    let versions: Vec<String> =
                        h.ext.versions.iter().map(|v| tls_version(*v)).collect();
                    if versions.is_empty() {
                        l.f("Version", tls_version(h.version));
                    } else {
                        l.f("Version", versions.join(", "));
                    }
                    if t == 1 {
                        if let Some(s) = &h.ext.sni {
                            l.f("Server name (SNI)", s);
                            text = format!("{name}, SNI={s}");
                        }
                        l.f("Cipher suites", h.ciphers.len());
                        for c in h.ciphers.iter().take(24) {
                            l.f("  offered", cipher_name(*c));
                        }
                    } else if let Some(c) = h.ciphers.first() {
                        l.f("Cipher suite", cipher_name(*c));
                        let v = h.ext.versions.first().copied().unwrap_or(h.version);
                        text = format!("{name}, {}", tls_version(v));
                    }
                    if !h.ext.alpn.is_empty() {
                        l.f("ALPN", h.ext.alpn.join(", "));
                    }
                    l.f("Extensions", h.ext.count);
                }
            }
            11 => {
                // TLS 1.2 certificate list: total(3) then len(3) + DER.
                if let Some(n) = be24(body, 3)
                    && let Some(der) = body.get(6..6 + n)
                    && let Ok((_, c)) = x509_parser::parse_x509_certificate(der)
                {
                    l.f("Subject", c.subject())
                        .f("Issuer", c.issuer())
                        .f("Not after", c.validity().not_after);
                }
            }
            _ => {}
        }
        out.push(text);
        match rest.get(n..) {
            Some(r) if !r.is_empty() => b = r,
            _ => break,
        }
    }
    if out.is_empty() {
        "Handshake".into()
    } else {
        out.join(", ")
    }
}

// ---------------------------------------------------------------- UDP

pub fn udp(p: &[u8], sp: u16, dp: u16) -> Option<App> {
    udp_signature(p, sp, dp).or_else(|| udp_port(p, sp, dp))
}

fn udp_signature(p: &[u8], sp: u16, dp: u16) -> Option<App> {
    const S: How = How::Signature;
    let either = |port: u16| sp == port || dp == port;
    if p.len() >= 20 && p[0] & 0xc0 == 0 && be32(p, 4) == Some(0x2112_a442) {
        let t = match be16(p, 0)? {
            0x0001 => "Binding request",
            0x0101 => "Binding response",
            0x0111 => "Binding error",
            0x0003 => "TURN allocate request",
            0x0103 => "TURN allocate response",
            0x0016 | 0x0017 => "TURN data",
            _ => "message",
        };
        return Some(App::new("STUN", t, S));
    }
    if p.len() >= 13 && matches!(p[0], 0x14..=0x17) && p[1] == 0xfe && matches!(p[2], 0xff | 0xfd) {
        let t = match (p[0], p.get(13)) {
            (0x16, Some(1)) => "Client Hello",
            (0x16, Some(2)) => "Server Hello",
            (0x16, _) => "Handshake",
            (0x14, _) => "Change Cipher Spec",
            (0x15, _) => "Alert",
            _ => "Application data",
        };
        return Some(App::new("DTLS", t, S));
    }
    if p.len() >= 240 && p[236..240] == [99, 130, 83, 99] {
        return Some(dhcp(p, S));
    }
    // WireGuard: type byte, three zero bytes, fixed handshake sizes.
    if p.len() >= 32 && p[1..4] == [0, 0, 0] {
        let t = match (p[0], p.len()) {
            (1, 148) => Some("Handshake initiation"),
            (2, 92) => Some("Handshake response"),
            (3, 64) => Some("Cookie reply"),
            (4, n) if n % 16 == 0 && either(51820) => Some("Transport data"),
            _ => None,
        };
        if let Some(t) = t {
            return Some(App::new("WireGuard", t, S));
        }
    }
    // QUIC long header with a known version.
    if p.len() >= 7 && p[0] & 0xc0 == 0xc0 {
        let v = be32(p, 1)?;
        let name = match v {
            1 => Some("v1".to_string()),
            0x6b33_43cf => Some("v2".to_string()),
            0xff00_0000..=0xff00_0022 => Some(format!("draft-{}", v & 0xff)),
            0 if either(443) => Some("version negotiation".into()),
            _ => None,
        };
        if let Some(n) = name {
            let kinds = ["Initial", "0-RTT", "Handshake", "Retry"];
            let k = ((p[0] >> 4) & 3) as usize;
            // QUIC v2 rotates the packet type numbers by one.
            let kind = if v == 0x6b33_43cf {
                ["Retry", "Initial", "0-RTT", "Handshake"][k]
            } else {
                kinds[k]
            };
            let dl = p[5] as usize;
            let mut l = Layer::new("QUIC");
            l.f("Version", &n).f("Packet type", kind);
            if let Some(id) = p.get(6..6 + dl).filter(|_| dl <= 20) {
                l.f("Destination connection ID", hexs(id));
            }
            return Some(App::new("QUIC", format!("{kind}, {n}"), S).with(l));
        }
    }
    if p.starts_with(b"M-SEARCH * HTTP/1.1")
        || p.starts_with(b"NOTIFY * HTTP/1.1")
        || (either(1900) && p.starts_with(b"HTTP/1.1 200"))
    {
        let st = String::from_utf8_lossy(p).lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.eq_ignore_ascii_case("ST") || k.eq_ignore_ascii_case("NT"))
                .then(|| v.trim().to_string())
        });
        let mut a = line_app("SSDP", p, S);
        if let Some(st) = st {
            a.info = format!("{} — {}", a.info, clean(st.as_bytes(), 120));
        }
        return Some(a);
    }
    if p.windows(7).take(400).any(|w| w == b"SIP/2.0") {
        return Some(line_app("SIP", p, S));
    }
    None
}

fn udp_port(p: &[u8], sp: u16, dp: u16) -> Option<App> {
    let either = |port: u16| sp == port || dp == port;
    for (port, name) in [(5353, "mDNS"), (53, "DNS"), (5355, "LLMNR")] {
        if either(port)
            && let Some(a) = dns(p, name, How::Port(port))
        {
            return Some(a);
        }
    }
    if either(67) || either(68) {
        return Some(App::new("DHCP", "BOOTP", How::Port(67)));
    }
    if either(546) || either(547) {
        let t = match p.first()? {
            1 => "Solicit",
            2 => "Advertise",
            3 => "Request",
            4 => "Confirm",
            5 => "Renew",
            6 => "Rebind",
            7 => "Reply",
            8 => "Release",
            9 => "Decline",
            11 => "Information request",
            12 => "Relay forward",
            13 => "Relay reply",
            _ => "message",
        };
        return Some(App::new("DHCPv6", t, How::Port(547)));
    }
    if either(123) && p.len() >= 48 {
        return Some(ntp(p));
    }
    if either(137) {
        return Some(nbns(p));
    }
    if either(161) || either(162) {
        return Some(snmp(p, if either(161) { 161 } else { 162 }));
    }
    if either(47808) && p.first() == Some(&0x81) {
        return Some(bacnet(p));
    }
    if either(502) {
        let lines = modbus::decode_tcp(p, Some(dp == 502));
        if !lines.is_empty() {
            return Some(App::new("Modbus/UDP", lines.join(" | "), How::Port(502)));
        }
    }
    if (either(5683) || either(5684)) && p.len() >= 4 && p[0] >> 6 == 1 {
        return Some(coap(p));
    }
    if (either(1812) || either(1813)) && p.len() >= 20 {
        let t = match p[0] {
            1 => "Access-Request",
            2 => "Access-Accept",
            3 => "Access-Reject",
            4 => "Accounting-Request",
            5 => "Accounting-Response",
            11 => "Access-Challenge",
            _ => "message",
        };
        return Some(App::new(
            "RADIUS",
            format!("{t} id={}", p[1]),
            How::Port(1812),
        ));
    }
    if either(69) && p.len() >= 4 {
        let t = match be16(p, 0)? {
            1 => format!("Read {}", clean(p[2..].split(|c| *c == 0).next()?, 120)),
            2 => format!("Write {}", clean(p[2..].split(|c| *c == 0).next()?, 120)),
            3 => format!("Data block {}", be16(p, 2)?),
            4 => format!("Ack block {}", be16(p, 2)?),
            5 => format!("Error {}", be16(p, 2)?),
            6 => "Option ack".into(),
            _ => "message".into(),
        };
        return Some(App::new("TFTP", t, How::Port(69)));
    }
    if (either(5004) || either(5005)) && p.len() >= 12 && p[0] >> 6 == 2 {
        return Some(App::new(
            "RTP",
            format!("payload type {} seq={}", p[1] & 0x7f, be16(p, 2)?),
            How::Port(5004),
        ));
    }
    if either(514) {
        return Some(line_app("Syslog", p, How::Port(514)));
    }
    if either(44818) && p.len() >= 24 {
        return Some(enip(p, How::Port(44818)));
    }
    for (port, name) in [
        (138, "NetBIOS-DGM"),
        (2222, "EtherNet/IP"),
        (3702, "WS-Discovery"),
        (319, "PTP"),
        (320, "PTP"),
        (500, "IKE"),
        (4500, "IKE"),
        (1194, "OpenVPN"),
        (51820, "WireGuard"),
        (1701, "L2TP"),
        (2055, "NetFlow"),
        (6343, "sFlow"),
        (88, "Kerberos"),
        (389, "CLDAP"),
        (443, "QUIC"),
        (1900, "SSDP"),
    ] {
        if either(port) {
            return Some(App::new(
                name,
                format!("{} bytes", p.len()),
                How::Port(port),
            ));
        }
    }
    None
}

fn ntp(p: &[u8]) -> App {
    let m = match p[0] & 7 {
        1 => "symmetric active",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        _ => "other",
    };
    let v = (p[0] >> 3) & 7;
    let mut l = Layer::new("Network Time Protocol");
    l.f("Version", v)
        .f("Mode", m)
        .f("Leap", p[0] >> 6)
        .f("Stratum", p[1]);
    if p[0] & 7 == 4 {
        l.f(
            "Reference ID",
            if p[1] <= 1 {
                clean(&p[12..16], 4)
            } else {
                Ipv4Addr::new(p[12], p[13], p[14], p[15]).to_string()
            },
        );
    }
    App::new("NTP", format!("NTPv{v} {m}"), How::Port(123)).with(l)
}

fn nbns(p: &[u8]) -> App {
    let mut info = "NetBIOS name service".to_string();
    // Half-ASCII encoded 16-byte name after the header.
    if p.len() >= 46 && p[12] == 32 {
        let name: Vec<u8> = p[13..45]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| (c[0].wrapping_sub(b'A') << 4) | (c[1].wrapping_sub(b'A') & 0xf))
            .collect();
        let resp = p[2] & 0x80 != 0;
        let t = match (p[2] >> 3) & 0xf {
            0 => "Name query",
            5 => "Registration",
            6 => "Release",
            _ => "Name service",
        };
        info = format!(
            "{t}{} {}<{:02x}>",
            if resp { " response" } else { "" },
            clean(&name[..15], 15),
            name[15]
        );
    }
    App::new("NBNS", info, How::Port(137))
}

fn snmp(p: &[u8], port: u16) -> App {
    let kind = if port == 162 {
        "trap"
    } else {
        "request/response"
    };
    let Ok(m) = crate::snmp::dec_message(p) else {
        return App::new("SNMP", kind, How::Port(port));
    };
    let mut l = Layer::new("SNMP");
    l.f("Version", if m.version == 0 { "v1" } else { "v2c" });
    l.f("Community", clean(&m.community, 80));
    for v in m.pdu.varbinds.iter().take(12) {
        l.f(&crate::snmp::oid_name(&v.oid), v.value.as_text());
    }
    let info = m
        .pdu
        .varbinds
        .first()
        .map(|v| format!("{kind} {}", crate::snmp::oid_name(&v.oid)))
        .unwrap_or_else(|| kind.into());
    App::new("SNMP", info, How::Signature).with(l)
}

fn bacnet(p: &[u8]) -> App {
    let f = match p.get(1) {
        Some(0x0a) => "Unicast",
        Some(0x0b) => "Broadcast",
        Some(0x04) => "Forwarded",
        Some(0x05) => "Register foreign device",
        Some(0x00) => "Result",
        _ => "BVLC",
    };
    // NPDU without routing: version, control, then the APDU.
    let at = if p.get(1) == Some(&0x04) { 10 } else { 4 };
    let svc = match (p.get(at + 1), p.get(at + 2), p.get(at + 3)) {
        (Some(c), Some(t), Some(s)) if c & 0xa8 == 0 => match (t >> 4, s) {
            (1, 8) => " Who-Is",
            (1, 0) => " I-Am",
            (1, 2) => " Unconfirmed COV",
            (0, _) => " Confirmed request",
            (2, _) => " Simple ack",
            (3, _) => " Complex ack",
            (5, _) => " Error",
            _ => "",
        },
        _ => "",
    };
    App::new("BACnet", format!("{f}{svc}"), How::Signature)
}

fn coap(p: &[u8]) -> App {
    let t = ["CON", "NON", "ACK", "RST"][((p[0] >> 4) & 3) as usize];
    let (class, detail) = (p[1] >> 5, p[1] & 0x1f);
    let code = match (class, detail) {
        (0, 0) => "empty".to_string(),
        (0, 1) => "GET".into(),
        (0, 2) => "POST".into(),
        (0, 3) => "PUT".into(),
        (0, 4) => "DELETE".into(),
        (c, d) => format!("{c}.{d:02}"),
    };
    App::new("CoAP", format!("{t} {code}"), How::Port(5683))
}

fn dhcp(p: &[u8], how: How) -> App {
    let mut l = Layer::new("DHCP");
    let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let mac = p[28..34]
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let yiaddr = ip(&p[16..20]);
    l.f("Client MAC", mac)
        .f("Transaction", format!("0x{:08x}", be32(p, 4).unwrap_or(0)));
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
            1 if len == 4 => {
                l.f("Subnet mask", ip(v));
            }
            3 | 6 if len >= 4 => {
                let list: Vec<String> = v
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| ip(c).to_string())
                    .collect();
                l.f(
                    if code == 3 { "Router" } else { "DNS servers" },
                    list.join(", "),
                );
            }
            50 if len == 4 => {
                l.f("Requested IP", ip(v));
            }
            51 if len == 4 => {
                l.f("Lease", format!("{} s", be32(v, 0).unwrap_or(0)));
            }
            54 if len == 4 => {
                l.f("Server", ip(v));
            }
            15 => {
                l.f("Domain", clean(v, 120));
            }
            60 => {
                l.f("Vendor class", clean(v, 120));
            }
            12 => host = Some(clean(v, 120)),
            _ => {}
        }
        pos += 2 + len;
    }
    l.f("Message", &msg);
    let mut info = format!("DHCP {msg}");
    if !yiaddr.is_unspecified() {
        l.f("Your IP", yiaddr);
        info += &format!(" {yiaddr}");
    }
    if let Some(h) = host {
        l.f("Hostname", &h);
        info += &format!(" ({h})");
    }
    App::new("DHCP", info, how).with(l)
}

// ---------------------------------------------------------------- DNS

fn trim_dot(s: String) -> String {
    match s.strip_suffix('.') {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => s,
    }
}

/// Record data as shown in lists: names without the final dot, unknown types
/// as a size.
fn dns_rdata(p: &[u8], t: u16, pos: usize, len: usize) -> String {
    let s = crate::dns::rdata(p, t, pos, len);
    if s.starts_with("\\# ") {
        return format!("{len} bytes");
    }
    match t {
        2 | 5 | 12 | 39 => trim_dot(s),
        _ => {
            if s.len() > 400 {
                format!("{}…", s.chars().take(400).collect::<String>())
            } else {
                s
            }
        }
    }
}

/// Lenient DNS parser: keeps what could be read of a cut-off message.
pub fn parse_dns(p: &[u8]) -> Option<DnsMsg> {
    let flags = be16(p, 2)?;
    if p.len() < 12 {
        return None;
    }
    let mut m = DnsMsg {
        id: be16(p, 0)?,
        response: flags & 0x8000 != 0,
        rcode: flags & 0xf,
        truncated: flags & 0x0200 != 0,
        authoritative: flags & 0x0400 != 0,
        authentic: flags & 0x0020 != 0,
        ..Default::default()
    };
    let mut pos = 12;
    for _ in 0..be16(p, 4)?.min(16) {
        let Some((name, next)) = crate::dns::read_name(p, pos) else {
            return Some(m);
        };
        let Some(t) = be16(p, next) else {
            return Some(m);
        };
        m.questions.push((trim_dot(name), t));
        pos = next + 4;
    }
    for (i, section) in ["Answer", "Authority", "Additional"]
        .into_iter()
        .enumerate()
    {
        for _ in 0..be16(p, 6 + i * 2)?.min(64) {
            let Some((name, next)) = crate::dns::read_name(p, pos) else {
                return Some(m);
            };
            let (Some(t), Some(ttl), Some(len)) =
                (be16(p, next), be32(p, next + 4), be16(p, next + 8))
            else {
                return Some(m);
            };
            let (rd, len) = (next + 10, len as usize);
            if rd + len > p.len() {
                return Some(m);
            }
            pos = rd + len;
            if t == 41 {
                m.rcode |= ((ttl >> 24) as u16) << 4;
                continue;
            }
            m.records.push(DnsRecord {
                section,
                name: trim_dot(name),
                rtype: t,
                ttl,
                data: dns_rdata(p, t, rd, len),
            });
        }
    }
    Some(m)
}

fn dns(p: &[u8], proto: &'static str, how: How) -> Option<App> {
    use crate::dns::{rcode_name, type_name};
    let m = parse_dns(p)?;
    let id = m.id;
    let mut l = Layer::new(if proto == "mDNS" {
        "Multicast DNS"
    } else {
        "Domain Name System"
    });
    l.f("Transaction ID", format!("0x{id:04x}"))
        .f("Type", if m.response { "response" } else { "query" })
        .f("Questions", m.questions.len());
    if m.response {
        l.f("Response code", rcode_name(m.rcode));
        let mut fl = Vec::new();
        for (on, t) in [
            (m.authoritative, "authoritative"),
            (m.truncated, "truncated"),
            (m.authentic, "DNSSEC validated"),
        ] {
            if on {
                fl.push(t);
            }
        }
        if !fl.is_empty() {
            l.f("Flags", fl.join(", "));
        }
    }
    let questions: Vec<String> = m
        .questions
        .iter()
        .map(|(n, t)| format!("{} {n}", type_name(*t)))
        .collect();
    for (n, t) in &m.questions {
        l.f("Query", format!("{n} {}", type_name(*t)));
    }
    for r in &m.records {
        l.f(
            r.section,
            format!(
                "{} {} {} (TTL {})",
                r.name,
                type_name(r.rtype),
                r.data,
                r.ttl
            ),
        );
    }
    let answers: Vec<String> = m
        .answers()
        .take(4)
        .map(|r| format!("{} {}", type_name(r.rtype), r.data))
        .collect();
    let info = if m.response {
        let rc = match m.rcode {
            0 => String::new(),
            n => format!(" {}", rcode_name(n)),
        };
        format!(
            "Response 0x{id:04x}{rc} {}{}{}",
            questions.join(", "),
            if answers.is_empty() { "" } else { " → " },
            answers.join(", ")
        )
    } else {
        format!("Query 0x{id:04x} {}", questions.join(", "))
    };
    let mut a = App::new(proto, info, how).with(l);
    a.dns = Some(Box::new(m));
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello() -> Vec<u8> {
        let mut ext = Vec::new();
        let name = b"plc.example";
        ext.extend([
            0,
            0,
            0,
            (name.len() + 5) as u8,
            0,
            (name.len() + 3) as u8,
            0,
            0,
        ]);
        ext.push(name.len() as u8);
        ext.extend(name);
        ext.extend([0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
        ext.extend([0, 43, 0, 5, 4, 0x3a, 0x3a, 3, 4]);
        let mut h = vec![3, 3];
        h.extend([7; 32]);
        h.push(0);
        h.extend([0, 4, 0x13, 0x01, 0xc0, 0x2f, 1, 0]);
        h.extend((ext.len() as u16).to_be_bytes());
        h.extend(ext);
        let mut hs = vec![1, 0];
        hs.extend((h.len() as u16).to_be_bytes());
        hs.extend(h);
        let mut r = vec![0x16, 3, 1];
        r.extend((hs.len() as u16).to_be_bytes());
        r.extend(hs);
        r
    }

    #[test]
    fn tls_hello_on_any_port() {
        let a = tcp(&client_hello(), 50000, 9999).unwrap();
        assert_eq!((a.proto, a.how), ("TLS", How::Signature));
        assert_eq!(a.info, "Client Hello, SNI=plc.example");
        let f = &a.layers[0].fields;
        let get = |k: &str| f.iter().find(|(n, _)| n == k).unwrap().1.clone();
        // GREASE is skipped.
        assert_eq!(get("Version"), "TLS 1.3");
        assert_eq!(get("ALPN"), "h2");
        assert_eq!(client_hello_sni(&client_hello()).unwrap(), "plc.example");
    }

    #[test]
    fn signatures_beat_ports() {
        let a = tcp(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 40000, 502).unwrap();
        assert_eq!((a.proto, a.how), ("HTTP", How::Signature));
        let a = tcp(b"OPTIONS rtsp://x RTSP/1.0\r\n", 40000, 8554).unwrap();
        assert_eq!(a.proto, "RTSP");
        let a = tcp(
            b"\x03\x00\x00\x19\x02\xf0\x80\x32\x01\0\0\0\0\0\x08\0\0\xf0",
            40000,
            102,
        );
        assert_eq!(a.unwrap().info, "Job Setup communication");
        assert_eq!(tcp(b"hi", 40000, 110).unwrap().how, How::Port(110));
        assert!(tcp(b"GETTING started", 40000, 41000).is_none());
        assert!(udp(b"random", 40000, 41000).is_none());
    }

    #[test]
    fn mqtt_and_quic() {
        let a = tcp(b"\x30\x09\x00\x05a/b/cxx", 40000, 1883).unwrap();
        assert_eq!(a.info, "PUBLISH a/b/c");
        let mut q = vec![0xc3, 0, 0, 0, 1, 8];
        q.extend([0xaa; 30]);
        assert_eq!(udp(&q, 40000, 8443).unwrap().info, "Initial, v1");
    }

    #[test]
    fn snmp_get() {
        let p = [
            0x30, 0x26, 2, 1, 1, 4, 6, b's', b'e', b'c', b'r', b'e', b't', 0xa0, 0x19, 2, 1, 1, 2,
            1, 0, 2, 1, 0, 0x30, 0x0e, 0x30, 0x0c, 6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0, 5, 0,
        ];
        let a = udp(&p, 40000, 161).unwrap();
        assert_eq!(a.how, How::Signature);
        assert!(format!("{:?}", a.layers).contains("secret"));
    }
}
