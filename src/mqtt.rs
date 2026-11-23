//! MQTT 3.1.1 / 5.0 client: packet encoder/decoder, a session worker
//! (QoS 0/1/2 both ways, keepalive with RTT) and the headless `--mqtt`.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crate::websocket::{ConnInfo, NetStream, io_err, open};

// ---------------------------------------------------------------- config

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub insecure: bool,
    pub client_id: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub keepalive: u16,
    pub clean: bool,
    pub v5: bool,
    pub timeout: Duration,
}

/// "mqtt://host:1883", "mqtts://host", "ssl://h:8883", "host", "host:port".
/// Returns (host, port, tls).
pub fn parse_broker(s: &str) -> Result<(String, u16, bool), String> {
    let s = s.trim().trim_end_matches('/');
    let (tls, rest) = match s.split_once("://") {
        Some(("mqtt" | "tcp", r)) => (false, r),
        Some(("mqtts" | "ssl" | "tls", r)) => (true, r),
        Some((p, _)) => {
            return Err(format!(
                "unsupported scheme '{p}://' (use mqtt:// or mqtts://)"
            ));
        }
        None => (false, s),
    };
    let (host, port) = if let Some(r) = rest.strip_prefix('[') {
        let end = r.find(']').ok_or("bad IPv6 address")?;
        (
            r[..end].to_string(),
            r[end + 1..].strip_prefix(':').map(|p| p.parse::<u16>()),
        )
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_string(), Some(p.parse::<u16>())),
            _ => (rest.to_string(), None),
        }
    };
    let port = match port {
        Some(p) => p.map_err(|_| "bad port")?,
        None => {
            if tls {
                8883
            } else {
                1883
            }
        }
    };
    if host.is_empty() {
        return Err("missing broker host".into());
    }
    // Port 8883 implies TLS when no scheme was given.
    let tls = tls || (!s.contains("://") && port == 8883);
    Ok((host, port, tls))
}

pub fn random_client_id() -> String {
    let r = crate::websocket::random_bytes(4);
    format!(
        "network-analyser-{}",
        r.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

// ---------------------------------------------------------------- encoding

pub const CONNECT: u8 = 1;
pub const CONNACK: u8 = 2;
pub const PUBLISH: u8 = 3;
pub const PUBACK: u8 = 4;
pub const PUBREC: u8 = 5;
pub const PUBREL: u8 = 6;
pub const PUBCOMP: u8 = 7;
pub const SUBSCRIBE: u8 = 8;
pub const SUBACK: u8 = 9;
pub const UNSUBSCRIBE: u8 = 10;
pub const UNSUBACK: u8 = 11;
pub const PINGREQ: u8 = 12;
pub const PINGRESP: u8 = 13;
pub const DISCONNECT: u8 = 14;

pub fn packet_name(t: u8) -> &'static str {
    match t {
        CONNECT => "CONNECT",
        CONNACK => "CONNACK",
        PUBLISH => "PUBLISH",
        PUBACK => "PUBACK",
        PUBREC => "PUBREC",
        PUBREL => "PUBREL",
        PUBCOMP => "PUBCOMP",
        SUBSCRIBE => "SUBSCRIBE",
        SUBACK => "SUBACK",
        UNSUBSCRIBE => "UNSUBSCRIBE",
        UNSUBACK => "UNSUBACK",
        PINGREQ => "PINGREQ",
        PINGRESP => "PINGRESP",
        DISCONNECT => "DISCONNECT",
        15 => "AUTH",
        _ => "RESERVED",
    }
}

pub fn encode_varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

/// (value, bytes used); `Ok(None)` = incomplete.
pub fn decode_varint(b: &[u8]) -> Result<Option<(usize, usize)>, String> {
    let mut v = 0usize;
    for i in 0..4 {
        let Some(&x) = b.get(i) else {
            return Ok(None);
        };
        v |= ((x & 0x7f) as usize) << (7 * i);
        if x & 0x80 == 0 {
            return Ok(Some((v, i + 1)));
        }
    }
    Err("malformed remaining length".into())
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s);
}

fn packet(first: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = vec![first];
    encode_varint(body.len(), &mut out);
    out.extend(body);
    out
}

pub fn encode_connect(c: &Config) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, b"MQTT");
    b.push(if c.v5 { 5 } else { 4 });
    let mut flags = 0u8;
    if c.clean {
        flags |= 0x02;
    }
    if c.username.is_some() {
        flags |= 0x80;
    }
    if c.password.is_some() {
        flags |= 0x40;
    }
    b.push(flags);
    b.extend_from_slice(&c.keepalive.to_be_bytes());
    if c.v5 {
        // Properties: request problem information (default anyway) — keep empty.
        b.push(0);
    }
    put_str(&mut b, c.client_id.as_bytes());
    if let Some(u) = &c.username {
        put_str(&mut b, u.as_bytes());
    }
    if let Some(p) = &c.password {
        put_str(&mut b, p.as_bytes());
    }
    packet(CONNECT << 4, b)
}

pub fn encode_subscribe(id: u16, filters: &[(String, u8)], v5: bool) -> Vec<u8> {
    let mut b = id.to_be_bytes().to_vec();
    if v5 {
        b.push(0);
    }
    for (f, q) in filters {
        put_str(&mut b, f.as_bytes());
        b.push(q & 3);
    }
    packet(SUBSCRIBE << 4 | 0x02, b)
}

pub fn encode_unsubscribe(id: u16, filters: &[String], v5: bool) -> Vec<u8> {
    let mut b = id.to_be_bytes().to_vec();
    if v5 {
        b.push(0);
    }
    for f in filters {
        put_str(&mut b, f.as_bytes());
    }
    packet(UNSUBSCRIBE << 4 | 0x02, b)
}

pub fn encode_publish(
    topic: &str,
    payload: &[u8],
    qos: u8,
    retain: bool,
    dup: bool,
    id: u16,
    v5: bool,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(topic.len() + payload.len() + 8);
    put_str(&mut b, topic.as_bytes());
    if qos > 0 {
        b.extend_from_slice(&id.to_be_bytes());
    }
    if v5 {
        b.push(0);
    }
    b.extend_from_slice(payload);
    let first = PUBLISH << 4 | if dup { 8 } else { 0 } | (qos & 3) << 1 | retain as u8;
    packet(first, b)
}

/// PUBACK / PUBREC / PUBREL / PUBCOMP (success; v5 may omit the reason code).
pub fn encode_ack(kind: u8, id: u16) -> Vec<u8> {
    let first = kind << 4 | if kind == PUBREL { 0x02 } else { 0 };
    packet(first, id.to_be_bytes().to_vec())
}

pub fn encode_simple(kind: u8) -> Vec<u8> {
    vec![kind << 4, 0]
}

// ---------------------------------------------------------------- decoding

#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    Connack {
        session_present: bool,
        code: u8,
        /// v5 properties as readable (name, value) pairs.
        props: Vec<(String, String)>,
        /// The broker answered in 3.1.1 format.
        v3_format: bool,
    },
    Publish {
        dup: bool,
        qos: u8,
        retain: bool,
        topic: String,
        id: Option<u16>,
        payload: Vec<u8>,
        props: Vec<(String, String)>,
    },
    /// PUBACK/PUBREC/PUBREL/PUBCOMP: (kind, id, reason).
    Ack(u8, u16, u8),
    Suback {
        id: u16,
        codes: Vec<u8>,
    },
    Unsuback {
        id: u16,
    },
    Pingresp,
    Disconnect {
        code: Option<u8>,
        props: Vec<(String, String)>,
    },
    Other(u8),
}

fn prop_name(id: u8) -> &'static str {
    match id {
        0x01 => "Payload format",
        0x02 => "Message expiry",
        0x03 => "Content type",
        0x08 => "Response topic",
        0x09 => "Correlation data",
        0x0B => "Subscription id",
        0x11 => "Session expiry",
        0x12 => "Assigned client id",
        0x13 => "Server keepalive",
        0x15 => "Auth method",
        0x16 => "Auth data",
        0x17 => "Request problem info",
        0x18 => "Will delay",
        0x19 => "Request response info",
        0x1A => "Response info",
        0x1C => "Server reference",
        0x1F => "Reason string",
        0x21 => "Receive maximum",
        0x22 => "Topic alias maximum",
        0x23 => "Topic alias",
        0x24 => "Maximum QoS",
        0x25 => "Retain available",
        0x26 => "User property",
        0x27 => "Maximum packet size",
        0x28 => "Wildcard subscriptions",
        0x29 => "Subscription ids",
        0x2A => "Shared subscriptions",
        _ => "Unknown property",
    }
}

/// Parse a v5 property block starting at `b[0]` (the length varint).
/// Returns (props, bytes used).
pub fn parse_props(b: &[u8]) -> Result<(Vec<(String, String)>, usize), String> {
    let (len, n) = decode_varint(b)?.ok_or("truncated properties")?;
    let end = n + len;
    let p = b.get(n..end).ok_or("truncated properties")?;
    let mut out = Vec::new();
    let mut i = 0;
    let str_at = |i: usize| -> Result<(String, usize), String> {
        let l = u16::from_be_bytes([
            *p.get(i).ok_or("bad property")?,
            *p.get(i + 1).ok_or("bad property")?,
        ]) as usize;
        let s = p.get(i + 2..i + 2 + l).ok_or("bad property")?;
        Ok((String::from_utf8_lossy(s).into_owned(), i + 2 + l))
    };
    while i < p.len() {
        let id = p[i];
        i += 1;
        let val = match id {
            0x01 | 0x17 | 0x19 | 0x24 | 0x25 | 0x28 | 0x29 | 0x2A => {
                let v = *p.get(i).ok_or("bad property")?;
                i += 1;
                v.to_string()
            }
            0x13 | 0x21 | 0x22 | 0x23 => {
                let v = u16::from_be_bytes([
                    *p.get(i).ok_or("bad property")?,
                    *p.get(i + 1).ok_or("bad property")?,
                ]);
                i += 2;
                v.to_string()
            }
            0x02 | 0x11 | 0x18 | 0x27 => {
                let v =
                    u32::from_be_bytes(p.get(i..i + 4).ok_or("bad property")?.try_into().unwrap());
                i += 4;
                v.to_string()
            }
            0x0B => {
                let (v, k) = decode_varint(&p[i..])?.ok_or("bad property")?;
                i += k;
                v.to_string()
            }
            0x03 | 0x08 | 0x12 | 0x15 | 0x1A | 0x1C | 0x1F => {
                let (s, ni) = str_at(i)?;
                i = ni;
                s
            }
            0x09 | 0x16 => {
                let (s, ni) = str_at(i)?;
                i = ni;
                format!("{} bytes", s.len())
            }
            0x26 => {
                let (k, ni) = str_at(i)?;
                let (v, ni) = str_at(ni)?;
                i = ni;
                format!("{k}={v}")
            }
            _ => return Err(format!("unknown property id {id:#04x}")),
        };
        out.push((prop_name(id).to_string(), val));
    }
    Ok((out, end))
}

/// Decode one packet from the front of `buf`; `Ok(None)` = incomplete.
pub fn decode(buf: &[u8], v5: bool) -> Result<Option<(Packet, usize)>, String> {
    if buf.is_empty() {
        return Ok(None);
    }
    let first = buf[0];
    let Some((len, n)) = decode_varint(&buf[1..])? else {
        return Ok(None);
    };
    let start = 1 + n;
    let end = start + len;
    if buf.len() < end {
        return Ok(None);
    }
    let b = &buf[start..end];
    let kind = first >> 4;
    let short = || format!("{} too short", packet_name(kind));
    let u16_at = |i: usize| -> Result<u16, String> {
        Ok(u16::from_be_bytes([
            *b.get(i).ok_or_else(short)?,
            *b.get(i + 1).ok_or_else(short)?,
        ]))
    };
    let pkt = match kind {
        CONNACK => {
            let session_present = b.first().ok_or_else(short)? & 1 != 0;
            let code = *b.get(1).ok_or_else(short)?;
            let v3_format = b.len() == 2;
            let props = if v5 && b.len() > 2 {
                parse_props(&b[2..])?.0
            } else {
                Vec::new()
            };
            Packet::Connack {
                session_present,
                code,
                props,
                v3_format,
            }
        }
        PUBLISH => {
            let qos = (first >> 1) & 3;
            if qos == 3 {
                return Err("PUBLISH with QoS 3 (malformed)".into());
            }
            let tl = u16_at(0)? as usize;
            let topic = b.get(2..2 + tl).ok_or_else(short)?;
            let mut i = 2 + tl;
            let id = if qos > 0 {
                let id = u16_at(i)?;
                i += 2;
                Some(id)
            } else {
                None
            };
            let props = if v5 {
                let (p, used) = parse_props(&b[i..])?;
                i += used;
                p
            } else {
                Vec::new()
            };
            Packet::Publish {
                dup: first & 8 != 0,
                qos,
                retain: first & 1 != 0,
                topic: String::from_utf8_lossy(topic).into_owned(),
                id,
                payload: b[i..].to_vec(),
                props,
            }
        }
        PUBACK | PUBREC | PUBREL | PUBCOMP => {
            Packet::Ack(kind, u16_at(0)?, b.get(2).copied().unwrap_or(0))
        }
        SUBACK => {
            let id = u16_at(0)?;
            let mut i = 2;
            if v5 {
                i += parse_props(&b[2..])?.1;
            }
            Packet::Suback {
                id,
                codes: b.get(i..).unwrap_or_default().to_vec(),
            }
        }
        UNSUBACK => Packet::Unsuback { id: u16_at(0)? },
        PINGRESP => Packet::Pingresp,
        DISCONNECT => Packet::Disconnect {
            code: b.first().copied(),
            props: if b.len() > 1 {
                parse_props(&b[1..]).map(|p| p.0).unwrap_or_default()
            } else {
                Vec::new()
            },
        },
        k => Packet::Other(k),
    };
    Ok(Some((pkt, end)))
}

/// CONNACK / DISCONNECT / SUBACK reason explained.
pub fn reason_text(code: u8, v3: bool) -> &'static str {
    if v3 {
        return match code {
            0 => "connection accepted",
            1 => "refused: unacceptable protocol version (broker does not speak this MQTT version)",
            2 => "refused: client identifier rejected",
            3 => "refused: server unavailable",
            4 => "refused: bad user name or password",
            5 => "refused: not authorised",
            _ => "refused: unknown reason",
        };
    }
    match code {
        0x00 => "success",
        0x01 => "granted QoS 1",
        0x02 => "granted QoS 2",
        0x04 => "disconnect with will message",
        0x10 => "no matching subscribers",
        0x11 => "no subscription existed",
        0x80 => "unspecified error",
        0x81 => "malformed packet",
        0x82 => "protocol error",
        0x83 => "implementation-specific error",
        0x84 => "unsupported protocol version",
        0x85 => "client identifier not valid",
        0x86 => "bad user name or password",
        0x87 => "not authorised",
        0x88 => "server unavailable",
        0x89 => "server busy",
        0x8A => "banned",
        0x8B => "server shutting down",
        0x8C => "bad authentication method",
        0x8D => "keep alive timeout",
        0x8E => "session taken over (another client connected with the same id)",
        0x8F => "topic filter invalid",
        0x90 => "topic name invalid",
        0x91 => "packet identifier in use",
        0x93 => "receive maximum exceeded",
        0x94 => "topic alias invalid",
        0x95 => "packet too large",
        0x96 => "message rate too high",
        0x97 => "quota exceeded",
        0x98 => "administrative action",
        0x99 => "payload format invalid",
        0x9A => "retain not supported",
        0x9B => "QoS not supported",
        0x9C => "use another server",
        0x9D => "server moved",
        0x9E => "shared subscriptions not supported",
        0x9F => "connection rate exceeded",
        0xA0 => "maximum connect time",
        0xA1 => "subscription identifiers not supported",
        0xA2 => "wildcard subscriptions not supported",
        _ => "unknown reason code",
    }
}

/// MQTT topic-filter match (`+` one level, `#` the rest; `$` topics only
/// match filters that start with `$`).
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    if topic.starts_with('$') && !filter.starts_with('$') {
        return false;
    }
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

pub fn validate_filter(f: &str) -> Result<(), String> {
    if f.is_empty() {
        return Err("empty topic filter".into());
    }
    let levels: Vec<&str> = f.split('/').collect();
    for (i, l) in levels.iter().enumerate() {
        if l.contains('#') && (*l != "#" || i != levels.len() - 1) {
            return Err("'#' must be the last level on its own".into());
        }
        if l.contains('+') && *l != "+" {
            return Err("'+' must occupy a whole level".into());
        }
    }
    Ok(())
}

pub fn validate_topic(t: &str) -> Result<(), String> {
    if t.is_empty() {
        return Err("empty topic".into());
    }
    if t.contains(['#', '+']) {
        return Err("wildcards are not allowed when publishing".into());
    }
    Ok(())
}

// ---------------------------------------------------------------- session

pub enum Cmd {
    Subscribe(String, u8),
    Unsubscribe(String),
    Publish {
        topic: String,
        payload: Vec<u8>,
        qos: u8,
        retain: bool,
    },
    Disconnect,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Lvl {
    Info,
    Good,
    Warn,
    Bad,
}

#[derive(Clone, Debug)]
pub struct Msg {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
    pub dup: bool,
    pub props: Vec<(String, String)>,
}

pub enum Event {
    Log(Lvl, String),
    Connected {
        conn: ConnInfo,
        session_present: bool,
        props: Vec<(String, String)>,
        ms: f64,
    },
    Message(Msg),
    /// Packet counters: (outgoing, bytes on the wire).
    Wire(bool, usize),
    Rtt(f64),
    Closed(String),
    Error(String),
}

pub struct Session {
    tx: Sender<Cmd>,
}

impl Session {
    pub fn send(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Disconnect);
    }
}

pub fn connect(cfg: Config) -> (Session, Receiver<Event>) {
    let (tx, crx) = channel();
    let (etx, erx) = channel();
    std::thread::spawn(move || {
        if let Err(e) = run(cfg, crx, &etx) {
            let _ = etx.send(Event::Error(e));
        }
    });
    (Session { tx }, erx)
}

struct Io<'a> {
    s: NetStream,
    tx: &'a Sender<Event>,
    last_sent: Instant,
}

impl Io<'_> {
    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.s
            .write_all(bytes)
            .and_then(|_| self.s.flush())
            .map_err(|e| format!("send failed: {}", io_err(&e)))?;
        self.last_sent = Instant::now();
        let _ = self.tx.send(Event::Wire(true, bytes.len()));
        Ok(())
    }
}

fn run(cfg: Config, rx: Receiver<Cmd>, tx: &Sender<Event>) -> Result<(), String> {
    let log = |l: Lvl, s: String| {
        let _ = tx.send(Event::Log(l, s));
    };
    log(
        Lvl::Info,
        format!(
            "Connecting to {}:{}{}…",
            cfg.host,
            cfg.port,
            if cfg.tls { " (TLS)" } else { "" }
        ),
    );
    let (s, conn) = open(&cfg.host, cfg.port, cfg.tls, cfg.insecure, cfg.timeout)?;
    if let Some(t) = &conn.tls {
        log(Lvl::Info, format!("TLS: {t}"));
    }
    if let Some(e) = &conn.cert_error {
        log(Lvl::Warn, format!("Certificate not trusted: {e}"));
    }
    if !cfg.tls && cfg.password.is_some() {
        log(
            Lvl::Warn,
            "Password sent without TLS — readable by anyone on the path".into(),
        );
    }
    let mut io = Io {
        s,
        tx,
        last_sent: Instant::now(),
    };
    let t0 = Instant::now();
    io.send(&encode_connect(&cfg))?;
    log(
        Lvl::Info,
        format!(
            "→ CONNECT MQTT {} client id \"{}\", keepalive {} s, clean {}",
            if cfg.v5 { "5.0" } else { "3.1.1" },
            cfg.client_id,
            cfg.keepalive,
            cfg.clean
        ),
    );
    io.s.set_read_timeout(Duration::from_millis(50));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut connected = false;
    let mut next_id: u16 = 0;
    let mut id = || {
        next_id = next_id.wrapping_add(1).max(1);
        next_id
    };
    // Outgoing QoS>0 publishes: id -> (topic, qos, sent)
    let mut outgoing: HashMap<u16, (String, u8, Instant)> = HashMap::new();
    // Pending subscribes: id -> filters
    let mut subs: HashMap<u16, Vec<String>> = HashMap::new();
    // Incoming QoS 2 ids awaiting PUBREL.
    let mut inbound_q2: HashSet<u16> = HashSet::new();
    let mut ping_at: Option<Instant> = None;
    let mut queued: Vec<Cmd> = Vec::new();
    let mut v5 = cfg.v5;

    loop {
        // Commands (queued until CONNACK).
        let mut cmds: Vec<Cmd> = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(c) => cmds.push(c),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    cmds.push(Cmd::Disconnect);
                    break;
                }
            }
        }
        if connected {
            cmds = queued.drain(..).chain(cmds).collect();
        } else {
            // Disconnect still applies immediately.
            if cmds.iter().any(|c| matches!(c, Cmd::Disconnect)) {
                let _ = tx.send(Event::Closed("Cancelled".into()));
                return Ok(());
            }
            queued.append(&mut cmds);
        }
        for c in cmds {
            match c {
                Cmd::Subscribe(f, q) => {
                    let i = id();
                    io.send(&encode_subscribe(i, &[(f.clone(), q)], v5))?;
                    log(Lvl::Info, format!("→ SUBSCRIBE {f} (QoS {q})"));
                    subs.insert(i, vec![f]);
                }
                Cmd::Unsubscribe(f) => {
                    let i = id();
                    io.send(&encode_unsubscribe(i, std::slice::from_ref(&f), v5))?;
                    log(Lvl::Info, format!("→ UNSUBSCRIBE {f}"));
                }
                Cmd::Publish {
                    topic,
                    payload,
                    qos,
                    retain,
                } => {
                    let i = if qos > 0 { id() } else { 0 };
                    io.send(&encode_publish(&topic, &payload, qos, retain, false, i, v5))?;
                    log(
                        Lvl::Info,
                        format!(
                            "→ PUBLISH {topic} ({} bytes, QoS {qos}{})",
                            payload.len(),
                            if retain { ", retained" } else { "" }
                        ),
                    );
                    if qos > 0 {
                        outgoing.insert(i, (topic, qos, Instant::now()));
                    }
                }
                Cmd::Disconnect => {
                    let _ = io.send(&encode_simple(DISCONNECT));
                    let _ = tx.send(Event::Closed("Disconnected".into()));
                    return Ok(());
                }
            }
        }
        // Timers.
        if !connected && t0.elapsed() > cfg.timeout {
            return Err("no CONNACK from the broker (is this an MQTT port?)".into());
        }
        if connected && cfg.keepalive > 0 {
            let ka = Duration::from_secs(cfg.keepalive as u64);
            match ping_at {
                Some(at) if at.elapsed() > ka + ka / 2 => {
                    return Err("no PINGRESP within 1.5× keepalive — connection lost".into());
                }
                None if io.last_sent.elapsed() >= ka * 3 / 4 => {
                    io.send(&encode_simple(PINGREQ))?;
                    ping_at = Some(Instant::now());
                }
                _ => {}
            }
        }
        // Packets.
        while let Some((p, used)) = decode(&buf, v5)? {
            let _ = tx.send(Event::Wire(false, used));
            buf.drain(..used);
            match p {
                Packet::Connack {
                    session_present,
                    code,
                    props,
                    v3_format,
                } => {
                    if v5 && v3_format {
                        v5 = false;
                    }
                    let text = reason_text(code, !v5);
                    if code != 0 {
                        let hint = if cfg.v5 && (code == 1 || code == 0x84) {
                            " — try MQTT 3.1.1"
                        } else {
                            ""
                        };
                        return Err(format!("← CONNACK {code:#04x}: {text}{hint}"));
                    }
                    connected = true;
                    log(
                        Lvl::Good,
                        format!(
                            "← CONNACK: {text}{}",
                            if session_present {
                                " (resumed an existing session)"
                            } else {
                                ""
                            }
                        ),
                    );
                    let _ = tx.send(Event::Connected {
                        conn: conn.clone(),
                        session_present,
                        props,
                        ms: t0.elapsed().as_secs_f64() * 1000.0,
                    });
                }
                Packet::Publish {
                    dup,
                    qos,
                    retain,
                    topic,
                    id,
                    payload,
                    props,
                } => {
                    let mut deliver = true;
                    match (qos, id) {
                        (1, Some(i)) => io.send(&encode_ack(PUBACK, i))?,
                        (2, Some(i)) => {
                            deliver = inbound_q2.insert(i);
                            io.send(&encode_ack(PUBREC, i))?;
                        }
                        _ => {}
                    }
                    if deliver {
                        let _ = tx.send(Event::Message(Msg {
                            topic,
                            payload,
                            qos,
                            retain,
                            dup,
                            props,
                        }));
                    }
                }
                Packet::Ack(kind, i, reason) => match kind {
                    PUBREL => {
                        inbound_q2.remove(&i);
                        io.send(&encode_ack(PUBCOMP, i))?;
                    }
                    PUBREC => {
                        if reason >= 0x80 {
                            outgoing.remove(&i);
                            log(
                                Lvl::Bad,
                                format!("← PUBREC {i}: {}", reason_text(reason, false)),
                            );
                        } else {
                            io.send(&encode_ack(PUBREL, i))?;
                        }
                    }
                    PUBACK | PUBCOMP => {
                        if let Some((topic, qos, at)) = outgoing.remove(&i) {
                            let ok = reason < 0x80;
                            log(
                                if ok { Lvl::Good } else { Lvl::Bad },
                                format!(
                                    "← {} for {topic} (QoS {qos}) after {:.1} ms{}",
                                    packet_name(kind),
                                    at.elapsed().as_secs_f64() * 1000.0,
                                    if reason != 0 {
                                        format!(": {}", reason_text(reason, false))
                                    } else {
                                        String::new()
                                    }
                                ),
                            );
                        }
                    }
                    _ => {}
                },
                Packet::Suback { id, codes } => {
                    let filters = subs.remove(&id).unwrap_or_default();
                    for (k, c) in codes.iter().enumerate() {
                        let f = filters.get(k).cloned().unwrap_or_default();
                        if *c >= 0x80 {
                            log(
                                Lvl::Bad,
                                format!(
                                    "← SUBACK {f}: refused ({})",
                                    reason_text(*c, !v5 && *c == 0x80)
                                ),
                            );
                        } else {
                            log(Lvl::Good, format!("← SUBACK {f}: granted QoS {c}"));
                        }
                    }
                }
                Packet::Unsuback { .. } => log(Lvl::Info, "← UNSUBACK".into()),
                Packet::Pingresp => {
                    if let Some(at) = ping_at.take() {
                        let _ = tx.send(Event::Rtt(at.elapsed().as_secs_f64() * 1000.0));
                    }
                }
                Packet::Disconnect { code, props } => {
                    let why = code
                        .map(|c| reason_text(c, false).to_string())
                        .unwrap_or_else(|| "no reason given".into());
                    let extra = props
                        .iter()
                        .find(|(k, _)| k == "Reason string")
                        .map(|(_, v)| format!(" — {v}"))
                        .unwrap_or_default();
                    let _ = tx.send(Event::Closed(format!(
                        "Broker sent DISCONNECT: {why}{extra}"
                    )));
                    return Ok(());
                }
                Packet::Other(k) => log(Lvl::Warn, format!("← unexpected {}", packet_name(k))),
            }
        }
        match io.s.read(&mut chunk) {
            Ok(0) => {
                return Err(if connected {
                    "broker closed the connection (another client with the same id, or an ACL / protocol violation)".into()
                } else {
                    "broker closed the connection before CONNACK".into()
                });
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(io_err(&e)),
        }
    }
}

// ---------------------------------------------------------------- CLI

/// `--mqtt BROKER [FILTER] [SECONDS]`
pub fn cli(args: &[String]) {
    let Some(broker) = args.first() else {
        eprintln!(
            "usage: --mqtt BROKER [TOPIC-FILTER] [SECONDS]   e.g. --mqtt test.mosquitto.org '$SYS/#' 5"
        );
        std::process::exit(2)
    };
    let (host, port, tls) = parse_broker(broker).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let filter = args.get(1).cloned().unwrap_or_else(|| "#".into());
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    if let Err(e) = validate_filter(&filter) {
        eprintln!("{e}");
        std::process::exit(2)
    }
    let (sess, rx) = connect(Config {
        host,
        port,
        tls,
        insecure: false,
        client_id: random_client_id(),
        username: None,
        password: None,
        keepalive: 30,
        clean: true,
        v5: false,
        timeout: Duration::from_secs(10),
    });
    sess.send(Cmd::Subscribe(filter, 0));
    let mut end: Option<Instant> = None;
    let mut topics: HashMap<String, usize> = HashMap::new();
    let mut count = 0usize;
    loop {
        if end.is_some_and(|e| Instant::now() > e) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Event::Log(_, s)) => println!("{s}"),
            Ok(Event::Connected { ms, .. }) => {
                println!("connected in {ms:.0} ms; listening for {secs} s");
                end = Some(Instant::now() + Duration::from_secs(secs));
            }
            Ok(Event::Message(m)) => {
                count += 1;
                *topics.entry(m.topic.clone()).or_default() += 1;
                if count <= 200 {
                    println!(
                        "{}{} = {}",
                        m.topic,
                        if m.retain { " [retained]" } else { "" },
                        crate::websocket::preview(&m.payload, false, 120)
                    );
                }
            }
            Ok(Event::Closed(s)) => {
                println!("{s}");
                break;
            }
            Ok(Event::Error(e)) => {
                eprintln!("error: {e}");
                std::process::exit(1)
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
    }
    println!(
        "{count} messages on {} topics{}",
        topics.len(),
        if count > 200 {
            " (first 200 shown)"
        } else {
            ""
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn cfg(port: u16, v5: bool) -> Config {
        Config {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            insecure: false,
            client_id: "abc".into(),
            username: Some("u".into()),
            password: Some("p".into()),
            keepalive: 60,
            clean: true,
            v5,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn varints() {
        for (n, b) in [
            (0usize, vec![0u8]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (16_383, vec![0xff, 0x7f]),
            (16_384, vec![0x80, 0x80, 0x01]),
            (268_435_455, vec![0xff, 0xff, 0xff, 0x7f]),
        ] {
            let mut out = Vec::new();
            encode_varint(n, &mut out);
            assert_eq!(out, b);
            assert_eq!(decode_varint(&b).unwrap(), Some((n, b.len())));
        }
        assert!(decode_varint(&[0xff, 0xff, 0xff, 0xff, 1]).is_err());
        assert_eq!(decode_varint(&[0x80]).unwrap(), None);
    }

    #[test]
    fn connect_bytes() {
        let c = cfg(1883, false);
        assert_eq!(
            encode_connect(&c),
            [
                0x10, 21, 0, 4, b'M', b'Q', b'T', b'T', 4, 0xc2, 0, 60, 0, 3, b'a', b'b', b'c', 0,
                1, b'u', 0, 1, b'p'
            ]
        );
        let mut c5 = cfg(1883, true);
        c5.username = None;
        c5.password = None;
        assert_eq!(
            encode_connect(&c5),
            [
                0x10, 16, 0, 4, b'M', b'Q', b'T', b'T', 5, 0x02, 0, 60, 0, 0, 3, b'a', b'b', b'c'
            ]
        );
    }

    #[test]
    fn publish_subscribe_bytes() {
        assert_eq!(
            encode_subscribe(10, &[("a/#".into(), 1)], false),
            [0x82, 8, 0, 10, 0, 3, b'a', b'/', b'#', 1]
        );
        let p = encode_publish("t", b"hi", 1, true, false, 7, false);
        assert_eq!(p, [0x33, 7, 0, 1, b't', 0, 7, b'h', b'i']);
        let (d, used) = decode(&p, false).unwrap().unwrap();
        assert_eq!(used, p.len());
        assert_eq!(
            d,
            Packet::Publish {
                dup: false,
                qos: 1,
                retain: true,
                topic: "t".into(),
                id: Some(7),
                payload: b"hi".to_vec(),
                props: vec![]
            }
        );
        assert_eq!(encode_ack(PUBREL, 0x0102), [0x62, 2, 1, 2]);
        assert_eq!(
            decode(&[0x20, 2, 1, 0], false).unwrap().unwrap().0,
            Packet::Connack {
                session_present: true,
                code: 0,
                props: vec![],
                v3_format: true
            }
        );
        // v5 CONNACK with Assigned client id "x" and Maximum QoS 1.
        let c5 = [0x20, 9, 0, 0, 6, 0x12, 0, 1, b'x', 0x24, 1];
        let Packet::Connack { props, .. } = decode(&c5, true).unwrap().unwrap().0 else {
            panic!()
        };
        assert_eq!(
            props,
            vec![
                ("Assigned client id".into(), "x".into()),
                ("Maximum QoS".into(), "1".into())
            ]
        );
        assert_eq!(
            decode(&[0x90, 3, 0, 10, 0x80], false).unwrap().unwrap().0,
            Packet::Suback {
                id: 10,
                codes: vec![0x80]
            }
        );
        assert!(decode(&[0x30, 5, 0], false).unwrap().is_none());
    }

    #[test]
    fn broker_strings_and_topics() {
        assert_eq!(
            parse_broker("test.mosquitto.org").unwrap(),
            ("test.mosquitto.org".into(), 1883, false)
        );
        assert_eq!(parse_broker("mqtts://h").unwrap(), ("h".into(), 8883, true));
        assert_eq!(parse_broker("h:8883").unwrap(), ("h".into(), 8883, true));
        assert_eq!(
            parse_broker("[::1]:1884").unwrap(),
            ("::1".into(), 1884, false)
        );
        assert!(parse_broker("http://x").is_err());
        assert!(topic_matches("a/+/c", "a/b/c"));
        assert!(topic_matches("a/#", "a"));
        assert!(topic_matches("#", "a/b"));
        assert!(!topic_matches("#", "$SYS/broker/uptime"));
        assert!(topic_matches("$SYS/#", "$SYS/broker/uptime"));
        assert!(!topic_matches("a/+", "a/b/c"));
        assert!(validate_filter("a/#/b").is_err());
        assert!(validate_filter("a+/b").is_err());
        assert!(validate_filter("+/x/#").is_ok());
        assert!(validate_topic("a/#").is_err());
    }

    /// Minimal broker: CONNACK, SUBACK, echoes publishes back at the
    /// requested QoS and runs the QoS 1/2 handshakes.
    fn broker() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut b = [0u8; 4096];
            loop {
                while let Ok((p, used)) = decode_client(&buf) {
                    let first = buf[0];
                    let body = buf[used - p..used].to_vec();
                    buf.drain(..used);
                    match first >> 4 {
                        CONNECT => c.write_all(&[0x20, 2, 0, 0]).unwrap(),
                        SUBSCRIBE => {
                            let q = *body.last().unwrap();
                            c.write_all(&[0x90, 3, body[0], body[1], q]).unwrap()
                        }
                        PUBLISH => {
                            let qos = (first >> 1) & 3;
                            let tl = u16::from_be_bytes([body[0], body[1]]) as usize;
                            let topic = String::from_utf8_lossy(&body[2..2 + tl]).into_owned();
                            let pid = if qos > 0 {
                                [body[2 + tl], body[3 + tl]]
                            } else {
                                [0, 0]
                            };
                            let payload = &body[2 + tl + if qos > 0 { 2 } else { 0 }..];
                            match qos {
                                1 => c.write_all(&[0x40, 2, pid[0], pid[1]]).unwrap(),
                                2 => c.write_all(&[0x50, 2, pid[0], pid[1]]).unwrap(),
                                _ => {}
                            }
                            c.write_all(&encode_publish(
                                &topic, payload, qos, false, false, 99, false,
                            ))
                            .unwrap();
                        }
                        PUBREL => c.write_all(&[0x70, 2, body[0], body[1]]).unwrap(),
                        PUBREC => c.write_all(&[0x62, 2, body[0], body[1]]).unwrap(),
                        PINGREQ => c.write_all(&[0xd0, 0]).unwrap(),
                        DISCONNECT => return,
                        _ => {}
                    }
                }
                let n = match c.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&b[..n]);
            }
        });
        port
    }

    /// (body length, total length) of a client packet.
    fn decode_client(buf: &[u8]) -> Result<(usize, usize), ()> {
        if buf.is_empty() {
            return Err(());
        }
        let (len, n) = decode_varint(&buf[1..]).map_err(|_| ())?.ok_or(())?;
        if buf.len() < 1 + n + len {
            return Err(());
        }
        Ok((len, 1 + n + len))
    }

    #[test]
    fn session_against_local_broker() {
        let port = broker();
        let (sess, rx) = connect(cfg(port, false));
        sess.send(Cmd::Subscribe("#".into(), 2));
        for q in 0..3u8 {
            sess.send(Cmd::Publish {
                topic: format!("t/{q}"),
                payload: vec![q],
                qos: q,
                retain: false,
            });
        }
        let mut got = Vec::new();
        let mut acks = 0;
        let mut connected = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while (got.len() < 3 || acks < 2) && Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Connected { .. } => connected = true,
                Event::Message(m) => got.push((m.topic, m.qos)),
                Event::Log(Lvl::Good, s) if s.contains("PUBACK") || s.contains("PUBCOMP") => {
                    acks += 1
                }
                Event::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
        assert!(connected);
        assert_eq!(
            got,
            vec![("t/0".into(), 0), ("t/1".into(), 1), ("t/2".into(), 2)]
        );
        assert_eq!(acks, 2);
        drop(sess);
    }

    /// Live: `cargo test mqtt_live -- --ignored` (uses test.mosquitto.org).
    #[test]
    #[ignore]
    fn mqtt_live_publish_roundtrip() {
        for v5 in [false, true] {
            let topic = format!("na-test/{}", random_client_id());
            let mut c = cfg(1883, v5);
            c.host = "test.mosquitto.org".into();
            c.username = None;
            c.password = None;
            c.client_id = random_client_id();
            let (sess, rx) = connect(c);
            sess.send(Cmd::Subscribe(format!("{topic}/#"), 2));
            for q in 0..3u8 {
                sess.send(Cmd::Publish {
                    topic: format!("{topic}/{q}"),
                    payload: format!("qos{q}").into_bytes(),
                    qos: q,
                    retain: false,
                });
            }
            let mut got = 0;
            let mut acks = 0;
            let deadline = Instant::now() + Duration::from_secs(15);
            while (got < 3 || acks < 2) && Instant::now() < deadline {
                match rx.recv_timeout(Duration::from_secs(15)).unwrap() {
                    Event::Message(m) => {
                        assert!(m.topic.starts_with(&topic));
                        got += 1
                    }
                    Event::Log(Lvl::Good, s) if s.contains("PUBACK") || s.contains("PUBCOMP") => {
                        acks += 1
                    }
                    Event::Error(e) => panic!("v5={v5}: {e}"),
                    _ => {}
                }
            }
            assert_eq!((got, acks), (3, 2), "v5={v5}");
        }
    }
}
