//! WebSocket (RFC 6455) client: ws:// and wss://, upgrade handshake with
//! custom headers and subprotocols, frame encoder/decoder, fragmentation,
//! ping RTT and close codes. Also holds the plain/TLS stream helper and the
//! small SHA-1 used by the IoT tools.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use base64::Engine;
use rustls::{ClientConnection, StreamOwned};

// ---------------------------------------------------------------- stream

/// A TCP connection, optionally wrapped in TLS.
pub enum NetStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl NetStream {
    pub fn tcp(&self) -> &TcpStream {
        match self {
            NetStream::Plain(s) => s,
            NetStream::Tls(s) => &s.sock,
        }
    }
    pub fn set_read_timeout(&self, d: Duration) {
        self.tcp().set_read_timeout(Some(d)).ok();
    }
}

impl Read for NetStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            NetStream::Plain(s) => s.read(buf),
            NetStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for NetStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            NetStream::Plain(s) => s.write(buf),
            NetStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            NetStream::Plain(s) => s.flush(),
            NetStream::Tls(s) => s.flush(),
        }
    }
}

/// What [`open`] connected to.
#[derive(Clone, Debug, Default)]
pub struct ConnInfo {
    pub addr: Option<SocketAddr>,
    pub connect_ms: f64,
    /// "TLS 1.3 TLS13_AES_256_GCM_SHA384"
    pub tls: Option<String>,
    /// Certificate summary when TLS was used.
    pub cert: Option<String>,
    /// Certificate verification problem (only with `insecure`).
    pub cert_error: Option<String>,
}

pub fn io_err(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "timeout".into(),
        io::ErrorKind::ConnectionRefused => "connection refused".into(),
        io::ErrorKind::ConnectionReset => "connection reset by the server".into(),
        io::ErrorKind::UnexpectedEof => "connection closed by the server".into(),
        _ => e.to_string(),
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn cert_summary(der: &[u8]) -> Option<String> {
    let c = crate::tls::parse_cert(der).ok()?;
    Some(format!(
        "{} — issued by {} — {} days left",
        c.subject, c.issuer, c.days_left
    ))
}

/// Connect to `host:port`, with TLS when `tls`. With `insecure` the
/// certificate is not verified (a verification failure is reported in
/// [`ConnInfo::cert_error`] instead of failing).
pub fn open(
    host: &str,
    port: u16,
    tls: bool,
    insecure: bool,
    wait: Duration,
) -> Result<(NetStream, ConnInfo), String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}: no address"))?;
    let t0 = Instant::now();
    let mut info = ConnInfo {
        addr: Some(addr),
        ..Default::default()
    };
    if !tls {
        let s = TcpStream::connect_timeout(&addr, wait)
            .map_err(|e| format!("{addr}: {}", io_err(&e)))?;
        info.connect_ms = t0.elapsed().as_secs_f64() * 1000.0;
        s.set_read_timeout(Some(wait)).ok();
        s.set_write_timeout(Some(wait)).ok();
        s.set_nodelay(true).ok();
        return Ok((NetStream::Plain(s), info));
    }
    let sni = host.trim_start_matches('[').trim_end_matches(']');
    let stream = if insecure {
        // Verify separately so the problem can be shown.
        if let Err(e) = crate::tls::connect_tls(sni, port, wait).and_then(|mut s| {
            while s.conn.is_handshaking() {
                s.conn.complete_io(&mut s.sock).map_err(|e| io_err(&e))?;
            }
            Ok(())
        }) {
            info.cert_error = Some(e);
        }
        let (s, _) = crate::tls::connect_insecure(sni, addr.ip(), port, wait)?;
        s
    } else {
        let mut s = crate::tls::connect_tls(sni, port, wait)?;
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .map_err(|e| format!("TLS: {}", io_err(&e)))?;
        }
        s
    };
    info.connect_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let v = match stream.conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        _ => "TLS",
    };
    let c = stream
        .conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_default();
    info.tls = Some(format!("{v} {c}"));
    info.cert = stream
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|c| cert_summary(c));
    stream.sock.set_nodelay(true).ok();
    Ok((NetStream::Tls(Box::new(stream)), info))
}

// ---------------------------------------------------------------- randomness & SHA-1

/// Unpredictable-enough bytes for nonces, masks and client ids (not for keys).
pub fn random_bytes(n: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let mut h = Sha256::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        h.update(now.to_le_bytes());
        h.update(CTR.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        h.update(std::process::id().to_le_bytes());
        let local = 0u8;
        h.update((&local as *const u8 as usize).to_le_bytes());
        h.update(format!("{:?}", Instant::now()).as_bytes());
        out.extend_from_slice(&h.finalize());
    }
    out.truncate(n);
    out
}

/// SHA-1 (FIPS 180-1). Only used for the WebSocket accept key.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, c) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn accept_key(key: &str) -> String {
    let mut s = key.as_bytes().to_vec();
    s.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha1(&s))
}

// ---------------------------------------------------------------- URL

#[derive(Clone, Debug, PartialEq)]
pub struct WsUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with '/'.
    pub path: String,
}

impl WsUrl {
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }
}

pub fn parse_url(s: &str) -> Result<WsUrl, String> {
    let s = s.trim();
    let (tls, rest) = if let Some(r) = s.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("ws://") {
        (false, r)
    } else if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else if s.contains("://") {
        return Err("URL must start with ws:// or wss://".into());
    } else {
        (false, s)
    };
    let (auth, path) = match rest.find(['/', '?']) {
        Some(i) if rest[i..].starts_with('/') => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let auth = auth.rsplit('@').next().unwrap_or(auth);
    let default = if tls { 443 } else { 80 };
    let (host, port) = if let Some(r) = auth.strip_prefix('[') {
        let end = r.find(']').ok_or("bad IPv6 address")?;
        let host = &r[..end];
        let port = match r[end + 1..].strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| "bad port")?,
            None => default,
        };
        (host.to_string(), port)
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
            None => (auth.to_string(), default),
        }
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    Ok(WsUrl {
        tls,
        host,
        port,
        path,
    })
}

// ---------------------------------------------------------------- frames

pub const OP_CONT: u8 = 0;
pub const OP_TEXT: u8 = 1;
pub const OP_BINARY: u8 = 2;
pub const OP_CLOSE: u8 = 8;
pub const OP_PING: u8 = 9;
pub const OP_PONG: u8 = 10;

pub fn opcode_name(op: u8) -> &'static str {
    match op {
        OP_CONT => "CONT",
        OP_TEXT => "TEXT",
        OP_BINARY => "BINARY",
        OP_CLOSE => "CLOSE",
        OP_PING => "PING",
        OP_PONG => "PONG",
        3..=7 => "RESERVED",
        _ => "RESERVED-CTRL",
    }
}

pub fn close_code_name(code: u16) -> &'static str {
    match code {
        1000 => "normal closure",
        1001 => "going away (server shutting down or page left)",
        1002 => "protocol error",
        1003 => "unsupported data type",
        1005 => "no status code given",
        1006 => "closed abnormally (no close frame)",
        1007 => "invalid payload data (e.g. bad UTF-8)",
        1008 => "policy violation",
        1009 => "message too big",
        1010 => "client expected an extension the server did not negotiate",
        1011 => "internal server error",
        1012 => "service restart",
        1013 => "try again later",
        1014 => "bad gateway",
        1015 => "TLS handshake failure",
        3000..=3999 => "registered application code",
        4000..=4999 => "private application code",
        _ => "unknown",
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    pub fin: bool,
    /// RSV1..3 bits (non-zero only with extensions such as permessage-deflate).
    pub rsv: u8,
    pub opcode: u8,
    pub masked: bool,
    pub payload: Vec<u8>,
}

/// Encode a frame; clients pass a mask, servers `None`.
pub fn encode_frame(opcode: u8, fin: bool, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(if fin { 0x80 } else { 0 } | (opcode & 0x0f));
    let m = if mask.is_some() { 0x80 } else { 0 };
    let n = payload.len();
    if n < 126 {
        out.push(m | n as u8);
    } else if n <= 0xffff {
        out.push(m | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(m | 127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    match mask {
        Some(k) => {
            out.extend_from_slice(&k);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

pub const MAX_FRAME: u64 = 16 << 20;

/// Decode one frame from the front of `buf`: `Ok(None)` = need more bytes.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    let rsv = (buf[0] >> 4) & 0x07;
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let mut pos = 2;
    let len = match buf[1] & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            pos = 4;
            u16::from_be_bytes([buf[2], buf[3]]) as u64
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            pos = 10;
            u64::from_be_bytes(buf[2..10].try_into().unwrap())
        }
        n => n as u64,
    };
    if len > MAX_FRAME {
        return Err(format!("frame of {len} bytes exceeds the 16 MiB limit"));
    }
    if opcode >= 8 && (len > 125 || !fin) {
        return Err("control frame too long or fragmented (protocol error)".into());
    }
    let key = if masked {
        if buf.len() < pos + 4 {
            return Ok(None);
        }
        let k = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        Some(k)
    } else {
        None
    };
    let end = pos + len as usize;
    if buf.len() < end {
        return Ok(None);
    }
    let mut payload = buf[pos..end].to_vec();
    if let Some(k) = key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= k[i % 4];
        }
    }
    Ok(Some((
        Frame {
            fin,
            rsv,
            opcode,
            masked,
            payload,
        },
        end,
    )))
}

/// Close-frame payload → (code, reason).
pub fn parse_close(p: &[u8]) -> (Option<u16>, String) {
    if p.len() < 2 {
        return (None, String::new());
    }
    (
        Some(u16::from_be_bytes([p[0], p[1]])),
        String::from_utf8_lossy(&p[2..]).into_owned(),
    )
}

/// Short printable preview of a payload.
pub fn preview(p: &[u8], text: bool, max: usize) -> String {
    if text || (std::str::from_utf8(p).is_ok() && !p.iter().any(|b| *b < 9)) {
        let s = String::from_utf8_lossy(p);
        let s: String = s
            .chars()
            .map(|c| if c.is_control() { '·' } else { c })
            .collect();
        if s.chars().count() > max {
            format!("{}…", s.chars().take(max).collect::<String>())
        } else {
            s
        }
    } else {
        let n = p.len().min(max / 3);
        let mut s: String = p[..n]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        if p.len() > n {
            s.push_str(" …");
        }
        s
    }
}

/// Parse "de ad be ef" / "deadbeef" / "0xde,0xad".
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != ':')
        .collect();
    if !clean.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| "not hex".to_string()))
        .collect()
}

// ---------------------------------------------------------------- handshake

#[derive(Clone, Debug)]
pub struct Config {
    pub url: String,
    /// Extra request headers ("Name: value").
    pub headers: Vec<(String, String)>,
    pub protocols: Vec<String>,
    pub origin: Option<String>,
    pub insecure: bool,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct HandshakeInfo {
    pub conn: ConnInfo,
    pub request: String,
    pub response: String,
    pub status: u16,
    pub subprotocol: Option<String>,
    pub extensions: Option<String>,
    pub server: Option<String>,
    pub accept_ok: bool,
    pub handshake_ms: f64,
}

pub fn build_request(url: &WsUrl, key: &str, cfg: &Config) -> String {
    let mut r = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
        url.path,
        url.host_header()
    );
    if !cfg.protocols.is_empty() {
        r.push_str(&format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            cfg.protocols.join(", ")
        ));
    }
    if let Some(o) = &cfg.origin {
        r.push_str(&format!("Origin: {o}\r\n"));
    }
    let has_ua = cfg
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
    if !has_ua {
        r.push_str(&format!(
            "User-Agent: network-analyser/{}\r\n",
            env!("CARGO_PKG_VERSION")
        ));
    }
    for (k, v) in &cfg.headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("\r\n");
    r
}

/// Split "Name: value" lines.
pub fn parse_header_lines(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let k = k.trim();
            (!k.is_empty()).then(|| (k.to_string(), v.trim().to_string()))
        })
        .collect()
}

fn header<'a>(resp: &'a str, name: &str) -> Option<&'a str> {
    resp.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Read up to the end of the HTTP headers; returns (headers, leftover bytes).
fn read_http_head(s: &mut NetStream, deadline: Instant) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).into_owned();
            return Ok((head, buf[i + 4..].to_vec()));
        }
        if buf.len() > 64 * 1024 {
            return Err("HTTP response headers too large".into());
        }
        if Instant::now() > deadline {
            return Err("timeout waiting for the upgrade response".into());
        }
        match s.read(&mut chunk) {
            Ok(0) => {
                return Err(if buf.is_empty() {
                    "connection closed before any response".into()
                } else {
                    format!(
                        "connection closed mid-response: {}",
                        String::from_utf8_lossy(&buf)
                    )
                });
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if is_timeout(&e) => {}
            Err(e) => return Err(io_err(&e)),
        }
    }
}

/// Explain a non-101 response.
fn explain_status(code: u16) -> &'static str {
    match code {
        200 => "the server answered as plain HTTP — this path is not a WebSocket endpoint",
        301 | 302 | 307 | 308 => "redirect — try the Location URL (often ws:// → wss://)",
        400 => "bad request — the server rejected the upgrade headers",
        401 | 403 => "authentication or origin refused (add an Authorization / Origin header)",
        404 => "no WebSocket endpoint at this path",
        426 => "upgrade required — the server wants a different protocol version",
        429 => "rate limited",
        500..=599 => "server error",
        _ => "upgrade refused",
    }
}

/// Connect and perform the opening handshake.
pub fn handshake(cfg: &Config) -> Result<(NetStream, HandshakeInfo, Vec<u8>), String> {
    let url = parse_url(&cfg.url)?;
    let (mut s, conn) = open(&url.host, url.port, url.tls, cfg.insecure, cfg.timeout)?;
    let key = base64::engine::general_purpose::STANDARD.encode(random_bytes(16));
    let req = build_request(&url, &key, cfg);
    let t0 = Instant::now();
    s.write_all(req.as_bytes()).map_err(|e| io_err(&e))?;
    s.set_read_timeout(Duration::from_millis(200));
    let (head, rest) = read_http_head(&mut s, Instant::now() + cfg.timeout)?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut info = HandshakeInfo {
        conn,
        request: req,
        response: head.clone(),
        status,
        subprotocol: header(&head, "sec-websocket-protocol").map(String::from),
        extensions: header(&head, "sec-websocket-extensions").map(String::from),
        server: header(&head, "server").map(String::from),
        accept_ok: header(&head, "sec-websocket-accept") == Some(accept_key(&key).as_str()),
        handshake_ms: t0.elapsed().as_secs_f64() * 1000.0,
    };
    if status != 101 {
        let loc = header(&head, "location")
            .map(|l| format!(" (Location: {l})"))
            .unwrap_or_default();
        return Err(format!(
            "HTTP {status}: {}{loc}\n\n{head}",
            explain_status(status)
        ));
    }
    if !header(&head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
        return Err(format!("101 without 'Upgrade: websocket'\n\n{head}"));
    }
    if !info.accept_ok {
        return Err(format!(
            "Sec-WebSocket-Accept does not match the key (proxy or broken server)\n\n{head}"
        ));
    }
    if let Some(p) = &info.subprotocol
        && !cfg.protocols.iter().any(|x| x == p)
    {
        info.subprotocol = Some(format!("{p} (not requested!)"));
    }
    Ok((s, info, rest))
}

// ---------------------------------------------------------------- session

pub enum Cmd {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Close(u16, String),
    Abort,
}

#[derive(Clone, Debug)]
pub struct LogFrame {
    /// Seconds since connect.
    pub at: f64,
    pub outgoing: bool,
    pub frame: Frame,
    /// Length on the wire including header.
    pub wire_len: usize,
}

pub enum Event {
    Handshake(Box<HandshakeInfo>),
    Frame(LogFrame),
    /// A complete (reassembled) data message.
    Message {
        text: bool,
        payload: Vec<u8>,
        fragments: usize,
    },
    Rtt(f64),
    Note(String),
    Closed {
        code: Option<u16>,
        reason: String,
        by_server: bool,
    },
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
        let _ = self.tx.send(Cmd::Abort);
    }
}

pub fn connect(cfg: Config) -> (Session, Receiver<Event>) {
    let (tx, crx) = channel();
    let (etx, erx) = channel();
    std::thread::spawn(move || run(cfg, crx, etx));
    (Session { tx }, erx)
}

fn mask() -> Option<[u8; 4]> {
    let r = random_bytes(4);
    Some([r[0], r[1], r[2], r[3]])
}

fn run(cfg: Config, rx: Receiver<Cmd>, tx: Sender<Event>) {
    let (mut s, info, mut buf) = match handshake(&cfg) {
        Ok(x) => x,
        Err(e) => {
            let _ = tx.send(Event::Error(e));
            return;
        }
    };
    let t0 = Instant::now();
    let _ = tx.send(Event::Handshake(Box::new(info)));
    s.set_read_timeout(Duration::from_millis(40));
    let mut pings: Vec<(Vec<u8>, Instant)> = Vec::new();
    let mut partial: Option<(bool, Vec<u8>, usize)> = None;
    let mut close_sent: Option<Instant> = None;
    let mut chunk = vec![0u8; 64 * 1024];

    let send = |s: &mut NetStream, op: u8, payload: &[u8], tx: &Sender<Event>| -> bool {
        let bytes = encode_frame(op, true, payload, mask());
        let ok = s.write_all(&bytes).and_then(|_| s.flush());
        if let Err(e) = ok {
            let _ = tx.send(Event::Error(format!("send failed: {}", io_err(&e))));
            return false;
        }
        let _ = tx.send(Event::Frame(LogFrame {
            at: t0.elapsed().as_secs_f64(),
            outgoing: true,
            frame: Frame {
                fin: true,
                rsv: 0,
                opcode: op,
                masked: true,
                payload: payload.to_vec(),
            },
            wire_len: bytes.len(),
        }));
        true
    };

    loop {
        // Commands.
        loop {
            match rx.try_recv() {
                Ok(Cmd::Text(t)) => {
                    if !send(&mut s, OP_TEXT, t.as_bytes(), &tx) {
                        return;
                    }
                }
                Ok(Cmd::Binary(b)) => {
                    if !send(&mut s, OP_BINARY, &b, &tx) {
                        return;
                    }
                }
                Ok(Cmd::Ping(mut p)) => {
                    if p.is_empty() {
                        p = format!("na-{}", t0.elapsed().as_micros()).into_bytes();
                    }
                    p.truncate(125);
                    pings.push((p.clone(), Instant::now()));
                    if !send(&mut s, OP_PING, &p, &tx) {
                        return;
                    }
                }
                Ok(Cmd::Close(code, reason)) => {
                    let mut p = code.to_be_bytes().to_vec();
                    p.extend(reason.bytes().take(123));
                    send(&mut s, OP_CLOSE, &p, &tx);
                    close_sent = Some(Instant::now());
                }
                Ok(Cmd::Abort) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if close_sent.is_none() {
                        let mut p = 1000u16.to_be_bytes().to_vec();
                        p.extend_from_slice(b"bye");
                        let _ = s.write_all(&encode_frame(OP_CLOSE, true, &p, mask()));
                    }
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
            }
        }
        if close_sent.is_some_and(|t| t.elapsed() > Duration::from_secs(3)) {
            let _ = tx.send(Event::Closed {
                code: None,
                reason: "server did not answer the close frame within 3 s".into(),
                by_server: false,
            });
            return;
        }
        // Frames already buffered.
        loop {
            match decode_frame(&buf) {
                Ok(Some((f, used))) => {
                    buf.drain(..used);
                    let _ = tx.send(Event::Frame(LogFrame {
                        at: t0.elapsed().as_secs_f64(),
                        outgoing: false,
                        frame: f.clone(),
                        wire_len: used,
                    }));
                    if f.masked {
                        let _ = tx.send(Event::Note(
                            "server sent a masked frame (RFC 6455 violation)".into(),
                        ));
                    }
                    if f.rsv != 0 {
                        let _ = tx.send(Event::Note(format!(
                            "frame has RSV bits {:03b} (compressed by an extension; payload not decoded)",
                            f.rsv
                        )));
                    }
                    match f.opcode {
                        OP_PING => {
                            send(&mut s, OP_PONG, &f.payload, &tx);
                        }
                        OP_PONG => {
                            if let Some(i) = pings.iter().position(|(p, _)| *p == f.payload) {
                                let (_, at) = pings.remove(i);
                                let _ = tx.send(Event::Rtt(at.elapsed().as_secs_f64() * 1000.0));
                            } else {
                                let _ = tx.send(Event::Note("unsolicited pong".into()));
                            }
                        }
                        OP_CLOSE => {
                            let (code, reason) = parse_close(&f.payload);
                            if close_sent.is_none() {
                                let echo =
                                    code.map(|c| c.to_be_bytes().to_vec()).unwrap_or_default();
                                send(&mut s, OP_CLOSE, &echo, &tx);
                            }
                            let _ = tx.send(Event::Closed {
                                code,
                                reason,
                                by_server: close_sent.is_none(),
                            });
                            return;
                        }
                        OP_TEXT | OP_BINARY => {
                            if partial.is_some() {
                                let _ = tx.send(Event::Note(
                                    "new data frame while a fragmented message was open (protocol error)"
                                        .into(),
                                ));
                            }
                            if f.fin {
                                let _ = tx.send(Event::Message {
                                    text: f.opcode == OP_TEXT,
                                    payload: f.payload,
                                    fragments: 1,
                                });
                                partial = None;
                            } else {
                                partial = Some((f.opcode == OP_TEXT, f.payload, 1));
                            }
                        }
                        OP_CONT => match partial.as_mut() {
                            Some((text, data, n)) => {
                                data.extend_from_slice(&f.payload);
                                *n += 1;
                                if data.len() as u64 > MAX_FRAME {
                                    let _ = tx.send(Event::Error("message exceeds 16 MiB".into()));
                                    return;
                                }
                                if f.fin {
                                    let (text, data, n) = (*text, std::mem::take(data), *n);
                                    partial = None;
                                    let _ = tx.send(Event::Message {
                                        text,
                                        payload: data,
                                        fragments: n,
                                    });
                                }
                            }
                            None => {
                                let _ = tx.send(Event::Note(
                                    "continuation frame without a start (protocol error)".into(),
                                ));
                            }
                        },
                        op => {
                            let _ = tx.send(Event::Note(format!("reserved opcode {op:#x}")));
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = tx.send(Event::Error(e));
                    return;
                }
            }
        }
        match s.read(&mut chunk) {
            Ok(0) => {
                let _ = tx.send(Event::Closed {
                    code: Some(1006),
                    reason: "TCP connection closed without a close frame".into(),
                    by_server: true,
                });
                return;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                let _ = tx.send(Event::Closed {
                    code: Some(1006),
                    reason: io_err(&e),
                    by_server: true,
                });
                return;
            }
        }
    }
}

// ---------------------------------------------------------------- CLI

/// `--ws URL [MESSAGE]`
pub fn cli(args: &[String]) {
    let Some(url) = args.first() else {
        eprintln!("usage: --ws URL [MESSAGE]   e.g. --ws wss://echo.websocket.org hello");
        std::process::exit(2)
    };
    let cfg = Config {
        url: url.clone(),
        headers: Vec::new(),
        protocols: Vec::new(),
        origin: None,
        insecure: false,
        timeout: Duration::from_secs(10),
    };
    let (sess, rx) = connect(cfg);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut sent = false;
    let mut quiet_until: Option<Instant> = None;
    loop {
        let ev = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(e) => e,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if quiet_until.is_some_and(|t| Instant::now() > t) || Instant::now() > deadline {
                    sess.send(Cmd::Close(1000, "done".into()));
                    quiet_until = None;
                }
                continue;
            }
            Err(_) => break,
        };
        match ev {
            Event::Handshake(h) => {
                println!(
                    "connected to {}",
                    h.conn.addr.map(|a| a.to_string()).unwrap_or_default()
                );
                if let Some(t) = &h.conn.tls {
                    println!("tls:         {t}");
                }
                if let Some(c) = &h.conn.cert {
                    println!("certificate: {c}");
                }
                println!(
                    "handshake:   HTTP {} in {:.1} ms (connect {:.1} ms)",
                    h.status, h.handshake_ms, h.conn.connect_ms
                );
                println!(
                    "subprotocol: {}   extensions: {}   server: {}",
                    h.subprotocol.as_deref().unwrap_or("-"),
                    h.extensions.as_deref().unwrap_or("-"),
                    h.server.as_deref().unwrap_or("-")
                );
                if !sent {
                    sent = true;
                    if let Some(m) = args.get(1) {
                        sess.send(Cmd::Text(m.clone()));
                    }
                    sess.send(Cmd::Ping(Vec::new()));
                    quiet_until = Some(Instant::now() + Duration::from_secs(3));
                }
            }
            Event::Frame(f) => println!(
                "{:>8.3}s {} {:<6} {:>6} B  {}",
                f.at,
                if f.outgoing { "→" } else { "←" },
                opcode_name(f.frame.opcode),
                f.frame.payload.len(),
                preview(&f.frame.payload, f.frame.opcode == OP_TEXT, 100)
            ),
            Event::Message { .. } => {}
            Event::Rtt(ms) => println!("ping RTT {ms:.1} ms"),
            Event::Note(n) => println!("note: {n}"),
            Event::Closed {
                code,
                reason,
                by_server,
            } => {
                println!(
                    "closed by {}: {} {}",
                    if by_server { "server" } else { "client" },
                    code.map(|c| format!("{c} ({})", close_code_name(c)))
                        .unwrap_or_else(|| "-".into()),
                    reason
                );
                break;
            }
            Event::Error(e) => {
                eprintln!("error: {e}");
                std::process::exit(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let a = vec![b'a'; 1000];
        assert_eq!(hex(&sha1(&a)), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
    }

    #[test]
    fn rfc6455_accept_key() {
        // RFC 6455 section 1.3 example.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn frames_rfc_examples() {
        // RFC 6455 5.7: unmasked "Hello".
        let f = encode_frame(OP_TEXT, true, b"Hello", None);
        assert_eq!(f, [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
        // Masked "Hello" with key 37 fa 21 3d.
        let m = encode_frame(OP_TEXT, true, b"Hello", Some([0x37, 0xfa, 0x21, 0x3d]));
        assert_eq!(
            m,
            [
                0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]
        );
        let (d, used) = decode_frame(&m).unwrap().unwrap();
        assert_eq!(used, m.len());
        assert!(d.masked && d.fin);
        assert_eq!(d.payload, b"Hello");
        // Fragmented: "Hel" + "lo".
        let (a, _) = decode_frame(&[0x01, 0x03, 0x48, 0x65, 0x6c])
            .unwrap()
            .unwrap();
        assert!(!a.fin && a.opcode == OP_TEXT);
        let (b, _) = decode_frame(&[0x80, 0x02, 0x6c, 0x6f]).unwrap().unwrap();
        assert!(b.fin && b.opcode == OP_CONT);
        // 256-byte binary uses the 16-bit length.
        let big = vec![7u8; 256];
        let e = encode_frame(OP_BINARY, true, &big, None);
        assert_eq!(&e[..4], &[0x82, 0x7e, 0x01, 0x00]);
        assert_eq!(decode_frame(&e).unwrap().unwrap().0.payload, big);
        // 64 KiB uses the 64-bit length.
        let huge = vec![1u8; 65536];
        let e = encode_frame(OP_BINARY, true, &huge, None);
        assert_eq!(&e[..10], &[0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0]);
        // Incomplete.
        assert!(decode_frame(&e[..100]).unwrap().is_none());
        assert!(decode_frame(&[0x81]).unwrap().is_none());
        // Oversized control frame.
        assert!(decode_frame(&[0x89, 0x7e, 0, 200]).is_err());
        assert_eq!(
            parse_close(&[0x03, 0xe8, b'o', b'k']),
            (Some(1000), "ok".into())
        );
    }

    #[test]
    fn urls_and_hex() {
        let u = parse_url("wss://example.com/chat?x=1").unwrap();
        assert_eq!((u.tls, u.port, u.path.as_str()), (true, 443, "/chat?x=1"));
        assert_eq!(u.host_header(), "example.com");
        let u = parse_url("ws://[::1]:9001").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("::1", 9001, "/")
        );
        assert_eq!(u.host_header(), "[::1]:9001");
        let u = parse_url("10.0.0.5:8080?token=a").unwrap();
        assert_eq!((u.tls, u.port, u.path.as_str()), (false, 8080, "/?token=a"));
        assert!(parse_url("ftp://x").is_err());
        assert_eq!(
            parse_hex("de ad 0xBE,ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(parse_hex("abc").is_err());
        assert_eq!(
            parse_header_lines("Authorization: Bearer x\nbad\nX-A:  1 "),
            vec![
                ("Authorization".into(), "Bearer x".into()),
                ("X-A".into(), "1".into())
            ]
        );
    }

    /// Minimal echo server: handshake, echoes text/binary, answers ping, closes.
    fn echo_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut b = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = c.read(&mut b).unwrap();
                buf.extend_from_slice(&b[..n]);
            }
            let req = String::from_utf8_lossy(&buf).into_owned();
            let key = header(&format!("x\r\n{req}"), "sec-websocket-key")
                .unwrap()
                .to_string();
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
                accept_key(&key)
            );
            c.write_all(resp.as_bytes()).unwrap();
            // Unsolicited fragmented message first.
            c.write_all(&encode_frame(OP_TEXT, false, b"frag-", None))
                .unwrap();
            c.write_all(&encode_frame(OP_CONT, true, b"ment", None))
                .unwrap();
            let mut buf: Vec<u8> = Vec::new();
            loop {
                while let Ok(Some((f, used))) = decode_frame(&buf) {
                    buf.drain(..used);
                    assert!(f.masked, "client frames must be masked");
                    let reply = match f.opcode {
                        OP_PING => OP_PONG,
                        OP_CLOSE => {
                            c.write_all(&encode_frame(OP_CLOSE, true, &f.payload, None))
                                .unwrap();
                            return;
                        }
                        op => op,
                    };
                    c.write_all(&encode_frame(reply, true, &f.payload, None))
                        .unwrap();
                }
                let n = c.read(&mut b).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&b[..n]);
            }
        });
        port
    }

    #[test]
    fn session_against_local_echo_server() {
        let port = echo_server();
        let (sess, rx) = connect(Config {
            url: format!("ws://127.0.0.1:{port}/echo"),
            headers: vec![("X-Test".into(), "1".into())],
            protocols: vec!["chat".into()],
            origin: None,
            insecure: false,
            timeout: Duration::from_secs(5),
        });
        let next = || rx.recv_timeout(Duration::from_secs(5)).expect("event");
        let Event::Handshake(h) = next() else {
            panic!("no handshake")
        };
        assert!(h.accept_ok);
        assert_eq!(h.subprotocol.as_deref(), Some("chat"));
        assert!(h.request.contains("X-Test: 1\r\n"));
        sess.send(Cmd::Text("hi".into()));
        sess.send(Cmd::Ping(Vec::new()));
        sess.send(Cmd::Binary(vec![1, 2, 3]));
        let mut msgs = Vec::new();
        let mut rtt = false;
        while msgs.len() < 3 || !rtt {
            match next() {
                Event::Message {
                    payload, fragments, ..
                } => msgs.push((payload, fragments)),
                Event::Rtt(_) => rtt = true,
                Event::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
        assert_eq!(msgs[0], (b"frag-ment".to_vec(), 2));
        assert_eq!(msgs[1].0, b"hi");
        assert_eq!(msgs[2].0, vec![1, 2, 3]);
        sess.send(Cmd::Close(1000, "done".into()));
        loop {
            if let Event::Closed {
                code, by_server, ..
            } = next()
            {
                assert_eq!(code, Some(1000));
                assert!(!by_server);
                break;
            }
        }
    }
}
