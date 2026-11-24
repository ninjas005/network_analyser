//! HTTP/1.x reconstruction from a reassembled TCP stream: requests and
//! responses are paired, chunked bodies joined and compressed bodies decoded.

use std::io::Read;

use crate::streams::{CLIENT, SERVER};

/// Body bytes kept per message.
const MAX_BODY: usize = 8 << 20;
/// Body bytes kept for the whole capture.
const MAX_TOTAL: usize = 256 << 20;
/// Headers longer than this are not HTTP.
const MAX_HEAD: usize = 128 << 10;
/// Limit for decompression ("zip bombs").
const MAX_DECODED: u64 = 16 << 20;

/// Body memory left for the capture.
pub struct Budget(usize);

impl Default for Budget {
    fn default() -> Self {
        Budget(MAX_TOTAL)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Message {
    /// Request or status line.
    pub line: String,
    pub headers: Vec<(String, String)>,
    /// Body without chunk framing, still compressed.
    pub body: Vec<u8>,
    /// Body bytes seen, including those not kept.
    pub body_len: u64,
    /// Body bytes missing from the capture.
    pub missing: u64,
    pub complete: bool,
    pub start: f64,
    pub end: f64,
    /// Number of the packet the message starts in.
    pub no: usize,
}

impl Message {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn content_type(&self) -> &str {
        let t = self.header("content-type").unwrap_or("");
        t.split(';').next().unwrap_or("").trim()
    }
    fn word(&self, n: usize) -> &str {
        self.line.split_whitespace().nth(n).unwrap_or("")
    }
    pub fn method(&self) -> &str {
        self.word(0)
    }
    pub fn target(&self) -> &str {
        self.word(1)
    }
    pub fn status(&self) -> u16 {
        self.word(1).parse().unwrap_or(0)
    }

    /// Body with the content encoding removed, and a note when it could not
    /// be (fully) decoded.
    pub fn decoded(&self) -> (Vec<u8>, Option<String>) {
        let enc = self
            .header("content-encoding")
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let mut out = Vec::new();
        let res = match enc.as_str() {
            "" | "identity" => return (self.body.clone(), None),
            "gzip" | "x-gzip" => flate2::read::MultiGzDecoder::new(&self.body[..])
                .take(MAX_DECODED)
                .read_to_end(&mut out),
            // "deflate" means zlib, but some servers send raw deflate.
            "deflate" => {
                let r = flate2::read::ZlibDecoder::new(&self.body[..])
                    .take(MAX_DECODED)
                    .read_to_end(&mut out);
                if r.is_err() && out.is_empty() {
                    flate2::read::DeflateDecoder::new(&self.body[..])
                        .take(MAX_DECODED)
                        .read_to_end(&mut out)
                } else {
                    r
                }
            }
            e => {
                return (
                    self.body.clone(),
                    Some(format!("{e} encoding is not decoded; raw bytes shown")),
                );
            }
        };
        match res {
            Ok(_) if out.len() as u64 >= MAX_DECODED => {
                (out, Some("decoded body cut at 16 MB".into()))
            }
            Ok(_) => (out, None),
            Err(_) if out.is_empty() && !self.body.is_empty() => (
                self.body.clone(),
                Some(format!("damaged or incomplete {enc} data; raw bytes shown")),
            ),
            Err(_) => (out, Some(format!("{enc} data is incomplete"))),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Exchange {
    pub req: Option<Message>,
    pub resp: Option<Message>,
    /// Interim responses (100 Continue, 103 Early Hints).
    pub interim: Vec<String>,
}

impl Exchange {
    pub fn host(&self) -> &str {
        self.req
            .as_ref()
            .and_then(|r| r.header("host"))
            .unwrap_or("")
    }
    pub fn url(&self) -> String {
        match &self.req {
            Some(r) if r.target().starts_with('/') => {
                format!("http://{}{}", self.host(), r.target())
            }
            Some(r) => r.target().to_string(),
            None => String::new(),
        }
    }
    /// Seconds from the end of the request to the first response byte.
    pub fn wait(&self) -> Option<f64> {
        Some((self.resp.as_ref()?.start - self.req.as_ref()?.end).max(0.0))
    }
    /// First request byte to last response byte.
    pub fn total(&self) -> Option<f64> {
        Some((self.resp.as_ref()?.end - self.req.as_ref()?.start).max(0.0))
    }
    pub fn start(&self) -> f64 {
        match (&self.req, &self.resp) {
            (Some(m), _) | (None, Some(m)) => m.start,
            _ => 0.0,
        }
    }

    /// A curl command repeating the request.
    pub fn curl(&self) -> Option<String> {
        let r = self.req.as_ref()?;
        let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        let mut out = format!("curl -X {} {}", q(r.method()), q(&self.url()));
        for (k, v) in &r.headers {
            let skip = ["host", "content-length", "transfer-encoding", "connection"];
            if !skip.contains(&k.to_ascii_lowercase().as_str()) {
                out += &format!(" -H {}", q(&format!("{k}: {v}")));
            }
        }
        if !r.body.is_empty() {
            match std::str::from_utf8(&r.body) {
                Ok(t) if !t.contains('\0') => out += &format!(" --data-raw {}", q(t)),
                _ => out += " --data-binary @body.bin",
            }
        }
        Some(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum St {
    /// Collecting the start line and headers.
    Head,
    Fixed(u64),
    UntilClose,
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailer,
    /// Lost track: wait for something that looks like a message.
    Resync,
    /// Not HTTP any more (upgrade or tunnel).
    Raw,
}

struct Side {
    st: St,
    buf: Vec<u8>,
    /// Exchange the message in progress belongs to.
    cur: Option<usize>,
}

impl Default for Side {
    fn default() -> Self {
        Side {
            st: St::Resync,
            buf: Vec::new(),
            cur: None,
        }
    }
}

#[derive(Default)]
pub struct HttpConn {
    pub exchanges: Vec<Exchange>,
    /// Protocol the connection switched to ("websocket", "CONNECT tunnel").
    pub upgraded: Option<String>,
    sides: [Side; 2],
    /// Exchange the next final response belongs to.
    next_resp: usize,
}

impl HttpConn {
    fn msg(&mut self, dir: usize) -> Option<&mut Message> {
        let e = self.exchanges.get_mut(self.sides[dir].cur?)?;
        if dir == CLIENT {
            e.req.as_mut()
        } else {
            e.resp.as_mut()
        }
    }

    fn end(&mut self, dir: usize, complete: bool) {
        if let Some(m) = self.msg(dir) {
            m.complete = complete && m.missing == 0;
        }
        let s = &mut self.sides[dir];
        s.cur = None;
        s.buf.clear();
        s.st = if complete { St::Head } else { St::Resync };
        if dir == SERVER {
            self.next_resp += 1;
        }
    }

    /// The sender closed its side.
    pub fn close(&mut self, dir: usize) {
        match self.sides[dir].st {
            St::UntilClose => self.end(dir, true),
            St::Head | St::Resync | St::Raw => {}
            _ => self.end(dir, false),
        }
    }

    /// `n` bytes are missing from the capture.
    pub fn gap(&mut self, dir: usize, n: u64) {
        let st = self.sides[dir].st;
        match st {
            St::Raw => {}
            St::UntilClose => {
                if let Some(m) = self.msg(dir) {
                    m.missing += n;
                }
            }
            St::Fixed(left) | St::ChunkData(left) if n <= left => {
                if let Some(m) = self.msg(dir) {
                    m.missing += n;
                }
                let left = left - n;
                if st == St::Fixed(left + n) {
                    self.sides[dir].st = St::Fixed(left);
                    if left == 0 {
                        self.end(dir, true);
                    }
                } else {
                    self.sides[dir].st = if left == 0 {
                        St::ChunkEnd
                    } else {
                        St::ChunkData(left)
                    };
                }
            }
            _ => {
                if self.sides[dir].cur.is_some() {
                    if let Some(m) = self.msg(dir) {
                        m.missing += n;
                    }
                    self.end(dir, false);
                }
                let s = &mut self.sides[dir];
                s.buf.clear();
                s.st = St::Resync;
            }
        }
    }

    fn body(&mut self, dir: usize, data: &[u8], ts: f64, budget: &mut Budget) {
        if let Some(m) = self.msg(dir) {
            m.end = ts;
            m.body_len += data.len() as u64;
            let room = (MAX_BODY - m.body.len().min(MAX_BODY)).min(budget.0);
            let n = data.len().min(room);
            budget.0 -= n;
            m.body.extend_from_slice(&data[..n]);
        }
    }

    /// Next `len` bytes of the direction's stream.
    pub fn feed(&mut self, dir: usize, mut data: &[u8], ts: f64, no: usize, budget: &mut Budget) {
        while !data.is_empty() {
            match self.sides[dir].st {
                St::Raw => return,
                St::Resync => {
                    if !crate::appproto::is_http(data) {
                        return;
                    }
                    self.sides[dir].st = St::Head;
                }
                St::Head => {
                    let s = &mut self.sides[dir];
                    if s.buf.is_empty() {
                        // Tolerate blank lines between messages.
                        let blank = data
                            .iter()
                            .take_while(|c| matches!(c, b'\r' | b'\n'))
                            .count();
                        data = &data[blank..];
                        if data.is_empty() {
                            return;
                        }
                    }
                    if s.cur.is_none() {
                        s.cur = Some(usize::MAX);
                        self.begin(dir, ts, no);
                    }
                    let s = &mut self.sides[dir];
                    let old = s.buf.len();
                    s.buf.extend_from_slice(data);
                    let Some(end) = head_end(&s.buf, old) else {
                        if s.buf.len() > MAX_HEAD {
                            self.abandon(dir);
                        }
                        return;
                    };
                    let head: Vec<u8> = s.buf.drain(..).take(end).collect();
                    data = &data[end - old..];
                    self.headers(dir, &head, ts);
                }
                St::Fixed(left) => {
                    let n = (data.len() as u64).min(left) as usize;
                    self.body(dir, &data[..n], ts, budget);
                    data = &data[n..];
                    let left = left - n as u64;
                    self.sides[dir].st = St::Fixed(left);
                    if left == 0 {
                        self.end(dir, true);
                    }
                }
                St::UntilClose => {
                    self.body(dir, data, ts, budget);
                    return;
                }
                St::ChunkData(left) => {
                    let n = (data.len() as u64).min(left) as usize;
                    self.body(dir, &data[..n], ts, budget);
                    data = &data[n..];
                    let left = left - n as u64;
                    self.sides[dir].st = if left == 0 {
                        St::ChunkEnd
                    } else {
                        St::ChunkData(left)
                    };
                }
                st @ (St::ChunkSize | St::ChunkEnd | St::Trailer) => {
                    let Some(line) = self.line(dir, &mut data) else {
                        if self.sides[dir].buf.len() > 8192 {
                            self.end(dir, false);
                        }
                        return;
                    };
                    match st {
                        St::ChunkEnd => self.sides[dir].st = St::ChunkSize,
                        St::Trailer => {
                            if line.is_empty() {
                                if let Some(m) = self.msg(dir) {
                                    m.end = ts;
                                }
                                self.end(dir, true);
                            }
                        }
                        _ => {
                            let hex = line.split(';').next().unwrap_or("").trim();
                            match u64::from_str_radix(hex, 16) {
                                Ok(0) => self.sides[dir].st = St::Trailer,
                                Ok(n) => self.sides[dir].st = St::ChunkData(n),
                                Err(_) => self.end(dir, false),
                            }
                        }
                    }
                }
            }
        }
    }

    /// A complete line (without its end) once it has arrived.
    fn line(&mut self, dir: usize, data: &mut &[u8]) -> Option<String> {
        let buf = &mut self.sides[dir].buf;
        match data.iter().position(|c| *c == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&data[..i]);
                *data = &data[i + 1..];
                let s = String::from_utf8_lossy(buf).trim().to_string();
                buf.clear();
                Some(s)
            }
            None => {
                buf.extend_from_slice(data);
                *data = &[];
                None
            }
        }
    }

    /// Create the message and attach it to its exchange.
    fn begin(&mut self, dir: usize, ts: f64, no: usize) {
        let m = Message {
            start: ts,
            end: ts,
            no,
            ..Default::default()
        };
        let i = if dir == CLIENT {
            // A response may have been seen first when its request was lost
            // from the capture; requests always open a new exchange.
            self.exchanges.push(Exchange {
                req: Some(m),
                ..Default::default()
            });
            self.exchanges.len() - 1
        } else {
            if self.next_resp >= self.exchanges.len() {
                self.exchanges.push(Exchange::default());
                self.next_resp = self.exchanges.len() - 1;
            }
            self.exchanges[self.next_resp].resp = Some(m);
            self.next_resp
        };
        self.sides[dir].cur = Some(i);
    }

    /// What was collected is not an HTTP message.
    fn abandon(&mut self, dir: usize) {
        if let Some(e) = self.sides[dir].cur.and_then(|i| self.exchanges.get_mut(i)) {
            if dir == CLIENT {
                e.req = None;
            } else {
                e.resp = None;
            }
        }
        let last_empty = self
            .exchanges
            .last()
            .is_some_and(|e| e.req.is_none() && e.resp.is_none());
        if last_empty {
            self.exchanges.pop();
        }
        let s = &mut self.sides[dir];
        s.cur = None;
        s.buf.clear();
        s.st = St::Resync;
    }

    fn headers(&mut self, dir: usize, head: &[u8], ts: f64) {
        if !crate::appproto::is_http(head) {
            return self.abandon(dir);
        }
        let text: String = String::from_utf8_lossy(head).into_owned();
        let mut lines = text.lines();
        let line = lines.next().unwrap_or("").trim().to_string();
        let mut headers: Vec<(String, String)> = Vec::new();
        for l in lines {
            if l.starts_with([' ', '\t'])
                && let Some(last) = headers.last_mut()
            {
                // Obsolete line folding.
                last.1 += " ";
                last.1 += l.trim();
            } else if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().into(), v.trim().into()));
            }
        }
        let Some(m) = self.msg(dir) else { return };
        m.line = line;
        m.headers = headers;
        m.end = ts;
        let m = m.clone();
        let chunked = m
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = m
            .header("content-length")
            .and_then(|v| v.parse::<u64>().ok());
        let st = if dir == CLIENT {
            match (chunked, length) {
                (true, _) => St::ChunkSize,
                (_, Some(n)) if n > 0 => St::Fixed(n),
                _ => return self.end(dir, true),
            }
        } else {
            let i = self.sides[dir].cur.unwrap_or(0);
            let method = self
                .exchanges
                .get(i)
                .and_then(|e| e.req.as_ref())
                .map(|r| r.method().to_string())
                .unwrap_or_default();
            let status = m.status();
            if status == 101 || (method == "CONNECT" && (200..300).contains(&status)) {
                self.upgraded = Some(if status == 101 {
                    m.header("upgrade").unwrap_or("upgraded").to_string()
                } else {
                    "CONNECT tunnel".into()
                });
                self.end(dir, true);
                for s in &mut self.sides {
                    s.st = St::Raw;
                }
                return;
            }
            if (100..200).contains(&status) {
                // Interim: the real response follows for the same request.
                let e = &mut self.exchanges[i];
                e.interim.push(m.line);
                e.resp = None;
                let s = &mut self.sides[dir];
                s.cur = None;
                s.buf.clear();
                return;
            }
            if method == "HEAD" || status == 204 || status == 304 {
                return self.end(dir, true);
            }
            match (chunked, length) {
                (true, _) => St::ChunkSize,
                (_, Some(0)) => return self.end(dir, true),
                (_, Some(n)) => St::Fixed(n),
                _ => St::UntilClose,
            }
        };
        self.sides[dir].st = st;
    }
}

/// Offset after the blank line ending the headers; `from` = bytes already
/// searched before.
fn head_end(b: &[u8], from: usize) -> Option<usize> {
    let mut i = from.saturating_sub(3);
    while let Some(n) = b[i..].iter().position(|c| *c == b'\n') {
        let at = i + n + 1;
        match &b[at..] {
            [b'\n', ..] if at + 1 > from => return Some(at + 1),
            [b'\r', b'\n', ..] if at + 2 > from => return Some(at + 2),
            _ => {}
        }
        i = at;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn run(parts: &[(usize, &[u8])]) -> HttpConn {
        let mut h = HttpConn::default();
        let mut b = Budget::default();
        for (i, (dir, data)) in parts.iter().enumerate() {
            h.feed(*dir, data, i as f64, i + 1, &mut b);
        }
        h
    }

    /// The same conversation cut at every possible place parses the same.
    #[test]
    fn every_segmentation_gives_the_same_result() {
        let req = b"POST /api HTTP/1.1\r\nHost: plc\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: plc\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nT: v\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnop";
        for step in 1..resp.len() {
            let mut parts: Vec<(usize, &[u8])> = Vec::new();
            // Keep request starts recognisable: the first piece is whole.
            parts.push((CLIENT, &req[..20]));
            parts.extend(req[20..].chunks(step).map(|c| (CLIENT, c)));
            parts.push((SERVER, &resp[..12]));
            parts.extend(resp[12..].chunks(step).map(|c| (SERVER, c)));
            let h = run(&parts);
            assert_eq!(h.exchanges.len(), 2, "step {step}");
            let (a, b) = (&h.exchanges[0], &h.exchanges[1]);
            assert_eq!(a.req.as_ref().unwrap().body, b"hello");
            assert_eq!(a.resp.as_ref().unwrap().body, b"Wikipedia");
            assert!(a.resp.as_ref().unwrap().complete);
            assert_eq!(a.url(), "http://plc/api");
            assert_eq!(b.resp.as_ref().unwrap().status(), 404);
            assert_eq!(b.resp.as_ref().unwrap().body, b"nop");
        }
    }

    #[test]
    fn head_interim_and_until_close() {
        let mut h = run(&[
            (CLIENT, b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n"),
            (SERVER, b"HTTP/1.1 200 OK\r\nContent-Length: 900\r\n\r\n"),
            (
                CLIENT,
                b"PUT /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\n",
            ),
            (SERVER, b"HTTP/1.1 100 Continue\r\n\r\n"),
            (CLIENT, b"ok"),
            (SERVER, b"HTTP/1.1 201 Created\r\n\r\npartial"),
            (SERVER, b" rest"),
        ]);
        assert_eq!(h.exchanges[0].resp.as_ref().unwrap().body_len, 0);
        let e = &h.exchanges[1];
        assert_eq!(e.interim, ["HTTP/1.1 100 Continue"]);
        assert_eq!(e.resp.as_ref().unwrap().body, b"partial rest");
        assert!(!e.resp.as_ref().unwrap().complete);
        h.close(SERVER);
        assert!(h.exchanges[1].resp.as_ref().unwrap().complete);
    }

    #[test]
    fn gzip_deflate_and_unknown_encodings() {
        let text = b"temperature=21.5".repeat(50);
        let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&text).unwrap();
        let gz = z.finish().unwrap();
        let msg = |enc: &str, body: &[u8]| Message {
            headers: vec![("Content-Encoding".into(), enc.into())],
            body: body.to_vec(),
            ..Default::default()
        };
        assert_eq!(msg("gzip", &gz).decoded(), (text.clone(), None));
        let (part, note) = msg("gzip", &gz[..gz.len() - 12]).decoded();
        assert!(note.is_some() && text.starts_with(&part[..]) || part == gz[..gz.len() - 12]);
        let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&text).unwrap();
        assert_eq!(msg("deflate", &z.finish().unwrap()).decoded().0, text);
        assert!(msg("br", b"xx").decoded().1.unwrap().contains("br"));
    }

    #[test]
    fn websocket_upgrade_stops_parsing() {
        let h = run(&[
            (
                CLIENT,
                b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n",
            ),
            (
                SERVER,
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello",
            ),
            (CLIENT, b"GET / HTTP/1.1\r\n\r\n"),
        ]);
        assert_eq!(h.upgraded.as_deref(), Some("websocket"));
        assert_eq!(h.exchanges.len(), 1);
    }

    #[test]
    fn gaps_inside_and_outside_bodies() {
        let mut h = HttpConn::default();
        let mut b = Budget::default();
        h.feed(CLIENT, b"GET / HTTP/1.1\r\n\r\n", 0.0, 1, &mut b);
        h.feed(
            SERVER,
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
            1.0,
            2,
            &mut b,
        );
        h.gap(SERVER, 4);
        h.feed(SERVER, b"xyz", 2.0, 3, &mut b);
        let m = h.exchanges[0].resp.as_ref().unwrap();
        assert_eq!(
            (&m.body[..], m.missing, m.complete),
            (&b"abcxyz"[..], 4, false)
        );
        // The next exchange still parses.
        h.feed(CLIENT, b"GET /2 HTTP/1.1\r\n\r\n", 3.0, 4, &mut b);
        h.gap(SERVER, 99);
        h.feed(SERVER, b"HTTP/1.1 204 No Content\r\n\r\n", 4.0, 5, &mut b);
        assert_eq!(h.exchanges[1].resp.as_ref().unwrap().status(), 204);
    }

    #[test]
    fn curl_quotes_untrusted_values() {
        let h = run(&[(
            CLIENT,
            b"POST /a'$(id) HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nX: 'y'\r\n\r\nit's",
        )]);
        assert_eq!(
            h.exchanges[0].curl().unwrap(),
            r"curl -X 'POST' 'http://h/a'\''$(id)' -H 'X: '\''y'\''' --data-raw 'it'\''s'"
        );
    }
}
