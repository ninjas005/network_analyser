//! DNS client tester: benchmarks resolvers over UDP, TCP and DNS-over-TLS
//! (cached and uncached names) and checks how they behave: NXDOMAIN
//! rewriting, DNSSEC validation, EDNS, TCP, truncation, answer integrity
//! and DNS-rebinding protection.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

use crate::dns::{self, Response};
use crate::gateway::{Finding, Level};

/// Popular names: normally in every resolver's cache.
pub const POPULAR: &[&str] = &[
    "google.com",
    "youtube.com",
    "facebook.com",
    "wikipedia.org",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "github.com",
    "netflix.com",
];

/// Names whose true A records are stable and public (integrity check).
const KNOWN: &[(&str, &[&str])] = &[
    ("one.one.one.one", &["1.0.0.1", "1.1.1.1"]),
    ("dns.google", &["8.8.4.4", "8.8.8.8"]),
];

/// Compared between resolvers (majority wins).
const COMPARE: &[&str] = &["example.com", "one.one.one.one", "dns.google"];

// ---------------------------------------------------------------- resolvers

#[derive(Clone, Debug, PartialEq)]
pub struct Resolver {
    pub label: String,
    pub addr: SocketAddr,
    /// Name to verify the DoT certificate against (IP if unknown).
    pub tls_name: String,
}

/// DoT certificate names of well-known public resolvers.
pub fn known_tls_name(ip: IpAddr) -> Option<&'static str> {
    Some(match ip.to_string().as_str() {
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => {
            "cloudflare-dns.com"
        }
        "1.1.1.2" | "1.0.0.2" => "security.cloudflare-dns.com",
        "1.1.1.3" | "1.0.0.3" => "family.cloudflare-dns.com",
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => "dns.google",
        "9.9.9.9" | "149.112.112.112" | "2620:fe::fe" | "2620:fe::9" => "dns.quad9.net",
        "94.140.14.14" | "94.140.15.15" => "dns.adguard-dns.com",
        "208.67.222.222" | "208.67.220.220" => "dns.opendns.com",
        _ => return None,
    })
}

pub fn provider(ip: IpAddr) -> Option<&'static str> {
    Some(match known_tls_name(ip)? {
        "cloudflare-dns.com" | "security.cloudflare-dns.com" | "family.cloudflare-dns.com" => {
            "Cloudflare"
        }
        "dns.google" => "Google",
        "dns.quad9.net" => "Quad9",
        "dns.adguard-dns.com" => "AdGuard",
        "dns.opendns.com" => "OpenDNS",
        _ => return None,
    })
}

/// "1.1.1.1", "9.9.9.9#dns.quad9.net", "dns.google", "[::1]:5353",
/// "192.168.1.1:53".
pub fn parse_resolver(s: &str) -> Result<Resolver, String> {
    let s = s.trim();
    let (spec, tls) = match s.split_once('#') {
        Some((a, n)) => (a, Some(n.to_string())),
        None => (s, None),
    };
    let addr = if let Ok(a) = spec.parse::<SocketAddr>() {
        a
    } else if let Ok(ip) = spec.trim_matches(['[', ']']).parse::<IpAddr>() {
        SocketAddr::new(ip, 53)
    } else {
        // Host name: resolve, and use it as the DoT name.
        let (host, port) = match spec.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => {
                (h, p.parse().map_err(|_| format!("bad port in '{s}'"))?)
            }
            _ => (spec, 53),
        };
        let a = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("{host}: {e}"))?
            .min_by_key(|a| a.is_ipv6())
            .ok_or_else(|| format!("{host}: no address"))?;
        return Ok(Resolver {
            label: host.to_string(),
            addr: a,
            tls_name: tls.unwrap_or_else(|| host.to_string()),
        });
    };
    let tls_name = tls
        .or_else(|| known_tls_name(addr.ip()).map(String::from))
        .unwrap_or_else(|| addr.ip().to_string());
    let label = match provider(addr.ip()) {
        Some(p) => format!("{} ({p})", addr.ip()),
        None if addr.port() != 53 => addr.to_string(),
        None => addr.ip().to_string(),
    };
    Ok(Resolver {
        label,
        addr,
        tls_name,
    })
}

/// System resolvers (and systemd-resolved's upstreams) plus public ones.
pub fn default_resolvers() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !v.contains(&s) {
            v.push(s)
        }
    };
    for ip in dns::system_servers() {
        push(ip.to_string());
    }
    for ip in dns::resolved_upstreams() {
        push(ip.to_string());
    }
    for p in ["1.1.1.1", "8.8.8.8", "9.9.9.9"] {
        push(p.to_string());
    }
    v
}

// ---------------------------------------------------------------- transport

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Transport {
    Udp,
    Tcp,
    Dot,
}

impl Transport {
    pub const ALL: [Transport; 3] = [Transport::Udp, Transport::Tcp, Transport::Dot];
    pub fn label(self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
            Transport::Dot => "DoT",
        }
    }
}

#[derive(Debug, PartialEq)]
enum QErr {
    Timeout,
    /// Could not connect / handshake / write.
    Link(String),
}

struct Conn {
    t: Transport,
    resolver: Resolver,
    timeout: Duration,
    udp: Option<UdpSocket>,
    dot: Option<StreamOwned<ClientConnection, TcpStream>>,
    /// Last TLS handshake duration (connect + handshake), ms.
    handshake_ms: Option<f32>,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Small xorshift PRNG seeded from the clock (ids and random labels).
fn rand64() -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut x = t
        ^ COUNTER
            .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
            .rotate_left(17)
        ^ (std::process::id() as u64) << 32;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

pub fn random_label(n: usize) -> String {
    let mut out = String::with_capacity(n);
    let mut r = rand64();
    for i in 0..n {
        if i % 12 == 11 {
            r = rand64();
        }
        out.push(b"abcdefghijklmnopqrstuvwxyz0123456789"[(r % 36) as usize] as char);
        r /= 36;
    }
    out
}

fn io_err(e: std::io::Error) -> QErr {
    if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        QErr::Timeout
    } else {
        QErr::Link(e.to_string())
    }
}

fn read_framed(s: &mut impl Read) -> Result<Vec<u8>, QErr> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).map_err(io_err)?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).map_err(io_err)?;
    Ok(buf)
}

fn framed(q: &[u8]) -> Vec<u8> {
    let mut m = (q.len() as u16).to_be_bytes().to_vec();
    m.extend_from_slice(q);
    m
}

impl Conn {
    fn new(t: Transport, resolver: &Resolver, timeout: Duration) -> Conn {
        Conn {
            t,
            resolver: resolver.clone(),
            timeout,
            udp: None,
            dot: None,
            handshake_ms: None,
        }
    }

    fn dot_connect(&mut self) -> Result<(), QErr> {
        let t0 = Instant::now();
        let tcp = TcpStream::connect_timeout(
            &SocketAddr::new(self.resolver.addr.ip(), 853),
            self.timeout,
        )
        .map_err(|e| QErr::Link(format!("port 853: {e}")))?;
        tcp.set_read_timeout(Some(self.timeout)).ok();
        tcp.set_write_timeout(Some(self.timeout)).ok();
        tcp.set_nodelay(true).ok();
        let name = ServerName::try_from(self.resolver.tls_name.clone())
            .map_err(|e| QErr::Link(format!("TLS name: {e}")))?;
        let conn = ClientConnection::new(crate::tls::client_config(), name)
            .map_err(|e| QErr::Link(e.to_string()))?;
        let mut s = StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .map_err(|e| QErr::Link(format!("TLS: {e}")))?;
        }
        self.handshake_ms = Some(t0.elapsed().as_secs_f32() * 1000.0);
        self.dot = Some(s);
        Ok(())
    }

    /// One exchange; returns the raw response and the time it took (ms).
    /// DoT reuses its connection (as real DoT clients do), so the time
    /// excludes the handshake, which is reported separately.
    fn ask(&mut self, q: &[u8]) -> Result<(Vec<u8>, f32), QErr> {
        let id = [q[0], q[1]];
        match self.t {
            Transport::Udp => {
                if self.udp.is_none() {
                    let bind = if self.resolver.addr.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    let s = UdpSocket::bind(bind).map_err(|e| QErr::Link(e.to_string()))?;
                    s.connect(self.resolver.addr)
                        .map_err(|e| QErr::Link(e.to_string()))?;
                    self.udp = Some(s);
                }
                let s = self.udp.as_ref().unwrap();
                let t0 = Instant::now();
                s.send(q).map_err(|e| QErr::Link(e.to_string()))?;
                let mut buf = vec![0u8; 4096];
                loop {
                    let left = self.timeout.saturating_sub(t0.elapsed());
                    if left.is_zero() {
                        return Err(QErr::Timeout);
                    }
                    s.set_read_timeout(Some(left)).ok();
                    match s.recv(&mut buf) {
                        Ok(n) if n >= 12 && buf[..2] == id => {
                            return Ok((buf[..n].to_vec(), t0.elapsed().as_secs_f32() * 1000.0));
                        }
                        Ok(_) => continue, // late answer to an earlier query
                        Err(e) => {
                            let e = io_err(e);
                            // ICMP port unreachable surfaces as a refused recv.
                            return Err(e);
                        }
                    }
                }
            }
            Transport::Tcp => {
                let t0 = Instant::now();
                let mut s = TcpStream::connect_timeout(&self.resolver.addr, self.timeout)
                    .map_err(|e| QErr::Link(format!("TCP connect: {e}")))?;
                s.set_read_timeout(Some(self.timeout)).ok();
                s.set_write_timeout(Some(self.timeout)).ok();
                s.set_nodelay(true).ok();
                s.write_all(&framed(q)).map_err(io_err)?;
                let r = read_framed(&mut s)?;
                Ok((r, t0.elapsed().as_secs_f32() * 1000.0))
            }
            Transport::Dot => {
                for attempt in 0..2 {
                    if self.dot.is_none() {
                        self.dot_connect()?;
                    }
                    let s = self.dot.as_mut().unwrap();
                    let t0 = Instant::now();
                    let r = s
                        .write_all(&framed(q))
                        .map_err(io_err)
                        .and_then(|_| s.flush().map_err(io_err))
                        .and_then(|_| read_framed(s));
                    match r {
                        Ok(r) => return Ok((r, t0.elapsed().as_secs_f32() * 1000.0)),
                        // Server closed an idle connection: reconnect once.
                        Err(QErr::Link(_)) if attempt == 0 => self.dot = None,
                        Err(e) => {
                            self.dot = None;
                            return Err(e);
                        }
                    }
                }
                Err(QErr::Link("connection closed".into()))
            }
        }
    }

    fn query(&mut self, name: &str, qtype: u16, dnssec: bool) -> Result<(Response, f32), QErr> {
        let id = rand64() as u16;
        let q = dns::build_query(id, name, qtype, true, dnssec).map_err(QErr::Link)?;
        let (raw, ms) = self.ask(&q)?;
        let r = dns::parse_response(&raw).map_err(QErr::Link)?;
        Ok((r, ms))
    }
}

/// A query without the EDNS0 OPT record (classic 512-byte UDP limit).
pub fn query_without_edns(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut q = dns::build_query(id, name, qtype, true, false)?;
    q.truncate(q.len() - 11);
    q[10] = 0;
    q[11] = 0;
    Ok(q)
}

// ---------------------------------------------------------------- results

#[derive(Clone, Debug, Default)]
pub struct TransportStats {
    /// Popular (cached) names: Some(ms) or None (timeout / failure).
    pub cached: Vec<Option<f32>>,
    /// Random names under popular domains: the resolver must recurse.
    pub uncached: Vec<Option<f32>>,
    pub timeouts: usize,
    /// SERVFAIL / REFUSED / malformed where an answer was expected.
    pub failures: usize,
    /// Transport not usable (no TCP, no DoT, certificate error…).
    pub error: Option<String>,
    pub handshake_ms: Option<f32>,
    /// What failed ("netflix.com SERVFAIL"), first few.
    pub failed: Vec<String>,
}

pub fn percentile(v: &[f32], p: f32) -> Option<f32> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let i = ((s.len() as f32 * p).ceil() as usize)
        .saturating_sub(1)
        .min(s.len() - 1);
    Some(s[i])
}

impl TransportStats {
    pub fn ok(&self) -> Vec<f32> {
        self.cached
            .iter()
            .chain(&self.uncached)
            .flatten()
            .copied()
            .collect()
    }
    pub fn sent(&self) -> usize {
        self.cached.len() + self.uncached.len()
    }
    pub fn median(&self) -> Option<f32> {
        percentile(&self.ok(), 0.5)
    }
    pub fn median_of(v: &[Option<f32>]) -> Option<f32> {
        percentile(&v.iter().flatten().copied().collect::<Vec<_>>(), 0.5)
    }
    pub fn p95(&self) -> Option<f32> {
        percentile(&self.ok(), 0.95)
    }
    pub fn max(&self) -> Option<f32> {
        self.ok().into_iter().reduce(f32::max)
    }
    /// Share of queries that timed out or failed (0..1).
    pub fn fail_rate(&self) -> f32 {
        let n = self.sent();
        if n == 0 {
            0.0
        } else {
            (self.timeouts + self.failures) as f32 / n as f32
        }
    }
}

#[derive(Clone, Debug)]
pub struct Check {
    pub key: String,
    pub value: String,
    pub level: Level,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub resolver: Resolver,
    pub stats: Vec<(Transport, TransportStats)>,
    pub checks: Vec<Check>,
    /// Sorted A answers for the comparison names.
    pub answers: HashMap<String, Vec<String>>,
    pub done: usize,
    pub total: usize,
    pub finished: bool,
}

impl Report {
    pub fn get(&self, t: Transport) -> Option<&TransportStats> {
        self.stats.iter().find(|(x, _)| *x == t).map(|(_, s)| s)
    }
    /// Lower is better: UDP median inflated by failures.
    pub fn score(&self) -> Option<f32> {
        let s = self.get(Transport::Udp)?;
        Some(s.median()? * (1.0 + 4.0 * s.fail_rate()))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub rounds: usize,
    pub transports: [bool; 3],
    pub checks: bool,
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rounds: 2,
            transports: [true, true, true],
            checks: true,
            timeout: Duration::from_secs(2),
        }
    }
}

pub enum Event {
    Update(usize, Box<Report>),
    Done,
}

pub struct RunHandle {
    pub events: Receiver<Event>,
    stop: Arc<AtomicBool>,
}

impl RunHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for RunHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn run(resolvers: Vec<Resolver>, cfg: Config) -> RunHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        let threads: Vec<_> = resolvers
            .into_iter()
            .enumerate()
            .map(|(i, r)| {
                let tx = tx.clone();
                let flag = flag.clone();
                std::thread::spawn(move || test_resolver(i, r, cfg, &tx, &flag))
            })
            .collect();
        for t in threads {
            let _ = t.join();
        }
        let _ = tx.send(Event::Done);
    });
    RunHandle { events: rx, stop }
}

fn check(r: &mut Report, key: &str, value: impl Into<String>, level: Level) {
    r.checks.push(Check {
        key: key.into(),
        value: value.into(),
        level,
    });
}

fn a_records(r: &Response) -> Vec<String> {
    let mut v: Vec<String> = r
        .answers
        .iter()
        .filter(|a| a.rtype == 1 || a.rtype == 28)
        .map(|a| a.data.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn is_private(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => v.is_private() || v.is_loopback() || v.is_link_local(),
        Ok(IpAddr::V6(v)) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

fn test_resolver(idx: usize, res: Resolver, cfg: Config, tx: &Sender<Event>, stop: &AtomicBool) {
    let enabled: Vec<Transport> = Transport::ALL
        .into_iter()
        .zip(cfg.transports)
        .filter(|(_, on)| *on)
        .map(|(t, _)| t)
        .collect();
    let per = cfg.rounds * POPULAR.len() * 2;
    let mut rep = Report {
        resolver: res.clone(),
        stats: enabled
            .iter()
            .map(|t| (*t, TransportStats::default()))
            .collect(),
        checks: Vec::new(),
        answers: HashMap::new(),
        done: 0,
        total: per * enabled.len() + if cfg.checks { 12 } else { 0 },
        finished: false,
    };
    let send = |rep: &Report| {
        let _ = tx.send(Event::Update(idx, Box::new(rep.clone())));
    };
    send(&rep);
    // Warm the cache so "cached" really is cached.
    {
        let mut c = Conn::new(Transport::Udp, &res, cfg.timeout);
        for n in POPULAR {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let _ = c.query(n, 1, false);
        }
    }
    for (ti, t) in enabled.iter().enumerate() {
        let mut c = Conn::new(*t, &res, cfg.timeout);
        let mut link_errors = 0;
        'rounds: for _ in 0..cfg.rounds {
            for n in POPULAR {
                for uncached in [false, true] {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let name = if uncached {
                        format!(
                            "{}.{}",
                            random_label(12),
                            // cloudflare.com REFUSEs random sub-names on 1.1.1.1.
                            if *n == "cloudflare.com" {
                                "wikimedia.org"
                            } else {
                                n
                            }
                        )
                    } else {
                        n.to_string()
                    };
                    let r = c.query(&name, 1, false);
                    let st = &mut rep.stats[ti].1;
                    let v = match r {
                        Ok((resp, ms)) => {
                            link_errors = 0;
                            let ok = if uncached {
                                resp.rcode == 0 || resp.rcode == 3
                            } else {
                                resp.rcode == 0 && !resp.answers.is_empty()
                            };
                            if ok {
                                Some(ms)
                            } else {
                                st.failures += 1;
                                if st.failed.len() < 6 {
                                    st.failed.push(format!(
                                        "{name} {}",
                                        if resp.rcode == 0 {
                                            "no address".to_string()
                                        } else {
                                            dns::rcode_name(resp.rcode).to_string()
                                        }
                                    ));
                                }
                                None
                            }
                        }
                        Err(QErr::Timeout) => {
                            st.timeouts += 1;
                            if st.failed.len() < 6 {
                                st.failed.push(format!("{name} timeout"));
                            }
                            None
                        }
                        Err(QErr::Link(e)) => {
                            link_errors += 1;
                            st.failures += 1;
                            if link_errors >= 2 && st.ok().is_empty() {
                                st.error = Some(e);
                                st.cached.clear();
                                st.uncached.clear();
                                st.failures = 0;
                                st.timeouts = 0;
                                break 'rounds;
                            }
                            None
                        }
                    };
                    if uncached {
                        st.uncached.push(v);
                    } else {
                        st.cached.push(v);
                    }
                    st.handshake_ms = c.handshake_ms;
                    rep.done += 1;
                    if rep.done.is_multiple_of(5) {
                        send(&rep);
                    }
                }
            }
            // A transport that never answered within a whole round is dead.
            let st = &mut rep.stats[ti].1;
            if st.ok().is_empty() && st.sent() >= POPULAR.len() * 2 {
                st.error = Some(if st.timeouts > 0 {
                    "no answers (timeouts)".into()
                } else {
                    format!(
                        "every query failed ({})",
                        st.failed
                            .first()
                            .and_then(|f| f.rsplit(' ').next())
                            .unwrap_or("error")
                    )
                });
                break;
            }
        }
        rep.done = (ti + 1) * per;
        send(&rep);
    }
    let udp_dead = rep.get(Transport::Udp).is_some_and(|s| s.error.is_some());
    if cfg.checks && !udp_dead {
        run_checks(&mut rep, &cfg, stop);
    } else if udp_dead {
        check(
            &mut rep,
            "Behaviour checks",
            "skipped: the resolver gives no usable answers over UDP",
            Level::Info,
        );
    }
    rep.done = rep.total;
    rep.finished = true;
    send(&rep);
}

fn run_checks(rep: &mut Report, cfg: &Config, stop: &AtomicBool) {
    let res = rep.resolver.clone();
    let mut c = Conn::new(Transport::Udp, &res, cfg.timeout);
    let step = |rep: &mut Report| rep.done += 1;

    // Recursion, EDNS
    match c.query("example.com", 1, false) {
        Ok((r, _)) => {
            if !r.recursion_available {
                check(
                    rep,
                    "Recursion",
                    "RA bit not set: this server may not resolve names for clients",
                    Level::Warn,
                );
            }
            match r.edns_udp_size {
                Some(n) => check(
                    rep,
                    "EDNS0",
                    format!("supported, UDP buffer {n} bytes"),
                    if n >= 512 { Level::Good } else { Level::Warn },
                ),
                None => check(
                    rep,
                    "EDNS0",
                    "not supported (or stripped on the path): large answers need TCP",
                    Level::Warn,
                ),
            }
        }
        Err(e) => {
            check(rep, "Reachability", format!("UDP: {e:?}"), Level::Bad);
            return;
        }
    }
    step(rep);

    // NXDOMAIN rewriting
    if stop.load(Ordering::Relaxed) {
        return;
    }
    let nx = format!("nx-{}-check.com", random_label(20));
    match c.query(&nx, 1, false) {
        Ok((r, _)) if r.rcode == 3 => {
            check(rep, "NXDOMAIN", "answered honestly (NXDOMAIN)", Level::Good)
        }
        Ok((r, _)) if r.rcode == 0 && !a_records(&r).is_empty() => check(
            rep,
            "NXDOMAIN",
            format!(
                "hijacked: a non-existent name resolved to {} (ad / search redirect)",
                a_records(&r).join(", ")
            ),
            Level::Bad,
        ),
        Ok((r, _)) => check(
            rep,
            "NXDOMAIN",
            format!(
                "unexpected {} for a non-existent name",
                dns::rcode_name(r.rcode)
            ),
            Level::Warn,
        ),
        Err(e) => check(rep, "NXDOMAIN", format!("inconclusive: {e:?}"), Level::Info),
    }
    step(rep);

    // DNSSEC
    if stop.load(Ordering::Relaxed) {
        return;
    }
    let signed = c.query("cloudflare.com", 1, true);
    let broken = c.query("dnssec-failed.org", 1, true);
    step(rep);
    step(rep);
    let ad = signed.as_ref().map(|(r, _)| r.authentic).unwrap_or(false);
    let rejects = broken.as_ref().map(|(r, _)| r.rcode == 2).unwrap_or(false);
    let accepts = broken
        .as_ref()
        .map(|(r, _)| r.rcode == 0 && !r.answers.is_empty())
        .unwrap_or(false);
    match (ad, rejects, accepts) {
        (true, true, _) => check(
            rep,
            "DNSSEC",
            "validates: signed answers carry AD, a broken signature gives SERVFAIL",
            Level::Good,
        ),
        (false, true, _) => check(
            rep,
            "DNSSEC",
            "rejects broken signatures but does not set AD on valid ones",
            Level::Info,
        ),
        (true, false, true) => check(
            rep,
            "DNSSEC",
            "sets AD but accepted a deliberately broken signature (dnssec-failed.org)",
            Level::Bad,
        ),
        (false, false, true) => check(
            rep,
            "DNSSEC",
            "not validating: forged answers for signed zones would be accepted",
            Level::Warn,
        ),
        _ => check(
            rep,
            "DNSSEC",
            "inconclusive (test names did not resolve)",
            Level::Info,
        ),
    }

    // TCP support (from the benchmark, or a single probe)
    if stop.load(Ordering::Relaxed) {
        return;
    }
    let tcp = match rep.get(Transport::Tcp) {
        Some(s) => s.error.clone().map(Err).unwrap_or(Ok(())),
        None => Conn::new(Transport::Tcp, &res, cfg.timeout)
            .query("example.com", 1, false)
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
    };
    match tcp {
        Ok(()) => check(rep, "TCP", "supported", Level::Good),
        Err(e) => check(
            rep,
            "TCP",
            format!("not supported ({e}): answers too large for UDP will fail"),
            Level::Bad,
        ),
    }
    step(rep);

    // Truncation without EDNS
    if stop.load(Ordering::Relaxed) {
        return;
    }
    let id = rand64() as u16;
    if let Ok(q) = query_without_edns(id, "google.com", 16) {
        match c
            .ask(&q)
            .map(|(raw, _)| (raw.len(), dns::parse_response(&raw)))
        {
            Ok((_, Ok(r))) if r.truncated => {
                let full = Conn::new(Transport::Tcp, &res, cfg.timeout).ask(&q);
                match full.map(|(raw, _)| dns::parse_response(&raw)) {
                    Ok(Ok(f)) => check(
                        rep,
                        "Truncation",
                        format!(
                            "oversize answer flagged TC; TCP retry returned {} records",
                            f.answers.len()
                        ),
                        Level::Good,
                    ),
                    _ => check(
                        rep,
                        "Truncation",
                        "flags TC but the TCP retry failed: large answers are lost",
                        Level::Bad,
                    ),
                }
            }
            Ok((n, Ok(_))) if n > 512 => check(
                rep,
                "Truncation",
                format!(
                    "sent a {n}-byte UDP answer to a client without EDNS (RFC 1035 limit is 512)"
                ),
                Level::Warn,
            ),
            Ok((_, Ok(_))) => check(rep, "Truncation", "answer fit in 512 bytes", Level::Info),
            Ok((_, Err(e))) => check(
                rep,
                "Truncation",
                format!("malformed reply: {e}"),
                Level::Warn,
            ),
            Err(e) => check(
                rep,
                "Truncation",
                format!("no reply to a large non-EDNS query ({e:?})"),
                Level::Warn,
            ),
        }
    }
    step(rep);

    // Integrity and comparison
    for name in COMPARE {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if let Ok((r, _)) = c.query(name, 1, false) {
            let v = a_records(&r);
            if let Some((_, truth)) = KNOWN.iter().find(|(n, _)| n == name)
                && !v.is_empty()
                && v.iter().any(|ip| !truth.contains(&ip.as_str()))
            {
                check(
                    rep,
                    "Answer integrity",
                    format!(
                        "{name} → {} (expected {}): answers are rewritten",
                        v.join(", "),
                        truth.join(", ")
                    ),
                    Level::Bad,
                );
            }
            rep.answers.insert(name.to_string(), v);
        }
        step(rep);
    }
    if !rep.checks.iter().any(|c| c.key == "Answer integrity")
        && KNOWN
            .iter()
            .any(|(n, _)| rep.answers.get(*n).is_some_and(|v| !v.is_empty()))
    {
        check(
            rep,
            "Answer integrity",
            "well-known records answered correctly",
            Level::Good,
        );
    }

    // Rebinding protection
    if stop.load(Ordering::Relaxed) {
        return;
    }
    match c.query("192.168.1.1.nip.io", 1, false) {
        Ok((r, _)) => {
            let v = a_records(&r);
            if v.iter().any(|ip| is_private(ip)) {
                check(
                    rep,
                    "Rebinding protection",
                    "returns private addresses for public names (no DNS-rebinding filter)",
                    if is_private(&res.addr.ip().to_string()) {
                        Level::Warn
                    } else {
                        Level::Info
                    },
                );
            } else if r.rcode == 2 {
                check(
                    rep,
                    "Rebinding protection",
                    "inconclusive (SERVFAIL)",
                    Level::Info,
                );
            } else {
                check(
                    rep,
                    "Rebinding protection",
                    "private-address answers for public names are filtered",
                    Level::Good,
                );
            }
        }
        Err(e) => check(
            rep,
            "Rebinding protection",
            format!("inconclusive: {e:?}"),
            Level::Info,
        ),
    }
    step(rep);
}

// ---------------------------------------------------------------- summary

/// Resolver indices ordered best first (unusable last).
pub fn ranking(reports: &[Report]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..reports.len()).collect();
    idx.sort_by(|a, b| {
        let (x, y) = (reports[*a].score(), reports[*b].score());
        match (x, y) {
            (Some(x), Some(y)) => x.total_cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    idx
}

pub fn ms(v: Option<f32>) -> String {
    match v {
        Some(v) if v >= 100.0 => format!("{v:.0} ms"),
        Some(v) => format!("{v:.1} ms"),
        None => "-".into(),
    }
}

pub fn findings(reports: &[Report]) -> Vec<Finding> {
    let mut out = Vec::new();
    let rank = ranking(reports);
    for (pos, &i) in rank.iter().enumerate() {
        let r = &reports[i];
        let udp = r.get(Transport::Udp);
        out.push(Finding {
            section: "Ranking (UDP median, failures penalised)".into(),
            key: format!("{}. {}", pos + 1, r.resolver.label),
            value: match (r.score(), udp) {
                (Some(_), Some(s)) => format!(
                    "cached {} · uncached {} · {:.0}% failed",
                    ms(TransportStats::median_of(&s.cached)),
                    ms(TransportStats::median_of(&s.uncached)),
                    s.fail_rate() * 100.0
                ),
                _ => "no usable UDP answers".into(),
            },
            level: if r.score().is_none() {
                Level::Bad
            } else if pos == 0 {
                Level::Good
            } else {
                Level::Info
            },
        });
    }
    // Cross-resolver disagreement on stable names.
    for name in COMPARE {
        let mut votes: HashMap<&Vec<String>, usize> = HashMap::new();
        for r in reports {
            if let Some(v) = r.answers.get(*name).filter(|v| !v.is_empty()) {
                *votes.entry(v).or_default() += 1;
            }
        }
        if votes.len() > 1
            && let Some((major, n)) = votes.iter().max_by_key(|(_, n)| **n)
            && *n >= 2
        {
            for r in reports {
                if let Some(v) = r.answers.get(*name)
                    && !v.is_empty()
                    && v != *major
                {
                    out.push(Finding {
                        section: "Consistency".into(),
                        key: r.resolver.label.clone(),
                        value: format!(
                            "{name} → {} while {n} others say {}",
                            v.join(", "),
                            major.join(", ")
                        ),
                        level: Level::Warn,
                    });
                }
            }
        }
    }
    for r in reports {
        let sec = r.resolver.label.clone();
        for (t, s) in &r.stats {
            if let Some(e) = &s.error {
                let (lvl, why) = match t {
                    Transport::Dot => (Level::Info, "DNS-over-TLS not available"),
                    Transport::Tcp => (Level::Warn, "TCP not available"),
                    Transport::Udp => (Level::Bad, "UDP not answering"),
                };
                out.push(Finding {
                    section: sec.clone(),
                    key: t.label().into(),
                    value: format!("{why}: {e}"),
                    level: lvl,
                });
            } else if s.sent() > 0 {
                let fr = s.fail_rate();
                out.push(Finding {
                    section: sec.clone(),
                    key: t.label().into(),
                    value: format!(
                        "median {} · p95 {} · max {}{} · {:.0}% failed{}",
                        ms(s.median()),
                        ms(s.p95()),
                        ms(s.max()),
                        s.handshake_ms
                            .map(|h| format!(" · TLS handshake {h:.0} ms"))
                            .unwrap_or_default(),
                        fr * 100.0,
                        if s.failed.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", s.failed.join(", "))
                        }
                    ),
                    level: if fr > 0.1 {
                        Level::Bad
                    } else if fr > 0.0 || s.median().unwrap_or(0.0) > 150.0 {
                        Level::Warn
                    } else {
                        Level::Good
                    },
                });
            }
        }
        for c in &r.checks {
            out.push(Finding {
                section: sec.clone(),
                key: c.key.clone(),
                value: c.value.clone(),
                level: c.level,
            });
        }
    }
    out
}

// ---------------------------------------------------------------- CLI

/// `--dnsbench [RESOLVER…] [-n ROUNDS] [--no-dot] [--no-tcp] [--quick]`
pub fn cli(args: &[String]) {
    let mut cfg = Config::default();
    let mut list = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                i += 1;
                cfg.rounds = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .filter(|n| (1..=20).contains(n))
                    .unwrap_or_else(|| {
                        eprintln!("-n: expected 1..20");
                        std::process::exit(2)
                    });
            }
            "--no-dot" => cfg.transports[2] = false,
            "--no-tcp" => cfg.transports[1] = false,
            "--quick" => cfg.checks = false,
            s => list.push(s.to_string()),
        }
        i += 1;
    }
    if list.is_empty() {
        list = default_resolvers();
    }
    let mut resolvers = Vec::new();
    for s in &list {
        match parse_resolver(s) {
            Ok(r) => resolvers.push(r),
            Err(e) => eprintln!("{e}"),
        }
    }
    if resolvers.is_empty() {
        eprintln!("no resolvers to test");
        std::process::exit(1)
    }
    eprintln!(
        "testing {} resolver(s), {} round(s)…",
        resolvers.len(),
        cfg.rounds
    );
    let n = resolvers.len();
    let h = run(resolvers, cfg);
    let mut reports: Vec<Option<Report>> = vec![None; n];
    for ev in h.events.iter() {
        match ev {
            Event::Update(i, r) => reports[i] = Some(*r),
            Event::Done => break,
        }
    }
    let reports: Vec<Report> = reports.into_iter().flatten().collect();
    println!(
        "{:<28} {:>10} {:>10} {:>10} {:>10} {:>10} {:>7}",
        "RESOLVER", "UDP cache", "UDP uncch", "UDP p95", "TCP", "DoT", "FAIL"
    );
    for i in ranking(&reports) {
        let r = &reports[i];
        let col = |t| {
            r.get(t)
                .map(|s: &TransportStats| {
                    if s.error.is_some() {
                        "n/a".into()
                    } else {
                        ms(s.median())
                    }
                })
                .unwrap_or("-".into())
        };
        let udp = r.get(Transport::Udp);
        println!(
            "{:<28} {:>10} {:>10} {:>10} {:>10} {:>10} {:>6.0}%",
            r.resolver.label,
            ms(udp.and_then(|s| TransportStats::median_of(&s.cached))),
            ms(udp.and_then(|s| TransportStats::median_of(&s.uncached))),
            ms(udp.and_then(|s| s.p95())),
            col(Transport::Tcp),
            col(Transport::Dot),
            udp.map(|s| s.fail_rate() * 100.0).unwrap_or(100.0)
        );
    }
    print!("{}", crate::widgets::findings_text(&findings(&reports)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_specs() {
        let r = parse_resolver("1.1.1.1").unwrap();
        assert_eq!(r.addr, "1.1.1.1:53".parse().unwrap());
        assert_eq!(r.tls_name, "cloudflare-dns.com");
        assert_eq!(r.label, "1.1.1.1 (Cloudflare)");
        let r = parse_resolver("192.0.2.1#dns.example").unwrap();
        assert_eq!(r.tls_name, "dns.example");
        let r = parse_resolver("[2001:db8::1]:5353").unwrap();
        assert_eq!(r.addr.port(), 5353);
        assert_eq!(r.tls_name, "2001:db8::1");
        let r = parse_resolver("192.0.2.9").unwrap();
        assert_eq!(r.tls_name, "192.0.2.9");
    }

    #[test]
    fn no_edns_query() {
        let q = query_without_edns(0x4242, "google.com", 16).unwrap();
        assert_eq!(&q[..12], &[0x42, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(q.len(), 12 + 12 + 4);
        assert_eq!(&q[q.len() - 4..], &[0, 16, 0, 1]);
    }

    #[test]
    fn labels_and_percentiles() {
        let a = random_label(20);
        let b = random_label(20);
        assert_eq!(a.len(), 20);
        assert_ne!(a, b);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        let v = [5.0, 1.0, 3.0, 2.0, 4.0];
        assert_eq!(percentile(&v, 0.5), Some(3.0));
        assert_eq!(percentile(&v, 0.95), Some(5.0));
        assert_eq!(percentile(&[], 0.5), None);
    }

    fn report(label: &str, udp: Vec<Option<f32>>, answers: &[(&str, &[&str])]) -> Report {
        Report {
            resolver: Resolver {
                label: label.into(),
                addr: "192.0.2.1:53".parse().unwrap(),
                tls_name: "x".into(),
            },
            stats: vec![(
                Transport::Udp,
                TransportStats {
                    timeouts: udp.iter().filter(|x| x.is_none()).count(),
                    cached: udp,
                    ..Default::default()
                },
            )],
            checks: Vec::new(),
            answers: answers
                .iter()
                .map(|(n, v)| (n.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
            done: 0,
            total: 0,
            finished: true,
        }
    }

    #[test]
    fn ranking_and_consistency() {
        let reps = vec![
            report(
                "slow",
                vec![Some(50.0), Some(60.0)],
                &[("example.com", &["1.2.3.4"])],
            ),
            report(
                "fast",
                vec![Some(10.0), Some(12.0)],
                &[("example.com", &["1.2.3.4"])],
            ),
            report(
                "flaky",
                vec![Some(5.0), None],
                &[("example.com", &["6.6.6.6"])],
            ),
            report("dead", vec![None, None], &[]),
        ];
        let r = ranking(&reps);
        assert_eq!(reps[r[0]].resolver.label, "fast");
        assert_eq!(reps[r[3]].resolver.label, "dead");
        let f = findings(&reps);
        assert!(
            f.iter()
                .any(|f| f.section == "Consistency" && f.key == "flaky")
        );
        assert!(
            !f.iter()
                .any(|f| f.section == "Consistency" && f.key == "fast")
        );
    }

    #[test]
    fn private_ranges() {
        assert!(is_private("192.168.1.1"));
        assert!(is_private("10.0.0.1"));
        assert!(is_private("fd00::1"));
        assert!(!is_private("8.8.8.8"));
    }
}
