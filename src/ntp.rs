//! NTP analyser: an SNTPv4 client (RFC 4330 / RFC 5905) that samples each
//! server several times, picks the lowest-delay sample (as NTP's clock
//! filter does), decodes reference IDs and Kiss-o'-Death codes, discovers
//! the system's configured time servers and judges the local clock.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::gateway::{Finding, Level};

/// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
const NTP_UNIX: f64 = 2_208_988_800.0;

pub const PUBLIC_SERVERS: &[&str] = &["pool.ntp.org", "time.cloudflare.com", "time.google.com"];

#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    /// Local clock error: positive = the local clock is behind the server.
    pub offset_ms: f64,
    /// Round-trip delay minus the server's processing time.
    pub delay_ms: f64,
    pub leap: u8,
    pub version: u8,
    pub stratum: u8,
    pub poll: i8,
    /// log2 seconds.
    pub precision: i8,
    pub root_delay_ms: f64,
    pub root_disp_ms: f64,
    pub refid: String,
    /// Server's reference (last sync) time, Unix seconds.
    pub ref_time: f64,
}

impl Sample {
    pub fn unsynchronised(&self) -> bool {
        self.leap == 3 || self.stratum == 0 || self.stratum >= 16
    }
    /// Root distance: worst-case error vs. the reference clock.
    pub fn root_distance_ms(&self) -> f64 {
        self.root_delay_ms / 2.0 + self.root_disp_ms + self.delay_ms / 2.0
    }
}

pub fn leap_name(l: u8) -> &'static str {
    match l {
        0 => "none",
        1 => "+1 s at end of day",
        2 => "−1 s at end of day",
        _ => "unsynchronised",
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SampleError {
    Timeout,
    /// Kiss-o'-Death code (RATE, DENY, RSTR…).
    Kiss(String),
    Other(String),
}

impl std::fmt::Display for SampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SampleError::Timeout => write!(f, "timeout"),
            SampleError::Kiss(c) => write!(f, "Kiss-o'-Death {c} ({})", kiss_meaning(c)),
            SampleError::Other(e) => write!(f, "{e}"),
        }
    }
}

pub fn kiss_meaning(code: &str) -> &'static str {
    match code {
        "RATE" => "rate exceeded: polling too often",
        "DENY" => "access denied by the server",
        "RSTR" => "access restricted by the server",
        "AUTH" => "authentication failed",
        "CRYP" => "cryptographic authentication failed",
        "NKEY" => "no key found",
        "AUTO" => "autokey sequence failed",
        "BCST" => "broadcast server",
        "MCST" => "multicast server",
        "INIT" => "server not yet synchronised",
        "STEP" => "server clock step change",
        "ACST" => "manycast server",
        "DROP" => "lost peer",
        _ => "unknown code",
    }
}

/// Meaning of a stratum-1 reference identifier.
pub fn refclock_name(code: &str) -> Option<&'static str> {
    Some(match code {
        "GPS" => "GPS",
        "GNSS" => "GNSS satellites",
        "GAL" => "Galileo",
        "GLO" | "GLN" => "GLONASS",
        "BDS" => "BeiDou",
        "PPS" => "pulse-per-second signal",
        "PTP" => "Precision Time Protocol",
        "IRIG" => "IRIG timecode",
        "ATOM" | "CS" | "CESM" => "atomic clock",
        "RBDM" => "rubidium clock",
        "DCF" => "DCF77 radio (Germany)",
        "MSF" => "MSF radio (UK)",
        "WWVB" | "WWV" | "WWVH" => "NIST radio (US)",
        "JJY" => "JJY radio (Japan)",
        "CHU" => "CHU radio (Canada)",
        "NIST" => "NIST modem",
        "ACTS" => "NIST telephone modem",
        "USNO" => "USNO modem",
        "LOCL" | "LCL" => "undisciplined local clock",
        "GOOG" => "Google time",
        "FB" => "Meta time",
        "SHM" => "shared memory driver",
        "NMEA" => "NMEA receiver",
        "XFAC" => "interface changed",
        _ => return None,
    })
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Unix seconds → 64-bit NTP timestamp.
pub fn to_ntp(unix: f64) -> u64 {
    let t = unix + NTP_UNIX;
    let secs = t.floor();
    let frac = ((t - secs) * 4_294_967_296.0) as u64;
    ((secs as u64 & 0xffff_ffff) << 32) | (frac & 0xffff_ffff)
}

/// 64-bit NTP timestamp → Unix seconds. Era 1 (after 2036-02-07) is
/// assumed when the seconds field has its high bit clear.
pub fn from_ntp(ts: u64) -> f64 {
    let secs = (ts >> 32) as f64;
    let frac = (ts & 0xffff_ffff) as f64 / 4_294_967_296.0;
    let era = if ts >> 63 == 0 { 4_294_967_296.0 } else { 0.0 };
    secs + era + frac - NTP_UNIX
}

fn short_ms(v: u32) -> f64 {
    // NTP short format: 16.16 seconds.
    (v >> 16) as f64 * 1000.0 + (v & 0xffff) as f64 / 65536.0 * 1000.0
}

pub fn build_request(transmit: u64) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = 4 << 3 | 3; // LI 0, version 4, mode 3 (client)
    p[40..48].copy_from_slice(&transmit.to_be_bytes());
    p
}

fn refid_text(stratum: u8, id: [u8; 4], ipv6: bool) -> String {
    if stratum <= 1 {
        let s: String = id
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as char)
            .collect();
        if s.chars().all(|c| c.is_ascii_graphic()) && !s.is_empty() {
            return s;
        }
    }
    if ipv6 {
        // IPv6 peers: first four bytes of the MD5 of the address.
        return format!(
            "{:02x}{:02x}{:02x}{:02x} (IPv6 hash)",
            id[0], id[1], id[2], id[3]
        );
    }
    std::net::Ipv4Addr::from(id).to_string()
}

/// Parse a server reply to the request sent at `t1` and received at `t4`
/// (Unix seconds); `ipv6` only affects how the refid is shown.
pub fn parse_reply(
    p: &[u8],
    sent: u64,
    t1: f64,
    t4: f64,
    ipv6: bool,
) -> Result<Sample, SampleError> {
    if p.len() < 48 {
        return Err(SampleError::Other(format!(
            "short reply ({} bytes)",
            p.len()
        )));
    }
    let be32 = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
    let be64 = |i: usize| ((be32(i) as u64) << 32) | be32(i + 4) as u64;
    let leap = p[0] >> 6;
    let version = (p[0] >> 3) & 7;
    let mode = p[0] & 7;
    let stratum = p[1];
    if mode != 4 && mode != 5 {
        return Err(SampleError::Other(format!("unexpected mode {mode}")));
    }
    let id = [p[12], p[13], p[14], p[15]];
    if stratum == 0 {
        let code: String = id
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as char)
            .collect();
        return Err(SampleError::Kiss(code));
    }
    if be64(24) != sent {
        return Err(SampleError::Other(
            "origin timestamp does not match the request (spoofed or stale reply)".into(),
        ));
    }
    let t2 = from_ntp(be64(32));
    let t3 = from_ntp(be64(40));
    if be64(40) == 0 {
        return Err(SampleError::Other(
            "server sent a zero transmit time".into(),
        ));
    }
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = ((t4 - t1) - (t3 - t2)).max(0.0);
    Ok(Sample {
        offset_ms: offset * 1000.0,
        delay_ms: delay * 1000.0,
        leap,
        version,
        stratum,
        poll: p[2] as i8,
        precision: p[3] as i8,
        root_delay_ms: short_ms(be32(4)),
        root_disp_ms: short_ms(be32(8)),
        refid: refid_text(stratum, id, ipv6),
        ref_time: if be64(16) == 0 {
            0.0
        } else {
            from_ntp(be64(16))
        },
    })
}

/// One SNTP exchange.
pub fn query(addr: SocketAddr, timeout: Duration) -> Result<Sample, SampleError> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let s = UdpSocket::bind(bind).map_err(|e| SampleError::Other(e.to_string()))?;
    s.connect(addr)
        .map_err(|e| SampleError::Other(format!("{addr}: {e}")))?;
    s.set_read_timeout(Some(timeout)).ok();
    let t1 = now_unix();
    // Random low bits in the transmit time make the origin check stronger.
    let sent = to_ntp(t1) ^ (std::process::id() as u64 & 0xfff);
    s.send(&build_request(sent))
        .map_err(|e| SampleError::Other(e.to_string()))?;
    let mut buf = [0u8; 512];
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match s.recv(&mut buf) {
            Ok(n) => {
                let t4 = now_unix();
                match parse_reply(&buf[..n], sent, t1, t4, addr.is_ipv6()) {
                    Err(SampleError::Other(e)) if e.starts_with("origin") => {
                        if std::time::Instant::now() >= deadline {
                            return Err(SampleError::Timeout);
                        }
                        continue;
                    }
                    r => return r,
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(SampleError::Timeout);
            }
            Err(e) => return Err(SampleError::Other(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------- per server

#[derive(Clone, Debug)]
pub struct ServerResult {
    /// Name as entered ("pool.ntp.org").
    pub name: String,
    pub addr: SocketAddr,
    pub samples: Vec<Result<Sample, SampleError>>,
    pub expected: usize,
}

impl ServerResult {
    pub fn ok(&self) -> impl Iterator<Item = &Sample> {
        self.samples.iter().filter_map(|s| s.as_ref().ok())
    }

    /// Lowest-delay sample (NTP's clock filter picks this one).
    pub fn best(&self) -> Option<&Sample> {
        self.ok().min_by(|a, b| a.delay_ms.total_cmp(&b.delay_ms))
    }

    /// RMS of offset differences from the best sample (RFC 5905 jitter).
    pub fn jitter_ms(&self) -> Option<f64> {
        let best = self.best()?;
        let others: Vec<f64> = self
            .ok()
            .filter(|s| *s != best)
            .map(|s| (s.offset_ms - best.offset_ms).powi(2))
            .collect();
        if others.is_empty() {
            return None;
        }
        Some((others.iter().sum::<f64>() / others.len() as f64).sqrt())
    }

    pub fn kiss(&self) -> Option<&str> {
        self.samples.iter().find_map(|s| match s {
            Err(SampleError::Kiss(c)) => Some(c.as_str()),
            _ => None,
        })
    }

    pub fn lost(&self) -> usize {
        self.samples
            .iter()
            .filter(|s| matches!(s, Err(SampleError::Timeout)))
            .count()
    }

    pub fn done(&self) -> bool {
        self.samples.len() >= self.expected || self.kiss().is_some()
    }

    /// Short status for tables.
    pub fn status(&self) -> (String, Level) {
        if let Some(k) = self.kiss() {
            return (format!("KoD {k}"), Level::Bad);
        }
        match self.best() {
            None if self.samples.is_empty() => ("…".into(), Level::Info),
            None => (
                self.samples
                    .last()
                    .and_then(|s| s.as_ref().err())
                    .map(|e| e.to_string())
                    .unwrap_or_default(),
                Level::Bad,
            ),
            Some(b) if b.unsynchronised() => ("unsynchronised".into(), Level::Bad),
            Some(_) if self.lost() > 0 => (format!("{} lost", self.lost()), Level::Warn),
            Some(_) => ("ok".into(), Level::Good),
        }
    }
}

pub enum Event {
    /// Name resolved to these addresses (one row each).
    Resolved(String, Result<Vec<SocketAddr>, String>),
    /// (name as entered, address, result)
    Sample(String, SocketAddr, Result<Sample, SampleError>),
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

/// Whether a global IPv6 destination is routable (UDP connect sends nothing).
pub fn ipv6_route() -> bool {
    UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2001:4860:4860::8888]:53"))
        .is_ok()
}

/// "host", "host:123", "1.2.3.4", "[::1]:123" → addresses.
pub fn resolve(name: &str, all: bool) -> Result<Vec<SocketAddr>, String> {
    let n = name.trim();
    if let Ok(a) = n.parse::<SocketAddr>() {
        return Ok(vec![a]);
    }
    if let Ok(ip) = n.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, 123)]);
    }
    let (host, port) = match n.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse().unwrap_or(123))
        }
        _ => (n, 123),
    };
    let mut v: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .collect();
    // IPv4 first; drop IPv6 when this host has no IPv6 route.
    if !ipv6_route() && v.iter().any(|a| a.is_ipv4()) {
        v.retain(|a| a.is_ipv4());
    }
    v.sort_by_key(|a| a.is_ipv6());
    v.dedup();
    if v.is_empty() {
        return Err(format!("{host}: no address"));
    }
    if !all {
        v.truncate(1);
    }
    Ok(v)
}

/// Query every server `samples` times, `gap` apart (≥ 2 s keeps public
/// servers from rate-limiting). With `all_addrs`, each address of a name
/// (pool) is a separate server.
pub fn run(servers: Vec<String>, samples: usize, gap: Duration, all_addrs: bool) -> RunHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        let mut threads = Vec::new();
        for name in servers {
            let tx = tx.clone();
            let flag = flag.clone();
            threads.push(std::thread::spawn(move || {
                let addrs = resolve(&name, all_addrs);
                let _ = tx.send(Event::Resolved(name.clone(), addrs.clone()));
                let Ok(addrs) = addrs else { return };
                let mut inner = Vec::new();
                for addr in addrs {
                    let tx = tx.clone();
                    let flag = flag.clone();
                    let name = name.clone();
                    inner.push(std::thread::spawn(move || {
                        for i in 0..samples {
                            if flag.load(Ordering::Relaxed) {
                                return;
                            }
                            if i > 0 {
                                let end = std::time::Instant::now() + gap;
                                while std::time::Instant::now() < end {
                                    if flag.load(Ordering::Relaxed) {
                                        return;
                                    }
                                    std::thread::sleep(Duration::from_millis(50));
                                }
                            }
                            let r = query(addr, Duration::from_secs(2));
                            let kiss = matches!(r, Err(SampleError::Kiss(_)));
                            let _ = tx.send(Event::Sample(name.clone(), addr, r));
                            if kiss {
                                return; // RFC 5905: stop polling after a KoD
                            }
                        }
                    }));
                }
                for t in inner {
                    let _ = t.join();
                }
            }));
        }
        for t in threads {
            let _ = t.join();
        }
        let _ = tx.send(Event::Done);
    });
    RunHandle { events: rx, stop }
}

// ---------------------------------------------------------------- system servers

fn push_host(out: &mut Vec<(String, String)>, host: &str, source: &str) {
    let h = host
        .trim()
        .trim_end_matches(',')
        .split(',')
        .next()
        .unwrap_or("")
        .trim();
    if h.is_empty() || h.starts_with('#') || out.iter().any(|(x, _)| x.eq_ignore_ascii_case(h)) {
        return;
    }
    out.push((h.to_string(), source.to_string()));
}

/// `server`/`pool` lines of ntp.conf / chrony.conf.
pub fn parse_conf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            let mut w = l.split_whitespace();
            match w.next()? {
                "server" | "pool" | "peer" => w.next().map(String::from),
                _ => None,
            }
        })
        .filter(|h| !h.starts_with("127.") && !h.contains("127.127."))
        .collect()
}

/// Windows `w32tm /query /peers` and NtpServer registry values:
/// "time.windows.com,0x9 pool.example 0x8".
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_w32tm(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines() {
        let l = l.trim();
        let v = l
            .strip_prefix("Peer:")
            .or_else(|| l.split_once("REG_SZ").map(|(_, v)| v));
        if let Some(v) = v {
            for w in v.split_whitespace() {
                let h = w.split(',').next().unwrap_or("");
                if !h.is_empty() && !h.starts_with("0x") && !out.contains(&h.to_string()) {
                    out.push(h.to_string());
                }
            }
        }
    }
    out
}

/// Time servers this machine is configured to use: (host, where found).
pub fn system_servers() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        if let Ok(o) = crate::platform::command("timedatectl")
            .args(["show-timesync", "--all"])
            .output()
        {
            let t = String::from_utf8_lossy(&o.stdout);
            for key in ["ServerName", "SystemNTPServers", "LinkNTPServers"] {
                for l in t.lines() {
                    if let Some(v) = l.strip_prefix(&format!("{key}=")) {
                        for h in v.split_whitespace() {
                            push_host(&mut out, h, "systemd-timesyncd");
                        }
                    }
                }
            }
        }
        if let Ok(o) = crate::platform::command("chronyc")
            .args(["-n", "-c", "sources"])
            .output()
        {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                // CSV: mode,state,address,…
                if let Some(a) = l.split(',').nth(2)
                    && !a.starts_with("127.")
                    && l.starts_with('^')
                {
                    push_host(&mut out, a, "chrony");
                }
            }
        }
        for (path, src) in [
            ("/etc/chrony.conf", "chrony.conf"),
            ("/etc/chrony/chrony.conf", "chrony.conf"),
            ("/etc/ntp.conf", "ntp.conf"),
            ("/etc/ntpsec/ntp.conf", "ntp.conf"),
        ] {
            if let Ok(t) = std::fs::read_to_string(path) {
                for h in parse_conf(&t) {
                    push_host(&mut out, &h, src);
                }
            }
        }
        if let Ok(t) = std::fs::read_to_string("/etc/systemd/timesyncd.conf") {
            for l in t.lines() {
                if let Some(v) = l.trim().strip_prefix("NTP=") {
                    for h in v.split_whitespace() {
                        push_host(&mut out, h, "timesyncd.conf");
                    }
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = crate::platform::command("systemsetup")
            .arg("-getnetworktimeserver")
            .output()
        {
            let t = String::from_utf8_lossy(&o.stdout);
            if let Some((_, v)) = t.split_once("Network Time Server:") {
                push_host(&mut out, v.trim(), "System Settings");
            }
        }
        if let Ok(t) = std::fs::read_to_string("/etc/ntp.conf") {
            for h in parse_conf(&t) {
                push_host(&mut out, &h, "ntp.conf");
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(o) = crate::platform::command("w32tm")
            .args(["/query", "/peers"])
            .output()
        {
            for h in parse_w32tm(&String::from_utf8_lossy(&o.stdout)) {
                push_host(&mut out, &h, "w32tm");
            }
        }
        if let Ok(o) = crate::platform::command("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
                "/v",
                "NtpServer",
            ])
            .output()
        {
            for h in parse_w32tm(&String::from_utf8_lossy(&o.stdout)) {
                push_host(&mut out, &h, "registry");
            }
        }
    }
    out
}

/// System servers followed by the public defaults.
pub fn default_servers() -> Vec<String> {
    let mut v: Vec<String> = system_servers().into_iter().map(|(h, _)| h).collect();
    for p in PUBLIC_SERVERS {
        if !v.iter().any(|x| x.eq_ignore_ascii_case(p)) {
            v.push(p.to_string());
        }
    }
    v
}

// ---------------------------------------------------------------- verdict

pub fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}

pub fn fmt_ms(ms: f64) -> String {
    let a = ms.abs();
    if a >= 60_000.0 {
        format!("{:+.1} min", ms / 60_000.0)
    } else if a >= 1000.0 {
        format!("{:+.3} s", ms / 1000.0)
    } else if a >= 10.0 {
        format!("{ms:+.1} ms")
    } else {
        format!("{ms:+.2} ms")
    }
}

/// Offset estimate from the usable servers: median of best offsets after
/// dropping falsetickers (servers far from the majority).
pub struct Verdict {
    pub offset_ms: Option<f64>,
    pub truechimers: usize,
    pub falsetickers: Vec<SocketAddr>,
}

pub fn verdict(results: &[ServerResult]) -> Verdict {
    let good: Vec<(SocketAddr, f64, f64)> = results
        .iter()
        .filter_map(|r| {
            let b = r.best()?;
            (!b.unsynchronised()).then(|| (r.addr, b.offset_ms, b.root_distance_ms()))
        })
        .collect();
    let mut offs: Vec<f64> = good.iter().map(|g| g.1).collect();
    let Some(med) = median(&mut offs) else {
        return Verdict {
            offset_ms: None,
            truechimers: 0,
            falsetickers: Vec::new(),
        };
    };
    let mut falsetickers = Vec::new();
    let mut keep = Vec::new();
    for (a, off, dist) in &good {
        // Beyond its own error bound plus a 100 ms margin from the majority.
        if good.len() >= 3 && (off - med).abs() > dist + 100.0 {
            falsetickers.push(*a);
        } else {
            keep.push(*off);
        }
    }
    Verdict {
        offset_ms: median(&mut keep),
        truechimers: keep.len(),
        falsetickers,
    }
}

pub fn findings(results: &[ServerResult]) -> Vec<Finding> {
    let mut out = Vec::new();
    let f = |section: &str, key: &str, value: String, level: Level| Finding {
        section: section.into(),
        key: key.into(),
        value,
        level,
    };
    let v = verdict(results);
    match v.offset_ms {
        Some(o) => {
            let a = o.abs();
            let (lvl, txt) = if a < 50.0 {
                (Level::Good, "in sync")
            } else if a < 500.0 {
                (
                    Level::Warn,
                    "drifting: noticeable for logs and time-based auth",
                )
            } else if a < 120_000.0 {
                (
                    Level::Bad,
                    "out of sync: TLS, Kerberos (5 min limit) and logs suffer",
                )
            } else {
                (Level::Bad, "badly wrong: certificates and logins will fail")
            };
            out.push(f(
                "Local clock",
                "Offset",
                format!(
                    "{} ({txt}; {} — positive means this clock is behind)",
                    fmt_ms(o),
                    if o >= 0.0 { "behind" } else { "ahead" }
                ),
                lvl,
            ));
            out.push(f(
                "Local clock",
                "Agreeing servers",
                format!(
                    "{} of {} server addresses agree within their error bounds",
                    v.truechimers,
                    results.len()
                ),
                if v.truechimers >= 3 {
                    Level::Good
                } else {
                    Level::Info
                },
            ));
        }
        None if !results.is_empty() => out.push(f(
            "Local clock",
            "Offset",
            "no synchronised server answered: NTP (UDP 123) may be blocked".into(),
            Level::Bad,
        )),
        None => {}
    }
    for a in &v.falsetickers {
        let r = results.iter().find(|r| r.addr == *a);
        out.push(f(
            "Local clock",
            "Falseticker",
            format!(
                "{} ({a}) disagrees with the others by {}",
                r.map(|r| r.name.as_str()).unwrap_or(""),
                r.and_then(|r| r.best())
                    .map(|b| fmt_ms(b.offset_ms - v.offset_ms.unwrap_or(0.0)))
                    .unwrap_or_default()
            ),
            Level::Bad,
        ));
    }
    for r in results {
        let sec = format!("{} ({})", r.name, r.addr.ip());
        if let Some(k) = r.kiss() {
            out.push(f(
                &sec,
                "Kiss-o'-Death",
                format!("{k}: {}", kiss_meaning(k)),
                Level::Bad,
            ));
            continue;
        }
        let Some(b) = r.best() else {
            if let Some(Err(e)) = r.samples.last() {
                let why = match e {
                    SampleError::Timeout => "no reply (UDP 123 blocked or server down)".into(),
                    e => e.to_string(),
                };
                out.push(f(&sec, "Reachability", why, Level::Bad));
            }
            continue;
        };
        if b.unsynchronised() {
            out.push(f(
                &sec,
                "Synchronisation",
                format!(
                    "server reports itself unsynchronised (leap {}, stratum {})",
                    b.leap, b.stratum
                ),
                Level::Bad,
            ));
        }
        if b.stratum > 4 && b.stratum < 16 {
            out.push(f(
                &sec,
                "Stratum",
                format!("{} — far from a reference clock", b.stratum),
                Level::Warn,
            ));
        }
        if b.root_disp_ms > 1000.0 {
            out.push(f(
                &sec,
                "Root dispersion",
                format!("{:.0} ms — server has not synced recently", b.root_disp_ms),
                Level::Warn,
            ));
        }
        if b.leap == 1 || b.leap == 2 {
            out.push(f(
                &sec,
                "Leap second",
                leap_name(b.leap).into(),
                Level::Info,
            ));
        }
        if r.lost() > 0 {
            out.push(f(
                &sec,
                "Loss",
                format!("{} of {} requests unanswered", r.lost(), r.samples.len()),
                Level::Warn,
            ));
        }
        if let Some(j) = r.jitter_ms()
            && j > 20.0
        {
            out.push(f(
                &sec,
                "Jitter",
                format!("{j:.1} ms — unstable path"),
                Level::Warn,
            ));
        }
        if b.delay_ms > 250.0 {
            out.push(f(
                &sec,
                "Delay",
                format!(
                    "{:.0} ms round trip — offset error up to ±{:.0} ms",
                    b.delay_ms,
                    b.delay_ms / 2.0
                ),
                Level::Warn,
            ));
        }
        if b.version < 3 {
            out.push(f(
                &sec,
                "Version",
                format!("NTPv{}", b.version),
                Level::Info,
            ));
        }
    }
    out
}

// ---------------------------------------------------------------- CLI

pub fn describe_refid(s: &Sample) -> String {
    if s.stratum == 1
        && let Some(n) = refclock_name(&s.refid)
    {
        return format!("{} ({n})", s.refid);
    }
    s.refid.clone()
}

/// `--ntp [SERVER…] [-n SAMPLES] [--all]`
pub fn cli(args: &[String]) {
    let mut servers = Vec::new();
    let mut samples = 4usize;
    let mut all = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                i += 1;
                samples = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .filter(|n| (1..=50).contains(n))
                    .unwrap_or_else(|| {
                        eprintln!("-n: expected 1..50");
                        std::process::exit(2)
                    });
            }
            "--all" => all = true,
            s => servers.push(s.to_string()),
        }
        i += 1;
    }
    if servers.is_empty() {
        let sys = system_servers();
        if !sys.is_empty() {
            println!(
                "system time servers: {}",
                sys.iter()
                    .map(|(h, s)| format!("{h} ({s})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        servers = default_servers();
    }
    let h = run(servers, samples, Duration::from_secs(2), all);
    let mut results: Vec<ServerResult> = Vec::new();
    for ev in h.events.iter() {
        match ev {
            Event::Resolved(name, Ok(addrs)) => {
                for a in addrs {
                    results.push(ServerResult {
                        name: name.clone(),
                        addr: a,
                        samples: Vec::new(),
                        expected: samples,
                    });
                }
            }
            Event::Resolved(name, Err(e)) => eprintln!("{name}: {e}"),
            Event::Sample(n, a, s) => {
                if let Some(r) = results.iter_mut().find(|r| r.addr == a && r.name == n) {
                    r.samples.push(s);
                }
            }
            Event::Done => break,
        }
    }
    println!(
        "{:<26} {:<40} {:>3} {:<18} {:>12} {:>9} {:>8}  STATUS",
        "SERVER", "ADDRESS", "ST", "REFID", "OFFSET", "DELAY", "JITTER"
    );
    for r in &results {
        let (st, _) = r.status();
        match r.best() {
            Some(b) => println!(
                "{:<26} {:<40} {:>3} {:<18} {:>12} {:>7.1}ms {:>8}  {st}",
                r.name,
                r.addr.to_string(),
                b.stratum,
                describe_refid(b),
                fmt_ms(b.offset_ms),
                b.delay_ms,
                r.jitter_ms()
                    .map(|j| format!("{j:.2}ms"))
                    .unwrap_or("-".into()),
            ),
            None => println!(
                "{:<26} {:<40} {:>3} {:<18} {:>12} {:>9} {:>8}  {st}",
                r.name,
                r.addr.to_string(),
                "-",
                "-",
                "-",
                "-",
                "-"
            ),
        }
    }
    print!("{}", crate::widgets::findings_text(&findings(&results)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_roundtrip() {
        let t = 1_790_000_000.25;
        let back = from_ntp(to_ntp(t));
        assert!((back - t).abs() < 1e-6, "{back}");
        // After the 2036 era rollover.
        let t2 = 2_100_000_000.5;
        assert!((from_ntp(to_ntp(t2)) - t2).abs() < 1e-6);
    }

    fn reply(stratum: u8, refid: [u8; 4], origin: u64, t2: f64, t3: f64) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 4 << 3 | 4;
        p[1] = stratum;
        p[2] = 6;
        p[3] = (-24i8) as u8;
        p[4..8].copy_from_slice(&0x0000_8000u32.to_be_bytes()); // 0.5 s → 500 ms
        p[8..12].copy_from_slice(&0x0000_0400u32.to_be_bytes());
        p[12..16].copy_from_slice(&refid);
        p[16..24].copy_from_slice(&to_ntp(t2 - 10.0).to_be_bytes());
        p[24..32].copy_from_slice(&origin.to_be_bytes());
        p[32..40].copy_from_slice(&to_ntp(t2).to_be_bytes());
        p[40..48].copy_from_slice(&to_ntp(t3).to_be_bytes());
        p
    }

    #[test]
    fn offset_and_delay() {
        // Client sends at 1000.000, server (clock 0.1 s ahead) receives at
        // 1000.110 and replies at 1000.111; client receives at 1000.021.
        let t1 = 1_800_000_000.000;
        let sent = to_ntp(t1);
        let p = reply(2, [192, 0, 2, 1], sent, t1 + 0.110, t1 + 0.111);
        let s = parse_reply(&p, sent, t1, t1 + 0.021, false).unwrap();
        assert!((s.offset_ms - 100.0).abs() < 0.01, "{}", s.offset_ms);
        assert!((s.delay_ms - 20.0).abs() < 0.01, "{}", s.delay_ms);
        assert_eq!(s.refid, "192.0.2.1");
        assert_eq!(s.stratum, 2);
        assert_eq!(s.version, 4);
        assert_eq!(s.precision, -24);
        assert!((s.root_delay_ms - 500.0).abs() < 0.01);
        // Wrong origin → rejected.
        assert!(matches!(
            parse_reply(&p, sent + 1, t1, t1 + 0.021, false),
            Err(SampleError::Other(_))
        ));
        let gps = reply(1, *b"GPS\0", sent, t1, t1);
        assert_eq!(parse_reply(&gps, sent, t1, t1, false).unwrap().refid, "GPS");
    }

    #[test]
    fn kiss_of_death() {
        let p = reply(0, *b"RATE", 5, 0.0, 0.0);
        assert_eq!(
            parse_reply(&p, 5, 0.0, 0.0, false),
            Err(SampleError::Kiss("RATE".into()))
        );
        assert!(kiss_meaning("DENY").contains("denied"));
    }

    fn sample(offset: f64, delay: f64) -> Result<Sample, SampleError> {
        Ok(Sample {
            offset_ms: offset,
            delay_ms: delay,
            leap: 0,
            version: 4,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay_ms: 10.0,
            root_disp_ms: 10.0,
            refid: "x".into(),
            ref_time: 0.0,
        })
    }

    #[test]
    fn best_jitter_and_verdict() {
        let mk = |a: &str, s: Vec<Result<Sample, SampleError>>| ServerResult {
            name: a.into(),
            addr: format!("{a}:123").parse().unwrap(),
            expected: s.len(),
            samples: s,
        };
        let r = mk(
            "192.0.2.1",
            vec![
                sample(5.0, 40.0),
                sample(3.0, 20.0),
                Err(SampleError::Timeout),
                sample(7.0, 30.0),
            ],
        );
        assert_eq!(r.best().unwrap().offset_ms, 3.0);
        let j = r.jitter_ms().unwrap();
        assert!((j - ((4.0 + 16.0) / 2.0f64).sqrt()).abs() < 1e-9);
        assert_eq!(r.lost(), 1);
        let all = vec![
            r,
            mk("192.0.2.2", vec![sample(4.0, 10.0)]),
            mk("192.0.2.3", vec![sample(2.0, 10.0)]),
            mk("192.0.2.4", vec![sample(900.0, 10.0)]),
        ];
        let v = verdict(&all);
        assert_eq!(v.falsetickers, vec!["192.0.2.4:123".parse().unwrap()]);
        assert_eq!(v.offset_ms, Some(3.0));
        let f = findings(&all);
        assert!(f.iter().any(|f| f.key == "Falseticker"));
        assert!(
            f.iter()
                .any(|f| f.key == "Offset" && f.level == Level::Good)
        );
    }

    #[test]
    fn config_parsers() {
        let conf = "# comment\nserver 0.pool.ntp.org iburst\npool time.example.org\nserver 127.127.1.0\nrestrict default\n";
        assert_eq!(parse_conf(conf), vec!["0.pool.ntp.org", "time.example.org"]);
        let w = "#Peers: 2\n\nPeer: time.windows.com,0x9\nState: Active\nPeer: 10.0.0.1\n";
        assert_eq!(parse_w32tm(w), vec!["time.windows.com", "10.0.0.1"]);
        let reg = "    NtpServer    REG_SZ    time.windows.com,0x9 pool.ntp.org,0x8\n";
        assert_eq!(parse_w32tm(reg), vec!["time.windows.com", "pool.ntp.org"]);
        assert_eq!(fmt_ms(-1234.0), "-1.234 s");
        assert_eq!(fmt_ms(2.5), "+2.50 ms");
    }
}
