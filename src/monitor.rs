//! Shared probe engine for the monitoring tools (latency, jitter, packet
//! loss, uptime): one probe = one measured round trip of some kind.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Icmp,
    Tcp,
    Http,
    Dns,
    UdpEcho,
}

impl Kind {
    pub const ALL: [Kind; 5] = [Kind::Icmp, Kind::Tcp, Kind::Http, Kind::Dns, Kind::UdpEcho];
    pub fn label(self) -> &'static str {
        match self {
            Kind::Icmp => "ICMP ping",
            Kind::Tcp => "TCP connect",
            Kind::Http => "HTTP(S)",
            Kind::Dns => "DNS query",
            Kind::UdpEcho => "UDP echo",
        }
    }
    pub fn hint(self) -> &'static str {
        match self {
            Kind::Icmp => "host or IP",
            Kind::Tcp => "host:port",
            Kind::Http => "https://example.com/",
            Kind::Dns => "server, e.g. 1.1.1.1 (queries example.com)",
            Kind::UdpEcho => "host:port of a Throughput Tester server (UDP echo)",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Target {
    pub kind: Kind,
    pub text: String,
}

impl Target {
    pub fn label(&self) -> String {
        format!("{} {}", self.kind.label(), self.text)
    }
}

/// Resolved form of a target, prepared once per series.
#[derive(Clone, Debug)]
enum Prepared {
    Icmp(IpAddr),
    Tcp(SocketAddr),
    Http(String),
    Dns(SocketAddr),
    Udp(SocketAddr),
}

fn host_port(s: &str, default_port: Option<u16>) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse().map_err(|_| format!("bad port in '{s}'"))?)
        }
        _ => (
            s,
            default_port.ok_or_else(|| format!("'{s}': add a :port"))?,
        ),
    };
    std::net::ToSocketAddrs::to_socket_addrs(&(host.trim_matches(['[', ']']), port))
        .map_err(|e| format!("cannot resolve '{host}': {e}"))?
        .next()
        .ok_or_else(|| format!("'{host}' has no address"))
}

fn prepare(t: &Target) -> Result<Prepared, String> {
    let text = t.text.trim();
    if text.is_empty() {
        return Err("empty target".into());
    }
    Ok(match t.kind {
        Kind::Icmp => Prepared::Icmp(crate::traceroute::resolve(text, false)?),
        Kind::Tcp => Prepared::Tcp(host_port(text, None)?),
        Kind::Http => Prepared::Http(if text.contains("://") {
            text.to_string()
        } else {
            format!("https://{text}/")
        }),
        Kind::Dns => Prepared::Dns(host_port(text, Some(53))?),
        Kind::UdpEcho => Prepared::Udp(host_port(text, Some(crate::throughput::DEFAULT_PORT))?),
    })
}

/// One probe. Ok(round trip ms) or Err(reason).
async fn probe(p: &Prepared, seq: u32, wait: Duration) -> Result<f32, String> {
    let t = Instant::now();
    let ms = |t: Instant| t.elapsed().as_secs_f32() * 1000.0;
    match p {
        Prepared::Icmp(ip) => match crate::traceroute::probe(*ip, 64, wait).await {
            crate::traceroute::ProbeResult::Reached(r) => Ok(r),
            _ => Err("no reply".into()),
        },
        Prepared::Tcp(a) => {
            match tokio::time::timeout(wait, tokio::net::TcpStream::connect(a)).await {
                Ok(Ok(_)) => Ok(ms(t)),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    Err("refused".into())
                }
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("timeout".into()),
            }
        }
        Prepared::Http(url) => {
            let out = crate::platform::async_command("curl")
                .args(["-sS", "-o"])
                .arg(if cfg!(windows) { "NUL" } else { "/dev/null" })
                .args(["-w", "%{http_code} %{time_total}", "--max-time"])
                .arg(format!("{:.1}", wait.as_secs_f32().max(1.0)))
                .arg(url)
                .kill_on_drop(true)
                .output()
                .await
                .map_err(|e| format!("curl: {e}"))?;
            let text = String::from_utf8_lossy(&out.stdout);
            let mut it = text.split_whitespace();
            let code: u16 = it.next().and_then(|c| c.parse().ok()).unwrap_or(0);
            let secs: f32 = it.next().and_then(|c| c.parse().ok()).unwrap_or(0.0);
            match code {
                0 => Err(String::from_utf8_lossy(&out.stderr)
                    .trim()
                    .chars()
                    .take(80)
                    .collect()),
                200..=399 => Ok(secs * 1000.0),
                c => Err(format!("HTTP {c}")),
            }
        }
        Prepared::Dns(server) => {
            let server = *server;
            let r = tokio::task::spawn_blocking(move || {
                crate::dns::query(&crate::dns::Query {
                    name: "example.com".into(),
                    qtype: 1,
                    server,
                    tcp: false,
                    timeout: wait,
                    recursion: true,
                    dnssec: false,
                })
            })
            .await
            .map_err(|e| e.to_string())?;
            match r {
                Ok(a) if a.response.rcode == 0 => Ok(a.rtt.as_secs_f32() * 1000.0),
                Ok(a) => Err(crate::dns::rcode_name(a.response.rcode).into()),
                Err(e) => Err(e),
            }
        }
        Prepared::Udp(a) => {
            let bind = if a.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let s = tokio::net::UdpSocket::bind(bind)
                .await
                .map_err(|e| e.to_string())?;
            let mut msg = b"NAPING".to_vec();
            msg.extend_from_slice(&seq.to_be_bytes());
            s.send_to(&msg, a).await.map_err(|e| e.to_string())?;
            let mut buf = [0u8; 64];
            let deadline = t + wait;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(left, s.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) if n >= 10 && buf[..n] == msg[..] => return Ok(ms(t)),
                    Ok(Ok(_)) => continue,
                    Ok(Err(e)) => return Err(e.to_string()),
                    Err(_) => return Err("timeout".into()),
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Sample {
    pub target: usize,
    pub seq: u32,
    pub wall: std::time::SystemTime,
    pub result: Result<f32, String>,
}

pub enum SeriesEvent {
    Error { target: usize, error: String },
    Sample(Sample),
    Done,
}

pub struct SeriesHandle {
    pub events: Receiver<SeriesEvent>,
    stop: Arc<AtomicBool>,
}

impl SeriesHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for SeriesHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Probe every target every `interval`, `count` times (None = until stopped).
pub fn run_series(
    targets: Vec<Target>,
    interval: Duration,
    count: Option<u32>,
    wait: Duration,
) -> SeriesHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::Builder::new()
        .name("monitor".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(series(targets, interval, count, wait, tx.clone(), flag));
            let _ = tx.send(SeriesEvent::Done);
            rt.shutdown_background();
        })
        .expect("spawn monitor thread");
    SeriesHandle { events: rx, stop }
}

async fn series(
    targets: Vec<Target>,
    interval: Duration,
    count: Option<u32>,
    wait: Duration,
    tx: Sender<SeriesEvent>,
    stop: Arc<AtomicBool>,
) {
    let prepared: Vec<Option<Prepared>> =
        futures::future::join_all(targets.iter().enumerate().map(|(i, t)| {
            let (t, tx) = (t.clone(), tx.clone());
            async move {
                match tokio::task::spawn_blocking(move || prepare(&t)).await {
                    Ok(Ok(p)) => Some(p),
                    Ok(Err(e)) => {
                        let _ = tx.send(SeriesEvent::Error {
                            target: i,
                            error: e,
                        });
                        None
                    }
                    Err(_) => None,
                }
            }
        }))
        .await;
    // Each target probes on its own schedule so a slow one doesn't delay others.
    let tasks = prepared
        .into_iter()
        .enumerate()
        .filter_map(|(i, p)| p.map(|p| (i, p)))
        .map(|(i, p)| {
            let (tx, stop) = (tx.clone(), stop.clone());
            async move {
                let start = Instant::now();
                let mut seq = 0u32;
                while count.is_none_or(|c| seq < c) && !stop.load(Ordering::Relaxed) {
                    let due = start + interval * seq;
                    if let Some(d) = due.checked_duration_since(Instant::now()) {
                        tokio::time::sleep(d).await;
                    }
                    let wall = std::time::SystemTime::now();
                    let probe_tx = tx.clone();
                    let p = p.clone();
                    let s = seq;
                    // Don't wait for the reply before scheduling the next probe.
                    tokio::spawn(async move {
                        let result = probe(&p, s, wait).await;
                        let _ = probe_tx.send(SeriesEvent::Sample(Sample {
                            target: i,
                            seq: s,
                            wall,
                            result,
                        }));
                    });
                    seq += 1;
                }
                // Let the last probes finish.
                tokio::time::sleep(wait + Duration::from_millis(300)).await;
            }
        });
    futures::future::join_all(tasks).await;
}

// ---------------------------------------------------------------- statistics

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Stats {
    pub sent: usize,
    pub received: usize,
    pub loss_pct: f32,
    pub min: f32,
    pub avg: f32,
    pub max: f32,
    pub p95: f32,
    pub stddev: f32,
    /// RFC 3550 interarrival-style jitter over successive RTTs.
    pub jitter: f32,
    pub max_burst_loss: usize,
    pub loss_bursts: usize,
}

impl Stats {
    /// `samples` in sequence order: Some(rtt) or None (lost).
    pub fn from(samples: &[Option<f32>]) -> Stats {
        let ok: Vec<f32> = samples.iter().flatten().copied().collect();
        let mut s = Stats {
            sent: samples.len(),
            received: ok.len(),
            ..Default::default()
        };
        if s.sent > 0 {
            s.loss_pct = 100.0 * (s.sent - s.received) as f32 / s.sent as f32;
        }
        let mut run = 0;
        for x in samples {
            if x.is_none() {
                run += 1;
                if run == 1 {
                    s.loss_bursts += 1;
                }
                s.max_burst_loss = s.max_burst_loss.max(run);
            } else {
                run = 0;
            }
        }
        if ok.is_empty() {
            return s;
        }
        s.min = ok.iter().copied().fold(f32::MAX, f32::min);
        s.max = ok.iter().copied().fold(0.0, f32::max);
        s.avg = ok.iter().sum::<f32>() / ok.len() as f32;
        s.stddev = (ok.iter().map(|x| (x - s.avg).powi(2)).sum::<f32>() / ok.len() as f32).sqrt();
        let mut sorted = ok.clone();
        sorted.sort_by(|a, b| a.total_cmp(b));
        s.p95 = sorted[((sorted.len() as f32 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(sorted.len() - 1)];
        let mut j = 0.0f32;
        for w in ok.windows(2) {
            j += ((w[1] - w[0]).abs() - j) / 16.0;
        }
        s.jitter = j;
        s
    }

    /// Mean Opinion Score estimate for a voice call over this path
    /// (simplified ITU-T G.107 E-model, one-way delay ≈ RTT/2).
    pub fn mos(&self) -> Option<f32> {
        if self.received == 0 {
            return None;
        }
        let latency = self.avg / 2.0 + 2.0 * self.jitter + 10.0;
        let mut r = if latency < 160.0 {
            93.2 - latency / 40.0
        } else {
            93.2 - (latency - 120.0) / 10.0
        };
        r -= 2.5 * self.loss_pct;
        let r = r.clamp(0.0, 100.0);
        Some((1.0 + 0.035 * r + 0.000007 * r * (r - 60.0) * (100.0 - r)).clamp(1.0, 4.5))
    }
}

pub fn mos_label(m: f32) -> &'static str {
    match m {
        m if m >= 4.3 => "excellent",
        m if m >= 4.0 => "good",
        m if m >= 3.6 => "fair",
        m if m >= 3.1 => "poor",
        _ => "bad",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistics() {
        let s = Stats::from(&[Some(10.0), None, None, Some(20.0), Some(30.0), None]);
        assert_eq!((s.sent, s.received), (6, 3));
        assert!((s.loss_pct - 50.0).abs() < 0.01);
        assert_eq!((s.min, s.avg, s.max), (10.0, 20.0, 30.0));
        assert_eq!(s.max_burst_loss, 2);
        assert_eq!(s.loss_bursts, 2);
        assert!(s.jitter > 0.0);
        let clean = Stats::from(&vec![Some(20.0); 50]);
        assert_eq!(clean.jitter, 0.0);
        assert!(clean.mos().unwrap() > 4.3);
        let bad = Stats::from(&[Some(400.0), None, Some(600.0), None]);
        assert!(bad.mos().unwrap() < 3.0);
        assert_eq!(Stats::from(&[]).sent, 0);
    }

    #[test]
    fn targets() {
        assert_eq!(host_port("127.0.0.1:80", None).unwrap().port(), 80);
        assert_eq!(host_port("[::1]:53", None).unwrap().port(), 53);
        assert_eq!(host_port("localhost", Some(53)).unwrap().port(), 53);
        assert!(host_port("localhost", None).is_err());
    }

    #[test]
    fn tcp_series_against_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || for _c in l.incoming() {});
        let h = run_series(
            vec![Target {
                kind: Kind::Tcp,
                text: format!("127.0.0.1:{port}"),
            }],
            Duration::from_millis(20),
            Some(5),
            Duration::from_millis(500),
        );
        let mut ok = 0;
        while let Ok(ev) = h.events.recv_timeout(Duration::from_secs(5)) {
            match ev {
                SeriesEvent::Sample(s) if s.result.is_ok() => ok += 1,
                SeriesEvent::Done => break,
                _ => {}
            }
        }
        assert_eq!(ok, 5);
    }
}
