//! Traceroute without root: the system `ping` (which holds the raw-socket
//! privilege) is run with an increasing TTL / hop limit. Routers answer
//! "time to live exceeded", the destination answers the echo. All hops of a
//! round are probed in parallel, so a 30-hop trace takes about one timeout.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeResult {
    /// A router at this hop answered.
    Hop(IpAddr, f32),
    /// The destination answered.
    Reached(f32),
    Timeout,
}

#[derive(Clone, Debug, Default)]
pub struct Hop {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub name: Option<String>,
    /// One entry per round: RTT in ms or None (no answer).
    pub rtts: Vec<Option<f32>>,
    pub reached: bool,
    /// The hop ignores direct echoes: `rtts` holds the TTL-probe estimate.
    pub estimated: bool,
}

impl Hop {
    pub fn loss_pct(&self) -> f32 {
        if self.rtts.is_empty() {
            return 0.0;
        }
        100.0 * self.rtts.iter().filter(|r| r.is_none()).count() as f32 / self.rtts.len() as f32
    }
    pub fn stats(&self) -> Option<(f32, f32, f32)> {
        let v: Vec<f32> = self.rtts.iter().flatten().copied().collect();
        if v.is_empty() {
            return None;
        }
        let min = v.iter().copied().fold(f32::MAX, f32::min);
        let max = v.iter().copied().fold(0.0, f32::max);
        Some((min, v.iter().sum::<f32>() / v.len() as f32, max))
    }
}

pub enum TraceEvent {
    Resolved(IpAddr),
    Hop(Hop),
    Finished { reached: bool, elapsed: Duration },
    Error(String),
}

pub struct TraceHandle {
    pub events: Receiver<TraceEvent>,
    cancel: Arc<AtomicBool>,
}

impl TraceHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for TraceHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Clone, Debug)]
pub struct TraceConfig {
    pub target: String,
    pub max_hops: u8,
    pub rounds: u8,
    pub timeout: Duration,
    pub resolve_names: bool,
    /// Prefer IPv6 when the name has both.
    pub ipv6: bool,
}

pub fn resolve(target: &str, ipv6: bool) -> Result<IpAddr, String> {
    let t = target.trim().trim_matches(['[', ']']);
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(t, 0u16))
        .map_err(|e| format!("cannot resolve '{t}': {e}"))?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv6() == ipv6)
        .or(addrs.first())
        .copied()
        .ok_or_else(|| format!("'{t}' has no address"))
}

pub fn start(cfg: TraceConfig) -> TraceHandle {
    let (tx, rx) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    std::thread::Builder::new()
        .name("traceroute".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(run(cfg, tx, flag));
            rt.shutdown_background();
        })
        .expect("spawn traceroute thread");
    TraceHandle { events: rx, cancel }
}

async fn run(cfg: TraceConfig, tx: Sender<TraceEvent>, cancel: Arc<AtomicBool>) {
    let started = Instant::now();
    let target = match tokio::task::spawn_blocking({
        let (t, v6) = (cfg.target.clone(), cfg.ipv6);
        move || resolve(&t, v6)
    })
    .await
    {
        Ok(Ok(ip)) => ip,
        Ok(Err(e)) => {
            let _ = tx.send(TraceEvent::Error(e));
            let _ = tx.send(TraceEvent::Finished {
                reached: false,
                elapsed: started.elapsed(),
            });
            return;
        }
        Err(e) => {
            let _ = tx.send(TraceEvent::Error(e.to_string()));
            return;
        }
    };
    let _ = tx.send(TraceEvent::Resolved(target));
    let max = cfg.max_hops.clamp(1, 64);
    let mut hops: Vec<Hop> = (1..=max)
        .map(|ttl| Hop {
            ttl,
            ..Default::default()
        })
        .collect();
    let mut dest_ttl: Option<u8> = None;
    // Wall-clock RTT of the TTL probe; only used for hops that ignore
    // direct echoes (Linux ping prints no time for "exceeded" replies).
    let mut discovery_rtt: Vec<Option<f32>> = vec![None; max as usize];
    let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(12));

    // 1) Discover the path: TTL-limited probes, unanswered TTLs retried once.
    for attempt in 0..2 {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let todo: Vec<u8> = (1..=dest_ttl.unwrap_or(max))
            .filter(|t| attempt == 0 || hops[*t as usize - 1].addr.is_none())
            .collect();
        let results = futures::future::join_all(todo.into_iter().map(|ttl| {
            let (wait, lim) = (cfg.timeout, limiter.clone());
            async move {
                let _p = lim.acquire().await;
                (ttl, probe(target, ttl, wait).await)
            }
        }))
        .await;
        for (ttl, res) in results {
            let i = ttl as usize - 1;
            match res {
                ProbeResult::Hop(ip, rtt) => {
                    hops[i].addr.get_or_insert(ip);
                    discovery_rtt[i].get_or_insert(rtt);
                }
                ProbeResult::Reached(rtt) => {
                    hops[i].addr = Some(target);
                    hops[i].reached = true;
                    discovery_rtt[i] = Some(rtt);
                    dest_ttl = Some(dest_ttl.map_or(ttl, |d| d.min(ttl)));
                }
                ProbeResult::Timeout => {}
            }
        }
        let shown = dest_ttl.unwrap_or(max) as usize;
        for h in &hops[..shown] {
            let _ = tx.send(TraceEvent::Hop(h.clone()));
        }
    }
    let shown = dest_ttl.unwrap_or(max) as usize;

    // 2) Measure: direct echoes to every discovered hop, `rounds` times.
    for _round in 0..cfg.rounds.max(1) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let results = futures::future::join_all(hops[..shown].iter().map(|h| {
            let (addr, wait, lim) = (h.addr, cfg.timeout, limiter.clone());
            async move {
                let _p = lim.acquire().await;
                match addr {
                    Some(a) => match probe(a, 64, wait).await {
                        ProbeResult::Reached(r) => Some(r),
                        _ => None,
                    },
                    None => None,
                }
            }
        }))
        .await;
        for (h, r) in hops[..shown].iter_mut().zip(results) {
            h.rtts.push(r);
            let _ = tx.send(TraceEvent::Hop(h.clone()));
        }
    }
    // Hops that never answered a direct echo keep their discovery estimate.
    for (h, d) in hops[..shown].iter_mut().zip(&discovery_rtt) {
        if h.addr.is_some() && h.rtts.iter().all(Option::is_none) && d.is_some() {
            h.rtts = vec![*d];
            h.estimated = true;
            let _ = tx.send(TraceEvent::Hop(h.clone()));
        }
    }

    if cfg.resolve_names && !cancel.load(Ordering::Relaxed) {
        let names = futures::future::join_all(hops[..shown].iter().map(|h| async move {
            match h.addr {
                Some(ip) => crate::probes::reverse_dns_any(ip).await,
                None => None,
            }
        }))
        .await;
        for (h, n) in hops.iter_mut().zip(names) {
            if n.is_some() {
                h.name = n;
                let _ = tx.send(TraceEvent::Hop(h.clone()));
            }
        }
    }
    let _ = tx.send(TraceEvent::Finished {
        reached: dest_ttl.is_some(),
        elapsed: started.elapsed(),
    });
}

/// One ICMP echo with the given TTL via the system ping.
pub async fn probe(target: IpAddr, ttl: u8, wait: Duration) -> ProbeResult {
    let ip = target.to_string();
    let ttl_s = ttl.to_string();
    let secs = wait.as_secs().max(1).to_string();
    let ms = wait.as_millis().max(200).to_string();
    let (prog, args): (&str, Vec<&str>) = if cfg!(windows) {
        let mut a = vec!["-n", "1", "-i", &ttl_s, "-w", &ms];
        if target.is_ipv6() {
            a.push("-6");
        }
        a.push(&ip);
        ("ping", a)
    } else if cfg!(target_os = "macos") {
        if target.is_ipv6() {
            ("ping6", vec!["-n", "-c", "1", "-h", &ttl_s, &ip])
        } else {
            (
                "ping",
                vec!["-n", "-c", "1", "-m", &ttl_s, "-t", &secs, &ip],
            )
        }
    } else {
        (
            "ping",
            vec!["-n", "-c", "1", "-t", &ttl_s, "-W", &secs, &ip],
        )
    };
    let t = Instant::now();
    let child = crate::platform::async_command(prog)
        .args(&args)
        .kill_on_drop(true)
        .output();
    let out = match tokio::time::timeout(wait + Duration::from_millis(500), child).await {
        Ok(Ok(o)) => o,
        _ => return ProbeResult::Timeout,
    };
    let wall = t.elapsed().as_secs_f32() * 1000.0;
    parse_probe(&String::from_utf8_lossy(&out.stdout), target, wall)
}

/// Every IPv4/IPv6 address mentioned in a line.
fn addresses(line: &str) -> Vec<IpAddr> {
    line.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|w| w.len() >= 3)
        .filter_map(|w| w.trim_end_matches(':').parse::<IpAddr>().ok())
        .collect()
}

/// Parse ping output (Linux, macOS, Windows in any language). The
/// destination answered if a reply line carries "ttl="; otherwise the first
/// other address in a reply line is the router that sent "exceeded".
pub fn parse_probe(text: &str, target: IpAddr, wall_ms: f32) -> ProbeResult {
    let lines: Vec<&str> = text.lines().collect();
    // Skip the header ("PING x (x)…", "Pinging x with 32 bytes…") and the
    // statistics footer, which both name the target.
    let body = lines.iter().skip(1).take_while(|l| {
        let l = l.trim_start();
        !(l.starts_with("---") || l.to_ascii_lowercase().contains("statistic"))
    });
    for l in body {
        let lower = l.to_ascii_lowercase();
        let ips = addresses(l);
        if lower.contains("ttl=") && ips.contains(&target) {
            let rtt = time_ms(&lower).unwrap_or(wall_ms);
            return ProbeResult::Reached(rtt);
        }
        if let Some(hop) = ips
            .into_iter()
            .find(|ip| *ip != target && !ip.is_unspecified())
        {
            return ProbeResult::Hop(hop, time_ms(&lower).unwrap_or(wall_ms));
        }
    }
    ProbeResult::Timeout
}

fn time_ms(lower: &str) -> Option<f32> {
    for key in ["time=", "time<", "zeit=", "temps=", "tiempo="] {
        if let Some(i) = lower.find(key) {
            let v: String = lower[i + key.len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(x) = v.parse::<f32>() {
                return Some(if key == "time<" { x.min(1.0) } else { x });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> IpAddr {
        "8.8.8.8".parse().unwrap()
    }

    #[test]
    fn linux_output() {
        let exceeded = "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\nFrom 192.168.1.1 icmp_seq=1 Time to live exceeded\n\n--- 8.8.8.8 ping statistics ---\n1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\n";
        assert_eq!(
            parse_probe(exceeded, t(), 3.0),
            ProbeResult::Hop("192.168.1.1".parse().unwrap(), 3.0)
        );
        let reached = "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=9.86 ms\n\n--- 8.8.8.8 ping statistics ---\n";
        assert_eq!(parse_probe(reached, t(), 50.0), ProbeResult::Reached(9.86));
        let none = "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n\n--- 8.8.8.8 ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n";
        assert_eq!(parse_probe(none, t(), 1.0), ProbeResult::Timeout);
    }

    #[test]
    fn windows_and_macos_output() {
        let win = "\r\nPinging 8.8.8.8 with 32 bytes of data:\r\nReply from 10.0.0.1: TTL expired in transit.\r\n\r\nPing statistics for 8.8.8.8:\r\n";
        assert_eq!(
            parse_probe(win, t(), 4.0),
            ProbeResult::Hop("10.0.0.1".parse().unwrap(), 4.0)
        );
        let win_de = "\r\nPing wird ausgeführt für 8.8.8.8 mit 32 Bytes Daten:\r\nAntwort von 8.8.8.8: Bytes=32 Zeit=12ms TTL=117\r\n";
        assert_eq!(parse_probe(win_de, t(), 40.0), ProbeResult::Reached(12.0));
        let mac = "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n36 bytes from 10.0.0.1: Time to live exceeded\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst\n 4  5  00 5400 1234   0 0000  01  01 abcd 10.0.0.5  8.8.8.8\n";
        assert_eq!(
            parse_probe(mac, t(), 2.0),
            ProbeResult::Hop("10.0.0.1".parse().unwrap(), 2.0)
        );
    }

    #[test]
    fn hop_stats() {
        let h = Hop {
            rtts: vec![Some(1.0), None, Some(3.0)],
            ..Default::default()
        };
        assert!((h.loss_pct() - 33.33).abs() < 0.1);
        assert_eq!(h.stats(), Some((1.0, 2.0, 3.0)));
    }
}
