//! TCP connect port scanner for arbitrary targets: domain names, IPv4/IPv6
//! addresses and IPv4 ranges, with service banners for open ports.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use futures::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::netinfo;
use crate::probes;

/// Roughly the most common TCP services found on the Internet and LANs.
pub const TOP_PORTS: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 102, 106, 110, 111, 113, 119, 135, 139,
    143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 502, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1110, 1433, 1521, 1720, 1723,
    1755, 1883, 1900, 2000, 2001, 2049, 2121, 2404, 2717, 3000, 3128, 3306, 3389, 3986, 4840, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8883, 8888, 9100, 9999, 10000, 20000, 32768, 44818,
    47808, 49152, 49153, 49154, 49155, 49156, 49157,
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Preset {
    Top,
    WellKnown,
    All,
    Industrial,
}

impl Preset {
    pub const ALL: [Preset; 4] = [
        Preset::Top,
        Preset::WellKnown,
        Preset::Industrial,
        Preset::All,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Preset::Top => "Top ports",
            Preset::WellKnown => "1-1024",
            Preset::Industrial => "Industrial",
            Preset::All => "All 65535",
        }
    }
    pub fn spec(self) -> String {
        match self {
            Preset::Top => "top".into(),
            Preset::WellKnown => "1-1024".into(),
            // Modbus, S7, IEC-104, OPC UA, DNP3, EtherNet/IP, BACnet, FINS, MQTT
            Preset::Industrial => {
                "102,502,1883,2404,4840,8883,9600,20000,44818,47808,1911,789,18245".into()
            }
            Preset::All => "1-65535".into(),
        }
    }
}

/// Parse "22,80,443", "1-1024", "top", "top,8000-8100".
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = std::collections::BTreeSet::new();
    for part in spec
        .split([',', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        if part.eq_ignore_ascii_case("top") {
            out.extend(TOP_PORTS);
        } else if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().map_err(|_| format!("bad port '{a}'"))?;
            let b: u16 = b.trim().parse().map_err(|_| format!("bad port '{b}'"))?;
            if a == 0 || b < a {
                return Err(format!("bad range '{part}'"));
            }
            out.extend(a..=b);
        } else {
            let p: u16 = part.parse().map_err(|_| format!("bad port '{part}'"))?;
            if p == 0 {
                return Err("port 0 is not valid".into());
            }
            out.insert(p);
        }
    }
    if out.is_empty() {
        return Err("no ports given".into());
    }
    Ok(out.into_iter().collect())
}

#[derive(Clone, Debug)]
pub struct Target {
    /// What the user typed for this target (domain or address).
    pub name: String,
    pub ip: IpAddr,
}

/// Split "example.com, 10.0.0.1 10.0.0.0/30" into named targets, resolving
/// domain names (all their addresses, IPv4 first). Blocking (DNS).
pub fn resolve_targets(input: &str) -> Result<Vec<Target>, String> {
    let mut out = Vec::new();
    for item in input
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let item = item
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        if let Ok(ip) = item.trim_matches(['[', ']']).parse::<IpAddr>() {
            out.push(Target {
                name: item.to_string(),
                ip,
            });
        } else if item.contains('/')
            || (item.contains('-') && item.chars().next().is_some_and(|c| c.is_ascii_digit()))
        {
            for ip in netinfo::parse_range(item)? {
                out.push(Target {
                    name: ip.to_string(),
                    ip: ip.into(),
                });
            }
        } else {
            let mut ips: Vec<IpAddr> = dns_lookup::lookup_host(item)
                .map_err(|e| format!("cannot resolve '{item}': {e}"))?
                .collect();
            ips.sort_by_key(|ip| ip.is_ipv6());
            ips.dedup();
            if ips.is_empty() {
                return Err(format!("'{item}' has no addresses"));
            }
            // A domain with many A records: scanning the first IPv4 + first
            // IPv6 address is what users usually want.
            let v4 = ips.iter().find(|i| i.is_ipv4()).copied();
            let v6 = ips.iter().find(|i| i.is_ipv6()).copied();
            for ip in v4.into_iter().chain(v6) {
                out.push(Target {
                    name: item.to_string(),
                    ip,
                });
            }
        }
        if out.len() > 4096 {
            return Err("too many targets (max 4096)".into());
        }
    }
    if out.is_empty() {
        return Err("enter a domain name, IP address or range".into());
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct OpenPort {
    pub target: usize,
    pub port: u16,
    pub service: &'static str,
    pub connect_ms: f32,
    pub banner: Option<String>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
}

pub enum PortScanEvent {
    Resolved(Vec<Target>),
    Open(OpenPort),
    /// Banner arrived later than the open-port report.
    Banner {
        target: usize,
        port: u16,
        banner: probes::Banner,
    },
    Progress {
        done: usize,
        total: usize,
        closed: usize,
        filtered: usize,
    },
    Error(String),
    Finished {
        elapsed: Duration,
        cancelled: bool,
    },
}

#[derive(Clone, Debug)]
pub struct PortScanConfig {
    pub targets: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub banners: bool,
}

pub struct PortScanHandle {
    pub events: Receiver<PortScanEvent>,
    cancel: Arc<AtomicBool>,
}

impl PortScanHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for PortScanHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub fn start(cfg: PortScanConfig) -> PortScanHandle {
    let (tx, rx) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    std::thread::Builder::new()
        .name("portscan".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(run(cfg, tx, flag));
            rt.shutdown_background();
        })
        .expect("spawn portscan thread");
    PortScanHandle { events: rx, cancel }
}

async fn run(cfg: PortScanConfig, tx: Sender<PortScanEvent>, cancel: Arc<AtomicBool>) {
    let started = Instant::now();
    let input = cfg.targets.clone();
    let targets = match tokio::task::spawn_blocking(move || resolve_targets(&input)).await {
        Ok(Ok(t)) => t,
        other => {
            let msg = match other {
                Ok(Err(e)) => e,
                _ => "resolver failed".into(),
            };
            let _ = tx.send(PortScanEvent::Error(msg));
            let _ = tx.send(PortScanEvent::Finished {
                elapsed: started.elapsed(),
                cancelled: false,
            });
            return;
        }
    };
    let _ = tx.send(PortScanEvent::Resolved(targets.clone()));
    let total = targets.len() * cfg.ports.len();
    let sockets = Arc::new(Semaphore::new(cfg.concurrency.clamp(16, 1024)));
    let done = AtomicUsize::new(0);
    let closed = AtomicUsize::new(0);
    let filtered = AtomicUsize::new(0);
    let last_progress = std::sync::Mutex::new(Instant::now());
    let banner_jobs = std::sync::Mutex::new(Vec::new());

    let jobs = targets
        .iter()
        .enumerate()
        .flat_map(|(ti, t)| cfg.ports.iter().map(move |&p| (ti, t.ip, p)));
    let work = futures::stream::iter(jobs).for_each_concurrent(
        cfg.concurrency.clamp(16, 1024),
        |(ti, ip, port)| {
            let sockets = sockets.clone();
            let tx = tx.clone();
            let cancel = cancel.clone();
            let (done, closed, filtered, last_progress, banner_jobs) =
                (&done, &closed, &filtered, &last_progress, &banner_jobs);
            let wait = cfg.timeout;
            async move {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let _permit = sockets.acquire().await;
                let t = Instant::now();
                match timeout(wait, TcpStream::connect(SocketAddr::new(ip, port))).await {
                    Ok(Ok(_)) => {
                        let _ = tx.send(PortScanEvent::Open(OpenPort {
                            target: ti,
                            port,
                            service: netinfo::service_name(port),
                            connect_ms: t.elapsed().as_secs_f32() * 1000.0,
                            banner: None,
                            http_title: None,
                            http_server: None,
                        }));
                        banner_jobs.lock().unwrap().push((ti, ip, port));
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        closed.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        filtered.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                let mut last = last_progress.lock().unwrap();
                if n == total || last.elapsed() >= Duration::from_millis(100) {
                    *last = Instant::now();
                    let _ = tx.send(PortScanEvent::Progress {
                        done: n,
                        total,
                        closed: closed.load(Ordering::Relaxed),
                        filtered: filtered.load(Ordering::Relaxed),
                    });
                }
            }
        },
    );
    work.await;

    // Banners after the sweep so they don't compete with connect timing.
    let jobs = std::mem::take(&mut *banner_jobs.lock().unwrap());
    if cfg.banners && !cancel.load(Ordering::Relaxed) {
        let names: Vec<String> = targets
            .iter()
            .map(|t| match t.name.parse::<IpAddr>() {
                Ok(IpAddr::V6(v6)) => format!("[{v6}]"),
                _ => t.name.clone(),
            })
            .collect();
        futures::stream::iter(jobs)
            .for_each_concurrent(32, |(ti, ip, port)| {
                let tx = tx.clone();
                let host = names[ti].clone();
                let cancel = cancel.clone();
                async move {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut b = if port == 502 {
                        // Ask a Modbus server who it is instead of sending HTTP.
                        let addr = SocketAddr::new(ip, port);
                        let id = tokio::task::spawn_blocking(move || {
                            crate::modbus::identify(addr, Duration::from_millis(1500))
                        })
                        .await
                        .ok()
                        .flatten();
                        probes::Banner {
                            text: id,
                            ..Default::default()
                        }
                    } else {
                        probes::grab_banner_at(ip, port, &host, netinfo::is_http_port(port)).await
                    };
                    b.text = b.text.map(|t| printable_or_binary(&t));
                    if b.text.is_some() || b.http_title.is_some() {
                        let _ = tx.send(PortScanEvent::Banner {
                            target: ti,
                            port,
                            banner: b,
                        });
                    }
                }
            })
            .await;
    }
    let _ = tx.send(PortScanEvent::Progress {
        done: done.load(Ordering::Relaxed),
        total,
        closed: closed.load(Ordering::Relaxed),
        filtered: filtered.load(Ordering::Relaxed),
    });
    let _ = tx.send(PortScanEvent::Finished {
        elapsed: started.elapsed(),
        cancelled: cancel.load(Ordering::Relaxed),
    });
}

/// Replace undecodable banners (binary protocols answering our probe).
fn printable_or_binary(t: &str) -> String {
    let odd = t
        .chars()
        .filter(|c| {
            *c == '\u{fffd}' || (!c.is_alphanumeric() && !c.is_ascii_punctuation() && *c != ' ')
        })
        .count();
    if t.contains('\u{fffd}') || odd * 4 > t.chars().count() {
        "binary response".into()
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs() {
        assert_eq!(parse_ports("22, 80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-5,3").unwrap(), vec![1, 2, 3, 4, 5]);
        assert_eq!(parse_ports("1-65535").unwrap().len(), 65535);
        assert!(parse_ports("top").unwrap().contains(&502));
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("10-5").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn binary_banners() {
        assert_eq!(
            printable_or_binary("SSH-2.0-OpenSSH_9.6"),
            "SSH-2.0-OpenSSH_9.6"
        );
        assert_eq!(printable_or_binary("GE  H\u{fffd}"), "binary response");
    }

    #[test]
    fn target_parsing() {
        let t = resolve_targets("10.0.0.1, 10.0.0.4-5 ::1").unwrap();
        assert_eq!(t.len(), 4);
        assert!(t[3].ip.is_ipv6());
        let t = resolve_targets("localhost").unwrap();
        assert!(t[0].ip.is_loopback());
        assert!(resolve_targets("  ").is_err());
    }
}
