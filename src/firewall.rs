//! Firewall testing: outbound (egress) policy against an any-port host, and
//! open / closed / filtered classification of ports on a chosen target.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

pub const EGRESS_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS/TCP"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (502, "Modbus/TCP"),
    (587, "Submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1194, "OpenVPN"),
    (1433, "MS SQL"),
    (1723, "PPTP"),
    (1883, "MQTT"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (4840, "OPC UA"),
    (5060, "SIP"),
    (5222, "XMPP"),
    (5432, "PostgreSQL"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (8883, "MQTTS"),
    (44818, "EtherNet/IP"),
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PortState {
    /// Connected.
    Open,
    /// RST: something actively rejected (closed port, or a REJECT rule).
    Closed,
    /// No answer: dropped by a firewall (or the host is down).
    Filtered,
}

impl PortState {
    pub fn label(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed (reset)",
            PortState::Filtered => "filtered (no reply)",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Check {
    pub name: String,
    pub state: Result<PortState, String>,
    pub ms: f32,
    pub note: String,
}

pub enum FwEvent {
    Resolved(IpAddr),
    Check(Check),
    Done,
    Error(String),
}

async fn tcp(addr: SocketAddr, wait: Duration) -> (PortState, f32) {
    // Windows retries the SYN after a reset and reports "refused" only after
    // ~2 s; a shorter timeout would turn closed ports into "filtered".
    let wait = if cfg!(windows) {
        wait.max(Duration::from_millis(3000))
    } else {
        wait
    };
    let t = Instant::now();
    let state = match tokio::time::timeout(wait, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        _ => PortState::Filtered,
    };
    (state, t.elapsed().as_secs_f32() * 1000.0)
}

fn ntp(server: &str, wait: Duration) -> Result<f32, String> {
    let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(wait)).ok();
    let mut req = [0u8; 48];
    req[0] = 0x1b; // LI 0, VN 3, client
    let t = Instant::now();
    s.send_to(&req, (server, 123)).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64];
    match s.recv_from(&mut buf) {
        Ok((n, _)) if n >= 48 && buf[0] & 7 == 4 => Ok(t.elapsed().as_secs_f32() * 1000.0),
        Ok(_) => Err("unexpected reply".into()),
        Err(_) => Err("no reply".into()),
    }
}

/// Outbound policy: TCP to every listed port on `host` (which must accept
/// any port), plus UDP DNS, UDP NTP and ICMP.
pub fn egress(host: String, wait: Duration) -> Receiver<FwEvent> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let ip = match crate::traceroute::resolve(&host, false) {
                Ok(ip) => ip,
                Err(e) => {
                    let _ = tx.send(FwEvent::Error(format!("{e} (DNS may itself be blocked)")));
                    let _ = tx.send(FwEvent::Done);
                    return;
                }
            };
            let _ = tx.send(FwEvent::Resolved(ip));
            let checks = EGRESS_PORTS.iter().map(|&(port, name)| {
                let tx = tx.clone();
                async move {
                    let (state, ms) = tcp(SocketAddr::new(ip, port), wait).await;
                    let note = match state {
                        PortState::Open => "allowed".into(),
                        PortState::Closed => "rejected (a firewall or proxy sent a reset)".into(),
                        PortState::Filtered => "blocked (dropped)".into(),
                    };
                    let _ = tx.send(FwEvent::Check(Check {
                        name: format!("TCP {port} {name}"),
                        state: Ok(state),
                        ms,
                        note,
                    }));
                }
            });
            futures::future::join_all(checks).await;
            // UDP DNS to public resolvers (bypassing the local resolver).
            for server in ["1.1.1.1", "8.8.8.8"] {
                let q = crate::dns::Query {
                    name: "example.com".into(),
                    qtype: 1,
                    server: SocketAddr::new(server.parse().unwrap(), 53),
                    tcp: false,
                    timeout: wait,
                    recursion: true,
                    dnssec: false,
                };
                let r = tokio::task::spawn_blocking(move || crate::dns::query(&q))
                    .await
                    .ok();
                let _ = tx.send(FwEvent::Check(match r {
                    Some(Ok(a)) => Check {
                        name: format!("UDP 53 DNS → {server}"),
                        state: Ok(PortState::Open),
                        ms: a.rtt.as_secs_f32() * 1000.0,
                        note: "external DNS allowed".into(),
                    },
                    _ => Check {
                        name: format!("UDP 53 DNS → {server}"),
                        state: Ok(PortState::Filtered),
                        ms: 0.0,
                        note: "external DNS blocked (only the local resolver may be allowed)"
                            .into(),
                    },
                }));
            }
            let n = tokio::task::spawn_blocking(move || ntp("pool.ntp.org", wait))
                .await
                .ok();
            let _ = tx.send(FwEvent::Check(match n {
                Some(Ok(ms)) => Check {
                    name: "UDP 123 NTP → pool.ntp.org".into(),
                    state: Ok(PortState::Open),
                    ms,
                    note: "time sync allowed".into(),
                },
                Some(Err(e)) => Check {
                    name: "UDP 123 NTP → pool.ntp.org".into(),
                    state: Ok(PortState::Filtered),
                    ms: 0.0,
                    note: e,
                },
                None => Check {
                    name: "UDP 123 NTP".into(),
                    state: Err("test failed".into()),
                    ms: 0.0,
                    note: String::new(),
                },
            }));
            let icmp = crate::traceroute::probe("1.1.1.1".parse().unwrap(), 64, wait).await;
            let _ = tx.send(FwEvent::Check(match icmp {
                crate::traceroute::ProbeResult::Reached(ms) => Check {
                    name: "ICMP echo → 1.1.1.1".into(),
                    state: Ok(PortState::Open),
                    ms,
                    note: "ping allowed".into(),
                },
                _ => Check {
                    name: "ICMP echo → 1.1.1.1".into(),
                    state: Ok(PortState::Filtered),
                    ms: 0.0,
                    note: "ping blocked".into(),
                },
            }));
            let _ = tx.send(FwEvent::Done);
        });
        rt.shutdown_background();
    });
    rx
}

/// Classify ports on a target: tells "port closed" from "firewall drops".
pub fn path(target: String, ports: Vec<u16>, wait: Duration) -> Receiver<FwEvent> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let ip = match crate::traceroute::resolve(&target, false) {
                Ok(ip) => ip,
                Err(e) => {
                    let _ = tx.send(FwEvent::Error(e));
                    let _ = tx.send(FwEvent::Done);
                    return;
                }
            };
            let _ = tx.send(FwEvent::Resolved(ip));
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(128));
            let checks = ports.into_iter().map(|port| {
                let (tx, sem) = (tx.clone(), sem.clone());
                async move {
                    let _p = sem.acquire().await;
                    let (state, ms) = tcp(SocketAddr::new(ip, port), wait).await;
                    let svc = crate::netinfo::service_name(port);
                    let _ = tx.send(FwEvent::Check(Check {
                        name: if svc.is_empty() {
                            format!("TCP {port}")
                        } else {
                            format!("TCP {port} {svc}")
                        },
                        state: Ok(state),
                        ms,
                        note: String::new(),
                    }));
                }
            });
            futures::future::join_all(checks).await;
            let icmp = crate::traceroute::probe(ip, 64, wait).await;
            let _ = tx.send(FwEvent::Check(Check {
                name: "ICMP echo".into(),
                state: Ok(
                    if matches!(icmp, crate::traceroute::ProbeResult::Reached(_)) {
                        PortState::Open
                    } else {
                        PortState::Filtered
                    },
                ),
                ms: if let crate::traceroute::ProbeResult::Reached(ms) = icmp {
                    ms
                } else {
                    0.0
                },
                note: String::new(),
            }));
            let _ = tx.send(FwEvent::Done);
        });
        rt.shutdown_background();
    });
    rx
}

/// Plain-language reading of a path test.
pub fn interpret(checks: &[Check]) -> String {
    let count = |s: PortState| {
        checks
            .iter()
            .filter(|c| c.name.starts_with("TCP") && c.state == Ok(s))
            .count()
    };
    let (open, closed, filtered) = (
        count(PortState::Open),
        count(PortState::Closed),
        count(PortState::Filtered),
    );
    let icmp = checks
        .iter()
        .find(|c| c.name.starts_with("ICMP"))
        .map(|c| c.state == Ok(PortState::Open));
    match (open, closed, filtered) {
        (0, 0, f) if f > 0 && icmp == Some(false) => {
            "Nothing answered (no TCP replies, no ping): the host is down, or a firewall silently drops everything.".into()
        }
        (0, 0, _) => "No TCP port answered but the host replies to ping: a stateful firewall drops TCP to these ports.".into(),
        (_, c, f) if f > 0 && c > 0 => format!(
            "{open} open, {c} closed, {f} filtered: the host is reachable; filtered ports are dropped by a firewall while closed ones get a reset."
        ),
        (_, _, f) if f > 0 => format!("{open} open, {f} filtered: a default-deny firewall allows only the open ports."),
        _ => format!("{open} open, {closed} closed: no firewall drops on the tested ports (closed ports send resets)."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpretation() {
        let c = |n: &str, s| Check {
            name: n.into(),
            state: Ok(s),
            ms: 0.0,
            note: String::new(),
        };
        let t = interpret(&[
            c("TCP 80", PortState::Open),
            c("TCP 81", PortState::Filtered),
            c("TCP 82", PortState::Closed),
        ]);
        assert!(t.contains("1 open, 1 closed, 1 filtered"), "{t}");
        let t = interpret(&[
            c("TCP 80", PortState::Filtered),
            c("ICMP echo", PortState::Filtered),
        ]);
        assert!(t.contains("host is down"), "{t}");
    }

    #[test]
    fn local_path_test() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = l.local_addr().unwrap().port();
        let rx = path(
            "127.0.0.1".into(),
            vec![open, 1],
            Duration::from_millis(500),
        );
        let mut states = std::collections::HashMap::new();
        while let Ok(ev) = rx.recv_timeout(Duration::from_secs(5)) {
            match ev {
                FwEvent::Check(c) => {
                    states.insert(c.name, c.state.unwrap());
                }
                FwEvent::Done => break,
                _ => {}
            }
        }
        assert_eq!(
            states.get(&format!("TCP {open}")).copied(),
            Some(PortState::Open)
        );
        assert_eq!(states.get("TCP 1").copied(), Some(PortState::Closed));
    }
}
