//! ARP spoofing detection: watches the OS neighbour table (no privileges)
//! and, when capture is allowed, ARP traffic on the wire.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant, SystemTime};

use crate::gateway::Level;

#[derive(Clone, Debug)]
pub struct Alert {
    pub at: SystemTime,
    pub level: Level,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct Binding {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub first: SystemTime,
    pub last: SystemTime,
    pub seen: u64,
    /// Earlier MACs for this IP.
    pub history: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Source {
    Table,
    Request,
    Reply,
    Gratuitous,
}

/// The detection state machine, fed by table polls and captured ARP.
pub struct Watch {
    pub gateway: Option<Ipv4Addr>,
    pub bindings: BTreeMap<Ipv4Addr, Binding>,
    mac_ips: HashMap<String, HashSet<Ipv4Addr>>,
    gratuitous: HashMap<String, Vec<Instant>>,
    asks: HashMap<String, (Instant, HashSet<Ipv4Addr>)>,
    alerted: HashSet<String>,
}

impl Watch {
    pub fn new(gateway: Option<Ipv4Addr>) -> Self {
        Self {
            gateway,
            bindings: BTreeMap::new(),
            mac_ips: HashMap::new(),
            gratuitous: HashMap::new(),
            asks: HashMap::new(),
            alerted: HashSet::new(),
        }
    }

    fn once(&mut self, key: String, level: Level, text: String, out: &mut Vec<Alert>) {
        if self.alerted.insert(key) {
            out.push(Alert {
                at: SystemTime::now(),
                level,
                text,
            });
        }
    }

    /// One observation "ip is at mac". Returns new alerts.
    pub fn observe(&mut self, ip: Ipv4Addr, mac: &str, src: Source, now: Instant) -> Vec<Alert> {
        let mut out = Vec::new();
        let mac = mac.to_uppercase();
        if ip.is_unspecified() || mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF" {
            return out;
        }
        let is_gw = Some(ip) == self.gateway;
        let wall = SystemTime::now();
        match self.bindings.get_mut(&ip) {
            Some(b) if b.mac != mac => {
                let old = std::mem::replace(&mut b.mac, mac.clone());
                if !b.history.contains(&old) {
                    b.history.push(old.clone());
                }
                b.last = wall;
                b.seen += 1;
                let what = if is_gw { "GATEWAY " } else { "" };
                out.push(Alert {
                    at: wall,
                    level: if is_gw { Level::Bad } else { Level::Warn },
                    text: format!(
                        "{what}{ip} changed MAC {old} → {mac} ({}){}",
                        crate::netinfo::mac_vendor(&mac).unwrap_or_else(|| "unknown vendor".into()),
                        if is_gw {
                            " — possible man-in-the-middle (ARP spoofing)"
                        } else {
                            " — IP conflict or spoofing"
                        }
                    ),
                });
            }
            Some(b) => {
                b.last = wall;
                b.seen += 1;
            }
            None => {
                self.bindings.insert(
                    ip,
                    Binding {
                        ip,
                        mac: mac.clone(),
                        first: wall,
                        last: wall,
                        seen: 1,
                        history: Vec::new(),
                    },
                );
            }
        }
        let ips = self.mac_ips.entry(mac.clone()).or_default();
        ips.insert(ip);
        let claims_gw = self.gateway.is_some_and(|g| ips.contains(&g));
        if claims_gw && ips.len() > 1 {
            let others: Vec<String> = ips
                .iter()
                .filter(|i| Some(**i) != self.gateway)
                .map(|i| i.to_string())
                .collect();
            self.once(
                format!("gwshare-{mac}"),
                Level::Bad,
                format!(
                    "MAC {mac} answers for the gateway AND {}: classic ARP-spoofing signature",
                    others.join(", ")
                ),
                &mut out,
            );
        } else if ips.len() >= 5 && src != Source::Table {
            let n = ips.len();
            self.once(
                format!("multi-{mac}-{}", n / 5),
                Level::Warn,
                format!("MAC {mac} claims {n} IP addresses (proxy ARP, a router, or spoofing)"),
                &mut out,
            );
        }
        if src == Source::Gratuitous {
            let v = self.gratuitous.entry(mac.clone()).or_default();
            v.push(now);
            v.retain(|t| now.duration_since(*t) < Duration::from_secs(10));
            let n = v.len();
            if n >= 10 {
                self.once(
                    format!("grat-{mac}-{}", now.elapsed().as_secs() / 60),
                    Level::Warn,
                    format!(
                        "{n} gratuitous ARPs in 10 s from {mac} (ARP poisoning tools send these)"
                    ),
                    &mut out,
                );
            }
        }
        out
    }

    /// An ARP request "who has target? tell sender". Detects ARP scans.
    pub fn request(&mut self, sender_mac: &str, target: Ipv4Addr, now: Instant) -> Vec<Alert> {
        let mut out = Vec::new();
        let e = self
            .asks
            .entry(sender_mac.to_uppercase())
            .or_insert((now, HashSet::new()));
        if now.duration_since(e.0) > Duration::from_secs(10) {
            *e = (now, HashSet::new());
        }
        e.1.insert(target);
        if e.1.len() >= 30 {
            let n = e.1.len();
            self.once(
                format!("scan-{sender_mac}-{}", now.elapsed().as_secs() / 60),
                Level::Info,
                format!("{sender_mac} asked for {n} addresses in 10 s (network scan)"),
                &mut out,
            );
        }
        out
    }
}

pub enum WatchEvent {
    Alert(Alert),
    Bindings(Vec<Binding>),
    CaptureState(Result<String, String>),
}

pub struct WatchHandle {
    pub events: Receiver<WatchEvent>,
    stop: Arc<AtomicBool>,
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn parse_arp(linktype: i32, f: &[u8]) -> Option<(u16, String, Ipv4Addr, Ipv4Addr)> {
    let off = match linktype {
        1 => {
            let mut et = u16::from_be_bytes([*f.get(12)?, *f.get(13)?]);
            let mut o = 14;
            while et == 0x8100 {
                et = u16::from_be_bytes([*f.get(o + 2)?, *f.get(o + 3)?]);
                o += 4;
            }
            (et == 0x0806).then_some(o)?
        }
        113 => (u16::from_be_bytes([*f.get(14)?, *f.get(15)?]) == 0x0806).then_some(16)?,
        _ => return None,
    };
    let a = f.get(off..off + 28)?;
    let op = u16::from_be_bytes([a[6], a[7]]);
    let mac = a[8..14]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Some((
        op,
        mac,
        Ipv4Addr::new(a[14], a[15], a[16], a[17]),
        Ipv4Addr::new(a[24], a[25], a[26], a[27]),
    ))
}

/// Start watching. `device` = pcap device for wire monitoring (optional).
pub fn start(device: Option<String>) -> WatchHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || run(device, &tx, &flag));
    WatchHandle { events: rx, stop }
}

fn run(device: Option<String>, tx: &Sender<WatchEvent>, stop: &AtomicBool) {
    let gw = crate::platform::default_gateway().map(|(_, g)| g);
    let mut w = Watch::new(gw);
    let cap = device.map(|d| {
        crate::capture::start(crate::capture::CaptureConfig {
            source: crate::capture::Source::Live {
                device: d.clone(),
                promisc: true,
            },
            filter: "arp".into(),
            save_to: None,
        })
    });
    let mut linktype = 1;
    let mut last_poll = Instant::now() - Duration::from_secs(10);
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        let mut alerts = Vec::new();
        if now.duration_since(last_poll) >= Duration::from_secs(2) {
            last_poll = now;
            for (ip, mac) in crate::platform::arp_table() {
                alerts.extend(w.observe(ip, &mac, Source::Table, now));
            }
            let _ = tx.send(WatchEvent::Bindings(w.bindings.values().cloned().collect()));
        }
        if let Some(c) = &cap {
            while let Ok(ev) = c.events.try_recv() {
                match ev {
                    crate::capture::CaptureEvent::Started { linktype: lt, desc } => {
                        linktype = lt;
                        let _ = tx.send(WatchEvent::CaptureState(Ok(desc)));
                    }
                    crate::capture::CaptureEvent::Packets(pkts) => {
                        for p in pkts {
                            let Some((op, mac, spa, tpa)) = parse_arp(linktype, &p.data) else {
                                continue;
                            };
                            let src = if spa == tpa {
                                Source::Gratuitous
                            } else if op == 2 {
                                Source::Reply
                            } else {
                                Source::Request
                            };
                            alerts.extend(w.observe(spa, &mac, src, now));
                            if op == 1 && spa != tpa {
                                alerts.extend(w.request(&mac, tpa, now));
                            }
                        }
                    }
                    crate::capture::CaptureEvent::Stopped(Some(e)) => {
                        let hint = crate::capture::permission_hint(&e).unwrap_or_default();
                        let _ = tx.send(WatchEvent::CaptureState(Err(format!("{e} {hint}"))));
                    }
                    _ => {}
                }
            }
        }
        for a in alerts {
            let _ = tx.send(WatchEvent::Alert(a));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gateway_takeover() {
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut w = Watch::new(Some(gw));
        let t = Instant::now();
        assert!(
            w.observe(gw, "aa:aa:aa:aa:aa:01", Source::Table, t)
                .is_empty()
        );
        assert!(
            w.observe(
                Ipv4Addr::new(10, 0, 0, 7),
                "bb:bb:bb:bb:bb:07",
                Source::Table,
                t
            )
            .is_empty()
        );
        // Attacker's MAC now claims the gateway.
        let a = w.observe(gw, "bb:bb:bb:bb:bb:07", Source::Reply, t);
        assert!(
            a.iter()
                .any(|x| x.level == Level::Bad && x.text.contains("GATEWAY")),
            "{a:?}"
        );
        assert!(
            a.iter().any(|x| x.text.contains("classic ARP-spoofing")),
            "{a:?}"
        );
        assert_eq!(
            w.bindings[&gw].history,
            vec!["AA:AA:AA:AA:AA:01".to_string()]
        );
    }

    #[test]
    fn detects_scans_and_gratuitous_floods() {
        let mut w = Watch::new(None);
        let t = Instant::now();
        let mut alerts = Vec::new();
        for i in 0..40 {
            alerts.extend(w.request("cc:cc:cc:cc:cc:cc", Ipv4Addr::new(10, 0, 0, i), t));
        }
        assert_eq!(alerts.len(), 1);
        let mut g = Vec::new();
        for _ in 0..12 {
            g.extend(w.observe(
                Ipv4Addr::new(10, 0, 0, 9),
                "dd:dd:dd:dd:dd:dd",
                Source::Gratuitous,
                t,
            ));
        }
        assert!(g.iter().any(|a| a.text.contains("gratuitous")));
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[
            2, 0, 0, 0, 0, 1, 8, 6, 0, 1, 8, 0, 6, 4, 0, 2, 2, 0, 0, 0, 0, 1, 10, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 10, 0, 0, 5,
        ]);
        let (op, mac, spa, tpa) = parse_arp(1, &frame).unwrap();
        assert_eq!(
            (op, mac.as_str(), spa, tpa),
            (
                2,
                "02:00:00:00:00:01",
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 5)
            )
        );
    }
}
