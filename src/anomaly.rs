//! Network anomaly detection over captured traffic: heuristics evaluated on
//! 10-second windows.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use crate::capture::Packet;
use crate::gateway::Level;

pub const WINDOW: Duration = Duration::from_secs(10);
const LEARNING: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct Alert {
    pub at: SystemTime,
    pub level: Level,
    pub kind: &'static str,
    pub text: String,
}

#[derive(Default)]
struct WindowCounters {
    packets: u64,
    bytes: u64,
    broadcast: u64,
    arp_by_mac: HashMap<String, u64>,
    icmp_by_src: HashMap<IpAddr, u64>,
    syn_targets: HashMap<IpAddr, HashSet<(IpAddr, u16)>>,
    syn_to: HashMap<(IpAddr, u16), u64>,
    discover_macs: HashSet<String>,
    nxdomain: u64,
    dns_responses: u64,
}

pub struct Detector {
    started: Instant,
    window_start: Instant,
    w: WindowCounters,
    history: VecDeque<u64>,
    known_macs: HashSet<String>,
    ip_mac: HashMap<IpAddr, String>,
    alerted: HashSet<String>,
    pub totals: Totals,
}

#[derive(Clone, Debug, Default)]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
    pub devices: usize,
    pub windows: u64,
    pub last_pps: f64,
    pub last_bps: f64,
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| -(c as f64 / n) * (c as f64 / n).log2())
        .sum()
}

/// Query names that look like data smuggled through DNS.
pub fn looks_like_tunnel(name: &str) -> bool {
    let first = name.split('.').next().unwrap_or("");
    name.len() > 100 || (first.len() >= 40 && entropy(first) > 3.8)
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            window_start: now,
            w: WindowCounters::default(),
            history: VecDeque::new(),
            known_macs: HashSet::new(),
            ip_mac: HashMap::new(),
            alerted: HashSet::new(),
            totals: Totals::default(),
        }
    }

    fn alert(
        &mut self,
        key: String,
        level: Level,
        kind: &'static str,
        text: String,
        out: &mut Vec<Alert>,
    ) {
        if self.alerted.insert(key) {
            out.push(Alert {
                at: SystemTime::now(),
                level,
                kind,
                text,
            });
        }
    }

    pub fn feed(&mut self, p: &Packet, linktype: i32, now: Instant) -> Vec<Alert> {
        let mut out = Vec::new();
        if now.duration_since(self.window_start) >= WINDOW {
            out.extend(self.close_window(now));
        }
        let d = &p.d;
        self.w.packets += 1;
        self.w.bytes += p.len as u64;
        self.totals.packets += 1;
        self.totals.bytes += p.len as u64;
        let learning = now.duration_since(self.started) < LEARNING;

        if let Some(mac) = &d.eth_src {
            let mac = mac.to_uppercase();
            if self.known_macs.insert(mac.clone()) {
                self.totals.devices = self.known_macs.len();
                if !learning && !mac.starts_with("33:33") && !mac.starts_with("01:") {
                    let vendor =
                        crate::netinfo::mac_vendor(&mac).unwrap_or_else(|| "unknown vendor".into());
                    let ip = d.src_ip.map(|i| format!(" at {i}")).unwrap_or_default();
                    self.alert(
                        format!("new-{mac}"),
                        Level::Info,
                        "New device",
                        format!("{mac} ({vendor}){ip} appeared on the network"),
                        &mut out,
                    );
                }
            }
            if let Some(ip) = d.src_ip
                && !ip.is_unspecified()
                && d.proto != "DHCP"
            {
                match self.ip_mac.insert(ip, mac.clone()) {
                    Some(old) if old != mac => self.alert(
                        format!("dup-{ip}-{mac}"),
                        Level::Warn,
                        "Duplicate IP",
                        format!(
                            "{ip} used by {old} and {mac} (IP conflict, failover, or spoofing)"
                        ),
                        &mut out,
                    ),
                    _ => {}
                }
            }
        }
        if d.eth_dst
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff"))
        {
            self.w.broadcast += 1;
        }
        match d.proto.as_str() {
            "ARP" => {
                if let Some(m) = &d.eth_src {
                    *self.w.arp_by_mac.entry(m.clone()).or_default() += 1;
                }
            }
            "ICMP" | "ICMPv6" => {
                if let Some(s) = d.src_ip {
                    *self.w.icmp_by_src.entry(s).or_default() += 1;
                }
            }
            "DHCP" if d.info.contains("Discover") => {
                if let Some(u) = crate::dhcp::udp_payload(linktype, &p.data)
                    && let Some(m) = crate::dhcp::parse(u.payload)
                {
                    self.w.discover_macs.insert(m.chaddr);
                }
            }
            "Telnet" => self.alert(
                format!("clear-telnet-{:?}", d.dst_ip),
                Level::Warn,
                "Clear text",
                format!(
                    "Telnet session {} → {} (credentials visible on the wire)",
                    d.src, d.dst
                ),
                &mut out,
            ),
            "FTP"
                if d.info.to_uppercase().starts_with("PASS")
                    || d.info.to_uppercase().starts_with("USER") =>
            {
                self.alert(
                    format!("clear-ftp-{:?}", d.dst_ip),
                    Level::Warn,
                    "Clear text",
                    format!("FTP login {} → {} in clear text", d.src, d.dst),
                    &mut out,
                )
            }
            "POP3" | "IMAP"
                if d.info.to_uppercase().contains("LOGIN")
                    || d.info.to_uppercase().starts_with("PASS") =>
            {
                self.alert(
                    format!("clear-mail-{:?}", d.dst_ip),
                    Level::Warn,
                    "Clear text",
                    format!("{} login {} → {} without TLS", d.proto, d.src, d.dst),
                    &mut out,
                )
            }
            "HTTP" => {
                let basic = d.layers.iter().flat_map(|l| &l.fields).any(|(k, v)| {
                    k.eq_ignore_ascii_case("authorization") && v.to_lowercase().starts_with("basic")
                });
                if basic {
                    self.alert(
                        format!("basic-{:?}", d.dst_ip),
                        Level::Warn,
                        "Clear text",
                        format!(
                            "HTTP Basic credentials sent {} → {} without TLS",
                            d.src, d.dst
                        ),
                        &mut out,
                    );
                }
            }
            "DNS" | "mDNS" => {
                if d.info.starts_with("Response") {
                    self.w.dns_responses += 1;
                    if d.info.contains("NXDOMAIN") {
                        self.w.nxdomain += 1;
                    }
                }
                if d.info.starts_with("Query")
                    && let Some(name) = d.info.split_whitespace().last()
                    && looks_like_tunnel(name)
                {
                    let domain: String = name
                        .rsplit('.')
                        .take(2)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join(".");
                    self.alert(
                        format!("tunnel-{domain}"),
                        Level::Bad,
                        "DNS tunnelling",
                        format!("{} queries long random-looking names under {domain} (data exfiltration / C2 pattern)", d.src),
                        &mut out,
                    );
                }
            }
            _ => {}
        }
        if let (Some(flags), Some(s), Some(dst), Some(port)) =
            (d.tcp_flags, d.src_ip, d.dst_ip, d.dst_port)
            && flags & 0x12 == 0x02
        {
            self.w.syn_targets.entry(s).or_default().insert((dst, port));
            *self.w.syn_to.entry((dst, port)).or_default() += 1;
        }
        out
    }

    /// Close the window when it has elapsed even without new packets.
    pub fn feed_tick(&mut self, now: Instant) -> Vec<Alert> {
        if now.duration_since(self.window_start) >= WINDOW {
            self.close_window(now)
        } else {
            Vec::new()
        }
    }

    /// Evaluate and reset the window counters.
    pub fn close_window(&mut self, now: Instant) -> Vec<Alert> {
        let mut out = Vec::new();
        let w = std::mem::take(&mut self.w);
        let secs = now.duration_since(self.window_start).as_secs_f64().max(1.0);
        self.window_start = now;
        self.totals.windows += 1;
        self.totals.last_pps = w.packets as f64 / secs;
        self.totals.last_bps = w.bytes as f64 * 8.0 / secs;
        let minute = now.duration_since(self.started).as_secs() / 60;
        for (src, targets) in &w.syn_targets {
            let ports: HashSet<u16> = targets.iter().map(|t| t.1).collect();
            let hosts: HashSet<IpAddr> = targets.iter().map(|t| t.0).collect();
            if ports.len() >= 50 {
                self.alert(
                    format!("pscan-{src}-{minute}"),
                    Level::Bad,
                    "Port scan",
                    format!(
                        "{src} probed {} ports on {} host(s) in 10 s",
                        ports.len(),
                        hosts.len()
                    ),
                    &mut out,
                );
            } else if hosts.len() >= 30 {
                self.alert(
                    format!("sweep-{src}-{minute}"),
                    Level::Warn,
                    "Host sweep",
                    format!("{src} contacted {} hosts in 10 s", hosts.len()),
                    &mut out,
                );
            }
        }
        for ((dst, port), n) in &w.syn_to {
            if *n as f64 / secs > 200.0 {
                self.alert(
                    format!("synflood-{dst}-{port}-{minute}"),
                    Level::Bad,
                    "SYN flood",
                    format!("{n} SYNs to {dst}:{port} in 10 s"),
                    &mut out,
                );
            }
        }
        if w.broadcast as f64 / secs > 300.0 {
            self.alert(
                format!("bcast-{minute}"),
                Level::Bad,
                "Broadcast storm",
                format!(
                    "{:.0} broadcast frames/s (loop or misbehaving device?)",
                    w.broadcast as f64 / secs
                ),
                &mut out,
            );
        }
        for (mac, n) in &w.arp_by_mac {
            if *n as f64 / secs > 20.0 {
                self.alert(
                    format!("arpstorm-{mac}-{minute}"),
                    Level::Warn,
                    "ARP storm",
                    format!("{mac} sent {n} ARP packets in 10 s"),
                    &mut out,
                );
            }
        }
        for (src, n) in &w.icmp_by_src {
            if *n as f64 / secs > 50.0 {
                self.alert(
                    format!("icmp-{src}-{minute}"),
                    Level::Warn,
                    "ICMP flood",
                    format!("{src} sent {n} ICMP packets in 10 s"),
                    &mut out,
                );
            }
        }
        if w.discover_macs.len() >= 20 {
            self.alert(
                format!("starve-{minute}"),
                Level::Bad,
                "DHCP starvation",
                format!(
                    "DHCP DISCOVERs from {} different MACs in 10 s",
                    w.discover_macs.len()
                ),
                &mut out,
            );
        }
        if w.dns_responses >= 20 && w.nxdomain * 2 > w.dns_responses {
            self.alert(
                format!("nx-{minute}"),
                Level::Warn,
                "DNS errors",
                format!(
                    "{} of {} DNS answers were NXDOMAIN (malware DGA or misconfiguration)",
                    w.nxdomain, w.dns_responses
                ),
                &mut out,
            );
        }
        // Spike against the running average of earlier windows.
        if self.history.len() >= 6 {
            let avg = self.history.iter().sum::<u64>() as f64 / self.history.len() as f64;
            if avg > 50_000.0 && w.bytes as f64 > avg * 5.0 {
                self.alert(
                    format!("spike-{minute}"),
                    Level::Warn,
                    "Traffic spike",
                    format!(
                        "{:.1} Mbit/s, {:.0}× the recent average",
                        w.bytes as f64 * 8.0 / secs / 1e6,
                        w.bytes as f64 / avg
                    ),
                    &mut out,
                );
            }
        }
        self.history.push_back(w.bytes);
        if self.history.len() > 30 {
            self.history.pop_front();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::Dissected;

    fn syn(src: &str, dst: &str, port: u16) -> Packet {
        Packet {
            no: 0,
            ts: 0.0,
            len: 60,
            data: Vec::new(),
            d: Dissected {
                proto: "TCP".into(),
                src_ip: src.parse().ok(),
                dst_ip: dst.parse().ok(),
                dst_port: Some(port),
                tcp_flags: Some(0x02),
                eth_src: Some("02:00:00:00:00:01".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Through the capture engine, as the Anomaly Detector receives packets.
    #[test]
    fn clear_text_basic_login() {
        use crate::capture::{CaptureConfig, CaptureEvent, Source, start, write_packets};
        let f = crate::streams::tests::frame(
            true,
            1,
            1,
            0x18,
            b"GET / HTTP/1.1\r\nHost: plc\r\nAuthorization: Basic YTpi\r\n\r\n",
        );
        let p = Packet {
            ts: 1.0,
            len: f.len() as u32,
            linktype: 1,
            data: f,
            ..Default::default()
        };
        let path = std::env::temp_dir().join(format!("na-basic-{}.pcap", std::process::id()));
        write_packets(&path, &[&p]).unwrap();
        let h = start(CaptureConfig {
            source: Source::File(path.clone()),
            filter: String::new(),
            save_to: None,
        });
        let mut d = Detector::new();
        let mut alerts = Vec::new();
        while let Ok(ev) = h.events.recv_timeout(Duration::from_secs(5)) {
            match ev {
                CaptureEvent::Packets(ps) => {
                    for p in &ps {
                        alerts.extend(d.feed(p, 1, Instant::now()));
                    }
                }
                CaptureEvent::Stopped(_) => break,
                _ => {}
            }
        }
        std::fs::remove_file(&path).ok();
        assert!(
            alerts.iter().any(|a| a.text.contains("HTTP Basic")),
            "{alerts:?}"
        );
    }

    #[test]
    fn port_scan_and_tunnel() {
        let mut d = Detector::new();
        let t = Instant::now();
        for port in 1..=80 {
            d.feed(&syn("10.0.0.66", "10.0.0.5", port), 1, t);
        }
        let alerts = d.close_window(t + WINDOW);
        assert!(alerts.iter().any(|a| a.kind == "Port scan"), "{alerts:?}");
        assert!(looks_like_tunnel(
            "a9f3k2q8z7x1m5n0b4v6c2l8p0o9i7u5y3t1r4e2w8.evil.example"
        ));
        assert!(!looks_like_tunnel("www.google.com"));
        assert!(entropy("aaaa") < 0.01);
    }
}
