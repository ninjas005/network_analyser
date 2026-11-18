//! Scan engine. Runs on its own thread with a small tokio runtime and
//! streams per-host results back to the UI through a channel.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use futures::StreamExt;
use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::netinfo::{self, LocalIface};
use crate::probes::{self, NetbiosInfo, TcpState, UpnpInfo};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pending,
    Probing,
    Dead,
    /// Alive, still gathering details.
    Enriching,
    Done,
}

#[derive(Clone, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub service: &'static str,
    pub banner: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HostInfo {
    pub ip: Ipv4Addr,
    pub status: Status,
    pub rtt_ms: Option<f32>,
    pub ttl: Option<u8>,
    pub dns_name: Option<String>,
    pub mdns_name: Option<String>,
    pub netbios: Option<NetbiosInfo>,
    pub upnp: Option<UpnpInfo>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub ports: Vec<PortInfo>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub os_guess: Option<String>,
    pub device_type: Option<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    /// How liveness was established (ICMP, TCP, ARP).
    pub seen_by: Vec<&'static str>,
}

impl HostInfo {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            status: Status::Pending,
            rtt_ms: None,
            ttl: None,
            dns_name: None,
            mdns_name: None,
            netbios: None,
            upnp: None,
            mac: None,
            vendor: None,
            ports: Vec::new(),
            http_title: None,
            http_server: None,
            os_guess: None,
            device_type: None,
            is_gateway: false,
            is_self: false,
            seen_by: Vec::new(),
        }
    }

    pub fn is_alive(&self) -> bool {
        matches!(self.status, Status::Enriching | Status::Done)
    }

    /// Best human-readable name from all sources.
    pub fn hostname(&self) -> Option<String> {
        self.dns_name
            .clone()
            .or_else(|| self.mdns_name.clone())
            .or_else(|| self.netbios.as_ref().and_then(|n| n.name.clone()))
            .or_else(|| self.upnp.as_ref().and_then(|u| u.friendly_name.clone()))
    }

    pub fn ports_summary(&self) -> String {
        self.ports
            .iter()
            .map(|p| p.port.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub targets: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
    pub host_concurrency: usize,
    pub connect_timeout: Duration,
    pub local: Option<LocalIface>,
}

pub enum ScanEvent {
    /// Ports that a local proxy/firewall answers for *any* destination.
    /// They are excluded from liveness checks and port results.
    Intercepted(Vec<u16>),
    Host(usize, Box<HostInfo>),
    Finished {
        elapsed: Duration,
        cancelled: bool,
    },
}

pub struct ScanHandle {
    pub events: Receiver<ScanEvent>,
    cancel: Arc<AtomicBool>,
}

impl ScanHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Ports used for the fast liveness check (any answer, even RST, = alive).
const DISCOVERY_PORTS: &[u16] = &[
    22, 53, 80, 135, 139, 443, 445, 554, 3389, 5000, 7000, 8008, 8080, 9100, 62078,
];

pub fn start(cfg: ScanConfig) -> ScanHandle {
    let (tx, rx) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    std::thread::Builder::new()
        .name("scanner".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(16)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(run(cfg, tx, flag));
            // Don't wait for stray blocking DNS lookups.
            rt.shutdown_background();
        })
        .expect("spawn scanner thread");
    ScanHandle { events: rx, cancel }
}

async fn run(cfg: ScanConfig, tx: Sender<ScanEvent>, cancel: Arc<AtomicBool>) {
    let started = Instant::now();
    let intercepted = detect_interception(&cfg.ports, cfg.connect_timeout).await;
    if !intercepted.is_empty() {
        let _ = tx.send(ScanEvent::Intercepted(
            intercepted.iter().copied().collect(),
        ));
    }
    let ctx = Arc::new(Ctx {
        intercepted,
        // Keep well below the default 1024 fd soft limit.
        sockets: Semaphore::new(384),
        gateway: netinfo::default_gateway().map(|(_, gw)| gw),
        local: cfg.local.clone(),
        ports: cfg.ports.clone(),
        connect_timeout: cfg.connect_timeout,
        tx: tx.clone(),
    });
    let work = futures::stream::iter(cfg.targets.iter().copied().enumerate()).for_each_concurrent(
        cfg.host_concurrency,
        |(idx, ip)| {
            let ctx = ctx.clone();
            async move { scan_host(idx, ip, &ctx).await }
        },
    );
    let watch = async {
        while !cancel.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let cancelled = tokio::select! {
        _ = work => false,
        _ = watch => true,
    };
    let _ = tx.send(ScanEvent::Finished {
        elapsed: started.elapsed(),
        cancelled,
    });
}

struct Ctx {
    intercepted: BTreeSet<u16>,
    sockets: Semaphore,
    gateway: Option<Ipv4Addr>,
    local: Option<LocalIface>,
    ports: Vec<u16>,
    connect_timeout: Duration,
    tx: Sender<ScanEvent>,
}

impl Ctx {
    fn send(&self, idx: usize, h: &HostInfo) {
        let _ = self.tx.send(ScanEvent::Host(idx, Box::new(h.clone())));
    }

    async fn probe(&self, ip: Ipv4Addr, port: u16) -> TcpState {
        if self.intercepted.contains(&port) {
            return TcpState::Filtered;
        }
        let _permit = self.sockets.acquire().await;
        probes::tcp_probe(ip, port, self.connect_timeout).await
    }
}

/// Connect to reserved, never-routed TEST-NET addresses (RFC 5737). Any
/// port that "opens" there is being answered by a transparent proxy or
/// security agent on this machine/network, not by the real target.
async fn detect_interception(ports: &[u16], wait: Duration) -> BTreeSet<u16> {
    let mut all: Vec<u16> = ports.iter().chain(DISCOVERY_PORTS).copied().collect();
    all.sort_unstable();
    all.dedup();
    let probes = ["192.0.2.1", "198.51.100.77"].into_iter().flat_map(|a| {
        let ip: Ipv4Addr = a.parse().unwrap();
        all.iter().map(move |&p| async move {
            match probes::tcp_probe(ip, p, wait).await {
                TcpState::Open => Some(p),
                _ => None,
            }
        })
    });
    join_all(probes).await.into_iter().flatten().collect()
}

async fn scan_host(idx: usize, ip: Ipv4Addr, ctx: &Ctx) {
    let mut h = HostInfo::new(ip);
    h.status = Status::Probing;
    h.is_gateway = ctx.gateway == Some(ip);
    h.is_self = ctx.local.as_ref().is_some_and(|l| l.ip == ip);
    ctx.send(idx, &h);

    // ---- phase 1: liveness (ICMP + TCP in parallel, then ARP)
    let ping = probes::ping(ip, Duration::from_secs(1));
    let tcp = join_all(
        DISCOVERY_PORTS
            .iter()
            .map(|&p| async move { (p, ctx.probe(ip, p).await) }),
    );
    let (ping, tcp) = futures::join!(ping, tcp);

    let mut open: BTreeSet<u16> = BTreeSet::new();
    let mut tcp_answer = false;
    for (port, st) in tcp {
        match st {
            TcpState::Open => {
                open.insert(port);
                tcp_answer = true;
            }
            TcpState::Closed => tcp_answer = true,
            TcpState::Filtered => {}
        }
    }
    if let Some(p) = &ping {
        h.rtt_ms = Some(p.rtt_ms);
        h.ttl = p.ttl;
        h.seen_by.push("ICMP");
    }
    if tcp_answer {
        h.seen_by.push("TCP");
    }
    // Our probes made the kernel ARP for the address; a firewalled host on
    // the local segment still has to answer ARP.
    let arp = netinfo::arp_table();
    if let Some(mac) = arp.get(&ip) {
        h.mac = Some(mac.clone());
        h.seen_by.push("ARP");
    }
    if h.is_self {
        h.mac = ctx.local.as_ref().and_then(|l| l.mac.clone());
        h.seen_by.push("local");
    }
    if h.seen_by.is_empty() {
        h.status = Status::Dead;
        ctx.send(idx, &h);
        return;
    }
    h.vendor = h.mac.as_deref().and_then(netinfo::mac_vendor);
    h.status = Status::Enriching;
    set_ports(&mut h, &open);
    ctx.send(idx, &h);

    // ---- phase 2: names + remaining ports, concurrently
    let rest: Vec<u16> = ctx
        .ports
        .iter()
        .copied()
        .filter(|p| !DISCOVERY_PORTS.contains(p))
        .collect();
    let port_scan = join_all(
        rest.iter()
            .map(|&p| async move { (p, ctx.probe(ip, p).await) }),
    );
    let (dns, mdns, nb, upnp, more) = futures::join!(
        probes::reverse_dns(ip),
        probes::mdns_name(ip),
        probes::netbios(ip),
        probes::upnp(ip),
        port_scan
    );
    open.extend(
        more.into_iter()
            .filter(|(_, s)| matches!(s, TcpState::Open))
            .map(|(p, _)| p),
    );
    h.dns_name = dns;
    h.mdns_name = mdns.map(|n| n.trim_end_matches('.').to_string());
    if h.mac.is_none() {
        h.mac = nb.as_ref().and_then(|n| n.mac.clone());
        h.vendor = h.mac.as_deref().and_then(netinfo::mac_vendor);
    }
    h.netbios = nb;
    h.upnp = upnp;
    if h.is_self && h.dns_name.is_none() {
        h.dns_name = dns_lookup::get_hostname().ok();
    }
    set_ports(&mut h, &open);
    ctx.send(idx, &h);

    // ---- phase 3: banners / HTTP
    let banners = join_all(open.iter().map(|&p| async move {
        let _permit = ctx.sockets.acquire().await;
        (
            p,
            probes::grab_banner(ip, p, netinfo::is_http_port(p)).await,
        )
    }))
    .await;
    for (port, b) in banners {
        if let Some(pi) = h.ports.iter_mut().find(|pi| pi.port == port) {
            pi.banner = b.text.clone();
        }
        if h.http_title.is_none() {
            h.http_title = b.http_title;
        }
        if h.http_server.is_none() {
            h.http_server = b.http_server;
        }
    }
    let (os, dev) = fingerprint(&h);
    h.os_guess = os;
    h.device_type = dev;
    h.status = Status::Done;
    ctx.send(idx, &h);
}

fn set_ports(h: &mut HostInfo, open: &BTreeSet<u16>) {
    for &p in open {
        if !h.ports.iter().any(|x| x.port == p) {
            h.ports.push(PortInfo {
                port: p,
                service: netinfo::service_name(p),
                banner: None,
            });
        }
    }
    h.ports.sort_by_key(|p| p.port);
}

/// Heuristic OS / device classification from everything gathered.
fn fingerprint(h: &HostInfo) -> (Option<String>, Option<String>) {
    let has = |p: u16| h.ports.iter().any(|x| x.port == p);
    let banners: String = h
        .ports
        .iter()
        .filter_map(|p| p.banner.as_deref())
        .chain(h.http_server.as_deref())
        .chain(h.upnp.as_ref().and_then(|u| u.server.as_deref()))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let vendor = h.vendor.as_deref().unwrap_or("").to_lowercase();
    let mdns = h.mdns_name.as_deref().unwrap_or("").to_lowercase();
    let upnp_type = h
        .upnp
        .as_ref()
        .and_then(|u| u.device_type.clone())
        .unwrap_or_default();

    let mut os: Option<String> = None;
    for (needle, name) in [
        ("ubuntu", "Linux (Ubuntu)"),
        ("debian", "Linux (Debian)"),
        ("raspbian", "Linux (Raspberry Pi OS)"),
        ("fedora", "Linux (Fedora)"),
        ("routeros", "MikroTik RouterOS"),
        ("mikrotik", "MikroTik RouterOS"),
        ("openwrt", "Linux (OpenWrt)"),
        ("synology", "Synology DSM"),
        ("freebsd", "FreeBSD"),
        ("microsoft-iis", "Windows"),
        ("windows", "Windows"),
        ("darwin", "macOS"),
        ("android", "Android"),
        ("linux", "Linux"),
    ] {
        if banners.contains(needle) {
            os = Some(name.into());
            break;
        }
    }
    if os.is_none() {
        os = if has(62078) {
            Some("iOS / iPadOS".into())
        } else if has(5555) {
            Some("Android".into())
        } else if has(3389) || has(135) {
            Some("Windows".into())
        } else if vendor.contains("apple") && (has(548) || has(22) || has(7000)) {
            Some("macOS".into())
        } else {
            h.ttl.map(|t| match t {
                0..=64 => "Linux / Unix / macOS / Android".into(),
                65..=128 => "Windows".into(),
                _ => "Embedded / network OS".into(),
            })
        };
    }

    let dev = if h.is_self {
        Some("This computer")
    } else if h.is_gateway {
        Some("Router / Gateway")
    } else if has(9100) || has(515) || has(631) || upnp_type.contains("Printer") {
        Some("Printer")
    } else if has(62078) || vendor.contains("apple") && mdns.contains("iphone") {
        Some("Phone / Tablet (Apple)")
    } else if has(8008) || has(8009) || upnp_type.contains("MediaRenderer") || has(32400) {
        Some("TV / Media device")
    } else if has(554) {
        Some("Camera / NVR")
    } else if has(7000) && vendor.contains("apple") {
        Some("Apple device (AirPlay)")
    } else if has(445) && (has(5000) || has(548) || has(2049)) {
        Some("NAS / File server")
    } else if has(1883) {
        Some("IoT hub")
    } else if has(3389) || has(445) {
        Some("Windows PC / Server")
    } else if upnp_type.contains("InternetGatewayDevice") || has(7547) {
        Some("Router / Access point")
    } else if vendor.contains("espressif") || vendor.contains("tuya") || vendor.contains("shenzhen")
    {
        Some("IoT device")
    } else if vendor.contains("samsung")
        || vendor.contains("xiaomi")
        || vendor.contains("oneplus")
        || vendor.contains("oppo")
        || vendor.contains("vivo")
        || vendor.contains("huawei")
        || vendor.contains("motorola")
    {
        Some("Phone / Tablet")
    } else if vendor.contains("raspberry") {
        Some("Raspberry Pi")
    } else if has(22) && h.ttl.is_some_and(|t| t <= 64) {
        Some("Linux host")
    } else {
        None
    };
    (os, dev.map(Into::into))
}
