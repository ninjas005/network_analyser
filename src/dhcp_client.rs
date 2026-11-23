//! DHCP client tester: runs a complete DISCOVER → OFFER → REQUEST → ACK
//! exchange from a test MAC address through packet injection (the OS's own
//! DHCP client on port 68 is untouched), times every step, records every
//! OFFER, optionally ARP-checks the leased address, tests DHCPINFORM and
//! releases (or declines) the lease afterwards.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crate::capture::{self, CaptureConfig, CaptureEvent, Source};
use crate::dhcp::{self, MAGIC, Message};
use crate::gateway::{Finding, Level};

const BROADCAST_MAC: [u8; 6] = [0xff; 6];
/// Collect further OFFERs this long after the first one.
const OFFER_WINDOW: f64 = 1.0;
const DISCOVER_RETRY: f64 = 4.0;
const REQUEST_RETRY: f64 = 3.0;
const TRIES: u32 = 3;
const ARP_WAIT: f64 = 1.0;
const INFORM_WAIT: f64 = 3.0;

pub fn mac_str(m: &[u8]) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Random locally-administered unicast MAC (02:xx:…).
pub fn random_mac() -> [u8; 6] {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut x = (t as u64) ^ ((t >> 64) as u64) ^ ((std::process::id() as u64) << 20);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    let b = x.to_be_bytes();
    [0x02, b[1], b[2], b[3], b[4], b[5]]
}

pub fn random_xid() -> u32 {
    let m = random_mac();
    u32::from_be_bytes([m[2], m[3], m[4], m[5]]) ^ std::process::id().rotate_left(16)
}

// ---------------------------------------------------------------- frames

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = b
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// BOOTREQUEST payload with options (53 msg type first, then `opts`).
pub fn dhcp_payload(
    mac: [u8; 6],
    xid: u32,
    msg_type: u8,
    ciaddr: Ipv4Addr,
    broadcast: bool,
    opts: &[(u8, Vec<u8>)],
) -> Vec<u8> {
    let mut d = vec![0u8; 240];
    d[0] = 1;
    d[1] = 1;
    d[2] = 6;
    d[4..8].copy_from_slice(&xid.to_be_bytes());
    if broadcast {
        d[10] = 0x80;
    }
    d[12..16].copy_from_slice(&ciaddr.octets());
    d[28..34].copy_from_slice(&mac);
    d[236..240].copy_from_slice(&MAGIC);
    d.extend_from_slice(&[53, 1, msg_type]);
    for (code, v) in opts {
        d.push(*code);
        d.push(v.len() as u8);
        d.extend_from_slice(v);
    }
    d.push(255);
    while d.len() < 300 {
        d.push(0);
    }
    d
}

/// Ethernet / IPv4 / UDP 68→67 frame around a DHCP payload.
pub fn udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut ip = vec![0x45, 0x10];
    ip.extend_from_slice(&(20 + udp_len).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let mut f = dst_mac.to_vec();
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend(ip);
    f.extend_from_slice(&68u16.to_be_bytes());
    f.extend_from_slice(&67u16.to_be_bytes());
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&[0, 0]); // UDP checksum optional on IPv4
    f.extend_from_slice(payload);
    f
}

#[derive(Clone, Debug, PartialEq)]
pub struct Arp {
    pub op: u16,
    pub sha: [u8; 6],
    pub spa: Ipv4Addr,
    pub tha: [u8; 6],
    pub tpa: Ipv4Addr,
}

pub fn arp_frame(eth_dst: [u8; 6], a: &Arp) -> Vec<u8> {
    let mut f = eth_dst.to_vec();
    f.extend_from_slice(&a.sha);
    f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4]);
    f.extend_from_slice(&a.op.to_be_bytes());
    f.extend_from_slice(&a.sha);
    f.extend_from_slice(&a.spa.octets());
    f.extend_from_slice(&a.tha);
    f.extend_from_slice(&a.tpa.octets());
    while f.len() < 60 {
        f.push(0);
    }
    f
}

/// ARP on an Ethernet frame (optionally VLAN-tagged).
pub fn parse_arp(f: &[u8]) -> Option<Arp> {
    let mut off = 12;
    let mut et = u16::from_be_bytes([*f.get(12)?, *f.get(13)?]);
    while et == 0x8100 || et == 0x88a8 {
        off += 4;
        et = u16::from_be_bytes([*f.get(off)?, *f.get(off + 1)?]);
    }
    if et != 0x0806 {
        return None;
    }
    let a = f.get(off + 2..off + 30)?;
    if a[0..2] != [0, 1] || a[2..4] != [8, 0] || a[4] != 6 || a[5] != 4 {
        return None;
    }
    let mac = |i: usize| -> [u8; 6] { a[i..i + 6].try_into().unwrap() };
    let ip = |i: usize| Ipv4Addr::new(a[i], a[i + 1], a[i + 2], a[i + 3]);
    Some(Arp {
        op: u16::from_be_bytes([a[6], a[7]]),
        sha: mac(8),
        spa: ip(14),
        tha: mac(18),
        tpa: ip(24),
    })
}

// ---------------------------------------------------------------- state machine

#[derive(Clone, Debug)]
pub struct RunConfig {
    pub requested_ip: Option<Ipv4Addr>,
    pub hostname: String,
    pub arp_check: bool,
    pub inform: bool,
    pub release: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            requested_ip: None,
            hostname: "na-dhcp-test".into(),
            arp_check: true,
            inform: false,
            release: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OfferRec {
    pub server: Ipv4Addr,
    pub server_mac: Option<String>,
    pub ip: Ipv4Addr,
    /// Since the DISCOVER it answers.
    pub ms: f64,
    pub msg: Message,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    /// Since the run started.
    pub t_ms: f64,
    pub outgoing: bool,
    pub text: String,
}

#[derive(Clone, Debug, Default)]
pub struct RunResult {
    pub run: u32,
    pub mac: String,
    pub xid: u32,
    pub requested: Option<Ipv4Addr>,
    pub offers: Vec<OfferRec>,
    pub chosen: Option<usize>,
    pub ack: Option<Message>,
    /// REQUEST → ACK.
    pub ack_ms: Option<f64>,
    /// First DISCOVER → ACK.
    pub total_ms: Option<f64>,
    pub nak: Option<String>,
    /// MAC that answered the ARP probe for the leased address.
    pub conflict: Option<String>,
    pub inform: Option<Result<(f64, Message), String>>,
    pub released: bool,
    pub declined: bool,
    pub error: Option<String>,
    pub log: Vec<LogLine>,
    pub finished: bool,
}

impl RunResult {
    pub fn lease(&self) -> Option<Ipv4Addr> {
        self.ack.as_ref().map(|m| m.yiaddr)
    }
    pub fn first_offer_ms(&self) -> Option<f64> {
        self.offers.iter().map(|o| o.ms).reduce(f64::min)
    }
    pub fn ok(&self) -> bool {
        self.ack.is_some() && self.conflict.is_none()
    }
    pub fn summary(&self) -> String {
        if let Some(e) = &self.error {
            return e.clone();
        }
        if let Some(n) = &self.nak {
            return format!("NAK: {n}");
        }
        if let Some(c) = &self.conflict {
            return format!("address conflict with {c}");
        }
        match (self.lease(), self.finished) {
            (Some(ip), _) => format!(
                "leased {ip}{}",
                if self.released {
                    ", released"
                } else if self.declined {
                    ", declined"
                } else {
                    ""
                }
            ),
            (None, false) => "running…".into(),
            (None, true) => "no lease".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Phase {
    Idle,
    Selecting,
    Requesting,
    Probing,
    Informing,
    Done,
}

pub struct Machine {
    cfg: RunConfig,
    mac: [u8; 6],
    ethernet: bool,
    phase: Phase,
    tries: u32,
    sent_at: f64,
    first_discover: f64,
    collect_until: Option<f64>,
    deadline: f64,
    inform_xid: u32,
    pub result: RunResult,
}

impl Machine {
    /// `ethernet`: the capture link is Ethernet, so ARP can be used.
    pub fn new(cfg: RunConfig, run: u32, mac: [u8; 6], xid: u32, ethernet: bool) -> Machine {
        Machine {
            mac,
            ethernet,
            phase: Phase::Idle,
            tries: 0,
            sent_at: 0.0,
            first_discover: 0.0,
            collect_until: None,
            deadline: 0.0,
            inform_xid: xid.wrapping_add(1),
            cfg: cfg.clone(),
            result: RunResult {
                run,
                mac: mac_str(&mac),
                xid,
                requested: cfg.requested_ip,
                ..Default::default()
            },
        }
    }

    pub fn finished(&self) -> bool {
        self.phase == Phase::Done
    }

    fn log(&mut self, now: f64, outgoing: bool, text: impl Into<String>) {
        self.result.log.push(LogLine {
            t_ms: now * 1000.0,
            outgoing,
            text: text.into(),
        });
    }

    fn base_opts(&self) -> Vec<(u8, Vec<u8>)> {
        let mut client_id = vec![1];
        client_id.extend_from_slice(&self.mac);
        vec![
            (61, client_id),
            (57, 1500u16.to_be_bytes().to_vec()),
            (12, self.cfg.hostname.as_bytes().to_vec()),
            (60, b"network-analyser".to_vec()),
            (
                55,
                vec![1, 3, 6, 15, 26, 28, 42, 51, 54, 58, 59, 119, 121, 252],
            ),
        ]
    }

    fn broadcast(
        &self,
        xid: u32,
        t: u8,
        ciaddr: Ipv4Addr,
        src: Ipv4Addr,
        opts: Vec<(u8, Vec<u8>)>,
    ) -> Vec<u8> {
        let p = dhcp_payload(self.mac, xid, t, ciaddr, true, &opts);
        udp_frame(self.mac, BROADCAST_MAC, src, Ipv4Addr::BROADCAST, &p)
    }

    fn discover(&mut self, now: f64) -> Vec<Vec<u8>> {
        self.tries += 1;
        self.sent_at = now;
        let mut opts = self.base_opts();
        if let Some(ip) = self.cfg.requested_ip {
            opts.push((50, ip.octets().to_vec()));
        }
        self.log(
            now,
            true,
            format!(
                "DISCOVER{}{}",
                self.cfg
                    .requested_ip
                    .map(|i| format!(" requesting {i}"))
                    .unwrap_or_default(),
                if self.tries > 1 {
                    format!(" (retry {})", self.tries - 1)
                } else {
                    String::new()
                }
            ),
        );
        vec![self.broadcast(
            self.result.xid,
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            opts,
        )]
    }

    fn request(&mut self, now: f64) -> Vec<Vec<u8>> {
        let Some(o) = self.result.chosen.and_then(|i| self.result.offers.get(i)) else {
            return Vec::new();
        };
        let (ip, server) = (o.ip, o.server);
        self.tries += 1;
        self.sent_at = now;
        let mut opts = self.base_opts();
        opts.push((50, ip.octets().to_vec()));
        opts.push((54, server.octets().to_vec()));
        self.log(
            now,
            true,
            format!(
                "REQUEST {ip} from {server}{}",
                if self.tries > 1 { " (retry)" } else { "" }
            ),
        );
        vec![self.broadcast(
            self.result.xid,
            3,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            opts,
        )]
    }

    pub fn start(&mut self, now: f64) -> Vec<Vec<u8>> {
        self.phase = Phase::Selecting;
        self.first_discover = now;
        self.deadline = now + DISCOVER_RETRY;
        self.discover(now)
    }

    fn fail(&mut self, now: f64, why: &str) {
        self.log(now, false, why);
        self.result.error = Some(why.into());
        self.phase = Phase::Done;
        self.result.finished = true;
    }

    fn chosen_server(&self) -> Option<&OfferRec> {
        self.result.chosen.and_then(|i| self.result.offers.get(i))
    }

    /// After ACK (and the ARP check): INFORM, then release.
    fn bound(&mut self, now: f64) -> Vec<Vec<u8>> {
        if self.cfg.inform
            && let Some(ip) = self.result.lease()
        {
            self.phase = Phase::Informing;
            self.deadline = now + INFORM_WAIT;
            self.sent_at = now;
            self.log(now, true, format!("INFORM from {ip}"));
            return vec![self.broadcast(self.inform_xid, 8, ip, ip, self.base_opts())];
        }
        self.finish(now)
    }

    fn finish(&mut self, now: f64) -> Vec<Vec<u8>> {
        self.phase = Phase::Done;
        self.result.finished = true;
        if !self.cfg.release {
            self.log(now, false, "lease kept (release disabled)");
            return Vec::new();
        }
        let (Some(ip), Some(o)) = (self.result.lease(), self.chosen_server()) else {
            return Vec::new();
        };
        let server = o.server;
        let dst_mac = o
            .server_mac
            .as_deref()
            .and_then(dhcp::parse_mac)
            .unwrap_or(BROADCAST_MAC);
        let mut client_id = vec![1];
        client_id.extend_from_slice(&self.mac);
        let p = dhcp_payload(
            self.mac,
            random_xid(),
            7,
            ip,
            false,
            &[(54, server.octets().to_vec()), (61, client_id)],
        );
        self.result.released = true;
        self.log(now, true, format!("RELEASE {ip} to {server}"));
        vec![udp_frame(self.mac, dst_mac, ip, server, &p)]
    }

    fn decline(&mut self, now: f64) -> Vec<Vec<u8>> {
        let (Some(ip), Some(o)) = (self.result.lease(), self.chosen_server()) else {
            return Vec::new();
        };
        let mut opts = vec![(50, ip.octets().to_vec()), (54, o.server.octets().to_vec())];
        let mut client_id = vec![1];
        client_id.extend_from_slice(&self.mac);
        opts.push((61, client_id));
        self.result.declined = true;
        self.phase = Phase::Done;
        self.result.finished = true;
        self.log(now, true, format!("DECLINE {ip} (address in use)"));
        vec![self.broadcast(
            random_xid(),
            4,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            opts,
        )]
    }

    pub fn on_dhcp(
        &mut self,
        now: f64,
        m: &Message,
        src_mac: Option<&str>,
        src: Ipv4Addr,
    ) -> Vec<Vec<u8>> {
        if m.op != 2 || dhcp::parse_mac(&m.chaddr) != Some(self.mac) {
            return Vec::new();
        }
        let server = m.server_id.unwrap_or(src);
        match (self.phase, m.msg_type) {
            (Phase::Selecting, Some(2)) if m.xid == self.result.xid => {
                if self
                    .result
                    .offers
                    .iter()
                    .any(|o| o.server == server && o.ip == m.yiaddr)
                {
                    return Vec::new(); // duplicate (answer to a retry)
                }
                let ms = (now - self.sent_at) * 1000.0;
                self.log(
                    now,
                    false,
                    format!("OFFER {} from {server} after {ms:.0} ms", m.yiaddr),
                );
                self.result.offers.push(OfferRec {
                    server,
                    server_mac: src_mac.map(String::from),
                    ip: m.yiaddr,
                    ms,
                    msg: m.clone(),
                });
                if self.collect_until.is_none() {
                    self.collect_until = Some(now + OFFER_WINDOW);
                }
                Vec::new()
            }
            (Phase::Requesting, Some(5)) if m.xid == self.result.xid => {
                let ms = (now - self.sent_at) * 1000.0;
                self.result.ack_ms = Some(ms);
                self.result.total_ms = Some((now - self.first_discover) * 1000.0);
                self.log(
                    now,
                    false,
                    format!(
                        "ACK {} from {server} after {ms:.0} ms{}",
                        m.yiaddr,
                        m.lease_secs
                            .map(|l| format!(", lease {}", dhcp::duration(l)))
                            .unwrap_or_default()
                    ),
                );
                self.result.ack = Some(m.clone());
                if self.cfg.arp_check && self.ethernet && !m.yiaddr.is_unspecified() {
                    self.phase = Phase::Probing;
                    self.deadline = now + ARP_WAIT;
                    self.log(
                        now,
                        true,
                        format!("ARP probe: is {} already in use?", m.yiaddr),
                    );
                    return vec![arp_frame(
                        BROADCAST_MAC,
                        &Arp {
                            op: 1,
                            sha: self.mac,
                            spa: Ipv4Addr::UNSPECIFIED,
                            tha: [0; 6],
                            tpa: m.yiaddr,
                        },
                    )];
                }
                self.bound(now)
            }
            (Phase::Requesting, Some(6)) if m.xid == self.result.xid => {
                let why = m
                    .options
                    .iter()
                    .find(|o| o.code == 56)
                    .map(|o| o.value.clone())
                    .unwrap_or_else(|| "no reason given".into());
                self.log(now, false, format!("NAK from {server}: {why}"));
                self.result.nak = Some(format!("{server}: {why}"));
                self.phase = Phase::Done;
                self.result.finished = true;
                Vec::new()
            }
            (Phase::Informing, Some(5)) if m.xid == self.inform_xid => {
                let ms = (now - self.sent_at) * 1000.0;
                self.log(
                    now,
                    false,
                    format!("ACK to INFORM from {server} after {ms:.0} ms"),
                );
                self.result.inform = Some(Ok((ms, m.clone())));
                self.finish(now)
            }
            _ => Vec::new(),
        }
    }

    pub fn on_arp(&mut self, now: f64, a: &Arp) -> Vec<Vec<u8>> {
        if a.sha == self.mac {
            return Vec::new(); // our own frame
        }
        let Some(ip) = self.result.lease() else {
            return Vec::new();
        };
        match self.phase {
            Phase::Probing if a.spa == ip => {
                let who = mac_str(&a.sha);
                self.log(now, false, format!("ARP: {ip} is in use by {who}"));
                self.result.conflict = Some(who);
                self.decline(now)
            }
            // Answer ARP for our lease so unicast replies (INFORM) reach us.
            Phase::Informing if a.op == 1 && a.tpa == ip && !a.spa.is_unspecified() => {
                vec![arp_frame(
                    a.sha,
                    &Arp {
                        op: 2,
                        sha: self.mac,
                        spa: ip,
                        tha: a.sha,
                        tpa: a.spa,
                    },
                )]
            }
            _ => Vec::new(),
        }
    }

    pub fn tick(&mut self, now: f64) -> Vec<Vec<u8>> {
        match self.phase {
            Phase::Selecting => {
                if let Some(t) = self.collect_until {
                    if now >= t {
                        // Like a real client: take the first offer.
                        self.result.chosen = Some(0);
                        self.phase = Phase::Requesting;
                        self.tries = 0;
                        self.deadline = now + REQUEST_RETRY;
                        return self.request(now);
                    }
                } else if now >= self.deadline {
                    if self.tries >= TRIES {
                        self.fail(now, "no DHCP server answered the DISCOVER");
                    } else {
                        self.deadline = now + DISCOVER_RETRY;
                        return self.discover(now);
                    }
                }
            }
            Phase::Requesting if now >= self.deadline => {
                if self.tries >= TRIES {
                    self.fail(
                        now,
                        "server offered an address but never acknowledged the REQUEST",
                    );
                } else {
                    self.deadline = now + REQUEST_RETRY;
                    return self.request(now);
                }
            }
            Phase::Probing if now >= self.deadline => {
                self.log(now, false, "ARP probe: no reply, the address is free");
                return self.bound(now);
            }
            Phase::Informing if now >= self.deadline => {
                self.log(now, false, "no reply to INFORM");
                self.result.inform = Some(Err("no reply".into()));
                return self.finish(now);
            }
            _ => {}
        }
        Vec::new()
    }
}

// ---------------------------------------------------------------- runner

#[derive(Clone, Debug)]
pub struct Config {
    pub device: String,
    /// None: a new random MAC for each run.
    pub mac: Option<[u8; 6]>,
    pub run: RunConfig,
    pub repeat: u32,
}

pub enum Event {
    Status(String),
    Update(Box<RunResult>),
    Finished(Result<(), String>),
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

fn cap_error(e: String) -> String {
    match capture::permission_hint(&e) {
        Some(h) => format!("{e}. {h}"),
        None => e,
    }
}

pub fn start(cfg: Config) -> RunHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        let r = worker(cfg, &tx, &flag);
        let _ = tx.send(Event::Finished(r));
    });
    RunHandle { events: rx, stop }
}

fn worker(cfg: Config, tx: &Sender<Event>, stop: &AtomicBool) -> Result<(), String> {
    let cap = capture::start(CaptureConfig {
        source: Source::Live {
            device: cfg.device.clone(),
            // Replies may be unicast to the test MAC, which is not ours.
            promisc: true,
        },
        filter: "(udp and (port 67 or port 68)) or arp".into(),
        save_to: None,
    });
    // Wait for the capture to open.
    let linktype = loop {
        match cap.events.recv_timeout(Duration::from_secs(5)) {
            Ok(CaptureEvent::Started { linktype, .. }) => break linktype,
            Ok(CaptureEvent::Stopped(Some(e))) => return Err(cap_error(e)),
            Ok(CaptureEvent::Stopped(None)) => return Err("capture stopped".into()),
            Ok(_) => {}
            Err(_) => return Err("capture did not start".into()),
        }
    };
    if linktype != 1 {
        return Err(format!(
            "interface link type {linktype} is not Ethernet; pick a physical / Wi-Fi interface"
        ));
    }
    for run in 1..=cfg.repeat.max(1) {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mac = cfg.mac.unwrap_or_else(random_mac);
        let mut m = Machine::new(cfg.run.clone(), run, mac, random_xid(), true);
        let _ = tx.send(Event::Status(format!(
            "Run {run}/{}: DHCP exchange from {}…",
            cfg.repeat.max(1),
            mac_str(&mac)
        )));
        let t0 = Instant::now();
        let now = || t0.elapsed().as_secs_f64();
        for f in m.start(now()) {
            cap.inject(f);
        }
        let mut last_sent = 0;
        while !m.finished() {
            if stop.load(Ordering::Relaxed) {
                m.result.error = Some("stopped".into());
                m.result.finished = true;
                // Give back a lease we already hold.
                if m.result.ack.is_some() && cfg.run.release {
                    for f in m.finish(now()) {
                        cap.inject(f);
                    }
                }
                break;
            }
            let mut out = Vec::new();
            while let Ok(ev) = cap.events.try_recv() {
                match ev {
                    CaptureEvent::Packets(pkts) => {
                        for p in pkts {
                            if let Some(a) = parse_arp(&p.data) {
                                out.extend(m.on_arp(now(), &a));
                            } else if let Some(u) = dhcp::udp_payload(linktype, &p.data)
                                && u.sport == 67
                                && let Some(msg) = dhcp::parse(u.payload)
                            {
                                out.extend(m.on_dhcp(now(), &msg, u.src_mac.as_deref(), u.src));
                            }
                        }
                    }
                    CaptureEvent::InjectFailed(e) => {
                        return Err(format!("could not send: {}", cap_error(e)));
                    }
                    CaptureEvent::Stopped(e) => {
                        return Err(cap_error(e.unwrap_or_else(|| "capture stopped".into())));
                    }
                    _ => {}
                }
            }
            out.extend(m.tick(now()));
            for f in out {
                cap.inject(f);
            }
            if m.result.log.len() != last_sent {
                last_sent = m.result.log.len();
                let _ = tx.send(Event::Update(Box::new(m.result.clone())));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = tx.send(Event::Update(Box::new(m.result.clone())));
        // Let the RELEASE leave before the next run / closing the capture.
        std::thread::sleep(Duration::from_millis(if run < cfg.repeat {
            700
        } else {
            300
        }));
    }
    cap.stop();
    Ok(())
}

// ---------------------------------------------------------------- findings

pub fn findings(runs: &[RunResult]) -> Vec<Finding> {
    let mut out = Vec::new();
    let f = |section: &str, key: &str, value: String, level: Level| Finding {
        section: section.into(),
        key: key.into(),
        value,
        level,
    };
    let done: Vec<&RunResult> = runs.iter().filter(|r| r.finished).collect();
    if done.is_empty() {
        return out;
    }
    let ok = done.iter().filter(|r| r.ack.is_some()).count();
    out.push(f(
        "Summary",
        "Successful leases",
        format!("{ok} of {} runs", done.len()),
        if ok == done.len() {
            Level::Good
        } else if ok > 0 {
            Level::Warn
        } else {
            Level::Bad
        },
    ));
    let mut servers: Vec<(Ipv4Addr, Option<String>)> = Vec::new();
    for o in done.iter().flat_map(|r| &r.offers) {
        if !servers.iter().any(|(s, _)| *s == o.server) {
            servers.push((o.server, o.server_mac.clone()));
        }
    }
    match servers.len() {
        0 => out.push(f(
            "Summary",
            "DHCP servers",
            "none answered: no server on this segment, a relay is missing, or DHCP snooping blocks the test".into(),
            Level::Bad,
        )),
        1 => out.push(f(
            "Summary",
            "DHCP servers",
            format!(
                "{} {}",
                servers[0].0,
                servers[0].1.clone().unwrap_or_default()
            ),
            Level::Good,
        )),
        n => out.push(f(
            "Summary",
            "DHCP servers",
            format!(
                "{n} servers offered addresses: {} — check that all are authorised",
                servers
                    .iter()
                    .map(|(s, m)| format!("{s} ({})", m.clone().unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Level::Warn,
        )),
    }
    let offers: Vec<f64> = done.iter().filter_map(|r| r.first_offer_ms()).collect();
    if let Some(max) = offers.iter().copied().reduce(f64::max) {
        let avg = offers.iter().sum::<f64>() / offers.len() as f64;
        out.push(f(
            "Timing",
            "DISCOVER → OFFER",
            format!("avg {avg:.0} ms, max {max:.0} ms"),
            if max > 3000.0 {
                Level::Bad
            } else if max > 1000.0 {
                Level::Warn
            } else {
                Level::Good
            },
        ));
    }
    let acks: Vec<f64> = done.iter().filter_map(|r| r.ack_ms).collect();
    if let Some(max) = acks.iter().copied().reduce(f64::max) {
        let avg = acks.iter().sum::<f64>() / acks.len() as f64;
        out.push(f(
            "Timing",
            "REQUEST → ACK",
            format!("avg {avg:.0} ms, max {max:.0} ms"),
            if max > 2000.0 {
                Level::Bad
            } else if max > 500.0 {
                Level::Warn
            } else {
                Level::Good
            },
        ));
    }
    let totals: Vec<f64> = done.iter().filter_map(|r| r.total_ms).collect();
    if let Some(max) = totals.iter().copied().reduce(f64::max) {
        out.push(f(
            "Timing",
            "Full exchange",
            format!(
                "avg {:.0} ms, max {max:.0} ms (includes the {:.0} ms wait for more offers)",
                totals.iter().sum::<f64>() / totals.len() as f64,
                OFFER_WINDOW * 1000.0
            ),
            Level::Info,
        ));
    }
    for r in &done {
        if let Some(n) = &r.nak {
            out.push(f(
                "Problems",
                &format!("Run {}", r.run),
                format!("NAK — {n}"),
                Level::Bad,
            ));
        }
        if let Some(c) = &r.conflict {
            out.push(f(
                "Problems",
                &format!("Run {}", r.run),
                format!(
                    "the server handed out {} which {c} already uses (duplicate address; DECLINE sent)",
                    r.lease().map(|i| i.to_string()).unwrap_or_default()
                ),
                Level::Bad,
            ));
        }
        if let Some(e) = &r.error
            && e != "stopped"
        {
            out.push(f(
                "Problems",
                &format!("Run {}", r.run),
                e.clone(),
                Level::Bad,
            ));
        }
    }
    // Pool exhaustion pattern: later runs fail after earlier ones worked.
    if let Some(first_fail) = done.iter().position(|r| r.ack.is_none())
        && first_fail > 0
        && done[first_fail..].iter().all(|r| r.offers.is_empty())
    {
        out.push(f(
            "Problems",
            "Pool",
            format!("offers stopped after run {first_fail}: the address pool may be exhausted or rate-limited"),
            Level::Warn,
        ));
    }
    if let Some(r) = done.iter().rev().find(|r| r.ack.is_some()) {
        let m = r.ack.as_ref().unwrap();
        let sec = "Lease (last ACK)";
        out.push(f(sec, "Address", format!("{}", m.yiaddr), Level::Info));
        match m.lease_secs {
            Some(l) if l < 3600 => out.push(f(
                sec,
                "Lease time",
                format!("{} — short; fine for guest networks", dhcp::duration(l)),
                Level::Info,
            )),
            Some(l) => out.push(f(sec, "Lease time", dhcp::duration(l), Level::Good)),
            None => out.push(f(
                sec,
                "Lease time",
                "missing (option 51)".into(),
                Level::Warn,
            )),
        }
        out.push(match m.subnet_mask {
            Some(s) => f(sec, "Subnet mask", s.to_string(), Level::Good),
            None => f(sec, "Subnet mask", "missing (option 1)".into(), Level::Warn),
        });
        out.push(if m.routers.is_empty() {
            f(
                sec,
                "Router",
                "missing: clients get no default gateway".into(),
                Level::Warn,
            )
        } else {
            f(
                sec,
                "Router",
                m.routers
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                Level::Good,
            )
        });
        out.push(if m.dns.is_empty() {
            f(
                sec,
                "DNS servers",
                "missing: clients cannot resolve names".into(),
                Level::Warn,
            )
        } else {
            f(
                sec,
                "DNS servers",
                m.dns
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                Level::Good,
            )
        });
        if let Some(d) = &m.domain {
            out.push(f(sec, "Domain", d.clone(), Level::Info));
        }
        if let Some(req) = r.requested {
            let honoured = req == m.yiaddr;
            out.push(f(
                sec,
                "Requested address",
                if honoured {
                    format!("{req} granted")
                } else {
                    format!("asked for {req}, got {}", m.yiaddr)
                },
                Level::Info,
            ));
        }
        match &r.inform {
            Some(Ok((ms, _))) => out.push(f(
                sec,
                "DHCPINFORM",
                format!("answered in {ms:.0} ms"),
                Level::Good,
            )),
            Some(Err(e)) => out.push(f(
                sec,
                "DHCPINFORM",
                format!("{e} (many home routers ignore INFORM)"),
                Level::Info,
            )),
            None => {}
        }
        out.push(if r.released {
            f(
                sec,
                "Release",
                "lease released after the test".into(),
                Level::Good,
            )
        } else if r.declined {
            f(
                sec,
                "Release",
                "address declined (conflict)".into(),
                Level::Warn,
            )
        } else {
            f(
                sec,
                "Release",
                "lease kept until it expires (release disabled)".into(),
                Level::Warn,
            )
        });
    }
    out
}

// ---------------------------------------------------------------- CLI

fn default_iface() -> Option<String> {
    let list = capture::interfaces().ok()?;
    let primary = crate::netinfo::local_interfaces()
        .first()
        .map(|i| i.ip.to_string());
    list.iter()
        .find(|i| primary.as_ref().is_some_and(|p| i.addrs.contains(p)))
        .or_else(|| {
            list.iter()
                .find(|i| i.up && !i.loopback && !i.addrs.is_empty())
        })
        .map(|i| i.name.clone())
}

/// `--dhcp-client [IFACE] [--mac MAC] [--request IP] [--inform]
/// [--no-release] [--no-arp] [--repeat N]`
pub fn cli(args: &[String]) {
    let fail = |m: String| -> ! {
        eprintln!("{m}");
        std::process::exit(2)
    };
    let mut device = None;
    let mut cfg = Config {
        device: String::new(),
        mac: None,
        run: RunConfig::default(),
        repeat: 1,
    };
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--mac" => {
                cfg.mac = Some(
                    dhcp::parse_mac(&next(i)).unwrap_or_else(|| fail("--mac: bad MAC".into())),
                );
                i += 1;
            }
            "--request" => {
                cfg.run.requested_ip = Some(
                    next(i)
                        .parse()
                        .unwrap_or_else(|_| fail("--request: bad IPv4".into())),
                );
                i += 1;
            }
            "--repeat" => {
                cfg.repeat = next(i)
                    .parse()
                    .ok()
                    .filter(|n| (1..=100).contains(n))
                    .unwrap_or_else(|| fail("--repeat: 1..100".into()));
                i += 1;
            }
            "--inform" => cfg.run.inform = true,
            "--no-release" => cfg.run.release = false,
            "--no-arp" => cfg.run.arp_check = false,
            s if !s.starts_with('-') && device.is_none() => device = Some(s.to_string()),
            s => fail(format!("unknown option {s}")),
        }
        i += 1;
    }
    cfg.device = device
        .or_else(default_iface)
        .unwrap_or_else(|| fail("no capture interface; pass one (see --list-ifaces)".into()));
    eprintln!("DHCP client test on {}", cfg.device);
    let h = start(cfg);
    let mut runs: Vec<RunResult> = Vec::new();
    let mut printed: std::collections::HashMap<u32, usize> = Default::default();
    for ev in h.events.iter() {
        match ev {
            Event::Status(s) => eprintln!("{s}"),
            Event::Update(r) => {
                let n = printed.entry(r.run).or_default();
                for l in &r.log[*n..] {
                    println!(
                        "  {:>8.1} ms  {} {}",
                        l.t_ms,
                        if l.outgoing { "→" } else { "←" },
                        l.text
                    );
                }
                *n = r.log.len();
                match runs.iter_mut().find(|x| x.run == r.run) {
                    Some(x) => *x = *r,
                    None => runs.push(*r),
                }
            }
            Event::Finished(Err(e)) => {
                eprintln!("{e}");
                std::process::exit(1)
            }
            Event::Finished(Ok(())) => break,
        }
    }
    if let Some(m) = runs.iter().rev().find_map(|r| r.ack.as_ref()) {
        println!("\nACK options:");
        for o in &m.options {
            println!("  {:>3} {:<28} {}", o.code, o.name, o.value);
        }
    }
    print!("{}", crate::widgets::findings_text(&findings(&runs)));
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    /// A server reply as captured: Ethernet frame from the server.
    fn reply(xid: u32, t: u8, yiaddr: Ipv4Addr, server: Ipv4Addr) -> Message {
        let mut p = dhcp_payload(
            MAC,
            xid,
            t,
            Ipv4Addr::UNSPECIFIED,
            true,
            &[
                (54, server.octets().to_vec()),
                (51, 3600u32.to_be_bytes().to_vec()),
                (1, vec![255, 255, 255, 0]),
                (3, SERVER.octets().to_vec()),
                (6, vec![1, 1, 1, 1]),
            ],
        );
        p[0] = 2;
        p[16..20].copy_from_slice(&yiaddr.octets());
        dhcp::parse(&p).unwrap()
    }

    fn sent_types(frames: &[Vec<u8>]) -> Vec<u8> {
        frames
            .iter()
            .filter_map(|f| dhcp::parse(dhcp::udp_payload(1, f)?.payload)?.msg_type)
            .collect()
    }

    #[test]
    fn frames_parse_back() {
        let p = dhcp_payload(
            MAC,
            0xabcd,
            3,
            Ipv4Addr::UNSPECIFIED,
            true,
            &[(50, vec![10, 0, 0, 5]), (54, vec![10, 0, 0, 1])],
        );
        let f = udp_frame(
            MAC,
            BROADCAST_MAC,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            &p,
        );
        let u = dhcp::udp_payload(1, &f).unwrap();
        assert_eq!((u.sport, u.dport), (68, 67));
        assert_eq!(checksum(&f[14..34]), 0);
        let m = dhcp::parse(u.payload).unwrap();
        assert_eq!(m.msg_type, Some(3));
        assert_eq!(m.requested_ip, Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(m.server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(m.chaddr, "02:11:22:33:44:55");
        let a = Arp {
            op: 1,
            sha: MAC,
            spa: Ipv4Addr::UNSPECIFIED,
            tha: [0; 6],
            tpa: Ipv4Addr::new(10, 0, 0, 5),
        };
        let fr = arp_frame(BROADCAST_MAC, &a);
        assert_eq!(fr.len(), 60);
        assert_eq!(parse_arp(&fr), Some(a));
        assert!(random_mac()[0] == 0x02);
    }

    #[test]
    fn full_dora_with_two_servers_and_release() {
        let xid = 77;
        let mut m = Machine::new(RunConfig::default(), 1, MAC, xid, true);
        assert_eq!(sent_types(&m.start(0.0)), vec![1]);
        let lease = Ipv4Addr::new(192, 168, 1, 50);
        let rogue = Ipv4Addr::new(10, 9, 9, 9);
        m.on_dhcp(
            0.020,
            &reply(xid, 2, lease, SERVER),
            Some("AA:AA:AA:AA:AA:01"),
            SERVER,
        );
        // Wrong xid ignored, second server recorded.
        m.on_dhcp(0.030, &reply(xid + 5, 2, lease, rogue), None, rogue);
        m.on_dhcp(
            0.040,
            &reply(xid, 2, Ipv4Addr::new(10, 9, 9, 50), rogue),
            None,
            rogue,
        );
        assert_eq!(m.result.offers.len(), 2);
        assert!((m.result.offers[0].ms - 20.0).abs() < 1e-6);
        assert!(m.tick(0.5).is_empty()); // still collecting
        let req = m.tick(1.1);
        assert_eq!(sent_types(&req), vec![3]);
        let msg = dhcp::parse(dhcp::udp_payload(1, &req[0]).unwrap().payload).unwrap();
        assert_eq!(msg.requested_ip, Some(lease));
        assert_eq!(msg.server_id, Some(SERVER));
        // ACK → ARP probe
        let probe = m.on_dhcp(1.115, &reply(xid, 5, lease, SERVER), None, SERVER);
        let a = parse_arp(&probe[0]).unwrap();
        assert_eq!((a.op, a.spa, a.tpa), (1, Ipv4Addr::UNSPECIFIED, lease));
        assert!((m.result.ack_ms.unwrap() - 15.0).abs() < 1e-6);
        // No conflict → release, unicast to the server's MAC.
        let rel = m.tick(2.2);
        assert!(m.finished());
        assert!(m.result.released);
        assert_eq!(&rel[0][..6], &[0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01]);
        let u = dhcp::udp_payload(1, &rel[0]).unwrap();
        assert_eq!((u.src, u.dst), (lease, SERVER));
        assert_eq!(dhcp::parse(u.payload).unwrap().msg_type, Some(7));
        let f = findings(&[m.result.clone()]);
        assert!(
            f.iter()
                .any(|f| f.key == "DHCP servers" && f.level == Level::Warn)
        );
        assert!(
            f.iter()
                .any(|f| f.key == "Release" && f.level == Level::Good)
        );
    }

    #[test]
    fn conflict_declines() {
        let mut m = Machine::new(RunConfig::default(), 1, MAC, 5, true);
        m.start(0.0);
        let lease = Ipv4Addr::new(192, 168, 1, 60);
        m.on_dhcp(0.01, &reply(5, 2, lease, SERVER), None, SERVER);
        m.tick(1.2);
        m.on_dhcp(1.3, &reply(5, 5, lease, SERVER), None, SERVER);
        let other = [0x00, 0x1b, 0x21, 1, 2, 3];
        let out = m.on_arp(
            1.4,
            &Arp {
                op: 2,
                sha: other,
                spa: lease,
                tha: MAC,
                tpa: Ipv4Addr::UNSPECIFIED,
            },
        );
        assert_eq!(sent_types(&out), vec![4]);
        assert!(m.finished() && m.result.declined && !m.result.released);
        assert_eq!(m.result.conflict.as_deref(), Some("00:1B:21:01:02:03"));
    }

    #[test]
    fn nak_and_retries() {
        let mut m = Machine::new(RunConfig::default(), 1, MAC, 9, false);
        m.start(0.0);
        assert_eq!(sent_types(&m.tick(4.1)), vec![1]); // retry
        assert_eq!(m.tries, 2);
        m.on_dhcp(
            4.2,
            &reply(9, 2, Ipv4Addr::new(10, 0, 0, 2), SERVER),
            None,
            SERVER,
        );
        // DISCOVER→OFFER measured from the retry.
        assert!((m.result.offers[0].ms - 100.0).abs() < 1e-6);
        m.tick(5.3);
        m.on_dhcp(
            5.4,
            &reply(9, 6, Ipv4Addr::UNSPECIFIED, SERVER),
            None,
            SERVER,
        );
        assert!(m.finished());
        assert!(m.result.nak.is_some());

        let mut m = Machine::new(RunConfig::default(), 2, MAC, 10, false);
        m.start(0.0);
        m.tick(4.0);
        m.tick(8.0);
        m.tick(12.0);
        assert!(m.finished());
        assert!(
            m.result
                .error
                .as_deref()
                .unwrap()
                .contains("no DHCP server")
        );
    }

    #[test]
    fn inform_answers_arp() {
        let cfg = RunConfig {
            inform: true,
            arp_check: false,
            ..Default::default()
        };
        let mut m = Machine::new(cfg, 1, MAC, 20, true);
        m.start(0.0);
        let lease = Ipv4Addr::new(192, 168, 1, 70);
        m.on_dhcp(0.01, &reply(20, 2, lease, SERVER), None, SERVER);
        m.tick(1.1);
        let inf = m.on_dhcp(1.2, &reply(20, 5, lease, SERVER), None, SERVER);
        assert_eq!(sent_types(&inf), vec![8]);
        let req = Arp {
            op: 1,
            sha: [0xaa; 6],
            spa: SERVER,
            tha: [0; 6],
            tpa: lease,
        };
        let rep = parse_arp(&m.on_arp(1.21, &req)[0]).unwrap();
        assert_eq!((rep.op, rep.sha, rep.spa, rep.tpa), (2, MAC, lease, SERVER));
        let fin = m.on_dhcp(1.25, &reply(21, 5, lease, SERVER), None, SERVER);
        assert!(matches!(m.result.inform, Some(Ok(_))));
        assert_eq!(sent_types(&fin), vec![7]);
    }
}
