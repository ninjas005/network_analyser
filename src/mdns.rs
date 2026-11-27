//! Network-wide mDNS / Bonjour (DNS-SD) discovery.
//!
//! Many devices (Apple, Android/Chromecast, printers, ESPHome/Shelly and
//! other IoT gear) never answer a unicast query sent straight to their IP,
//! but they do answer multicast browsing on 224.0.0.251:5353. This runs once
//! per scan, next to the per-host probes, and returns what every responder
//! on the link said about itself, keyed by IPv4 address.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep_until};

use crate::probes::{encode_dns_name, read_dns_name};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const PORT: u16 = 5353;
/// Total listening time.
const LISTEN: Duration = Duration::from_millis(3200);
/// When query rounds go out (relative to start). Later rounds follow up on
/// what earlier answers revealed (service types -> instances -> hosts).
const ROUNDS: &[u64] = &[0, 300, 1000, 1700, 2400];
/// Upper bound for per-address reverse (in-addr.arpa) questions.
const MAX_REVERSE: usize = 4096;
const MAX_PACKET: usize = 1400;

const T_A: u16 = 1;
const T_PTR: u16 = 12;
const T_TXT: u16 = 16;
const T_SRV: u16 = 33;

/// Asked for in the first round, so devices whose responder doesn't support
/// `_services._dns-sd._udp` enumeration are still found.
const COMMON_SERVICES: &[&str] = &[
    "_device-info._tcp",
    "_workstation._tcp",
    "_companion-link._tcp",
    "_apple-mobdev2._tcp",
    "_rdlink._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_homekit._tcp",
    "_hap._tcp",
    "_hap._udp",
    "_sleep-proxy._udp",
    "_googlecast._tcp",
    "_androidtvremote2._tcp",
    "_amzn-wplay._tcp",
    "_spotify-connect._tcp",
    "_sonos._tcp",
    "_ipp._tcp",
    "_ipps._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_scanner._tcp",
    "_uscan._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_nfs._tcp",
    "_ssh._tcp",
    "_sftp-ssh._tcp",
    "_http._tcp",
    "_https._tcp",
    "_esphomelib._tcp",
    "_shelly._tcp",
    "_hue._tcp",
    "_matter._tcp",
    "_matterc._udp",
    "_meshcop._udp",
    "_home-assistant._tcp",
    "_mqtt._tcp",
    "_arduino._tcp",
    "_octoprint._tcp",
    "_miio._udp",
    "_daap._tcp",
    "_nvstream._tcp",
    "_rfb._tcp",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdnsService {
    /// e.g. `_airplay._tcp`
    pub kind: String,
    /// Instance name, e.g. `Living Room`.
    pub instance: String,
    pub port: u16,
}

impl MdnsService {
    pub fn label(&self) -> String {
        if self.port == 0 {
            format!(
                "{} ({}) {}",
                service_label(&self.kind),
                self.kind,
                self.instance
            )
        } else {
            format!(
                "{} ({}:{}) {}",
                service_label(&self.kind),
                self.kind,
                self.port,
                self.instance
            )
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MdnsHost {
    /// `name.local`
    pub hostname: Option<String>,
    /// Human name the device advertises ("Vivek's iPhone", "Living Room TV").
    pub friendly: Option<String>,
    pub model: Option<String>,
    /// From `_workstation._tcp` (`host [aa:bb:cc:dd:ee:ff]`).
    pub mac: Option<String>,
    pub services: Vec<MdnsService>,
    /// The address itself sent an mDNS packet (so it's alive). Records that
    /// only mention it may come from a sleep proxy answering on its behalf.
    pub responded: bool,
}

pub type MdnsMap = HashMap<Ipv4Addr, MdnsHost>;

/// Browse the link for `LISTEN` and return everything learned. `iface` is the
/// local address of the interface to use; `targets` get reverse lookups.
pub async fn discover(iface: Option<Ipv4Addr>, targets: &[Ipv4Addr]) -> MdnsMap {
    let iface = iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let Some(query) = query_socket(iface) else {
        return MdnsMap::new();
    };
    // Optional: hears multicast answers from responders that ignore the
    // legacy-unicast rule. Fails harmlessly if the port can't be shared.
    let listen = listen_socket(iface);

    let mut db = Records::default();
    let mut asked: HashMap<(String, u16), u8> = HashMap::new();
    let reverse: Vec<String> = targets
        .iter()
        .filter(|ip| ip.is_private() || ip.is_link_local())
        .take(MAX_REVERSE)
        .map(|ip| reverse_name(*ip))
        .collect();

    let start = Instant::now();
    let end = start + LISTEN;
    let mut round = 0;
    let mut b1 = vec![0u8; 9000];
    let mut b2 = vec![0u8; 9000];
    loop {
        let next = ROUNDS
            .get(round)
            .map(|ms| start + Duration::from_millis(*ms))
            .unwrap_or(end);
        tokio::select! {
            r = query.recv_from(&mut b1) => {
                if let Ok((n, from)) = r {
                    db.absorb(&b1[..n], from);
                }
            }
            r = recv_opt(listen.as_ref(), &mut b2) => {
                if let Ok((n, from)) = r {
                    db.absorb(&b2[..n], from);
                }
            }
            _ = sleep_until(next) => {
                if round >= ROUNDS.len() {
                    break;
                }
                let pkts = if round <= 1 {
                    // Sent twice: UDP multicast on Wi-Fi drops packets.
                    // `_services` goes alone: small embedded responders
                    // only answer the first question of a packet.
                    let common: Vec<(String, u16)> =
                        COMMON_SERVICES.iter().map(|s| (format!("{s}.local"), T_PTR)).collect();
                    let rev: Vec<(String, u16)> = reverse.iter().map(|r| (r.clone(), T_PTR)).collect();
                    let mut p = build_queries(&[("_services._dns-sd._udp.local".into(), T_PTR)]);
                    p.extend(build_queries(&common));
                    p.extend(build_queries(&rev));
                    p
                } else {
                    // Follow-ups are few; one question per packet.
                    db.follow_ups(&mut asked)
                        .into_iter()
                        .flat_map(|q| build_queries(&[q]))
                        .collect()
                };
                for pkt in pkts {
                    let _ = query.send_to(&pkt, SocketAddrV4::new(GROUP, PORT)).await;
                }
                round += 1;
            }
        }
    }
    db.into_map()
}

async fn recv_opt(s: Option<&UdpSocket>, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    match s {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

fn query_socket(iface: Ipv4Addr) -> Option<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
        .ok()?;
    if !iface.is_unspecified() {
        let _ = s.set_multicast_if_v4(&iface);
    }
    let _ = s.set_multicast_ttl_v4(255);
    // Lets this machine's own responder (avahi, Bonjour, Windows) answer too.
    let _ = s.set_multicast_loop_v4(true);
    s.set_nonblocking(true).ok()?;
    UdpSocket::from_std(s.into()).ok()
}

fn listen_socket(iface: Ipv4Addr) -> Option<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    s.set_reuse_address(true).ok()?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    let _ = s.set_reuse_port(true);
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)).into())
        .ok()?;
    s.join_multicast_v4(&GROUP, &iface).ok()?;
    s.set_nonblocking(true).ok()?;
    UdpSocket::from_std(s.into()).ok()
}

fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Pack questions into as few packets as fit. The unicast-response (QU) bit
/// is set; queries also come from an ephemeral port, so RFC 6762 responders
/// reply straight to us ("legacy unicast").
fn build_queries(qs: &[(String, u16)]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body = Vec::new();
    let mut count: u16 = 0;
    let flush = |body: &mut Vec<u8>, count: &mut u16, out: &mut Vec<Vec<u8>>| {
        if *count > 0 {
            let mut p = vec![0x6d, 0x64, 0, 0];
            p.extend_from_slice(&count.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            p.append(body);
            out.push(p);
            *count = 0;
        }
    };
    for (name, qtype) in qs {
        let mut q = Vec::new();
        encode_dns_name(name, &mut q);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&0x8001u16.to_be_bytes()); // QU, IN
        if 12 + body.len() + q.len() > MAX_PACKET {
            flush(&mut body, &mut count, &mut out);
        }
        body.extend_from_slice(&q);
        count += 1;
    }
    flush(&mut body, &mut count, &mut out);
    out
}

// ---------------------------------------------------------------- records

#[derive(Debug, PartialEq)]
enum RData {
    A(Ipv4Addr),
    Ptr(String),
    Srv { port: u16, target: String },
    Txt(Vec<String>),
    Other,
}

#[derive(Debug)]
struct Record {
    name: String,
    data: RData,
}

/// Every resource record in the answer, authority and additional sections.
fn parse_records(pkt: &[u8]) -> Vec<Record> {
    let mut out = Vec::new();
    if pkt.len() < 12 || pkt[2] & 0x80 == 0 {
        return out; // not a response
    }
    let n = |i: usize| u16::from_be_bytes([pkt[i], pkt[i + 1]]) as usize;
    let (qd, total) = (n(4), n(6) + n(8) + n(10));
    let mut pos = 12;
    for _ in 0..qd {
        match read_dns_name(pkt, pos) {
            Some((_, p)) => pos = p + 4,
            None => return out,
        }
    }
    for _ in 0..total {
        let Some((name, p)) = read_dns_name(pkt, pos) else {
            break;
        };
        let Some(hdr) = pkt.get(p..p + 10) else {
            break;
        };
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
        let rd = p + 10;
        let Some(raw) = pkt.get(rd..rd + rdlen) else {
            break;
        };
        let data = match rtype {
            T_A if rdlen == 4 => RData::A(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
            T_PTR => read_dns_name(pkt, rd).map_or(RData::Other, |(n, _)| RData::Ptr(n)),
            T_SRV if rdlen > 6 => {
                read_dns_name(pkt, rd + 6).map_or(RData::Other, |(t, _)| RData::Srv {
                    port: u16::from_be_bytes([raw[4], raw[5]]),
                    target: t,
                })
            }
            T_TXT => {
                let mut v = Vec::new();
                let mut i = 0;
                while let Some(&len) = raw.get(i) {
                    if let Some(s) = raw.get(i + 1..i + 1 + len as usize)
                        && !s.is_empty()
                    {
                        v.push(String::from_utf8_lossy(s).into_owned());
                    }
                    i += 1 + len as usize;
                }
                RData::Txt(v)
            }
            _ => RData::Other,
        };
        out.push(Record { name, data });
        pos = rd + rdlen;
    }
    out
}

/// DNS names compare case-insensitively; maps are keyed on this form while
/// display names keep their original spelling.
fn key(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Default)]
struct Records {
    /// host name (lowercase key) -> (display name, addresses)
    a: HashMap<String, (String, BTreeSet<Ipv4Addr>)>,
    /// service type -> instance full names
    ptr: HashMap<String, BTreeSet<String>>,
    /// instance full name (key) -> (display name, port, target host key)
    srv: HashMap<String, (String, u16, String)>,
    txt: HashMap<String, Vec<String>>,
    /// address -> reverse-lookup name
    rev: HashMap<Ipv4Addr, String>,
    /// service types learned from `_services._dns-sd._udp` (key -> as sent;
    /// some responders match names case-sensitively)
    types: BTreeMap<String, String>,
    /// SRV target host key -> as sent
    targets: HashMap<String, String>,
    /// instance key -> address that sent the record (fallback for A)
    src: HashMap<String, Ipv4Addr>,
    responders: BTreeSet<Ipv4Addr>,
}

impl Records {
    fn absorb(&mut self, pkt: &[u8], from: SocketAddr) {
        let src = match from.ip() {
            std::net::IpAddr::V4(v) => v,
            _ => return,
        };
        let recs = parse_records(pkt);
        if recs.is_empty() {
            return;
        }
        self.responders.insert(src);
        for r in recs {
            let k = key(&r.name);
            match r.data {
                RData::A(ip) => {
                    let e = self.a.entry(k).or_insert_with(|| {
                        (r.name.trim_end_matches('.').to_string(), BTreeSet::new())
                    });
                    e.1.insert(ip);
                }
                RData::Ptr(target) => {
                    if k == "_services._dns-sd._udp.local" {
                        self.types
                            .insert(key(&target), target.trim_end_matches('.').to_string());
                    } else if let Some(ip) = parse_reverse(&k) {
                        self.rev
                            .insert(ip, target.trim_end_matches('.').to_string());
                    } else {
                        self.src.entry(key(&target)).or_insert(src);
                        self.ptr
                            .entry(k)
                            .or_default()
                            .insert(target.trim_end_matches('.').to_string());
                    }
                }
                RData::Srv { port, target } => {
                    self.src.entry(k.clone()).or_insert(src);
                    self.targets
                        .insert(key(&target), target.trim_end_matches('.').to_string());
                    self.srv.insert(
                        k,
                        (r.name.trim_end_matches('.').to_string(), port, key(&target)),
                    );
                }
                RData::Txt(v) => {
                    if !v.is_empty() {
                        self.txt.insert(k, v);
                    }
                }
                RData::Other => {}
            }
        }
    }

    /// Questions for anything referenced but not yet resolved; each is
    /// asked at most twice.
    fn follow_ups(&self, asked: &mut HashMap<(String, u16), u8>) -> Vec<(String, u16)> {
        let mut q = Vec::new();
        let mut ask = |name: &str, t: u16| {
            let n = asked.entry((name.to_string(), t)).or_default();
            if *n < 2 {
                *n += 1;
                q.push((name.to_string(), t));
            }
        };
        for (k, t) in &self.types {
            if !self.ptr.contains_key(k) {
                ask(t, T_PTR);
            }
        }
        for inst in self.ptr.values().flatten() {
            let k = key(inst);
            if !self.srv.contains_key(&k) {
                ask(inst, T_SRV);
            }
            if !self.txt.contains_key(&k) {
                ask(inst, T_TXT);
            }
        }
        for (_, _, target) in self.srv.values() {
            if !self.a.contains_key(target) {
                ask(self.targets.get(target).unwrap_or(target), T_A);
            }
        }
        q
    }

    fn into_map(self) -> MdnsMap {
        let mut m = MdnsMap::new();
        for ip in &self.responders {
            m.entry(*ip).or_default().responded = true;
        }
        for (ip, name) in &self.rev {
            m.entry(*ip).or_default().hostname = Some(name.clone());
        }
        for (name, ips) in self.a.values() {
            for ip in ips {
                let h = m.entry(*ip).or_default();
                // Prefer the shortest `.local` name if a host has several.
                if h.hostname.as_ref().is_none_or(|n| n.len() > name.len()) {
                    h.hostname = Some(name.clone());
                }
            }
        }
        // Every instance, with its type, whether it was browsed or just
        // came along as an additional record.
        let mut kinds: HashMap<String, String> = HashMap::new();
        for (t, insts) in &self.ptr {
            for i in insts {
                let t = self.types.get(t).unwrap_or(t);
                kinds.insert(key(i), t.trim_end_matches(".local").to_string());
            }
        }
        for (ik, (full, port, target)) in &self.srv {
            let kind = kinds.get(ik).cloned().unwrap_or_else(|| kind_of(ik));
            let instance = instance_of(full, &kind);
            let ips: Vec<Ipv4Addr> = match self.a.get(target) {
                Some((_, ips)) => ips.iter().copied().collect(),
                None => self.src.get(ik).copied().into_iter().collect(),
            };
            let txt = self.txt.get(ik);
            for ip in ips {
                let h = m.entry(ip).or_default();
                let svc = MdnsService {
                    kind: kind.clone(),
                    instance: instance.clone(),
                    port: *port,
                };
                if !h.services.contains(&svc) {
                    h.services.push(svc);
                }
                if h.hostname.is_none()
                    && let Some((n, _)) = self.a.get(target)
                {
                    h.hostname = Some(n.clone());
                }
                if let Some(t) = txt {
                    if h.model.is_none() {
                        h.model = model_from_txt(&kind, t);
                    }
                    if kind == "_googlecast._tcp"
                        && let Some(f) = txt_val(t, "fn")
                    {
                        h.friendly = Some(f);
                    }
                }
            }
        }
        // Instances seen only via PTR (no SRV): still useful as a name.
        for (ik, src) in &self.src {
            if self.srv.contains_key(ik) {
                continue;
            }
            if let Some(kind) = kinds.get(ik) {
                let h = m.entry(*src).or_default();
                let full = self
                    .ptr
                    .values()
                    .flatten()
                    .find(|i| key(i) == *ik)
                    .cloned()
                    .unwrap_or_default();
                let svc = MdnsService {
                    kind: kind.clone(),
                    instance: instance_of(&full, kind),
                    port: 0,
                };
                if !h.services.contains(&svc) {
                    h.services.push(svc);
                }
            }
        }
        // `_device-info._tcp` is TXT-only (model=MacBookPro18,1).
        for (ik, t) in &self.txt {
            if ik.ends_with("._device-info._tcp.local")
                && let Some(ip) = self.src.get(ik).or_else(|| {
                    let host = ik.trim_end_matches("._device-info._tcp.local");
                    self.a
                        .get(&format!("{host}.local"))
                        .and_then(|(_, s)| s.first())
                })
                && let Some(model) = txt_val(t, "model")
            {
                m.entry(*ip).or_default().model = Some(model);
            }
        }
        for h in m.values_mut() {
            // Some responders publish a bare SRV target ("beast").
            if let Some(n) = &mut h.hostname
                && !n.contains('.')
            {
                n.push_str(".local");
            }
            h.services
                .sort_by(|a, b| a.kind.cmp(&b.kind).then(a.port.cmp(&b.port)));
            if h.friendly.is_none() {
                h.friendly = friendly_name(&h.services);
            }
            if h.mac.is_none() {
                h.mac = h
                    .services
                    .iter()
                    .find(|s| s.kind == "_workstation._tcp")
                    .and_then(|s| workstation_mac(&s.instance));
            }
        }
        m
    }
}

fn parse_reverse(name: &str) -> Option<Ipv4Addr> {
    let rest = name.strip_suffix(".in-addr.arpa")?;
    let o: Vec<u8> = rest
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    (o.len() == 4).then(|| Ipv4Addr::new(o[3], o[2], o[1], o[0]))
}

/// `Living Room._airplay._tcp.local` -> `_airplay._tcp`
fn kind_of(instance_key: &str) -> String {
    let parts: Vec<&str> = instance_key.trim_end_matches(".local").split('.').collect();
    let n = parts.len();
    if n >= 2 && parts[n - 2].starts_with('_') {
        format!("{}.{}", parts[n - 2], parts[n - 1])
    } else {
        String::new()
    }
}

/// `Living Room._airplay._tcp.local` -> `Living Room` (instance labels may
/// contain dots, so strip the known suffix instead of splitting).
fn instance_of(full: &str, kind: &str) -> String {
    let suffix = format!(".{kind}.local").to_ascii_lowercase();
    let lower = full.to_ascii_lowercase();
    if !kind.is_empty() && lower.ends_with(&suffix) {
        full[..full.len() - suffix.len()].to_string()
    } else {
        full.to_string()
    }
}

fn txt_val(txt: &[String], k: &str) -> Option<String> {
    txt.iter().find_map(|kv| {
        let (a, b) = kv.split_once('=')?;
        (a.eq_ignore_ascii_case(k) && !b.trim().is_empty()).then(|| b.trim().to_string())
    })
}

fn model_from_txt(kind: &str, txt: &[String]) -> Option<String> {
    let keys: &[&str] = match kind {
        "_googlecast._tcp" => &["md"],
        "_airplay._tcp" | "_raop._tcp" => &["model", "am"],
        "_ipp._tcp"
        | "_ipps._tcp"
        | "_printer._tcp"
        | "_pdl-datastream._tcp"
        | "_uscan._tcp"
        | "_scanner._tcp" => &["ty", "usb_MDL", "product"],
        "_hap._tcp" | "_hap._udp" => &["md"],
        "_esphomelib._tcp" => &["board", "platform"],
        "_shelly._tcp" => &["app", "gen"],
        _ => &["model", "md"],
    };
    keys.iter()
        .find_map(|k| txt_val(txt, k))
        .map(|m| m.trim_matches(|c| c == '(' || c == ')').to_string())
}

/// Best advertised human name, by how reliably each type carries one.
fn friendly_name(services: &[MdnsService]) -> Option<String> {
    const ORDER: &[&str] = &[
        "_device-info._tcp",
        "_companion-link._tcp",
        "_airplay._tcp",
        "_raop._tcp",
        "_googlecast._tcp",
        "_amzn-wplay._tcp",
        "_spotify-connect._tcp",
        "_ipp._tcp",
        "_printer._tcp",
        "_pdl-datastream._tcp",
        "_hap._tcp",
        "_smb._tcp",
        "_afpovertcp._tcp",
        "_workstation._tcp",
        "_esphomelib._tcp",
        "_shelly._tcp",
        "_http._tcp",
    ];
    let pick = |s: &MdnsService| -> Option<String> {
        let name = match s.kind.as_str() {
            // `AABBCCDDEEFF@Kitchen`
            "_raop._tcp" => s.instance.split_once('@').map_or(&*s.instance, |(_, n)| n),
            // `host [aa:bb:cc:dd:ee:ff]`
            "_workstation._tcp" => s.instance.split(" [").next().unwrap_or(&s.instance),
            // Chromecast instances are `Model-<uuid>`; `fn=` is used instead.
            "_googlecast._tcp" => return None,
            _ => &s.instance,
        };
        let name = name.trim();
        (!name.is_empty()).then(|| name.to_string())
    };
    ORDER
        .iter()
        .find_map(|k| services.iter().filter(|s| s.kind == *k).find_map(pick))
        // Unknown types are often random app IDs (adb, Spotify) whose
        // instance names are tokens, not names.
        .or_else(|| {
            services
                .iter()
                .filter(|s| service_label(&s.kind) != "Service")
                .find_map(pick)
        })
}

fn workstation_mac(instance: &str) -> Option<String> {
    let inner = instance.rsplit_once('[')?.1.strip_suffix(']')?;
    let parts: Vec<&str> = inner.split(':').collect();
    (parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok()))
    .then(|| inner.to_ascii_uppercase())
}

/// Short human label for a DNS-SD service type.
pub fn service_label(kind: &str) -> &'static str {
    match kind.to_ascii_lowercase().as_str() {
        "_airplay._tcp" => "AirPlay",
        "_raop._tcp" => "AirPlay audio",
        "_companion-link._tcp" => "Apple Companion",
        "_apple-mobdev2._tcp" => "Apple device sync",
        "_rdlink._tcp" => "Apple Remote",
        "_device-info._tcp" => "Device info",
        "_sleep-proxy._udp" => "Bonjour sleep proxy",
        "_homekit._tcp" | "_hap._tcp" | "_hap._udp" => "HomeKit",
        "_googlecast._tcp" => "Google Cast",
        "_androidtvremote2._tcp" => "Android TV remote",
        "_amzn-wplay._tcp" => "Amazon Fire TV",
        "_spotify-connect._tcp" => "Spotify Connect",
        "_sonos._tcp" => "Sonos",
        "_ipp._tcp" => "IPP printer",
        "_ipps._tcp" => "IPP printer (TLS)",
        "_printer._tcp" => "LPD printer",
        "_pdl-datastream._tcp" => "Raw printer",
        "_scanner._tcp" | "_uscan._tcp" => "Scanner",
        "_smb._tcp" => "SMB file share",
        "_afpovertcp._tcp" => "AFP file share",
        "_nfs._tcp" => "NFS",
        "_ssh._tcp" => "SSH",
        "_sftp-ssh._tcp" => "SFTP",
        "_http._tcp" => "Web",
        "_https._tcp" => "Web (TLS)",
        "_workstation._tcp" => "Workstation",
        "_esphomelib._tcp" => "ESPHome",
        "_shelly._tcp" => "Shelly",
        "_hue._tcp" => "Philips Hue",
        "_matter._tcp" | "_matterc._udp" => "Matter",
        "_meshcop._udp" => "Thread border router",
        "_home-assistant._tcp" => "Home Assistant",
        "_mqtt._tcp" => "MQTT",
        "_arduino._tcp" => "Arduino",
        "_octoprint._tcp" => "OctoPrint",
        "_miio._udp" => "Xiaomi",
        "_daap._tcp" => "iTunes sharing",
        "_nvstream._tcp" => "NVIDIA GameStream",
        "_rfb._tcp" => "VNC",
        _ => "Service",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(out: &mut Vec<u8>, name: &str, t: u16, rdata: &[u8]) {
        encode_dns_name(name, out);
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&[0x80, 1, 0, 0, 0x11, 0x94]);
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    fn name(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        encode_dns_name(n, &mut v);
        v
    }

    #[test]
    fn full_browse_response() {
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 3];
        rr(
            &mut p,
            "_airplay._tcp.local",
            T_PTR,
            &name("Living Room._airplay._tcp.local"),
        );
        rr(
            &mut p,
            "_device-info._tcp.local",
            T_PTR,
            &name("Living Room._device-info._tcp.local"),
        );
        let mut srv = vec![0, 0, 0, 0, 0x1b, 0x58];
        srv.extend(name("Apple-TV.local"));
        rr(&mut p, "Living Room._airplay._tcp.local", T_SRV, &srv);
        rr(&mut p, "Apple-TV.local", T_A, &[192, 168, 1, 40]);
        rr(
            &mut p,
            "Living Room._device-info._tcp.local",
            T_TXT,
            b"\x11model=AppleTV11,1",
        );

        let mut db = Records::default();
        db.absorb(&p, "192.168.1.40:5353".parse().unwrap());
        let m = db.into_map();
        let h = &m[&Ipv4Addr::new(192, 168, 1, 40)];
        assert!(h.responded);
        assert_eq!(h.hostname.as_deref(), Some("Apple-TV.local"));
        assert_eq!(h.friendly.as_deref(), Some("Living Room"));
        assert_eq!(h.model.as_deref(), Some("AppleTV11,1"));
        assert_eq!(
            h.services,
            vec![
                MdnsService {
                    kind: "_airplay._tcp".into(),
                    instance: "Living Room".into(),
                    port: 7000
                },
                MdnsService {
                    kind: "_device-info._tcp".into(),
                    instance: "Living Room".into(),
                    port: 0
                }
            ]
        );
    }

    #[test]
    fn reverse_and_workstation() {
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        rr(
            &mut p,
            "20.1.168.192.in-addr.arpa",
            T_PTR,
            &name("nas.local"),
        );
        rr(
            &mut p,
            "_workstation._tcp.local",
            T_PTR,
            &name("nas [b8:27:eb:01:02:03]._workstation._tcp.local"),
        );
        rr(
            &mut p,
            "_services._dns-sd._udp.local",
            T_PTR,
            &name("_smb._tcp.local"),
        );
        let mut db = Records::default();
        db.absorb(&p, "192.168.1.20:5353".parse().unwrap());
        let mut asked = HashMap::new();
        let q = db.follow_ups(&mut asked);
        assert!(q.contains(&("_smb._tcp.local".into(), T_PTR)));
        assert!(q.contains(&(
            "nas [b8:27:eb:01:02:03]._workstation._tcp.local".into(),
            T_SRV
        )));
        // Unanswered questions are retried once, then dropped.
        assert!(!db.follow_ups(&mut asked).is_empty());
        assert!(db.follow_ups(&mut asked).is_empty());
        let m = db.into_map();
        let h = &m[&Ipv4Addr::new(192, 168, 1, 20)];
        assert_eq!(h.hostname.as_deref(), Some("nas.local"));
        assert_eq!(h.mac.as_deref(), Some("B8:27:EB:01:02:03"));
        assert_eq!(h.friendly.as_deref(), Some("nas"));
    }

    #[test]
    fn queries_split_and_parse_back() {
        let qs: Vec<(String, u16)> = (0..300)
            .map(|i| (reverse_name(Ipv4Addr::new(10, 0, 1, i as u8)), T_PTR))
            .collect();
        let pkts = build_queries(&qs);
        assert!(pkts.len() > 1);
        assert!(pkts.iter().all(|p| p.len() <= MAX_PACKET));
        let total: usize = pkts
            .iter()
            .map(|p| u16::from_be_bytes([p[4], p[5]]) as usize)
            .sum();
        assert_eq!(total, 300);
        assert_eq!(
            parse_reverse("5.1.0.10.in-addr.arpa"),
            Some(Ipv4Addr::new(10, 0, 1, 5))
        );
        assert_eq!(kind_of("tv._googlecast._tcp.local"), "_googlecast._tcp");
    }
}

#[cfg(test)]
mod live {
    #[test]
    #[ignore = "needs a LAN"]
    fn live_discover() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let iface = crate::netinfo::local_interfaces()
            .into_iter()
            .next()
            .map(|l| l.ip);
        let m = rt.block_on(super::discover(iface, &[]));
        for (ip, h) in &m {
            eprintln!("{ip} {h:?}");
        }
    }
}
