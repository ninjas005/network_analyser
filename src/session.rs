//! The capture session shared by all packet-analysis tools: one live capture
//! or opened file, its packets, and everything derived from them.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use gpui::{App, AppContext, Context, Entity, EventEmitter, Global, SharedString, Task};

use crate::capture::{
    self, CaptureConfig, CaptureEvent, CaptureHandle, Interface, Limits, Packet, Source,
};
use crate::dnsmon::Monitor;
use crate::httpstream::Exchange;
use crate::pcapfile::FileInfo;
use crate::pktstats::PacketStats;
use crate::streams::Tracker;
use crate::tools::Tool;

/// Packets kept for display; statistics keep counting beyond this.
pub const MAX_PACKETS: usize = 200_000;
/// Time per update spent on new packets, so the window stays responsive.
const WORK: Duration = Duration::from_millis(40);

/// Packets and the analysis of them (no UI).
#[derive(Default)]
pub struct Analysis {
    pub packets: Vec<Packet>,
    /// TCP stream of each packet.
    pub stream_of: Vec<Option<u32>>,
    /// Packets counted but not kept.
    pub not_kept: u64,
    pub stats: PacketStats,
    pub tcp: Tracker,
    pub dns: Monitor,
}

impl Analysis {
    pub fn add(&mut self, mut p: Packet) {
        self.stats.add(&p);
        self.dns.add(&p);
        if self.packets.len() >= MAX_PACKETS {
            self.not_kept += 1;
            self.tcp.add(&self.packets, &p, None);
            return;
        }
        // Decoded again when the packet is opened.
        p.d.dns = None;
        let i = self.packets.len();
        self.packets.push(p);
        let id = self.tcp.add(&self.packets, &self.packets[i], Some(i));
        self.stream_of.push(id.map(|n| n as u32));
    }

    pub fn finish(&mut self) {
        self.tcp.finish(&self.packets);
        self.dns.finish();
    }

    /// Every HTTP exchange with its stream, in stream order.
    pub fn http(&self) -> impl Iterator<Item = (usize, &Exchange)> {
        self.tcp.streams.iter().flat_map(|s| {
            s.http
                .iter()
                .flat_map(|h| h.exchanges.iter())
                .map(|e| (s.id, e))
        })
    }
}

/// Emitted to switch to another tool (e.g. "Follow stream").
pub struct OpenTool(pub Tool);

pub struct Session {
    pub ifaces: Result<Vec<Interface>, String>,
    pub iface: Option<usize>,
    /// Capture filter for live captures / for opened files.
    pub bpf: String,
    pub file_bpf: String,
    pub promisc: bool,
    pub save: bool,
    pub limits: Limits,
    handle: Option<CaptureHandle>,
    pub a: Analysis,
    pub info: Option<FileInfo>,
    /// A file is (being) shown, not a live capture.
    pub is_file: bool,
    pub source: String,
    pub pcap_stats: Option<(u32, u32, u32)>,
    pub status: SharedString,
    pub error: Option<String>,
    pub started: Option<Instant>,
    /// Changes when the packets are replaced.
    pub generation: u64,
    /// Stream to show in the stream tools.
    pub stream: Option<usize>,
    /// Packet to select in the packet list.
    pub goto: Option<usize>,
    queue: VecDeque<Packet>,
    ended: Option<Option<String>>,
    _poll: Option<Task<()>>,
}

impl EventEmitter<OpenTool> for Session {}

struct Shared(Entity<Session>);
impl Global for Shared {}

impl Session {
    /// The session of this app, created on first use.
    pub fn shared(cx: &mut App) -> Entity<Session> {
        if let Some(s) = cx.try_global::<Shared>() {
            return s.0.clone();
        }
        let e = cx.new(|_| Session::new());
        cx.set_global(Shared(e.clone()));
        e
    }

    fn new() -> Self {
        let ifaces = capture::interfaces();
        // Default to the interface carrying the default route.
        let primary = crate::netinfo::local_interfaces()
            .into_iter()
            .next()
            .map(|i| i.ip.to_string());
        let iface = ifaces.as_ref().ok().and_then(|l| {
            l.iter()
                .position(|i| primary.as_ref().is_some_and(|p| i.addrs.contains(p)))
                .or((!l.is_empty()).then_some(0))
        });
        let status = match &ifaces {
            Ok(l) => format!(
                "{} capture interfaces. Start a capture or open a file.",
                l.len()
            ),
            Err(e) => format!("Live capture unavailable: {e}"),
        };
        Session {
            ifaces,
            iface,
            bpf: String::new(),
            file_bpf: String::new(),
            promisc: true,
            save: false,
            limits: Limits::default(),
            handle: None,
            a: Analysis::default(),
            info: None,
            is_file: false,
            source: String::new(),
            pcap_stats: None,
            status: status.into(),
            error: None,
            started: None,
            generation: 0,
            stream: None,
            goto: None,
            queue: VecDeque::new(),
            ended: None,
            _poll: None,
        }
    }

    pub fn running(&self) -> bool {
        self.handle.is_some()
    }

    pub fn live(&self) -> bool {
        self.running() && !self.is_file
    }

    pub fn iface_label(&self) -> String {
        match (&self.ifaces, self.iface) {
            (Ok(l), Some(i)) => l.get(i).map(|i| i.label()).unwrap_or_default(),
            (Ok(_), None) => "Select interface".into(),
            (Err(_), _) => "Capture unavailable".into(),
        }
    }

    pub fn clear(&mut self) {
        self.a = Analysis::default();
        self.info = None;
        self.pcap_stats = None;
        self.error = None;
        self.stream = None;
        self.goto = None;
        self.queue.clear();
        self.generation += 1;
        if !self.running() {
            self.source.clear();
        }
    }

    pub fn start_live(&mut self, cx: &mut Context<Self>) {
        if self.running() {
            return;
        }
        let Some(iface) = self
            .iface
            .and_then(|i| self.ifaces.as_ref().ok()?.get(i).cloned())
        else {
            self.error = Some(match &self.ifaces {
                Err(e) => e.clone(),
                Ok(_) => "Select a capture interface first".into(),
            });
            cx.notify();
            return;
        };
        let save_to = self.save.then(|| {
            crate::platform::home_dir()
                .unwrap_or_else(|| ".".into())
                .join(format!("capture-{}.pcap", unix_now()))
        });
        self.is_file = false;
        self.begin(
            CaptureConfig {
                source: Source::Live {
                    device: iface.name.clone(),
                    promisc: self.promisc,
                },
                filter: self.bpf.clone(),
                save_to: save_to.clone(),
            },
            cx,
        );
        self.source = iface.label();
        self.status = match save_to {
            Some(p) => format!("Capturing on {} → {}", iface.label(), p.display()),
            None => format!("Capturing on {}", iface.label()),
        }
        .into();
    }

    /// Open a capture file. Stops a running capture first.
    pub fn open(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        // Dropping the handle stops its thread.
        self.handle = None;
        self.is_file = true;
        self.begin(
            CaptureConfig {
                source: Source::File(path.clone()),
                filter: self.file_bpf.clone(),
                save_to: None,
            },
            cx,
        );
        self.source = path.display().to_string();
        self.status = format!("Reading {}", path.display()).into();
        let shown = path.display().to_string();
        let _ = crate::settings::update(|s| {
            s.recent_captures.retain(|p| *p != shown);
            s.recent_captures.insert(0, shown);
            s.recent_captures.truncate(8);
        });
    }

    /// Ask for a file with the system's file picker.
    pub fn browse(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(gpui::PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Open".into()),
        });
        cx.spawn(async move |this, cx| {
            let picked = match rx.await {
                Ok(Ok(Some(mut paths))) if !paths.is_empty() => Ok(paths.remove(0)),
                Ok(Ok(_)) | Err(_) => return,
                Ok(Err(e)) => Err(format!(
                    "File picker unavailable ({e}); type the path in the PCAP Viewer instead"
                )),
            };
            this.update(cx, |t, cx| {
                match picked {
                    Ok(p) => t.open(p, cx),
                    Err(e) => t.error = Some(e),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn begin(&mut self, cfg: CaptureConfig, cx: &mut Context<Self>) {
        let limits = if self.is_file {
            Limits::default()
        } else {
            self.limits
        };
        self.clear();
        self.ended = None;
        self.handle = Some(capture::start_brief(cfg, limits));
        self.started = Some(Instant::now());
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                // Work in slices while there is a backlog.
                loop {
                    match this.update(cx, |t, cx| t.drain(cx)) {
                        Ok(Step::Wait) => break,
                        Ok(Step::More) => {
                            cx.background_executor()
                                .timer(Duration::from_millis(4))
                                .await
                        }
                        _ => return,
                    }
                }
            }
        }));
        cx.notify();
    }

    pub fn stop(&mut self) {
        if let Some(h) = &self.handle {
            h.stop();
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> Step {
        let t0 = Instant::now();
        let Some(h) = &self.handle else {
            return Step::Done;
        };
        let mut got = false;
        while t0.elapsed() < WORK {
            if let Some(p) = self.queue.pop_front() {
                self.a.add(p);
                got = true;
                continue;
            }
            match h.events.try_recv() {
                Ok(CaptureEvent::Packets(p)) => self.queue.extend(p),
                Ok(CaptureEvent::Stats {
                    received,
                    dropped,
                    if_dropped,
                }) => self.pcap_stats = Some((received, dropped, if_dropped)),
                Ok(CaptureEvent::FileInfo(i)) => self.info = Some(*i),
                Ok(CaptureEvent::InjectFailed(_) | CaptureEvent::Started { .. }) => {}
                Ok(CaptureEvent::Stopped(e)) => {
                    self.ended = Some(e);
                    break;
                }
                Err(_) => break,
            }
        }
        if let Some(err) = self.ended.take() {
            self.handle = None;
            self.started = None;
            self.a.finish();
            self.status = match err {
                Some(e) => {
                    self.error = Some(match capture::permission_hint(&e) {
                        Some(h) if !self.is_file => format!("{e}\n{h}"),
                        _ => e.clone(),
                    });
                    if self.is_file {
                        format!("Could not read the file: {e}").into()
                    } else {
                        format!("Capture failed: {e}").into()
                    }
                }
                None => {
                    let (verb, filter) = if self.is_file {
                        ("Loaded", self.file_bpf.trim())
                    } else {
                        ("Stopped —", self.bpf.trim())
                    };
                    let filter = match filter {
                        "" => String::new(),
                        f => format!(" (capture filter: {f})"),
                    };
                    format!(
                        "{verb} {} packets from {}{filter}",
                        self.a.stats.packets, self.source
                    )
                    .into()
                }
            };
            if let Some(p) = self.info.as_ref().and_then(|i| i.problem.clone()) {
                self.error = Some(format!("Damaged file: {p}. Packets before that were read."));
            }
            cx.notify();
            return Step::Done;
        }
        if got || self.live() {
            cx.notify();
        }
        if t0.elapsed() >= WORK {
            Step::More
        } else {
            Step::Wait
        }
    }

    /// Save packets (indices) to the home directory.
    pub fn save_packets(&mut self, idx: &[usize]) {
        if idx.is_empty() {
            self.status = "Nothing to save".into();
            return;
        }
        let pkts: Vec<&Packet> = idx.iter().map(|&i| &self.a.packets[i]).collect();
        // pcapng when a plain pcap could not hold everything.
        let ng = pkts
            .iter()
            .any(|p| p.linktype != pkts[0].linktype || p.comment.is_some());
        let path = crate::platform::home_dir()
            .unwrap_or_else(|| ".".into())
            .join(format!(
                "packets-{}.{}",
                unix_now(),
                if ng { "pcapng" } else { "pcap" }
            ));
        self.status = match capture::write_packets(&path, &pkts) {
            Ok(()) => format!("Saved {} packets to {}", pkts.len(), path.display()).into(),
            Err(e) => format!("Save failed: {e}").into(),
        };
    }

    /// Write bytes to a new file in the home directory.
    pub fn save_bytes(&mut self, name: &str, ext: &str, data: &[u8]) {
        let path = crate::platform::home_dir()
            .unwrap_or_else(|| ".".into())
            .join(format!("{name}-{}.{ext}", unix_now()));
        self.status = match std::fs::write(&path, data) {
            Ok(()) => format!("Saved {} bytes to {}", data.len(), path.display()).into(),
            Err(e) => format!("Save failed: {e}").into(),
        };
    }
}

enum Step {
    Wait,
    More,
    Done,
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// When to end a capture: "1000" packets, "60s", "5min", "50MB".
pub fn parse_limit(s: &str) -> Result<Limits, String> {
    let mut l = Limits::default();
    for w in s.to_lowercase().split([' ', ',']).filter(|w| !w.is_empty()) {
        let at = w.find(|c: char| !c.is_ascii_digit()).unwrap_or(w.len());
        let bad = || format!("\"{w}\": use e.g. 1000 (packets), 60s, 5min or 50MB");
        let n: u64 = w[..at].parse().map_err(|_| bad())?;
        match &w[at..] {
            "" | "p" | "pkt" | "packets" => l.packets = Some(n),
            "s" | "sec" => l.seconds = Some(n),
            "m" | "min" => l.seconds = Some(n.saturating_mul(60)),
            "h" => l.seconds = Some(n.saturating_mul(3600)),
            "kb" => l.bytes = Some(n.saturating_mul(1 << 10)),
            "mb" => l.bytes = Some(n.saturating_mul(1 << 20)),
            "gb" => l.bytes = Some(n.saturating_mul(1 << 30)),
            _ => return Err(bad()),
        }
    }
    Ok(l)
}

/// Path typed by the user: quotes removed, `~/` expanded.
pub fn user_path(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim().trim_matches('"');
    if raw.is_empty() {
        return None;
    }
    Some(match raw.strip_prefix("~/") {
        Some(rest) => crate::platform::home_dir().unwrap_or_default().join(rest),
        None => PathBuf::from(raw),
    })
}

/// Display filter: (must match, lower-case term).
pub fn filter_terms(q: &str) -> Vec<(bool, String)> {
    q.split_whitespace()
        .map(|t| match t.strip_prefix('!') {
            Some(neg) => (false, neg.to_lowercase()),
            None => (true, t.to_lowercase()),
        })
        .filter(|(_, t)| !t.is_empty())
        .collect()
}

pub fn matches(p: &Packet, terms: &[(bool, String)]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let port = |p: Option<u16>| p.map(|p| p.to_string()).unwrap_or_default();
    let hay = format!(
        "{} {} {} {} {} {} {} {}",
        p.d.proto,
        p.d.path.join(" "),
        p.d.src,
        p.d.dst,
        port(p.d.src_port),
        port(p.d.dst_port),
        p.d.info,
        p.comment.as_deref().unwrap_or("")
    )
    .to_lowercase();
    terms
        .iter()
        .all(|(want, t)| hay.contains(t.as_str()) == *want)
}

/// UTC date and time of a capture timestamp.
pub fn format_ts(ts: f64) -> String {
    let (secs, us) = crate::pcapfile::split_ts(ts);
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!(
        "{} {h:02}:{m:02}:{s:02}.{us:06} UTC",
        crate::dns::unix_date(secs.min(u32::MAX as u64) as u32)
    )
}

/// Properties of a capture file for display.
pub fn file_info_rows(i: &FileInfo) -> Vec<(String, String)> {
    let mut r: Vec<(String, String)> = Vec::new();
    let mut add = |k: &str, v: String| {
        if !v.is_empty() {
            r.push((k.to_string(), v));
        }
    };
    add("File", i.path.display().to_string());
    add(
        "Format",
        format!(
            "{}{}, {}-endian",
            i.format,
            if i.gzip { ", gzip" } else { "" },
            if i.big_endian { "big" } else { "little" }
        ),
    );
    add("Size", crate::capture_view::human_bytes(i.size));
    add("Packets", i.packets.to_string());
    if i.cut > 0 {
        add("Cut by snap length", i.cut.to_string());
    }
    if let (Some(a), Some(b)) = (i.first, i.last) {
        add("First packet", format_ts(a));
        add("Last packet", format_ts(b));
        add("Duration", format!("{:.6} s", b - a));
    }
    add("Hardware", i.hardware.clone());
    add("Operating system", i.os.clone());
    add("Written by", i.application.clone());
    for c in &i.comments {
        add("Comment", c.clone());
    }
    if i.packet_comments > 0 {
        add("Packet comments", i.packet_comments.to_string());
    }
    for (n, f) in i.ifaces.iter().enumerate() {
        let mut parts = Vec::new();
        for s in [&f.name, &f.desc] {
            if !s.is_empty() {
                parts.push(s.clone());
            }
        }
        parts.push(crate::dissect::linktype_name(f.linktype).into());
        parts.push(format!("{} packets", f.packets));
        if f.snaplen > 0 {
            parts.push(format!("snap length {}", f.snaplen));
        }
        if f.ticks != 1_000_000 {
            parts.push(format!("{} ticks/s", f.ticks));
        }
        if let Some(s) = f.speed {
            parts.push(format!("{} Mbit/s", s / 1_000_000));
        }
        if !f.filter.is_empty() {
            parts.push(format!("filter \"{}\"", f.filter));
        }
        if !f.os.is_empty() {
            parts.push(f.os.clone());
        }
        if let Some(n) = f.received {
            parts.push(format!("{n} received"));
        }
        if let Some(n) = f.dropped {
            parts.push(format!("{n} dropped"));
        }
        add(&format!("Interface {n}"), parts.join(", "));
    }
    if !i.blocks.is_empty() {
        add(
            "Blocks",
            i.blocks
                .iter()
                .map(|(n, c)| format!("{n} ×{c}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    for (ip, name) in i.names.iter().take(50) {
        add("Name", format!("{ip} = {name}"));
    }
    if let Some(p) = &i.problem {
        add("Problem", p.clone());
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_match_protocol_path_ports_and_exclusions() {
        let f = crate::streams::tests::frame(true, 1, 0, 0x18, b"GET /x HTTP/1.1\r\n\r\n");
        let p = Packet {
            linktype: 1,
            d: crate::dissect::dissect(1, &f),
            data: f,
            ..Default::default()
        };
        for (q, want) in [
            ("http 10.0.0.2", true),
            ("TCP 80", true),
            ("ipv4 !dns", true),
            ("!http", false),
            ("", true),
            ("modbus", false),
        ] {
            assert_eq!(matches(&p, &filter_terms(q)), want, "{q}");
        }
    }

    #[test]
    fn capture_limits() {
        let l = parse_limit("1000, 5min 50MB").unwrap();
        assert_eq!(
            (l.packets, l.seconds, l.bytes),
            (Some(1000), Some(300), Some(50 << 20))
        );
        assert_eq!(parse_limit(" ").unwrap(), Limits::default());
        assert!(parse_limit("5 parsecs").is_err());
    }

    #[test]
    fn timestamps_have_a_date() {
        assert_eq!(
            format_ts(1_700_000_000.25),
            "2023-11-14 22:13:20.250000 UTC"
        );
    }
}
