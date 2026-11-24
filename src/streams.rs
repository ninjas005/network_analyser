//! TCP connection tracking: handshake and close analysis, loss and
//! retransmission counters, and reassembly of each direction's byte stream.
//! Reassembled data is kept as references into the packet list.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::appproto::{self, How};
use crate::capture::Packet;
use crate::dissect::{self, ACK, FIN, RST, SYN, TcpOpts};
use crate::gateway::Level;
use crate::httpstream::{Budget, HttpConn};

/// Connections tracked; later ones are only counted.
const MAX_STREAMS: usize = 50_000;
/// Segments waiting for missing data before the gap is accepted.
const MAX_PENDING: usize = 512;
/// Start of each direction kept for protocol identification.
const HEAD: usize = 4096;

pub const CLIENT: usize = 0;
pub const SERVER: usize = 1;

/// A piece of a direction's stream in delivery order.
#[derive(Clone, Copy, Debug)]
pub struct Chunk {
    pub dir: u8,
    pub ts: f64,
    /// Index in the packet list and byte range inside that packet.
    pub pkt: u32,
    pub off: u32,
    pub len: u32,
    /// Bytes missing from the capture here (then `len` is 0).
    pub gap: u64,
}

#[derive(Clone, Copy, Debug)]
struct Held {
    pkt: u32,
    off: u32,
    /// Captured / on-the-wire length.
    cap: u32,
    wire: u32,
    ts: f64,
}

#[derive(Clone, Debug, Default)]
pub struct Dir {
    pub packets: u64,
    /// Payload bytes including retransmissions.
    pub wire_bytes: u64,
    pub retrans: u64,
    pub out_of_order: u64,
    pub dup_acks: u64,
    pub zero_window: u64,
    pub keepalives: u64,
    /// Bytes the capture is missing.
    pub lost: u64,
    pub opts: TcpOpts,
    pub syn_window: u16,
    pub max_window: u64,
    pub fin: bool,
    /// Sequence number expected next, at stream offset `pos`.
    next: Option<u32>,
    pos: u64,
    /// Highest stream offset seen, and when.
    max_end: u64,
    max_ts: f64,
    /// Highest offset the other side acknowledged.
    acked: u64,
    pending: BTreeMap<u64, Held>,
    last_ack: Option<(u32, u16)>,
    head: Vec<u8>,
}

impl Dir {
    /// Reassembled bytes (gaps included).
    pub fn bytes(&self) -> u64 {
        self.pos
    }

    /// Stream offset of a sequence number; negative = before the start.
    fn offset(&self, seq: u32) -> Option<i64> {
        self.next
            .map(|n| self.pos as i64 + seq.wrapping_sub(n) as i32 as i64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsState {
    Complete,
    /// SYN answered by RST.
    Refused,
    NoAnswer,
    /// SYN/ACK never acknowledged.
    HalfOpen,
    /// Capture started after the SYN.
    Partial,
    Midstream,
}

impl HsState {
    pub const ALL: [HsState; 6] = [
        HsState::Complete,
        HsState::Refused,
        HsState::NoAnswer,
        HsState::HalfOpen,
        HsState::Partial,
        HsState::Midstream,
    ];
    pub fn label(self) -> &'static str {
        match self {
            HsState::Complete => "Complete",
            HsState::Refused => "Refused",
            HsState::NoAnswer => "No answer",
            HsState::HalfOpen => "Half-open",
            HsState::Partial => "SYN not captured",
            HsState::Midstream => "Mid-stream",
        }
    }
    pub fn level(self) -> Level {
        match self {
            HsState::Complete => Level::Good,
            HsState::Refused | HsState::NoAnswer => Level::Bad,
            HsState::HalfOpen => Level::Warn,
            HsState::Partial | HsState::Midstream => Level::Info,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    Open,
    /// One side sent FIN.
    Half(usize),
    Fin(usize),
    Reset(usize),
}

impl Close {
    pub fn label(self) -> &'static str {
        match self {
            Close::Open => "Open",
            Close::Half(CLIENT) => "Half-closed (client FIN)",
            Close::Half(_) => "Half-closed (server FIN)",
            Close::Fin(CLIENT) => "Closed, client first",
            Close::Fin(_) => "Closed, server first",
            Close::Reset(CLIENT) => "Reset by client",
            Close::Reset(_) => "Reset by server",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Handshake {
    pub syn_first: Option<f64>,
    /// Latest SYN before the SYN/ACK.
    pub syn_last: Option<f64>,
    pub syns: u32,
    pub synack: Option<f64>,
    pub synacks: u32,
    pub ack: Option<f64>,
    pub refused: bool,
    pub syn_data: bool,
    /// Packet numbers of SYN, SYN/ACK and ACK.
    pub nos: [Option<usize>; 3],
    client_isn: Option<u32>,
    server_isn: Option<u32>,
    pub ecn: bool,
}

impl Handshake {
    /// SYN → SYN/ACK: round trip to the server from the capture point.
    pub fn server_rtt(&self) -> Option<f64> {
        Some((self.synack? - self.syn_last?).max(0.0))
    }
    /// SYN/ACK → ACK: round trip to the client.
    pub fn client_rtt(&self) -> Option<f64> {
        Some((self.ack? - self.synack?).max(0.0))
    }
    /// First SYN → ACK, including SYN retransmissions.
    pub fn total(&self) -> Option<f64> {
        Some((self.ack? - self.syn_first?).max(0.0))
    }
}

pub struct Stream {
    pub id: usize,
    /// Client and server endpoints.
    pub ends: [(IpAddr, u16); 2],
    pub dirs: [Dir; 2],
    pub hs: Handshake,
    pub first: f64,
    pub last: f64,
    pub proto: String,
    pub how: Option<How>,
    pub sni: Option<String>,
    pub chunks: Vec<Chunk>,
    pub http: Option<Box<HttpConn>>,
    pub first_data: [Option<f64>; 2],
    /// Packets of this stream were not kept (list full): data is incomplete.
    pub cut: bool,
    fin_first: Option<usize>,
    reset: Option<usize>,
}

pub fn endpoint(e: (IpAddr, u16)) -> String {
    match e {
        (IpAddr::V6(a), p) => format!("[{a}]:{p}"),
        (a, p) => format!("{a}:{p}"),
    }
}

impl Stream {
    pub fn client(&self) -> String {
        endpoint(self.ends[CLIENT])
    }
    pub fn server(&self) -> String {
        endpoint(self.ends[SERVER])
    }
    pub fn duration(&self) -> f64 {
        (self.last - self.first).max(0.0)
    }
    pub fn packets(&self) -> u64 {
        self.dirs[0].packets + self.dirs[1].packets
    }
    pub fn retrans(&self) -> u64 {
        self.dirs[0].retrans + self.dirs[1].retrans
    }
    pub fn lost(&self) -> u64 {
        self.dirs[0].lost + self.dirs[1].lost
    }

    pub fn state(&self) -> HsState {
        let h = &self.hs;
        match (h.syns > 0, h.synack.is_some(), h.ack.is_some()) {
            (true, true, true) => HsState::Complete,
            (_, true, false) => HsState::HalfOpen,
            (false, true, true) => HsState::Partial,
            (true, false, _) if h.refused => HsState::Refused,
            // Data flowed although the SYN/ACK is missing from the capture.
            (true, false, _) if self.dirs[SERVER].packets > 0 => HsState::Partial,
            (true, false, _) => HsState::NoAnswer,
            (false, false, _) => HsState::Midstream,
        }
    }

    pub fn close(&self) -> Close {
        if let Some(d) = self.reset {
            return Close::Reset(d);
        }
        match (self.fin_first, self.dirs[0].fin && self.dirs[1].fin) {
            (Some(d), true) => Close::Fin(d),
            (Some(d), false) => Close::Half(d),
            _ => Close::Open,
        }
    }

    /// Observations about the handshake and connection health.
    pub fn findings(&self) -> Vec<(Level, String)> {
        let mut out = Vec::new();
        let h = &self.hs;
        let ms = |s: f64| format!("{:.1} ms", s * 1000.0);
        match self.state() {
            HsState::Complete => out.push((
                Level::Good,
                format!(
                    "Three-way handshake completed in {}",
                    ms(h.total().unwrap_or(0.0))
                ),
            )),
            HsState::Refused => out.push((
                Level::Bad,
                "Connection refused: the SYN was answered with RST (port closed or rejected by a firewall)".into(),
            )),
            HsState::NoAnswer => out.push((
                Level::Bad,
                "No answer to the SYN: host down, packet dropped by a firewall, or return path missing".into(),
            )),
            HsState::HalfOpen => out.push((
                Level::Warn,
                "SYN/ACK was sent but the final ACK was not seen (client gone, spoofed SYN, or asymmetric path)".into(),
            )),
            HsState::Partial => out.push((
                Level::Info,
                "Part of the handshake is missing from the capture".into(),
            )),
            HsState::Midstream => out.push((
                Level::Info,
                "Connection was already open when the capture started; options are unknown".into(),
            )),
        }
        if h.syns > 1 {
            out.push((
                Level::Warn,
                format!("SYN sent {} times: {} lost or delayed", h.syns, h.syns - 1),
            ));
        }
        if h.synacks > 1 {
            out.push((
                Level::Warn,
                format!("SYN/ACK sent {} times: the ACK was lost or late", h.synacks),
            ));
        }
        for (who, r) in [("server", h.server_rtt()), ("client", h.client_rtt())] {
            if let Some(r) = r.filter(|r| *r > 0.2) {
                out.push((
                    Level::Warn,
                    format!("High round trip to the {who}: {}", ms(r)),
                ));
            }
        }
        for (who, d, seen) in [
            ("Client", CLIENT, h.syns > 0),
            ("Server", SERVER, h.synack.is_some()),
        ] {
            if !seen {
                continue;
            }
            let o = &self.dirs[d].opts;
            match o.mss {
                None => out.push((
                    Level::Warn,
                    format!("{who} sent no MSS option (536 bytes assumed)"),
                )),
                Some(m) if m < 1220 => out.push((
                    Level::Warn,
                    format!("{who} announces a small MSS of {m} bytes"),
                )),
                _ => {}
            }
            // Only the client's offer decides; the server may just follow.
            if o.wscale.is_none() && (d == CLIENT || self.dirs[CLIENT].opts.wscale.is_some()) {
                out.push((
                    Level::Warn,
                    format!("{who} does not support window scaling: at most 64 KB in flight"),
                ));
            }
            if !o.sack_ok && (d == CLIENT || self.dirs[CLIENT].opts.sack_ok) {
                out.push((
                    Level::Info,
                    format!("{who} does not support selective ACK: slow loss recovery"),
                ));
            }
            if self.dirs[d].syn_window == 0 {
                out.push((Level::Warn, format!("{who} opened with a zero window")));
            }
        }
        if h.ecn {
            out.push((
                Level::Info,
                "Explicit congestion notification negotiated".into(),
            ));
        }
        if h.syn_data {
            out.push((Level::Info, "Data in the SYN (TCP Fast Open)".into()));
        }
        for (who, d) in [("Client", &self.dirs[0]), ("Server", &self.dirs[1])] {
            if d.retrans > 0 {
                let pct = d.retrans as f64 * 100.0 / d.packets.max(1) as f64;
                out.push((
                    if pct > 2.0 { Level::Warn } else { Level::Info },
                    format!("{who} retransmitted {} segments ({pct:.1}%)", d.retrans),
                ));
            }
            if d.zero_window > 0 {
                out.push((
                    Level::Warn,
                    format!(
                        "{who} closed its receive window {} times (application reads too slowly)",
                        d.zero_window
                    ),
                ));
            }
            if d.lost > 0 {
                out.push((
                    Level::Info,
                    format!(
                        "{} bytes sent by the {} are missing from the capture",
                        d.lost,
                        who.to_lowercase()
                    ),
                ));
            }
        }
        if let (Some(q), Some(r)) = (self.first_data[CLIENT], self.first_data[SERVER])
            && r > q
        {
            out.push((
                if r - q > 1.0 {
                    Level::Warn
                } else {
                    Level::Info
                },
                format!(
                    "First response data {} after the first request data",
                    ms(r - q)
                ),
            ));
        }
        match self.close() {
            Close::Reset(d) if self.state() != HsState::Refused => out.push((
                Level::Warn,
                format!(
                    "Connection was reset by the {}",
                    if d == CLIENT { "client" } else { "server" }
                ),
            )),
            _ => {}
        }
        out
    }
}

/// A run of data in one direction, for display.
pub struct Part {
    pub dir: usize,
    pub ts: f64,
    /// Number of the first packet.
    pub no: usize,
    pub data: Vec<u8>,
    /// Bytes missing from the capture before `data`.
    pub gap: u64,
}

type Key = ((IpAddr, u16), (IpAddr, u16));

#[derive(Default)]
pub struct Tracker {
    pub streams: Vec<Stream>,
    /// Connections beyond the limit.
    pub ignored: u64,
    index: HashMap<Key, usize>,
    budget: Budget,
}

impl Tracker {
    /// Track the packet `p`. `stored` is its index in `packets` when it was
    /// kept there (reassembly needs the bytes later).
    pub fn add(&mut self, packets: &[Packet], p: &Packet, stored: Option<usize>) -> Option<usize> {
        let t = p.d.tcp?;
        let src = (p.d.src_ip?, p.d.src_port?);
        let dst = (p.d.dst_ip?, p.d.dst_port?);
        let key = if src <= dst { (src, dst) } else { (dst, src) };
        let syn = t.flags & SYN != 0;
        let is_ack = t.flags & ACK != 0;
        let mut id = self.index.get(&key).copied();
        // A new SYN on known ports: retransmission, or the ports were reused.
        if let Some(i) = id
            && syn
            && !is_ack
        {
            let s = &self.streams[i];
            let same = s.hs.client_isn == Some(t.seq) && s.ends[CLIENT] == src;
            if !same {
                id = None;
            }
        }
        let id = match id {
            Some(i) => i,
            None => {
                if self.streams.len() >= MAX_STREAMS {
                    self.ignored += 1;
                    return None;
                }
                let client = if syn {
                    if is_ack { dst } else { src }
                } else if src.1 == dst.1 {
                    src
                } else {
                    // Mid-stream: the lower port is most likely the server.
                    if src.1 > dst.1 { src } else { dst }
                };
                let server = if client == src { dst } else { src };
                let id = self.streams.len();
                self.streams.push(Stream {
                    id,
                    ends: [client, server],
                    dirs: Default::default(),
                    hs: Handshake::default(),
                    first: p.ts,
                    last: p.ts,
                    proto: "TCP".into(),
                    how: None,
                    sni: None,
                    chunks: Vec::new(),
                    http: None,
                    first_data: [None; 2],
                    cut: false,
                    fin_first: None,
                    reset: None,
                });
                self.index.insert(key, id);
                id
            }
        };
        let budget = &mut self.budget;
        let s = &mut self.streams[id];
        let dir = if s.ends[CLIENT] == src {
            CLIENT
        } else {
            SERVER
        };
        s.last = s.last.max(p.ts);
        s.header(dir, &t, p);
        // Payload
        let mut seq = t.seq;
        if syn {
            seq = seq.wrapping_add(1);
        }
        if s.dirs[dir].next.is_none() {
            s.dirs[dir].next = Some(seq);
        }
        if t.len > 0 {
            s.first_data[dir].get_or_insert(p.ts);
            s.dirs[dir].wire_bytes += t.len as u64;
            if let Some(h) = p.d.how
                && (s.how.is_none() || (s.how != Some(How::Signature) && h == How::Signature))
            {
                s.how = Some(h);
                s.proto = p.d.proto.clone();
            }
            match stored {
                Some(i) => {
                    let held = Held {
                        pkt: i as u32,
                        off: p.d.payload.0,
                        cap: p.d.payload.1.min(t.len),
                        wire: t.len,
                        ts: p.ts,
                    };
                    s.segment(dir, seq, held, packets, budget);
                }
                None => s.cut = true,
            }
        } else if t.flags & (SYN | FIN | RST) == 0
            && s.dirs[dir]
                .offset(seq)
                .is_some_and(|o| o == s.dirs[dir].pos as i64 - 1)
        {
            s.dirs[dir].keepalives += 1;
        }
        // Acknowledged data that was not captured.
        if is_ack {
            let other = 1 - dir;
            if let Some(o) = s.dirs[other].offset(t.ack)
                && o > s.dirs[other].acked as i64
                // Ignore absurd jumps (corrupt or unrelated ACK numbers).
                && o < s.dirs[other].max_end as i64 + (1 << 30)
            {
                s.dirs[other].acked = o as u64;
                s.fill_gap(other, false, packets, budget);
            }
        }
        if t.flags & FIN != 0 {
            s.dirs[dir].fin = true;
            s.fin_first.get_or_insert(dir);
            if let Some(h) = &mut s.http
                && s.dirs[dir].pending.is_empty()
            {
                h.close(dir);
            }
        }
        if t.flags & RST != 0 {
            s.reset.get_or_insert(dir);
            if s.hs.syns > 0 && s.hs.synack.is_none() && dir == SERVER {
                s.hs.refused = true;
            }
        }
        Some(id)
    }

    /// End of the capture: give up waiting for missing segments.
    pub fn finish(&mut self, packets: &[Packet]) {
        for s in &mut self.streams {
            for dir in 0..2 {
                s.fill_gap(dir, true, packets, &mut self.budget);
                let d = &s.dirs[dir];
                // FIN consumes one sequence number.
                let tail = d.acked.saturating_sub(d.pos + d.fin as u64);
                if tail > 0 && !s.cut && d.wire_bytes > 0 {
                    s.gap(dir, tail, s.last);
                }
                if s.dirs[dir].fin
                    && let Some(h) = &mut s.http
                {
                    h.close(dir);
                }
            }
        }
    }

    /// Conversation of a stream: adjacent data in the same direction is
    /// merged. Stops after `max` bytes; returns whether it was cut.
    pub fn follow(
        &self,
        packets: &[Packet],
        id: usize,
        only: Option<usize>,
        max: usize,
    ) -> (Vec<Part>, bool) {
        let mut out: Vec<Part> = Vec::new();
        let mut total = 0;
        let Some(s) = self.streams.get(id) else {
            return (out, false);
        };
        for c in &s.chunks {
            let dir = c.dir as usize;
            if only.is_some_and(|o| o != dir) {
                continue;
            }
            let Some(p) = packets.get(c.pkt as usize) else {
                continue;
            };
            if c.gap > 0 {
                out.push(Part {
                    dir,
                    ts: c.ts,
                    no: p.no,
                    data: Vec::new(),
                    gap: c.gap,
                });
                continue;
            }
            let data = p
                .data
                .get(c.off as usize..(c.off + c.len) as usize)
                .unwrap_or(&[]);
            if total + data.len() > max {
                return (out, true);
            }
            total += data.len();
            match out.last_mut() {
                Some(last) if last.dir == dir => last.data.extend_from_slice(data),
                _ => out.push(Part {
                    dir,
                    ts: c.ts,
                    no: p.no,
                    data: data.to_vec(),
                    gap: 0,
                }),
            }
        }
        (out, false)
    }
}

impl Stream {
    /// Handshake, window and ACK bookkeeping.
    fn header(&mut self, dir: usize, t: &dissect::TcpInfo, p: &Packet) {
        let (syn, ack) = (t.flags & SYN != 0, t.flags & ACK != 0);
        let h = &mut self.hs;
        let d = &mut self.dirs[dir];
        d.packets += 1;
        if syn {
            d.opts = t.opts;
            d.syn_window = t.window;
            if ack {
                h.synacks += 1;
                if h.synack.is_none() {
                    h.synack = Some(p.ts);
                    h.nos[1] = Some(p.no);
                }
                h.server_isn = Some(t.seq);
                // ECE without CWR on the SYN/ACK accepts ECN.
                h.ecn = t.flags & 0xc0 == 0x40 && h.ecn;
            } else {
                h.syns += 1;
                h.syn_first.get_or_insert(p.ts);
                if h.synack.is_none() {
                    h.syn_last = Some(p.ts);
                }
                h.nos[0].get_or_insert(p.no);
                h.client_isn = Some(t.seq);
                h.syn_data |= t.len > 0;
                h.ecn = t.flags & 0xc0 == 0xc0;
            }
            return;
        }
        if ack
            && dir == CLIENT
            && h.ack.is_none()
            && t.flags & RST == 0
            && let Some(isn) = h.server_isn
            && t.ack.wrapping_sub(isn.wrapping_add(1)) < 1 << 30
        {
            h.ack = Some(p.ts);
            h.nos[2] = Some(p.no);
        }
        if t.flags & (RST | FIN) == 0 {
            if t.window == 0 {
                d.zero_window += 1;
            }
            // The scale applies only when both sides offered it.
            let scale = match (self.dirs[0].opts.wscale, self.dirs[1].opts.wscale) {
                (Some(a), Some(b)) => [a, b][dir],
                _ => 0,
            };
            let d = &mut self.dirs[dir];
            d.max_window = d.max_window.max((t.window as u64) << scale);
            if ack && t.len == 0 {
                let outstanding = {
                    let o = &self.dirs[1 - dir];
                    o.offset(t.ack)
                        .is_some_and(|x| (x.max(0) as u64) < o.max_end)
                };
                let d = &mut self.dirs[dir];
                if outstanding && d.last_ack == Some((t.ack, t.window)) {
                    d.dup_acks += 1;
                }
            }
            if ack {
                self.dirs[dir].last_ack = Some((t.ack, t.window));
            }
        }
    }

    fn segment(&mut self, dir: usize, seq: u32, h: Held, packets: &[Packet], budget: &mut Budget) {
        let d = &mut self.dirs[dir];
        let Some(start) = d.offset(seq) else { return };
        let end = start + h.wire as i64;
        let pos = d.pos as i64;
        if end <= pos {
            if h.wire == 1 && start == pos - 1 {
                d.keepalives += 1;
            } else {
                d.retrans += 1;
            }
            return;
        }
        // A jump this large is not this connection's data.
        if start - pos > 1 << 30 {
            return;
        }
        if (start.max(0) as u64) < d.max_end {
            // Below the highest byte seen: late (reordered) or sent again.
            if h.ts - d.max_ts < 0.003 {
                d.out_of_order += 1;
            } else {
                d.retrans += 1;
            }
        }
        if end as u64 > d.max_end {
            d.max_end = end as u64;
            d.max_ts = h.ts;
        }
        if start > pos {
            let e = d.pending.entry(start as u64).or_insert(h);
            if h.wire > e.wire {
                *e = h;
            }
            if d.pending.len() > MAX_PENDING {
                self.fill_gap(dir, true, packets, budget);
            }
            return;
        }
        self.deliver(dir, (pos - start) as u32, h, packets, budget);
        self.release(dir, packets, budget);
    }

    /// Deliver waiting segments that are now in order.
    fn release(&mut self, dir: usize, packets: &[Packet], budget: &mut Budget) {
        loop {
            let d = &mut self.dirs[dir];
            let Some((&at, &h)) = d.pending.first_key_value() else {
                return;
            };
            if at > d.pos {
                return;
            }
            d.pending.remove(&at);
            let skip = d.pos - at;
            if skip < h.wire as u64 {
                self.deliver(dir, skip as u32, h, packets, budget);
            }
        }
    }

    /// Accept missing data: when the receiver acknowledged it (it arrived but
    /// was not captured), or unconditionally with `force`.
    fn fill_gap(&mut self, dir: usize, force: bool, packets: &[Packet], budget: &mut Budget) {
        loop {
            let d = &self.dirs[dir];
            let Some((&at, h)) = d.pending.first_key_value() else {
                return;
            };
            if at > d.pos {
                if !force && d.acked < at {
                    return;
                }
                let (n, ts) = (at - d.pos, h.ts);
                self.gap_at(dir, n, ts, h_pkt(d));
            }
            self.release(dir, packets, budget);
        }
    }

    fn gap(&mut self, dir: usize, n: u64, ts: f64) {
        let pkt = self.chunks.last().map_or(0, |c| c.pkt);
        self.gap_at(dir, n, ts, pkt);
    }

    fn gap_at(&mut self, dir: usize, n: u64, ts: f64, pkt: u32) {
        let d = &mut self.dirs[dir];
        d.lost += n;
        d.pos += n;
        d.max_end = d.max_end.max(d.pos);
        d.next = d.next.map(|x| x.wrapping_add(n as u32));
        self.chunks.push(Chunk {
            dir: dir as u8,
            ts,
            pkt,
            off: 0,
            len: 0,
            gap: n,
        });
        if let Some(h) = &mut self.http {
            h.gap(dir, n);
        }
    }

    /// Append a segment, leaving out its first `skip` bytes.
    fn deliver(&mut self, dir: usize, skip: u32, h: Held, packets: &[Packet], budget: &mut Budget) {
        let n = h.wire - skip;
        let have = h.cap.saturating_sub(skip);
        if have > 0 {
            let off = h.off + skip;
            self.chunks.push(Chunk {
                dir: dir as u8,
                ts: h.ts,
                pkt: h.pkt,
                off,
                len: have,
                gap: 0,
            });
            let d = &mut self.dirs[dir];
            d.pos += have as u64;
            d.next = d.next.map(|x| x.wrapping_add(have));
            if let Some(p) = packets.get(h.pkt as usize) {
                let data = p
                    .data
                    .get(off as usize..(off + have) as usize)
                    .unwrap_or(&[]);
                self.content(dir, data, h.ts, p.no, budget);
            }
        }
        if n > have {
            // Cut by the snap length.
            self.gap_at(dir, (n - have) as u64, h.ts, h.pkt);
        }
    }

    /// New in-order bytes: identify the protocol, feed the HTTP parser.
    fn content(&mut self, dir: usize, data: &[u8], ts: f64, no: usize, budget: &mut Budget) {
        let d = &mut self.dirs[dir];
        if d.pos - data.len() as u64 == d.head.len() as u64 && d.head.len() < HEAD {
            let first = d.head.is_empty();
            let n = data.len().min(HEAD - d.head.len());
            d.head.extend_from_slice(&data[..n]);
            if !first && self.how != Some(How::Signature) {
                // The first segment alone was too short to tell.
                let (sp, dp) = (self.ends[dir].1, self.ends[1 - dir].1);
                if let Some(a) = appproto::tcp(&self.dirs[dir].head, sp, dp)
                    && a.how == How::Signature
                {
                    self.how = Some(a.how);
                    self.proto = a.proto.into();
                }
            }
            if dir == CLIENT && self.sni.is_none() {
                self.sni = appproto::client_hello_sni(&self.dirs[CLIENT].head);
            }
        }
        if self.http.is_none() && appproto::is_http(data) {
            self.http = Some(Box::default());
        }
        if let Some(h) = &mut self.http {
            h.feed(dir, data, ts, no, budget);
        }
    }
}

fn h_pkt(d: &Dir) -> u32 {
    d.pending.first_key_value().map_or(0, |(_, h)| h.pkt)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Ethernet + IPv4 + TCP frame between 10.0.0.1:40000 and 10.0.0.2:80.
    pub fn frame(from_client: bool, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut f = vec![2; 12];
        f.extend([0x08, 0x00, 0x45, 0]);
        let opts: &[u8] = if flags & SYN != 0 {
            &[2, 4, 5, 0xb4, 4, 2, 3, 3, 7, 0, 0, 0]
        } else {
            &[]
        };
        f.extend(((40 + opts.len() + data.len()) as u16).to_be_bytes());
        f.extend([0, 1, 0, 0, 64, 6, 0, 0]);
        let (a, b) = ([10, 0, 0, 1], [10, 0, 0, 2]);
        let (pa, pb) = (40000u16, 80u16);
        let (s, d, sp, dp) = if from_client {
            (a, b, pa, pb)
        } else {
            (b, a, pb, pa)
        };
        f.extend(s);
        f.extend(d);
        f.extend(sp.to_be_bytes());
        f.extend(dp.to_be_bytes());
        f.extend(seq.to_be_bytes());
        f.extend(ack.to_be_bytes());
        f.push(((5 + opts.len() / 4) << 4) as u8);
        f.push(flags);
        f.extend([0xff, 0, 0, 0, 0, 0]);
        f.extend(opts);
        f.extend(data);
        f
    }

    #[derive(Default)]
    pub struct Rig {
        pub t: Tracker,
        pub packets: Vec<Packet>,
    }

    impl Rig {
        pub fn push(&mut self, ts: f64, f: Vec<u8>) {
            self.packets.push(Packet {
                no: self.packets.len() + 1,
                ts,
                len: f.len() as u32,
                linktype: 1,
                d: dissect::dissect(1, &f),
                data: f,
                ..Default::default()
            });
            let i = self.packets.len() - 1;
            self.t.add(&self.packets, &self.packets[i], Some(i));
        }
        pub fn open(&mut self) {
            self.push(0.0, frame(true, 100, 0, SYN, b""));
            self.push(0.010, frame(false, 500, 101, SYN | ACK, b""));
            self.push(0.015, frame(true, 101, 501, ACK, b""));
        }
        pub fn text(&self, dir: usize) -> String {
            let (parts, _) = self.t.follow(&self.packets, 0, Some(dir), 1 << 20);
            parts
                .iter()
                .map(|p| {
                    let gap = match p.gap {
                        0 => String::new(),
                        n => format!("<{n}>"),
                    };
                    gap + &String::from_utf8_lossy(&p.data)
                })
                .collect()
        }
    }

    #[test]
    fn handshake_times_and_options() {
        let mut r = Rig::default();
        r.open();
        let s = &r.t.streams[0];
        assert_eq!(s.state(), HsState::Complete);
        assert!((s.hs.server_rtt().unwrap() - 0.010).abs() < 1e-9);
        assert!((s.hs.client_rtt().unwrap() - 0.005).abs() < 1e-9);
        assert_eq!(s.dirs[CLIENT].opts.mss, Some(1460));
        assert_eq!(s.hs.nos, [Some(1), Some(2), Some(3)]);
        assert_eq!(s.close(), Close::Open);
        assert_eq!(s.client(), "10.0.0.1:40000");
    }

    #[test]
    fn refused_unanswered_half_open_midstream() {
        let mut r = Rig::default();
        r.push(0.0, frame(true, 100, 0, SYN, b""));
        assert_eq!(r.t.streams[0].state(), HsState::NoAnswer);
        r.push(1.0, frame(true, 100, 0, SYN, b""));
        assert_eq!(r.t.streams[0].hs.syns, 2);
        r.push(1.1, frame(false, 0, 101, RST | ACK, b""));
        assert_eq!(r.t.streams[0].state(), HsState::Refused);
        // Same ports, new connection.
        r.push(2.0, frame(true, 9000, 0, SYN, b""));
        r.push(2.1, frame(false, 70, 9001, SYN | ACK, b""));
        assert_eq!(r.t.streams.len(), 2);
        assert_eq!(r.t.streams[1].state(), HsState::HalfOpen);
        let mut r = Rig::default();
        r.push(0.0, frame(false, 70, 9, ACK, b"data"));
        assert_eq!(r.t.streams[0].state(), HsState::Midstream);
        // The lower port is the server although it spoke first.
        assert_eq!(r.t.streams[0].ends[SERVER].1, 80);
    }

    #[test]
    fn reorders_trims_and_counts_retransmissions() {
        let mut r = Rig::default();
        r.open();
        r.push(0.100, frame(true, 101, 501, ACK, b"AAAA"));
        r.push(0.101, frame(true, 109, 501, ACK, b"CCCC"));
        r.push(0.102, frame(true, 105, 501, ACK, b"BBBB")); // reordered
        r.push(0.500, frame(true, 101, 501, ACK, b"AAAA")); // again
        r.push(0.600, frame(true, 111, 501, ACK, b"CCDDDD")); // overlaps
        assert_eq!(r.text(CLIENT), "AAAABBBBCCCCDDDD");
        let d = &r.t.streams[0].dirs[CLIENT];
        assert_eq!((d.out_of_order, d.lost), (1, 0));
        // The exact repeat and the partly repeated segment.
        assert_eq!(d.retrans, 2);
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut r = Rig::default();
        r.push(0.0, frame(true, u32::MAX - 2, 0, SYN, b""));
        r.push(0.1, frame(false, 500, u32::MAX - 1, SYN | ACK, b""));
        r.push(0.2, frame(true, u32::MAX - 1, 501, ACK, b"abcd"));
        r.push(0.3, frame(true, 2, 501, ACK, b"efgh"));
        assert_eq!(r.text(CLIENT), "abcdefgh");
    }

    #[test]
    fn acknowledged_but_uncaptured_data_becomes_a_gap() {
        let mut r = Rig::default();
        r.open();
        r.push(0.1, frame(true, 101, 501, ACK, b"one"));
        r.push(0.2, frame(true, 114, 501, ACK, b"three")); // 10 missing
        assert_eq!(r.text(CLIENT), "one");
        r.push(0.3, frame(false, 501, 119, ACK, b""));
        assert_eq!(r.text(CLIENT), "one<10>three");
        // The tail: acknowledged, never captured, then FIN.
        r.push(0.4, frame(false, 501, 124, ACK, b""));
        r.t.finish(&r.packets);
        assert_eq!(r.text(CLIENT), "one<10>three<5>");
        assert_eq!(r.t.streams[0].dirs[CLIENT].lost, 15);
    }

    #[test]
    fn snap_length_cut_is_a_gap_not_an_offset() {
        let mut r = Rig::default();
        r.open();
        let mut f = frame(true, 101, 501, ACK, b"0123456789");
        f.truncate(f.len() - 6);
        r.push(0.1, f);
        r.push(0.2, frame(true, 111, 501, ACK, b"next"));
        assert_eq!(r.text(CLIENT), "0123<6>next");
    }

    #[test]
    fn orderly_close_and_keepalive() {
        let mut r = Rig::default();
        r.open();
        r.push(0.1, frame(true, 101, 501, ACK, b"x"));
        r.push(0.2, frame(false, 501, 102, ACK, b""));
        r.push(9.0, frame(true, 101, 501, ACK, b""));
        r.push(10.0, frame(false, 501, 102, FIN | ACK, b""));
        assert_eq!(r.t.streams[0].close(), Close::Half(SERVER));
        r.push(10.1, frame(true, 102, 502, FIN | ACK, b""));
        r.push(10.2, frame(false, 502, 103, ACK, b""));
        r.t.finish(&r.packets);
        let s = &r.t.streams[0];
        assert_eq!(s.close(), Close::Fin(SERVER));
        assert_eq!(s.dirs[CLIENT].keepalives, 1);
        // The FIN's sequence number is not missing data.
        assert_eq!(s.lost(), 0);
    }

    #[test]
    fn random_segments_never_panic() {
        let mut x = 88172645463325252u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20 {
            let mut r = Rig::default();
            for i in 0..400 {
                let seq = match rnd() % 8 {
                    0 => rnd() as u32,
                    _ => 100 + (rnd() % 300) as u32,
                };
                let ack = match rnd() % 8 {
                    0 => rnd() as u32,
                    _ => 100 + (rnd() % 300) as u32,
                };
                let body =
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
                let a = rnd() as usize % body.len();
                let n = rnd() as usize % (body.len() - a);
                let mut f = frame(rnd() % 2 == 0, seq, ack, rnd() as u8, &body[a..a + n]);
                if rnd() % 10 == 0 {
                    f.truncate(40 + rnd() as usize % (f.len() - 40));
                }
                r.push(i as f64 * 0.01, f);
            }
            r.t.finish(&r.packets);
            for id in 0..r.t.streams.len() {
                r.t.follow(&r.packets, id, None, 1 << 20);
                r.t.streams[id].findings();
            }
        }
    }
}
