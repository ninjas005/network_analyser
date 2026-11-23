//! CAN bus: frames, SocketCAN (Linux, raw libc sockets, classic + CAN FD,
//! error frames), slcan / Lawicel ASCII adapters over a serial port (every
//! OS), per-ID statistics and a bus-load estimate.

use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- frames

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Frame {
    /// Seconds since the Unix epoch.
    pub ts: f64,
    /// 11-bit or 29-bit identifier (for error frames: the error class bits).
    pub id: u32,
    pub ext: bool,
    pub rtr: bool,
    pub fd: bool,
    /// CAN FD bit-rate switch.
    pub brs: bool,
    /// CAN FD error-state indicator.
    pub esi: bool,
    pub err: bool,
    /// Requested length of a remote frame (data is empty).
    pub rtr_len: u8,
    pub data: Vec<u8>,
    /// Sent by this app.
    pub tx: bool,
}

/// CAN FD length for a DLC code (0..=15).
pub fn dlc_to_len(dlc: u8) -> usize {
    match dlc {
        0..=8 => dlc as usize,
        9 => 12,
        10 => 16,
        11 => 20,
        12 => 24,
        13 => 32,
        14 => 48,
        _ => 64,
    }
}

/// Smallest DLC code whose length holds `len` bytes.
pub fn len_to_dlc(len: usize) -> u8 {
    (0u8..=15).find(|&d| dlc_to_len(d) >= len).unwrap_or(15)
}

/// Valid payload lengths are padded up to the next CAN FD size.
pub fn fd_pad(len: usize) -> usize {
    dlc_to_len(len_to_dlc(len))
}

impl Frame {
    pub fn new(id: u32, ext: bool, data: Vec<u8>) -> Frame {
        Frame {
            id,
            ext: ext || id > 0x7ff,
            data,
            ..Default::default()
        }
    }

    pub fn dlc(&self) -> u8 {
        if self.rtr {
            self.rtr_len
        } else {
            len_to_dlc(self.data.len())
        }
    }

    pub fn id_str(&self) -> String {
        if self.err {
            "ERROR".into()
        } else if self.ext {
            format!("{:08X}", self.id)
        } else {
            format!("{:03X}", self.id)
        }
    }

    pub fn hex(&self) -> String {
        hex(&self.data)
    }

    pub fn flags(&self) -> String {
        let mut f = Vec::new();
        if self.ext {
            f.push("EXT");
        }
        if self.rtr {
            f.push("RTR");
        }
        if self.fd {
            f.push("FD");
        }
        if self.brs {
            f.push("BRS");
        }
        if self.esi {
            f.push("ESI");
        }
        if self.err {
            f.push("ERR");
        }
        f.join(" ")
    }

    /// Approximate bits on the wire at the nominal rate (frame incl. worst
    /// case bit stuffing and interframe space). For CAN FD with BRS the data
    /// phase is scaled by `data_ratio` (= nominal / data bit rate).
    pub fn wire_bits(&self, data_ratio: f64) -> f64 {
        let n = self.data.len() as f64;
        if self.fd {
            // Arbitration phase: SOF, ID, r1/IDE/FDF/res/BRS (+ SRR/IDE for ext).
            let arb = if self.ext {
                32.0 + 3.0
            } else {
                12.0 + 3.0 + 1.0
            };
            // ESI + DLC + data + stuff count + CRC (17 or 21) + fixed stuff bits.
            let crc = if n > 16.0 { 21.0 } else { 17.0 };
            let data_bits = 1.0 + 4.0 + 8.0 * n + 4.0 + crc + (4.0 + 8.0 * n + crc) / 4.0;
            let ratio = if self.brs { data_ratio } else { 1.0 };
            // CRC delimiter, ACK, EOF, IFS.
            arb * 1.2 + data_bits * ratio + 2.0 + 7.0 + 3.0
        } else {
            let base = if self.ext { 54.0 } else { 34.0 };
            let body = base + 8.0 * n;
            // Stuffing applies to SOF..CRC; worst case one stuff bit per 4.
            body + ((body - 1.0) / 4.0).floor() + 13.0
        }
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn ascii(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            }
        })
        .collect()
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s: String = s
        .chars()
        .filter(|c| !matches!(c, ' ' | '.' | ':' | '-'))
        .collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Parse cansend syntax: `123#DEADBEEF`, `1F334455#11.22`, `123#R`,
/// `123#R4`, CAN FD `123##1DEADBEEF` (flags nibble: 1 = BRS, 2 = ESI).
pub fn parse_cansend(s: &str) -> Result<Frame, String> {
    let s = s.trim();
    let (id_s, rest) = s
        .split_once('#')
        .ok_or("expected ID#DATA (e.g. 123#DEADBEEF)")?;
    if id_s.is_empty() || id_s.len() > 8 {
        return Err(format!("bad CAN ID '{id_s}'"));
    }
    let id = u32::from_str_radix(id_s, 16).map_err(|_| format!("bad CAN ID '{id_s}'"))?;
    let ext = id_s.len() > 3 || id > 0x7ff;
    if id > 0x1fff_ffff {
        return Err("CAN ID is more than 29 bits".into());
    }
    let mut f = Frame::new(id, ext, Vec::new());
    if let Some(fd) = rest.strip_prefix('#') {
        let mut ch = fd.chars();
        let flags = ch
            .next()
            .and_then(|c| c.to_digit(16))
            .ok_or("CAN FD: expected a flags digit after ##")?;
        f.fd = true;
        f.brs = flags & 1 != 0;
        f.esi = flags & 2 != 0;
        f.data = parse_hex_bytes(ch.as_str()).ok_or("bad data bytes")?;
        if f.data.len() > 64 {
            return Err("CAN FD data is limited to 64 bytes".into());
        }
        f.data.resize(fd_pad(f.data.len()), 0);
    } else if let Some(r) = rest.strip_prefix(['R', 'r']) {
        f.rtr = true;
        f.rtr_len = if r.is_empty() {
            0
        } else {
            r.parse::<u8>()
                .ok()
                .filter(|l| *l <= 8)
                .ok_or("bad RTR length")?
        };
    } else {
        f.data = parse_hex_bytes(rest).ok_or("bad data bytes")?;
        if f.data.len() > 8 {
            return Err("classic CAN data is limited to 8 bytes (use ## for CAN FD)".into());
        }
    }
    Ok(f)
}

/// Inverse of [`parse_cansend`].
pub fn to_cansend(f: &Frame) -> String {
    let id = f.id_str();
    if f.fd {
        format!(
            "{id}##{:X}{}",
            (f.brs as u8) | ((f.esi as u8) << 1),
            hex(&f.data).replace(' ', "")
        )
    } else if f.rtr {
        format!(
            "{id}#R{}",
            if f.rtr_len > 0 {
                f.rtr_len.to_string()
            } else {
                String::new()
            }
        )
    } else {
        format!("{id}#{}", hex(&f.data).replace(' ', ""))
    }
}

/// Human description of a SocketCAN error frame.
pub fn describe_error(f: &Frame) -> String {
    let c = f.id;
    let d = |i: usize| f.data.get(i).copied().unwrap_or(0);
    let mut out = Vec::new();
    if c & 0x1 != 0 {
        out.push("TX timeout".to_string());
    }
    if c & 0x2 != 0 {
        out.push(format!("lost arbitration at bit {}", d(0)));
    }
    if c & 0x4 != 0 {
        let x = d(1);
        let mut s = Vec::new();
        for (bit, name) in [
            (0x01, "RX overflow"),
            (0x02, "TX overflow"),
            (0x04, "RX warning"),
            (0x08, "TX warning"),
            (0x10, "RX passive"),
            (0x20, "TX passive"),
            (0x40, "back to active"),
        ] {
            if x & bit != 0 {
                s.push(name);
            }
        }
        out.push(format!(
            "controller: {}",
            if s.is_empty() {
                "problem".into()
            } else {
                s.join(", ")
            }
        ));
    }
    if c & 0x8 != 0 {
        let t = d(2);
        let mut s = Vec::new();
        for (bit, name) in [
            (0x01, "single bit"),
            (0x02, "frame format"),
            (0x04, "bit stuffing"),
            (0x08, "dominant bit"),
            (0x10, "recessive bit"),
            (0x20, "overload"),
            (0x40, "active error"),
            (0x80, "TX error"),
        ] {
            if t & bit != 0 {
                s.push(name);
            }
        }
        out.push(format!(
            "protocol violation{}",
            if s.is_empty() {
                String::new()
            } else {
                format!(": {}", s.join(", "))
            }
        ));
    }
    if c & 0x10 != 0 {
        out.push("transceiver".into());
    }
    if c & 0x20 != 0 {
        out.push("no ACK".into());
    }
    if c & 0x40 != 0 {
        out.push("BUS OFF".into());
    }
    if c & 0x80 != 0 {
        out.push("bus error".into());
    }
    if c & 0x100 != 0 {
        out.push("controller restarted".into());
    }
    if f.data.len() >= 8 && (d(6) > 0 || d(7) > 0) {
        out.push(format!("TEC {} REC {}", d(6), d(7)));
    }
    if out.is_empty() {
        "error frame".into()
    } else {
        out.join("; ")
    }
}

// ---------------------------------------------------------------- slcan

/// slcan `Sn` bit-rate codes.
pub const SLCAN_RATES: &[(u32, char)] = &[
    (10_000, '0'),
    (20_000, '1'),
    (50_000, '2'),
    (100_000, '3'),
    (125_000, '4'),
    (250_000, '5'),
    (500_000, '6'),
    (800_000, '7'),
    (1_000_000, '8'),
];

/// Encode a frame as an slcan transmit command (with trailing CR).
pub fn slcan_encode(f: &Frame) -> String {
    let id = if f.ext {
        format!("{:08X}", f.id)
    } else {
        format!("{:03X}", f.id)
    };
    if f.rtr {
        let c = if f.ext { 'R' } else { 'r' };
        return format!("{c}{id}{}\r", f.rtr_len.min(8));
    }
    let c = match (f.fd, f.brs, f.ext) {
        (false, _, false) => 't',
        (false, _, true) => 'T',
        (true, false, false) => 'd',
        (true, false, true) => 'D',
        (true, true, false) => 'b',
        (true, true, true) => 'B',
    };
    format!(
        "{c}{id}{:X}{}\r",
        f.dlc(),
        hex(&f.data[..dlc_to_len(f.dlc()).min(f.data.len())]).replace(' ', "")
    )
}

/// Parse one received slcan line (without the CR). Unknown lines → None.
pub fn slcan_decode(line: &str) -> Option<Frame> {
    let mut ch = line.chars();
    let kind = ch.next()?;
    let (ext, rtr, fd, brs) = match kind {
        't' => (false, false, false, false),
        'T' => (true, false, false, false),
        'r' => (false, true, false, false),
        'R' => (true, true, false, false),
        'd' => (false, false, true, false),
        'D' => (true, false, true, false),
        'b' => (false, false, true, true),
        'B' => (true, false, true, true),
        _ => return None,
    };
    let rest = ch.as_str();
    let idlen = if ext { 8 } else { 3 };
    let id = u32::from_str_radix(rest.get(..idlen)?, 16).ok()?;
    let dlc = u8::from_str_radix(rest.get(idlen..idlen + 1)?, 16).ok()?;
    if !fd && dlc > 8 {
        return None;
    }
    let mut f = Frame {
        id,
        ext,
        rtr,
        fd,
        brs,
        ..Default::default()
    };
    if rtr {
        f.rtr_len = dlc;
        return Some(f);
    }
    let n = dlc_to_len(dlc);
    let data = rest.get(idlen + 1..idlen + 1 + n * 2)?;
    f.data = parse_hex_bytes(data)?;
    Some(f)
}

// ---------------------------------------------------------------- SocketCAN

/// CAN network interfaces (Linux: /sys/class/net/*/type == 280).
pub fn socketcan_interfaces() -> Vec<(String, String)> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            let p = e.path();
            let ty = std::fs::read_to_string(p.join("type")).unwrap_or_default();
            if ty.trim() == "280" {
                let state = std::fs::read_to_string(p.join("operstate"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                out.push((e.file_name().to_string_lossy().into_owned(), state));
            }
        }
    }
    out.sort();
    out
}

/// Bit rates of a SocketCAN interface from `ip -details link show`.
pub fn socketcan_bitrates(name: &str) -> (Option<u32>, Option<u32>) {
    let Ok(out) = crate::platform::command("ip")
        .args(["-details", "link", "show", "dev", name])
        .output()
    else {
        return (None, None);
    };
    parse_ip_bitrates(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_ip_bitrates(text: &str) -> (Option<u32>, Option<u32>) {
    let mut nominal = None;
    let mut data = None;
    let mut words = text.split_whitespace().peekable();
    while let Some(w) = words.next() {
        match w {
            "bitrate" if nominal.is_none() => nominal = words.peek().and_then(|v| v.parse().ok()),
            "dbitrate" if data.is_none() => data = words.peek().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    (nominal, data)
}

const CAN_EFF_FLAG: u32 = 0x8000_0000;
const CAN_RTR_FLAG: u32 = 0x4000_0000;
const CAN_ERR_FLAG: u32 = 0x2000_0000;
const CANFD_BRS: u8 = 0x01;
const CANFD_ESI: u8 = 0x02;
const CANFD_FDF: u8 = 0x04;
pub const CAN_MTU: usize = 16;
pub const CANFD_MTU: usize = 72;

/// Encode as a Linux `struct can_frame` (16 bytes) or `canfd_frame` (72).
pub fn sock_encode(f: &Frame) -> Vec<u8> {
    let mut id = f.id & if f.ext { 0x1fff_ffff } else { 0x7ff };
    if f.ext {
        id |= CAN_EFF_FLAG;
    }
    if f.rtr && !f.fd {
        id |= CAN_RTR_FLAG;
    }
    let mut b = vec![0u8; if f.fd { CANFD_MTU } else { CAN_MTU }];
    b[0..4].copy_from_slice(&id.to_ne_bytes());
    if f.fd {
        let n = fd_pad(f.data.len());
        b[4] = n as u8;
        b[5] = CANFD_FDF | if f.brs { CANFD_BRS } else { 0 } | if f.esi { CANFD_ESI } else { 0 };
        b[8..8 + f.data.len()].copy_from_slice(&f.data);
    } else {
        b[4] = if f.rtr {
            f.rtr_len
        } else {
            f.data.len().min(8) as u8
        };
        let n = f.data.len().min(8);
        b[8..8 + n].copy_from_slice(&f.data[..n]);
    }
    b
}

/// Decode a frame read from a raw CAN socket (`n` = bytes read).
pub fn sock_decode(b: &[u8]) -> Option<Frame> {
    if b.len() != CAN_MTU && b.len() != CANFD_MTU {
        return None;
    }
    let raw = u32::from_ne_bytes(b[0..4].try_into().ok()?);
    let fd = b.len() == CANFD_MTU;
    let ext = raw & CAN_EFF_FLAG != 0;
    let err = raw & CAN_ERR_FLAG != 0;
    let rtr = !fd && raw & CAN_RTR_FLAG != 0;
    let len = b[4] as usize;
    let mut f = Frame {
        id: raw & if ext || err { 0x1fff_ffff } else { 0x7ff },
        ext: ext && !err,
        err,
        rtr,
        fd,
        brs: fd && b[5] & CANFD_BRS != 0,
        esi: fd && b[5] & CANFD_ESI != 0,
        ..Default::default()
    };
    if rtr {
        f.rtr_len = len.min(8) as u8;
    } else {
        let n = len.min(if fd { 64 } else { 8 });
        f.data = b[8..8 + n].to_vec();
    }
    Some(f)
}

#[cfg(target_os = "linux")]
mod sock {
    use std::ffi::CString;
    use std::io;

    #[repr(C)]
    struct SockaddrCan {
        family: u16,
        ifindex: i32,
        addr: [u64; 2],
    }

    const PF_CAN: i32 = 29;
    const CAN_RAW: i32 = 1;
    const SOL_CAN_RAW: i32 = 100 + CAN_RAW;
    const CAN_RAW_ERR_FILTER: i32 = 2;
    const CAN_RAW_FD_FRAMES: i32 = 5;
    const CAN_ERR_MASK: u32 = 0x1fff_ffff;

    pub struct Sock(i32);

    impl Drop for Sock {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    impl Sock {
        pub fn open(name: &str) -> io::Result<(Sock, bool)> {
            let cname = CString::new(name).map_err(|_| io::Error::other("bad name"))?;
            let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
            if ifindex == 0 {
                return Err(io::Error::other(format!("no such interface: {name}")));
            }
            let fd = unsafe { libc::socket(PF_CAN, libc::SOCK_RAW, CAN_RAW) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let s = Sock(fd);
            let on: i32 = 1;
            let fd_ok = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_CAN_RAW,
                    CAN_RAW_FD_FRAMES,
                    &on as *const i32 as *const libc::c_void,
                    4,
                )
            } == 0;
            let mask = CAN_ERR_MASK;
            unsafe {
                libc::setsockopt(
                    fd,
                    SOL_CAN_RAW,
                    CAN_RAW_ERR_FILTER,
                    &mask as *const u32 as *const libc::c_void,
                    4,
                );
            }
            let tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 10_000,
            };
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const libc::timeval as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as u32,
                );
            }
            let addr = SockaddrCan {
                family: PF_CAN as u16,
                ifindex: ifindex as i32,
                addr: [0; 2],
            };
            let r = unsafe {
                libc::bind(
                    fd,
                    &addr as *const SockaddrCan as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrCan>() as u32,
                )
            };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((s, fd_ok))
        }

        /// Ok(None) on timeout.
        pub fn read(&self, buf: &mut [u8; 72]) -> io::Result<Option<usize>> {
            let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, 72) };
            if n < 0 {
                let e = io::Error::last_os_error();
                return match e.kind() {
                    io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted => Ok(None),
                    _ => Err(e),
                };
            }
            Ok(Some(n as usize))
        }

        pub fn write(&self, b: &[u8]) -> io::Result<()> {
            let n = unsafe { libc::write(self.0, b.as_ptr() as *const libc::c_void, b.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------- session

#[derive(Clone, Debug, PartialEq)]
pub enum Backend {
    SocketCan(String),
    Slcan {
        port: String,
        /// Serial baud (most USB adapters ignore it).
        baud: u32,
        bitrate: u32,
        listen_only: bool,
    },
}

impl Backend {
    pub fn label(&self) -> String {
        match self {
            Backend::SocketCan(n) => n.clone(),
            Backend::Slcan {
                port,
                bitrate,
                listen_only,
                ..
            } => format!(
                "slcan {port} @ {} kbit/s{}",
                bitrate / 1000,
                if *listen_only { " (listen only)" } else { "" }
            ),
        }
    }
}

pub enum Cmd {
    Send(Frame),
    /// Start (Some) or stop (None) periodic transmission.
    Periodic(Option<(Frame, Duration)>),
}

pub enum CanEvent {
    Opened(String),
    Frames(Vec<Frame>),
    /// A transmit failed or the adapter rejected a command.
    Warning(String),
    Closed(Option<String>),
}

pub struct CanHandle {
    pub events: Receiver<CanEvent>,
    cmds: Sender<Cmd>,
    stop: Arc<AtomicBool>,
}

impl CanHandle {
    pub fn send(&self, f: Frame) {
        let _ = self.cmds.send(Cmd::Send(f));
    }
    pub fn periodic(&self, p: Option<(Frame, Duration)>) {
        let _ = self.cmds.send(Cmd::Periodic(p));
    }
    pub fn close(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for CanHandle {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn open(backend: Backend) -> CanHandle {
    let (tx, rx) = channel();
    let (ctx, crx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::Builder::new()
        .name("can".into())
        .spawn(move || {
            let r = match &backend {
                Backend::SocketCan(name) => run_socketcan(name, &tx, &crx, &flag),
                Backend::Slcan { .. } => run_slcan(&backend, &tx, &crx, &flag),
            };
            let _ = tx.send(CanEvent::Closed(r.err()));
        })
        .expect("spawn can thread");
    CanHandle {
        events: rx,
        cmds: ctx,
        stop,
    }
}

/// Batches received frames (every 50 ms or 256 frames).
struct Batch<'a> {
    tx: &'a Sender<CanEvent>,
    buf: Vec<Frame>,
    last: Instant,
}

impl Batch<'_> {
    fn push(&mut self, f: Frame) {
        self.buf.push(f);
        if self.buf.len() >= 256 {
            self.flush();
        }
    }
    fn tick(&mut self) {
        if self.last.elapsed() >= Duration::from_millis(50) {
            self.flush();
        }
    }
    fn flush(&mut self) {
        self.last = Instant::now();
        if !self.buf.is_empty() {
            let _ = self
                .tx
                .send(CanEvent::Frames(std::mem::take(&mut self.buf)));
        }
    }
}

/// Shared command / periodic-send handling for both back-ends.
struct Sender2 {
    periodic: Option<(Frame, Duration, Instant)>,
}

impl Sender2 {
    fn due(&mut self, cmds: &Receiver<Cmd>) -> Vec<Frame> {
        let mut out = Vec::new();
        while let Ok(c) = cmds.try_recv() {
            match c {
                Cmd::Send(f) => out.push(f),
                Cmd::Periodic(p) => {
                    self.periodic =
                        p.map(|(f, d)| (f, d.max(Duration::from_millis(1)), Instant::now()))
                }
            }
        }
        if let Some((f, d, next)) = &mut self.periodic
            && Instant::now() >= *next
        {
            out.push(f.clone());
            *next += *d;
            // Don't burst to catch up after a stall.
            if *next < Instant::now() {
                *next = Instant::now() + *d;
            }
        }
        out
    }
}

#[cfg(target_os = "linux")]
fn run_socketcan(
    name: &str,
    tx: &Sender<CanEvent>,
    cmds: &Receiver<Cmd>,
    stop: &AtomicBool,
) -> Result<(), String> {
    let (s, fd_ok) = sock::Sock::open(name).map_err(|e| format!("{name}: {e}"))?;
    let _ = tx.send(CanEvent::Opened(format!(
        "{name} (SocketCAN{})",
        if fd_ok { ", CAN FD enabled" } else { "" }
    )));
    let mut b = Batch {
        tx,
        buf: Vec::new(),
        last: Instant::now(),
    };
    let mut snd = Sender2 { periodic: None };
    let mut buf = [0u8; 72];
    while !stop.load(Ordering::Relaxed) {
        for mut f in snd.due(cmds) {
            if f.fd && !fd_ok {
                let _ = tx.send(CanEvent::Warning(
                    "this interface does not accept CAN FD frames".into(),
                ));
                continue;
            }
            match s.write(&sock_encode(&f)) {
                Ok(()) => {
                    f.ts = now();
                    f.tx = true;
                    b.push(f);
                }
                Err(e) => {
                    let _ = tx.send(CanEvent::Warning(format!("send failed: {e}")));
                }
            }
        }
        if let Some(n) = s.read(&mut buf).map_err(|e| e.to_string())?
            && let Some(mut f) = sock_decode(&buf[..n])
        {
            f.ts = now();
            b.push(f);
        }
        b.tick();
    }
    b.flush();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_socketcan(
    _name: &str,
    _tx: &Sender<CanEvent>,
    _cmds: &Receiver<Cmd>,
    _stop: &AtomicBool,
) -> Result<(), String> {
    Err(
        "SocketCAN is only available on Linux. Use an slcan (Lawicel) adapter on this system."
            .into(),
    )
}

fn run_slcan(
    backend: &Backend,
    tx: &Sender<CanEvent>,
    cmds: &Receiver<Cmd>,
    stop: &AtomicBool,
) -> Result<(), String> {
    let Backend::Slcan {
        port,
        baud,
        bitrate,
        listen_only,
    } = backend
    else {
        return Err("not slcan".into());
    };
    let settings = crate::serial::SerialSettings {
        port: port.clone(),
        baud: *baud,
        ..Default::default()
    };
    let mut p = settings.open(Duration::from_millis(10)).map_err(|e| {
        let e = e.to_string();
        match crate::serial::permission_hint(&e) {
            Some(h) => format!("{port}: {e}. {h}"),
            None => format!("{port}: {e}"),
        }
    })?;
    let code = SLCAN_RATES
        .iter()
        .find(|(r, _)| r == bitrate)
        .map(|(_, c)| *c)
        .ok_or_else(|| format!("slcan does not support {bitrate} bit/s"))?;
    // Close any open channel, flush, set the rate, open.
    let init = format!(
        "\r\r\rC\rS{code}\r{}\r",
        if *listen_only { 'L' } else { 'O' }
    );
    p.write_all(init.as_bytes()).map_err(|e| e.to_string())?;
    let _ = p.flush();
    let _ = tx.send(CanEvent::Opened(backend.label()));
    let mut b = Batch {
        tx,
        buf: Vec::new(),
        last: Instant::now(),
    };
    let mut snd = Sender2 { periodic: None };
    let mut line = String::new();
    let mut rbuf = [0u8; 4096];
    let mut bells = 0u32;
    while !stop.load(Ordering::Relaxed) {
        for mut f in snd.due(cmds) {
            if *listen_only {
                let _ = tx.send(CanEvent::Warning("listen-only mode: not sending".into()));
                continue;
            }
            match p.write_all(slcan_encode(&f).as_bytes()) {
                Ok(()) => {
                    f.ts = now();
                    f.tx = true;
                    b.push(f);
                }
                Err(e) => {
                    let _ = tx.send(CanEvent::Warning(format!("send failed: {e}")));
                }
            }
        }
        match p.read(&mut rbuf) {
            Ok(n) => {
                for &c in &rbuf[..n] {
                    match c {
                        b'\r' | b'\n' => {
                            if let Some(mut f) = slcan_decode(&line) {
                                f.ts = now();
                                b.push(f);
                            }
                            line.clear();
                        }
                        7 => {
                            bells += 1;
                            if bells <= 3 || bells.is_power_of_two() {
                                let _ = tx.send(CanEvent::Warning(format!(
                                    "adapter rejected a command (BEL, {bells} so far)"
                                )));
                            }
                            line.clear();
                        }
                        c if line.len() < 200 => line.push(c as char),
                        _ => line.clear(),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                b.flush();
                return Err(e.to_string());
            }
        }
        b.tick();
    }
    b.flush();
    let _ = p.write_all(b"C\r");
    Ok(())
}

// ---------------------------------------------------------------- statistics

#[derive(Clone, Debug, Default)]
pub struct IdStats {
    pub id: u32,
    pub ext: bool,
    pub count: u64,
    pub first: f64,
    pub last: f64,
    pub last_data: Vec<u8>,
    /// Timestamp each byte last changed (for highlighting).
    pub changed_at: Vec<f64>,
    // Welford running mean / variance of the period.
    n_periods: u64,
    mean: f64,
    m2: f64,
    pub min_period: f64,
    pub max_period: f64,
    pub tx: bool,
    pub fd: bool,
}

impl IdStats {
    pub fn update(&mut self, f: &Frame) {
        if self.count == 0 {
            self.id = f.id;
            self.ext = f.ext;
            self.first = f.ts;
            self.min_period = f64::MAX;
            self.changed_at = vec![f.ts; f.data.len()];
        } else {
            let p = f.ts - self.last;
            if p >= 0.0 {
                self.n_periods += 1;
                let d = p - self.mean;
                self.mean += d / self.n_periods as f64;
                self.m2 += d * (p - self.mean);
                self.min_period = self.min_period.min(p);
                self.max_period = self.max_period.max(p);
            }
            self.changed_at.resize(f.data.len(), f.ts);
            for (i, b) in f.data.iter().enumerate() {
                if self.last_data.get(i) != Some(b) {
                    self.changed_at[i] = f.ts;
                }
            }
        }
        self.count += 1;
        self.last = f.ts;
        self.last_data = f.data.clone();
        self.tx |= f.tx;
        self.fd |= f.fd;
    }

    /// Mean period in seconds.
    pub fn period(&self) -> Option<f64> {
        (self.n_periods > 0).then_some(self.mean)
    }

    /// Standard deviation of the period in seconds.
    pub fn jitter(&self) -> Option<f64> {
        (self.n_periods > 1).then(|| (self.m2 / (self.n_periods - 1) as f64).sqrt())
    }

    pub fn rate(&self) -> f64 {
        match self.period() {
            Some(p) if p > 0.0 => 1.0 / p,
            _ => 0.0,
        }
    }
}

/// Matches an ID/mask filter: `(id & mask) == (filter & mask)`.
pub fn filter_match(id: u32, filter: u32, mask: u32) -> bool {
    id & mask == filter & mask
}

/// Parse a filter like `123`, `100:7F0` (id:mask) or `100-1FF` (range).
pub fn parse_filter(s: &str) -> Result<Option<(u32, u32, bool)>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let h = |x: &str| u32::from_str_radix(x.trim(), 16).map_err(|_| format!("bad hex '{x}'"));
    if let Some((a, b)) = s.split_once(':') {
        Ok(Some((h(a)?, h(b)?, false)))
    } else if let Some((a, b)) = s.split_once('-') {
        Ok(Some((h(a)?, h(b)?, true)))
    } else {
        Ok(Some((h(s)?, 0x1fff_ffff, false)))
    }
}

pub fn filter_ok(f: &Frame, filt: Option<(u32, u32, bool)>) -> bool {
    match filt {
        None => true,
        Some((a, b, true)) => f.id >= a && f.id <= b,
        Some((id, mask, false)) => filter_match(f.id, id, mask),
    }
}

// ---------------------------------------------------------------- CLI

fn cli_backend(spec: &str, bitrate: u32, listen: bool) -> Backend {
    if let Some(port) = spec.strip_prefix("slcan:") {
        Backend::Slcan {
            port: port.to_string(),
            baud: 115_200,
            bitrate,
            listen_only: listen,
        }
    } else {
        Backend::SocketCan(spec.to_string())
    }
}

/// `--can list` | `--can IFACE|slcan:PORT [--bitrate N] [--listen] [send FRAME…] [--count N]`
pub fn cli(args: &[String]) {
    let usage = "usage: --can list\n       --can IFACE|slcan:PORT [--bitrate 500000] [--listen] [--count N] [send ID#DATA ...]";
    let Some(spec) = args.first() else {
        eprintln!("{usage}");
        std::process::exit(2)
    };
    if spec == "list" {
        for (n, st) in socketcan_interfaces() {
            let (b, d) = socketcan_bitrates(&n);
            println!(
                "{n:<12} {st:<8} {}{}",
                b.map(|b| format!("{b} bit/s")).unwrap_or_default(),
                d.map(|d| format!(" data {d} bit/s")).unwrap_or_default()
            );
        }
        if !cfg!(target_os = "linux") {
            eprintln!("SocketCAN is Linux-only; slcan adapters: use --can slcan:PORT");
        }
        if let Ok(ports) = crate::serial::list_ports() {
            for p in ports {
                println!("slcan:{:<20} {} {}", p.name, p.kind, p.detail);
            }
        }
        return;
    }
    let mut bitrate = 500_000;
    let mut listen = false;
    let mut count: Option<u64> = None;
    let mut sends = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bitrate" => {
                i += 1;
                bitrate = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(500_000)
            }
            "--listen" => listen = true,
            "--count" => {
                i += 1;
                count = args.get(i).and_then(|v| v.parse().ok())
            }
            "send" => {
                for a in &args[i + 1..] {
                    match parse_cansend(a) {
                        Ok(f) => sends.push(f),
                        Err(e) => {
                            eprintln!("{a}: {e}");
                            std::process::exit(2)
                        }
                    }
                }
                break;
            }
            other => {
                eprintln!("unknown option '{other}'\n{usage}");
                std::process::exit(2)
            }
        }
        i += 1;
    }
    let h = open(cli_backend(spec, bitrate, listen));
    let sending = !sends.is_empty();
    for f in sends {
        h.send(f);
    }
    let mut seen = 0u64;
    let t_end = sending.then(|| Instant::now() + Duration::from_millis(500));
    loop {
        match h.events.recv_timeout(Duration::from_millis(100)) {
            Ok(CanEvent::Opened(d)) => eprintln!("opened {d}"),
            Ok(CanEvent::Frames(fs)) => {
                for f in fs {
                    let body = if f.err {
                        describe_error(&f)
                    } else if f.rtr {
                        format!("remote request, DLC {}", f.rtr_len)
                    } else {
                        format!("[{}] {}", f.data.len(), f.hex())
                    };
                    println!(
                        "({:.6}) {} {:>8}  {}{}",
                        f.ts,
                        if f.tx { "TX" } else { "RX" },
                        f.id_str(),
                        body,
                        if f.fd { "  FD" } else { "" }
                    );
                    seen += 1;
                    if count.is_some_and(|c| seen >= c) {
                        return;
                    }
                }
            }
            Ok(CanEvent::Warning(w)) => eprintln!("warning: {w}"),
            Ok(CanEvent::Closed(e)) => {
                if let Some(e) = e {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
                return;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return,
        }
        if t_end.is_some_and(|t| Instant::now() >= t) && count.is_none() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlc_table() {
        assert_eq!(dlc_to_len(8), 8);
        assert_eq!(dlc_to_len(9), 12);
        assert_eq!(dlc_to_len(15), 64);
        assert_eq!(len_to_dlc(13), 10);
        assert_eq!(len_to_dlc(64), 15);
        assert_eq!(fd_pad(33), 48);
    }

    #[test]
    fn cansend_syntax() {
        let f = parse_cansend("123#DEADBEEF").unwrap();
        assert_eq!(
            (f.id, f.ext, f.data.clone()),
            (0x123, false, vec![0xde, 0xad, 0xbe, 0xef])
        );
        let f = parse_cansend("1F334455#11.22.33").unwrap();
        assert!(f.ext);
        assert_eq!(f.data, vec![0x11, 0x22, 0x33]);
        let f = parse_cansend("123#R").unwrap();
        assert!(f.rtr && f.rtr_len == 0);
        let f = parse_cansend("00000123#R3").unwrap();
        assert!(f.ext && f.rtr && f.rtr_len == 3);
        let f = parse_cansend("213##311223344556677889900").unwrap();
        assert!(f.fd && f.brs && f.esi);
        assert_eq!(f.data.len(), 12); // 10 bytes padded to 12
        assert_eq!(to_cansend(&parse_cansend("7FF#0102").unwrap()), "7FF#0102");
        assert!(parse_cansend("123#010203040506070809").is_err());
        assert!(parse_cansend("XYZ#00").is_err());
    }

    #[test]
    fn slcan_roundtrip() {
        // Lawicel examples: t1230 = ID 123 no data; t4563112233 = ID 456 3 bytes.
        let f = slcan_decode("t4563112233").unwrap();
        assert_eq!((f.id, f.data.clone()), (0x456, vec![0x11, 0x22, 0x33]));
        assert_eq!(slcan_encode(&f), "t4563112233\r");
        let f = slcan_decode("T12ABCDEF2AA55").unwrap();
        assert!(f.ext);
        assert_eq!(f.id, 0x12ABCDEF);
        assert_eq!(f.data, vec![0xaa, 0x55]);
        assert_eq!(slcan_encode(&f), "T12ABCDEF2AA55\r");
        let f = slcan_decode("r1002").unwrap();
        assert!(f.rtr && f.rtr_len == 2);
        assert_eq!(slcan_encode(&f), "r1002\r");
        // Trailing 4-digit timestamp is ignored.
        let f = slcan_decode("t12320102EA5F").unwrap();
        assert_eq!(f.data, vec![1, 2]);
        // CAN FD with BRS, DLC 9 = 12 bytes.
        let f = slcan_decode("b1239000102030405060708090A0B").unwrap();
        assert!(f.fd && f.brs);
        assert_eq!(f.data.len(), 12);
        assert_eq!(slcan_encode(&f), "b1239000102030405060708090A0B\r");
        assert!(slcan_decode("t12").is_none());
        assert!(slcan_decode("z").is_none());
        assert!(slcan_decode("t1239").is_none()); // classic DLC > 8
    }

    #[test]
    fn socketcan_layout() {
        let f = parse_cansend("123#DEADBEEF").unwrap();
        let b = sock_encode(&f);
        assert_eq!(b.len(), 16);
        assert_eq!(u32::from_ne_bytes(b[0..4].try_into().unwrap()), 0x123);
        assert_eq!(b[4], 4);
        assert_eq!(&b[8..12], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(sock_decode(&b).unwrap(), f);

        let f = parse_cansend("1ABCDEF0#R5").unwrap();
        let b = sock_encode(&f);
        assert_eq!(
            u32::from_ne_bytes(b[0..4].try_into().unwrap()),
            0x1ABCDEF0 | CAN_EFF_FLAG | CAN_RTR_FLAG
        );
        assert_eq!(sock_decode(&b).unwrap(), f);

        let f = parse_cansend("321##1AABB").unwrap();
        let b = sock_encode(&f);
        assert_eq!(b.len(), 72);
        assert_eq!(b[5], CANFD_FDF | CANFD_BRS);
        let d = sock_decode(&b).unwrap();
        assert!(d.fd && d.brs && !d.esi);
        assert_eq!(d.data, vec![0xaa, 0xbb]);

        // Error frame: bus-off + controller RX passive.
        let mut e = [0u8; 16];
        e[0..4].copy_from_slice(&(CAN_ERR_FLAG | 0x40 | 0x04).to_ne_bytes());
        e[4] = 8;
        e[9] = 0x10;
        e[14] = 130;
        e[15] = 7;
        let d = sock_decode(&e).unwrap();
        assert!(d.err);
        let s = describe_error(&d);
        assert!(
            s.contains("BUS OFF") && s.contains("RX passive") && s.contains("TEC 130"),
            "{s}"
        );
    }

    #[test]
    fn stats_period_and_changes() {
        let mut s = IdStats::default();
        for (i, t) in [0.0, 0.1, 0.2, 0.31].iter().enumerate() {
            let mut f = Frame::new(0x100, false, vec![1, i as u8]);
            f.ts = *t;
            s.update(&f);
        }
        assert_eq!(s.count, 4);
        assert!((s.period().unwrap() - 0.1033).abs() < 0.001);
        assert!(s.jitter().unwrap() > 0.0);
        assert_eq!(s.changed_at[0], 0.0);
        assert_eq!(s.changed_at[1], 0.31);
    }

    #[test]
    fn filters_and_bits() {
        assert_eq!(
            parse_filter("100:7F0").unwrap(),
            Some((0x100, 0x7f0, false))
        );
        let f = Frame::new(0x10f, false, vec![]);
        assert!(filter_ok(&f, parse_filter("100:7F0").unwrap()));
        assert!(!filter_ok(&f, parse_filter("200").unwrap()));
        assert!(filter_ok(&f, parse_filter("100-1FF").unwrap()));
        // 8-byte standard frame: 98 bits + up to 24 stuff bits + 13.
        let b = Frame::new(0x100, false, vec![0; 8]).wire_bits(1.0);
        assert!((120.0..140.0).contains(&b), "{b}");
        assert_eq!(
            parse_ip_bitrates(
                "can state ERROR-ACTIVE\n bitrate 500000 sample-point 0.875\n dbitrate 2000000"
            ),
            (Some(500_000), Some(2_000_000))
        );
    }
}
