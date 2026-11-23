//! Modbus RTU / TCP: frame building and parsing, a blocking master (client)
//! running on its own thread, unit-ID / host scans, and a passive decoder used
//! by the serial monitor and the packet analyser.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::serial::SerialSettings;

// ---------------------------------------------------------------- protocol

pub const MAX_READ_BITS: u16 = 2000;
pub const MAX_READ_WORDS: u16 = 125;

pub fn function_name(fc: u8) -> &'static str {
    match fc & 0x7f {
        1 => "Read Coils",
        2 => "Read Discrete Inputs",
        3 => "Read Holding Registers",
        4 => "Read Input Registers",
        5 => "Write Single Coil",
        6 => "Write Single Register",
        7 => "Read Exception Status",
        8 => "Diagnostics",
        11 => "Get Comm Event Counter",
        15 => "Write Multiple Coils",
        16 => "Write Multiple Registers",
        17 => "Report Server ID",
        22 => "Mask Write Register",
        23 => "Read/Write Multiple Registers",
        43 => "Encapsulated Interface (Device ID)",
        _ => "Unknown function",
    }
}

pub fn exception_name(code: u8) -> &'static str {
    match code {
        1 => "Illegal Function",
        2 => "Illegal Data Address",
        3 => "Illegal Data Value",
        4 => "Server Device Failure",
        5 => "Acknowledge",
        6 => "Server Device Busy",
        8 => "Memory Parity Error",
        10 => "Gateway Path Unavailable",
        11 => "Gateway Target Failed to Respond",
        _ => "Unknown exception",
    }
}

/// Modbus CRC-16 (poly 0xA001, init 0xFFFF). Transmitted low byte first.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    Coils,
    DiscreteInputs,
    HoldingRegisters,
    InputRegisters,
}

impl Table {
    pub const ALL: [Table; 4] = [
        Table::Coils,
        Table::DiscreteInputs,
        Table::HoldingRegisters,
        Table::InputRegisters,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Table::Coils => "Coils (FC1)",
            Table::DiscreteInputs => "Discrete inputs (FC2)",
            Table::HoldingRegisters => "Holding registers (FC3)",
            Table::InputRegisters => "Input registers (FC4)",
        }
    }
    pub fn is_bits(self) -> bool {
        matches!(self, Table::Coils | Table::DiscreteInputs)
    }
    pub fn writable(self) -> bool {
        matches!(self, Table::Coils | Table::HoldingRegisters)
    }
    pub fn max_qty(self) -> u16 {
        if self.is_bits() {
            MAX_READ_BITS
        } else {
            MAX_READ_WORDS
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    Read {
        table: Table,
        addr: u16,
        qty: u16,
    },
    WriteCoil {
        addr: u16,
        value: bool,
    },
    WriteRegister {
        addr: u16,
        value: u16,
    },
    WriteCoils {
        addr: u16,
        values: Vec<bool>,
    },
    WriteRegisters {
        addr: u16,
        values: Vec<u16>,
    },
    /// FC 43 / MEI 14, basic or regular category.
    ReadDeviceId {
        category: u8,
    },
}

impl Request {
    pub fn function(&self) -> u8 {
        match self {
            Request::Read { table, .. } => match table {
                Table::Coils => 1,
                Table::DiscreteInputs => 2,
                Table::HoldingRegisters => 3,
                Table::InputRegisters => 4,
            },
            Request::WriteCoil { .. } => 5,
            Request::WriteRegister { .. } => 6,
            Request::WriteCoils { .. } => 15,
            Request::WriteRegisters { .. } => 16,
            Request::ReadDeviceId { .. } => 43,
        }
    }

    pub fn pdu(&self) -> Vec<u8> {
        let mut p = vec![self.function()];
        let be = |p: &mut Vec<u8>, v: u16| p.extend_from_slice(&v.to_be_bytes());
        match self {
            Request::Read { addr, qty, .. } => {
                be(&mut p, *addr);
                be(&mut p, *qty);
            }
            Request::WriteCoil { addr, value } => {
                be(&mut p, *addr);
                be(&mut p, if *value { 0xff00 } else { 0 });
            }
            Request::WriteRegister { addr, value } => {
                be(&mut p, *addr);
                be(&mut p, *value);
            }
            Request::WriteCoils { addr, values } => {
                be(&mut p, *addr);
                be(&mut p, values.len() as u16);
                let bytes = pack_bits(values);
                p.push(bytes.len() as u8);
                p.extend(bytes);
            }
            Request::WriteRegisters { addr, values } => {
                be(&mut p, *addr);
                be(&mut p, values.len() as u16);
                p.push((values.len() * 2) as u8);
                for v in values {
                    be(&mut p, *v);
                }
            }
            Request::ReadDeviceId { category } => p.extend_from_slice(&[0x0e, *category, 0x00]),
        }
        p
    }

    pub fn describe(&self) -> String {
        match self {
            Request::Read { table, addr, qty } => format!("{} @{addr} ×{qty}", table.label()),
            Request::WriteCoil { addr, value } => {
                format!("Write coil @{addr} = {}", if *value { "ON" } else { "OFF" })
            }
            Request::WriteRegister { addr, value } => format!("Write register @{addr} = {value}"),
            Request::WriteCoils { addr, values } => {
                format!("Write {} coils @{addr}", values.len())
            }
            Request::WriteRegisters { addr, values } => {
                format!("Write {} registers @{addr}", values.len())
            }
            Request::ReadDeviceId { .. } => "Read device identification".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Response {
    Bits(Vec<bool>),
    Words(Vec<u16>),
    /// Echo of a write: (address, value or quantity).
    Written(u16, u16),
    DeviceId(Vec<(u8, String)>),
    Exception {
        function: u8,
        code: u8,
    },
}

fn pack_bits(values: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; values.len().div_ceil(8)];
    for (i, v) in values.iter().enumerate() {
        if *v {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

fn unpack_bits(bytes: &[u8], n: usize) -> Vec<bool> {
    (0..n)
        .map(|i| bytes.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0))
        .collect()
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Parse a response PDU (function code first) for the request that caused it.
pub fn parse_response(req: &Request, pdu: &[u8]) -> Result<Response, String> {
    let fc = *pdu.first().ok_or("empty response")?;
    if fc & 0x80 != 0 {
        let code = *pdu.get(1).ok_or("truncated exception")?;
        return Ok(Response::Exception {
            function: fc & 0x7f,
            code,
        });
    }
    if fc != req.function() {
        return Err(format!(
            "function code mismatch: sent {}, got {fc}",
            req.function()
        ));
    }
    match req {
        Request::Read { table, qty, .. } => {
            let n = *pdu.get(1).ok_or("truncated response")? as usize;
            let data = pdu.get(2..2 + n).ok_or("truncated data")?;
            if table.is_bits() {
                if n < (*qty as usize).div_ceil(8) {
                    return Err("short bit response".into());
                }
                Ok(Response::Bits(unpack_bits(data, *qty as usize)))
            } else {
                if n < *qty as usize * 2 {
                    return Err("short register response".into());
                }
                Ok(Response::Words(
                    data.as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect(),
                ))
            }
        }
        Request::WriteCoil { .. }
        | Request::WriteRegister { .. }
        | Request::WriteCoils { .. }
        | Request::WriteRegisters { .. } => Ok(Response::Written(
            be16(pdu, 1).ok_or("truncated")?,
            be16(pdu, 3).ok_or("truncated")?,
        )),
        Request::ReadDeviceId { .. } => {
            parse_device_id(pdu).ok_or_else(|| "bad device-id reply".into())
        }
    }
}

fn parse_device_id(pdu: &[u8]) -> Option<Response> {
    // fc, mei, read code, conformity, more, next id, count, objects…
    if *pdu.get(1)? != 0x0e {
        return None;
    }
    let count = *pdu.get(6)? as usize;
    let mut pos = 7;
    let mut objs = Vec::new();
    for _ in 0..count {
        let id = *pdu.get(pos)?;
        let len = *pdu.get(pos + 1)? as usize;
        let val = pdu.get(pos + 2..pos + 2 + len)?;
        objs.push((id, String::from_utf8_lossy(val).trim().to_string()));
        pos += 2 + len;
    }
    Some(Response::DeviceId(objs))
}

pub fn device_object_name(id: u8) -> &'static str {
    match id {
        0 => "Vendor",
        1 => "Product code",
        2 => "Revision",
        3 => "Vendor URL",
        4 => "Product name",
        5 => "Model name",
        6 => "Application name",
        _ => "Object",
    }
}

pub fn rtu_frame(unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(pdu.len() + 3);
    f.push(unit);
    f.extend_from_slice(pdu);
    let crc = crc16(&f);
    f.extend_from_slice(&crc.to_le_bytes());
    f
}

pub fn tcp_frame(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(pdu.len() + 7);
    f.extend_from_slice(&tid.to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    f.push(unit);
    f.extend_from_slice(pdu);
    f
}

/// Total length of an RTU *response* frame given its first bytes, or None
/// if more bytes are needed to tell.
pub fn rtu_response_len(buf: &[u8]) -> Option<usize> {
    let fc = *buf.get(1)?;
    if fc & 0x80 != 0 {
        return Some(5);
    }
    match fc {
        1..=4 | 23 | 17 => Some(5 + *buf.get(2)? as usize),
        5 | 6 | 15 | 16 => Some(8),
        43 => {
            // unit fc mei code conf more next count {id len data}* crc
            let count = *buf.get(7)? as usize;
            let mut pos = 8;
            for _ in 0..count {
                let len = *buf.get(pos + 1)? as usize;
                pos += 2 + len;
            }
            Some(pos + 2)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------- passive decoder

/// Human-readable description of a PDU. `request` = Some(true/false) if the
/// direction is known; None = guess from the length.
pub fn describe_pdu(pdu: &[u8], request: Option<bool>) -> String {
    let Some(&fc) = pdu.first() else {
        return "empty PDU".into();
    };
    if fc & 0x80 != 0 {
        let code = pdu.get(1).copied().unwrap_or(0);
        return format!(
            "Exception to {} (FC{}): {} ({code})",
            function_name(fc),
            fc & 0x7f,
            exception_name(code)
        );
    }
    let name = function_name(fc);
    let is_req = request.unwrap_or_else(|| guess_is_request(pdu));
    let tail = match (fc, is_req) {
        (1..=4, true) => match (be16(pdu, 1), be16(pdu, 3)) {
            (Some(a), Some(q)) => format!("addr {a} qty {q}"),
            _ => "truncated".into(),
        },
        (1 | 2, false) => {
            let n = pdu.get(1).copied().unwrap_or(0) as usize;
            let data = pdu.get(2..2 + n).unwrap_or(&[]);
            let bits: String = unpack_bits(data, (n * 8).min(32))
                .iter()
                .map(|b| if *b { '1' } else { '0' })
                .collect();
            format!("{n} bytes: {bits}{}", if n > 4 { "…" } else { "" })
        }
        (3 | 4 | 23, false) => {
            let n = pdu.get(1).copied().unwrap_or(0) as usize;
            let data = pdu.get(2..2 + n).unwrap_or(&[]);
            let words: Vec<String> = data
                .as_chunks::<2>()
                .0
                .iter()
                .take(12)
                .map(|c| u16::from_be_bytes([c[0], c[1]]).to_string())
                .collect();
            format!(
                "{} regs: [{}{}]",
                n / 2,
                words.join(", "),
                if n / 2 > 12 { ", …" } else { "" }
            )
        }
        (5, _) => match (be16(pdu, 1), be16(pdu, 3)) {
            (Some(a), Some(v)) => {
                format!("addr {a} = {}", if v == 0xff00 { "ON" } else { "OFF" })
            }
            _ => "truncated".into(),
        },
        (6, _) => match (be16(pdu, 1), be16(pdu, 3)) {
            (Some(a), Some(v)) => format!("addr {a} = {v}"),
            _ => "truncated".into(),
        },
        (15 | 16, _) => match (be16(pdu, 1), be16(pdu, 3)) {
            (Some(a), Some(q)) => format!("addr {a} qty {q}"),
            _ => "truncated".into(),
        },
        (43, _) => match parse_device_id(pdu) {
            Some(Response::DeviceId(o)) if !is_req => o
                .iter()
                .map(|(id, v)| format!("{}={v}", device_object_name(*id)))
                .collect::<Vec<_>>()
                .join(", "),
            _ => "MEI 14".into(),
        },
        _ => format!("{} data bytes", pdu.len() - 1),
    };
    format!(
        "{} {name} (FC{fc}) {tail}",
        if is_req { "→ Req" } else { "← Rsp" }
    )
}

fn guess_is_request(pdu: &[u8]) -> bool {
    match pdu.first() {
        // Response: fc, byte count, data (len == 2 + count).
        Some(1..=4 | 23) => !(pdu.len() >= 2 && pdu.len() == 2 + pdu[1] as usize),
        // Writes of multiple values: requests carry a byte count + data.
        Some(15 | 16) => pdu.len() > 5,
        Some(43) => pdu.len() <= 4,
        _ => true,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RtuDecoded {
    pub unit: u8,
    pub crc_ok: bool,
    pub text: String,
}

/// Decode one RTU frame (unit, PDU, CRC). None if too short to be Modbus.
pub fn decode_rtu(frame: &[u8]) -> Option<RtuDecoded> {
    if frame.len() < 4 {
        return None;
    }
    let (body, crc) = frame.split_at(frame.len() - 2);
    let crc_ok = crc16(body) == u16::from_le_bytes([crc[0], crc[1]]);
    Some(RtuDecoded {
        unit: body[0],
        crc_ok,
        text: describe_pdu(&body[1..], None),
    })
}

/// CRC check only (cheap): None if too short to be an RTU frame.
pub fn rtu_crc_ok(frame: &[u8]) -> Option<bool> {
    if frame.len() < 4 {
        return None;
    }
    let (body, crc) = frame.split_at(frame.len() - 2);
    Some(crc16(body) == u16::from_le_bytes([crc[0], crc[1]]))
}

/// Decode the Modbus/TCP ADUs in a TCP payload. `to_server` = the payload was
/// sent to port 502 (a request).
pub fn decode_tcp(payload: &[u8], to_server: Option<bool>) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = payload;
    while p.len() >= 8 {
        let tid = u16::from_be_bytes([p[0], p[1]]);
        let proto = u16::from_be_bytes([p[2], p[3]]);
        let len = u16::from_be_bytes([p[4], p[5]]) as usize;
        if proto != 0 || len < 2 || p.len() < 6 + len {
            break;
        }
        let unit = p[6];
        out.push(format!(
            "tid {tid} unit {unit}: {}",
            describe_pdu(&p[7..6 + len], to_server)
        ));
        p = &p[6 + len..];
    }
    out
}

/// Split a serial byte stream into RTU frames using the inter-frame silence.
/// `chunks` are (arrival time, bytes); a gap > `gap` starts a new frame.
pub fn split_frames(chunks: &[(Instant, Vec<u8>)], gap: Duration) -> Vec<(Instant, Vec<u8>)> {
    let mut out: Vec<(Instant, Vec<u8>)> = Vec::new();
    let mut last: Option<Instant> = None;
    for (t, bytes) in chunks {
        match (last, out.last_mut()) {
            (Some(prev), Some(cur)) if t.duration_since(prev) <= gap => {
                cur.1.extend_from_slice(bytes)
            }
            _ => out.push((*t, bytes.clone())),
        }
        last = Some(*t);
    }
    out
}

/// 3.5 character times (11 bits/char), at least 1.75 ms per the spec.
/// Padded generously because OS serial drivers deliver bytes in bursts.
pub fn rtu_gap(baud: u32) -> Duration {
    let t = Duration::from_secs_f64(3.5 * 11.0 / baud.max(1) as f64);
    t.max(Duration::from_micros(1750)) + Duration::from_millis(8)
}

// ---------------------------------------------------------------- transport

#[derive(Clone, Debug)]
pub enum Endpoint {
    Tcp { host: String, port: u16 },
    Rtu(SerialSettings),
}

impl Endpoint {
    pub fn label(&self) -> String {
        match self {
            Endpoint::Tcp { host, port } => format!("TCP {host}:{port}"),
            Endpoint::Rtu(s) => format!("RTU {} {}", s.port, s.summary()),
        }
    }
}

enum Link {
    Tcp {
        s: TcpStream,
        tid: u16,
    },
    Rtu {
        port: Box<dyn serialport::SerialPort>,
        gap: Duration,
    },
}

/// Bytes on the wire, for the traffic log.
pub type Wire = (bool, Vec<u8>);

impl Link {
    fn open(ep: &Endpoint, wait: Duration) -> Result<Link, String> {
        match ep {
            Endpoint::Tcp { host, port } => {
                let addr = resolve(host, *port)?;
                let s = TcpStream::connect_timeout(&addr, wait)
                    .map_err(|e| format!("connect {addr}: {e}"))?;
                s.set_read_timeout(Some(wait)).ok();
                s.set_write_timeout(Some(wait)).ok();
                s.set_nodelay(true).ok();
                Ok(Link::Tcp { s, tid: 0 })
            }
            Endpoint::Rtu(cfg) => {
                let port = cfg.open(wait).map_err(|e| format!("{}: {e}", cfg.port))?;
                Ok(Link::Rtu {
                    port,
                    gap: rtu_gap(cfg.baud),
                })
            }
        }
    }

    fn transact(
        &mut self,
        unit: u8,
        req: &Request,
        wait: Duration,
        log: &mut Vec<Wire>,
    ) -> Result<Response, String> {
        let pdu = req.pdu();
        match self {
            Link::Tcp { s, tid } => {
                *tid = tid.wrapping_add(1);
                let frame = tcp_frame(*tid, unit, &pdu);
                log.push((true, frame.clone()));
                s.write_all(&frame).map_err(|e| format!("send: {e}"))?;
                loop {
                    let mut hdr = [0u8; 7];
                    read_exact_timeout(s, &mut hdr)?;
                    let len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
                    if !(2..=260).contains(&len) {
                        return Err(format!("bad MBAP length {len}"));
                    }
                    let mut body = vec![0u8; len - 1];
                    read_exact_timeout(s, &mut body)?;
                    let mut raw = hdr.to_vec();
                    raw.extend_from_slice(&body);
                    log.push((false, raw));
                    // Stale answer to an earlier, timed-out request: skip it.
                    if u16::from_be_bytes([hdr[0], hdr[1]]) != *tid {
                        continue;
                    }
                    return parse_response(req, &body);
                }
            }
            Link::Rtu { port, gap } => {
                let frame = rtu_frame(unit, &pdu);
                // Drop line noise / late replies before talking.
                port.clear(serialport::ClearBuffer::Input).ok();
                std::thread::sleep(*gap);
                log.push((true, frame.clone()));
                port.write_all(&frame).map_err(|e| format!("send: {e}"))?;
                port.flush().ok();
                let deadline = Instant::now() + wait;
                let mut buf = Vec::new();
                let mut tmp = [0u8; 256];
                loop {
                    if let Some(n) = rtu_response_len(&buf)
                        && buf.len() >= n
                    {
                        buf.truncate(n);
                        break;
                    }
                    if Instant::now() >= deadline {
                        if !buf.is_empty() {
                            log.push((false, buf.clone()));
                        }
                        return Err(if buf.is_empty() {
                            "timeout (no reply)".into()
                        } else {
                            format!("timeout (partial reply, {} bytes)", buf.len())
                        });
                    }
                    match port.read(&mut tmp) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(e) => return Err(format!("read: {e}")),
                    }
                }
                log.push((false, buf.clone()));
                let (body, crc) = buf.split_at(buf.len() - 2);
                if crc16(body) != u16::from_le_bytes([crc[0], crc[1]]) {
                    return Err("CRC error in reply".into());
                }
                if body[0] != unit {
                    return Err(format!("reply from unit {} (expected {unit})", body[0]));
                }
                parse_response(req, &body[1..])
            }
        }
    }
}

fn read_exact_timeout(s: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    s.read_exact(buf).map_err(|e| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            "timeout (no reply)".into()
        }
        std::io::ErrorKind::UnexpectedEof => "connection closed by device".into(),
        _ => format!("read: {e}"),
    })
}

pub fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host.trim(), port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}: no address"))
}

// ---------------------------------------------------------------- master thread

pub enum Command {
    /// Run once; with `every` set, repeat until another command arrives.
    Run {
        unit: u8,
        req: Request,
        every: Option<Duration>,
    },
    ScanUnits {
        from: u8,
        to: u8,
    },
    ScanHosts {
        targets: Vec<std::net::Ipv4Addr>,
        port: u16,
        unit: u8,
    },
    Stop,
}

pub enum Event {
    Connected(String),
    Disconnected(Option<String>),
    Reply {
        unit: u8,
        req: Request,
        result: Result<Response, String>,
        rtt: Duration,
    },
    Traffic(Instant, Wire),
    /// A unit ID (RTU/TCP gateway) or host (TCP) that answered.
    Found {
        who: String,
        detail: String,
    },
    Progress {
        done: usize,
        total: usize,
    },
    ScanDone,
}

pub struct Master {
    pub events: Receiver<Event>,
    cmds: Sender<Command>,
    busy: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Master {
    pub fn send(&self, c: Command) {
        // A new command interrupts a running poll loop or scan.
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.cmds.send(c);
    }
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::Relaxed)
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Open the endpoint on a worker thread. Commands are handled in order.
pub fn connect(ep: Endpoint, wait: Duration) -> Master {
    spawn(Some(ep), wait)
}

/// A worker without a device link, for [`Command::ScanHosts`].
pub fn host_scanner(wait: Duration) -> Master {
    spawn(None, wait)
}

fn spawn(ep: Option<Endpoint>, wait: Duration) -> Master {
    let (etx, erx) = channel();
    let (ctx, crx) = channel::<Command>();
    let busy = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (b2, s2) = (busy.clone(), stop.clone());
    std::thread::Builder::new()
        .name("modbus".into())
        .spawn(move || master_loop(ep, wait, crx, etx, b2, s2))
        .expect("spawn modbus thread");
    Master {
        events: erx,
        cmds: ctx,
        busy,
        stop,
    }
}

fn master_loop(
    ep: Option<Endpoint>,
    wait: Duration,
    cmds: Receiver<Command>,
    tx: Sender<Event>,
    busy: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    let mut link = match ep.as_ref().map(|ep| (ep, Link::open(ep, wait))) {
        Some((ep, Ok(l))) => {
            let _ = tx.send(Event::Connected(ep.label()));
            Some(l)
        }
        Some((_, Err(e))) => {
            let _ = tx.send(Event::Disconnected(Some(e)));
            return;
        }
        None => None,
    };
    let log = |tx: &Sender<Event>, wire: Vec<Wire>| {
        for w in wire {
            let _ = tx.send(Event::Traffic(Instant::now(), w));
        }
    };
    while let Ok(cmd) = cmds.recv() {
        stop.store(false, Ordering::Relaxed);
        busy.store(true, Ordering::Relaxed);
        match cmd {
            Command::Stop => {}
            Command::Run { unit, req, every } => loop {
                let Some(l) = link.as_mut() else {
                    let _ = tx.send(Event::Disconnected(Some("not connected".into())));
                    break;
                };
                let mut wire = Vec::new();
                let t = Instant::now();
                let result = l.transact(unit, &req, wait, &mut wire);
                log(&tx, wire);
                let rtt = t.elapsed();
                // A broken TCP stream: reconnect once on the next round.
                let dead =
                    matches!(&result, Err(e) if e.contains("closed") || e.starts_with("send"));
                let _ = tx.send(Event::Reply {
                    unit,
                    req: req.clone(),
                    result,
                    rtt,
                });
                if dead && let Some(ep @ Endpoint::Tcp { .. }) = &ep {
                    link = Link::open(ep, wait).ok();
                }
                let Some(every) = every else { break };
                let until = Instant::now() + every.saturating_sub(rtt);
                while Instant::now() < until && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            },
            Command::ScanUnits { from, to } => {
                let Some(l) = link.as_mut() else {
                    let _ = tx.send(Event::Disconnected(Some("not connected".into())));
                    continue;
                };
                let total = (to as usize + 1).saturating_sub(from as usize);
                // Short timeout: most IDs are silent.
                let scan_wait = wait.min(Duration::from_millis(300));
                for (i, unit) in (from..=to).enumerate() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Some(detail) = probe_unit(l, unit, scan_wait, &tx) {
                        let _ = tx.send(Event::Found {
                            who: format!("unit {unit}"),
                            detail,
                        });
                    }
                    let _ = tx.send(Event::Progress { done: i + 1, total });
                }
                let _ = tx.send(Event::ScanDone);
            }
            Command::ScanHosts {
                targets,
                port,
                unit,
            } => {
                scan_hosts(&targets, port, unit, wait, &tx, &stop);
                let _ = tx.send(Event::ScanDone);
            }
        }
        busy.store(false, Ordering::Relaxed);
    }
}

/// Any reply, even an exception, means a device is listening on that ID.
fn probe_unit(l: &mut Link, unit: u8, wait: Duration, tx: &Sender<Event>) -> Option<String> {
    let mut wire = Vec::new();
    let probes = [
        Request::Read {
            table: Table::HoldingRegisters,
            addr: 0,
            qty: 1,
        },
        Request::Read {
            table: Table::Coils,
            addr: 0,
            qty: 1,
        },
    ];
    let mut answer = None;
    for req in &probes {
        match l.transact(unit, req, wait, &mut wire) {
            Ok(Response::Exception { function, code }) => {
                answer = Some(format!("FC{function}: exception {}", exception_name(code)));
            }
            Ok(_) => {
                answer = Some(format!("answers {}", function_name(req.function())));
                break;
            }
            Err(e) if e.contains("closed") => break,
            Err(_) => {}
        }
    }
    let answer = answer?;
    let id = l
        .transact(
            unit,
            &Request::ReadDeviceId { category: 1 },
            wait,
            &mut wire,
        )
        .ok()
        .and_then(|r| match r {
            Response::DeviceId(o) => Some(
                o.iter()
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            _ => None,
        });
    for w in wire {
        let _ = tx.send(Event::Traffic(Instant::now(), w));
    }
    Some(match id {
        Some(id) if !id.is_empty() => format!("{answer} — {id}"),
        _ => answer,
    })
}

fn scan_hosts(
    targets: &[std::net::Ipv4Addr],
    port: u16,
    unit: u8,
    wait: Duration,
    tx: &Sender<Event>,
    stop: &AtomicBool,
) {
    let total = targets.len();
    let next = Mutex::new(0usize);
    let done = Mutex::new(0usize);
    let connect_wait = wait.min(Duration::from_millis(800));
    std::thread::scope(|s| {
        for _ in 0..total.min(48) {
            s.spawn(|| {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let i = {
                        let mut n = next.lock().unwrap();
                        let i = *n;
                        *n += 1;
                        i
                    };
                    let Some(ip) = targets.get(i) else { return };
                    let addr = SocketAddr::from((*ip, port));
                    if let Ok(stream) = TcpStream::connect_timeout(&addr, connect_wait) {
                        stream.set_read_timeout(Some(wait)).ok();
                        stream.set_write_timeout(Some(wait)).ok();
                        let mut l = Link::Tcp { s: stream, tid: 0 };
                        let mut wire = Vec::new();
                        let detail = match l.transact(
                            unit,
                            &Request::ReadDeviceId { category: 1 },
                            wait,
                            &mut wire,
                        ) {
                            Ok(Response::DeviceId(o)) => o
                                .iter()
                                .map(|(_, v)| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" "),
                            Ok(Response::Exception { code, .. }) => {
                                format!("Modbus server (device ID: {})", exception_name(code))
                            }
                            Ok(_) => "Modbus server".into(),
                            Err(e) => format!("port {port} open, {e}"),
                        };
                        let _ = tx.send(Event::Found {
                            who: addr.to_string(),
                            detail,
                        });
                    }
                    let mut d = done.lock().unwrap();
                    *d += 1;
                    let _ = tx.send(Event::Progress { done: *d, total });
                }
            });
        }
    });
}

/// One-shot Modbus/TCP identification (unit 1 and 255): device ID objects,
/// or "Modbus server" if it answers anything at all. Blocking.
pub fn identify(addr: SocketAddr, wait: Duration) -> Option<String> {
    let s = TcpStream::connect_timeout(&addr, wait).ok()?;
    s.set_read_timeout(Some(wait)).ok();
    s.set_write_timeout(Some(wait)).ok();
    let mut l = Link::Tcp { s, tid: 0 };
    let mut wire = Vec::new();
    let mut answered = false;
    for unit in [1u8, 255] {
        match l.transact(
            unit,
            &Request::ReadDeviceId { category: 1 },
            wait,
            &mut wire,
        ) {
            Ok(Response::DeviceId(o)) if !o.is_empty() => {
                let id = o
                    .iter()
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                return Some(format!("Modbus: {id}"));
            }
            Ok(_) => answered = true,
            Err(e) if e.contains("closed") => break,
            Err(_) => {}
        }
    }
    answered.then(|| "Modbus server".to_string())
}

/// Render bytes as spaced hex.
pub fn hex(bytes: &[u8]) -> String {
    if bytes.len() > 512 {
        return format!("{} … ({} bytes)", hex(&bytes[..512]), bytes.len());
    }
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse register values: "100", "-5", "0x1F", "1, 2, 3".
pub fn parse_words(s: &str) -> Result<Vec<u16>, String> {
    let v: Result<Vec<u16>, String> = s
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                u16::from_str_radix(h, 16).map_err(|_| format!("bad hex value '{t}'"))
            } else if let Ok(n) = t.parse::<i32>() {
                if (-32768..=65535).contains(&n) {
                    Ok(if n < 0 { n as i16 as u16 } else { n as u16 })
                } else {
                    Err(format!("'{t}' out of range (-32768..65535)"))
                }
            } else {
                Err(format!("bad value '{t}'"))
            }
        })
        .collect();
    let v = v?;
    if v.is_empty() {
        return Err("enter a value".into());
    }
    if v.len() > 123 {
        return Err("at most 123 registers per write".into());
    }
    Ok(v)
}

/// Parse coil values: "1", "on", "1,0,1", "true false".
pub fn parse_bits(s: &str) -> Result<Vec<bool>, String> {
    let v: Result<Vec<bool>, String> = s
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| match t.to_ascii_lowercase().as_str() {
            "1" | "on" | "true" | "yes" => Ok(true),
            "0" | "off" | "false" | "no" => Ok(false),
            _ => Err(format!("bad coil value '{t}' (use 1/0 or on/off)")),
        })
        .collect();
    let v = v?;
    if v.is_empty() {
        return Err("enter a value".into());
    }
    if v.len() > 1968 {
        return Err("at most 1968 coils per write".into());
    }
    Ok(v)
}

/// Parse "01 03 00 00 00 0A", "0x01,0x03", "01030000000A".
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| !matches!(c, ' ' | ',' | ':' | '-' | '\t'))
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("invalid hex '{}'", &cleaned[i..i + 2]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_vector() {
        // 01 03 00 00 00 0A -> CRC C5 CD
        let f = rtu_frame(1, &[3, 0, 0, 0, 0x0a]);
        assert_eq!(&f[6..], &[0xc5, 0xcd]);
    }

    #[test]
    fn read_holding_roundtrip() {
        let req = Request::Read {
            table: Table::HoldingRegisters,
            addr: 0x6b,
            qty: 3,
        };
        assert_eq!(req.pdu(), vec![3, 0, 0x6b, 0, 3]);
        let rsp = [3, 6, 0x02, 0x2b, 0, 0, 0, 0x64];
        assert_eq!(
            parse_response(&req, &rsp).unwrap(),
            Response::Words(vec![555, 0, 100])
        );
        assert_eq!(rtu_response_len(&[1, 3, 6]), Some(11));
    }

    #[test]
    fn coils_and_exceptions() {
        let req = Request::Read {
            table: Table::Coils,
            addr: 19,
            qty: 10,
        };
        let r = parse_response(&req, &[1, 2, 0xcd, 0x01]).unwrap();
        assert_eq!(
            r,
            Response::Bits(vec![
                true, false, true, true, false, false, true, true, true, false
            ])
        );
        assert_eq!(
            parse_response(&req, &[0x81, 2]).unwrap(),
            Response::Exception {
                function: 1,
                code: 2
            }
        );
        let w = Request::WriteCoils {
            addr: 19,
            values: vec![
                true, false, true, true, false, false, true, true, true, false,
            ],
        };
        assert_eq!(w.pdu(), vec![15, 0, 19, 0, 10, 2, 0xcd, 0x01]);
    }

    #[test]
    fn tcp_framing_and_decode() {
        let f = tcp_frame(1, 17, &[3, 0, 0x6b, 0, 3]);
        assert_eq!(f, vec![0, 1, 0, 0, 0, 6, 17, 3, 0, 0x6b, 0, 3]);
        let d = decode_tcp(&f, Some(true));
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("Read Holding Registers") && d[0].contains("addr 107 qty 3"));
    }

    #[test]
    fn rtu_decode_guesses_direction() {
        let req = rtu_frame(1, &[3, 0, 0, 0, 2]);
        let d = decode_rtu(&req).unwrap();
        assert!(d.crc_ok && d.text.contains("Req"), "{}", d.text);
        let rsp = rtu_frame(1, &[3, 4, 0, 1, 0, 2]);
        let d = decode_rtu(&rsp).unwrap();
        assert!(
            d.crc_ok && d.text.contains("Rsp") && d.text.contains("[1, 2]"),
            "{}",
            d.text
        );
        let mut bad = rsp.clone();
        bad[3] ^= 1;
        assert!(!decode_rtu(&bad).unwrap().crc_ok);
    }

    #[test]
    fn device_id_parse() {
        let pdu = [
            43, 14, 1, 1, 0, 0, 2, 0, 3, b'A', b'B', b'C', 1, 2, b'X', b'1',
        ];
        let r = parse_response(&Request::ReadDeviceId { category: 1 }, &pdu).unwrap();
        assert_eq!(
            r,
            Response::DeviceId(vec![(0, "ABC".into()), (1, "X1".into())])
        );
        let mut frame = vec![1u8];
        frame.extend_from_slice(&pdu);
        assert_eq!(rtu_response_len(&frame), Some(frame.len() + 2));
    }

    #[test]
    fn frame_splitting() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let chunks = vec![(ms(0), vec![1, 2]), (ms(2), vec![3]), (ms(50), vec![4])];
        let f = split_frames(&chunks, Duration::from_millis(10));
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].1, vec![1, 2, 3]);
    }

    #[test]
    fn value_parsing() {
        assert_eq!(
            parse_words("100, -1, 0x1F, 65535").unwrap(),
            vec![100, 0xffff, 0x1f, 65535]
        );
        assert!(parse_words("70000").is_err());
        assert_eq!(
            parse_bits("1 off ON 0").unwrap(),
            vec![true, false, true, false]
        );
        assert!(parse_bits("2").is_err());
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("01 03 0x0A,ff").unwrap(), vec![1, 3, 10, 255]);
        assert!(parse_hex("123").is_err());
    }

    /// Minimal server: registers hold their own address, coils alternate,
    /// FC6 echoes, FC43 identifies, anything else -> Illegal Function.
    fn serve(pdu: &[u8]) -> Vec<u8> {
        let fc = pdu[0];
        let word = |i: usize| {
            pdu.get(i..i + 2)
                .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]))
        };
        let (a, q) = (word(1), word(3));
        match fc {
            3 | 4 => {
                let mut r = vec![fc, (q * 2) as u8];
                for i in 0..q {
                    r.extend_from_slice(&(a + i).to_be_bytes());
                }
                r
            }
            1 => {
                let bits: Vec<bool> = (0..q).map(|i| (a + i) % 2 == 0).collect();
                let b = pack_bits(&bits);
                let mut r = vec![1, b.len() as u8];
                r.extend(b);
                r
            }
            6 => pdu.to_vec(),
            43 => {
                let mut r = vec![43, 14, 1, 1, 0, 0, 1, 0, 4];
                r.extend_from_slice(b"ACME");
                r
            }
            _ => vec![fc | 0x80, 1],
        }
    }

    fn recv_reply(m: &Master) -> Event {
        loop {
            match m
                .events
                .recv_timeout(Duration::from_secs(5))
                .expect("event")
            {
                Event::Traffic(..) | Event::Connected(_) => continue,
                ev => return ev,
            }
        }
    }

    #[test]
    fn tcp_master_against_server() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut hdr = [0u8; 7];
            while s.read_exact(&mut hdr).is_ok() {
                let len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
                let mut pdu = vec![0u8; len - 1];
                s.read_exact(&mut pdu).unwrap();
                let tid = u16::from_be_bytes([hdr[0], hdr[1]]);
                s.write_all(&tcp_frame(tid, hdr[6], &serve(&pdu))).unwrap();
            }
        });
        let m = connect(
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port,
            },
            Duration::from_secs(2),
        );
        let run = |req| {
            m.send(Command::Run {
                unit: 1,
                req,
                every: None,
            })
        };
        run(Request::Read {
            table: Table::HoldingRegisters,
            addr: 100,
            qty: 3,
        });
        match recv_reply(&m) {
            Event::Reply { result, .. } => {
                assert_eq!(result.unwrap(), Response::Words(vec![100, 101, 102]))
            }
            _ => panic!("expected reply"),
        }
        run(Request::WriteRegister { addr: 7, value: 42 });
        match recv_reply(&m) {
            Event::Reply { result, .. } => assert_eq!(result.unwrap(), Response::Written(7, 42)),
            _ => panic!("expected reply"),
        }
        run(Request::WriteCoils {
            addr: 0,
            values: vec![true],
        });
        match recv_reply(&m) {
            Event::Reply { result, .. } => {
                assert_eq!(
                    result.unwrap(),
                    Response::Exception {
                        function: 15,
                        code: 1
                    }
                )
            }
            _ => panic!("expected reply"),
        }
        run(Request::ReadDeviceId { category: 1 });
        match recv_reply(&m) {
            Event::Reply { result, .. } => {
                assert_eq!(
                    result.unwrap(),
                    Response::DeviceId(vec![(0, "ACME".into())])
                )
            }
            _ => panic!("expected reply"),
        }
    }

    #[test]
    fn identify_probe() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut hdr = [0u8; 7];
            while s.read_exact(&mut hdr).is_ok() {
                let len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
                let mut pdu = vec![0u8; len - 1];
                s.read_exact(&mut pdu).unwrap();
                let tid = u16::from_be_bytes([hdr[0], hdr[1]]);
                s.write_all(&tcp_frame(tid, hdr[6], &serve(&pdu))).unwrap();
            }
        });
        assert_eq!(
            identify(addr, Duration::from_secs(2)).as_deref(),
            Some("Modbus: ACME")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rtu_master_over_pty() {
        use serialport::SerialPort;
        let (mut dev, host) = serialport::TTYPort::pair().expect("pty pair");
        let path = host.name().expect("pty name");
        std::thread::spawn(move || {
            dev.set_timeout(Duration::from_millis(20)).ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 64];
            loop {
                match dev.read(&mut tmp) {
                    Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        // Silence: a full request has arrived.
                        if buf.len() >= 4 {
                            let unit = buf[0];
                            if unit == 9
                                && crc16(&buf[..buf.len() - 2]).to_le_bytes()
                                    == buf[buf.len() - 2..]
                            {
                                let reply = rtu_frame(unit, &serve(&buf[1..buf.len() - 2]));
                                dev.write_all(&reply).unwrap();
                            }
                            buf.clear();
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        let cfg = SerialSettings {
            port: path,
            baud: 19200,
            ..Default::default()
        };
        let m = connect(Endpoint::Rtu(cfg), Duration::from_millis(500));
        m.send(Command::Run {
            unit: 9,
            req: Request::Read {
                table: Table::Coils,
                addr: 0,
                qty: 4,
            },
            every: None,
        });
        match recv_reply(&m) {
            Event::Reply { result, .. } => {
                assert_eq!(
                    result.unwrap(),
                    Response::Bits(vec![true, false, true, false])
                )
            }
            _ => panic!("expected reply"),
        }
        // Unit scan finds only unit 9.
        m.send(Command::ScanUnits { from: 8, to: 10 });
        let mut found = Vec::new();
        loop {
            match m
                .events
                .recv_timeout(Duration::from_secs(10))
                .expect("event")
            {
                Event::Found { who, detail } => found.push((who, detail)),
                Event::ScanDone => break,
                _ => {}
            }
        }
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "unit 9");
        assert!(found[0].1.contains("ACME"), "{found:?}");
    }
}
