//! Serial ports: enumeration, line settings, and a monitor thread that
//! timestamps received chunks so the UI can split them into frames
//! (e.g. Modbus RTU) by inter-byte silence.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use serialport::{DataBits, FlowControl, Parity, SerialPort, SerialPortType, StopBits};

pub const BAUD_RATES: &[u32] = &[
    1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600,
];

#[derive(Clone, Debug, PartialEq)]
pub struct SerialSettings {
    pub port: String,
    pub baud: u32,
    pub data_bits: u8,
    /// 'N', 'E' or 'O'
    pub parity: char,
    pub stop_bits: u8,
    pub rtscts: bool,
}

impl Default for SerialSettings {
    fn default() -> Self {
        Self {
            port: String::new(),
            baud: 9600,
            data_bits: 8,
            parity: 'N',
            stop_bits: 1,
            rtscts: false,
        }
    }
}

impl SerialSettings {
    /// "9600 8N1"
    pub fn summary(&self) -> String {
        format!(
            "{} {}{}{}{}",
            self.baud,
            self.data_bits,
            self.parity,
            self.stop_bits,
            if self.rtscts { " RTS/CTS" } else { "" }
        )
    }

    pub fn open(&self, read_timeout: Duration) -> serialport::Result<Box<dyn SerialPort>> {
        serialport::new(&self.port, self.baud)
            .data_bits(match self.data_bits {
                5 => DataBits::Five,
                6 => DataBits::Six,
                7 => DataBits::Seven,
                _ => DataBits::Eight,
            })
            .parity(match self.parity {
                'E' => Parity::Even,
                'O' => Parity::Odd,
                _ => Parity::None,
            })
            .stop_bits(if self.stop_bits == 2 {
                StopBits::Two
            } else {
                StopBits::One
            })
            .flow_control(if self.rtscts {
                FlowControl::Hardware
            } else {
                FlowControl::None
            })
            .timeout(read_timeout)
            .open()
    }
}

#[derive(Clone, Debug)]
pub struct PortEntry {
    pub name: String,
    pub kind: String,
    pub detail: String,
}

pub fn list_ports() -> Result<Vec<PortEntry>, String> {
    let mut ports = serialport::available_ports().map_err(|e| e.to_string())?;
    ports.sort_by(|a, b| a.port_name.cmp(&b.port_name));
    Ok(ports
        .into_iter()
        // macOS lists each device twice; the /dev/tty.* twin blocks on DCD.
        .filter(|p| !p.port_name.starts_with("/dev/tty.") || cfg!(not(target_os = "macos")))
        .filter(|p| !is_placeholder_uart(&p.port_name))
        .map(|p| {
            let (kind, detail) = match p.port_type {
                SerialPortType::UsbPort(u) => (
                    "USB".to_string(),
                    [
                        Some(format!("{:04x}:{:04x}", u.vid, u.pid)),
                        u.manufacturer,
                        u.product,
                        u.serial_number.map(|s| format!("S/N {s}")),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" · "),
                ),
                SerialPortType::PciPort => ("PCI".into(), String::new()),
                SerialPortType::BluetoothPort => ("Bluetooth".into(), String::new()),
                SerialPortType::Unknown => ("Serial".into(), String::new()),
            };
            PortEntry {
                name: p.port_name,
                kind,
                detail,
            }
        })
        .collect())
}

/// Linux registers /dev/ttyS0-31 whether or not a UART exists; the sysfs
/// `type` attribute is 0 (PORT_UNKNOWN) for the empty slots.
fn is_placeholder_uart(name: &str) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let Some(base) = name.strip_prefix("/dev/").filter(|b| b.starts_with("ttyS")) else {
        return false;
    };
    std::fs::read_to_string(format!("/sys/class/tty/{base}/type")).is_ok_and(|t| t.trim() == "0")
}

/// Common hint for the usual "permission denied" on Linux.
pub fn permission_hint(err: &str) -> Option<&'static str> {
    let e = err.to_lowercase();
    (e.contains("permission") || e.contains("access is denied")).then_some(
        if cfg!(target_os = "linux") {
            "Add yourself to the 'dialout' group (sudo usermod -aG dialout $USER) and log in again."
        } else {
            "The port is in use by another program or access is denied."
        },
    )
}

pub enum SerialEvent {
    Opened(String),
    Data(Instant, Vec<u8>),
    Sent(Instant, Vec<u8>),
    Closed(Option<String>),
}

pub struct SerialHandle {
    pub events: Receiver<SerialEvent>,
    out: Sender<Vec<u8>>,
    stop: Arc<AtomicBool>,
}

impl SerialHandle {
    pub fn send(&self, bytes: Vec<u8>) {
        let _ = self.out.send(bytes);
    }
    pub fn close(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for SerialHandle {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn open_monitor(cfg: SerialSettings) -> SerialHandle {
    let (tx, rx) = channel();
    let (otx, orx) = channel::<Vec<u8>>();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::Builder::new()
        .name("serial".into())
        .spawn(move || monitor(cfg, tx, orx, flag))
        .expect("spawn serial thread");
    SerialHandle {
        events: rx,
        out: otx,
        stop,
    }
}

fn monitor(
    cfg: SerialSettings,
    tx: Sender<SerialEvent>,
    out: Receiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
) {
    // Short read timeout: keeps the loop responsive and the timestamps tight.
    let mut port = match cfg.open(Duration::from_millis(5)) {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(SerialEvent::Closed(Some(format!("{}: {e}", cfg.port))));
            return;
        }
    };
    let _ = tx.send(SerialEvent::Opened(format!(
        "{} {}",
        cfg.port,
        cfg.summary()
    )));
    let mut buf = [0u8; 4096];
    let mut error = None;
    while !stop.load(Ordering::Relaxed) {
        while let Ok(bytes) = out.try_recv() {
            if let Err(e) = port.write_all(&bytes) {
                error = Some(format!("write: {e}"));
                break;
            }
            port.flush().ok();
            let _ = tx.send(SerialEvent::Sent(Instant::now(), bytes));
        }
        if error.is_some() {
            break;
        }
        match port.read(&mut buf) {
            Ok(n) if n > 0 => {
                if tx
                    .send(SerialEvent::Data(Instant::now(), buf[..n].to_vec()))
                    .is_err()
                {
                    return;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                // Unplugged USB adapters surface as EIO / broken pipe.
                error = Some(format!("read: {e}"));
                break;
            }
        }
    }
    let _ = tx.send(SerialEvent::Closed(error));
}

// ---------------------------------------------------------------- baud detection

#[derive(Clone, Debug)]
pub struct BaudScore {
    pub baud: u32,
    pub bytes: usize,
    /// Share of printable ASCII / CR / LF / TAB.
    pub printable: f32,
    /// Frames (split by RTU silence) with a valid Modbus CRC.
    pub modbus_frames: usize,
}

impl BaudScore {
    pub fn verdict(&self) -> &'static str {
        if self.bytes == 0 {
            "silent"
        } else if self.modbus_frames > 0 {
            "valid Modbus RTU frames"
        } else if self.printable > 0.9 {
            "readable text"
        } else if self.printable > 0.6 {
            "mostly text"
        } else {
            "binary / garbled"
        }
    }
    fn rank(&self) -> (usize, u32) {
        (
            self.modbus_frames,
            (self.printable * 1000.0) as u32 * (self.bytes > 8) as u32,
        )
    }
}

pub enum BaudEvent {
    Trying(u32),
    Score(BaudScore),
    /// Best rate (if anything was received) or an error.
    Done(Result<Option<u32>, String>),
}

/// Listen passively at each baud rate for `dwell` and score what arrives.
/// Only works while the device is transmitting (e.g. a Modbus master polling
/// or a device printing a console).
pub fn baud_scan(
    cfg: SerialSettings,
    rates: Vec<u32>,
    dwell: Duration,
) -> (Receiver<BaudEvent>, Arc<AtomicBool>) {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::Builder::new()
        .name("baud-scan".into())
        .spawn(move || {
            let mut best: Option<BaudScore> = None;
            for baud in rates {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                let _ = tx.send(BaudEvent::Trying(baud));
                let c = SerialSettings {
                    baud,
                    ..cfg.clone()
                };
                let mut port = match c.open(Duration::from_millis(5)) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(BaudEvent::Done(Err(format!("{}: {e}", c.port))));
                        return;
                    }
                };
                let mut chunks = Vec::new();
                let mut buf = [0u8; 1024];
                let end = Instant::now() + dwell;
                while Instant::now() < end && !flag.load(Ordering::Relaxed) {
                    if let Ok(n) = port.read(&mut buf)
                        && n > 0
                    {
                        chunks.push((Instant::now(), buf[..n].to_vec()));
                    }
                }
                drop(port);
                let all: Vec<u8> = chunks.iter().flat_map(|c| c.1.iter().copied()).collect();
                let printable = if all.is_empty() {
                    0.0
                } else {
                    all.iter()
                        .filter(|&&b| {
                            (0x20..0x7f).contains(&b) || matches!(b, b'\r' | b'\n' | b'\t')
                        })
                        .count() as f32
                        / all.len() as f32
                };
                let modbus_frames =
                    crate::modbus::split_frames(&chunks, crate::modbus::rtu_gap(baud))
                        .iter()
                        .filter(|(_, f)| crate::modbus::decode_rtu(f).is_some_and(|d| d.crc_ok))
                        .count();
                let score = BaudScore {
                    baud,
                    bytes: all.len(),
                    printable,
                    modbus_frames,
                };
                if score.bytes > 0 && best.as_ref().is_none_or(|b| score.rank() > b.rank()) {
                    best = Some(score.clone());
                }
                let _ = tx.send(BaudEvent::Score(score));
            }
            let _ = tx.send(BaudEvent::Done(Ok(best.map(|b| b.baud))));
        })
        .expect("spawn baud-scan thread");
    (rx, stop)
}

/// Decode C-style escapes in a send line: \r \n \t \\ \xNN.
pub fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'r' => out.push(b'\r'),
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'0' => out.push(0),
                b'\\' => out.push(b'\\'),
                b'x' => {
                    if let Some(v) = s
                        .get(i + 2..i + 4)
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                    {
                        out.push(v);
                        i += 4;
                        continue;
                    }
                    out.push(b'\\');
                    i += 1;
                    continue;
                }
                _ => {
                    out.push(b'\\');
                    i += 1;
                    continue;
                }
            }
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Printable rendering of received bytes (non-printables as ·, CR/LF shown).
pub fn ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            b'\r' => '␍',
            b'\n' => '␊',
            0x20..=0x7e => b as char,
            _ => '·',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(unescape(r"AT\r\n"), b"AT\r\n");
        assert_eq!(unescape(r"\x01\x7F!"), vec![1, 0x7f, b'!']);
        assert_eq!(unescape(r"a\q"), b"a\\q");
        assert_eq!(unescape(r"\x"), b"\\x");
    }

    #[test]
    fn summary() {
        let s = SerialSettings {
            port: "/dev/ttyUSB0".into(),
            parity: 'E',
            ..Default::default()
        };
        assert_eq!(s.summary(), "9600 8E1");
    }

    #[cfg(unix)]
    #[test]
    fn monitor_over_pty() {
        let (mut dev, host) = serialport::TTYPort::pair().expect("pty pair");
        let h = open_monitor(SerialSettings {
            port: host.name().unwrap(),
            ..Default::default()
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        let mut opened = false;
        while Instant::now() < deadline && got != b"hello" {
            match h.events.recv_timeout(Duration::from_millis(200)) {
                Ok(SerialEvent::Opened(_)) => {
                    opened = true;
                    dev.write_all(b"hello").unwrap();
                    h.send(b"ping".to_vec());
                }
                Ok(SerialEvent::Data(_, b)) => got.extend(b),
                Ok(SerialEvent::Closed(e)) => panic!("closed: {e:?}"),
                _ => {}
            }
        }
        assert!(opened);
        assert_eq!(got, b"hello");
        let mut buf = [0u8; 4];
        dev.set_timeout(Duration::from_secs(2)).ok();
        dev.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }
}
