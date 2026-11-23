//! Packet capture via libpcap / Npcap on a worker thread. Packets are
//! dissected on that thread and handed to the UI in batches.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crate::dissect::{self, Dissected};

#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub desc: String,
    pub addrs: Vec<String>,
    pub up: bool,
    pub loopback: bool,
}

impl Interface {
    pub fn label(&self) -> String {
        // Windows device names are GUID paths; the description is readable.
        let base = if cfg!(windows) && !self.desc.is_empty() {
            self.desc.clone()
        } else {
            self.name.clone()
        };
        match self.addrs.first() {
            Some(a) => format!("{base} ({a})"),
            None => base,
        }
    }
}

/// Whether the capture library could be loaded (Npcap on Windows).
pub fn available() -> Result<(), String> {
    #[cfg(windows)]
    {
        if !win::npcap_loaded() {
            return Err(
                "Npcap is not installed. Install it from https://npcap.com and restart the app."
                    .into(),
            );
        }
    }
    Ok(())
}

pub fn interfaces() -> Result<Vec<Interface>, String> {
    available()?;
    let mut list: Vec<Interface> = pcap::Device::list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|d| Interface {
            addrs: d
                .addresses
                .iter()
                .filter(|a| a.addr.is_ipv4())
                .map(|a| a.addr.to_string())
                .collect(),
            up: d.flags.is_up() && d.flags.is_running(),
            loopback: d.flags.is_loopback(),
            desc: d.desc.unwrap_or_default(),
            name: d.name,
        })
        // Skip pseudo devices that rarely work for a GUI capture.
        .filter(|i| {
            !matches!(
                i.name.as_str(),
                "bluetooth-monitor" | "nflog" | "nfqueue" | "dbus-system" | "dbus-session"
            ) && !i.name.starts_with("usbmon")
        })
        .collect();
    // Up interfaces with an IPv4 address first, then by name.
    list.sort_by_key(|i| (!i.up, i.addrs.is_empty(), i.loopback, i.name.clone()));
    Ok(list)
}

/// Explain the usual "you need privileges" failure for each platform.
pub fn permission_hint(err: &str) -> Option<String> {
    let e = err.to_lowercase();
    if !(e.contains("permission") || e.contains("operation not permitted") || e.contains("access"))
    {
        return None;
    }
    Some(if cfg!(target_os = "linux") {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "/usr/bin/network_analyser".into());
        format!(
            "Capture needs raw-socket rights. Run once: sudo setcap cap_net_raw,cap_net_admin=eip {exe}"
        )
    } else if cfg!(target_os = "macos") {
        "Capture needs access to /dev/bpf*. Install Wireshark's ChmodBPF helper or run with sudo."
            .into()
    } else {
        "Npcap may be restricted to administrators; reinstall it without \"Restrict Npcap driver's access to Administrators only\" or run as administrator.".into()
    })
}

#[derive(Clone, Debug)]
pub enum Source {
    Live { device: String, promisc: bool },
    File(PathBuf),
}

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub source: Source,
    /// BPF filter expression ("tcp port 502", "host 10.0.0.5"…), may be empty.
    pub filter: String,
    /// Live captures: also write a .pcap file here.
    pub save_to: Option<PathBuf>,
}

pub struct Packet {
    pub no: usize,
    /// Seconds since the Unix epoch.
    pub ts: f64,
    pub len: u32,
    pub data: Vec<u8>,
    pub d: Dissected,
}

pub enum CaptureEvent {
    Started {
        linktype: i32,
        desc: String,
    },
    Packets(Vec<Packet>),
    Stats {
        received: u32,
        dropped: u32,
        if_dropped: u32,
    },
    Stopped(Option<String>),
}

pub struct CaptureHandle {
    pub events: Receiver<CaptureEvent>,
    stop: Arc<AtomicBool>,
}

impl CaptureHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start(cfg: CaptureConfig) -> CaptureHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            let err = run(cfg, &tx, &flag).err();
            let _ = tx.send(CaptureEvent::Stopped(err));
        })
        .expect("spawn capture thread");
    CaptureHandle { events: rx, stop }
}

/// Batches packets so a busy link doesn't flood the UI channel.
struct Batcher<'a> {
    tx: &'a Sender<CaptureEvent>,
    buf: Vec<Packet>,
    last: Instant,
    no: usize,
    linktype: i32,
}

impl Batcher<'_> {
    fn push(&mut self, h: &pcap::PacketHeader, data: &[u8]) {
        self.no += 1;
        self.buf.push(Packet {
            no: self.no,
            ts: h.ts.tv_sec as f64 + h.ts.tv_usec as f64 / 1e6,
            len: h.len,
            data: data.to_vec(),
            d: dissect::dissect(self.linktype, data),
        });
        if self.buf.len() >= 512 {
            self.flush();
        }
    }
    fn tick(&mut self) {
        if self.last.elapsed() >= Duration::from_millis(100) {
            self.flush();
        }
    }
    fn flush(&mut self) {
        self.last = Instant::now();
        if !self.buf.is_empty() {
            let _ = self
                .tx
                .send(CaptureEvent::Packets(std::mem::take(&mut self.buf)));
        }
    }
}

fn run(cfg: CaptureConfig, tx: &Sender<CaptureEvent>, stop: &AtomicBool) -> Result<(), String> {
    available()?;
    match &cfg.source {
        Source::File(path) => {
            let mut cap =
                pcap::Capture::from_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
            if !cfg.filter.trim().is_empty() {
                cap.filter(cfg.filter.trim(), true)
                    .map_err(|e| format!("filter: {e}"))?;
            }
            let linktype = cap.get_datalink().0;
            let _ = tx.send(CaptureEvent::Started {
                linktype,
                desc: format!("{} ({})", path.display(), dissect::linktype_name(linktype)),
            });
            let mut b = Batcher {
                tx,
                buf: Vec::new(),
                last: Instant::now(),
                no: 0,
                linktype,
            };
            while !stop.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(p) => b.push(p.header, p.data),
                    Err(pcap::Error::NoMorePackets) => break,
                    Err(e) => {
                        b.flush();
                        return Err(e.to_string());
                    }
                }
            }
            b.flush();
            Ok(())
        }
        Source::Live { device, promisc } => {
            let mut cap = pcap::Capture::from_device(device.as_str())
                .map_err(|e| e.to_string())?
                .promisc(*promisc)
                .snaplen(65535)
                .timeout(100)
                .immediate_mode(true)
                .buffer_size(8 << 20)
                .open()
                .map_err(|e| format!("{device}: {e}"))?;
            if !cfg.filter.trim().is_empty() {
                cap.filter(cfg.filter.trim(), true)
                    .map_err(|e| format!("filter: {e}"))?;
            }
            let linktype = cap.get_datalink().0;
            let mut save = match &cfg.save_to {
                Some(p) => Some(
                    cap.savefile(p)
                        .map_err(|e| format!("save {}: {e}", p.display()))?,
                ),
                None => None,
            };
            let _ = tx.send(CaptureEvent::Started {
                linktype,
                desc: format!("{device} ({})", dissect::linktype_name(linktype)),
            });
            let mut b = Batcher {
                tx,
                buf: Vec::new(),
                last: Instant::now(),
                no: 0,
                linktype,
            };
            let mut last_stats = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(p) => {
                        if let Some(s) = save.as_mut() {
                            s.write(&p);
                        }
                        b.push(p.header, p.data);
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        b.flush();
                        return Err(e.to_string());
                    }
                }
                b.tick();
                if last_stats.elapsed() >= Duration::from_secs(1) {
                    last_stats = Instant::now();
                    if let Ok(s) = cap.stats() {
                        let _ = tx.send(CaptureEvent::Stats {
                            received: s.received,
                            dropped: s.dropped,
                            if_dropped: s.if_dropped,
                        });
                    }
                }
            }
            b.flush();
            if let Some(mut s) = save {
                s.flush().ok();
            }
            Ok(())
        }
    }
}

/// Write packets to a classic .pcap file (used to export a filtered view).
pub fn write_pcap(
    path: &std::path::Path,
    linktype: i32,
    packets: &[&Packet],
) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(24 + packets.iter().map(|p| p.data.len() + 16).sum::<usize>());
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&(linktype as u32).to_le_bytes());
    for p in packets {
        let secs = p.ts.trunc();
        out.extend_from_slice(&(secs as u32).to_le_bytes());
        out.extend_from_slice(
            &(((p.ts - secs) * 1e6).round() as u32)
                .min(999_999)
                .to_le_bytes(),
        );
        out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&p.len.to_le_bytes());
        out.extend_from_slice(&p.data);
    }
    std::fs::write(path, out)
}

/// Npcap installs wpcap.dll under System32\Npcap, which is not on the DLL
/// search path. wpcap.dll is delay-loaded (see build.rs), so add that
/// directory before the first pcap call and check that it actually loads;
/// without Npcap the rest of the app keeps working.
#[cfg(windows)]
pub mod win {
    use std::sync::OnceLock;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetDllDirectoryW(path: *const u16) -> i32;
        fn LoadLibraryW(name: *const u16) -> isize;
        fn GetSystemDirectoryW(buf: *mut u16, len: u32) -> u32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn npcap_loaded() -> bool {
        static OK: OnceLock<bool> = OnceLock::new();
        *OK.get_or_init(|| unsafe {
            let mut buf = [0u16; 260];
            let n = GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) as usize;
            if n > 0 && n < buf.len() {
                let dir = format!("{}\\Npcap", String::from_utf16_lossy(&buf[..n]));
                SetDllDirectoryW(wide(&dir).as_ptr());
            }
            LoadLibraryW(wide("wpcap.dll").as_ptr()) != 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_roundtrip() {
        if let Err(e) = available() {
            eprintln!("skipping: {e}");
            return;
        }
        // Ethernet + IPv4 + UDP DNS query, written and read back via libpcap.
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        dns.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        let udp_len = 8 + dns.len();
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        f.extend_from_slice(&[
            0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 0xd4, 0x31, 0, 53,
        ]);
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&dns);
        let pkts: Vec<Packet> = (0..3)
            .map(|i| Packet {
                no: i + 1,
                ts: 1_700_000_000.25 + i as f64,
                len: f.len() as u32,
                data: f.clone(),
                d: Dissected::default(),
            })
            .collect();
        let path = std::env::temp_dir().join(format!("na-test-{}.pcap", std::process::id()));
        write_pcap(&path, 1, &pkts.iter().collect::<Vec<_>>()).unwrap();
        let h = start(CaptureConfig {
            source: Source::File(path.clone()),
            filter: "udp port 53".into(),
            save_to: None,
        });
        let mut got = Vec::new();
        loop {
            match h
                .events
                .recv_timeout(Duration::from_secs(5))
                .expect("event")
            {
                CaptureEvent::Packets(p) => got.extend(p),
                CaptureEvent::Stopped(err) => {
                    assert!(err.is_none(), "{err:?}");
                    break;
                }
                _ => {}
            }
        }
        std::fs::remove_file(&path).ok();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].d.proto, "DNS");
        assert_eq!(got[0].d.info, "Query 0x1234 A example.com");
        assert!((got[1].ts - 1_700_000_001.25).abs() < 1e-6);
    }
}
