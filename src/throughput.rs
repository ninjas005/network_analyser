//! Throughput testing: an in-app TCP server (with UDP echo for the latency
//! tools), a multi-stream upload/download client, and an HTTP(S) download
//! test.
//!
//! Protocol (TCP): the client sends `NATP1 up|down <seconds>\n`.
//! `up`: the client streams data until it closes its write side; the server
//! answers `OK <bytes> <micros>\n`. `down`: the server streams for
//! `<seconds>` and closes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 5299;
const BUF: usize = 128 * 1024;

// ---------------------------------------------------------------- server

pub enum ServerEvent {
    Listening(u16),
    Session {
        peer: SocketAddr,
        mode: String,
        bytes: u64,
        secs: f64,
    },
    Error(String),
    Stopped,
}

pub struct ServerHandle {
    pub events: Receiver<ServerEvent>,
    stop: Arc<AtomicBool>,
}

impl ServerHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn serve(port: u16) -> ServerHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::Builder::new()
        .name("tput-server".into())
        .spawn(move || {
            if let Err(e) = server_loop(port, &tx, &flag) {
                let _ = tx.send(ServerEvent::Error(e));
            }
            let _ = tx.send(ServerEvent::Stopped);
        })
        .expect("spawn server");
    ServerHandle { events: rx, stop }
}

fn server_loop(port: u16, tx: &Sender<ServerEvent>, stop: &Arc<AtomicBool>) -> Result<(), String> {
    let l = TcpListener::bind(("0.0.0.0", port)).map_err(|e| format!("TCP port {port}: {e}"))?;
    l.set_nonblocking(true).map_err(|e| e.to_string())?;
    let udp = UdpSocket::bind(("0.0.0.0", port)).map_err(|e| format!("UDP port {port}: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let _ = tx.send(ServerEvent::Listening(port));
    // UDP echo for the latency / jitter / loss tools.
    let ustop = stop.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !ustop.load(Ordering::Relaxed) {
            if let Ok((n, from)) = udp.recv_from(&mut buf)
                && n >= 6
                && &buf[..6] == b"NAPING"
            {
                let _ = udp.send_to(&buf[..n], from);
            }
        }
    });
    while !stop.load(Ordering::Relaxed) {
        match l.accept() {
            Ok((s, peer)) => {
                let (tx, stop) = (tx.clone(), stop.clone());
                std::thread::spawn(move || {
                    if let Err(e) = session(s, peer, &tx, &stop) {
                        let _ = tx.send(ServerEvent::Error(format!("{peer}: {e}")));
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

fn session(
    s: TcpStream,
    peer: SocketAddr,
    tx: &Sender<ServerEvent>,
    stop: &AtomicBool,
) -> Result<(), String> {
    s.set_nonblocking(false).ok();
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.set_nodelay(true).ok();
    let mut r = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    r.read_line(&mut line).map_err(|e| e.to_string())?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.first() != Some(&"NATP1") || parts.len() < 3 {
        return Err("not a Network Analyser client".into());
    }
    let secs: u64 = parts[2].parse().unwrap_or(10).clamp(1, 600);
    let t = Instant::now();
    let mut w = s;
    let bytes = match parts[1] {
        "up" => {
            let mut buf = vec![0u8; BUF];
            let mut total = r.buffer().len() as u64;
            r.consume(r.buffer().len());
            let mut inner = r.into_inner();
            loop {
                match inner.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total += n as u64,
                    Err(e) => return Err(e.to_string()),
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
            let _ = w.write_all(format!("OK {total} {}\n", t.elapsed().as_micros()).as_bytes());
            total
        }
        "down" => {
            let buf = vec![0x5au8; BUF];
            let mut total = 0u64;
            let end = t + Duration::from_secs(secs);
            while Instant::now() < end && !stop.load(Ordering::Relaxed) {
                match w.write(&buf) {
                    Ok(n) => total += n as u64,
                    Err(_) => break,
                }
            }
            let _ = w.shutdown(Shutdown::Write);
            total
        }
        m => return Err(format!("unknown mode {m}")),
    };
    let _ = tx.send(ServerEvent::Session {
        peer,
        mode: parts[1].into(),
        bytes,
        secs: t.elapsed().as_secs_f64(),
    });
    Ok(())
}

// ---------------------------------------------------------------- client

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    Upload,
    Download,
}

pub enum ClientEvent {
    Connected(String),
    /// Bytes moved during one second of the test.
    Interval {
        second: u32,
        bytes: u64,
    },
    Done {
        bytes: u64,
        secs: f64,
        server_bytes: Option<u64>,
    },
    Error(String),
}

pub struct ClientHandle {
    pub events: Receiver<ClientEvent>,
    stop: Arc<AtomicBool>,
}

impl ClientHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Report bytes per second from a shared counter until `done`.
fn reporter(counter: Arc<AtomicU64>, done: Arc<AtomicBool>, tx: Sender<ClientEvent>) {
    std::thread::spawn(move || {
        let start = Instant::now();
        let mut last = 0;
        let mut second = 1;
        loop {
            let due = start + Duration::from_secs(second as u64);
            while Instant::now() < due {
                if done.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let now = counter.load(Ordering::Relaxed);
            let _ = tx.send(ClientEvent::Interval {
                second,
                bytes: now - last,
            });
            last = now;
            second += 1;
        }
    });
}

pub fn run_client(host: String, port: u16, mode: Mode, secs: u32, streams: u32) -> ClientHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        let addr = match std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
            .map(|mut a| a.next())
        {
            Ok(Some(a)) => a,
            _ => {
                let _ = tx.send(ClientEvent::Error(format!("cannot resolve {host}")));
                return;
            }
        };
        let mut socks = Vec::new();
        for _ in 0..streams.clamp(1, 16) {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                Ok(s) => socks.push(s),
                Err(e) => {
                    let _ = tx.send(ClientEvent::Error(format!(
                        "{addr}: {e} — is a Throughput Tester server running there?"
                    )));
                    return;
                }
            }
        }
        let _ = tx.send(ClientEvent::Connected(format!(
            "{addr}, {} stream(s)",
            socks.len()
        )));
        let counter = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));
        reporter(counter.clone(), done.clone(), tx.clone());
        let t = Instant::now();
        let end = t + Duration::from_secs(secs as u64);
        let workers: Vec<_> = socks
            .into_iter()
            .map(|mut s| {
                let (counter, flag) = (counter.clone(), flag.clone());
                std::thread::spawn(move || -> Option<u64> {
                    s.set_nodelay(true).ok();
                    let hdr = format!(
                        "NATP1 {} {secs}\n",
                        if mode == Mode::Upload { "up" } else { "down" }
                    );
                    s.write_all(hdr.as_bytes()).ok()?;
                    match mode {
                        Mode::Upload => {
                            let buf = vec![0xa5u8; BUF];
                            while Instant::now() < end && !flag.load(Ordering::Relaxed) {
                                let n = s.write(&buf).ok()?;
                                counter.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            s.shutdown(Shutdown::Write).ok()?;
                            s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                            let mut line = String::new();
                            BufReader::new(s).read_line(&mut line).ok()?;
                            line.split_whitespace().nth(1)?.parse().ok()
                        }
                        Mode::Download => {
                            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                            let mut buf = vec![0u8; BUF];
                            while !flag.load(Ordering::Relaxed) {
                                match s.read(&mut buf) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        counter.fetch_add(n as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                            None
                        }
                    }
                })
            })
            .collect();
        let server: Vec<Option<u64>> = workers
            .into_iter()
            .map(|w| w.join().ok().flatten())
            .collect();
        done.store(true, Ordering::Relaxed);
        let server_bytes = (mode == Mode::Upload && server.iter().all(Option::is_some))
            .then(|| server.iter().flatten().sum());
        let _ = tx.send(ClientEvent::Done {
            bytes: counter.load(Ordering::Relaxed),
            secs: t.elapsed().as_secs_f64(),
            server_bytes,
        });
    });
    ClientHandle { events: rx, stop }
}

/// Download `url` (http or https, no redirects) for at most `secs`.
pub fn http_download(url: String, secs: u32) -> ClientHandle {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        if let Err(e) = http_inner(&url, secs, &tx, &flag) {
            let _ = tx.send(ClientEvent::Error(e));
        }
    });
    ClientHandle { events: rx, stop }
}

fn http_inner(
    url: &str,
    secs: u32,
    tx: &Sender<ClientEvent>,
    stop: &AtomicBool,
) -> Result<(), String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("URL must start with http:// or https://".into());
    };
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(443))
        }
        _ => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: network-analyser/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let mut stream: Box<dyn Read> = if tls {
        let mut s = crate::tls::connect_tls(&host, port, Duration::from_secs(10))?;
        s.write_all(req.as_bytes())
            .map_err(|e| format!("TLS: {e}"))?;
        Box::new(s)
    } else {
        let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
            .map_err(|e| format!("{host}: {e}"))?
            .next()
            .ok_or("no address")?;
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        Box::new(s)
    };
    // Headers.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).map_err(|e| e.to_string())? == 0 || head.len() > 32 * 1024 {
            return Err("connection closed before the response".into());
        }
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    if !status.contains(" 200") {
        return Err(format!("server answered: {status}"));
    }
    let _ = tx.send(ClientEvent::Connected(format!("{host}:{port} — {status}")));
    let counter = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    reporter(counter.clone(), done.clone(), tx.clone());
    let t = Instant::now();
    let end = t + Duration::from_secs(secs as u64);
    let mut buf = vec![0u8; BUF];
    while Instant::now() < end && !stop.load(Ordering::Relaxed) {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => {
                done.store(true, Ordering::Relaxed);
                return Err(e.to_string());
            }
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = tx.send(ClientEvent::Done {
        bytes: counter.load(Ordering::Relaxed),
        secs: t.elapsed().as_secs_f64(),
        server_bytes: None,
    });
    Ok(())
}

pub fn mbps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        bytes as f64 * 8.0 / secs / 1e6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn loopback_upload_download_and_echo() {
        let port = free_port();
        let server = serve(port);
        match server.events.recv_timeout(Duration::from_secs(3)) {
            Ok(ServerEvent::Listening(p)) => assert_eq!(p, port),
            _ => panic!("server did not start"),
        }
        for mode in [Mode::Upload, Mode::Download] {
            let c = run_client("127.0.0.1".into(), port, mode, 1, 2);
            let mut done = None;
            while let Ok(ev) = c.events.recv_timeout(Duration::from_secs(10)) {
                match ev {
                    ClientEvent::Done {
                        bytes,
                        server_bytes,
                        ..
                    } => {
                        done = Some((bytes, server_bytes));
                        break;
                    }
                    ClientEvent::Error(e) => panic!("{e}"),
                    _ => {}
                }
            }
            let (bytes, server_bytes) = done.expect("client finished");
            assert!(bytes > 1_000_000, "{mode:?}: {bytes}");
            if mode == Mode::Upload {
                assert_eq!(server_bytes, Some(bytes));
            }
        }
        // UDP echo.
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        u.send_to(b"NAPING\0\0\0\x07", ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 32];
        let (n, _) = u.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"NAPING\0\0\0\x07");
        assert!((mbps(1_000_000, 1.0) - 8.0).abs() < 1e-9);
    }
}
