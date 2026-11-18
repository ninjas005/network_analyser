//! Small, dependency-free protocol probes used to enrich a live host.
//! Everything here is unprivileged (plain TCP/UDP sockets).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

// ---------------------------------------------------------------- ping

pub struct PingReply {
    pub rtt_ms: f32,
    pub ttl: Option<u8>,
}

/// ICMP echo via the system `ping` binary (it carries the raw-socket
/// capability, so this app needs no root privileges).
pub async fn ping(ip: Ipv4Addr, wait: Duration) -> Option<PingReply> {
    let secs = wait.as_secs().max(1).to_string();
    let start = Instant::now();
    let out = tokio::process::Command::new("ping")
        .args(["-n", "-c", "1", "-W", &secs, &ip.to_string()])
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("ttl="))?;
    let field = |key: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .map(|v| v.to_string())
    };
    let ttl = field("ttl=").and_then(|v| v.parse().ok());
    let rtt_ms = field("time=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(start.elapsed().as_secs_f32() * 1000.0);
    Some(PingReply { rtt_ms, ttl })
}

// ---------------------------------------------------------------- tcp

pub enum TcpState {
    Open,
    /// RST received: port closed but the host is definitely up.
    Closed,
    Filtered,
}

pub async fn tcp_probe(ip: Ipv4Addr, port: u16, wait: Duration) -> TcpState {
    match timeout(wait, TcpStream::connect(SocketAddr::from((ip, port)))).await {
        Ok(Ok(_)) => TcpState::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => TcpState::Closed,
        _ => TcpState::Filtered,
    }
}

#[derive(Default, Clone, Debug)]
pub struct Banner {
    pub text: Option<String>,
    pub http_server: Option<String>,
    pub http_title: Option<String>,
    pub http_status: Option<String>,
}

/// Read whatever the service says first; if it is silent and the port looks
/// like HTTP, send a minimal GET and extract status / Server / <title>.
pub async fn grab_banner(ip: Ipv4Addr, port: u16, http_hint: bool) -> Banner {
    let mut out = Banner::default();
    let addr = SocketAddr::from((ip, port));
    let Ok(Ok(mut s)) = timeout(Duration::from_millis(1200), TcpStream::connect(addr)).await else {
        return out;
    };
    let mut buf = vec![0u8; 4096];
    if !http_hint
        && let Ok(Ok(n)) = timeout(Duration::from_millis(1200), s.read(&mut buf)).await
            && n > 0 {
                out.text = Some(clean_line(&buf[..n]));
                return out;
            }
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (network-analyser)\r\nAccept: */*\r\n\r\n"
    );
    if s.write_all(req.as_bytes()).await.is_err() {
        return out;
    }
    let mut data = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(2000);
    while data.len() < 16 * 1024 {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => data.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    if data.is_empty() {
        return out;
    }
    let text = String::from_utf8_lossy(&data);
    if text.starts_with("HTTP/") {
        out.http_status = text.lines().next().map(|l| l.trim().to_string());
        out.http_server = header(&text, "server");
        out.http_title = html_tag(&text, "title");
        out.text = out.http_status.clone();
    } else {
        out.text = Some(clean_line(&data));
    }
    out
}

fn clean_line(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let s: String = s
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(160)
        .collect();
    s.trim().to_string()
}

fn header(resp: &str, name: &str) -> Option<String> {
    resp.split("\r\n\r\n").next()?.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// Case-insensitive `<tag>...</tag>` extraction (handles `<tag attr>` and XML).
pub fn html_tag(text: &str, tag: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let open = format!("<{}", tag.to_ascii_lowercase());
    let mut from = 0;
    while let Some(pos) = lower[from..].find(&open) {
        let start = from + pos;
        let after = start + open.len();
        // Make sure this is <title> / <title ...> and not <titlebar>.
        if matches!(lower.as_bytes().get(after), Some(b'>') | Some(b' ')) {
            let gt = start + lower[start..].find('>')? + 1;
            let end = gt + lower[gt..].find(&format!("</{}", tag.to_ascii_lowercase()))?;
            let v = decode_entities(text[gt..end].trim());
            let v: String = v.split_whitespace().collect::<Vec<_>>().join(" ");
            return (!v.is_empty()).then(|| v.chars().take(120).collect());
        }
        from = after;
    }
    None
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

// ---------------------------------------------------------------- dns helpers

fn read_dns_name(pkt: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end_pos = None;
    for _ in 0..64 {
        let len = *pkt.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *pkt.get(pos + 1)? as usize;
            end_pos.get_or_insert(pos + 2);
            pos = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(pkt.get(pos + 1..pos + 1 + len)?).to_string());
        pos += 1 + len;
    }
    Some((labels.join("."), end_pos.unwrap_or(pos)))
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

async fn udp_exchange(ip: Ipv4Addr, port: u16, payload: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(payload, (ip, port)).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let (n, from) = timeout(left, sock.recv_from(&mut buf)).await.ok()?.ok()?;
        if from.ip() == std::net::IpAddr::V4(ip) {
            buf.truncate(n);
            return Some(buf);
        }
    }
}

// ---------------------------------------------------------------- mDNS

/// Unicast reverse lookup against the host's own mDNS responder
/// (Apple, Android, Linux/avahi, printers, smart-home gear answer this).
pub async fn mdns_name(ip: Ipv4Addr) -> Option<String> {
    let o = ip.octets();
    let qname = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    let mut pkt = vec![0x4e, 0x41, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    encode_dns_name(&qname, &mut pkt);
    pkt.extend_from_slice(&[0, 12, 0, 1]); // PTR, IN
    let resp = udp_exchange(ip, 5353, &pkt, Duration::from_millis(900)).await?;
    parse_first_ptr(&resp)
}

fn parse_first_ptr(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_dns_name(pkt, pos)?.1 + 4;
    }
    for _ in 0..an {
        let (_, p) = read_dns_name(pkt, pos)?;
        let rtype = u16::from_be_bytes([*pkt.get(p)?, *pkt.get(p + 1)?]);
        let rdlen = u16::from_be_bytes([*pkt.get(p + 8)?, *pkt.get(p + 9)?]) as usize;
        let rdata = p + 10;
        if rtype == 12 {
            let (name, _) = read_dns_name(pkt, rdata)?;
            return (!name.is_empty()).then_some(name);
        }
        pos = rdata + rdlen;
    }
    None
}

// ---------------------------------------------------------------- NetBIOS

#[derive(Default, Clone, Debug)]
pub struct NetbiosInfo {
    pub name: Option<String>,
    pub group: Option<String>,
    pub user: Option<String>,
    pub mac: Option<String>,
}

/// NBSTAT node-status query (UDP/137) - Windows, Samba, NAS boxes.
pub async fn netbios(ip: Ipv4Addr) -> Option<NetbiosInfo> {
    let mut pkt = vec![0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, b'C', b'K'];
    pkt.extend(std::iter::repeat_n(b'A', 30));
    pkt.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    let r = udp_exchange(ip, 137, &pkt, Duration::from_millis(900)).await?;
    if r.len() < 57 {
        return None;
    }
    let (_, p) = read_dns_name(&r, 12)?;
    let rdata = p + 10;
    let count = *r.get(rdata)? as usize;
    let mut info = NetbiosInfo::default();
    for i in 0..count {
        let off = rdata + 1 + i * 18;
        let entry = r.get(off..off + 18)?;
        let name = String::from_utf8_lossy(&entry[..15]).trim().to_string();
        let suffix = entry[15];
        let is_group = entry[16] & 0x80 != 0;
        match (suffix, is_group) {
            (0x00, false) => {
                info.name.get_or_insert(name);
            }
            (0x00, true) => {
                info.group.get_or_insert(name);
            }
            (0x03, false) if Some(&name) != info.name.as_ref() => {
                info.user.get_or_insert(name);
            }
            _ => {}
        }
    }
    let mac_off = rdata + 1 + count * 18;
    if let Some(m) = r.get(mac_off..mac_off + 6)
        && m.iter().any(|b| *b != 0) {
            info.mac = Some(m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"));
        }
    (info.name.is_some() || info.group.is_some()).then_some(info)
}

// ---------------------------------------------------------------- SSDP / UPnP

#[derive(Default, Clone, Debug)]
pub struct UpnpInfo {
    pub server: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub device_type: Option<String>,
}

/// Unicast SSDP M-SEARCH, then fetch the device description XML it points at.
pub async fn upnp(ip: Ipv4Addr) -> Option<UpnpInfo> {
    let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    let r = udp_exchange(ip, 1900, msg.as_bytes(), Duration::from_millis(1500)).await?;
    let text = String::from_utf8_lossy(&r).to_string();
    let mut info = UpnpInfo {
        server: header(&format!("{text}\r\n\r\n"), "server"),
        ..Default::default()
    };
    if let Some(loc) = header(&format!("{text}\r\n\r\n"), "location")
        && let Some(xml) = http_get_url(&loc, ip).await {
            info.friendly_name = html_tag(&xml, "friendlyName");
            info.manufacturer = html_tag(&xml, "manufacturer");
            info.model = html_tag(&xml, "modelName").map(|m| match html_tag(&xml, "modelNumber") {
                Some(n) if !m.contains(&n) => format!("{m} {n}"),
                _ => m,
            });
            info.device_type = html_tag(&xml, "deviceType")
                .map(|t| t.split(':').rev().nth(1).unwrap_or(&t).to_string());
        }
    Some(info)
}

/// Plain-HTTP GET of a URL that must point at `expect_ip` (we never follow a
/// LOCATION header to some other machine).
async fn http_get_url(url: &str, expect_ip: Ipv4Addr) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let (host, port) = hostport.split_once(':').unwrap_or((hostport, "80"));
    let ip: Ipv4Addr = host.parse().ok()?;
    if ip != expect_ip {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    let mut s = timeout(Duration::from_millis(1500), TcpStream::connect((ip, port))).await.ok()?.ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut data = Vec::new();
    let _ = timeout(Duration::from_millis(2500), s.take(64 * 1024).read_to_end(&mut data)).await;
    (!data.is_empty()).then(|| String::from_utf8_lossy(&data).to_string())
}

// ---------------------------------------------------------------- reverse DNS

pub async fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let task = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip.into()).ok());
    let name = timeout(Duration::from_secs(3), task).await.ok()?.ok()??;
    (name != ip.to_string()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_extraction() {
        let html = "HTTP/1.1 200 OK\r\nServer: lighttpd\r\n\r\n<html><head><TITLE> My &amp; Router </TITLE>";
        assert_eq!(html_tag(html, "title").as_deref(), Some("My & Router"));
        assert_eq!(header(html, "server").as_deref(), Some("lighttpd"));
        assert_eq!(html_tag("<titlebar>x</titlebar>", "title"), None);
    }

    #[test]
    fn dns_ptr_parse() {
        // Response with compressed PTR answer pointing back into the question.
        let mut p = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        encode_dns_name("1.0.168.192.in-addr.arpa", &mut p);
        p.extend_from_slice(&[0, 12, 0, 1]);
        p.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 10]);
        let mut rd = Vec::new();
        encode_dns_name("printer.local", &mut rd);
        p.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        p.extend_from_slice(&rd);
        assert_eq!(parse_first_ptr(&p).as_deref(), Some("printer.local"));
    }
}
