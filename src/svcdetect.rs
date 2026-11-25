//! Service and version detection: protocol-aware probes for open ports.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Detection {
    pub service: String,
    pub product: String,
    pub version: String,
    /// Raw banner / extra detail.
    pub detail: String,
    /// Security-relevant observations.
    pub notes: Vec<String>,
}

fn open(ip: IpAddr, port: u16, wait: Duration) -> Option<TcpStream> {
    let s = TcpStream::connect_timeout(&SocketAddr::new(ip, port), wait).ok()?;
    s.set_read_timeout(Some(wait)).ok();
    s.set_write_timeout(Some(wait)).ok();
    Some(s)
}

fn read_some(s: &mut TcpStream, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while out.len() < max {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if n < buf.len() {
                    break;
                }
            }
        }
    }
    out
}

fn first_line(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_string()
}

/// "OpenSSH_9.6p1 Ubuntu-3ubuntu13" -> ("OpenSSH", "9.6p1")
fn split_product(s: &str) -> (String, String) {
    let tok = s.split_whitespace().next().unwrap_or("");
    for sep in ['_', '/', '-'] {
        if let Some((p, v)) = tok.split_once(sep)
            && v.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return (p.to_string(), v.to_string());
        }
    }
    (tok.to_string(), String::new())
}

fn header<'a>(resp: &'a str, name: &str) -> Option<&'a str> {
    resp.split("\r\n\r\n")
        .next()?
        .lines()
        .skip(1)
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
}

fn http(d: &mut Detection, resp: &str) {
    d.service = if d.service.is_empty() {
        "http".into()
    } else {
        d.service.clone()
    };
    d.detail = first_line(resp.as_bytes());
    if let Some(server) = header(resp, "server") {
        let (p, v) = split_product(server);
        d.product = p;
        d.version = v;
        d.detail = format!("{} · Server: {server}", d.detail);
    }
    if let Some(x) = header(resp, "x-powered-by") {
        d.notes
            .push(format!("X-Powered-By: {x} (version disclosure)"));
    }
    if d.version.chars().any(|c| c.is_ascii_digit()) {
        d.notes
            .push("Server header discloses the exact version".into());
    }
    let lower = resp.to_lowercase();
    if lower.contains("\"cluster_name\"") && lower.contains("\"number\"") {
        d.product = "Elasticsearch".into();
        d.version = json_str(resp, "number").unwrap_or_default();
        d.notes
            .push("Elasticsearch answered without authentication".into());
    }
    if lower.contains("\"apiversion\"")
        && lower.contains("\"version\"")
        && lower.contains("\"goversion\"")
    {
        d.product = "Docker Engine API".into();
        d.version = json_str(resp, "Version").unwrap_or_default();
        d.notes
            .push("Docker API answered without authentication (host takeover risk)".into());
    }
}

fn json_str(text: &str, key: &str) -> Option<String> {
    let i = text.find(&format!("\"{key}\""))?;
    let rest = &text[i + key.len() + 2..];
    let rest = rest
        .trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('"')?;
    Some(rest.split('"').next()?.to_string())
}

fn http_probe(ip: IpAddr, host: &str, port: u16, wait: Duration, path: &str) -> Option<String> {
    let mut s = open(ip, port, wait)?;
    let req =
        format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: network-analyser\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    Some(String::from_utf8_lossy(&read_some(&mut s, 16 * 1024)).into_owned())
}

fn https_probe(host: &str, ip: IpAddr, port: u16, wait: Duration) -> Option<(String, String)> {
    // Any certificate is accepted here: we only want the Server header.
    let sni = if host.parse::<IpAddr>().is_ok() {
        ip.to_string()
    } else {
        host.to_string()
    };
    let (mut s, tls) = crate::tls::connect_insecure(&sni, ip, port, wait).ok()?;
    if matches!(port, 993 | 995 | 465 | 8883 | 636) {
        // Server-speaks-first protocols over implicit TLS.
        let mut out = vec![0u8; 2048];
        let n = s.read(&mut out).unwrap_or(0);
        return Some((String::from_utf8_lossy(&out[..n]).into_owned(), tls));
    }
    let req = format!("GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: network-analyser\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while out.len() < 16 * 1024 {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    Some((String::from_utf8_lossy(&out).into_owned(), tls))
}

fn mysql(b: &[u8], d: &mut Detection) -> bool {
    // len(3) seq(1) protocol(1)=10 version\0
    if b.len() > 6 && b[4] == 10 {
        let v: String = b[5..]
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect();
        d.service = "mysql".into();
        d.product = if v.to_lowercase().contains("mariadb") {
            "MariaDB".into()
        } else {
            "MySQL".into()
        };
        d.version = v.split('-').next().unwrap_or(&v).to_string();
        d.detail = v;
        return true;
    }
    false
}

fn redis(ip: IpAddr, port: u16, wait: Duration, d: &mut Detection) -> bool {
    let Some(mut s) = open(ip, port, wait) else {
        return false;
    };
    if s.write_all(b"INFO server\r\n").is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&read_some(&mut s, 8192)).into_owned();
    if let Some(v) = text.lines().find_map(|l| l.strip_prefix("redis_version:")) {
        d.service = "redis".into();
        d.product = "Redis".into();
        d.version = v.trim().into();
        d.notes
            .push("Redis answered INFO without authentication".into());
        return true;
    }
    if text.starts_with("-NOAUTH") || text.contains("Authentication required") {
        d.service = "redis".into();
        d.product = "Redis".into();
        d.detail = "authentication required".into();
        return true;
    }
    false
}

fn memcached(ip: IpAddr, port: u16, wait: Duration, d: &mut Detection) -> bool {
    let Some(mut s) = open(ip, port, wait) else {
        return false;
    };
    if s.write_all(b"version\r\n").is_err() {
        return false;
    }
    let l = first_line(&read_some(&mut s, 256));
    if let Some(v) = l.strip_prefix("VERSION ") {
        d.service = "memcached".into();
        d.product = "memcached".into();
        d.version = v.into();
        d.notes
            .push("memcached answers without authentication".into());
        return true;
    }
    false
}

fn mqtt(ip: IpAddr, port: u16, wait: Duration, d: &mut Detection) -> bool {
    let Some(mut s) = open(ip, port, wait) else {
        return false;
    };
    // CONNECT, MQTT 3.1.1, clean session, keepalive 10, client id "na-probe".
    let pkt = [
        0x10, 20, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 10, 0, 8, b'n', b'a', b'-', b'p', b'r',
        b'o', b'b', b'e',
    ];
    if s.write_all(&pkt).is_err() {
        return false;
    }
    let r = read_some(&mut s, 16);
    if r.len() >= 4 && r[0] == 0x20 {
        d.service = "mqtt".into();
        d.product = "MQTT broker".into();
        match r[3] {
            0 => d.notes.push("MQTT broker accepts anonymous clients".into()),
            4 | 5 => d.detail = "authentication required".into(),
            c => d.detail = format!("CONNACK code {c}"),
        }
        let _ = s.write_all(&[0xe0, 0]); // DISCONNECT
        return true;
    }
    false
}

fn rdp(ip: IpAddr, port: u16, wait: Duration, d: &mut Detection) -> bool {
    let Some(mut s) = open(ip, port, wait) else {
        return false;
    };
    // X.224 Connection Request with RDP negotiation (TLS | CredSSP).
    let pkt = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];
    if s.write_all(&pkt).is_err() {
        return false;
    }
    let r = read_some(&mut s, 64);
    if r.len() >= 11 && r[0] == 3 && r[5] == 0xd0 {
        d.service = "rdp".into();
        d.product = "Remote Desktop".into();
        if r.len() >= 19 && r[11] == 2 {
            let proto = u32::from_le_bytes([r[15], r[16], r[17], r[18]]);
            d.detail = match proto {
                0 => "standard RDP security".into(),
                1 => "TLS".into(),
                2 | 8 => "CredSSP / NLA".into(),
                p => format!("protocol {p}"),
            };
            if proto == 0 {
                d.notes
                    .push("RDP without TLS/NLA (legacy RDP security)".into());
            }
        } else if r.len() >= 12 && r[11] == 3 {
            d.detail = "negotiation failure".into();
        }
        return true;
    }
    false
}

fn dns_version(ip: IpAddr, wait: Duration, d: &mut Detection) {
    // version.bind CHAOS TXT
    let mut q = vec![0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07version\x04bind\x00\x00\x10\x00\x03");
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let Ok(s) = UdpSocket::bind(bind) else { return };
    s.set_read_timeout(Some(wait)).ok();
    if s.send_to(&q, (ip, 53)).is_err() {
        return;
    }
    let mut buf = [0u8; 512];
    if let Ok((n, _)) = s.recv_from(&mut buf)
        && let Ok(r) = crate::dns::parse_response(&buf[..n])
        && let Some(a) = r.answers.first()
    {
        let v = a.data.trim_matches('"').to_string();
        let (p, ver) = split_product(&v);
        d.product = p;
        d.version = ver;
        d.detail = format!("version.bind: {v}");
        d.notes
            .push("DNS server discloses its version (version.bind)".into());
    }
}

/// Probe one open port. `host` is the name used for HTTP Host / TLS SNI.
pub fn detect(ip: IpAddr, host: &str, port: u16, wait: Duration) -> Detection {
    let mut d = Detection {
        service: crate::netinfo::service_name(port).to_string(),
        ..Default::default()
    };
    if crate::netinfo::is_print_port(port) {
        d.detail = "not probed: printers print whatever they receive".into();
        return d;
    }
    // Ports where the client speaks first.
    match port {
        6379 if redis(ip, port, wait, &mut d) => return d,
        11211 if memcached(ip, port, wait, &mut d) => return d,
        1883 if mqtt(ip, port, wait, &mut d) => return d,
        3389 if rdp(ip, port, wait, &mut d) => return d,
        5432 => {
            if let Some(mut s) = open(ip, port, wait)
                && s.write_all(&[0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f]).is_ok()
            {
                let r = read_some(&mut s, 1);
                if matches!(r.first(), Some(b'S' | b'N')) {
                    d.service = "postgres".into();
                    d.product = "PostgreSQL".into();
                    d.detail = if r[0] == b'S' {
                        "TLS supported".into()
                    } else {
                        "no TLS offered".into()
                    };
                    if r[0] == b'N' {
                        d.notes.push(
                            "PostgreSQL does not offer TLS: passwords and data in clear text"
                                .into(),
                        );
                    }
                }
            }
            return d;
        }
        502 => {
            if let Some(id) = crate::modbus::identify(SocketAddr::new(ip, port), wait) {
                d.service = "modbus".into();
                d.product = id;
                d.notes
                    .push("Modbus/TCP answers without authentication".into());
            }
            return d;
        }
        53 => {
            d.service = "dns".into();
            dns_version(ip, wait, &mut d);
            return d;
        }
        443 | 8443 | 6443 | 9443 | 4443 | 5986 | 993 | 995 | 465 | 8883 | 636 => {
            if let Some((resp, tls)) = https_probe(host, ip, port, wait) {
                d.service = if matches!(port, 993 | 995 | 465 | 8883 | 636) {
                    d.service.clone()
                } else {
                    "https".into()
                };
                if resp.starts_with("HTTP/") {
                    http(&mut d, &resp);
                    d.service = "https".into();
                } else if !resp.is_empty() {
                    let l = first_line(resp.as_bytes());
                    let (p, v) = split_product(
                        l.trim_start_matches(['*', '+', ' '])
                            .trim_start_matches("OK "),
                    );
                    d.product = p;
                    d.version = v;
                    d.detail = l;
                }
                d.detail = format!("{tls} · {}", d.detail)
                    .trim_end_matches(" · ")
                    .to_string();
                return d;
            }
        }
        _ => {}
    }
    // Server speaks first (SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL…)?
    if let Some(mut s) = open(ip, port, wait) {
        let b = read_some(&mut s, 4096);
        if !b.is_empty() {
            if mysql(&b, &mut d) {
                return d;
            }
            let l = first_line(&b);
            d.detail = l.clone();
            if let Some(rest) = l.strip_prefix("SSH-") {
                d.service = "ssh".into();
                let soft = rest.split_once('-').map(|x| x.1).unwrap_or(rest);
                let (p, v) = split_product(soft);
                d.product = p;
                d.version = v;
                if rest.starts_with("1.") {
                    d.notes.push("SSH protocol 1 supported (insecure)".into());
                }
            } else if let Some(rest) = l.strip_prefix("RFB ") {
                d.service = "vnc".into();
                d.product = "VNC (RFB)".into();
                d.version = rest.trim_start_matches('0').replace(".00", ".").to_string();
            } else if l.starts_with("220") || l.starts_with("+OK") || l.starts_with("* OK") {
                d.service = match port {
                    21 => "ftp",
                    25 | 587 => "smtp",
                    110 => "pop3",
                    143 => "imap",
                    _ if l.starts_with("+OK") => "pop3",
                    _ if l.starts_with("* OK") => "imap",
                    _ if l.to_lowercase().contains("ftp") => "ftp",
                    _ => "smtp",
                }
                .into();
                // "220 mail.example.com ESMTP Postfix (Ubuntu)", "220 (vsFTPd 3.0.5)"
                let text = l[3..].trim_start_matches([' ', '-', 'K', 'O']).trim();
                let known = [
                    "Postfix",
                    "Exim",
                    "Sendmail",
                    "Microsoft",
                    "vsFTPd",
                    "ProFTPD",
                    "Pure-FTPd",
                    "FileZilla",
                    "Dovecot",
                    "Courier",
                    "Cyrus",
                ];
                if let Some(k) = known.iter().find(|k| text.contains(*k)) {
                    d.product = k.to_string();
                    let after = &text[text.find(*k).unwrap_or(0) + k.len()..];
                    d.version = after
                        .trim_start_matches([' ', '/', '_'])
                        .split(|c: char| c.is_whitespace() || c == ')' || c == ']')
                        .next()
                        .filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit()))
                        .unwrap_or("")
                        .to_string();
                }
                if d.service == "ftp" && port == 21 {
                    d.notes
                        .push("FTP: credentials sent in clear text unless AUTH TLS is used".into());
                }
            } else if l.starts_with("HTTP/") {
                http(&mut d, &String::from_utf8_lossy(&b));
            } else {
                let (p, v) = split_product(&l);
                d.product = p;
                d.version = v;
            }
            return d;
        }
    }
    // Silent service: try HTTP.
    if let Some(resp) = http_probe(
        ip,
        host,
        port,
        wait,
        if port == 2375 || port == 2376 {
            "/version"
        } else {
            "/"
        },
    ) && resp.starts_with("HTTP/")
    {
        http(&mut d, &resp);
        if let Some(title) = crate::probes::html_tag(&resp, "title") {
            d.detail = format!("{} · “{title}”", d.detail);
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn products() {
        assert_eq!(
            split_product("OpenSSH_9.6p1 Ubuntu-3"),
            ("OpenSSH".into(), "9.6p1".into())
        );
        assert_eq!(
            split_product("nginx/1.24.0 (Ubuntu)"),
            ("nginx".into(), "1.24.0".into())
        );
        assert_eq!(split_product("Apache"), ("Apache".into(), String::new()));
        assert_eq!(
            json_str(r#"{"Version": "24.0.7", "x":1}"#, "Version").as_deref(),
            Some("24.0.7")
        );
        let mut d = Detection::default();
        assert!(mysql(
            b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00",
            &mut d
        ));
        assert_eq!(
            (d.product.as_str(), d.version.as_str()),
            ("MySQL", "8.0.36")
        );
    }

    #[test]
    fn local_ssh_if_present() {
        // Exercise the live path against whatever runs locally on 22 (if anything).
        let d = detect(
            "127.0.0.1".parse().unwrap(),
            "localhost",
            22,
            Duration::from_millis(500),
        );
        if d.service == "ssh" {
            assert!(!d.product.is_empty());
        }
    }
}
