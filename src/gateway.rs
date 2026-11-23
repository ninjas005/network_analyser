//! Gateway discovery: default routers (IPv4/IPv6), reachability, MAC and
//! vendor, management services, UPnP-IGD and NAT-PMP external address,
//! double-NAT / CGNAT detection and DNS server health.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Level {
    Info,
    Good,
    Warn,
    Bad,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub section: String,
    pub key: String,
    pub value: String,
    pub level: Level,
}

pub enum GwEvent {
    Finding(Finding),
    Status(String),
    Done,
}

pub fn start() -> Receiver<GwEvent> {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("gateway".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(run(&tx));
            rt.shutdown_background();
            let _ = tx.send(GwEvent::Done);
        })
        .expect("spawn gateway thread");
    rx
}

struct Out<'a>(&'a Sender<GwEvent>);

impl Out<'_> {
    fn add(&self, section: &str, key: &str, value: impl Into<String>, level: Level) {
        let _ = self.0.send(GwEvent::Finding(Finding {
            section: section.into(),
            key: key.into(),
            value: value.into(),
            level,
        }));
    }
    fn status(&self, s: &str) {
        let _ = self.0.send(GwEvent::Status(s.into()));
    }
}

const MGMT_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (23, "Telnet"),
    (53, "DNS"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (5000, "UPnP/HTTP"),
    (1900, "UPnP"),
];

async fn run(tx: &Sender<GwEvent>) {
    let out = Out(tx);
    out.status("Reading routing table…");
    let routes = tokio::task::spawn_blocking(crate::netconfig::routes)
        .await
        .unwrap_or_default();
    let mut gws: Vec<(IpAddr, String, Option<u32>)> = Vec::new();
    for r in routes.iter().filter(|r| r.is_default()) {
        if let Some(g) = r.gateway
            && !gws.iter().any(|(x, i, _)| *x == g && *i == r.iface)
        {
            gws.push((g, r.iface.clone(), r.metric));
        }
    }
    if gws.is_empty() {
        out.add(
            "Default routes",
            "Gateway",
            "No default route — this machine has no path off the local network",
            Level::Bad,
        );
    }
    for (i, (g, iface, metric)) in gws.iter().enumerate() {
        let label = if gws.len() > 1 && i == 0 {
            "Gateway (preferred)".to_string()
        } else {
            "Gateway".to_string()
        };
        let metric = metric.map(|m| format!(", metric {m}")).unwrap_or_default();
        out.add(
            "Default routes",
            &label,
            format!("{g} via {iface}{metric}"),
            Level::Info,
        );
    }
    if gws.iter().filter(|(g, _, _)| g.is_ipv4()).count() > 1 {
        out.add(
            "Default routes",
            "Note",
            "Several IPv4 default routes: traffic uses the lowest metric; check for VPN or duplicate links",
            Level::Warn,
        );
    }

    for (g, _, _) in &gws {
        let sec = format!("Gateway {g}");
        out.status(&format!("Probing {g}…"));
        // Three echoes for RTT / loss.
        let mut rtts = Vec::new();
        for _ in 0..3 {
            if let crate::traceroute::ProbeResult::Reached(r) =
                crate::traceroute::probe(*g, 64, Duration::from_secs(1)).await
            {
                rtts.push(r);
            }
        }
        if rtts.is_empty() {
            out.add(
                &sec,
                "Ping",
                "no reply (ICMP may be blocked by the router)",
                Level::Warn,
            );
        } else {
            let avg = rtts.iter().sum::<f32>() / rtts.len() as f32;
            let lvl = if avg > 20.0 { Level::Warn } else { Level::Good };
            out.add(
                &sec,
                "Ping",
                format!("{avg:.1} ms avg, {}/3 replies", rtts.len()),
                lvl,
            );
        }
        if let IpAddr::V4(v4) = g {
            if let Some(mac) = crate::platform::arp_table().get(v4) {
                let vendor =
                    crate::netinfo::mac_vendor(mac).unwrap_or_else(|| "unknown vendor".into());
                out.add(&sec, "MAC", format!("{mac} ({vendor})"), Level::Info);
            }
            if let Some(name) = crate::probes::reverse_dns(*v4).await {
                out.add(&sec, "Name", name, Level::Info);
            }
            let probes = MGMT_PORTS.iter().map(|&(p, n)| async move {
                let open = matches!(
                    crate::probes::tcp_probe(*v4, p, Duration::from_millis(800)).await,
                    crate::probes::TcpState::Open
                );
                (p, n, open)
            });
            let open: Vec<(u16, &str)> = futures::future::join_all(probes)
                .await
                .into_iter()
                .filter(|x| x.2)
                .map(|x| (x.0, x.1))
                .collect();
            if open.is_empty() {
                out.add(&sec, "Services", "no management ports open", Level::Info);
            } else {
                let list = open
                    .iter()
                    .map(|(p, n)| format!("{p}/{n}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let telnet = open.iter().any(|(p, _)| *p == 23);
                out.add(
                    &sec,
                    "Services",
                    list,
                    if telnet { Level::Warn } else { Level::Info },
                );
                if telnet {
                    out.add(
                        &sec,
                        "Telnet",
                        "Telnet is open: unencrypted management access",
                        Level::Warn,
                    );
                }
                for port in [80u16, 8080] {
                    if open.iter().any(|(p, _)| *p == port) {
                        let b = crate::probes::grab_banner(*v4, port, true).await;
                        if let Some(t) = b.http_title.or(b.http_server) {
                            out.add(
                                &sec,
                                "Web UI",
                                format!("http://{v4}:{port}/ — {t}"),
                                Level::Info,
                            );
                        }
                    }
                }
            }
        }
    }

    // External address as seen by the gateway.
    let gw4 = gws.iter().find_map(|(g, _, _)| match g {
        IpAddr::V4(v) => Some(*v),
        _ => None,
    });
    if let Some(gw) = gw4 {
        out.status("Asking the gateway for its external address (NAT-PMP, UPnP)…");
        let natpmp = tokio::task::spawn_blocking(move || nat_pmp_external(gw))
            .await
            .ok()
            .flatten();
        let upnp = tokio::task::spawn_blocking(upnp_external)
            .await
            .ok()
            .flatten();
        let mut external = None;
        match natpmp {
            Some(ip) => {
                out.add(
                    "Internet connection",
                    "NAT-PMP external IP",
                    ip.to_string(),
                    Level::Info,
                );
                external = Some(ip);
            }
            None => out.add(
                "Internet connection",
                "NAT-PMP",
                "not supported or disabled",
                Level::Info,
            ),
        }
        match upnp {
            Some((ip, model)) => {
                out.add("Internet connection", "UPnP-IGD", model, Level::Info);
                match ip {
                    Some(ip) => {
                        out.add(
                            "Internet connection",
                            "UPnP external IP",
                            ip.to_string(),
                            Level::Info,
                        );
                        external = external.or(Some(ip));
                    }
                    None => out.add(
                        "Internet connection",
                        "UPnP external IP",
                        "not reported",
                        Level::Info,
                    ),
                }
                out.add(
                    "Internet connection",
                    "UPnP note",
                    "UPnP port mapping is enabled: devices on the LAN can open ports to the internet",
                    Level::Warn,
                );
            }
            None => out.add(
                "Internet connection",
                "UPnP-IGD",
                "no Internet Gateway Device answered",
                Level::Info,
            ),
        }
        if let Some(IpAddr::V4(ext)) = external {
            let class = crate::webapi::classify(IpAddr::V4(ext));
            if class == "public" {
                out.add(
                    "Internet connection",
                    "NAT",
                    "single NAT: the gateway holds a public address",
                    Level::Good,
                );
            } else {
                out.add(
                    "Internet connection",
                    "NAT",
                    format!(
                        "the gateway's WAN address is {class}: double NAT{}",
                        if class.contains("carrier") {
                            " (carrier-grade NAT)"
                        } else {
                            ""
                        }
                    ),
                    Level::Warn,
                );
            }
        }
    }

    // Resolvers.
    out.status("Checking DNS servers…");
    let mut servers = tokio::task::spawn_blocking(crate::dns::system_servers)
        .await
        .unwrap_or_default();
    // systemd-resolved: test the real upstream servers behind the stub too.
    if servers.iter().any(|s| s.is_loopback()) {
        for up in tokio::task::spawn_blocking(crate::dns::resolved_upstreams)
            .await
            .unwrap_or_default()
        {
            if !servers.contains(&up) {
                servers.push(up);
            }
        }
    }
    if servers.is_empty() {
        out.add("DNS servers", "Resolver", "none configured", Level::Bad);
    }
    for s in servers {
        let r = tokio::task::spawn_blocking(move || {
            crate::dns::query(&crate::dns::Query {
                name: "example.com".into(),
                qtype: 1,
                server: SocketAddr::new(s, 53),
                tcp: false,
                timeout: Duration::from_secs(2),
                recursion: true,
                dnssec: false,
            })
        })
        .await;
        match r {
            Ok(Ok(a)) if a.response.rcode == 0 && !a.response.answers.is_empty() => out.add(
                "DNS servers",
                &s.to_string(),
                format!(
                    "answers in {:.0} ms{}",
                    a.rtt.as_secs_f64() * 1000.0,
                    if a.response.authentic {
                        ", DNSSEC-validating"
                    } else {
                        ""
                    }
                ),
                Level::Good,
            ),
            Ok(Ok(a)) => out.add(
                "DNS servers",
                &s.to_string(),
                format!("replied {}", crate::dns::rcode_name(a.response.rcode)),
                Level::Warn,
            ),
            Ok(Err(e)) => out.add("DNS servers", &s.to_string(), e, Level::Bad),
            Err(e) => out.add("DNS servers", &s.to_string(), e.to_string(), Level::Bad),
        }
    }
    out.status("Done");
}

/// NAT-PMP (RFC 6886) external address request to the gateway.
pub fn nat_pmp_external(gw: Ipv4Addr) -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.set_read_timeout(Some(Duration::from_millis(700))).ok()?;
    let mut buf = [0u8; 16];
    for _ in 0..2 {
        s.send_to(&[0, 0], (gw, 5351)).ok()?;
        if let Ok((n, from)) = s.recv_from(&mut buf)
            && from.ip() == IpAddr::V4(gw)
            && n >= 12
            && buf[1] == 128
            && buf[2..4] == [0, 0]
        {
            return Some(IpAddr::V4(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11])));
        }
    }
    None
}

/// Minimal HTTP/1.0 request; returns the body.
fn http(url: &str, method: &str, headers: &str, body: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let addr: SocketAddr = if hostport.contains(':') {
        hostport.parse().ok()?
    } else {
        format!("{hostport}:80").parse().ok()?
    };
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {hostport}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut resp = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline && resp.len() < 256 * 1024 {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&resp).into_owned();
    text.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let i = xml.find(&open)? + open.len();
    let j = xml[i..].find(&format!("</{name}>"))? + i;
    Some(xml[i..j].trim())
}

/// SSDP search for an Internet Gateway Device; returns (external IP, model).
pub fn upnp_external() -> Option<(Option<IpAddr>, String)> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.set_read_timeout(Some(Duration::from_millis(400))).ok()?;
    let search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    let _ = s.send_to(search.as_bytes(), ("239.255.255.250", 1900));
    let mut location = None;
    let deadline = Instant::now() + Duration::from_millis(2500);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && location.is_none() {
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            location = text.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("location")
                    .then(|| v.trim().to_string())
            });
        }
    }
    let location = location?;
    let desc = http(&location, "GET", "", "")?;
    let model = [
        tag(&desc, "friendlyName"),
        tag(&desc, "manufacturer"),
        tag(&desc, "modelName"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" · ");
    // Find the WAN connection service's control URL.
    let mut ext = None;
    for svc in ["WANIPConnection", "WANPPPConnection"] {
        let Some(i) = desc.find(&format!("urn:schemas-upnp-org:service:{svc}:")) else {
            continue;
        };
        let st_end = desc[i..].find('<').map(|j| i + j).unwrap_or(desc.len());
        let service_type = &desc[i..st_end];
        let Some(ctrl) = tag(&desc[i..], "controlURL") else {
            continue;
        };
        let base = location.split('/').take(3).collect::<Vec<_>>().join("/");
        let url = if ctrl.starts_with("http") {
            ctrl.to_string()
        } else {
            format!(
                "{base}{}{ctrl}",
                if ctrl.starts_with('/') { "" } else { "/" }
            )
        };
        let body = format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetExternalIPAddress xmlns:u=\"{service_type}\"/></s:Body></s:Envelope>"
        );
        let headers = format!(
            "Content-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service_type}#GetExternalIPAddress\"\r\n"
        );
        if let Some(resp) = http(&url, "POST", &headers, &body)
            && let Some(ip) = tag(&resp, "NewExternalIPAddress").and_then(|v| v.parse().ok())
        {
            ext = Some(ip);
            break;
        }
    }
    Some((
        ext,
        if model.is_empty() {
            "Internet Gateway Device".into()
        } else {
            model
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_tags() {
        let x = "<root><device><friendlyName> Router </friendlyName><controlURL>/ctl/IPConn</controlURL></device></root>";
        assert_eq!(tag(x, "friendlyName"), Some("Router"));
        assert_eq!(tag(x, "controlURL"), Some("/ctl/IPConn"));
        assert_eq!(tag(x, "missing"), None);
    }

    #[test]
    fn natpmp_unreachable_is_none() {
        // TEST-NET-1 never answers.
        assert!(nat_pmp_external(Ipv4Addr::new(192, 0, 2, 1)).is_none());
    }
}
