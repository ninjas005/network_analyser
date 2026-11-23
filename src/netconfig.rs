//! Local network configuration: interfaces, routes, DNS servers, hostname.
//! Structured where the OS offers it cheaply, raw command output otherwise.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::platform;

#[derive(Clone, Debug, Default)]
pub struct Iface {
    pub name: String,
    pub mac: Option<String>,
    /// (address, prefix length)
    pub addrs: Vec<(IpAddr, u8)>,
    pub mtu: Option<u32>,
    pub up: Option<bool>,
    pub speed_mbps: Option<u64>,
    pub kind: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub dest: String,
    pub gateway: Option<IpAddr>,
    pub iface: String,
    pub metric: Option<u32>,
    pub v6: bool,
}

impl Route {
    pub fn is_default(&self) -> bool {
        matches!(
            self.dest.as_str(),
            "default" | "0.0.0.0/0" | "::/0" | "0.0.0.0"
        )
    }
}

fn prefix_len(mask: IpAddr) -> u8 {
    match mask {
        IpAddr::V4(m) => u32::from(m).count_ones() as u8,
        IpAddr::V6(m) => u128::from(m).count_ones() as u8,
    }
}

fn read(path: String) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn interfaces() -> Vec<Iface> {
    let mut map: BTreeMap<String, Iface> = BTreeMap::new();
    for a in if_addrs::get_if_addrs().unwrap_or_default() {
        let (ip, mask) = match &a.addr {
            if_addrs::IfAddr::V4(v) => (IpAddr::V4(v.ip), IpAddr::V4(v.netmask)),
            if_addrs::IfAddr::V6(v) => (IpAddr::V6(v.ip), IpAddr::V6(v.netmask)),
        };
        let e = map.entry(a.name.clone()).or_insert_with(|| Iface {
            name: a.name.clone(),
            kind: if a.is_loopback() { "loopback" } else { "" },
            ..Default::default()
        });
        e.addrs.push((ip, prefix_len(mask)));
    }
    if cfg!(target_os = "linux")
        && let Ok(dir) = std::fs::read_dir("/sys/class/net")
    {
        for d in dir.flatten() {
            let name = d.file_name().to_string_lossy().into_owned();
            let e = map.entry(name.clone()).or_insert_with(|| Iface {
                name: name.clone(),
                ..Default::default()
            });
            let base = format!("/sys/class/net/{name}");
            e.mac = read(format!("{base}/address"))
                .filter(|m| m != "00:00:00:00:00:00")
                .map(|m| m.to_uppercase());
            e.mtu = read(format!("{base}/mtu")).and_then(|v| v.parse().ok());
            // Tunnels and loopback report "unknown": use IFF_UP plus carrier.
            let flags = read(format!("{base}/flags"))
                .and_then(|f| u32::from_str_radix(f.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            e.up = read(format!("{base}/operstate")).map(|s| {
                s == "up"
                    || (s == "unknown"
                        && flags & 1 == 1
                        && read(format!("{base}/carrier")).is_some_and(|c| c == "1"))
            });
            e.speed_mbps = read(format!("{base}/speed"))
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| *v > 0)
                .map(|v| v as u64);
            if e.kind.is_empty() {
                e.kind = if std::path::Path::new(&format!("{base}/wireless")).exists() {
                    "wireless"
                } else if std::path::Path::new(&format!("/sys/devices/virtual/net/{name}")).exists()
                {
                    "virtual"
                } else {
                    "ethernet"
                };
            }
        }
    }
    if cfg!(target_os = "macos")
        && let Some(text) = output("ifconfig", &[])
    {
        let mut cur: Option<String> = None;
        for l in text.lines() {
            if !l.starts_with(['\t', ' ']) {
                cur = l.split(':').next().map(String::from);
                if let (Some(n), Some(i)) = (&cur, l.find("mtu ")) {
                    let mtu = l[i + 4..]
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok());
                    if let Some(e) = map.get_mut(n) {
                        e.mtu = mtu;
                    }
                }
            } else if let Some(n) = &cur
                && let Some(e) = map.get_mut(n)
            {
                let t = l.trim();
                if let Some(m) = t.strip_prefix("ether ") {
                    e.mac = Some(m.trim().to_uppercase());
                } else if let Some(s) = t.strip_prefix("status: ") {
                    e.up = Some(s == "active");
                }
            }
        }
    }
    for e in map.values_mut() {
        if e.mac.is_none()
            && let Some((IpAddr::V4(v4), _)) = e.addrs.iter().find(|(a, _)| a.is_ipv4())
        {
            e.mac = platform::iface_mac(&e.name, *v4);
        }
        if e.kind.is_empty() {
            e.kind = "interface";
        }
        e.addrs.sort_by_key(|(a, _)| (a.is_ipv6(), *a));
    }
    let mut v: Vec<Iface> = map.into_values().collect();
    // Interfaces with an IPv4 address first, loopback last.
    v.sort_by_key(|i| {
        (
            i.kind == "loopback",
            !i.addrs.iter().any(|(a, _)| a.is_ipv4()),
            i.name.clone(),
        )
    });
    v
}

fn output(prog: &str, args: &[&str]) -> Option<String> {
    let o = platform::command(prog).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn routes() -> Vec<Route> {
    if cfg!(target_os = "linux") {
        let mut out = Vec::new();
        for (fam, v6) in [("-4", false), ("-6", true)] {
            let Some(json) = output("ip", &["-j", fam, "route", "show", "table", "main"]) else {
                continue;
            };
            let Ok(serde_json::Value::Array(items)) =
                serde_json::from_str::<serde_json::Value>(&json)
            else {
                continue;
            };
            for r in items {
                let s = |k: &str| r.get(k).and_then(|v| v.as_str()).map(String::from);
                let dest = s("dst").unwrap_or_default();
                out.push(Route {
                    dest: if dest == "default" {
                        if v6 {
                            "::/0".into()
                        } else {
                            "0.0.0.0/0".into()
                        }
                    } else {
                        dest
                    },
                    gateway: s("gateway").and_then(|g| g.parse().ok()),
                    iface: s("dev").unwrap_or_default(),
                    metric: r.get("metric").and_then(|m| m.as_u64()).map(|m| m as u32),
                    v6,
                });
            }
        }
        if out.is_empty()
            && let Some((dev, gw)) = platform::default_gateway()
        {
            out.push(Route {
                dest: "0.0.0.0/0".into(),
                gateway: Some(gw.into()),
                iface: dev,
                metric: None,
                v6: false,
            });
        }
        return out;
    }
    if cfg!(target_os = "macos") {
        let mut out = Vec::new();
        for (fam, v6) in [("inet", false), ("inet6", true)] {
            let Some(text) = output("netstat", &["-rn", "-f", fam]) else {
                continue;
            };
            for l in text.lines() {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() < 4 || f[0] == "Destination" || f[0].ends_with(':') {
                    continue;
                }
                let gw = f[1].split('%').next().unwrap_or("").parse().ok();
                out.push(Route {
                    dest: if f[0] == "default" {
                        if v6 {
                            "::/0".into()
                        } else {
                            "0.0.0.0/0".into()
                        }
                    } else {
                        f[0].into()
                    },
                    gateway: gw,
                    iface: f[3].into(),
                    metric: None,
                    v6,
                });
            }
        }
        return out;
    }
    // Windows: parse `route print` (column layout is not localized).
    let Some(text) = output("route", &["print"]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() == 5
            && let (Ok(dst), Ok(mask)) = (
                f[0].parse::<std::net::Ipv4Addr>(),
                f[1].parse::<std::net::Ipv4Addr>(),
            )
        {
            out.push(Route {
                dest: format!("{dst}/{}", u32::from(mask).count_ones()),
                gateway: f[2].parse().ok(),
                iface: f[3].into(),
                metric: f[4].parse().ok(),
                v6: false,
            });
        } else if f.len() == 4
            && f[0].parse::<u32>().is_ok()
            && f[2].contains(':')
            && f[2].contains('/')
        {
            out.push(Route {
                dest: f[2].into(),
                gateway: f[3].parse().ok(),
                iface: format!("if {}", f[0]),
                metric: f[1].parse().ok(),
                v6: true,
            });
        }
    }
    out
}

pub fn hostname() -> String {
    dns_lookup::get_hostname().unwrap_or_else(|_| "?".into())
}

/// Neighbour (ARP) cache for display.
pub fn neighbours() -> Vec<(IpAddr, String)> {
    let mut v: Vec<(IpAddr, String)> = platform::arp_table()
        .into_iter()
        .map(|(ip, mac)| (IpAddr::V4(ip), mac))
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_config_is_readable() {
        let ifs = interfaces();
        // Every machine has at least a loopback with an address.
        assert!(ifs.iter().any(|i| !i.addrs.is_empty()), "{ifs:?}");
        let _ = routes();
        assert!(!hostname().is_empty());
        assert!(
            Route {
                dest: "::/0".into(),
                gateway: None,
                iface: String::new(),
                metric: None,
                v6: true
            }
            .is_default()
        );
    }
}
