//! OS-specific glue: running helper commands without console windows,
//! default gateway, ARP cache, interface MACs and per-user directories.
//!
//! Linux reads /proc and /sys directly. macOS and Windows parse the output
//! of the stock `route`, `arp` and `ifconfig` tools, so no extra
//! dependencies or privileges are needed.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;

/// Windows: don't flash a console window for helper processes.
#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn command(program: &str) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.env("LC_ALL", "C");
    cmd
}

pub fn async_command(program: &str) -> tokio::process::Command {
    #[allow(unused_mut)]
    let mut cmd = tokio::process::Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.env("LC_ALL", "C");
    cmd
}

#[cfg(not(target_os = "linux"))]
fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = command(program).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------- gateway

/// (interface name or address, gateway) of the default IPv4 route.
#[cfg(target_os = "linux")]
pub fn default_gateway() -> Option<(String, Ipv4Addr)> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    text.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 2 && f[1] == "00000000" {
            let gw = u32::from_str_radix(f[2], 16).ok()?;
            Some((f[0].to_string(), Ipv4Addr::from(u32::from_be(gw))))
        } else {
            None
        }
    })
}

#[cfg(target_os = "macos")]
pub fn default_gateway() -> Option<(String, Ipv4Addr)> {
    // "   gateway: 192.168.1.1" / "  interface: en0"
    let text = output("route", &["-n", "get", "default"])?;
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().to_string()))
    };
    Some((field("interface:")?, field("gateway:")?.parse().ok()?))
}

#[cfg(windows)]
pub fn default_gateway() -> Option<(String, Ipv4Addr)> {
    // "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     35"
    let text = output("route", &["print", "-4", "0.0.0.0"])?;
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 5 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0")
                .then(|| {
                    Some((
                        f[3].to_string(),
                        f[2].parse().ok()?,
                        f[4].parse::<u32>().unwrap_or(9999),
                    ))
                })
                .flatten()
        })
        .min_by_key(|(_, _, metric)| *metric)
        .map(|(iface_ip, gw, _)| (iface_ip, gw))
}

// ---------------------------------------------------------------- ARP

/// Resolved entries of the OS neighbour cache: ip -> MAC (upper-case, ':').
#[cfg(target_os = "linux")]
pub fn arp_table() -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
        for line in text.lines().skip(1) {
            // IP, HW type, Flags, HW address, Mask, Device
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 4
                && f[2] == "0x2"
                && let (Ok(ip), Some(mac)) = (f[0].parse(), normalize_mac(f[3]))
            {
                map.insert(ip, mac);
            }
        }
    }
    map
}

/// `arp -a` is a process spawn, so the result is cached for a second.
#[cfg(not(target_os = "linux"))]
pub fn arp_table() -> HashMap<Ipv4Addr, String> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static CACHE: Mutex<Option<(Instant, HashMap<Ipv4Addr, String>)>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, map)) = guard.as_ref()
        && at.elapsed() < Duration::from_secs(1)
    {
        return map.clone();
    }
    let map = output("arp", &["-a"])
        .map(|t| parse_arp_output(&t))
        .unwrap_or_default();
    *guard = Some((Instant::now(), map.clone()));
    map
}

/// Parses both macOS (`? (10.0.0.1) at e8:22:b8:b:c:19 on en0`) and
/// Windows (`  10.0.0.1     e8-22-b8-0b-0c-19     dynamic`) formats.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn parse_arp_output(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            let tok = tok.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none()
                && let Ok(v) = tok.parse::<Ipv4Addr>()
            {
                ip = Some(v);
            } else if mac.is_none() {
                mac = normalize_mac(tok);
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            map.insert(ip, mac);
        }
    }
    map
}

/// "e8:22:b8:b:c:19" / "E8-22-B8-0B-0C-19" -> "E8:22:B8:0B:0C:19".
/// Rejects all-zero, broadcast and multicast addresses.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 || parts.iter().any(|p| p.is_empty() || p.len() > 2) {
        return None;
    }
    let bytes: Vec<u8> = parts
        .iter()
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<_>>()?;
    if bytes.iter().all(|b| *b == 0) || bytes.iter().all(|b| *b == 0xff) || bytes[0] & 0x01 != 0 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

// ---------------------------------------------------------------- interface MAC

#[cfg(target_os = "linux")]
pub fn iface_mac(name: &str, _ip: Ipv4Addr) -> Option<String> {
    normalize_mac(
        std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
            .ok()?
            .trim(),
    )
}

#[cfg(target_os = "macos")]
pub fn iface_mac(name: &str, _ip: Ipv4Addr) -> Option<String> {
    let text = output("ifconfig", &[name])?;
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix("ether ")
            .and_then(|m| normalize_mac(m.trim()))
    })
}

#[cfg(windows)]
pub fn iface_mac(_name: &str, ip: Ipv4Addr) -> Option<String> {
    // `ipconfig /all`: each adapter block lists "Physical Address" before
    // its "IPv4 Address"; take the MAC of the block containing our IP.
    let text = output("ipconfig", &["/all"])?;
    let mut mac = None;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            mac = None; // new adapter block
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.contains("Physical Address") {
                mac = normalize_mac(v.trim());
            } else if k.contains("IPv4 Address") && v.trim().starts_with(&ip.to_string()) {
                return mac;
            }
        }
    }
    None
}

// ---------------------------------------------------------------- directories

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

/// Per-user data directory for this app.
pub fn data_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home_dir().map(|h| h.join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|h| h.join(".local/share")))
    }?;
    Some(base.join("network_analyser"))
}

/// Places a packaged MAC-vendor list may live, lowest priority first.
pub fn bundled_oui_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        v.extend(
            [
                "/usr/share/nmap/nmap-mac-prefixes",
                "/usr/share/arp-scan/ieee-oui.txt",
                "/usr/share/ieee-data/oui.txt",
                "/usr/share/network-analyser/oui.txt",
            ]
            .map(PathBuf::from),
        );
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        v.push(dir.join("oui.txt"));
        v.push(dir.join("../Resources/oui.txt")); // macOS .app bundle
        v.push(dir.join("../share/network-analyser/oui.txt")); // tarball layout
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_normalization() {
        assert_eq!(
            normalize_mac("e8:22:b8:b:c:19").as_deref(),
            Some("E8:22:B8:0B:0C:19")
        );
        assert_eq!(
            normalize_mac("E8-22-B8-0B-0C-19").as_deref(),
            Some("E8:22:B8:0B:0C:19")
        );
        assert_eq!(normalize_mac("ff-ff-ff-ff-ff-ff"), None);
        assert_eq!(normalize_mac("01-00-5e-00-00-fb"), None);
        assert_eq!(normalize_mac("(incomplete)"), None);
    }

    #[test]
    fn arp_formats() {
        let mac = "? (192.168.1.1) at e8:22:b8:b:c:19 on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0";
        let m = parse_arp_output(mac);
        assert_eq!(m.len(), 1);
        assert_eq!(m[&"192.168.1.1".parse().unwrap()], "E8:22:B8:0B:0C:19");
        let win = "Interface: 192.168.1.20 --- 0x7\n  Internet Address      Physical Address      Type\n  192.168.1.1           e8-22-b8-0b-0c-19     dynamic\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n  224.0.0.251           01-00-5e-00-00-fb     static";
        let m = parse_arp_output(win);
        assert_eq!(m.len(), 1);
        assert!(m.contains_key(&"192.168.1.1".parse().unwrap()));
    }
}
