//! Local network facts: interfaces, gateway, ARP table, MAC vendor lookup,
//! range parsing and well-known service names.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub struct LocalIface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: Option<String>,
}

impl LocalIface {
    pub fn cidr(&self) -> String {
        let mask = prefix_mask(self.prefix);
        let net = Ipv4Addr::from(u32::from(self.ip) & mask);
        format!("{}/{}", net, self.prefix)
    }
}

fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) }
}

/// Non-loopback IPv4 interfaces, physical-looking ones first.
pub fn local_interfaces() -> Vec<LocalIface> {
    let mut out: Vec<LocalIface> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() => Some(LocalIface {
                mac: read_iface_mac(&i.name),
                name: i.name,
                ip: v4.ip,
                prefix: v4.prefixlen,
            }),
            _ => None,
        })
        .collect();
    let gw_iface = default_gateway().map(|(iface, _)| iface);
    out.sort_by_key(|i| {
        let virt = ["docker", "br-", "veth", "virbr", "tailscale", "tun", "wg", "lxc"]
            .iter()
            .any(|p| i.name.starts_with(p));
        (Some(&i.name) != gw_iface.as_ref(), virt, i.name.clone())
    });
    out
}

fn read_iface_mac(name: &str) -> Option<String> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    let s = s.trim().to_uppercase();
    (s.len() == 17 && s != "00:00:00:00:00:00").then_some(s)
}

/// (interface, gateway ip) of the default IPv4 route, from /proc/net/route.
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

/// Complete entries of the kernel ARP cache: ip -> MAC.
pub fn arp_table() -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // IP, HW type, Flags, HW address, Mask, Device
            if f.len() >= 4 && f[2] == "0x2" && f[3] != "00:00:00:00:00:00"
                && let Ok(ip) = f[0].parse() {
                    map.insert(ip, f[3].to_uppercase());
                }
        }
    }
    map
}

/// Vendor for a MAC address. Uses the IEEE registry or nmap's prefix list
/// if present on the system; nothing is bundled to keep the binary small.
pub fn mac_vendor(mac: &str) -> Option<String> {
    static DB: OnceLock<HashMap<String, String>> = OnceLock::new();
    let db = DB.get_or_init(load_oui_db);
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    if hex.len() < 6 {
        return None;
    }
    // Locally administered bit => randomized / private MAC.
    let first = u8::from_str_radix(&hex[0..2], 16).ok()?;
    if let Some(v) = db.get(&hex[0..6]) {
        return Some(v.clone());
    }
    (first & 0x02 != 0).then(|| "Private / randomized MAC".to_string())
}

pub fn user_oui_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share")))?;
    Some(base.join("network_analyser/oui.txt"))
}

/// Download the current IEEE OUI registry with the system `curl`
/// (keeps a TLS stack out of this binary).
pub fn update_oui_db() -> Result<std::path::PathBuf, String> {
    let path = user_oui_path().ok_or("cannot determine data directory")?;
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("tmp");
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "120", "-A", "Mozilla/5.0", "-o"])
        .arg(&tmp)
        .arg("https://standards-oui.ieee.org/oui/oui.txt")
        .status()
        .map_err(|e| format!("failed to run curl: {e}"))?;
    if !status.success() {
        return Err(format!("curl exited with {status}"));
    }
    let n = parse_ieee(&std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?).len();
    if n < 10_000 {
        return Err(format!("downloaded file looks wrong ({n} entries)"));
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(path)
}

fn parse_ieee(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        // "286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd."
        if let Some((prefix, rest)) = line.split_once("(base 16)") {
            let p = prefix.trim();
            if p.len() == 6 {
                map.insert(p.to_uppercase(), rest.trim().to_string());
            }
        }
    }
    map
}

/// Merge every OUI source available; newer sources override older ones.
fn load_oui_db() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for path in ["/usr/share/nmap/nmap-mac-prefixes", "/usr/share/arp-scan/ieee-oui.txt"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines().filter(|l| !l.starts_with('#')) {
                if let Some((p, v)) = line.split_once(|c: char| c.is_whitespace())
                    && p.len() == 6 {
                        map.insert(p.to_uppercase(), v.trim().to_string());
                    }
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string("/usr/share/ieee-data/oui.txt") {
        map.extend(parse_ieee(&text));
    }
    if let Some(Ok(text)) = user_oui_path().map(std::fs::read_to_string) {
        map.extend(parse_ieee(&text));
    }
    map
}

/// Parse "192.168.1.0/24", "10.0.0.5-10.0.0.40", "10.0.0.5-40" or a single IP.
/// For CIDR ranges the network and broadcast addresses are skipped.
pub fn parse_range(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    const MAX: u32 = 65_536;
    let s = input.trim();
    let (start, end) = if let Some((ip, bits)) = s.split_once('/') {
        let ip: Ipv4Addr = ip.trim().parse().map_err(|_| format!("Invalid IP '{ip}'"))?;
        let bits: u8 = bits.trim().parse().map_err(|_| format!("Invalid prefix '{bits}'"))?;
        if !(16..=32).contains(&bits) {
            return Err("Prefix must be between /16 and /32".into());
        }
        let mask = prefix_mask(bits);
        let net = u32::from(ip) & mask;
        let bcast = net | !mask;
        if bits >= 31 { (net, bcast) } else { (net + 1, bcast - 1) }
    } else if let Some((a, b)) = s.split_once('-') {
        let a: Ipv4Addr = a.trim().parse().map_err(|_| format!("Invalid start IP '{a}'"))?;
        let b = b.trim();
        let b: Ipv4Addr = match b.parse::<u8>() {
            Ok(last) => {
                let o = a.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            }
            Err(_) => b.parse().map_err(|_| format!("Invalid end IP '{b}'"))?,
        };
        (u32::from(a), u32::from(b))
    } else {
        let ip: Ipv4Addr = s.parse().map_err(|_| format!("Invalid IP or range '{s}'"))?;
        (u32::from(ip), u32::from(ip))
    };
    if end < start {
        return Err("End address is before start address".into());
    }
    if end - start >= MAX {
        return Err("Range too large (max 65536 addresses)".into());
    }
    Ok((start..=end).map(Ipv4Addr::from).collect())
}

/// Ports probed on every host. Kept short so a /24 finishes quickly.
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445, 515, 548, 554,
    631, 873, 993, 995, 1080, 1433, 1521, 1723, 1883, 1900, 2049, 2375, 3000, 3306, 3389, 5000,
    5060, 5432, 5555, 5900, 6379, 6443, 7000, 7547, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9000, 9090, 9100, 9200, 10000, 27017, 32400, 49152, 62078,
];

pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8888 | 3000 | 5000 | 9000 | 9090 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 | 8443 | 6443 => "https",
        445 => "smb",
        515 => "lpd",
        548 => "afp",
        554 => "rtsp",
        631 => "ipp",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        1900 => "upnp",
        2049 => "nfs",
        2375 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5060 => "sip",
        5432 => "postgres",
        5555 => "adb",
        5900 => "vnc",
        6379 => "redis",
        7000 => "airplay",
        7547 => "tr-069",
        8009 => "chromecast",
        9100 => "jetdirect",
        9200 => "elastic",
        10000 => "webmin",
        27017 => "mongodb",
        32400 => "plex",
        49152 => "upnp",
        62078 => "iphone-sync",
        _ => "",
    }
}

pub fn is_http_port(port: u16) -> bool {
    service_name(port) == "http" || matches!(port, 7000 | 8009 | 32400 | 49152 | 1900 | 631 | 10000 | 9200 | 2375)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("192.168.1.0/24").unwrap().len(), 254);
        assert_eq!(parse_range("10.0.0.5-40").unwrap().len(), 36);
        assert_eq!(parse_range("10.0.0.5 - 10.0.1.4").unwrap().len(), 256);
        assert_eq!(parse_range("10.0.0.9").unwrap().len(), 1);
        assert!(parse_range("10.0.0.0/8").is_err());
        assert!(parse_range("10.0.0.9-3").is_err());
    }
}
