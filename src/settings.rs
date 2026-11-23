//! Small persistent settings file (`<data dir>/settings.json`): online
//! provider URLs and saved Wake-on-LAN devices.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PUBLIC_IP_V4: &str = "https://api.ipify.org?format=json";
pub const DEFAULT_PUBLIC_IP_V6: &str = "https://api6.ipify.org?format=json";
pub const DEFAULT_GEO: &str = "https://ipapi.co/{ip}/json/";
/// Host that accepts TCP on every port (egress firewall test).
pub const DEFAULT_FIREWALL_HOST: &str = "portquiz.net";
pub const DEFAULT_SPEED_URL: &str = "https://speed.cloudflare.com/__down?bytes=200000000";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WolDevice {
    pub name: String,
    pub mac: String,
    /// Broadcast or unicast address the packet is sent to.
    pub target: String,
    pub port: u16,
    /// Address to ping after sending, to confirm the wake-up.
    #[serde(default)]
    pub ip: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub public_ip_v4_url: String,
    pub public_ip_v6_url: String,
    /// `{ip}` is replaced by the address being looked up.
    pub geo_url: String,
    pub wol_devices: Vec<WolDevice>,
    pub firewall_host: String,
    pub speed_url: String,
    /// Authorised DHCP servers for the rogue DHCP tester.
    pub dhcp_servers: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            public_ip_v4_url: DEFAULT_PUBLIC_IP_V4.into(),
            public_ip_v6_url: DEFAULT_PUBLIC_IP_V6.into(),
            geo_url: DEFAULT_GEO.into(),
            wol_devices: Vec::new(),
            firewall_host: DEFAULT_FIREWALL_HOST.into(),
            speed_url: DEFAULT_SPEED_URL.into(),
            dhcp_servers: Vec::new(),
        }
    }
}

fn path() -> Option<PathBuf> {
    crate::platform::data_dir().map(|d| d.join("settings.json"))
}

fn store() -> &'static Mutex<Settings> {
    static S: OnceLock<Mutex<Settings>> = OnceLock::new();
    S.get_or_init(|| {
        let s = path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Mutex::new(s)
    })
}

pub fn get() -> Settings {
    store().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Change and save. Errors writing the file are returned but the new
/// values stay in effect for this session.
pub fn update(f: impl FnOnce(&mut Settings)) -> Result<(), String> {
    let s = {
        let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g);
        g.clone()
    };
    let p = path().ok_or("no data directory")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?;
    std::fs::write(&p, json).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_partial_files() {
        let s: Settings = serde_json::from_str(r#"{"geo_url":"https://x/{ip}"}"#).unwrap();
        assert_eq!(s.geo_url, "https://x/{ip}");
        assert_eq!(s.public_ip_v4_url, DEFAULT_PUBLIC_IP_V4);
        assert!(s.wol_devices.is_empty());
    }
}
