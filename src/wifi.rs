//! Wi-Fi scanning (nmcli / system_profiler / netsh) and channel analysis.

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Network {
    pub ssid: String,
    pub bssid: Option<String>,
    pub channel: u32,
    pub freq_mhz: Option<u32>,
    /// 0-100
    pub signal: Option<u8>,
    pub dbm: Option<i32>,
    pub security: String,
    pub rate: Option<String>,
    pub in_use: bool,
}

pub fn band(channel: u32, freq: Option<u32>) -> &'static str {
    match freq {
        Some(f) if f >= 5925 => "6 GHz",
        Some(f) if f >= 4900 => "5 GHz",
        Some(_) => "2.4 GHz",
        None if channel <= 14 => "2.4 GHz",
        None => "5 GHz",
    }
}

/// nmcli -t splits on ':' with '\:' escapes.
fn split_terse(l: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut esc = false;
    for c in l.chars() {
        if esc {
            out.last_mut().unwrap().push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == ':' {
            out.push(String::new());
        } else {
            out.last_mut().unwrap().push(c);
        }
    }
    out
}

pub fn parse_nmcli(text: &str) -> Vec<Network> {
    text.lines()
        .filter_map(|l| {
            let f = split_terse(l);
            if f.len() < 8 {
                return None;
            }
            Some(Network {
                in_use: f[0] == "*",
                bssid: Some(f[1].clone()).filter(|b| !b.is_empty()),
                ssid: f[2].clone(),
                channel: f[3].parse().unwrap_or(0),
                freq_mhz: f[4].split_whitespace().next().and_then(|v| v.parse().ok()),
                rate: Some(f[5].clone()).filter(|r| !r.is_empty()),
                signal: f[6].parse().ok(),
                dbm: None,
                security: if f[7].is_empty() {
                    "Open".into()
                } else {
                    f[7].clone()
                },
            })
        })
        .collect()
}

/// `netsh wlan show networks mode=bssid` — labels are localized, so values
/// are recognised by shape.
pub fn parse_netsh(text: &str) -> Vec<Network> {
    let mut out = Vec::new();
    let mut ssid = String::new();
    let mut security = String::new();
    let mut cur: Option<Network> = None;
    for l in text.lines() {
        let t = l.trim();
        let Some((k, v)) = t.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if k.starts_with("SSID") {
            if let Some(n) = cur.take() {
                out.push(n);
            }
            ssid = v.to_string();
            security.clear();
        } else if k.starts_with("BSSID") {
            if let Some(n) = cur.take() {
                out.push(n);
            }
            cur = Some(Network {
                ssid: ssid.clone(),
                bssid: Some(
                    t.split_once(':')
                        .map(|x| x.1.trim().to_string())
                        .unwrap_or_default(),
                ),
                security: security.clone(),
                ..Default::default()
            });
        } else if security.is_empty()
            && (v.contains("WPA")
                || v == "Open"
                || v.contains("WEP")
                || v.contains("Ouvert")
                || v.contains("Offen"))
        {
            security = v.to_string();
        } else if let Some(n) = cur.as_mut() {
            if let Some(p) = v
                .strip_suffix('%')
                .and_then(|p| p.trim().parse::<u8>().ok())
            {
                n.signal = Some(p);
            } else if let Ok(ch) = v.parse::<u32>()
                && (1..=233).contains(&ch)
                && n.channel == 0
            {
                n.channel = ch;
            } else if (v.ends_with("GHz") || v.contains("GHz")) && n.freq_mhz.is_none() {
                n.freq_mhz = if v.starts_with('5') {
                    Some(5000)
                } else if v.starts_with('6') {
                    Some(6000)
                } else {
                    Some(2400)
                };
            }
        }
    }
    if let Some(n) = cur {
        out.push(n);
    }
    out
}

fn macos() -> Result<Vec<Network>, String> {
    let o = crate::platform::command("system_profiler")
        .args(["SPAirPortDataType", "-json"])
        .output()
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let ifaces = v["SPAirPortDataType"][0]["spairport_airport_interfaces"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let net = |n: &serde_json::Value, in_use: bool| {
        let ch = n["spairport_network_channel"]
            .as_str()
            .map(String::from)
            .or_else(|| {
                n["spairport_network_channel"]
                    .as_u64()
                    .map(|c| c.to_string())
            })
            .unwrap_or_default();
        let channel: u32 = ch
            .split_whitespace()
            .next()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let dbm = n["spairport_signal_noise"]
            .as_str()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<i32>().ok());
        Network {
            ssid: n["_name"].as_str().unwrap_or("").to_string(),
            bssid: None,
            channel,
            freq_mhz: if ch.contains("6GHz") {
                Some(6000)
            } else if ch.contains("5GHz") {
                Some(5000)
            } else if ch.contains("2GHz") {
                Some(2400)
            } else {
                None
            },
            signal: dbm.map(dbm_to_pct),
            dbm,
            security: n["spairport_security_mode"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("spairport_security_mode_")
                .replace('_', " "),
            rate: n["spairport_network_rate"]
                .as_u64()
                .map(|r| format!("{r} Mbit/s")),
            in_use,
        }
    };
    for i in ifaces {
        if i["spairport_current_network_information"].is_object() {
            out.push(net(&i["spairport_current_network_information"], true));
        }
        for n in i["spairport_airport_other_local_wireless_networks"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            out.push(net(&n, false));
        }
    }
    Ok(out)
}

pub fn dbm_to_pct(dbm: i32) -> u8 {
    (2 * (dbm + 100)).clamp(0, 100) as u8
}

pub fn scan(rescan: bool) -> Result<Vec<Network>, String> {
    if cfg!(target_os = "linux") {
        if rescan {
            let _ = crate::platform::command("nmcli")
                .args(["dev", "wifi", "rescan"])
                .output();
        }
        let o = crate::platform::command("nmcli")
            .args([
                "-t",
                "-e",
                "yes",
                "-f",
                "IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                "dev",
                "wifi",
                "list",
            ])
            .output()
            .map_err(|_| {
                "nmcli (NetworkManager) is required for Wi-Fi scanning on Linux".to_string()
            })?;
        if !o.status.success() {
            return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
        }
        Ok(parse_nmcli(&String::from_utf8_lossy(&o.stdout)))
    } else if cfg!(target_os = "macos") {
        macos()
    } else {
        let o = crate::platform::command("netsh")
            .args(["wlan", "show", "networks", "mode=bssid"])
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        if text.to_lowercase().contains("location") && text.to_lowercase().contains("permission") {
            return Err("Windows requires Location access for Wi-Fi scanning (Settings → Privacy → Location)".into());
        }
        Ok(parse_netsh(&text))
    }
}

/// Congestion score per channel: sum of signal of networks that overlap it
/// (2.4 GHz channels overlap ±4).
pub fn congestion(nets: &[Network], channel: u32) -> u32 {
    nets.iter()
        .filter(|n| {
            if channel <= 14 && n.channel <= 14 {
                n.channel.abs_diff(channel) <= 4
            } else {
                n.channel == channel
            }
        })
        .map(|n| n.signal.unwrap_or(50) as u32)
        .sum()
}

/// Best of 1/6/11 on 2.4 GHz and the least used common 5 GHz channel.
pub fn recommend(nets: &[Network]) -> (u32, u32) {
    let best24 = [1, 6, 11]
        .into_iter()
        .min_by_key(|c| congestion(nets, *c))
        .unwrap_or(1);
    let best5 = [36, 40, 44, 48, 149, 153, 157, 161]
        .into_iter()
        .min_by_key(|c| congestion(nets, *c))
        .unwrap_or(36);
    (best24, best5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmcli_and_channels() {
        let t = "*:AA\\:BB\\:CC\\:DD\\:EE\\:01:Home:6:2437 MHz:270 Mbit/s:78:WPA2\n:AA\\:BB\\:CC\\:DD\\:EE\\:02:Cafe\\:Guest:44:5220 MHz:540 Mbit/s:40:\n";
        let n = parse_nmcli(t);
        assert_eq!(n.len(), 2);
        assert!(n[0].in_use);
        assert_eq!(n[0].bssid.as_deref(), Some("AA:BB:CC:DD:EE:01"));
        assert_eq!(n[1].ssid, "Cafe:Guest");
        assert_eq!(n[1].security, "Open");
        assert_eq!(band(n[1].channel, n[1].freq_mhz), "5 GHz");
        let (c24, c5) = recommend(&n);
        assert_ne!(c24, 6); // 6 is busy; 1 and 11 are free (5 channels away)
        assert_ne!(c5, 44);
        assert_eq!(dbm_to_pct(-50), 100);
    }

    #[test]
    fn netsh_parsing() {
        let t = "SSID 1 : Office\n    Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n    Encryption              : CCMP\n    BSSID 1                 : 11:22:33:44:55:66\n         Signal             : 80%\n         Radio type         : 802.11ac\n         Band               : 5 GHz\n         Channel            : 36\n";
        let n = parse_netsh(t);
        assert_eq!(n.len(), 1);
        assert_eq!(
            (n[0].signal, n[0].channel, n[0].security.as_str()),
            (Some(80), 36, "WPA2-Personal")
        );
        assert_eq!(n[0].bssid.as_deref(), Some("11:22:33:44:55:66"));
    }
}
