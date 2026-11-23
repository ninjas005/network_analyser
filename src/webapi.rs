//! Opt-in online lookups (public IP, geolocation) through user-configurable
//! provider URLs. Nothing here runs unless the user presses a button.

use std::net::IpAddr;

fn curl(url: &str) -> Result<String, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("provider URL must start with https:// or http://".into());
    }
    let out = crate::platform::command("curl")
        .args(["-sSL", "--max-time", "15", "--retry", "1", "-A"])
        .arg(format!("network-analyser/{}", env!("CARGO_PKG_VERSION")))
        .args(["-w", "\n%{http_code}"])
        .arg(url)
        .output()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("request failed: {}", err.trim()));
    }
    let (body, code) = body.rsplit_once('\n').unwrap_or((&body, "000"));
    match code.parse::<u16>().unwrap_or(0) {
        200..=299 => Ok(body.to_string()),
        429 => Err(
            "provider rate limit reached (HTTP 429), try later or configure another provider"
                .into(),
        ),
        c => Err(format!(
            "provider returned HTTP {c}: {}",
            body.chars().take(200).collect::<String>()
        )),
    }
}

/// Address from a JSON `{"ip": "…"}` (or similar) or a plain-text body.
pub fn public_ip(url: &str) -> Result<IpAddr, String> {
    let body = curl(url)?;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        for key in ["ip", "address", "query", "origin", "ip_addr"] {
            if let Some(ip) = v
                .get(key)
                .and_then(|x| x.as_str())
                .and_then(|s| s.trim().parse().ok())
            {
                return Ok(ip);
            }
        }
    }
    body.trim().parse().map_err(|_| {
        format!(
            "unexpected response: {}",
            body.chars().take(120).collect::<String>()
        )
    })
}

/// Flatten JSON into "a.b" → value rows (arrays as comma lists).
pub fn flatten(v: &serde_json::Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(x, &key, out);
            }
        }
        serde_json::Value::Array(a) if a.iter().all(|x| !x.is_object()) => out.push((
            prefix.to_string(),
            a.iter()
                .map(|x| {
                    x.as_str()
                        .map(String::from)
                        .unwrap_or_else(|| x.to_string())
                })
                .collect::<Vec<_>>()
                .join(", "),
        )),
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                flatten(x, &format!("{prefix}[{i}]"), out);
            }
        }
        serde_json::Value::Null => {}
        serde_json::Value::String(s) => out.push((prefix.to_string(), s.clone())),
        x => out.push((prefix.to_string(), x.to_string())),
    }
}

/// Look up `ip` with a URL template containing `{ip}`.
pub fn geolocate(template: &str, ip: IpAddr) -> Result<Vec<(String, String)>, String> {
    if !template.contains("{ip}") {
        return Err("the geolocation URL must contain {ip}".into());
    }
    let body = curl(&template.replace("{ip}", &ip.to_string()))?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|_| {
        format!(
            "provider did not return JSON: {}",
            body.chars().take(160).collect::<String>()
        )
    })?;
    if v.get("error").and_then(|e| e.as_bool()) == Some(true)
        || v.get("status").and_then(|s| s.as_str()) == Some("fail")
    {
        let reason = ["reason", "message", "msg"]
            .iter()
            .find_map(|k| v.get(*k).and_then(|x| x.as_str()))
            .unwrap_or("lookup failed");
        return Err(format!("provider: {reason}"));
    }
    let mut rows = Vec::new();
    flatten(&v, "", &mut rows);
    Ok(rows)
}

/// What kind of address this is, for display next to a public IP.
pub fn classify(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_private() {
                "private (RFC 1918)"
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                "carrier-grade NAT (RFC 6598)"
            } else if v.is_loopback() {
                "loopback"
            } else if v.is_link_local() {
                "link-local"
            } else {
                "public"
            }
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_loopback() {
                "loopback"
            } else if s[0] & 0xfe00 == 0xfc00 {
                "unique local"
            } else if s[0] & 0xffc0 == 0xfe80 {
                "link-local"
            } else {
                "public"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_json() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"ip":"1.2.3.4","loc":{"city":"X","lat":1.5},"tags":["a","b"],"n":null}"#,
        )
        .unwrap();
        let mut out = Vec::new();
        flatten(&v, "", &mut out);
        assert!(out.contains(&("loc.city".into(), "X".into())));
        assert!(out.contains(&("loc.lat".into(), "1.5".into())));
        assert!(out.contains(&("tags".into(), "a, b".into())));
        assert!(!out.iter().any(|(k, _)| k == "n"));
    }

    #[test]
    fn address_classes() {
        assert_eq!(
            classify("100.70.1.1".parse().unwrap()),
            "carrier-grade NAT (RFC 6598)"
        );
        assert_eq!(
            classify("192.168.1.1".parse().unwrap()),
            "private (RFC 1918)"
        );
        assert_eq!(classify("8.8.8.8".parse().unwrap()), "public");
        assert_eq!(classify("fd00::1".parse().unwrap()), "unique local");
        assert!(geolocate("https://x/json", "8.8.8.8".parse().unwrap()).is_err());
        assert!(public_ip("ftp://x").is_err());
    }
}
