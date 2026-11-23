//! Open-port audit rules and baselines.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

pub struct Rule {
    pub port: u16,
    pub service: &'static str,
    pub severity: Severity,
    pub risk: &'static str,
    pub advice: &'static str,
}

const fn r(
    port: u16,
    service: &'static str,
    severity: Severity,
    risk: &'static str,
    advice: &'static str,
) -> Rule {
    Rule {
        port,
        service,
        severity,
        risk,
        advice,
    }
}

use Severity::*;

pub const RULES: &[Rule] = &[
    r(
        21,
        "FTP",
        Medium,
        "Credentials and files travel in clear text",
        "Use SFTP or FTPS; disable anonymous login",
    ),
    r(
        23,
        "Telnet",
        Critical,
        "Clear-text remote shell; passwords visible on the wire",
        "Disable Telnet, use SSH",
    ),
    r(
        25,
        "SMTP",
        Low,
        "Mail server reachable; check it is not an open relay",
        "Require authentication for relaying, enable STARTTLS",
    ),
    r(
        69,
        "TFTP",
        High,
        "Unauthenticated file transfer",
        "Disable or restrict to provisioning VLANs",
    ),
    r(
        80,
        "HTTP",
        Low,
        "Unencrypted web traffic",
        "Redirect to HTTPS",
    ),
    r(
        102,
        "Siemens S7",
        High,
        "PLC programming protocol without authentication",
        "Isolate in an OT zone behind a firewall",
    ),
    r(
        110,
        "POP3",
        Medium,
        "Mail passwords in clear text",
        "Use POP3S (995) or STARTTLS",
    ),
    r(
        111,
        "rpcbind",
        Medium,
        "Exposes RPC service map (NFS etc.)",
        "Block outside trusted hosts",
    ),
    r(
        135,
        "MS-RPC",
        Medium,
        "Windows RPC endpoint mapper; common attack surface",
        "Block at the network edge",
    ),
    r(
        139,
        "NetBIOS-SSN",
        High,
        "Legacy SMB over NetBIOS",
        "Disable NetBIOS over TCP/IP where possible",
    ),
    r(
        143,
        "IMAP",
        Medium,
        "Mail passwords in clear text",
        "Use IMAPS (993) or STARTTLS",
    ),
    r(
        389,
        "LDAP",
        Medium,
        "Directory queries / binds in clear text",
        "Use LDAPS (636) or StartTLS; disable anonymous bind",
    ),
    r(
        445,
        "SMB",
        High,
        "File sharing; frequent target for worms and ransomware",
        "Never expose beyond the LAN; disable SMBv1",
    ),
    r(
        502,
        "Modbus/TCP",
        High,
        "Industrial control with no authentication: anyone can read and write registers",
        "Restrict to engineering hosts / OT firewall",
    ),
    r(
        512,
        "rexec",
        Critical,
        "Legacy unauthenticated remote execution",
        "Disable",
    ),
    r(
        513,
        "rlogin",
        Critical,
        "Legacy trust-based remote login",
        "Disable",
    ),
    r(
        514,
        "rsh",
        Critical,
        "Legacy trust-based remote shell",
        "Disable",
    ),
    r(
        873,
        "rsync",
        Medium,
        "Modules may be readable without a password",
        "Require auth or bind to localhost",
    ),
    r(
        1433,
        "MS SQL",
        High,
        "Database exposed to the network",
        "Firewall to application servers only",
    ),
    r(
        1521,
        "Oracle DB",
        High,
        "Database exposed to the network",
        "Firewall to application servers only",
    ),
    r(
        1883,
        "MQTT",
        Medium,
        "Clear-text IoT messaging; often allows anonymous clients",
        "Use MQTTS (8883) and require credentials",
    ),
    r(
        1900,
        "UPnP",
        Medium,
        "Device control / port-mapping interface",
        "Disable UPnP on gateways",
    ),
    r(
        2049,
        "NFS",
        High,
        "File systems exported to the network",
        "Restrict exports by host; use Kerberos",
    ),
    r(
        2375,
        "Docker API",
        Critical,
        "Unauthenticated Docker daemon = root on the host",
        "Bind to localhost or use TLS (2376)",
    ),
    r(
        2404,
        "IEC 60870-5-104",
        High,
        "Telecontrol protocol without authentication",
        "Isolate in an OT zone",
    ),
    r(
        3306,
        "MySQL",
        High,
        "Database exposed to the network",
        "Firewall to application servers only",
    ),
    r(
        3389,
        "RDP",
        High,
        "Remote desktop; brute-force and exploit target",
        "Use a VPN / RD Gateway, enable NLA",
    ),
    r(
        4840,
        "OPC UA",
        Medium,
        "Industrial data access; check security mode is not None",
        "Require Sign/SignAndEncrypt and user auth",
    ),
    r(
        5432,
        "PostgreSQL",
        High,
        "Database exposed to the network",
        "Firewall to application servers only",
    ),
    r(
        5555,
        "Android ADB",
        Critical,
        "Unauthenticated debug shell on Android devices",
        "Disable network ADB",
    ),
    r(
        5800,
        "VNC (HTTP)",
        High,
        "Remote desktop",
        "Use a VPN; require strong passwords",
    ),
    r(
        5900,
        "VNC",
        High,
        "Remote desktop, often weakly protected",
        "Use a VPN; require strong passwords",
    ),
    r(
        5985,
        "WinRM (HTTP)",
        Medium,
        "Windows remote management",
        "Restrict to admin hosts; prefer HTTPS (5986)",
    ),
    r(
        6379,
        "Redis",
        High,
        "Often runs without authentication",
        "Bind to localhost, set requirepass / ACLs",
    ),
    r(
        7547,
        "TR-069",
        High,
        "ISP router management; historically exploited",
        "Restrict to the ISP's ACS",
    ),
    r(
        8080,
        "HTTP-alt",
        Low,
        "Admin panels / proxies often listen here",
        "Check what runs here; require auth",
    ),
    r(
        8291,
        "MikroTik Winbox",
        High,
        "Router management",
        "Restrict to management network",
    ),
    r(
        8883,
        "MQTTS",
        Info,
        "Encrypted MQTT",
        "Ensure client authentication",
    ),
    r(
        9100,
        "JetDirect",
        Low,
        "Raw printing; printers accept any job",
        "Restrict to print servers",
    ),
    r(
        9200,
        "Elasticsearch",
        High,
        "Search cluster, often without authentication",
        "Enable security, firewall the port",
    ),
    r(
        10000,
        "Webmin",
        Medium,
        "Web administration",
        "Restrict to admin hosts",
    ),
    r(
        11211,
        "memcached",
        High,
        "No authentication; DDoS amplification",
        "Bind to localhost",
    ),
    r(
        20000,
        "DNP3",
        High,
        "Utility SCADA protocol without authentication",
        "Isolate in an OT zone",
    ),
    r(
        27017,
        "MongoDB",
        High,
        "Database often without authentication",
        "Enable auth, bind to private interfaces",
    ),
    r(
        44818,
        "EtherNet/IP",
        High,
        "Industrial control (CIP) without authentication",
        "Isolate in an OT zone",
    ),
    r(
        47808,
        "BACnet",
        Medium,
        "Building automation",
        "Isolate building-control networks",
    ),
    r(
        1911,
        "Niagara Fox",
        High,
        "Building automation management",
        "Restrict to management network",
    ),
];

pub fn rule(port: u16) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.port == port)
}

/// Ports checked by the audit: every rule plus the common top ports.
pub fn ports() -> Vec<u16> {
    let mut v: BTreeSet<u16> = RULES.iter().map(|r| r.port).collect();
    v.extend(crate::portscan::TOP_PORTS);
    v.into_iter().collect()
}

/// target -> open ports, saved in the data directory.
pub type Baseline = BTreeMap<String, BTreeSet<u16>>;

fn baseline_path() -> Option<std::path::PathBuf> {
    crate::platform::data_dir().map(|d| d.join("audit-baseline.json"))
}

pub fn load_baseline() -> Baseline {
    baseline_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_baseline(b: &Baseline) -> Result<std::path::PathBuf, String> {
    let p = baseline_path().ok_or("no data directory")?;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        &p,
        serde_json::to_string_pretty(b).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(p)
}

/// (newly opened, closed since) relative to the baseline.
pub fn diff(baseline: &BTreeSet<u16>, now: &BTreeSet<u16>) -> (Vec<u16>, Vec<u16>) {
    (
        now.difference(baseline).copied().collect(),
        baseline.difference(now).copied().collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_are_unique_and_scanned() {
        let mut seen = BTreeSet::new();
        for r in RULES {
            assert!(seen.insert(r.port), "duplicate rule for {}", r.port);
        }
        let p = ports();
        assert!(p.contains(&2375) && p.contains(&502) && p.contains(&443));
        assert_eq!(rule(23).unwrap().severity, Severity::Critical);
        let (new, gone) = diff(&[22, 80].into(), &[22, 443].into());
        assert_eq!((new, gone), (vec![443], vec![80]));
    }
}
