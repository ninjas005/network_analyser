//! Per-interface traffic counters for the bandwidth monitor.

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Counters {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub errors: u64,
    pub drops: u64,
}

pub fn read() -> Vec<Counters> {
    let mut v = if cfg!(target_os = "linux") {
        linux()
    } else if cfg!(target_os = "macos") {
        macos()
    } else {
        windows()
    };
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

fn linux() -> Vec<Counters> {
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let num = |p: String| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    dir.flatten()
        .map(|d| {
            let name = d.file_name().to_string_lossy().into_owned();
            let b = format!("/sys/class/net/{name}/statistics");
            Counters {
                rx_bytes: num(format!("{b}/rx_bytes")),
                tx_bytes: num(format!("{b}/tx_bytes")),
                rx_packets: num(format!("{b}/rx_packets")),
                tx_packets: num(format!("{b}/tx_packets")),
                errors: num(format!("{b}/rx_errors")) + num(format!("{b}/tx_errors")),
                drops: num(format!("{b}/rx_dropped")) + num(format!("{b}/tx_dropped")),
                name,
            }
        })
        .collect()
}

/// `netstat -ibn`: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
pub fn parse_netstat_ib(text: &str) -> Vec<Counters> {
    let mut out: Vec<Counters> = Vec::new();
    for l in text.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        // Link-level rows carry "<Link#n>" in the Network column.
        if f.len() < 10 || !f[2].starts_with("<Link") {
            continue;
        }
        // Rows without an address have one column less.
        let off = if f.len() >= 11 { 0 } else { 1 };
        let n = |i: usize| {
            f.get(i - off)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };
        if out.iter().any(|c| c.name == f[0]) {
            continue;
        }
        out.push(Counters {
            name: f[0].to_string(),
            rx_packets: n(4),
            errors: n(5) + n(8),
            rx_bytes: n(6),
            tx_packets: n(7),
            tx_bytes: n(9),
            drops: 0,
        });
    }
    out
}

fn macos() -> Vec<Counters> {
    crate::platform::command("netstat")
        .args(["-ibn"])
        .output()
        .map(|o| parse_netstat_ib(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

fn windows() -> Vec<Counters> {
    let Ok(o) = crate::platform::command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapterStatistics | ForEach-Object { \"$($_.Name)|$($_.ReceivedBytes)|$($_.SentBytes)|$($_.ReceivedUnicastPackets)|$($_.SentUnicastPackets)|$($_.ReceivedPacketErrors)|$($_.ReceivedDiscardedPackets)\" }",
        ])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.trim().split('|').collect();
            let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            (f.len() >= 7).then(|| Counters {
                name: f[0].to_string(),
                rx_bytes: n(1),
                tx_bytes: n(2),
                rx_packets: n(3),
                tx_packets: n(4),
                errors: n(5),
                drops: n(6),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_netstat() {
        let t = "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\n\
lo0        16384 <Link#1>                         1000     0     50000     1000     0     50000     0\n\
en0        1500  <Link#4>    a4:83:e7:00:11:22  20000     1  30000000    15000     2   2000000     0\n\
en0        1500  192.168.1     192.168.1.20     20000     -  30000000    15000     -   2000000     -\n";
        let c = parse_netstat_ib(t);
        assert_eq!(c.len(), 2);
        let en0 = c.iter().find(|c| c.name == "en0").unwrap();
        assert_eq!(
            (en0.rx_bytes, en0.tx_bytes, en0.errors),
            (30_000_000, 2_000_000, 3)
        );
        let lo = c.iter().find(|c| c.name == "lo0").unwrap();
        assert_eq!(lo.rx_bytes, 50000);
        if cfg!(target_os = "linux") {
            assert!(read().iter().any(|c| c.name == "lo"));
        }
    }
}
