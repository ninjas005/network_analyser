//! Wake-on-LAN magic packets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// 6 × 0xFF, the MAC 16 times, then an optional SecureOn password (4 or 6 bytes).
pub fn magic_packet(mac: [u8; 6], password: &[u8]) -> Vec<u8> {
    let mut p = vec![0xff; 6];
    for _ in 0..16 {
        p.extend_from_slice(&mac);
    }
    p.extend_from_slice(password);
    p
}

/// SecureOn password: empty, "a.b.c.d" (4 bytes) or a MAC-style 6-byte value.
pub fn parse_password(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Ok(ip.octets().to_vec());
    }
    crate::dhcp::parse_mac(s)
        .map(|m| m.to_vec())
        .ok_or_else(|| "SecureOn password must be 6 hex bytes (like a MAC) or a.b.c.d".into())
}

/// Send the packet to `target:port` (broadcast allowed). Returns bytes sent.
pub fn send(mac: [u8; 6], password: &[u8], target: IpAddr, port: u16) -> Result<usize, String> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let s = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    s.set_broadcast(true).map_err(|e| e.to_string())?;
    let p = magic_packet(mac, password);
    // Send a few copies: UDP is lossy and NICs only need one.
    let mut sent = 0;
    for _ in 0..3 {
        sent = s
            .send_to(&p, (target, port))
            .map_err(|e| format!("{target}:{port}: {e}"))?;
    }
    Ok(sent)
}

/// (interface, subnet broadcast address) for each local IPv4 interface.
pub fn broadcast_addresses() -> Vec<(String, Ipv4Addr)> {
    crate::netinfo::local_interfaces()
        .into_iter()
        .map(|i| {
            let mask = if i.prefix == 0 {
                0
            } else {
                u32::MAX << (32 - i.prefix as u32)
            };
            (i.name, Ipv4Addr::from(u32::from(i.ip) | !mask))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_layout() {
        let mac = [1, 2, 3, 4, 5, 6];
        let p = magic_packet(mac, &[]);
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xff; 6]);
        assert_eq!(&p[96..102], &mac);
        assert_eq!(magic_packet(mac, &[9, 9, 9, 9]).len(), 106);
        assert_eq!(parse_password("192.168.0.1").unwrap(), vec![192, 168, 0, 1]);
        assert_eq!(parse_password("").unwrap(), Vec::<u8>::new());
        assert!(parse_password("nope").is_err());
    }

    #[test]
    fn loopback_send() {
        let r = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = r.local_addr().unwrap().port();
        send([0xaa; 6], &[], "127.0.0.1".parse().unwrap(), port).unwrap();
        let mut buf = [0u8; 200];
        let n = r.recv(&mut buf).unwrap();
        assert_eq!(n, 102);
    }
}
