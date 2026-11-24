//! PROFINET: DCP (Identify, Set NameOfStation / IP, Signal, Hello) frames
//! built and parsed by hand, plus passive classification of PN-RT cyclic,
//! alarm and PTCP frames and LLDP neighbours. Frames go out through pcap.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::capture::{self, CaptureConfig, CaptureEvent, CaptureHandle, Source};

pub const ETHERTYPE_PN: u16 = 0x8892;
pub const ETHERTYPE_LLDP: u16 = 0x88cc;
pub const DCP_MULTICAST: [u8; 6] = [0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00];

pub const FID_HELLO: u16 = 0xfefc;
pub const FID_GETSET: u16 = 0xfefd;
pub const FID_IDENT_REQ: u16 = 0xfefe;
pub const FID_IDENT_RESP: u16 = 0xfeff;

pub const SVC_SET: u8 = 4;
pub const SVC_IDENTIFY: u8 = 5;

pub fn mac_str(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What a PROFINET frame ID range is used for.
pub fn classify(fid: u16) -> &'static str {
    match fid {
        0x0000..=0x00ff => "PTCP sync",
        0x0100..=0x7fff => "RT class 3 (IRT)",
        0x8000..=0xbfff => "RT cyclic (class 2)",
        0xc000..=0xfbff => "RT cyclic (class 1)",
        0xfc01 => "Alarm high",
        0xfe01 => "Alarm low",
        FID_HELLO => "DCP Hello",
        FID_GETSET => "DCP Get/Set",
        FID_IDENT_REQ => "DCP Identify request",
        FID_IDENT_RESP => "DCP Identify response",
        0xff00..=0xff43 => "PTCP announce / delay",
        _ => "reserved / other",
    }
}

pub fn is_cyclic(fid: u16) -> bool {
    (0x0100..=0xfbff).contains(&fid)
}

/// Well-known PROFINET vendor IDs (PI organisation numbers).
pub fn vendor_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x002a => "Siemens",
        0x00b0 => "Phoenix Contact",
        0x011d => "WAGO",
        0x011e => "Hilscher",
        0x0120 => "Beckhoff",
        _ => return None,
    })
}

pub fn role_str(r: u8) -> String {
    let mut v = Vec::new();
    if r & 0x01 != 0 {
        v.push("IO-Device");
    }
    if r & 0x02 != 0 {
        v.push("IO-Controller");
    }
    if r & 0x04 != 0 {
        v.push("IO-Multidevice");
    }
    if r & 0x08 != 0 {
        v.push("PN-Supervisor");
    }
    if v.is_empty() {
        format!("{r:#04x}")
    } else {
        v.join(", ")
    }
}

pub fn ip_info_str(info: u16) -> String {
    let base = match info & 0x7f {
        0 => "IP not set",
        1 => "IP set",
        2 => "IP set by DHCP",
        _ => "IP state unknown",
    };
    if info & 0x80 != 0 {
        format!("{base}, ADDRESS CONFLICT")
    } else {
        base.into()
    }
}

pub fn block_name(opt: u8, sub: u8) -> &'static str {
    match (opt, sub) {
        (1, 1) => "MAC address",
        (1, 2) => "IP parameter",
        (1, 3) => "Full IP suite",
        (2, 1) => "Type of station",
        (2, 2) => "Name of station",
        (2, 3) => "Device ID",
        (2, 4) => "Device role",
        (2, 5) => "Device options",
        (2, 6) => "Alias name",
        (2, 7) => "Device instance",
        (2, 8) => "OEM device ID",
        (2, 9) => "Standard gateway",
        (3, _) => "DHCP",
        (5, 1) => "Control: start",
        (5, 2) => "Control: stop",
        (5, 3) => "Control: signal",
        (5, 4) => "Control: response",
        (5, 5) => "Control: factory reset",
        (5, 6) => "Control: reset to factory",
        (6, _) => "Device initiative",
        (0xff, 0xff) => "All selector",
        _ => "unknown",
    }
}

pub fn set_error_str(e: u8) -> &'static str {
    match e {
        0 => "OK",
        1 => "option not supported",
        2 => "suboption not supported or no data set",
        3 => "suboption not set",
        4 => "resource error",
        5 => "set not possible (local reasons)",
        6 => "in operation, set not possible",
        _ => "unknown error",
    }
}

// ---------------------------------------------------------------- frames

fn eth(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ETHERTYPE_PN.to_be_bytes());
    f.extend_from_slice(payload);
    while f.len() < 60 {
        f.push(0);
    }
    f
}

fn dcp_pdu(fid: u16, service: u8, xid: u32, delay: u16, blocks: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&fid.to_be_bytes());
    p.push(service);
    p.push(0); // request
    p.extend_from_slice(&xid.to_be_bytes());
    p.extend_from_slice(&delay.to_be_bytes());
    p.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
    p.extend_from_slice(blocks);
    p
}

fn block(opt: u8, sub: u8, value: &[u8]) -> Vec<u8> {
    let mut b = vec![opt, sub];
    b.extend_from_slice(&(value.len() as u16).to_be_bytes());
    b.extend_from_slice(value);
    if b.len() % 2 == 1 {
        b.push(0);
    }
    b
}

/// Multicast Identify All request.
pub fn identify_all(src: [u8; 6], xid: u32) -> Vec<u8> {
    eth(
        DCP_MULTICAST,
        src,
        &dcp_pdu(
            FID_IDENT_REQ,
            SVC_IDENTIFY,
            xid,
            0x0040,
            &block(0xff, 0xff, &[]),
        ),
    )
}

/// Unicast Set NameOfStation (`permanent` = stored across power cycles).
pub fn set_name(src: [u8; 6], dst: [u8; 6], xid: u32, name: &str, permanent: bool) -> Vec<u8> {
    let mut v = (permanent as u16).to_be_bytes().to_vec();
    v.extend_from_slice(name.as_bytes());
    eth(
        dst,
        src,
        &dcp_pdu(FID_GETSET, SVC_SET, xid, 0, &block(2, 2, &v)),
    )
}

/// Unicast Set IP parameter (address, mask, gateway).
pub fn set_ip(
    src: [u8; 6],
    dst: [u8; 6],
    xid: u32,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gw: Ipv4Addr,
    permanent: bool,
) -> Vec<u8> {
    let mut v = (permanent as u16).to_be_bytes().to_vec();
    v.extend_from_slice(&ip.octets());
    v.extend_from_slice(&mask.octets());
    v.extend_from_slice(&gw.octets());
    eth(
        dst,
        src,
        &dcp_pdu(FID_GETSET, SVC_SET, xid, 0, &block(1, 2, &v)),
    )
}

/// Unicast Signal: flash the device's identification LED.
pub fn signal(src: [u8; 6], dst: [u8; 6], xid: u32) -> Vec<u8> {
    eth(
        dst,
        src,
        &dcp_pdu(
            FID_GETSET,
            SVC_SET,
            xid,
            0,
            &block(5, 3, &[0, 0, 0x01, 0x00]),
        ),
    )
}

/// NameOfStation rules (IEC 61158-6-10): lower-case DNS-like labels of
/// a-z, 0-9 and '-', ≤ 63 chars each, ≤ 240 total, not starting with
/// "port-xyz", not in the form of an IP address.
pub fn validate_name(n: &str) -> Result<(), String> {
    if n.is_empty() || n.len() > 240 {
        return Err("name must be 1–240 characters".into());
    }
    if n.parse::<Ipv4Addr>().is_ok() {
        return Err("name must not look like an IP address".into());
    }
    if n.starts_with("port-")
        && n.len() >= 8
        && n.as_bytes()[5..8].iter().all(|c| c.is_ascii_digit())
    {
        return Err("name must not start with port-xyz".into());
    }
    for l in n.split('.') {
        if l.is_empty() || l.len() > 63 {
            return Err("each label must be 1–63 characters".into());
        }
        if l.starts_with('-') || l.ends_with('-') {
            return Err("labels must not start or end with '-'".into());
        }
        if !l
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err("only a–z, 0–9, '-' and '.' are allowed (lower case)".into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- parsing

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub opt: u8,
    pub sub: u8,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Dcp {
    pub fid: u16,
    pub service: u8,
    /// 0 request, 1 success, 5 not supported
    pub stype: u8,
    pub xid: u32,
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lldp {
    pub chassis: String,
    pub port: String,
    pub ttl: u16,
    pub port_desc: String,
    pub sys_name: String,
    pub sys_desc: String,
    pub mgmt_ip: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    Dcp(Dcp),
    Rt {
        fid: u16,
        cycle: u16,
        data_status: u8,
        transfer: u8,
        len: usize,
    },
    Other(u16),
    Lldp(Lldp),
}

#[derive(Clone, Debug, PartialEq)]
pub struct PnFrame {
    pub src: [u8; 6],
    pub dst: [u8; 6],
    pub vlan: Option<u16>,
    pub body: Body,
}

fn u16be(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

pub fn parse_blocks(mut b: &[u8]) -> Vec<Block> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        let Some(data) = b.get(4..4 + len) else { break };
        out.push(Block {
            opt: b[0],
            sub: b[1],
            data: data.to_vec(),
        });
        let adv = 4 + len + (len & 1);
        b = b.get(adv..).unwrap_or(&[]);
    }
    out
}

pub fn parse_dcp(fid: u16, p: &[u8]) -> Option<Dcp> {
    if p.len() < 10 {
        return None;
    }
    let len = u16be(p, 8)? as usize;
    let blocks = p.get(10..10 + len.min(p.len() - 10))?;
    Some(Dcp {
        fid,
        service: p[0],
        stype: p[1],
        xid: u32::from_be_bytes(p[2..6].try_into().ok()?),
        blocks: parse_blocks(blocks),
    })
}

fn lldp_id(subtype: u8, v: &[u8]) -> String {
    match subtype {
        // MAC address
        3 | 4 if v.len() == 6 => mac_str(&v.try_into().unwrap_or([0; 6])),
        // Network address (IPv4)
        5 if v.len() == 5 && v[0] == 1 => Ipv4Addr::new(v[1], v[2], v[3], v[4]).to_string(),
        _ => String::from_utf8_lossy(v)
            .trim_end_matches('\0')
            .to_string(),
    }
}

pub fn parse_lldp(mut b: &[u8]) -> Lldp {
    let mut l = Lldp::default();
    while b.len() >= 2 {
        let h = u16::from_be_bytes([b[0], b[1]]);
        let (ty, len) = ((h >> 9) as u8, (h & 0x1ff) as usize);
        if ty == 0 {
            break;
        }
        let Some(v) = b.get(2..2 + len) else { break };
        let s = || {
            String::from_utf8_lossy(v)
                .trim_end_matches('\0')
                .to_string()
        };
        match ty {
            1 if !v.is_empty() => l.chassis = lldp_id(v[0], &v[1..]),
            2 if !v.is_empty() => l.port = lldp_id(v[0], &v[1..]),
            3 if v.len() >= 2 => l.ttl = u16::from_be_bytes([v[0], v[1]]),
            4 => l.port_desc = s(),
            5 => l.sys_name = s(),
            6 => l.sys_desc = s(),
            8 if v.len() >= 6 && v[0] == 5 && v[1] == 1 => {
                l.mgmt_ip = Some(Ipv4Addr::new(v[2], v[3], v[4], v[5]))
            }
            _ => {}
        }
        b = &b[2 + len..];
    }
    l
}

/// Parse an Ethernet frame (pcap link type 1) carrying PROFINET or LLDP.
pub fn parse_frame(f: &[u8]) -> Option<PnFrame> {
    if f.len() < 16 {
        return None;
    }
    let dst: [u8; 6] = f[0..6].try_into().ok()?;
    let src: [u8; 6] = f[6..12].try_into().ok()?;
    let mut ty = u16be(f, 12)?;
    let mut off = 14;
    let mut vlan = None;
    if ty == 0x8100 {
        vlan = Some(u16be(f, 14)? & 0x0fff);
        ty = u16be(f, 16)?;
        off = 18;
    }
    let p = f.get(off..)?;
    let body = match ty {
        ETHERTYPE_LLDP => Body::Lldp(parse_lldp(p)),
        ETHERTYPE_PN => {
            let fid = u16be(p, 0)?;
            match fid {
                FID_HELLO | FID_GETSET | FID_IDENT_REQ | FID_IDENT_RESP => {
                    Body::Dcp(parse_dcp(fid, &p[2..])?)
                }
                _ if is_cyclic(fid) && p.len() >= 6 => {
                    // APDU status at the end: cycle counter, data status, transfer status.
                    let n = p.len();
                    Body::Rt {
                        fid,
                        cycle: u16be(p, n - 4)?,
                        data_status: p[n - 2],
                        transfer: p[n - 1],
                        len: n - 6,
                    }
                }
                _ => Body::Other(fid),
            }
        }
        _ => return None,
    };
    Some(PnFrame {
        src,
        dst,
        vlan,
        body,
    })
}

pub fn data_status_str(s: u8) -> String {
    format!(
        "{} · {} · {}",
        if s & 0x10 != 0 { "RUN" } else { "STOP" },
        if s & 0x04 != 0 {
            "data valid"
        } else {
            "data INVALID"
        },
        if s & 0x20 != 0 {
            "no problem"
        } else {
            "station problem"
        }
    )
}

// ---------------------------------------------------------------- devices

#[derive(Clone, Debug, Default)]
pub struct RtStat {
    pub count: u64,
    pub first: f64,
    pub last: f64,
    pub len: usize,
    pub data_status: u8,
    pub dst: [u8; 6],
}

impl RtStat {
    pub fn interval_ms(&self) -> Option<f64> {
        (self.count > 1).then(|| (self.last - self.first) * 1000.0 / (self.count - 1) as f64)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Device {
    pub mac: [u8; 6],
    pub name: String,
    pub alias: String,
    pub station_type: String,
    pub vendor_id: Option<u16>,
    pub device_id: Option<u16>,
    pub oem: Option<(u16, u16)>,
    pub role: Option<u8>,
    pub instance: Option<(u8, u8)>,
    pub ip: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub gw: Option<Ipv4Addr>,
    pub ip_info: Option<u16>,
    pub options: Vec<(u8, u8)>,
    pub dcp: bool,
    pub answered_identify: bool,
    pub hello: bool,
    pub lldp: Option<Lldp>,
    pub rt: BTreeMap<u16, RtStat>,
    pub alarms: u64,
    pub vlan: Option<u16>,
    pub last_seen: f64,
}

impl Device {
    pub fn vendor(&self) -> String {
        match self.vendor_id {
            Some(v) => match vendor_name(v) {
                Some(n) => format!("{n} ({v:#06x})"),
                None => format!("{v:#06x}"),
            },
            None => String::new(),
        }
    }

    pub fn display_name(&self) -> String {
        if !self.name.is_empty() {
            self.name.clone()
        } else if let Some(l) = &self.lldp
            && !l.sys_name.is_empty()
        {
            l.sys_name.clone()
        } else {
            String::new()
        }
    }

    /// Apply the blocks of an Identify / Hello / Get response.
    pub fn apply_blocks(&mut self, blocks: &[Block]) {
        self.dcp = true;
        for b in blocks {
            // Response blocks start with a 2-byte BlockInfo.
            let Some(info) = u16be(&b.data, 0) else {
                continue;
            };
            let v = &b.data[2..];
            let s = || {
                String::from_utf8_lossy(v)
                    .trim_end_matches('\0')
                    .to_string()
            };
            let ip = |i: usize| {
                v.get(i..i + 4)
                    .map(|o| Ipv4Addr::new(o[0], o[1], o[2], o[3]))
            };
            match (b.opt, b.sub) {
                (1, 2) | (1, 3) => {
                    self.ip_info = Some(info);
                    self.ip = ip(0);
                    self.mask = ip(4);
                    self.gw = ip(8);
                }
                (2, 1) => self.station_type = s(),
                (2, 2) => self.name = s(),
                (2, 3) => {
                    self.vendor_id = u16be(v, 0);
                    self.device_id = u16be(v, 2);
                }
                (2, 4) => self.role = v.first().copied(),
                (2, 5) => {
                    self.options = v.as_chunks::<2>().0.iter().map(|c| (c[0], c[1])).collect()
                }
                (2, 6) => self.alias = s(),
                (2, 7) if v.len() >= 2 => self.instance = Some((v[0], v[1])),
                (2, 8) if v.len() >= 4 => {
                    self.oem = Some((u16be(v, 0).unwrap_or(0), u16be(v, 2).unwrap_or(0)))
                }
                _ => {}
            }
        }
    }
}

/// Outcome of a Set / Signal request.
#[derive(Clone, Debug, PartialEq)]
pub struct SetResult {
    pub xid: u32,
    pub from: [u8; 6],
    pub results: Vec<(u8, u8, u8)>,
}

impl SetResult {
    pub fn ok(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.2 == 0)
    }
    pub fn describe(&self) -> String {
        if self.results.is_empty() {
            return "device answered without a result block".into();
        }
        self.results
            .iter()
            .map(|(o, s, e)| format!("{}: {}", block_name(*o, *s), set_error_str(*e)))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

pub fn parse_set_response(d: &Dcp) -> Option<Vec<(u8, u8, u8)>> {
    if d.fid != FID_GETSET || d.service != SVC_SET || d.stype == 0 {
        return None;
    }
    Some(
        d.blocks
            .iter()
            .filter(|b| b.opt == 5 && b.sub == 4 && b.data.len() >= 3)
            .map(|b| (b.data[0], b.data[1], b.data[2]))
            .collect(),
    )
}

#[derive(Default)]
pub struct Devices {
    pub map: BTreeMap<[u8; 6], Device>,
    pub frames: u64,
}

impl Devices {
    /// Fold a parsed frame in; returns a Set response if it is one.
    pub fn apply(&mut self, f: &PnFrame, ts: f64, own: [u8; 6], xids: &[u32]) -> Option<SetResult> {
        self.frames += 1;
        if f.src == own {
            return None;
        }
        let entry = |map: &mut BTreeMap<[u8; 6], Device>| {
            let d = map.entry(f.src).or_insert_with(|| Device {
                mac: f.src,
                ..Default::default()
            });
            d.last_seen = ts;
            if f.vlan.is_some() {
                d.vlan = f.vlan;
            }
        };
        match &f.body {
            Body::Dcp(d) => match d.fid {
                FID_IDENT_RESP | FID_HELLO => {
                    entry(&mut self.map);
                    let dev = self.map.get_mut(&f.src)?;
                    dev.apply_blocks(&d.blocks);
                    dev.hello |= d.fid == FID_HELLO;
                    dev.answered_identify |= d.fid == FID_IDENT_RESP && xids.contains(&d.xid);
                }
                FID_GETSET => {
                    if let Some(results) = parse_set_response(d) {
                        entry(&mut self.map);
                        return Some(SetResult {
                            xid: d.xid,
                            from: f.src,
                            results,
                        });
                    }
                }
                _ => {}
            },
            Body::Rt {
                fid,
                data_status,
                len,
                ..
            } => {
                entry(&mut self.map);
                let dev = self.map.get_mut(&f.src)?;
                let s = dev.rt.entry(*fid).or_default();
                if s.count == 0 {
                    s.first = ts;
                }
                s.count += 1;
                s.last = ts;
                s.len = *len;
                s.data_status = *data_status;
                s.dst = f.dst;
            }
            Body::Other(fid) => {
                if matches!(*fid, 0xfc01 | 0xfe01) {
                    entry(&mut self.map);
                    if let Some(d) = self.map.get_mut(&f.src) {
                        d.alarms += 1;
                    }
                }
            }
            Body::Lldp(l) => {
                entry(&mut self.map);
                let dev = self.map.get_mut(&f.src)?;
                dev.lldp = Some(l.clone());
            }
        }
        None
    }
}

// ---------------------------------------------------------------- session

pub const CAPTURE_FILTER: &str = "ether proto 0x8892 or ether proto 0x88cc or vlan";

/// MAC address of a capture interface.
pub fn iface_mac(iface: &capture::Interface) -> Option<[u8; 6]> {
    let ip = iface
        .addrs
        .iter()
        .find_map(|a| a.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    crate::platform::iface_mac(&iface.name, ip).and_then(|m| crate::dhcp::parse_mac(&m))
}

pub fn new_xid() -> u32 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (t as u32) ^ ((t >> 32) as u32).rotate_left(11) ^ std::process::id()
}

pub fn start_capture(device: &str) -> CaptureHandle {
    capture::start(CaptureConfig {
        source: Source::Live {
            device: device.to_string(),
            // DCP responses are unicast to us; RT traffic between other
            // stations is only visible on a mirror port / hub anyway.
            promisc: true,
        },
        filter: CAPTURE_FILTER.into(),
        save_to: None,
    })
}

// ---------------------------------------------------------------- CLI

/// `--profinet IFACE [--wait SECONDS]`: Identify All and list devices.
pub fn cli(args: &[String]) {
    let usage = "usage: --profinet IFACE [--wait SECONDS]   (see --list-ifaces)";
    let Some(name) = args.first() else {
        eprintln!("{usage}");
        std::process::exit(2)
    };
    let wait: u64 = args
        .iter()
        .position(|a| a == "--wait")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let iface = match capture::interfaces() {
        Ok(l) => l.into_iter().find(|i| &i.name == name || &i.desc == name),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    };
    let Some(iface) = iface else {
        eprintln!("no capture interface named '{name}' (see --list-ifaces)");
        std::process::exit(2)
    };
    let Some(mac) = iface_mac(&iface) else {
        eprintln!("could not read the MAC address of {name}");
        std::process::exit(1)
    };
    let cap = start_capture(&iface.name);
    let xid = new_xid();
    let mut devs = Devices::default();
    let mut sent_at: Option<Instant> = None;
    loop {
        while let Ok(ev) = cap.events.try_recv() {
            match ev {
                CaptureEvent::Started { .. } => {
                    cap.inject(identify_all(mac, xid));
                    sent_at = Some(Instant::now());
                    eprintln!("Identify All sent on {} from {}", iface.name, mac_str(&mac));
                }
                CaptureEvent::Packets(ps) => {
                    for p in ps {
                        if let Some(f) = parse_frame(&p.data) {
                            devs.apply(&f, p.ts, mac, &[xid]);
                        }
                    }
                }
                CaptureEvent::InjectFailed(e) => {
                    eprintln!("could not send: {e}");
                    std::process::exit(1)
                }
                CaptureEvent::Stopped(Some(e)) => {
                    eprintln!("{e}");
                    if let Some(h) = capture::permission_hint(&e) {
                        eprintln!("{h}");
                    }
                    std::process::exit(1)
                }
                CaptureEvent::Stopped(None) => break,
                CaptureEvent::Stats { .. } | CaptureEvent::FileInfo(_) => {}
            }
        }
        if sent_at.is_some_and(|t| t.elapsed() >= Duration::from_secs(wait)) {
            cap.stop();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let list: Vec<&Device> = devs.map.values().filter(|d| d.dcp).collect();
    println!(
        "{:<17}  {:<28} {:<15} {:<24} {:<14} ROLE",
        "MAC", "NAME OF STATION", "IP", "TYPE", "VENDOR/DEV"
    );
    for d in &list {
        println!(
            "{:<17}  {:<28} {:<15} {:<24} {:<14} {}",
            mac_str(&d.mac),
            d.name,
            d.ip.map(|i| i.to_string()).unwrap_or_default(),
            d.station_type,
            match (d.vendor_id, d.device_id) {
                (Some(v), Some(i)) => format!("{v:04X}/{i:04X}"),
                _ => String::new(),
            },
            d.role.map(role_str).unwrap_or_default()
        );
    }
    eprintln!("{} PROFINET device(s) answered", list.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const DEV: [u8; 6] = [0x00, 0x1b, 0x1b, 0x11, 0x22, 0x33];

    #[test]
    fn identify_all_frame() {
        let f = identify_all(ME, 0x01020304);
        assert_eq!(f.len(), 60);
        assert_eq!(&f[0..6], &DCP_MULTICAST);
        assert_eq!(&f[12..14], &[0x88, 0x92]);
        // FrameID FEFE, Identify, request, xid, delay, length 4, FF FF 00 00
        assert_eq!(
            &f[14..32],
            &[
                0xfe, 0xfe, 5, 0, 1, 2, 3, 4, 0x00, 0x40, 0, 4, 0xff, 0xff, 0, 0, 0, 0
            ][..18]
        );
    }

    #[test]
    fn set_frames() {
        let f = set_name(ME, DEV, 7, "plc1", true);
        // FEFD, Set, req, xid 7, reserved, len 10, block 02 02 0006 0001 "plc1"
        assert_eq!(
            &f[14..38],
            &[
                0xfe, 0xfd, 4, 0, 0, 0, 0, 7, 0, 0, 0, 10, 2, 2, 0, 6, 0, 1, b'p', b'l', b'c',
                b'1', 0, 0
            ]
        );
        // Temporary name.
        let f = set_name(ME, DEV, 7, "io", false);
        assert_eq!(&f[24..26], &[0, 8]);
        assert_eq!(&f[26..34], &[2, 2, 0, 4, 0, 0, b'i', b'o']);
        let f = set_ip(
            ME,
            DEV,
            9,
            Ipv4Addr::new(192, 168, 0, 10),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 0, 1),
            false,
        );
        assert_eq!(
            &f[24..44],
            &[
                0, 18, 1, 2, 0, 14, 0, 0, 192, 168, 0, 10, 255, 255, 255, 0, 192, 168, 0, 1
            ]
        );
        let f = signal(ME, DEV, 1);
        assert_eq!(&f[24..34], &[0, 8, 5, 3, 0, 4, 0, 0, 1, 0]);
    }

    fn ident_response() -> Vec<u8> {
        let mut blocks = Vec::new();
        blocks.extend(block(2, 2, &[0, 0, b'p', b'n', b'-', b'i', b'o']));
        blocks.extend(block(2, 1, b"\x00\x00ET 200SP"));
        blocks.extend(block(2, 3, &[0, 0, 0x00, 0x2a, 0x03, 0x13]));
        blocks.extend(block(2, 4, &[0, 0, 0x01, 0]));
        blocks.extend(block(
            1,
            2,
            &[0, 1, 192, 168, 0, 20, 255, 255, 255, 0, 192, 168, 0, 1],
        ));
        let mut p = vec![0xfe, 0xff, 5, 1, 0xde, 0xad, 0xbe, 0xef, 0, 0];
        p.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
        p.extend(blocks);
        let mut f = ME.to_vec();
        f.extend_from_slice(&DEV);
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x00, 0x88, 0x92]);
        f.extend(p);
        f
    }

    #[test]
    fn parse_identify_response() {
        let f = parse_frame(&ident_response()).unwrap();
        assert_eq!(f.src, DEV);
        assert_eq!(f.vlan, Some(0));
        let mut devs = Devices::default();
        devs.apply(&f, 1.0, ME, &[0xdeadbeef]);
        let d = &devs.map[&DEV];
        assert_eq!(d.name, "pn-io");
        assert_eq!(d.station_type, "ET 200SP");
        assert_eq!((d.vendor_id, d.device_id), (Some(0x2a), Some(0x0313)));
        assert_eq!(d.vendor(), "Siemens (0x002a)");
        assert_eq!(d.role.map(role_str).as_deref(), Some("IO-Device"));
        assert_eq!(d.ip, Some(Ipv4Addr::new(192, 168, 0, 20)));
        assert_eq!(d.gw, Some(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(d.ip_info.map(ip_info_str).as_deref(), Some("IP set"));
        assert!(d.answered_identify);
    }

    #[test]
    fn set_response_and_rt() {
        let mut p = vec![0xfe, 0xfd, 4, 1, 0, 0, 0, 7, 0, 0, 0, 8];
        p.extend(block(5, 4, &[2, 2, 0]));
        let mut f = ME.to_vec();
        f.extend_from_slice(&DEV);
        f.extend_from_slice(&[0x88, 0x92]);
        f.extend(p);
        let pf = parse_frame(&f).unwrap();
        let r = Devices::default().apply(&pf, 0.0, ME, &[]).unwrap();
        assert!(r.ok());
        assert_eq!(r.describe(), "Name of station: OK");

        // Cyclic RT frame 0x8001, 40-byte C_SDU + status.
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&DEV);
        f.extend_from_slice(&[0x88, 0x92, 0x80, 0x01]);
        f.extend(vec![0u8; 40]);
        f.extend_from_slice(&[0x12, 0x34, 0x35, 0x00]);
        let pf = parse_frame(&f).unwrap();
        assert_eq!(
            pf.body,
            Body::Rt {
                fid: 0x8001,
                cycle: 0x1234,
                data_status: 0x35,
                transfer: 0,
                len: 40
            }
        );
        assert_eq!(data_status_str(0x35), "RUN · data valid · no problem");
        let mut devs = Devices::default();
        devs.apply(&pf, 1.0, ME, &[]);
        devs.apply(&pf, 1.004, ME, &[]);
        let s = &devs.map[&DEV].rt[&0x8001];
        assert!((s.interval_ms().unwrap() - 4.0).abs() < 0.01);
    }

    #[test]
    fn lldp() {
        let mut t = Vec::new();
        let tlv = |t: &mut Vec<u8>, ty: u16, v: &[u8]| {
            t.extend_from_slice(&((ty << 9) | v.len() as u16).to_be_bytes());
            t.extend_from_slice(v);
        };
        tlv(&mut t, 1, &[4, 0, 0x1b, 0x1b, 1, 2, 3]);
        tlv(&mut t, 2, b"\x07port-001.pn-io");
        tlv(&mut t, 3, &[0, 20]);
        tlv(&mut t, 5, b"pn-io");
        tlv(&mut t, 8, &[5, 1, 10, 0, 0, 5, 2, 0, 0, 0, 1, 0]);
        tlv(&mut t, 0, &[]);
        let l = parse_lldp(&t);
        assert_eq!(l.chassis, "00:1B:1B:01:02:03");
        assert_eq!(l.port, "port-001.pn-io");
        assert_eq!(l.ttl, 20);
        assert_eq!(l.sys_name, "pn-io");
        assert_eq!(l.mgmt_ip, Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn names() {
        assert!(validate_name("plc-1.line2").is_ok());
        assert!(validate_name("PLC").is_err());
        assert!(validate_name("port-123").is_err());
        assert!(validate_name("port-ab").is_ok());
        assert!(validate_name("10.0.0.1").is_err());
        assert!(validate_name("-x").is_err());
        assert!(validate_name("a..b").is_err());
    }
}
