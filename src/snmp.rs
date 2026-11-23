//! SNMP v1 / v2c client with a hand-rolled BER codec: Get, GetNext,
//! GetBulk, Walk and Set; system-group and interface-table summaries;
//! community-string checks; an SNMPv3 engine-discovery probe; and a
//! subnet sweep for agents.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::gateway::{Finding, Level};

pub type Oid = Vec<u32>;

// ---------------------------------------------------------------- values

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Int(i64),
    Str(Vec<u8>),
    Null,
    Oid(Oid),
    Ip([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    Other(u8, Vec<u8>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Int(_) => "INTEGER",
            Value::Str(_) => "OCTET STRING",
            Value::Null => "NULL",
            Value::Oid(_) => "OID",
            Value::Ip(_) => "IpAddress",
            Value::Counter32(_) => "Counter32",
            Value::Gauge32(_) => "Gauge32",
            Value::TimeTicks(_) => "TimeTicks",
            Value::Opaque(_) => "Opaque",
            Value::Counter64(_) => "Counter64",
            Value::NoSuchObject => "noSuchObject",
            Value::NoSuchInstance => "noSuchInstance",
            Value::EndOfMibView => "endOfMibView",
            Value::Other(..) => "unknown",
        }
    }

    /// True for a real value (not an exception / NULL).
    pub fn is_value(&self) -> bool {
        !matches!(
            self,
            Value::Null | Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView
        )
    }

    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::Int(i) if i >= 0 => Some(i as u64),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => Some(v as u64),
            Value::Counter64(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_text(&self) -> String {
        match self {
            Value::Str(b) => bytes_text(b),
            other => other.to_string(),
        }
    }
}

/// Printable text when the bytes look like text, else colon-separated hex.
pub fn bytes_text(b: &[u8]) -> String {
    let trimmed = b.strip_suffix(&[0]).unwrap_or(b);
    match std::str::from_utf8(trimmed) {
        Ok(s)
            if s.chars()
                .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') =>
        {
            s.to_string()
        }
        _ => hex(b, ":"),
    }
}

pub fn hex(b: &[u8], sep: &str) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(sep)
}

pub fn ticks(t: u32) -> String {
    let s = t / 100;
    let (d, h, m, sec) = (s / 86400, s / 3600 % 24, s / 60 % 60, s % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m {sec}s")
    } else {
        format!("{h}h {m}m {sec}s")
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{i}"),
            Value::Str(b) => write!(f, "{}", bytes_text(b)),
            Value::Null => write!(f, "NULL"),
            Value::Oid(o) => write!(f, "{}", oid_name(o)),
            Value::Ip(a) => write!(f, "{}", Ipv4Addr::from(*a)),
            Value::Counter32(v) | Value::Gauge32(v) => write!(f, "{v}"),
            Value::TimeTicks(t) => write!(f, "{} ({t})", ticks(*t)),
            Value::Opaque(b) => write!(f, "{}", hex(b, " ")),
            Value::Counter64(v) => write!(f, "{v}"),
            Value::NoSuchObject => write!(f, "No such object"),
            Value::NoSuchInstance => write!(f, "No such instance"),
            Value::EndOfMibView => write!(f, "End of MIB view"),
            Value::Other(t, b) => write!(f, "[tag {t:#04x}] {}", hex(b, " ")),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VarBind {
    pub oid: Oid,
    pub value: Value,
}

// ---------------------------------------------------------------- BER encode

const T_INT: u8 = 0x02;
const T_OCTETS: u8 = 0x04;
const T_NULL: u8 = 0x05;
const T_OID: u8 = 0x06;
const T_SEQ: u8 = 0x30;

pub const PDU_GET: u8 = 0xa0;
pub const PDU_GETNEXT: u8 = 0xa1;
pub const PDU_RESPONSE: u8 = 0xa2;
pub const PDU_SET: u8 = 0xa3;
pub const PDU_GETBULK: u8 = 0xa5;
pub const PDU_REPORT: u8 = 0xa8;

fn push_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = (n as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(tag);
    push_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn int_body(v: i64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    b[i..].to_vec()
}

fn uint_body(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let skip = b.iter().take_while(|x| **x == 0).count().min(7);
    let mut out = Vec::new();
    if b[skip] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&b[skip..]);
    out
}

fn enc_int(v: i64) -> Vec<u8> {
    tlv(T_INT, &int_body(v))
}

fn enc_octets(b: &[u8]) -> Vec<u8> {
    tlv(T_OCTETS, b)
}

pub fn enc_oid(oid: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    let (a, b) = (
        oid.first().copied().unwrap_or(0),
        oid.get(1).copied().unwrap_or(0),
    );
    let mut sub = |mut v: u32| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        body.extend(tmp);
    };
    sub(a * 40 + b);
    for &v in oid.iter().skip(2) {
        sub(v);
    }
    tlv(T_OID, &body)
}

pub fn enc_value(v: &Value) -> Vec<u8> {
    match v {
        Value::Int(i) => enc_int(*i),
        Value::Str(b) => enc_octets(b),
        Value::Null => tlv(T_NULL, &[]),
        Value::Oid(o) => enc_oid(o),
        Value::Ip(a) => tlv(0x40, a),
        Value::Counter32(x) => tlv(0x41, &uint_body(*x as u64)),
        Value::Gauge32(x) => tlv(0x42, &uint_body(*x as u64)),
        Value::TimeTicks(x) => tlv(0x43, &uint_body(*x as u64)),
        Value::Opaque(b) => tlv(0x44, b),
        Value::Counter64(x) => tlv(0x46, &uint_body(*x)),
        Value::NoSuchObject => tlv(0x80, &[]),
        Value::NoSuchInstance => tlv(0x81, &[]),
        Value::EndOfMibView => tlv(0x82, &[]),
        Value::Other(t, b) => tlv(*t, b),
    }
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(T_SEQ, &parts.concat())
}

/// PDU body; for GetBulk `a`/`b` are non-repeaters / max-repetitions,
/// otherwise error-status / error-index (0).
fn enc_pdu(pdu_type: u8, request_id: i32, a: i64, b: i64, vbs: &[VarBind]) -> Vec<u8> {
    let list: Vec<Vec<u8>> = vbs
        .iter()
        .map(|vb| seq(&[enc_oid(&vb.oid), enc_value(&vb.value)]))
        .collect();
    tlv(
        pdu_type,
        &[
            enc_int(request_id as i64),
            enc_int(a),
            enc_int(b),
            seq(&list),
        ]
        .concat(),
    )
}

/// A complete v1 (version 0) or v2c (version 1) message.
pub fn enc_message(
    version: Version,
    community: &str,
    pdu_type: u8,
    request_id: i32,
    a: i64,
    b: i64,
    vbs: &[VarBind],
) -> Vec<u8> {
    seq(&[
        enc_int(version.wire()),
        enc_octets(community.as_bytes()),
        enc_pdu(pdu_type, request_id, a, b, vbs),
    ])
}

// ---------------------------------------------------------------- BER decode

struct Reader<'a> {
    p: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(p: &'a [u8]) -> Self {
        Self { p, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.p.len()
    }

    fn tlv(&mut self) -> Result<(u8, &'a [u8]), String> {
        let short = || "truncated BER data".to_string();
        let tag = *self.p.get(self.pos).ok_or_else(short)?;
        let mut i = self.pos + 1;
        let first = *self.p.get(i).ok_or_else(short)?;
        i += 1;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err("unsupported BER length".into());
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *self.p.get(i).ok_or_else(short)? as usize;
                i += 1;
            }
            l
        };
        let end = i.checked_add(len).ok_or_else(short)?;
        if end > self.p.len() {
            return Err(short());
        }
        self.pos = end;
        Ok((tag, &self.p[i..end]))
    }

    fn expect(&mut self, want: u8) -> Result<&'a [u8], String> {
        let (t, b) = self.tlv()?;
        if t != want {
            return Err(format!("expected tag {want:#04x}, got {t:#04x}"));
        }
        Ok(b)
    }

    fn int(&mut self) -> Result<i64, String> {
        Ok(dec_int(self.expect(T_INT)?))
    }
}

fn dec_int(b: &[u8]) -> i64 {
    if b.is_empty() {
        return 0;
    }
    let mut v: i64 = if b[0] & 0x80 != 0 { -1 } else { 0 };
    for &x in b.iter().take(8) {
        v = (v << 8) | x as i64;
    }
    v
}

fn dec_uint(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |v, &x| (v << 8) | x as u64)
}

pub fn dec_oid(b: &[u8]) -> Result<Oid, String> {
    let mut subs = Vec::new();
    let mut v: u64 = 0;
    for (i, &x) in b.iter().enumerate() {
        v = (v << 7) | (x & 0x7f) as u64;
        if v > u32::MAX as u64 {
            return Err("OID sub-identifier too large".into());
        }
        if x & 0x80 == 0 {
            subs.push(v as u32);
            v = 0;
        } else if i == b.len() - 1 {
            return Err("truncated OID".into());
        }
    }
    let Some(&first) = subs.first() else {
        return Ok(Vec::new());
    };
    let mut oid = match first {
        0..=39 => vec![0, first],
        40..=79 => vec![1, first - 40],
        _ => vec![2, first - 80],
    };
    oid.extend_from_slice(&subs[1..]);
    Ok(oid)
}

fn dec_value(tag: u8, b: &[u8]) -> Result<Value, String> {
    Ok(match tag {
        T_INT => Value::Int(dec_int(b)),
        T_OCTETS => Value::Str(b.to_vec()),
        T_NULL => Value::Null,
        T_OID => Value::Oid(dec_oid(b)?),
        0x40 if b.len() == 4 => Value::Ip([b[0], b[1], b[2], b[3]]),
        0x41 => Value::Counter32(dec_uint(b) as u32),
        0x42 => Value::Gauge32(dec_uint(b) as u32),
        0x43 => Value::TimeTicks(dec_uint(b) as u32),
        0x44 => Value::Opaque(b.to_vec()),
        0x46 => Value::Counter64(dec_uint(b)),
        0x80 => Value::NoSuchObject,
        0x81 => Value::NoSuchInstance,
        0x82 => Value::EndOfMibView,
        t => Value::Other(t, b.to_vec()),
    })
}

#[derive(Clone, Debug)]
pub struct Pdu {
    pub pdu_type: u8,
    pub request_id: i32,
    pub error_status: i64,
    pub error_index: i64,
    pub varbinds: Vec<VarBind>,
}

fn dec_pdu(tag: u8, body: &[u8]) -> Result<Pdu, String> {
    let mut r = Reader::new(body);
    let request_id = r.int()? as i32;
    let error_status = r.int()?;
    let error_index = r.int()?;
    let mut list = Reader::new(r.expect(T_SEQ)?);
    let mut varbinds = Vec::new();
    while !list.done() {
        let mut vb = Reader::new(list.expect(T_SEQ)?);
        let oid = dec_oid(vb.expect(T_OID)?)?;
        let (t, b) = vb.tlv()?;
        varbinds.push(VarBind {
            oid,
            value: dec_value(t, b)?,
        });
    }
    Ok(Pdu {
        pdu_type: tag,
        request_id,
        error_status,
        error_index,
        varbinds,
    })
}

#[derive(Clone, Debug)]
pub struct Message {
    pub version: i64,
    pub community: Vec<u8>,
    pub pdu: Pdu,
}

pub fn dec_message(p: &[u8]) -> Result<Message, String> {
    let mut r = Reader::new(Reader::new(p).expect(T_SEQ)?);
    let version = r.int()?;
    if version == 3 {
        return Err("SNMPv3 message".into());
    }
    let community = r.expect(T_OCTETS)?.to_vec();
    let (tag, body) = r.tlv()?;
    Ok(Message {
        version,
        community,
        pdu: dec_pdu(tag, body)?,
    })
}

pub fn error_name(e: i64) -> &'static str {
    match e {
        0 => "noError",
        1 => "tooBig",
        2 => "noSuchName",
        3 => "badValue",
        4 => "readOnly",
        5 => "genErr",
        6 => "noAccess",
        7 => "wrongType",
        8 => "wrongLength",
        9 => "wrongEncoding",
        10 => "wrongValue",
        11 => "noCreation",
        12 => "inconsistentValue",
        13 => "resourceUnavailable",
        14 => "commitFailed",
        15 => "undoFailed",
        16 => "authorizationError",
        17 => "notWritable",
        18 => "inconsistentName",
        _ => "unknown error",
    }
}

// ---------------------------------------------------------------- OID names

const NAMES: &[(&str, &str)] = &[
    ("1.3.6.1.2.1", "mib-2"),
    ("1.3.6.1.2.1.1", "system"),
    ("1.3.6.1.2.1.1.1", "sysDescr"),
    ("1.3.6.1.2.1.1.2", "sysObjectID"),
    ("1.3.6.1.2.1.1.3", "sysUpTime"),
    ("1.3.6.1.2.1.1.4", "sysContact"),
    ("1.3.6.1.2.1.1.5", "sysName"),
    ("1.3.6.1.2.1.1.6", "sysLocation"),
    ("1.3.6.1.2.1.1.7", "sysServices"),
    ("1.3.6.1.2.1.1.9", "sysORTable"),
    ("1.3.6.1.2.1.2", "interfaces"),
    ("1.3.6.1.2.1.2.1", "ifNumber"),
    ("1.3.6.1.2.1.2.2", "ifTable"),
    ("1.3.6.1.2.1.2.2.1.1", "ifIndex"),
    ("1.3.6.1.2.1.2.2.1.2", "ifDescr"),
    ("1.3.6.1.2.1.2.2.1.3", "ifType"),
    ("1.3.6.1.2.1.2.2.1.4", "ifMtu"),
    ("1.3.6.1.2.1.2.2.1.5", "ifSpeed"),
    ("1.3.6.1.2.1.2.2.1.6", "ifPhysAddress"),
    ("1.3.6.1.2.1.2.2.1.7", "ifAdminStatus"),
    ("1.3.6.1.2.1.2.2.1.8", "ifOperStatus"),
    ("1.3.6.1.2.1.2.2.1.9", "ifLastChange"),
    ("1.3.6.1.2.1.2.2.1.10", "ifInOctets"),
    ("1.3.6.1.2.1.2.2.1.11", "ifInUcastPkts"),
    ("1.3.6.1.2.1.2.2.1.13", "ifInDiscards"),
    ("1.3.6.1.2.1.2.2.1.14", "ifInErrors"),
    ("1.3.6.1.2.1.2.2.1.16", "ifOutOctets"),
    ("1.3.6.1.2.1.2.2.1.17", "ifOutUcastPkts"),
    ("1.3.6.1.2.1.2.2.1.19", "ifOutDiscards"),
    ("1.3.6.1.2.1.2.2.1.20", "ifOutErrors"),
    ("1.3.6.1.2.1.4", "ip"),
    ("1.3.6.1.2.1.4.1", "ipForwarding"),
    ("1.3.6.1.2.1.4.20.1.1", "ipAdEntAddr"),
    ("1.3.6.1.2.1.4.20.1.2", "ipAdEntIfIndex"),
    ("1.3.6.1.2.1.4.20.1.3", "ipAdEntNetMask"),
    ("1.3.6.1.2.1.4.21", "ipRouteTable"),
    ("1.3.6.1.2.1.4.22.1.2", "ipNetToMediaPhysAddress"),
    ("1.3.6.1.2.1.4.24", "ipForward"),
    ("1.3.6.1.2.1.6", "tcp"),
    ("1.3.6.1.2.1.6.13", "tcpConnTable"),
    ("1.3.6.1.2.1.7", "udp"),
    ("1.3.6.1.2.1.11", "snmp"),
    ("1.3.6.1.2.1.17", "dot1dBridge"),
    ("1.3.6.1.2.1.17.4.3.1.1", "dot1dTpFdbAddress"),
    ("1.3.6.1.2.1.17.4.3.1.2", "dot1dTpFdbPort"),
    ("1.3.6.1.2.1.25", "host"),
    ("1.3.6.1.2.1.25.1.1", "hrSystemUptime"),
    ("1.3.6.1.2.1.25.1.6", "hrSystemProcesses"),
    ("1.3.6.1.2.1.25.2.2", "hrMemorySize"),
    ("1.3.6.1.2.1.25.2.3.1.3", "hrStorageDescr"),
    ("1.3.6.1.2.1.25.2.3.1.4", "hrStorageAllocationUnits"),
    ("1.3.6.1.2.1.25.2.3.1.5", "hrStorageSize"),
    ("1.3.6.1.2.1.25.2.3.1.6", "hrStorageUsed"),
    ("1.3.6.1.2.1.25.3.3.1.2", "hrProcessorLoad"),
    ("1.3.6.1.2.1.25.4.2.1.2", "hrSWRunName"),
    ("1.3.6.1.2.1.31.1.1.1.1", "ifName"),
    ("1.3.6.1.2.1.31.1.1.1.6", "ifHCInOctets"),
    ("1.3.6.1.2.1.31.1.1.1.10", "ifHCOutOctets"),
    ("1.3.6.1.2.1.31.1.1.1.15", "ifHighSpeed"),
    ("1.3.6.1.2.1.31.1.1.1.18", "ifAlias"),
    ("1.3.6.1.2.1.47.1.1.1.1.2", "entPhysicalDescr"),
    ("1.3.6.1.2.1.47.1.1.1.1.7", "entPhysicalName"),
    ("1.3.6.1.2.1.47.1.1.1.1.10", "entPhysicalSoftwareRev"),
    ("1.3.6.1.2.1.47.1.1.1.1.11", "entPhysicalSerialNum"),
    ("1.3.6.1.2.1.47.1.1.1.1.12", "entPhysicalMfgName"),
    ("1.3.6.1.2.1.47.1.1.1.1.13", "entPhysicalModelName"),
    ("1.3.6.1.2.1.43", "printmib"),
    ("1.3.6.1.2.1.105", "powerEthernetMIB"),
    ("1.3.6.1.4.1", "enterprises"),
    ("1.3.6.1.6.3.10.2.1.1", "snmpEngineID"),
    ("1.3.6.1.6.3.10.2.1.2", "snmpEngineBoots"),
    ("1.3.6.1.6.3.10.2.1.3", "snmpEngineTime"),
    ("1.3.6.1.6.3.10.2.1.4", "snmpEngineMaxMessageSize"),
    ("1.3.6.1.6.3.15.1.1.1", "usmStatsUnsupportedSecLevels"),
    ("1.3.6.1.6.3.15.1.1.2", "usmStatsNotInTimeWindows"),
    ("1.3.6.1.6.3.15.1.1.3", "usmStatsUnknownUserNames"),
    ("1.3.6.1.6.3.15.1.1.4", "usmStatsUnknownEngineIDs"),
    ("1.3.6.1.6.3.15.1.1.5", "usmStatsWrongDigests"),
    ("1.3.6.1.6.3.15.1.1.6", "usmStatsDecryptionErrors"),
    ("1.0.8802.1.1.2.1.4.1.1.9", "lldpRemSysName"),
    ("1.0.8802.1.1.2.1.4.1.1.7", "lldpRemPortId"),
    ("1.0.8802.1.1.2.1.4.1.1.8", "lldpRemPortDesc"),
];

pub fn oid_str(oid: &[u32]) -> String {
    oid.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn parse_numeric(s: &str) -> Option<Oid> {
    let s = s.trim().trim_start_matches('.');
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|p| p.parse::<u32>().ok()).collect()
}

/// Symbolic name for an OID: longest known prefix plus the remaining arcs.
pub fn oid_name(oid: &[u32]) -> String {
    let mut best: Option<(usize, &str)> = None;
    for (num, name) in NAMES {
        if let Some(p) = parse_numeric(num)
            && oid.starts_with(&p)
            && best.is_none_or(|(l, _)| p.len() > l)
        {
            best = Some((p.len(), name));
        }
    }
    if let Some(e) = enterprise_of(oid)
        && best.is_none_or(|(l, _)| l <= 6)
    {
        let rest = oid_str(&oid[7..]);
        let name = enterprise_name(e).unwrap_or("enterprise");
        return if rest.is_empty() {
            format!("{name} ({e})")
        } else {
            format!("{name} ({e}).{rest}")
        };
    }
    match best {
        Some((l, name)) if l == oid.len() => name.to_string(),
        Some((l, name)) => format!("{name}.{}", oid_str(&oid[l..])),
        None => oid_str(oid),
    }
}

/// Parse "1.3.6.1…", ".1.3…", "sysDescr.0", "ifDescr" or "system".
pub fn parse_oid(s: &str) -> Result<Oid, String> {
    let s = s.trim();
    if let Some(o) = parse_numeric(s) {
        return if o.len() >= 2 {
            Ok(o)
        } else {
            Err(format!("'{s}': an OID needs at least two arcs"))
        };
    }
    let (name, rest) = s.split_once('.').unwrap_or((s, ""));
    let base = NAMES
        .iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(name))
        .and_then(|(num, _)| parse_numeric(num))
        .ok_or_else(|| format!("unknown OID name '{name}'"))?;
    let mut oid = base;
    if !rest.is_empty() {
        oid.extend(parse_numeric(rest).ok_or_else(|| format!("bad OID suffix '{rest}'"))?);
    }
    Ok(oid)
}

fn enterprise_of(oid: &[u32]) -> Option<u32> {
    (oid.len() >= 7 && oid[..6] == [1, 3, 6, 1, 4, 1]).then(|| oid[6])
}

pub fn enterprise_name(n: u32) -> Option<&'static str> {
    Some(match n {
        2 => "IBM",
        9 => "Cisco",
        11 => "HP",
        43 => "3Com",
        171 => "D-Link",
        207 => "Allied Telesis",
        232 => "HP (Compaq)",
        311 => "Microsoft",
        318 => "APC",
        674 => "Dell",
        1916 => "Extreme Networks",
        1991 => "Brocade (Foundry)",
        2011 => "Huawei",
        2021 => "UCD-SNMP",
        2272 => "Nortel / Avaya",
        2636 => "Juniper",
        3375 => "F5",
        4413 => "Broadcom",
        4526 => "Netgear",
        5528 => "Netbotz",
        6027 => "Force10 / Dell",
        6486 => "Alcatel-Lucent",
        6527 => "Nokia (TiMOS)",
        6574 => "Synology",
        6876 => "VMware",
        8072 => "Net-SNMP",
        9303 => "Mikrotik (legacy)",
        11863 => "TP-Link",
        12356 => "Fortinet",
        14179 => "Cisco (Airespace)",
        14823 => "Aruba",
        14988 => "MikroTik",
        17163 => "Riverbed",
        24681 => "QNAP",
        25461 => "Palo Alto Networks",
        25506 => "H3C",
        26543 => "IBM (BladeCenter)",
        30065 => "Arista",
        41112 => "Ubiquiti",
        47196 => "Moxa",
        4329 => "Siemens",
        248 => "Hirschmann",
        13576 => "Phoenix Contact",
        16838 => "Schneider Electric",
        8691 => "Moxa (legacy)",
        _ => return None,
    })
}

pub fn if_type_name(t: i64) -> String {
    match t {
        1 => "other".into(),
        6 => "ethernet".into(),
        23 => "ppp".into(),
        24 => "loopback".into(),
        53 => "virtual".into(),
        62 => "fastEthernet".into(),
        71 => "802.11".into(),
        117 => "gigabitEthernet".into(),
        131 => "tunnel".into(),
        135 => "vlan".into(),
        136 => "l3vlan".into(),
        161 => "LAG".into(),
        166 => "mpls".into(),
        209 => "bridge".into(),
        244 => "wwan".into(),
        n => format!("type {n}"),
    }
}

pub fn status_name(s: i64) -> &'static str {
    match s {
        1 => "up",
        2 => "down",
        3 => "testing",
        4 => "unknown",
        5 => "dormant",
        6 => "notPresent",
        7 => "lowerLayerDown",
        _ => "-",
    }
}

/// Parse a Set value from a net-snmp style type letter
/// (i, u, t, a, o, s, x, c).
pub fn parse_set_value(t: &str, v: &str) -> Result<Value, String> {
    let bad = |what: &str| format!("'{v}' is not a valid {what}");
    Ok(match t.trim() {
        "i" => Value::Int(v.trim().parse().map_err(|_| bad("integer"))?),
        "u" => Value::Gauge32(v.trim().parse().map_err(|_| bad("unsigned"))?),
        "c" => Value::Counter32(v.trim().parse().map_err(|_| bad("counter"))?),
        "t" => Value::TimeTicks(v.trim().parse().map_err(|_| bad("timeticks"))?),
        "a" => Value::Ip(
            v.trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| bad("IPv4 address"))?
                .octets(),
        ),
        "o" => Value::Oid(parse_oid(v)?),
        "s" => Value::Str(v.as_bytes().to_vec()),
        "x" => {
            let h: String = v.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if !h.len().is_multiple_of(2) {
                return Err(bad("hex string"));
            }
            Value::Str(
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap_or(0))
                    .collect(),
            )
        }
        other => return Err(format!("unknown type '{other}' (use i u c t a o s x)")),
    })
}

// ---------------------------------------------------------------- session

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Version {
    V1,
    V2c,
}

impl Version {
    fn wire(self) -> i64 {
        match self {
            Version::V1 => 0,
            Version::V2c => 1,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Version::V1 => "v1",
            Version::V2c => "v2c",
        }
    }
}

fn next_request_id() -> i32 {
    static ID: AtomicI32 = AtomicI32::new(0);
    let v = ID.fetch_add(1, Ordering::Relaxed);
    if v == 0 {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as i32 & 0x3fff_ffff)
            .unwrap_or(1)
            .max(1);
        ID.store(seed + 1, Ordering::Relaxed);
        return seed;
    }
    v & 0x7fff_ffff
}

/// Resolve "host", "host:port", "[v6]:port" with default port 161.
pub fn resolve(host: &str) -> Result<SocketAddr, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("enter a host".into());
    }
    if let Ok(sa) = host.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 161));
    }
    let with_port = if host
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    {
        host.to_string()
    } else {
        format!("{host}:161")
    };
    with_port
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .min_by_key(|a| a.is_ipv6())
        .ok_or_else(|| format!("{host}: no address"))
}

fn bind_for(addr: &SocketAddr) -> std::io::Result<UdpSocket> {
    if addr.is_ipv6() {
        UdpSocket::bind("[::]:0")
    } else {
        UdpSocket::bind("0.0.0.0:0")
    }
}

/// Send `req` and wait for a datagram accepted by `matches`, retrying.
fn exchange<T>(
    addr: SocketAddr,
    req: &[u8],
    timeout: Duration,
    retries: u32,
    mut matches: impl FnMut(&[u8]) -> Option<T>,
) -> Result<(T, Duration), String> {
    let sock = bind_for(&addr).map_err(|e| e.to_string())?;
    sock.connect(addr).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65535];
    for _ in 0..=retries {
        let start = Instant::now();
        sock.send(req).map_err(|e| e.to_string())?;
        let deadline = start + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            sock.set_read_timeout(Some(deadline - now)).ok();
            match sock.recv(&mut buf) {
                Ok(n) => {
                    if let Some(v) = matches(&buf[..n]) {
                        return Ok((v, start.elapsed()));
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    return Err("port unreachable (no SNMP agent on this port)".into());
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }
    Err("no response (wrong community, SNMP disabled, or filtered)".into())
}

#[derive(Clone, Debug)]
pub struct Session {
    pub addr: SocketAddr,
    pub community: String,
    pub version: Version,
    pub timeout: Duration,
    pub retries: u32,
}

impl Session {
    pub fn new(addr: SocketAddr, community: &str, version: Version) -> Self {
        Self {
            addr,
            community: community.to_string(),
            version,
            timeout: Duration::from_millis(2000),
            retries: 1,
        }
    }

    /// One request/response; returns the response PDU (errors included).
    pub fn request(
        &self,
        pdu_type: u8,
        a: i64,
        b: i64,
        vbs: &[VarBind],
    ) -> Result<(Pdu, Duration), String> {
        if pdu_type == PDU_GETBULK && self.version == Version::V1 {
            return Err("GetBulk needs SNMP v2c".into());
        }
        let id = next_request_id();
        let req = enc_message(self.version, &self.community, pdu_type, id, a, b, vbs);
        exchange(self.addr, &req, self.timeout, self.retries, |p| {
            dec_message(p)
                .ok()
                .filter(|m| {
                    m.pdu.request_id == id
                        && m.pdu.pdu_type == PDU_RESPONSE
                        && m.version == self.version.wire()
                        && m.community == self.community.as_bytes()
                })
                .map(|m| m.pdu)
        })
    }

    fn null_vbs(oids: &[Oid]) -> Vec<VarBind> {
        oids.iter()
            .map(|o| VarBind {
                oid: o.clone(),
                value: Value::Null,
            })
            .collect()
    }

    fn checked(pdu: Pdu) -> Result<Vec<VarBind>, String> {
        if pdu.error_status != 0 {
            let at = pdu
                .varbinds
                .get((pdu.error_index - 1).max(0) as usize)
                .map(|v| format!(" at {}", oid_name(&v.oid)))
                .unwrap_or_default();
            return Err(format!(
                "agent error: {} ({}){at}",
                error_name(pdu.error_status),
                pdu.error_status
            ));
        }
        Ok(pdu.varbinds)
    }

    pub fn get(&self, oids: &[Oid]) -> Result<Vec<VarBind>, String> {
        Self::checked(self.request(PDU_GET, 0, 0, &Self::null_vbs(oids))?.0)
    }

    pub fn get_next(&self, oids: &[Oid]) -> Result<Vec<VarBind>, String> {
        Self::checked(self.request(PDU_GETNEXT, 0, 0, &Self::null_vbs(oids))?.0)
    }

    pub fn get_bulk(
        &self,
        non_rep: i64,
        max_rep: i64,
        oids: &[Oid],
    ) -> Result<Vec<VarBind>, String> {
        Self::checked(
            self.request(PDU_GETBULK, non_rep, max_rep, &Self::null_vbs(oids))?
                .0,
        )
    }

    pub fn set(&self, oid: &Oid, value: Value) -> Result<Vec<VarBind>, String> {
        Self::checked(
            self.request(
                PDU_SET,
                0,
                0,
                &[VarBind {
                    oid: oid.clone(),
                    value,
                }],
            )?
            .0,
        )
    }

    /// Get one value; `None` for exceptions or v1 noSuchName.
    pub fn get_one(&self, oid: &Oid) -> Result<Option<Value>, String> {
        match self
            .request(PDU_GET, 0, 0, &Self::null_vbs(std::slice::from_ref(oid)))?
            .0
        {
            p if p.error_status == 2 => Ok(None),
            p => Ok(Self::checked(p)?
                .into_iter()
                .next()
                .map(|v| v.value)
                .filter(Value::is_value)),
        }
    }

    /// Walk a subtree with GetBulk (v2c) or GetNext (v1). `progress` gets
    /// the running count and may return false to stop. Stops at `limit`,
    /// at the end of the subtree, or when the agent returns a
    /// non-increasing OID (a broken agent that would loop forever).
    pub fn walk(
        &self,
        root: &Oid,
        limit: usize,
        mut progress: impl FnMut(usize) -> bool,
    ) -> Result<WalkResult, String> {
        let mut out = Vec::new();
        let mut cur = root.clone();
        let mut max_rep = 25i64;
        let mut note = None;
        'outer: loop {
            let pdu = if self.version == Version::V2c {
                match self.request(PDU_GETBULK, 0, max_rep, &Self::null_vbs(&[cur.clone()])) {
                    Ok((p, _)) if p.error_status == 1 && max_rep > 1 => {
                        max_rep = (max_rep / 2).max(1);
                        continue;
                    }
                    Ok((p, _)) => p,
                    Err(e) if out.is_empty() => return Err(e),
                    Err(e) => {
                        note = Some(format!("stopped early: {e}"));
                        break;
                    }
                }
            } else {
                match self.request(PDU_GETNEXT, 0, 0, &Self::null_vbs(&[cur.clone()])) {
                    Ok((p, _)) => p,
                    Err(e) if out.is_empty() => return Err(e),
                    Err(e) => {
                        note = Some(format!("stopped early: {e}"));
                        break;
                    }
                }
            };
            if pdu.error_status == 2 {
                break; // v1 end of MIB
            }
            let vbs = Self::checked(pdu)?;
            if vbs.is_empty() {
                break;
            }
            for vb in vbs {
                if vb.value == Value::EndOfMibView || !vb.oid.starts_with(root) {
                    break 'outer;
                }
                if vb.oid <= cur {
                    note = Some(format!(
                        "agent returned a non-increasing OID ({}); stopped to avoid a loop",
                        oid_str(&vb.oid)
                    ));
                    break 'outer;
                }
                cur = vb.oid.clone();
                out.push(vb);
                if out.len() >= limit {
                    note = Some(format!("stopped at the {limit}-entry limit"));
                    break 'outer;
                }
            }
            if !progress(out.len()) {
                note = Some("stopped".into());
                break;
            }
        }
        // Walking a leaf (e.g. sysDescr.0) returns nothing: fall back to Get.
        if out.is_empty()
            && let Ok(Some(v)) = self.get_one(root)
        {
            out.push(VarBind {
                oid: root.clone(),
                value: v,
            });
        }
        Ok(WalkResult { vbs: out, note })
    }

    /// Walk a table column into index → value.
    fn column(&self, col: &str) -> BTreeMap<u32, Value> {
        let Ok(root) = parse_oid(col) else {
            return BTreeMap::new();
        };
        self.walk(&root, 5000, |_| true)
            .map(|w| {
                w.vbs
                    .into_iter()
                    .filter(|v| v.oid.len() == root.len() + 1)
                    .map(|v| (v.oid[root.len()], v.value))
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub struct WalkResult {
    pub vbs: Vec<VarBind>,
    pub note: Option<String>,
}

// ---------------------------------------------------------------- summary

#[derive(Clone, Debug, Default)]
pub struct SystemInfo {
    pub descr: String,
    pub object_id: String,
    pub vendor: Option<String>,
    pub uptime: Option<u32>,
    pub contact: String,
    pub name: String,
    pub location: String,
    pub services: Option<i64>,
    pub rtt_ms: f64,
}

pub fn system_info(s: &Session) -> Result<SystemInfo, String> {
    let oids: Vec<Oid> = (1..=7).map(|i| vec![1, 3, 6, 1, 2, 1, 1, i, 0]).collect();
    let (pdu, rtt) = s.request(PDU_GET, 0, 0, &Session::null_vbs(&oids))?;
    // v1 agents answer noSuchName for the whole request if one is missing.
    let vbs = if pdu.error_status == 2 {
        let mut v = Vec::new();
        for o in &oids {
            if let Ok(Some(val)) = s.get_one(o) {
                v.push(VarBind {
                    oid: o.clone(),
                    value: val,
                });
            }
        }
        v
    } else {
        Session::checked(pdu)?
    };
    let mut info = SystemInfo {
        rtt_ms: rtt.as_secs_f64() * 1000.0,
        ..Default::default()
    };
    for vb in vbs {
        if !vb.value.is_value() {
            continue;
        }
        match vb.oid.get(7) {
            Some(1) => info.descr = vb.value.as_text(),
            Some(2) => {
                if let Value::Oid(o) = &vb.value {
                    info.object_id = oid_str(o);
                    info.vendor = enterprise_of(o).map(|e| {
                        enterprise_name(e)
                            .map(|n| format!("{n} (enterprise {e})"))
                            .unwrap_or_else(|| format!("enterprise {e}"))
                    });
                }
            }
            Some(3) => info.uptime = vb.value.as_u64().map(|v| v as u32),
            Some(4) => info.contact = vb.value.as_text(),
            Some(5) => info.name = vb.value.as_text(),
            Some(6) => info.location = vb.value.as_text(),
            Some(7) => {
                if let Value::Int(i) = vb.value {
                    info.services = Some(i)
                }
            }
            _ => {}
        }
    }
    Ok(info)
}

/// sysServices bits → OSI layers offered.
pub fn services_text(v: i64) -> String {
    let names = [
        "physical",
        "datalink/switch",
        "internet/router",
        "end-to-end",
        "",
        "",
        "applications",
    ];
    let l: Vec<&str> = names
        .iter()
        .enumerate()
        .filter(|(i, n)| !n.is_empty() && v & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect();
    format!("{v} ({})", l.join(", "))
}

#[derive(Clone, Debug, Default)]
pub struct IfRow {
    pub index: u32,
    pub descr: String,
    pub name: String,
    pub alias: String,
    pub if_type: i64,
    pub speed_mbps: u64,
    pub mac: String,
    pub admin: i64,
    pub oper: i64,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
    /// 64-bit counters (ifXTable) are available.
    pub hc: bool,
}

impl IfRow {
    pub fn label(&self) -> String {
        if !self.name.is_empty() && self.name != self.descr {
            format!("{} ({})", self.name, self.descr)
        } else if !self.descr.is_empty() {
            self.descr.clone()
        } else {
            format!("if {}", self.index)
        }
    }
}

pub fn interfaces(s: &Session) -> Vec<IfRow> {
    let mut rows: BTreeMap<u32, IfRow> = BTreeMap::new();
    let mut set = |col: &str, f: &dyn Fn(&mut IfRow, &Value)| {
        for (i, v) in s.column(col) {
            let r = rows.entry(i).or_insert_with(|| IfRow {
                index: i,
                ..Default::default()
            });
            f(r, &v);
        }
    };
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    set("ifDescr", &|r, v| r.descr = v.as_text());
    set("ifType", &|r, v| r.if_type = n(v) as i64);
    set("ifSpeed", &|r, v| r.speed_mbps = n(v) / 1_000_000);
    set("ifPhysAddress", &|r, v| {
        if let Value::Str(b) = v {
            r.mac = hex(b, ":")
        }
    });
    set("ifAdminStatus", &|r, v| r.admin = n(v) as i64);
    set("ifOperStatus", &|r, v| r.oper = n(v) as i64);
    set("ifInOctets", &|r, v| r.in_octets = n(v));
    set("ifOutOctets", &|r, v| r.out_octets = n(v));
    set("ifInErrors", &|r, v| r.in_errors = n(v));
    set("ifOutErrors", &|r, v| r.out_errors = n(v));
    set("ifInDiscards", &|r, v| r.in_discards = n(v));
    set("ifOutDiscards", &|r, v| r.out_discards = n(v));
    if s.version == Version::V2c {
        set("ifName", &|r, v| r.name = v.as_text());
        set("ifAlias", &|r, v| r.alias = v.as_text());
        set("ifHighSpeed", &|r, v| {
            if n(v) > 0 {
                r.speed_mbps = n(v)
            }
        });
        set("ifHCInOctets", &|r, v| {
            r.in_octets = n(v);
            r.hc = true;
        });
        set("ifHCOutOctets", &|r, v| r.out_octets = n(v));
    }
    rows.into_values().collect()
}

/// In/out octet counters per interface index, for rate polling.
pub fn counters(s: &Session, hc: bool) -> BTreeMap<u32, (u64, u64)> {
    let (i, o) = if hc && s.version == Version::V2c {
        ("ifHCInOctets", "ifHCOutOctets")
    } else {
        ("ifInOctets", "ifOutOctets")
    };
    let ins = s.column(i);
    let outs = s.column(o);
    ins.into_iter()
        .map(|(k, v)| {
            let out = outs.get(&k).and_then(Value::as_u64).unwrap_or(0);
            (k, (v.as_u64().unwrap_or(0), out))
        })
        .collect()
}

/// Counter delta allowing for one 32- or 64-bit wrap.
pub fn counter_delta(prev: u64, now: u64, hc: bool) -> u64 {
    if now >= prev {
        now - prev
    } else if hc {
        (u64::MAX - prev).wrapping_add(now).wrapping_add(1)
    } else {
        (u32::MAX as u64 - prev) + now + 1
    }
}

// ---------------------------------------------------------------- communities

#[derive(Clone, Debug)]
pub struct CommunityResult {
    pub community: String,
    pub version: Version,
    pub descr: String,
    /// Some(true) writable, Some(false) read-only, None not tested.
    pub writable: Option<bool>,
}

const DEFAULT_COMMUNITIES: &[&str] = &["public", "private", "community", "admin", "snmp"];

/// Try each community with v2c then v1. With `test_write`, try writing
/// sysLocation.0 back with its current value (changes nothing if it works).
pub fn check_communities(
    addr: SocketAddr,
    list: &[String],
    test_write: bool,
    progress: impl Fn(String),
) -> (Vec<CommunityResult>, Vec<Finding>) {
    let mut found = Vec::new();
    let sys_descr = vec![1, 3, 6, 1, 2, 1, 1, 1, 0];
    let sys_location = vec![1, 3, 6, 1, 2, 1, 1, 6, 0];
    for c in list {
        progress(format!("Trying community '{c}'…"));
        for v in [Version::V2c, Version::V1] {
            let mut s = Session::new(addr, c, v);
            s.timeout = Duration::from_millis(1500);
            s.retries = 0;
            let Ok(Some(descr)) = s.get_one(&sys_descr) else {
                continue;
            };
            let writable = test_write.then(|| match s.get_one(&sys_location) {
                Ok(Some(cur)) => s.set(&sys_location, cur).is_ok(),
                _ => false,
            });
            found.push(CommunityResult {
                community: c.clone(),
                version: v,
                descr: descr.as_text(),
                writable,
            });
        }
    }
    let mut f = Vec::new();
    let sec = "Community strings";
    let fd = |key: String, value: String, level| Finding {
        section: sec.into(),
        key,
        value,
        level,
    };
    if found.is_empty() {
        f.push(fd(
            "Result".into(),
            format!("none of {} communities answered (v1 or v2c)", list.len()),
            Level::Good,
        ));
    }
    for r in &found {
        let default = DEFAULT_COMMUNITIES.contains(&r.community.to_ascii_lowercase().as_str());
        let (level, what) = match r.writable {
            Some(true) => (Level::Bad, "READ-WRITE".to_string()),
            Some(false) => (
                if default { Level::Warn } else { Level::Info },
                "read-only".to_string(),
            ),
            None => (
                if default { Level::Warn } else { Level::Info },
                "readable (write not tested)".to_string(),
            ),
        };
        f.push(fd(
            format!("'{}' ({})", r.community, r.version.label()),
            format!(
                "{what}{}",
                if default {
                    " — well-known default community"
                } else {
                    ""
                }
            ),
            level,
        ));
    }
    if !found.is_empty() {
        f.push(fd(
            "Clear text".into(),
            "SNMP v1/v2c sends the community string unencrypted; prefer SNMPv3 with authPriv"
                .into(),
            Level::Warn,
        ));
        if let Some(r) = found.first() {
            f.push(fd("sysDescr".into(), r.descr.clone(), Level::Info));
        }
    }
    (found, f)
}

// ---------------------------------------------------------------- SNMPv3 discovery

#[derive(Clone, Debug, Default)]
pub struct EngineInfo {
    pub engine_id: Vec<u8>,
    pub boots: i64,
    pub time: i64,
    pub enterprise: Option<u32>,
    pub format: String,
    pub reports: Vec<VarBind>,
    pub rtt_ms: f64,
}

pub fn v3_discovery_request(msg_id: i64) -> Vec<u8> {
    let usm = seq(&[
        enc_octets(&[]),
        enc_int(0),
        enc_int(0),
        enc_octets(&[]),
        enc_octets(&[]),
        enc_octets(&[]),
    ]);
    let scoped = seq(&[
        enc_octets(&[]),
        enc_octets(&[]),
        enc_pdu(PDU_GET, msg_id as i32, 0, 0, &[]),
    ]);
    seq(&[
        enc_int(3),
        seq(&[
            enc_int(msg_id),
            enc_int(65507),
            enc_octets(&[0x04]), // reportable, noAuthNoPriv
            enc_int(3),          // USM
        ]),
        enc_octets(&usm),
        scoped,
    ])
}

pub fn parse_v3_report(p: &[u8], want_id: i64) -> Result<EngineInfo, String> {
    let mut r = Reader::new(Reader::new(p).expect(T_SEQ)?);
    if r.int()? != 3 {
        return Err("not SNMPv3".into());
    }
    let mut hdr = Reader::new(r.expect(T_SEQ)?);
    if hdr.int()? != want_id {
        return Err("message id mismatch".into());
    }
    let mut usm = Reader::new(Reader::new(r.expect(T_OCTETS)?).expect(T_SEQ)?);
    let engine_id = usm.expect(T_OCTETS)?.to_vec();
    let boots = usm.int()?;
    let time = usm.int()?;
    let mut reports = Vec::new();
    if let Ok(scoped) = r.expect(T_SEQ) {
        let mut sr = Reader::new(scoped);
        let _ = sr.expect(T_OCTETS)?;
        let _ = sr.expect(T_OCTETS)?;
        let (tag, body) = sr.tlv()?;
        if tag == PDU_REPORT || tag == PDU_RESPONSE {
            reports = dec_pdu(tag, body)?.varbinds;
        }
    }
    let (enterprise, format) = describe_engine_id(&engine_id);
    Ok(EngineInfo {
        engine_id,
        boots,
        time,
        enterprise,
        format,
        reports,
        rtt_ms: 0.0,
    })
}

/// Enterprise number and a description of an snmpEngineID (RFC 3411).
pub fn describe_engine_id(id: &[u8]) -> (Option<u32>, String) {
    if id.len() < 5 {
        return (None, "too short".into());
    }
    let ent = u32::from_be_bytes([id[0] & 0x7f, id[1], id[2], id[3]]);
    if id[0] & 0x80 == 0 {
        return (Some(ent), format!("RFC 1910 format: {}", hex(&id[4..], "")));
    }
    let rest = &id[5..];
    let d = match id[4] {
        1 if rest.len() == 4 => format!(
            "IPv4 address {}",
            Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])
        ),
        2 if rest.len() == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rest);
            format!("IPv6 address {}", std::net::Ipv6Addr::from(a))
        }
        3 => format!("MAC address {}", hex(rest, ":")),
        4 => format!("text '{}'", String::from_utf8_lossy(rest)),
        5 => format!("octets {}", hex(rest, "")),
        128 if ent == 8072 => format!("Net-SNMP random {}", hex(rest, "")),
        f => format!("enterprise-specific (format {f}) {}", hex(rest, "")),
    };
    (Some(ent), d)
}

pub fn v3_discover(addr: SocketAddr, timeout: Duration) -> Result<EngineInfo, String> {
    let id = (next_request_id() & 0x7fff) as i64 + 1;
    let req = v3_discovery_request(id);
    let (mut info, rtt) = exchange(addr, &req, timeout, 1, |p| parse_v3_report(p, id).ok())
        .map_err(|e| {
            if e.starts_with("no response") {
                "no SNMPv3 response (v3 disabled, or filtered)".to_string()
            } else {
                e
            }
        })?;
    info.rtt_ms = rtt.as_secs_f64() * 1000.0;
    Ok(info)
}

pub fn engine_findings(e: &EngineInfo) -> Vec<Finding> {
    let sec = "SNMPv3 engine";
    let f = |k: &str, v: String, level| Finding {
        section: sec.into(),
        key: k.into(),
        value: v,
        level,
    };
    let mut out = vec![
        f("Engine ID", hex(&e.engine_id, ""), Level::Info),
        f(
            "Enterprise",
            e.enterprise
                .map(|n| match enterprise_name(n) {
                    Some(name) => format!("{name} ({n})"),
                    None => n.to_string(),
                })
                .unwrap_or_else(|| "-".into()),
            Level::Info,
        ),
        f("Engine ID format", e.format.clone(), Level::Info),
        f("Engine boots", e.boots.to_string(), Level::Info),
        f(
            "Engine time",
            format!(
                "{} (since last boot)",
                ticks((e.time.max(0) as u32).saturating_mul(100))
            ),
            Level::Info,
        ),
        f("Response time", format!("{:.1} ms", e.rtt_ms), Level::Info),
    ];
    for r in &e.reports {
        out.push(f(
            "Report",
            format!("{} = {}", oid_name(&r.oid), r.value),
            Level::Info,
        ));
    }
    out.push(f(
        "Note",
        "SNMPv3 is enabled. Use authPriv (SHA-2 + AES) users; the engine ID also \
         identifies the device without credentials."
            .into(),
        Level::Good,
    ));
    out
}

// ---------------------------------------------------------------- sweep

#[derive(Clone, Debug)]
pub struct SweepHit {
    pub ip: Ipv4Addr,
    pub name: String,
    pub descr: String,
    pub vendor: String,
    pub uptime: Option<u32>,
}

/// Ask every address for sysDescr/sysName/sysObjectID/sysUpTime with one
/// socket (UDP 161); hits arrive on `on_hit`. Returns the number of hits.
pub fn sweep(
    ips: &[Ipv4Addr],
    community: &str,
    version: Version,
    wait: Duration,
    cancel: &std::sync::atomic::AtomicBool,
    mut on_hit: impl FnMut(SweepHit),
    mut on_progress: impl FnMut(usize),
) -> Result<usize, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(5))).ok();
    let base = next_request_id() & 0x0fff_ffff;
    let oids: Vec<VarBind> = [1u32, 5, 2, 3]
        .iter()
        .map(|i| VarBind {
            oid: vec![1, 3, 6, 1, 2, 1, 1, *i, 0],
            value: Value::Null,
        })
        .collect();
    let mut seen = std::collections::HashSet::new();
    let mut buf = vec![0u8; 65535];
    let mut drain = |seen: &mut std::collections::HashSet<Ipv4Addr>| {
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let IpAddr::V4(ip) = from.ip() else { continue };
            let Ok(m) = dec_message(&buf[..n]) else {
                continue;
            };
            if m.pdu.request_id.wrapping_sub(base) as usize >= ips.len() || !seen.insert(ip) {
                continue;
            }
            let mut h = SweepHit {
                ip,
                name: String::new(),
                descr: String::new(),
                vendor: String::new(),
                uptime: None,
            };
            for vb in m.pdu.varbinds {
                match vb.oid.get(7) {
                    Some(1) => h.descr = vb.value.as_text(),
                    Some(5) => h.name = vb.value.as_text(),
                    Some(2) => {
                        if let Value::Oid(o) = &vb.value {
                            h.vendor = enterprise_of(o)
                                .map(|e| {
                                    enterprise_name(e)
                                        .map(String::from)
                                        .unwrap_or_else(|| format!("enterprise {e}"))
                                })
                                .unwrap_or_default();
                        }
                    }
                    Some(3) => h.uptime = vb.value.as_u64().map(|v| v as u32),
                    _ => {}
                }
            }
            on_hit(h);
        }
    };
    for pass in 0..2 {
        for (i, ip) in ips.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return Ok(seen.len());
            }
            if seen.contains(ip) {
                continue;
            }
            let req = enc_message(
                version,
                community,
                PDU_GET,
                base.wrapping_add(i as i32),
                0,
                0,
                &oids,
            );
            let _ = sock.send_to(&req, (*ip, 161));
            if i % 32 == 31 {
                drain(&mut seen);
                on_progress(pass * ips.len() + i + 1);
            }
        }
        let end = Instant::now() + wait;
        while Instant::now() < end && !cancel.load(Ordering::Relaxed) {
            drain(&mut seen);
            std::thread::sleep(Duration::from_millis(20));
        }
        on_progress((pass + 1) * ips.len());
    }
    Ok(seen.len())
}

// ---------------------------------------------------------------- CLI

pub const CLI_USAGE: &str = "\
    --snmp HOST[:PORT] [summary | get OID… | walk OID | v3 | check [COMMUNITIES]]
                  [-c COMMUNITY] [-1]
                  SNMP device summary (default), get / walk, SNMPv3 engine
                  discovery, or community check (-1 = SNMP v1)
";

pub fn cli(args: &[String]) {
    let mut host = None;
    let mut community = "public".to_string();
    let mut version = Version::V2c;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                community = args.get(i).cloned().unwrap_or_default();
            }
            "-1" | "-v1" => version = Version::V1,
            "-2c" | "-v2c" => version = Version::V2c,
            a if host.is_none() => host = Some(a.to_string()),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let die = |e: String| -> ! {
        eprintln!("{e}");
        std::process::exit(1)
    };
    let Some(host) = host else {
        eprint!("usage:\n{CLI_USAGE}");
        std::process::exit(2)
    };
    let addr = resolve(&host).unwrap_or_else(|e| die(e));
    let s = Session::new(addr, &community, version);
    let cmd = rest.first().map(String::as_str).unwrap_or("summary");
    let print = |vbs: &[VarBind]| {
        for vb in vbs {
            println!(
                "{:<40} {:<13} {}",
                oid_name(&vb.oid),
                vb.value.type_name(),
                vb.value
            );
        }
    };
    match cmd {
        "summary" => {
            let info = system_info(&s).unwrap_or_else(|e| die(e));
            println!("sysDescr     {}", info.descr);
            println!("sysName      {}", info.name);
            println!(
                "sysObjectID  {} {}",
                info.object_id,
                info.vendor.unwrap_or_default()
            );
            if let Some(t) = info.uptime {
                println!("sysUpTime    {}", ticks(t));
            }
            println!("sysContact   {}", info.contact);
            println!("sysLocation  {}", info.location);
            if let Some(sv) = info.services {
                println!("sysServices  {}", services_text(sv));
            }
            println!();
            println!(
                "{:<6} {:<28} {:<14} {:>8} {:<6} {:<6} {:>14} {:>14} {:>8}",
                "INDEX",
                "INTERFACE",
                "TYPE",
                "MBIT/S",
                "ADMIN",
                "OPER",
                "IN OCTETS",
                "OUT OCTETS",
                "ERRORS"
            );
            for r in interfaces(&s) {
                println!(
                    "{:<6} {:<28} {:<14} {:>8} {:<6} {:<6} {:>14} {:>14} {:>8}",
                    r.index,
                    r.label().chars().take(28).collect::<String>(),
                    if_type_name(r.if_type),
                    r.speed_mbps,
                    status_name(r.admin),
                    status_name(r.oper),
                    r.in_octets,
                    r.out_octets,
                    r.in_errors + r.out_errors
                );
            }
        }
        "get" => {
            let oids: Vec<Oid> = rest[1..]
                .iter()
                .map(|o| parse_oid(o).unwrap_or_else(|e| die(e)))
                .collect();
            if oids.is_empty() {
                die("get: give one or more OIDs".into());
            }
            print(&s.get(&oids).unwrap_or_else(|e| die(e)));
        }
        "walk" => {
            let root = parse_oid(rest.get(1).map(String::as_str).unwrap_or("system"))
                .unwrap_or_else(|e| die(e));
            let w = s.walk(&root, 100_000, |_| true).unwrap_or_else(|e| die(e));
            print(&w.vbs);
            if let Some(n) = w.note {
                eprintln!("({n})");
            }
        }
        "v3" => {
            let e = v3_discover(addr, Duration::from_secs(2)).unwrap_or_else(|e| die(e));
            print!("{}", crate::widgets::findings_text(&engine_findings(&e)));
        }
        "check" => {
            let list: Vec<String> = rest
                .get(1)
                .map(|l| l.split(',').map(|c| c.trim().to_string()).collect())
                .unwrap_or_else(|| DEFAULT_COMMUNITIES.iter().map(|c| c.to_string()).collect());
            let (_, f) = check_communities(addr, &list, false, |_| {});
            print!("{}", crate::widgets::findings_text(&f));
        }
        other => die(format!("unknown SNMP command '{other}'\n\n{CLI_USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        for (v, bytes) in [
            (0i64, vec![0x02, 0x01, 0x00]),
            (127, vec![0x02, 0x01, 0x7f]),
            (128, vec![0x02, 0x02, 0x00, 0x80]),
            (256, vec![0x02, 0x02, 0x01, 0x00]),
            (-1, vec![0x02, 0x01, 0xff]),
            (-128, vec![0x02, 0x01, 0x80]),
            (-129, vec![0x02, 0x02, 0xff, 0x7f]),
        ] {
            assert_eq!(enc_int(v), bytes, "{v}");
            assert_eq!(dec_int(&bytes[2..]), v);
        }
        assert_eq!(uint_body(0xffff_ffff), vec![0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(uint_body(0), vec![0]);
    }

    #[test]
    fn oids() {
        let o = parse_oid("1.3.6.1.2.1.1.1.0").unwrap();
        let e = enc_oid(&o);
        assert_eq!(e, vec![0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(dec_oid(&e[2..]).unwrap(), o);
        // Multi-byte sub-identifiers (8072 = 0xbf 0x08).
        let o = vec![1, 3, 6, 1, 4, 1, 8072, 3, 2, 10];
        let e = enc_oid(&o);
        assert_eq!(&e[2..], &[0x2b, 6, 1, 4, 1, 0xbf, 0x08, 3, 2, 10]);
        assert_eq!(dec_oid(&e[2..]).unwrap(), o);
        // Joint-iso arc 2.999 (first byte multi-byte).
        let o = vec![2, 999, 3];
        assert_eq!(dec_oid(&enc_oid(&o)[2..]).unwrap(), o);
        assert_eq!(
            parse_oid("sysDescr.0").unwrap(),
            vec![1, 3, 6, 1, 2, 1, 1, 1, 0]
        );
        assert_eq!(parse_oid(".1.3.6").unwrap(), vec![1, 3, 6]);
        assert!(parse_oid("nosuch").is_err());
        assert_eq!(oid_name(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 3]), "ifDescr.3");
        assert_eq!(oid_name(&[1, 3, 6, 1, 4, 1, 9, 1, 1]), "Cisco (9).1.1");
    }

    #[test]
    fn get_request_matches_net_snmp() {
        // snmpget -v2c -c public host sysDescr.0 with request-id 0x1234.
        let m = enc_message(
            Version::V2c,
            "public",
            PDU_GET,
            0x1234,
            0,
            0,
            &[VarBind {
                oid: vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
                value: Value::Null,
            }],
        );
        let want = [
            0x30, 0x27, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x1a, 0x02, 0x02, 0x12, 0x34, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
            0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ];
        assert_eq!(m, want);
    }

    #[test]
    fn decode_response() {
        let vbs = vec![
            VarBind {
                oid: vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
                value: Value::Str(b"Linux router 5.15".to_vec()),
            },
            VarBind {
                oid: vec![1, 3, 6, 1, 2, 1, 1, 3, 0],
                value: Value::TimeTicks(8_640_123),
            },
            VarBind {
                oid: vec![1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 2],
                value: Value::Counter64(u64::MAX - 5),
            },
            VarBind {
                oid: vec![1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 10, 0, 0, 1],
                value: Value::Ip([10, 0, 0, 1]),
            },
            VarBind {
                oid: vec![1, 3, 6, 1, 2, 1, 1, 9, 9],
                value: Value::NoSuchInstance,
            },
        ];
        let m = enc_message(Version::V1, "c", PDU_RESPONSE, -7, 0, 0, &vbs);
        let d = dec_message(&m).unwrap();
        assert_eq!(d.version, 0);
        assert_eq!(d.community, b"c");
        assert_eq!(d.pdu.request_id, -7);
        assert_eq!(d.pdu.varbinds, vbs);
        assert_eq!(vbs[1].value.to_string(), "1d 0h 0m 1s (8640123)");
        // A long (>127 bytes) value uses the long length form.
        let long = Value::Str(vec![b'a'; 300]);
        let e = enc_value(&long);
        assert_eq!(&e[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert!(dec_message(&m[..m.len() - 3]).is_err());
    }

    #[test]
    fn v3_report_roundtrip() {
        let req = v3_discovery_request(42);
        // Build a matching report the way an agent would.
        let engine = vec![0x80, 0x00, 0x1f, 0x88, 0x80, 1, 2, 3, 4, 5, 6, 7, 8];
        let usm = seq(&[
            enc_octets(&engine),
            enc_int(7),
            enc_int(12345),
            enc_octets(&[]),
            enc_octets(&[]),
            enc_octets(&[]),
        ]);
        let report = enc_pdu(
            PDU_REPORT,
            42,
            0,
            0,
            &[VarBind {
                oid: vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0],
                value: Value::Counter32(3),
            }],
        );
        let resp = seq(&[
            enc_int(3),
            seq(&[enc_int(42), enc_int(65507), enc_octets(&[0]), enc_int(3)]),
            enc_octets(&usm),
            seq(&[enc_octets(&engine), enc_octets(&[]), report]),
        ]);
        assert!(req.len() > 30);
        let e = parse_v3_report(&resp, 42).unwrap();
        assert_eq!(e.engine_id, engine);
        assert_eq!((e.boots, e.time), (7, 12345));
        assert_eq!(e.enterprise, Some(8072));
        assert!(e.format.starts_with("Net-SNMP"));
        assert_eq!(oid_name(&e.reports[0].oid), "usmStatsUnknownEngineIDs.0");
        assert!(parse_v3_report(&resp, 41).is_err());
        let (ent, d) = describe_engine_id(&[0x80, 0, 0, 9, 3, 0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(ent, Some(9));
        assert_eq!(d, "MAC address 00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn set_values_and_deltas() {
        assert_eq!(parse_set_value("i", "-5").unwrap(), Value::Int(-5));
        assert_eq!(
            parse_set_value("a", "10.1.2.3").unwrap(),
            Value::Ip([10, 1, 2, 3])
        );
        assert_eq!(
            parse_set_value("x", "de:ad").unwrap(),
            Value::Str(vec![0xde, 0xad])
        );
        assert!(parse_set_value("q", "1").is_err());
        assert_eq!(counter_delta(10, 25, false), 15);
        assert_eq!(counter_delta(u32::MAX as u64 - 4, 5, false), 10);
        assert_eq!(bytes_text(b"hello\0"), "hello");
        assert_eq!(bytes_text(&[0, 0x1a, 0xff]), "00:1a:ff");
    }
}
