//! OPC UA client (UA Binary over opc.tcp), hand-rolled: HEL/ACK, secure
//! channel (OPN/CLO, renew, chunking) with SecurityPolicy None or a signed /
//! encrypted policy (see `opcua_crypto`), GetEndpoints, FindServers,
//! CreateSession/ActivateSession (anonymous, user name with an encrypted
//! password, or an X.509 user certificate), Browse/BrowseNext, Read,
//! CloseSession; endpoint security assessment; a session worker for the UI
//! and the headless `--opcua`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use rsa::{PrivateKey, PublicKey};

use crate::gateway::{Finding, Level};
use crate::opcua_crypto::{self as uac, ClientIdentity, Keys, Local, Policy};

// ---------------------------------------------------------------- ids

pub const POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";

mod id {
    pub const SERVICE_FAULT: u32 = 397;
    pub const OPN_REQ: u32 = 446;
    pub const OPN_RESP: u32 = 449;
    pub const CLO_REQ: u32 = 452;
    pub const FIND_SERVERS_REQ: u32 = 422;
    pub const FIND_SERVERS_RESP: u32 = 425;
    pub const GET_ENDPOINTS_REQ: u32 = 428;
    pub const GET_ENDPOINTS_RESP: u32 = 431;
    pub const CREATE_SESSION_REQ: u32 = 461;
    pub const CREATE_SESSION_RESP: u32 = 464;
    pub const ACTIVATE_SESSION_REQ: u32 = 467;
    pub const ACTIVATE_SESSION_RESP: u32 = 470;
    pub const CLOSE_SESSION_REQ: u32 = 473;
    pub const CLOSE_SESSION_RESP: u32 = 476;
    pub const BROWSE_REQ: u32 = 527;
    pub const BROWSE_RESP: u32 = 530;
    pub const BROWSE_NEXT_REQ: u32 = 533;
    pub const BROWSE_NEXT_RESP: u32 = 536;
    pub const READ_REQ: u32 = 631;
    pub const READ_RESP: u32 = 634;
    pub const ANONYMOUS_TOKEN: u32 = 321;
    pub const USERNAME_TOKEN: u32 = 324;
    pub const X509_TOKEN: u32 = 327;
}

/// Well-known nodes.
pub const OBJECTS: u32 = 85;
pub const HIERARCHICAL_REFS: u32 = 33;
pub const SERVER_STATE: u32 = 2259;
pub const SERVER_CURRENT_TIME: u32 = 2258;
pub const SERVER_START_TIME: u32 = 2257;
pub const SERVER_PRODUCT_NAME: u32 = 2261;
pub const SERVER_SOFTWARE_VERSION: u32 = 2264;
pub const SERVER_MANUFACTURER: u32 = 2263;

// ---------------------------------------------------------------- NodeId

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ident {
    Num(u32),
    Str(String),
    Guid([u8; 16]),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    pub ns: u16,
    pub id: Ident,
}

impl NodeId {
    pub const fn num(ns: u16, n: u32) -> NodeId {
        NodeId {
            ns,
            id: Ident::Num(n),
        }
    }
    pub fn null() -> NodeId {
        NodeId::num(0, 0)
    }
    pub fn is_null(&self) -> bool {
        *self == NodeId::null()
    }

    /// "i=85", "ns=2;s=Demo.Static", "ns=1;g=…", "ns=1;b=base64"
    pub fn parse(s: &str) -> Result<NodeId, String> {
        let s = s.trim();
        let (ns, rest) = match s.strip_prefix("ns=") {
            Some(r) => {
                let (n, rest) = r.split_once(';').ok_or("expected ns=N;…")?;
                (n.parse::<u16>().map_err(|_| "bad namespace index")?, rest)
            }
            None => (0, s),
        };
        let id = if let Some(v) = rest.strip_prefix("i=") {
            Ident::Num(v.parse().map_err(|_| "bad numeric id")?)
        } else if let Some(v) = rest.strip_prefix("s=") {
            Ident::Str(v.to_string())
        } else if let Some(v) = rest.strip_prefix("g=") {
            Ident::Guid(parse_guid(v)?)
        } else if let Some(v) = rest.strip_prefix("b=") {
            use base64::Engine;
            Ident::Bytes(
                base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .map_err(|_| "bad base64 id")?,
            )
        } else if let Ok(n) = rest.parse::<u32>() {
            Ident::Num(n)
        } else {
            return Err("expected i=, s=, g= or b= (e.g. ns=2;s=Demo)".into());
        };
        Ok(NodeId { ns, id })
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ns != 0 {
            write!(f, "ns={};", self.ns)?;
        }
        match &self.id {
            Ident::Num(n) => write!(f, "i={n}"),
            Ident::Str(s) => write!(f, "s={s}"),
            Ident::Guid(g) => write!(f, "g={}", guid_string(g)),
            Ident::Bytes(b) => {
                use base64::Engine;
                write!(
                    f,
                    "b={}",
                    base64::engine::general_purpose::STANDARD.encode(b)
                )
            }
        }
    }
}

/// Wire layout: Data1 u32 LE, Data2 u16 LE, Data3 u16 LE, Data4 [u8; 8].
pub fn guid_string(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    let tail: String = g[10..].iter().map(|b| format!("{b:02x}")).collect();
    format!("{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{tail}", g[8], g[9])
}

fn parse_guid(s: &str) -> Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err("GUID must have 32 hex digits".into());
    }
    let b: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "bad GUID"))
        .collect::<Result<_, _>>()?;
    let mut g = [0u8; 16];
    g[..4].copy_from_slice(&[b[3], b[2], b[1], b[0]]);
    g[4..6].copy_from_slice(&[b[5], b[4]]);
    g[6..8].copy_from_slice(&[b[7], b[6]]);
    g[8..].copy_from_slice(&b[8..]);
    Ok(g)
}

// ---------------------------------------------------------------- encoder

#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn f64(&mut self, v: f64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn string(&mut self, s: Option<&str>) -> &mut Self {
        self.bytes(s.map(str::as_bytes))
    }
    pub fn bytes(&mut self, b: Option<&[u8]>) -> &mut Self {
        match b {
            None => self.i32(-1),
            Some(b) => {
                self.i32(b.len() as i32);
                self.0.extend_from_slice(b);
                self
            }
        }
    }
    pub fn node_id(&mut self, n: &NodeId) -> &mut Self {
        match &n.id {
            Ident::Num(v) if n.ns == 0 && *v <= 255 => self.u8(0).u8(*v as u8),
            Ident::Num(v) if n.ns <= 255 && *v <= 0xffff => {
                self.u8(1).u8(n.ns as u8).u16(*v as u16)
            }
            Ident::Num(v) => self.u8(2).u16(n.ns).u32(*v),
            Ident::Str(s) => self.u8(3).u16(n.ns).string(Some(s)),
            Ident::Guid(g) => {
                self.u8(4).u16(n.ns);
                self.0.extend_from_slice(g);
                self
            }
            Ident::Bytes(b) => self.u8(5).u16(n.ns).bytes(Some(b)),
        }
    }
    pub fn type_id(&mut self, id: u32) -> &mut Self {
        self.node_id(&NodeId::num(0, id))
    }
    pub fn null_ext(&mut self) -> &mut Self {
        self.u8(0).u8(0).u8(0)
    }
    pub fn empty_array(&mut self) -> &mut Self {
        self.i32(0)
    }
    pub fn localized(&mut self, text: &str) -> &mut Self {
        self.u8(0x02).string(Some(text))
    }
}

// ---------------------------------------------------------------- decoder

pub struct R<'a> {
    b: &'a [u8],
    pub pos: usize,
}

type Res<T> = Result<T, String>;

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        R { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let s = self
            .b
            .get(self.pos..self.pos + n)
            .ok_or_else(|| format!("message truncated at byte {}", self.pos))?;
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Res<bool> {
        Ok(self.u8()? != 0)
    }
    pub fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn i32(&mut self) -> Res<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn i64(&mut self) -> Res<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn f32(&mut self) -> Res<f32> {
        Ok(f32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn f64(&mut self) -> Res<f64> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn bytes(&mut self) -> Res<Option<Vec<u8>>> {
        let n = self.i32()?;
        if n < 0 {
            return Ok(None);
        }
        Ok(Some(self.take(n as usize)?.to_vec()))
    }
    pub fn string(&mut self) -> Res<Option<String>> {
        Ok(self
            .bytes()?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }
    pub fn str(&mut self) -> Res<String> {
        Ok(self.string()?.unwrap_or_default())
    }
    pub fn array<T>(&mut self, mut f: impl FnMut(&mut Self) -> Res<T>) -> Res<Vec<T>> {
        let n = self.i32()?;
        if n <= 0 {
            return Ok(Vec::new());
        }
        if n as usize > self.b.len() {
            return Err(format!("array length {n} exceeds the message"));
        }
        (0..n).map(|_| f(self)).collect()
    }
    pub fn node_id(&mut self) -> Res<NodeId> {
        let enc = self.u8()?;
        self.node_id_body(enc & 0x3f)
    }
    fn node_id_body(&mut self, enc: u8) -> Res<NodeId> {
        Ok(match enc {
            0 => NodeId::num(0, self.u8()? as u32),
            1 => {
                let ns = self.u8()? as u16;
                NodeId::num(ns, self.u16()? as u32)
            }
            2 => {
                let ns = self.u16()?;
                NodeId::num(ns, self.u32()?)
            }
            3 => NodeId {
                ns: self.u16()?,
                id: Ident::Str(self.str()?),
            },
            4 => {
                let ns = self.u16()?;
                NodeId {
                    ns,
                    id: Ident::Guid(self.take(16)?.try_into().unwrap()),
                }
            }
            5 => NodeId {
                ns: self.u16()?,
                id: Ident::Bytes(self.bytes()?.unwrap_or_default()),
            },
            e => return Err(format!("unknown NodeId encoding {e:#x}")),
        })
    }
    /// ExpandedNodeId: the namespace URI / server index are read and dropped.
    pub fn expanded_node_id(&mut self) -> Res<NodeId> {
        let enc = self.u8()?;
        let n = self.node_id_body(enc & 0x3f)?;
        if enc & 0x80 != 0 {
            self.string()?;
        }
        if enc & 0x40 != 0 {
            self.u32()?;
        }
        Ok(n)
    }
    pub fn qualified_name(&mut self) -> Res<(u16, String)> {
        Ok((self.u16()?, self.str()?))
    }
    pub fn localized(&mut self) -> Res<String> {
        let m = self.u8()?;
        if m & 1 != 0 {
            self.string()?;
        }
        Ok(if m & 2 != 0 {
            self.str()?
        } else {
            String::new()
        })
    }
    pub fn diagnostic_info(&mut self) -> Res<()> {
        let m = self.u8()?;
        for bit in [0x01, 0x02, 0x04, 0x08] {
            if m & bit != 0 {
                self.i32()?;
            }
        }
        if m & 0x10 != 0 {
            self.string()?;
        }
        if m & 0x20 != 0 {
            self.u32()?;
        }
        if m & 0x40 != 0 {
            self.diagnostic_info()?;
        }
        Ok(())
    }
    /// (type id, body)
    pub fn extension_object(&mut self) -> Res<(NodeId, Option<Vec<u8>>)> {
        let t = self.node_id()?;
        let enc = self.u8()?;
        let body = match enc {
            0 => None,
            1 | 2 => self.bytes()?,
            e => return Err(format!("bad ExtensionObject encoding {e}")),
        };
        Ok((t, body))
    }
    pub fn variant(&mut self) -> Res<Value> {
        let m = self.u8()?;
        let t = m & 0x3f;
        let v = if m & 0x80 != 0 {
            let items = self.array(|r| r.scalar(t))?;
            Value::Array(t, items)
        } else {
            self.scalar(t)?
        };
        if m & 0x40 != 0 {
            self.array(|r| r.i32())?;
        }
        Ok(v)
    }
    fn scalar(&mut self, t: u8) -> Res<Value> {
        Ok(match t {
            0 => Value::Null,
            1 => Value::Bool(self.bool()?),
            2 => Value::Int(self.u8()? as i8 as i64, t),
            3 => Value::UInt(self.u8()? as u64, t),
            4 => Value::Int(self.u16()? as i16 as i64, t),
            5 => Value::UInt(self.u16()? as u64, t),
            6 => Value::Int(self.i32()? as i64, t),
            7 => Value::UInt(self.u32()? as u64, t),
            8 => Value::Int(self.i64()?, t),
            9 => Value::UInt(self.u64()?, t),
            10 => Value::Float(self.f32()? as f64, t),
            11 => Value::Float(self.f64()?, t),
            12 => Value::Str(self.string()?),
            13 => Value::DateTime(self.i64()?),
            14 => Value::Guid(self.take(16)?.try_into().unwrap()),
            15 => Value::Bytes(self.bytes()?),
            16 => Value::Xml(self.str()?),
            17 => Value::NodeId(self.node_id()?),
            18 => Value::NodeId(self.expanded_node_id()?),
            19 => Value::Status(self.u32()?),
            20 => {
                let (ns, n) = self.qualified_name()?;
                Value::QName(ns, n)
            }
            21 => Value::Text(self.localized()?),
            22 => {
                let (t, b) = self.extension_object()?;
                Value::Ext(t, b.map(|b| b.len()).unwrap_or(0))
            }
            23 => Value::Data(Box::new(self.data_value()?)),
            24 => Value::Variant(Box::new(self.variant()?)),
            25 => {
                self.diagnostic_info()?;
                Value::Diag
            }
            t => return Err(format!("unknown Variant type {t}")),
        })
    }
    pub fn data_value(&mut self) -> Res<DataValue> {
        let m = self.u8()?;
        let mut d = DataValue::default();
        if m & 0x01 != 0 {
            d.value = self.variant()?;
        }
        if m & 0x02 != 0 {
            d.status = self.u32()?;
        }
        if m & 0x04 != 0 {
            d.source_ts = Some(self.i64()?);
        }
        if m & 0x10 != 0 {
            self.u16()?;
        }
        if m & 0x08 != 0 {
            d.server_ts = Some(self.i64()?);
        }
        if m & 0x20 != 0 {
            self.u16()?;
        }
        Ok(d)
    }
    /// ResponseHeader → ServiceResult.
    pub fn response_header(&mut self) -> Res<u32> {
        self.i64()?;
        self.u32()?;
        let result = self.u32()?;
        self.diagnostic_info()?;
        self.array(|r| r.string())?;
        self.extension_object()?;
        Ok(result)
    }
}

// ---------------------------------------------------------------- values

#[derive(Clone, Debug, PartialEq, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    /// (value, variant type id)
    Int(i64, u8),
    UInt(u64, u8),
    Float(f64, u8),
    Str(Option<String>),
    DateTime(i64),
    Guid([u8; 16]),
    Bytes(Option<Vec<u8>>),
    Xml(String),
    NodeId(NodeId),
    Status(u32),
    QName(u16, String),
    Text(String),
    /// Structure: (type id, body length)
    Ext(NodeId, usize),
    Data(Box<DataValue>),
    Variant(Box<Value>),
    Diag,
    Array(u8, Vec<Value>),
}

pub fn variant_type_name(t: u8) -> &'static str {
    match t {
        0 => "Null",
        1 => "Boolean",
        2 => "SByte",
        3 => "Byte",
        4 => "Int16",
        5 => "UInt16",
        6 => "Int32",
        7 => "UInt32",
        8 => "Int64",
        9 => "UInt64",
        10 => "Float",
        11 => "Double",
        12 => "String",
        13 => "DateTime",
        14 => "Guid",
        15 => "ByteString",
        16 => "XmlElement",
        17 => "NodeId",
        18 => "ExpandedNodeId",
        19 => "StatusCode",
        20 => "QualifiedName",
        21 => "LocalizedText",
        22 => "ExtensionObject",
        23 => "DataValue",
        24 => "Variant",
        25 => "DiagnosticInfo",
        _ => "?",
    }
}

impl Value {
    pub fn type_name(&self) -> String {
        match self {
            Value::Null => "Null".into(),
            Value::Bool(_) => "Boolean".into(),
            Value::Int(_, t) | Value::UInt(_, t) | Value::Float(_, t) => {
                variant_type_name(*t).into()
            }
            Value::Str(_) => "String".into(),
            Value::DateTime(_) => "DateTime".into(),
            Value::Guid(_) => "Guid".into(),
            Value::Bytes(_) => "ByteString".into(),
            Value::Xml(_) => "XmlElement".into(),
            Value::NodeId(_) => "NodeId".into(),
            Value::Status(_) => "StatusCode".into(),
            Value::QName(..) => "QualifiedName".into(),
            Value::Text(_) => "LocalizedText".into(),
            Value::Ext(..) => "ExtensionObject".into(),
            Value::Data(_) => "DataValue".into(),
            Value::Variant(_) => "Variant".into(),
            Value::Diag => "DiagnosticInfo".into(),
            Value::Array(t, v) => format!("{}[{}]", variant_type_name(*t), v.len()),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Value::Null => "null".into(),
            Value::Bool(b) => b.to_string(),
            Value::Int(v, _) => v.to_string(),
            Value::UInt(v, _) => v.to_string(),
            Value::Float(v, _) => {
                if v.fract() == 0.0 && v.abs() < 1e15 {
                    format!("{v:.1}")
                } else {
                    format!("{v}")
                }
            }
            Value::Str(s) => s.clone().unwrap_or_else(|| "null".into()),
            Value::DateTime(t) => datetime_string(*t),
            Value::Guid(g) => guid_string(g),
            Value::Bytes(None) => "null".into(),
            Value::Bytes(Some(b)) => {
                let hex: String = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
                if b.len() > 32 {
                    format!("{hex}… ({} bytes)", b.len())
                } else {
                    hex
                }
            }
            Value::Xml(s) => s.clone(),
            Value::NodeId(n) => n.to_string(),
            Value::Status(s) => status_name(*s),
            Value::QName(ns, n) => {
                if *ns == 0 {
                    n.clone()
                } else {
                    format!("{ns}:{n}")
                }
            }
            Value::Text(t) => t.clone(),
            Value::Ext(t, n) => format!("structure {} ({n} bytes)", data_type_name(t)),
            Value::Data(d) => d.value.display(),
            Value::Variant(v) => v.display(),
            Value::Diag => "diagnostic info".into(),
            Value::Array(_, v) => {
                let items: Vec<String> = v.iter().take(20).map(|x| x.display()).collect();
                format!(
                    "[{}{}]",
                    items.join(", "),
                    if v.len() > 20 { ", …" } else { "" }
                )
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct DataValue {
    pub value: Value,
    pub status: u32,
    pub source_ts: Option<i64>,
    pub server_ts: Option<i64>,
}

/// OPC UA DateTime (100 ns ticks since 1601-01-01) → "2024-05-01 12:00:00.000 UTC".
pub fn datetime_string(ticks: i64) -> String {
    if ticks <= 0 {
        return "-".into();
    }
    let unix_ms = ticks / 10_000 - 11_644_473_600_000;
    let secs = unix_ms.div_euclid(1000);
    let ms = unix_ms.rem_euclid(1000);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!(
        "{}-{m:02}-{d:02} {:02}:{:02}:{:02}.{ms:03} UTC",
        if m <= 2 { y + 1 } else { y },
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn now_ticks() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_millis() as i64 + 11_644_473_600_000) * 10_000
}

pub fn status_name(code: u32) -> String {
    let name = match code {
        0x0000_0000 => "Good",
        0x8001_0000 => "BadUnexpectedError",
        0x8002_0000 => "BadInternalError",
        0x8003_0000 => "BadOutOfMemory",
        0x8004_0000 => "BadResourceUnavailable",
        0x8005_0000 => "BadCommunicationError",
        0x8006_0000 => "BadEncodingError",
        0x8007_0000 => "BadDecodingError",
        0x8008_0000 => "BadEncodingLimitsExceeded",
        0x800A_0000 => "BadTimeout",
        0x800B_0000 => "BadServiceUnsupported",
        0x800C_0000 => "BadShutdown",
        0x800D_0000 => "BadServerNotConnected",
        0x800E_0000 => "BadServerHalted",
        0x800F_0000 => "BadNothingToDo",
        0x8010_0000 => "BadTooManyOperations",
        0x8011_0000 => "BadDataTypeIdUnknown",
        0x8012_0000 => "BadCertificateInvalid",
        0x8013_0000 => "BadSecurityChecksFailed",
        0x8014_0000 => "BadCertificateTimeInvalid",
        0x8015_0000 => "BadCertificateIssuerTimeInvalid",
        0x8016_0000 => "BadCertificateHostNameInvalid",
        0x8017_0000 => "BadCertificateUriInvalid",
        0x8018_0000 => "BadCertificateUseNotAllowed",
        0x8019_0000 => "BadCertificateIssuerUseNotAllowed",
        0x801A_0000 => "BadCertificateUntrusted",
        0x801B_0000 => "BadCertificateRevocationUnknown",
        0x801C_0000 => "BadCertificateIssuerRevocationUnknown",
        0x801D_0000 => "BadCertificateRevoked",
        0x801E_0000 => "BadCertificateIssuerRevoked",
        0x801F_0000 => "BadUserAccessDenied",
        0x8020_0000 => "BadIdentityTokenInvalid",
        0x8021_0000 => "BadIdentityTokenRejected",
        0x8022_0000 => "BadSecureChannelIdInvalid",
        0x8023_0000 => "BadInvalidTimestamp",
        0x8024_0000 => "BadNonceInvalid",
        0x8025_0000 => "BadSessionIdInvalid",
        0x8026_0000 => "BadSessionClosed",
        0x8027_0000 => "BadSessionNotActivated",
        0x802A_0000 => "BadRequestHeaderInvalid",
        0x8031_0000 => "BadNoCommunication",
        0x8032_0000 => "BadWaitingForInitialData",
        0x8033_0000 => "BadNodeIdInvalid",
        0x8034_0000 => "BadNodeIdUnknown",
        0x8035_0000 => "BadAttributeIdInvalid",
        0x8036_0000 => "BadIndexRangeInvalid",
        0x8037_0000 => "BadIndexRangeNoData",
        0x803A_0000 => "BadNotReadable",
        0x803B_0000 => "BadNotWritable",
        0x803C_0000 => "BadOutOfRange",
        0x803D_0000 => "BadNotSupported",
        0x803E_0000 => "BadNotFound",
        0x8040_0000 => "BadNotImplemented",
        0x8054_0000 => "BadSecurityModeRejected",
        0x8055_0000 => "BadSecurityPolicyRejected",
        0x8056_0000 => "BadTooManySessions",
        0x8057_0000 => "BadUserSignatureInvalid",
        0x8058_0000 => "BadApplicationSignatureInvalid",
        0x807E_0000 => "BadTcpServerTooBusy",
        0x807F_0000 => "BadTcpMessageTypeInvalid",
        0x8080_0000 => "BadTcpSecureChannelUnknown",
        0x8081_0000 => "BadTcpMessageTooLarge",
        0x8082_0000 => "BadTcpNotEnoughResources",
        0x8083_0000 => "BadTcpInternalError",
        0x8084_0000 => "BadTcpEndpointUrlInvalid",
        0x8085_0000 => "BadRequestInterrupted",
        0x8086_0000 => "BadRequestTimeout",
        0x8087_0000 => "BadSecureChannelClosed",
        0x8088_0000 => "BadSecureChannelTokenUnknown",
        0x8089_0000 => "BadSequenceNumberInvalid",
        0x80AB_0000 => "BadInvalidArgument",
        0x80AC_0000 => "BadConnectionRejected",
        0x80AD_0000 => "BadDisconnect",
        0x80AE_0000 => "BadConnectionClosed",
        0x80AF_0000 => "BadInvalidState",
        0x80B0_0000 => "BadEndOfStream",
        0x80B8_0000 => "BadRequestTooLarge",
        0x80B9_0000 => "BadResponseTooLarge",
        0x80BE_0000 => "BadProtocolVersionUnsupported",
        _ => "",
    };
    if !name.is_empty() {
        return name.to_string();
    }
    match code >> 30 {
        0 => format!("Good ({code:#010x})"),
        1 => format!("Uncertain ({code:#010x})"),
        _ => format!("Bad ({code:#010x})"),
    }
}

pub fn is_good(code: u32) -> bool {
    code >> 30 == 0
}

pub fn node_class_name(c: u32) -> &'static str {
    match c {
        1 => "Object",
        2 => "Variable",
        4 => "Method",
        8 => "ObjectType",
        16 => "VariableType",
        32 => "ReferenceType",
        64 => "DataType",
        128 => "View",
        _ => "Unspecified",
    }
}

pub fn attribute_name(a: u32) -> &'static str {
    match a {
        1 => "NodeId",
        2 => "NodeClass",
        3 => "BrowseName",
        4 => "DisplayName",
        5 => "Description",
        6 => "WriteMask",
        7 => "UserWriteMask",
        8 => "IsAbstract",
        9 => "Symmetric",
        10 => "InverseName",
        11 => "ContainsNoLoops",
        12 => "EventNotifier",
        13 => "Value",
        14 => "DataType",
        15 => "ValueRank",
        16 => "ArrayDimensions",
        17 => "AccessLevel",
        18 => "UserAccessLevel",
        19 => "MinimumSamplingInterval",
        20 => "Historizing",
        21 => "Executable",
        22 => "UserExecutable",
        _ => "?",
    }
}

pub fn ref_type_name(n: &NodeId) -> String {
    if n.ns == 0
        && let Ident::Num(i) = n.id
    {
        let s = match i {
            33 => "HierarchicalReferences",
            35 => "Organizes",
            36 => "HasEventSource",
            37 => "HasModellingRule",
            40 => "HasTypeDefinition",
            41 => "GeneratesEvent",
            44 => "Aggregates",
            45 => "HasSubtype",
            46 => "HasProperty",
            47 => "HasComponent",
            48 => "HasNotifier",
            49 => "HasOrderedComponent",
            _ => "",
        };
        if !s.is_empty() {
            return s.to_string();
        }
    }
    n.to_string()
}

pub fn data_type_name(n: &NodeId) -> String {
    if n.ns == 0
        && let Ident::Num(i) = n.id
    {
        let s = match i {
            1..=25 => variant_type_name(i as u8),
            26 => "Number",
            27 => "Integer",
            28 => "UInteger",
            29 => "Enumeration",
            290 => "Duration",
            294 => "UtcTime",
            295 => "LocaleId",
            338 => "BuildInfo",
            852 => "ServerState",
            862 => "ServerStatusDataType",
            884 => "Range",
            887 => "EUInformation",
            7594 => "EnumValueType",
            _ => "",
        };
        if !s.is_empty() {
            return s.to_string();
        }
    }
    n.to_string()
}

pub fn access_level_text(v: u64) -> String {
    let names = [
        (1, "read"),
        (2, "write"),
        (4, "history read"),
        (8, "history write"),
        (16, "semantic change"),
        (32, "status write"),
        (64, "timestamp write"),
    ];
    let s: Vec<&str> = names
        .iter()
        .filter(|(b, _)| v & b != 0)
        .map(|(_, n)| *n)
        .collect();
    if s.is_empty() {
        "none".into()
    } else {
        s.join(", ")
    }
}

fn server_state_name(v: i64) -> &'static str {
    match v {
        0 => "Running",
        1 => "Failed",
        2 => "NoConfiguration",
        3 => "Suspended",
        4 => "Shutdown",
        5 => "Test",
        6 => "CommunicationFault",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------- service types

#[derive(Clone, Debug, Default)]
pub struct AppDescription {
    pub uri: String,
    pub product_uri: String,
    pub name: String,
    /// 0 Server, 1 Client, 2 ClientAndServer, 3 DiscoveryServer
    pub app_type: u32,
    pub discovery_urls: Vec<String>,
}

pub fn app_type_name(t: u32) -> &'static str {
    match t {
        0 => "Server",
        1 => "Client",
        2 => "Client and server",
        3 => "Discovery server",
        _ => "?",
    }
}

#[derive(Clone, Debug, Default)]
pub struct TokenPolicy {
    pub policy_id: String,
    /// 0 Anonymous, 1 UserName, 2 Certificate, 3 IssuedToken
    pub token_type: u32,
    pub security_policy: String,
}

pub fn token_type_name(t: u32) -> &'static str {
    match t {
        0 => "Anonymous",
        1 => "User name",
        2 => "Certificate",
        3 => "Issued token",
        _ => "?",
    }
}

#[derive(Clone, Debug, Default)]
pub struct Endpoint {
    pub url: String,
    pub server: AppDescription,
    pub cert: Vec<u8>,
    /// 1 None, 2 Sign, 3 SignAndEncrypt
    pub mode: u32,
    pub policy: String,
    pub tokens: Vec<TokenPolicy>,
    pub transport: String,
    pub level: u8,
}

pub fn mode_name(m: u32) -> &'static str {
    match m {
        1 => "None",
        2 => "Sign",
        3 => "SignAndEncrypt",
        _ => "Invalid",
    }
}

/// "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256" → "Basic256Sha256"
pub fn policy_short(uri: &str) -> String {
    if uri.is_empty() {
        return "(endpoint's)".into();
    }
    uri.rsplit('#').next().unwrap_or(uri).to_string()
}

fn app_description(r: &mut R) -> Res<AppDescription> {
    let uri = r.str()?;
    let product_uri = r.str()?;
    let name = r.localized()?;
    let app_type = r.u32()?;
    r.string()?;
    r.string()?;
    let discovery_urls = r.array(|r| r.str())?;
    Ok(AppDescription {
        uri,
        product_uri,
        name,
        app_type,
        discovery_urls,
    })
}

fn endpoint(r: &mut R) -> Res<Endpoint> {
    let url = r.str()?;
    let server = app_description(r)?;
    let cert = r.bytes()?.unwrap_or_default();
    let mode = r.u32()?;
    let policy = r.str()?;
    let tokens = r.array(|r| {
        let policy_id = r.str()?;
        let token_type = r.u32()?;
        r.string()?;
        r.string()?;
        let security_policy = r.str()?;
        Ok(TokenPolicy {
            policy_id,
            token_type,
            security_policy,
        })
    })?;
    let transport = r.str()?;
    let level = r.u8()?;
    Ok(Endpoint {
        url,
        server,
        cert,
        mode,
        policy,
        tokens,
        transport,
        level,
    })
}

#[derive(Clone, Debug)]
pub struct Reference {
    pub ref_type: NodeId,
    pub forward: bool,
    pub node: NodeId,
    pub browse_name: (u16, String),
    pub display: String,
    pub class: u32,
    pub type_def: NodeId,
}

// ---------------------------------------------------------------- URL

/// "opc.tcp://host:4840/path" → (host, port)
pub fn parse_url(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .trim()
        .strip_prefix("opc.tcp://")
        .ok_or("URL must start with opc.tcp://")?;
    let auth = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(r) = auth.strip_prefix('[') {
        let end = r.find(']').ok_or("bad IPv6 address")?;
        let port = r[end + 1..]
            .strip_prefix(':')
            .map(|p| p.parse().map_err(|_| "bad port"))
            .transpose()?;
        (r[..end].to_string(), port)
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.parse().map_err(|_| "bad port")?)),
            None => (auth.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    Ok((host, port.unwrap_or(4840)))
}

/// Accepts "host", "host:port" or a full URL.
pub fn normalize_url(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("opc.tcp://") {
        s.to_string()
    } else {
        format!("opc.tcp://{s}")
    }
}

fn url_host(url: &str) -> String {
    parse_url(url)
        .map(|(h, _)| h.to_ascii_lowercase())
        .unwrap_or_default()
}

// ---------------------------------------------------------------- transport

#[derive(Clone, Debug, Default)]
pub struct AckInfo {
    pub version: u32,
    pub recv_buf: u32,
    pub send_buf: u32,
    pub max_msg: u32,
    pub max_chunks: u32,
}

pub fn hello(url: &str) -> Vec<u8> {
    let mut w = W::default();
    w.u32(0)
        .u32(65536)
        .u32(65536)
        .u32(0)
        .u32(0)
        .string(Some(url));
    frame(b"HEL", b'F', &w.0)
}

fn frame(kind: &[u8; 3], chunk: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend_from_slice(kind);
    out.push(chunk);
    out.extend_from_slice(&((body.len() + 8) as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// ERR message → text.
fn err_text(body: &[u8]) -> String {
    let mut r = R::new(body);
    let code = r.u32().unwrap_or(0);
    let reason = r.str().unwrap_or_default();
    let hint = match code {
        0x8084_0000 => " — the server does not know this endpoint URL path",
        0x807E_0000 => " — too many connections",
        0x80BE_0000 => " — protocol version not supported",
        _ => "",
    };
    format!(
        "server error {}{}{hint}",
        status_name(code),
        if reason.is_empty() {
            String::new()
        } else {
            format!(": {reason}")
        }
    )
}

/// Security for a signed / encrypted channel.
#[derive(Clone)]
pub struct Security {
    pub policy: Policy,
    /// 2 Sign, 3 SignAndEncrypt
    pub mode: u32,
    pub identity: ClientIdentity,
    /// The server's certificate (from the endpoint description).
    pub server_cert: Vec<u8>,
}

struct SecState {
    s: Security,
    server_key: PublicKey,
}

/// Symmetric keys of one security token: (token id, client→server,
/// server→client).
type TokenKeys = (u32, Keys, Keys);

pub struct Client {
    s: TcpStream,
    pub addr: SocketAddr,
    pub url: String,
    pub ack: AckInfo,
    channel_id: u32,
    token_id: u32,
    seq: u32,
    req_id: u32,
    handle: u32,
    auth: NodeId,
    channel_opened: Instant,
    lifetime_ms: u32,
    timeout: Duration,
    pub connect_ms: f64,
    sec: Option<SecState>,
    /// Newest last; the previous token is kept for late server messages.
    keys: Vec<TokenKeys>,
    /// Last server nonce of the session (CreateSession / ActivateSession).
    server_nonce: Vec<u8>,
    /// Server certificate from CreateSession (for user token encryption).
    session_cert: Vec<u8>,
}

impl Client {
    pub fn connect(url: &str, timeout: Duration) -> Res<Client> {
        Client::connect_with(url, timeout, None)
    }

    /// Connect and open a secure channel (`None` = SecurityPolicy None).
    pub fn connect_with(url: &str, timeout: Duration, security: Option<Security>) -> Res<Client> {
        let sec = match security {
            Some(s) if s.policy != Policy::None => {
                if !(2..=3).contains(&s.mode) {
                    return Err("security mode must be Sign or SignAndEncrypt".into());
                }
                if s.server_cert.is_empty() {
                    return Err("the endpoint has no server certificate".into());
                }
                let server_key = uac::cert_public_key(&s.server_cert)?;
                let bits = rsa::traits::PublicKeyParts::size(&s.identity.key) * 8;
                let (lo, hi) = s.policy.key_bits();
                if bits < lo || bits > hi {
                    return Err(format!(
                        "{} needs a {lo}–{hi}-bit client key; this certificate has {bits} bits",
                        s.policy.name()
                    ));
                }
                Some(SecState { s, server_key })
            }
            _ => None,
        };
        let (host, port) = parse_url(url)?;
        let t0 = Instant::now();
        let (s, addr) = crate::tls::connect(&host, port, timeout)?;
        let connect_ms = t0.elapsed().as_secs_f64() * 1000.0;
        s.set_nodelay(true).ok();
        let mut c = Client {
            s,
            addr,
            url: url.to_string(),
            ack: AckInfo::default(),
            channel_id: 0,
            token_id: 0,
            seq: 0,
            req_id: 0,
            handle: 0,
            auth: NodeId::null(),
            channel_opened: Instant::now(),
            lifetime_ms: 3_600_000,
            timeout,
            connect_ms,
            sec,
            keys: Vec::new(),
            server_nonce: Vec::new(),
            session_cert: Vec::new(),
        };
        c.write(&hello(url))?;
        let (kind, _, body) = c.read_chunk()?;
        match &kind {
            b"ACK" => {
                let mut r = R::new(&body);
                c.ack = AckInfo {
                    version: r.u32()?,
                    recv_buf: r.u32()?,
                    send_buf: r.u32()?,
                    max_msg: r.u32()?,
                    max_chunks: r.u32()?,
                };
            }
            b"ERR" => return Err(err_text(&body)),
            k => {
                return Err(format!(
                    "not an OPC UA server (got {:?} instead of ACK)",
                    String::from_utf8_lossy(k)
                ));
            }
        }
        c.open_channel(false)?;
        Ok(c)
    }

    /// "Basic256Sha256 / SignAndEncrypt" or "None".
    pub fn security_text(&self) -> String {
        match &self.sec {
            Some(st) => format!("{} / {}", st.s.policy.name(), mode_name(st.s.mode)),
            None => "None".into(),
        }
    }

    fn policy(&self) -> Policy {
        self.sec
            .as_ref()
            .map(|s| s.s.policy)
            .unwrap_or(Policy::None)
    }

    fn encrypting(&self) -> bool {
        self.sec.as_ref().is_some_and(|s| s.s.mode == 3)
    }

    fn write(&mut self, b: &[u8]) -> Res<()> {
        self.s
            .write_all(b)
            .map_err(|e| format!("send: {}", crate::websocket::io_err(&e)))
    }

    /// (message type, chunk type, body after the 8-byte header)
    fn read_chunk(&mut self) -> Res<([u8; 3], u8, Vec<u8>)> {
        let mut h = [0u8; 8];
        self.s.read_exact(&mut h).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                "the server closed the connection".to_string()
            } else {
                crate::websocket::io_err(&e)
            }
        })?;
        let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if !(8..=16 << 20).contains(&size) {
            return Err(format!("bad message size {size} (not OPC UA binary?)"));
        }
        let mut body = vec![0u8; size - 8];
        self.s
            .read_exact(&mut body)
            .map_err(|e| crate::websocket::io_err(&e))?;
        Ok(([h[0], h[1], h[2]], h[3], body))
    }

    fn request_header(&mut self, w: &mut W) {
        self.handle += 1;
        let auth = self.auth.clone();
        w.node_id(&auth)
            .i64(now_ticks())
            .u32(self.handle)
            .u32(0)
            .string(None)
            .u32(self.timeout.as_millis() as u32)
            .null_ext();
    }

    /// Send a request (split into chunks if needed); returns the request id.
    fn send_request(&mut self, kind: &[u8; 3], body: &[u8]) -> Res<u32> {
        self.req_id += 1;
        let req = self.req_id;
        if kind == b"OPN" {
            self.seq += 1;
            let mut payload = self.seq.to_le_bytes().to_vec();
            payload.extend_from_slice(&req.to_le_bytes());
            payload.extend_from_slice(body);
            let f = match &self.sec {
                Some(st) => uac::seal_asym(
                    st.s.policy,
                    b'F',
                    self.channel_id,
                    Some(&Local {
                        cert: &st.s.identity.cert,
                        key: &st.s.identity.key,
                    }),
                    &st.s.server_cert,
                    Some(&st.server_key),
                    &payload,
                )?,
                None => uac::seal_asym(Policy::None, b'F', 0, None, &[], None, &payload)?,
            };
            if f.len() > self.ack.recv_buf.max(8192) as usize {
                return Err(format!(
                    "OpenSecureChannel request ({} bytes) exceeds the server's buffer ({})",
                    f.len(),
                    self.ack.recv_buf
                ));
            }
            self.write(&f)?;
            return Ok(req);
        }
        let limit = if self.ack.recv_buf >= 8192 {
            self.ack.recv_buf as usize
        } else {
            8192
        };
        let (policy, enc) = (self.policy(), self.encrypting());
        let max_body = uac::max_sym_body(policy, enc, limit);
        let parts: Vec<&[u8]> = if body.is_empty() {
            vec![body]
        } else {
            body.chunks(max_body).collect()
        };
        let last = parts.len() - 1;
        let keys = self.keys.last().map(|k| k.1.clone());
        for (i, part) in parts.into_iter().enumerate() {
            self.seq += 1;
            let mut payload = self.seq.to_le_bytes().to_vec();
            payload.extend_from_slice(&req.to_le_bytes());
            payload.extend_from_slice(part);
            let f = uac::seal_sym(
                policy,
                enc,
                kind,
                if i == last { b'F' } else { b'C' },
                self.channel_id,
                self.token_id,
                keys.as_ref(),
                &payload,
            )?;
            self.write(&f)?;
        }
        Ok(req)
    }

    /// Verify/decrypt a received chunk → sequence header + body.
    fn open_chunk(&self, kind: &[u8; 3], chunk: u8, body: &[u8]) -> Res<Vec<u8>> {
        let mut frame = Vec::with_capacity(body.len() + 8);
        frame.extend_from_slice(kind);
        frame.push(chunk);
        frame.extend_from_slice(&((body.len() + 8) as u32).to_le_bytes());
        frame.extend_from_slice(body);
        if kind == b"OPN" {
            let local = self.sec.as_ref().map(|st| Local {
                cert: &st.s.identity.cert,
                key: &st.s.identity.key,
            });
            let (h, payload) = uac::open_asym(&frame, local.as_ref())?;
            if self.channel_id != 0 && h.channel_id != self.channel_id {
                return Err(format!(
                    "OPN response for channel {} (ours is {})",
                    h.channel_id, self.channel_id
                ));
            }
            if let Some(st) = &self.sec {
                if h.policy_uri != st.s.policy.uri() {
                    return Err(format!(
                        "the server answered with security policy {}",
                        policy_short(&h.policy_uri)
                    ));
                }
                if h.sender_cert != st.s.server_cert {
                    return Err(
                        "the server signed the channel with a different certificate than its endpoint advertises"
                            .into(),
                    );
                }
            }
            return Ok(payload);
        }
        if body.len() < 16 {
            return Err("short chunk".into());
        }
        let token = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let keys = match &self.sec {
            Some(_) => Some(
                self.keys
                    .iter()
                    .rev()
                    .find(|k| k.0 == token)
                    .map(|k| &k.2)
                    .ok_or_else(|| format!("message for unknown security token {token}"))?,
            ),
            None => None,
        };
        uac::open_sym(self.policy(), self.encrypting(), &frame, keys)
    }

    /// Receive the full response for `req` (reassembling chunks).
    fn recv_response(&mut self, req: u32) -> Res<Vec<u8>> {
        let mut body = Vec::new();
        let deadline = Instant::now() + self.timeout + Duration::from_secs(2);
        loop {
            if Instant::now() > deadline {
                return Err("timeout waiting for the response".into());
            }
            let (kind, chunk, b) = self.read_chunk()?;
            if &kind == b"ERR" {
                return Err(err_text(&b));
            }
            let payload = self.open_chunk(&kind, chunk, &b)?;
            let mut r = R::new(&payload);
            r.u32()?; // sequence number
            let rid = r.u32()?;
            if chunk == b'A' {
                let code = r.u32().unwrap_or(0);
                let reason = r.str().unwrap_or_default();
                return Err(format!(
                    "server aborted the message: {} {reason}",
                    status_name(code)
                ));
            }
            if rid != req {
                continue; // a late answer to an earlier request
            }
            body.extend_from_slice(&payload[r.pos..]);
            if body.len() > 64 << 20 {
                return Err("response larger than 64 MiB".into());
            }
            if chunk == b'F' {
                return Ok(body);
            }
        }
    }

    /// Run one service: `build` writes the fields after the RequestHeader.
    /// Returns the response bytes and the position after the ResponseHeader.
    fn call(
        &mut self,
        req_type: u32,
        resp_type: u32,
        build: impl FnOnce(&mut W),
    ) -> Res<(Vec<u8>, usize)> {
        self.maybe_renew()?;
        let mut w = W::default();
        w.type_id(req_type);
        self.request_header(&mut w);
        build(&mut w);
        let req = self.send_request(b"MSG", &w.0)?;
        let body = self.recv_response(req)?;
        let mut r = R::new(&body);
        let t = r.node_id()?;
        let result = r.response_header()?;
        if t == NodeId::num(0, id::SERVICE_FAULT) {
            return Err(format!("service fault: {}", status_name(result)));
        }
        if t != NodeId::num(0, resp_type) {
            return Err(format!("unexpected response type {t}"));
        }
        if !is_good(result) {
            return Err(format!("service failed: {}", status_name(result)));
        }
        let pos = r.pos;
        Ok((body, pos))
    }

    fn open_channel(&mut self, renew: bool) -> Res<()> {
        let policy = self.policy();
        let mode = self.sec.as_ref().map(|s| s.s.mode).unwrap_or(1);
        let client_nonce = uac::random(policy.nonce_len());
        let mut w = W::default();
        w.type_id(id::OPN_REQ);
        let saved = std::mem::replace(&mut self.auth, NodeId::null());
        self.request_header(&mut w);
        self.auth = saved;
        w.u32(0)
            .u32(renew as u32)
            .u32(mode)
            .bytes((!client_nonce.is_empty()).then_some(&client_nonce[..]))
            .u32(self.lifetime_ms);
        let req = self.send_request(b"OPN", &w.0)?;
        let body = self.recv_response(req)?;
        let mut r = R::new(&body);
        let t = r.node_id()?;
        let result = r.response_header()?;
        if t != NodeId::num(0, id::OPN_RESP) || !is_good(result) {
            return Err(format!(
                "OpenSecureChannel refused: {}{}",
                status_name(result),
                if self.sec.is_none() {
                    " (the server may not offer SecurityPolicy None)"
                } else {
                    ""
                }
            ));
        }
        r.u32()?;
        self.channel_id = r.u32()?;
        self.token_id = r.u32()?;
        r.i64()?;
        self.lifetime_ms = r.u32()?.max(10_000);
        let server_nonce = r.bytes()?.unwrap_or_default();
        if self.sec.is_some() {
            if server_nonce.len() != policy.nonce_len() {
                return Err(format!(
                    "server nonce has {} bytes, {} expects {}",
                    server_nonce.len(),
                    policy.name(),
                    policy.nonce_len()
                ));
            }
            let client = uac::derive(policy, &server_nonce, &client_nonce);
            let server = uac::derive(policy, &client_nonce, &server_nonce);
            self.keys.push((self.token_id, client, server));
            if self.keys.len() > 2 {
                self.keys.remove(0);
            }
        }
        self.channel_opened = Instant::now();
        Ok(())
    }

    fn maybe_renew(&mut self) -> Res<()> {
        if self.channel_opened.elapsed().as_millis() as u64 > self.lifetime_ms as u64 * 3 / 4 {
            self.open_channel(true)?;
        }
        Ok(())
    }

    pub fn get_endpoints(&mut self) -> Res<Vec<Endpoint>> {
        let url = self.url.clone();
        let (b, pos) = self.call(id::GET_ENDPOINTS_REQ, id::GET_ENDPOINTS_RESP, |w| {
            w.string(Some(&url)).empty_array().empty_array();
        })?;
        let mut r = R::new(&b);
        r.pos = pos;
        r.array(endpoint)
    }

    pub fn find_servers(&mut self) -> Res<Vec<AppDescription>> {
        let url = self.url.clone();
        let (b, pos) = self.call(id::FIND_SERVERS_REQ, id::FIND_SERVERS_RESP, |w| {
            w.string(Some(&url)).empty_array().empty_array();
        })?;
        let mut r = R::new(&b);
        r.pos = pos;
        r.array(app_description)
    }

    /// CreateSession; returns (session id, revised timeout ms). On a secured
    /// channel the server's signature over our certificate and nonce is
    /// verified.
    pub fn create_session(&mut self) -> Res<(NodeId, f64)> {
        let url = self.url.clone();
        let nonce = uac::random(32);
        let name = format!(
            "network-analyser-{}",
            nonce[..3]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let (app_uri, client_cert) = match &self.sec {
            Some(st) => (st.s.identity.app_uri.clone(), st.s.identity.cert.clone()),
            None => ("urn:network-analyser:client".to_string(), Vec::new()),
        };
        let (b, pos) = self.call(id::CREATE_SESSION_REQ, id::CREATE_SESSION_RESP, |w| {
            w.string(Some(&app_uri))
                .string(Some("urn:network-analyser"))
                .localized("Network Analyser")
                .u32(1)
                .string(None)
                .string(None)
                .empty_array();
            w.string(None)
                .string(Some(&url))
                .string(Some(&name))
                .bytes(Some(&nonce))
                .bytes((!client_cert.is_empty()).then_some(&client_cert[..]))
                .f64(120_000.0)
                .u32(0);
        })?;
        let mut r = R::new(&b);
        r.pos = pos;
        let session = r.node_id()?;
        self.auth = r.node_id()?;
        let timeout = r.f64()?;
        self.server_nonce = r.bytes()?.unwrap_or_default();
        self.session_cert = r.bytes()?.unwrap_or_default();
        r.array(endpoint)?;
        r.array(|r| {
            r.bytes()?;
            r.bytes()
        })?;
        let alg = r.str()?;
        let sig = r.bytes()?.unwrap_or_default();
        if let Some(st) = &self.sec {
            if self.session_cert != st.s.server_cert {
                return Err(
                    "CreateSession returned a different server certificate than the endpoint"
                        .into(),
                );
            }
            if self.server_nonce.len() < 32 {
                return Err("the server sent no (or a short) session nonce".into());
            }
            let mut data = client_cert.clone();
            data.extend_from_slice(&nonce);
            uac::rsa_verify(st.s.policy, &st.server_key, &data, &sig).map_err(|_| {
                format!(
                    "BadApplicationSignatureInvalid: the server's session signature ({}) does not verify",
                    if alg.is_empty() { "none" } else { &alg }
                )
            })?;
        }
        Ok((session, timeout))
    }

    /// Server certificate to encrypt user tokens for.
    fn token_cert(&self) -> Vec<u8> {
        match &self.sec {
            Some(st) => st.s.server_cert.clone(),
            None => self.session_cert.clone(),
        }
    }

    /// ActivateSession with the client signature (secured channels) and the
    /// identity token (password encrypted per the token's security policy).
    pub fn activate_session(&mut self, identity: &Identity) -> Res<()> {
        let channel_policy = self.policy();
        let token_policy = |p: &str| -> Policy {
            if p.is_empty() {
                channel_policy
            } else {
                Policy::from_uri(p).unwrap_or(channel_policy)
            }
        };
        let mut tok = W::default();
        let mut token_sig: Option<(String, Vec<u8>)> = None;
        let type_id = match identity {
            Identity::Anonymous(policy) => {
                tok.string(Some(policy));
                id::ANONYMOUS_TOKEN
            }
            Identity::User {
                policy,
                security_policy,
                user,
                password,
            } => {
                let p = token_policy(security_policy);
                if p == Policy::None {
                    tok.string(Some(policy))
                        .string(Some(user))
                        .bytes(Some(password.as_bytes()))
                        .string(None);
                } else {
                    let cert = self.token_cert();
                    if cert.is_empty() {
                        return Err(
                            "the server sent no certificate to encrypt the password with".into(),
                        );
                    }
                    let key = uac::cert_public_key(&cert)?;
                    let mut plain = ((password.len() + self.server_nonce.len()) as u32)
                        .to_le_bytes()
                        .to_vec();
                    plain.extend_from_slice(password.as_bytes());
                    plain.extend_from_slice(&self.server_nonce);
                    let enc = uac::rsa_encrypt(p, &key, &plain)?;
                    tok.string(Some(policy))
                        .string(Some(user))
                        .bytes(Some(&enc))
                        .string(Some(p.enc_algorithm_uri()));
                }
                id::USERNAME_TOKEN
            }
            Identity::Cert {
                policy,
                security_policy,
                cert,
                key,
            } => {
                let p = token_policy(security_policy);
                if p == Policy::None {
                    return Err("X.509 user login needs a token security policy to sign with; choose a secured endpoint".into());
                }
                let mut data = self.token_cert();
                data.extend_from_slice(&self.server_nonce);
                token_sig = Some((
                    p.sig_algorithm_uri().to_string(),
                    uac::rsa_sign(p, key, &data)?,
                ));
                tok.string(Some(policy)).bytes(Some(cert));
                id::X509_TOKEN
            }
        };
        let client_sig = match &self.sec {
            Some(st) => {
                let mut data = st.s.server_cert.clone();
                data.extend_from_slice(&self.server_nonce);
                Some((
                    st.s.policy.sig_algorithm_uri().to_string(),
                    uac::rsa_sign(st.s.policy, &st.s.identity.key, &data)?,
                ))
            }
            None => None,
        };
        let (b, pos) = self.call(id::ACTIVATE_SESSION_REQ, id::ACTIVATE_SESSION_RESP, |w| {
            match &client_sig {
                Some((a, s)) => w.string(Some(a)).bytes(Some(s)),
                None => w.string(None).bytes(None),
            };
            w.empty_array(); // software certificates
            w.i32(1).string(Some("en"));
            w.type_id(type_id).u8(1).bytes(Some(&tok.0));
            match &token_sig {
                Some((a, s)) => w.string(Some(a)).bytes(Some(s)),
                None => w.string(None).bytes(None),
            };
        })?;
        let mut r = R::new(&b);
        r.pos = pos;
        if let Some(n) = r.bytes()?.filter(|n| !n.is_empty()) {
            self.server_nonce = n;
        }
        let results = r.array(|r| r.u32())?;
        if let Some(bad) = results.iter().find(|s| !is_good(**s)) {
            return Err(format!("ActivateSession: {}", status_name(*bad)));
        }
        Ok(())
    }

    pub fn browse(&mut self, node: &NodeId) -> Res<Vec<Reference>> {
        let n = node.clone();
        let (b, pos) = self.call(id::BROWSE_REQ, id::BROWSE_RESP, |w| {
            w.u8(0).u8(0).i64(0).u32(0); // view
            w.u32(1000);
            w.i32(1)
                .node_id(&n)
                .u32(0)
                .type_id(HIERARCHICAL_REFS)
                .bool(true)
                .u32(0)
                .u32(63);
        })?;
        let mut r = R::new(&b);
        r.pos = pos;
        let mut results = r.array(browse_result)?;
        let (status, mut cont, mut refs) = results.pop().ok_or("empty browse result")?;
        if !is_good(status) {
            return Err(status_name(status));
        }
        let mut rounds = 0;
        while let Some(cp) = cont.filter(|c| !c.is_empty()) {
            rounds += 1;
            if rounds > 100 {
                break;
            }
            let (b, pos) = self.call(id::BROWSE_NEXT_REQ, id::BROWSE_NEXT_RESP, |w| {
                w.bool(false).i32(1).bytes(Some(&cp));
            })?;
            let mut r = R::new(&b);
            r.pos = pos;
            let mut more = r.array(browse_result)?;
            let (st, c, mut rs) = more.pop().ok_or("empty BrowseNext result")?;
            if !is_good(st) {
                break;
            }
            refs.append(&mut rs);
            cont = c;
        }
        Ok(refs)
    }

    pub fn read(&mut self, items: &[(NodeId, u32)]) -> Res<Vec<DataValue>> {
        let (b, pos) = self.call(id::READ_REQ, id::READ_RESP, |w| {
            w.f64(0.0).u32(2).i32(items.len() as i32);
            for (n, a) in items {
                w.node_id(n).u32(*a).string(None).u16(0).string(None);
            }
        })?;
        let mut r = R::new(&b);
        r.pos = pos;
        r.array(|r| r.data_value())
    }

    pub fn close(mut self) {
        if !self.auth.is_null() {
            let _ = self.call(id::CLOSE_SESSION_REQ, id::CLOSE_SESSION_RESP, |w| {
                w.bool(true);
            });
            self.auth = NodeId::null();
        }
        let mut w = W::default();
        w.type_id(id::CLO_REQ);
        self.request_header(&mut w);
        let _ = self.send_request(b"CLO", &w.0);
    }
}

type BrowseResult = (u32, Option<Vec<u8>>, Vec<Reference>);

fn browse_result(r: &mut R) -> Res<BrowseResult> {
    let status = r.u32()?;
    let cont = r.bytes()?;
    let refs = r.array(|r| {
        Ok(Reference {
            ref_type: r.node_id()?,
            forward: r.bool()?,
            node: r.expanded_node_id()?,
            browse_name: r.qualified_name()?,
            display: r.localized()?,
            class: r.u32()?,
            type_def: r.expanded_node_id()?,
        })
    })?;
    Ok((status, cont, refs))
}

/// Identity token for ActivateSession. `policy` is the token's PolicyId,
/// `security_policy` its SecurityPolicyUri (empty = the channel's).
#[derive(Clone, Debug)]
pub enum Identity {
    Anonymous(String),
    User {
        policy: String,
        security_policy: String,
        user: String,
        password: String,
    },
    Cert {
        policy: String,
        security_policy: String,
        cert: Vec<u8>,
        key: Box<PrivateKey>,
    },
}

// ---------------------------------------------------------------- assessment

#[derive(Clone, Debug, Default)]
pub struct Discovery {
    pub url: String,
    pub addr: Option<SocketAddr>,
    pub connect_ms: f64,
    pub ack: AckInfo,
    pub endpoints: Vec<Endpoint>,
    pub servers: Vec<AppDescription>,
    pub cert: Option<crate::tls::CertInfo>,
    pub findings: Vec<Finding>,
}

fn f(section: &str, key: &str, value: impl Into<String>, level: Level) -> Finding {
    Finding {
        section: section.into(),
        key: key.into(),
        value: value.into(),
        level,
    }
}

/// Security review of the endpoint list.
pub fn assess(url: &str, eps: &[Endpoint]) -> Vec<Finding> {
    let mut out = Vec::new();
    const S: &str = "Security";
    if eps.is_empty() {
        out.push(f(
            S,
            "Endpoints",
            "the server returned no endpoints",
            Level::Bad,
        ));
        return out;
    }
    let none: Vec<&Endpoint> = eps.iter().filter(|e| e.mode == 1).collect();
    let secure = eps.iter().filter(|e| e.mode == 3).count();
    if !none.is_empty() {
        let anon_none = none
            .iter()
            .any(|e| e.tokens.iter().any(|t| t.token_type == 0));
        out.push(f(
            S,
            "Unsecured endpoint",
            if anon_none {
                "SecurityPolicy None with anonymous access — anyone on the network can read (and possibly write) data"
            } else {
                "SecurityPolicy None is offered — traffic is neither signed nor encrypted"
            },
            if anon_none { Level::Bad } else { Level::Warn },
        ));
        let clear_pw = none.iter().any(|e| {
            e.tokens.iter().any(|t| {
                t.token_type == 1
                    && (t.security_policy.is_empty() || t.security_policy == POLICY_NONE)
            })
        });
        if clear_pw {
            out.push(f(
                S,
                "Clear-text passwords",
                "user name login on a None endpoint without token encryption — passwords cross the network in clear text",
                Level::Bad,
            ));
        }
    }
    if secure == 0 {
        out.push(f(
            S,
            "Encryption",
            "no SignAndEncrypt endpoint — data cannot be protected in transit",
            Level::Bad,
        ));
    } else {
        out.push(f(
            S,
            "Encryption",
            format!("{secure} SignAndEncrypt endpoint(s) available"),
            Level::Good,
        ));
    }
    let mut deprecated: Vec<String> = eps
        .iter()
        .map(|e| policy_short(&e.policy))
        .filter(|p| p == "Basic128Rsa15" || p == "Basic256")
        .collect();
    deprecated.sort();
    deprecated.dedup();
    if !deprecated.is_empty() {
        out.push(f(
            S,
            "Deprecated policies",
            format!(
                "{} (SHA-1 based, deprecated since OPC UA 1.04)",
                deprecated.join(", ")
            ),
            Level::Warn,
        ));
    }
    if eps.iter().any(|e| e.mode == 2) {
        out.push(f(
            S,
            "Sign-only endpoint",
            "Sign mode protects integrity but not confidentiality",
            Level::Info,
        ));
    }
    let anon_any = eps
        .iter()
        .any(|e| e.mode != 1 && e.tokens.iter().any(|t| t.token_type == 0));
    if anon_any {
        out.push(f(
            S,
            "Anonymous login",
            "anonymous users are accepted on secured endpoints",
            Level::Warn,
        ));
    }
    let host = url_host(url);
    let other: Vec<String> = eps
        .iter()
        .map(|e| url_host(&e.url))
        .filter(|h| !h.is_empty() && *h != host)
        .collect();
    if let Some(h) = other.first() {
        out.push(f(
            "Configuration",
            "Endpoint host",
            format!(
                "endpoints advertise host '{h}' but you connected to '{host}' — clients that follow the advertised URL may fail to connect (DNS/NAT)"
            ),
            Level::Warn,
        ));
    }
    out
}

/// URI subject-alternative names (OPC UA puts the ApplicationUri there).
fn cert_uris(der: &[u8]) -> Vec<String> {
    use x509_parser::prelude::*;
    let Ok((_, c)) = parse_x509_certificate(der) else {
        return Vec::new();
    };
    c.subject_alternative_name()
        .ok()
        .flatten()
        .map(|e| {
            e.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    GeneralName::URI(u) => Some(u.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn assess_cert(c: &crate::tls::CertInfo, uris: &[String], app_uri: &str) -> Vec<Finding> {
    const S: &str = "Server certificate";
    let mut out = vec![
        f(S, "Subject", c.subject.clone(), Level::Info),
        f(
            S,
            "Issuer",
            format!(
                "{}{}",
                c.issuer,
                if c.self_signed { " (self-signed)" } else { "" }
            ),
            if c.self_signed {
                Level::Info
            } else {
                Level::Good
            },
        ),
    ];
    out.push(f(
        S,
        "Validity",
        format!(
            "{} → {} ({})",
            c.not_before,
            c.not_after,
            if c.days_left < 0 {
                format!("expired {} days ago", -c.days_left)
            } else {
                format!("{} days left", c.days_left)
            }
        ),
        if c.days_left < 0 {
            Level::Bad
        } else if c.days_left < 30 {
            Level::Warn
        } else {
            Level::Good
        },
    ));
    out.push(f(
        S,
        "Key",
        format!("{} {} bits", c.key, c.key_bits),
        if c.key == "RSA" && c.key_bits < 2048 {
            Level::Warn
        } else {
            Level::Good
        },
    ));
    out.push(f(
        S,
        "Signature",
        c.sig_alg.clone(),
        if c.sig_alg.contains("SHA-1") || c.sig_alg.contains("MD5") {
            Level::Warn
        } else {
            Level::Good
        },
    ));
    if !app_uri.is_empty() {
        let ok = uris.iter().any(|s| s == app_uri);
        out.push(f(
            S,
            "Application URI",
            if ok {
                format!("{app_uri} is in the certificate")
            } else {
                format!("{app_uri} not found in the certificate's SAN (clients may reject it)")
            },
            if ok { Level::Good } else { Level::Warn },
        ));
    }
    out.push(f(S, "SHA-256", c.sha256.clone(), Level::Info));
    out
}

/// Connect, GetEndpoints and FindServers on one channel.
pub fn discover(client: &mut Client) -> Res<Discovery> {
    let endpoints = client.get_endpoints()?;
    let servers = client.find_servers().unwrap_or_default();
    let mut d = Discovery {
        url: client.url.clone(),
        addr: Some(client.addr),
        connect_ms: client.connect_ms,
        ack: client.ack.clone(),
        findings: assess(&client.url, &endpoints),
        endpoints,
        servers,
        cert: None,
    };
    if let Some(e) = d.endpoints.iter().find(|e| !e.cert.is_empty())
        && let Ok(c) = crate::tls::parse_cert(&e.cert)
    {
        d.findings
            .extend(assess_cert(&c, &cert_uris(&e.cert), &e.server.uri));
        d.cert = Some(c);
    }
    if let Some(e) = d.endpoints.first() {
        let s = &e.server;
        let mut info = vec![
            f("Server", "Name", s.name.clone(), Level::Info),
            f("Server", "Application URI", s.uri.clone(), Level::Info),
        ];
        if !s.product_uri.is_empty() {
            info.push(f(
                "Server",
                "Product URI",
                s.product_uri.clone(),
                Level::Info,
            ));
        }
        info.push(f(
            "Server",
            "Buffers",
            format!(
                "protocol v{}, receive {} / send {} bytes, max message {}, max chunks {}",
                d.ack.version,
                d.ack.recv_buf,
                d.ack.send_buf,
                if d.ack.max_msg == 0 {
                    "unlimited".into()
                } else {
                    d.ack.max_msg.to_string()
                },
                if d.ack.max_chunks == 0 {
                    "unlimited".into()
                } else {
                    d.ack.max_chunks.to_string()
                }
            ),
            Level::Info,
        ));
        d.findings.splice(0..0, info);
    }
    Ok(d)
}

/// Endpoint and user token policy for a session with `policy` / `mode`
/// (`mode` 0 = the most secure mode offered with that policy).
pub fn pick_endpoint(
    eps: &[Endpoint],
    policy: Policy,
    mode: u32,
    token_type: u32,
) -> Res<(Endpoint, TokenPolicy)> {
    let uri = policy.uri();
    let mut matching: Vec<&Endpoint> = eps
        .iter()
        .filter(|e| e.policy == uri && (policy == Policy::None || mode == 0 || e.mode == mode))
        .collect();
    if matching.is_empty() {
        if policy == Policy::None {
            return Err("the server offers no SecurityPolicy None endpoint — press Discover, pick a secured endpoint and trust the server certificate".into());
        }
        let mut offered: Vec<String> = eps
            .iter()
            .filter(|e| e.mode != 1)
            .map(|e| format!("{} / {}", policy_short(&e.policy), mode_name(e.mode)))
            .collect();
        offered.dedup();
        return Err(format!(
            "the server has no {} / {} endpoint (it offers: {})",
            policy.name(),
            if mode == 0 {
                "any mode"
            } else {
                mode_name(mode)
            },
            if offered.is_empty() {
                "only None".to_string()
            } else {
                offered.join(", ")
            }
        ));
    }
    matching.sort_by_key(|e| std::cmp::Reverse(e.mode));
    for e in &matching {
        if let Some(t) = e.tokens.iter().find(|t| t.token_type == token_type) {
            return Ok(((*e).clone(), t.clone()));
        }
    }
    let e = matching[0];
    Err(format!(
        "the {} / {} endpoint does not accept {} login (it offers: {})",
        policy.name(),
        mode_name(e.mode),
        token_type_name(token_type).to_lowercase(),
        e.tokens
            .iter()
            .map(|t| token_type_name(t.token_type))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Plain-language advice for common OPC UA (security) errors.
pub fn hint(e: &str) -> Option<&'static str> {
    const REVOCATION: &str = "The server cannot check revocation for the client certificate (no CRL). For a self-signed client certificate, relax revocation checks or add a CRL on the server.";
    const H: &[(&str, &str)] = &[
        (
            "BadSecurityChecksFailed",
            "The server rejected the secure channel. Most often it does not trust this client's certificate yet: on the server, move the Network Analyser certificate from the rejected to the trusted list (certificate manager / PKI folder), then connect again. Also check that both clocks are right.",
        ),
        (
            "BadCertificateUntrusted",
            "The server does not trust this client's certificate. Trust it in the server's certificate manager (after the first attempt it is usually in the 'rejected' list).",
        ),
        (
            "BadCertificateUriInvalid",
            "The application URI in a certificate does not match the one announced (client) or the endpoint's (server).",
        ),
        (
            "BadCertificateTimeInvalid",
            "A certificate is expired or not yet valid — check the clocks on both machines.",
        ),
        (
            "BadCertificateHostNameInvalid",
            "The host name in the URL is not in the server certificate; connect with a name the certificate lists.",
        ),
        (
            "BadCertificateUseNotAllowed",
            "A certificate lacks the key usage OPC UA needs (digitalSignature, keyEncipherment, dataEncipherment).",
        ),
        ("BadCertificateIssuerRevocationUnknown", REVOCATION),
        ("BadCertificateRevocationUnknown", REVOCATION),
        ("BadCertificateRevoked", "The certificate has been revoked."),
        (
            "BadCertificateInvalid",
            "The server could not parse or validate the certificate.",
        ),
        (
            "BadIdentityTokenRejected",
            "The server refused this kind of login on this endpoint (or does not trust the user certificate).",
        ),
        (
            "BadIdentityTokenInvalid",
            "The login token was malformed, or the password was encrypted with a policy the server did not expect.",
        ),
        (
            "BadUserAccessDenied",
            "Wrong user name or password, or this user may not log in.",
        ),
        (
            "BadUserSignatureInvalid",
            "The user certificate's signature was refused — does the key belong to the certificate?",
        ),
        (
            "BadApplicationSignatureInvalid",
            "A session signature did not verify — client and server disagree on the certificates or the policy.",
        ),
        (
            "BadSecurityPolicyRejected",
            "The server does not accept this security policy — pick another endpoint.",
        ),
        (
            "BadSecurityModeRejected",
            "The server does not accept this security mode — pick another endpoint.",
        ),
        (
            "BadNonceInvalid",
            "The server refused the nonce (often a policy or key-size mismatch).",
        ),
        (
            "BadTooManySessions",
            "The server has reached its session limit.",
        ),
        (
            "the server closed the connection",
            "Servers often just drop the connection when they reject a client certificate: check the server's rejected-certificates list and trust the client certificate.",
        ),
    ];
    H.iter().find(|(k, _)| e.contains(k)).map(|(_, v)| *v)
}

pub fn with_hint(e: String) -> String {
    match hint(&e) {
        Some(h) => format!("{e} — {h}"),
        None => e,
    }
}

// ---------------------------------------------------------------- worker

#[derive(Clone, Debug)]
pub enum Login {
    Anonymous,
    User(String, String),
    /// X.509 user certificate and key files.
    Cert(PathBuf, PathBuf),
}

impl Login {
    fn token_type(&self) -> u32 {
        match self {
            Login::Anonymous => 0,
            Login::User(..) => 1,
            Login::Cert(..) => 2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionOpts {
    pub policy: Policy,
    /// 1 None, 2 Sign, 3 SignAndEncrypt (0 = best offered for the policy)
    pub mode: u32,
    pub login: Login,
    /// Custom client application certificate and key (else the built-in one).
    pub client_cert: Option<(PathBuf, PathBuf)>,
    /// SHA-1 thumbprint (hex) of the server certificate the user accepted.
    pub accepted_server: Option<String>,
}

impl SessionOpts {
    pub fn anonymous_none() -> SessionOpts {
        SessionOpts {
            policy: Policy::None,
            mode: 1,
            login: Login::Anonymous,
            client_cert: None,
            accepted_server: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Auth {
    DiscoverOnly,
    Session(SessionOpts),
}

pub enum Cmd {
    Browse(NodeId),
    Read(NodeId),
    SetWatch(Vec<NodeId>),
    Disconnect,
}

#[derive(Clone, Debug, Default)]
pub struct SessionInfo {
    pub session_id: String,
    pub timeout_ms: f64,
    pub identity: String,
    pub security: String,
    pub product: String,
    pub version: String,
    pub state: String,
    pub started: String,
}

pub enum Event {
    Log(Level, String),
    Discovery(Box<Discovery>),
    ClientCert(uac::CertSummary),
    Session(SessionInfo),
    Browsed(NodeId, Result<Vec<Reference>, String>),
    Attrs(NodeId, Result<Vec<(u32, DataValue)>, String>),
    Watch(Vec<(NodeId, DataValue)>),
    ServerTime(String),
    Closed(String),
    Error(String),
}

pub struct Handle {
    tx: Sender<Cmd>,
}

impl Handle {
    pub fn send(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Disconnect);
    }
}

pub fn start(url: String, auth: Auth, timeout: Duration) -> (Handle, Receiver<Event>) {
    let (tx, crx) = channel();
    let (etx, erx) = channel();
    std::thread::spawn(move || {
        if let Err(e) = worker(url, auth, timeout, crx, &etx) {
            let _ = etx.send(Event::Error(with_hint(e)));
        }
    });
    (Handle { tx }, erx)
}

const ATTRS: [u32; 18] = [
    1, 2, 3, 4, 5, 6, 8, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
];

pub fn read_attributes(c: &mut Client, n: &NodeId) -> Res<Vec<(u32, DataValue)>> {
    let items: Vec<(NodeId, u32)> = ATTRS.iter().map(|a| (n.clone(), *a)).collect();
    let vals = c.read(&items)?;
    Ok(ATTRS
        .iter()
        .copied()
        .zip(vals)
        .filter(|(a, v)| is_good(v.status) || *a == 13)
        .collect())
}

fn server_info(c: &mut Client) -> (String, String, String, String) {
    let ids = [
        SERVER_PRODUCT_NAME,
        SERVER_SOFTWARE_VERSION,
        SERVER_STATE,
        SERVER_START_TIME,
        SERVER_MANUFACTURER,
    ];
    let items: Vec<(NodeId, u32)> = ids.iter().map(|i| (NodeId::num(0, *i), 13)).collect();
    let v = c.read(&items).unwrap_or_default();
    let get = |i: usize| -> String {
        v.get(i)
            .filter(|d| is_good(d.status))
            .map(|d| d.value.display())
            .unwrap_or_default()
    };
    let product = match (get(4), get(0)) {
        (m, p) if !m.is_empty() && !p.contains(&m) => format!("{m} {p}"),
        (_, p) => p,
    };
    let state = match v.get(2).map(|d| &d.value) {
        Some(Value::Int(s, _)) => server_state_name(*s).to_string(),
        _ => String::new(),
    };
    (product, get(1), state, get(3))
}

/// The client application certificate: custom files or the built-in one
/// (created on first use).
fn client_identity(opts: &SessionOpts, log: &dyn Fn(Level, String)) -> Res<ClientIdentity> {
    match &opts.client_cert {
        Some((c, k)) => ClientIdentity::load(c, k),
        None => {
            let dir = uac::default_dir().ok_or("no data directory for the client certificate")?;
            let (id, created) = ClientIdentity::load_or_create(&dir)?;
            if created {
                let s = id.summary();
                log(
                    Level::Warn,
                    format!(
                        "Created the client certificate {} (SHA-1 {}). Servers usually reject a new client the first time — trust it on the server, then connect again.",
                        s.path.map(|p| p.display().to_string()).unwrap_or_default(),
                        s.thumbprint
                    ),
                );
            }
            Ok(id)
        }
    }
}

/// An open, activated session.
pub struct Opened {
    pub client: Client,
    pub session_id: NodeId,
    pub timeout_ms: f64,
    pub identity: String,
}

/// From a discovery channel `c` to an activated session as `opts` asks:
/// picks the endpoint, opens a secured channel when needed (after checking
/// the accepted server certificate), CreateSession, ActivateSession.
pub fn open_session(
    c: Client,
    endpoints: &[Endpoint],
    opts: &SessionOpts,
    log: &dyn Fn(Level, String),
    on_client_cert: &dyn Fn(uac::CertSummary),
) -> Res<Opened> {
    let (ep, tok) = pick_endpoint(endpoints, opts.policy, opts.mode, opts.login.token_type())?;
    let url = c.url.clone();
    let timeout = c.timeout;
    let mut c = if ep.mode == 1 || opts.policy == Policy::None {
        c
    } else {
        let thumb = uac::hex(&uac::thumbprint(&ep.cert));
        match &opts.accepted_server {
            Some(t) if *t == thumb => {}
            Some(_) => {
                return Err("the server certificate changed after you accepted it — Discover again and review it".into());
            }
            None => {
                return Err("the server certificate has not been accepted — trust it first".into());
            }
        }
        let id = client_identity(opts, log)?;
        let s = id.summary();
        on_client_cert(s.clone());
        c.close();
        log(
            Level::Info,
            format!(
                "Opening a {} / {} channel as {} (client certificate SHA-1 {})…",
                opts.policy.name(),
                mode_name(ep.mode),
                id.app_uri,
                s.thumbprint
            ),
        );
        let sc = Client::connect_with(
            &url,
            timeout,
            Some(Security {
                policy: opts.policy,
                mode: ep.mode,
                identity: id,
                server_cert: ep.cert.clone(),
            }),
        )?;
        log(
            Level::Good,
            format!("Secure channel open ({})", sc.security_text()),
        );
        sc
    };
    let channel_policy = Policy::from_uri(&ep.policy).unwrap_or(Policy::None);
    let (identity, who) = match &opts.login {
        Login::Anonymous => (
            Identity::Anonymous(tok.policy_id.clone()),
            "anonymous".into(),
        ),
        Login::User(u, p) => {
            let eff = if tok.security_policy.is_empty() {
                channel_policy
            } else {
                Policy::from_uri(&tok.security_policy).unwrap_or(channel_policy)
            };
            if eff == Policy::None && ep.mode == 3 {
                log(
                    Level::Info,
                    "The password is protected by the channel encryption only (the user token policy is None)"
                        .into(),
                );
            } else if eff == Policy::None {
                log(
                    Level::Warn,
                    format!(
                        "The password is sent unencrypted ({} channel, user token policy None)",
                        mode_name(ep.mode)
                    ),
                );
            } else {
                log(
                    Level::Info,
                    format!("Password encrypted with {}", eff.name()),
                );
            }
            (
                Identity::User {
                    policy: tok.policy_id.clone(),
                    security_policy: tok.security_policy.clone(),
                    user: u.clone(),
                    password: p.clone(),
                },
                format!("user {u}"),
            )
        }
        Login::Cert(cp, kp) => {
            let user = ClientIdentity::load_user(cp, kp)?;
            let who = format!("certificate {}", uac::summarize(&user.0, None).subject);
            (
                Identity::Cert {
                    policy: tok.policy_id.clone(),
                    security_policy: tok.security_policy.clone(),
                    cert: user.0,
                    key: Box::new(user.1),
                },
                who,
            )
        }
    };
    let (session_id, timeout_ms) = c.create_session()?;
    c.activate_session(&identity)?;
    Ok(Opened {
        client: c,
        session_id,
        timeout_ms,
        identity: who,
    })
}

fn worker(
    url: String,
    auth: Auth,
    timeout: Duration,
    rx: Receiver<Cmd>,
    tx: &Sender<Event>,
) -> Res<()> {
    let log = |l: Level, s: String| {
        let _ = tx.send(Event::Log(l, s));
    };
    log(Level::Info, format!("Connecting to {url}…"));
    let mut c = Client::connect(&url, timeout)?;
    log(
        Level::Good,
        format!(
            "HEL/ACK and discovery channel (None) open with {} in {:.0} ms",
            c.addr, c.connect_ms
        ),
    );
    let d = discover(&mut c)?;
    log(
        Level::Info,
        format!(
            "GetEndpoints: {} endpoint(s); FindServers: {} server(s)",
            d.endpoints.len(),
            d.servers.len()
        ),
    );
    let endpoints = d.endpoints.clone();
    let _ = tx.send(Event::Discovery(Box::new(d)));
    let opts = match auth {
        Auth::DiscoverOnly => {
            c.close();
            let _ = tx.send(Event::Closed("Discovery finished".into()));
            return Ok(());
        }
        Auth::Session(o) => o,
    };
    let opened = open_session(c, &endpoints, &opts, &log, &|s| {
        let _ = tx.send(Event::ClientCert(s));
    })?;
    let mut c = opened.client;
    let (sid, sto) = (opened.session_id, opened.timeout_ms);
    let (product, version, state, started) = server_info(&mut c);
    log(
        Level::Good,
        format!(
            "Session {sid} active ({}, {}), timeout {:.0} s",
            opened.identity,
            c.security_text(),
            sto / 1000.0
        ),
    );
    let _ = tx.send(Event::Session(SessionInfo {
        session_id: sid.to_string(),
        timeout_ms: sto,
        identity: opened.identity,
        security: c.security_text(),
        product,
        version,
        state,
        started,
    }));
    let objects = NodeId::num(0, OBJECTS);
    let r = c.browse(&objects);
    let _ = tx.send(Event::Browsed(objects, r));
    let mut watch: Vec<NodeId> = Vec::new();
    let mut last_poll = Instant::now();
    let mut last_keepalive = Instant::now();
    let keep = Duration::from_millis((sto / 3.0).clamp(5_000.0, 60_000.0) as u64);
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Cmd::Browse(n)) => {
                let r = c.browse(&n);
                if let Err(e) = &r
                    && is_fatal(e)
                {
                    return Err(e.clone());
                }
                let _ = tx.send(Event::Browsed(n, r));
                last_keepalive = Instant::now();
            }
            Ok(Cmd::Read(n)) => {
                let r = read_attributes(&mut c, &n);
                if let Err(e) = &r
                    && is_fatal(e)
                {
                    return Err(e.clone());
                }
                let _ = tx.send(Event::Attrs(n, r));
                last_keepalive = Instant::now();
            }
            Ok(Cmd::SetWatch(w)) => {
                watch = w;
                last_poll = Instant::now() - Duration::from_secs(5);
            }
            Ok(Cmd::Disconnect) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                c.close();
                let _ = tx.send(Event::Closed("Session closed".into()));
                return Ok(());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if !watch.is_empty() && last_poll.elapsed() >= Duration::from_secs(1) {
            last_poll = Instant::now();
            let items: Vec<(NodeId, u32)> = watch.iter().map(|n| (n.clone(), 13)).collect();
            let vals = c.read(&items)?;
            let _ = tx.send(Event::Watch(watch.iter().cloned().zip(vals).collect()));
            last_keepalive = Instant::now();
        }
        if last_keepalive.elapsed() >= keep {
            last_keepalive = Instant::now();
            let v = c.read(&[(NodeId::num(0, SERVER_CURRENT_TIME), 13)])?;
            if let Some(d) = v.first() {
                let _ = tx.send(Event::ServerTime(d.value.display()));
            }
        }
    }
}

/// Transport-level errors end the session; per-node errors do not.
fn is_fatal(e: &str) -> bool {
    e.contains("closed the connection")
        || e.contains("timeout")
        || e.contains("send:")
        || e.contains("BadSession")
        || e.contains("BadSecureChannel")
        || e.contains("BadSecurityChecksFailed")
        || e.contains("unknown security token")
}

// ---------------------------------------------------------------- CLI

pub const CLI_USAGE: &str = "usage: --opcua opc.tcp://HOST[:4840][/PATH] [browse]
         [--policy NAME --mode sign|encrypt] [--user U --password P]
         [--user-cert FILE --user-key FILE] [--cert FILE --key FILE] [--trust]
  NAME: None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss,
        Basic256, Basic128Rsa15 (deprecated)
  --cert/--key   client application certificate (default: built-in, created
                 on first use in the data directory)
  --trust        trust the server certificate (saved) — needed the first time";

fn cli_fail(e: impl std::fmt::Display) -> ! {
    eprintln!("{e}");
    std::process::exit(1)
}

/// `--opcua URL [browse] [options]`
pub fn cli(args: &[String]) {
    let mut url = None;
    let mut browse = false;
    let mut policy = None;
    let mut mode = None;
    let (mut user, mut password) = (None, None);
    let (mut user_cert, mut user_key) = (None, None);
    let (mut cert, mut key) = (None, None);
    let mut trust = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut val = || -> String {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| {
                eprintln!("{a}: missing value\n{CLI_USAGE}");
                std::process::exit(2)
            })
        };
        match a {
            "browse" => browse = true,
            "--policy" => {
                let v = val();
                policy = Some(Policy::parse(&v).unwrap_or_else(|| {
                    eprintln!("--policy: unknown policy '{v}'\n{CLI_USAGE}");
                    std::process::exit(2)
                }))
            }
            "--mode" => {
                mode = Some(match val().to_ascii_lowercase().as_str() {
                    "none" => 1,
                    "sign" => 2,
                    "encrypt" | "signandencrypt" | "sign-and-encrypt" => 3,
                    m => {
                        eprintln!("--mode: expected sign or encrypt, not '{m}'");
                        std::process::exit(2)
                    }
                })
            }
            "--user" => user = Some(val()),
            "--password" => password = Some(val()),
            "--user-cert" => user_cert = Some(PathBuf::from(val())),
            "--user-key" => user_key = Some(PathBuf::from(val())),
            "--cert" => cert = Some(PathBuf::from(val())),
            "--key" => key = Some(PathBuf::from(val())),
            "--trust" => trust = true,
            s if !s.starts_with("--") && url.is_none() => url = Some(s.to_string()),
            s => {
                eprintln!("--opcua: unexpected '{s}'\n{CLI_USAGE}");
                std::process::exit(2)
            }
        }
        i += 1;
    }
    let Some(url) = url else {
        eprintln!("{CLI_USAGE}");
        std::process::exit(2)
    };
    let url = normalize_url(&url);
    let session =
        browse || policy.is_some() || mode.is_some() || user.is_some() || user_cert.is_some();
    let mut c = Client::connect(&url, Duration::from_secs(10)).unwrap_or_else(|e| cli_fail(e));
    let d = discover(&mut c).unwrap_or_else(|e| cli_fail(e));
    println!("{url} ({}) connect {:.0} ms", c.addr, c.connect_ms);
    println!("\nEndpoints:");
    for e in &d.endpoints {
        println!(
            "  {:<15} {:<22} level {:>3}  {}  [{}] {}",
            mode_name(e.mode),
            policy_short(&e.policy),
            e.level,
            e.url,
            e.tokens
                .iter()
                .map(|t| token_type_name(t.token_type))
                .collect::<Vec<_>>()
                .join(", "),
            e.transport.rsplit('/').next().unwrap_or("")
        );
    }
    if !d.servers.is_empty() {
        println!("\nServers (FindServers):");
        for s in &d.servers {
            println!(
                "  {} — {} [{}] {}",
                s.name,
                s.uri,
                app_type_name(s.app_type),
                s.discovery_urls.join(" ")
            );
        }
    }
    print!("{}", crate::widgets::findings_text(&d.findings));
    if !session {
        c.close();
        return;
    }
    let policy = policy.unwrap_or(Policy::None);
    let login = match (user, password, user_cert, user_key) {
        (Some(u), p, _, _) => Login::User(u, p.unwrap_or_default()),
        (None, _, Some(c), Some(k)) => Login::Cert(c, k),
        (None, _, Some(_), None) | (None, _, None, Some(_)) => {
            cli_fail("--user-cert and --user-key go together")
        }
        _ => Login::Anonymous,
    };
    let client_cert = match (cert, key) {
        (Some(c), Some(k)) => Some((c, k)),
        (None, None) => None,
        _ => cli_fail("--cert and --key go together"),
    };
    let mut opts = SessionOpts {
        policy,
        mode: mode.unwrap_or(if policy == Policy::None { 1 } else { 3 }),
        login,
        client_cert,
        accepted_server: None,
    };
    if policy != Policy::None {
        let (ep, _) = pick_endpoint(
            &d.endpoints,
            opts.policy,
            opts.mode,
            opts.login.token_type(),
        )
        .unwrap_or_else(|e| cli_fail(e));
        let key = uac::trust_key(&ep.server.uri, &url);
        let s = uac::summarize(&ep.cert, None);
        match uac::trust_status(&key, &ep.cert) {
            uac::Trust::Trusted => {
                println!("\nServer certificate trusted (SHA-1 {})", s.thumbprint)
            }
            st => {
                if let uac::Trust::Changed(old) = &st {
                    println!("\nWARNING: the server certificate CHANGED (trusted before: {old})");
                }
                println!(
                    "\nServer certificate: {}\n  valid until {} · SHA-1 {}",
                    s.subject, s.not_after, s.thumbprint
                );
                if !trust {
                    cli_fail(
                        "Not trusted yet — check the thumbprint with the server administrator, then re-run with --trust",
                    );
                }
                uac::trust(&key, &ep.cert).unwrap_or_else(|e| cli_fail(e));
                println!("Trusted and saved.");
            }
        }
        opts.accepted_server = Some(uac::hex(&uac::thumbprint(&ep.cert)));
    }
    let log = |_: Level, s: String| println!("{s}");
    let r = open_session(c, &d.endpoints, &opts, &log, &|s| {
        println!(
            "Client certificate: {} (SHA-1 {}){}",
            s.app_uri,
            s.thumbprint,
            s.path
                .map(|p| format!(" — {}", p.display()))
                .unwrap_or_default()
        )
    });
    let mut o = r.unwrap_or_else(|e| cli_fail(format!("session: {}", with_hint(e))));
    let (p, v, s, st) = server_info(&mut o.client);
    println!(
        "\nSession ({}, {}): {p} {v}, state {s}, started {st}",
        o.identity,
        o.client.security_text()
    );
    match o.client.browse(&NodeId::num(0, OBJECTS)) {
        Ok(refs) => {
            println!("Objects:");
            for r in refs {
                println!(
                    "  {:<12} {:<30} {}",
                    node_class_name(r.class),
                    r.display,
                    r.node
                );
            }
        }
        Err(e) => eprintln!("browse: {e}"),
    }
    o.client.close();
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn hello_bytes() {
        let h = hello("opc.tcp://a:4840");
        let mut want = b"HELF".to_vec();
        want.extend_from_slice(&(8u32 + 20 + 4 + 16).to_le_bytes());
        for v in [0u32, 65536, 65536, 0, 0] {
            want.extend_from_slice(&v.to_le_bytes());
        }
        want.extend_from_slice(&16i32.to_le_bytes());
        want.extend_from_slice(b"opc.tcp://a:4840");
        assert_eq!(h, want);
    }

    #[test]
    fn node_ids() {
        let cases: Vec<(NodeId, Vec<u8>)> = vec![
            (NodeId::num(0, 85), vec![0x00, 85]),
            (NodeId::num(0, 2259), vec![0x01, 0, 0xd3, 0x08]),
            (NodeId::num(2, 70000), vec![0x02, 2, 0, 0x70, 0x11, 1, 0]),
            (
                NodeId {
                    ns: 3,
                    id: Ident::Str("ab".into()),
                },
                vec![0x03, 3, 0, 2, 0, 0, 0, b'a', b'b'],
            ),
        ];
        for (n, bytes) in cases {
            let mut w = W::default();
            w.node_id(&n);
            assert_eq!(w.0, bytes, "{n}");
            assert_eq!(R::new(&bytes).node_id().unwrap(), n);
            assert_eq!(NodeId::parse(&n.to_string()).unwrap(), n);
        }
        let g = NodeId::parse("ns=1;g=72962b91-fa75-4ae6-8d28-b404dc7daf63").unwrap();
        assert_eq!(g.to_string(), "ns=1;g=72962b91-fa75-4ae6-8d28-b404dc7daf63");
        let Ident::Guid(raw) = g.id else { panic!() };
        assert_eq!(&raw[..4], &[0x91, 0x2b, 0x96, 0x72]);
        assert_eq!(NodeId::parse("ns=2;s=Demo.Static").unwrap().ns, 2);
        assert!(NodeId::parse("ns=x;i=1").is_err());
        // Expanded NodeId with namespace URI and server index.
        let mut b = vec![0xc0, 7];
        b.extend_from_slice(&1i32.to_le_bytes());
        b.push(b'u');
        b.extend_from_slice(&5u32.to_le_bytes());
        let mut r = R::new(&b);
        assert_eq!(r.expanded_node_id().unwrap(), NodeId::num(0, 7));
        assert_eq!(r.pos, b.len());
    }

    #[test]
    fn variants_and_data_values() {
        // Int32 -5
        assert_eq!(
            R::new(&[6, 0xfb, 0xff, 0xff, 0xff]).variant().unwrap(),
            Value::Int(-5, 6)
        );
        // Double 1.5
        let mut b = vec![11];
        b.extend_from_slice(&1.5f64.to_le_bytes());
        assert_eq!(R::new(&b).variant().unwrap().display(), "1.5");
        // Array of 2 Boolean
        assert_eq!(
            R::new(&[0x81, 2, 0, 0, 0, 1, 0])
                .variant()
                .unwrap()
                .display(),
            "[true, false]"
        );
        // LocalizedText with locale + text
        let lt = [21, 3, 2, 0, 0, 0, b'e', b'n', 2, 0, 0, 0, b'h', b'i'];
        assert_eq!(R::new(&lt).variant().unwrap(), Value::Text("hi".into()));
        // DataValue: value UInt16 7, status BadNodeIdUnknown, server ts.
        let mut dv = vec![0x0b, 5, 7, 0];
        dv.extend_from_slice(&0x8034_0000u32.to_le_bytes());
        dv.extend_from_slice(&132_000_000_000_000_000i64.to_le_bytes());
        let d = R::new(&dv).data_value().unwrap();
        assert_eq!(d.value, Value::UInt(7, 5));
        assert_eq!(status_name(d.status), "BadNodeIdUnknown");
        assert!(d.server_ts.is_some() && d.source_ts.is_none());
        assert_eq!(status_name(0x4000_0001), "Uncertain (0x40000001)");
    }

    #[test]
    fn datetimes_and_urls() {
        // 2000-01-01 00:00:00 UTC
        let t = (946_684_800_000i64 + 11_644_473_600_000) * 10_000;
        assert_eq!(datetime_string(t), "2000-01-01 00:00:00.000 UTC");
        assert_eq!(datetime_string(0), "-");
        assert_eq!(
            parse_url("opc.tcp://plc.local:4841/UA/Server").unwrap(),
            ("plc.local".into(), 4841)
        );
        assert_eq!(parse_url("opc.tcp://[::1]").unwrap(), ("::1".into(), 4840));
        assert!(parse_url("http://x").is_err());
        assert_eq!(normalize_url("10.0.0.2:4840"), "opc.tcp://10.0.0.2:4840");
        assert_eq!(
            policy_short("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"),
            "Basic256Sha256"
        );
    }

    fn ep(mode: u32, policy: &str, tokens: &[(u32, &str)]) -> Endpoint {
        Endpoint {
            url: "opc.tcp://plc:4840".into(),
            mode,
            policy: format!("http://opcfoundation.org/UA/SecurityPolicy#{policy}"),
            tokens: tokens
                .iter()
                .map(|(t, p)| TokenPolicy {
                    policy_id: format!("p{t}"),
                    token_type: *t,
                    security_policy: p.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn assessment() {
        let eps = vec![
            ep(1, "None", &[(0, ""), (1, "")]),
            ep(3, "Basic256", &[(1, "")]),
        ];
        let f = assess("opc.tcp://10.0.0.9:4840", &eps);
        let has = |k: &str, l: Level| f.iter().any(|x| x.key == k && x.level == l);
        assert!(has("Unsecured endpoint", Level::Bad));
        assert!(has("Clear-text passwords", Level::Bad));
        assert!(has("Deprecated policies", Level::Warn));
        assert!(has("Encryption", Level::Good));
        assert!(has("Endpoint host", Level::Warn));
        assert!(pick_endpoint(&eps, Policy::None, 1, 0).is_ok());
        assert!(pick_endpoint(&[ep(3, "Basic256Sha256", &[(0, "")])], Policy::None, 1, 0).is_err());
        assert!(pick_endpoint(&eps, Policy::Basic256, 3, 1).is_ok());
        assert!(
            pick_endpoint(&eps, Policy::Basic256, 3, 0)
                .unwrap_err()
                .contains("does not accept anonymous")
        );
        assert!(
            pick_endpoint(&eps, Policy::Basic256Sha256, 0, 1)
                .unwrap_err()
                .contains("offers: Basic256 / SignAndEncrypt")
        );
        let enc = vec![ep(
            1,
            "None",
            &[(
                1,
                "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            )],
        )];
        let (_, t) = pick_endpoint(&enc, Policy::None, 1, 1).unwrap();
        assert!(t.security_policy.ends_with("Basic256Sha256"));
    }

    // ------------------------------------------------ in-process test server

    fn read_frame(s: &mut TcpStream) -> Option<([u8; 3], u8, Vec<u8>)> {
        let mut h = [0u8; 8];
        s.read_exact(&mut h).ok()?;
        let n = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        let mut b = vec![0u8; n - 8];
        s.read_exact(&mut b).ok()?;
        Some(([h[0], h[1], h[2]], h[3], b))
    }

    fn resp_header(w: &mut W, status: u32) {
        w.i64(now_ticks())
            .u32(1)
            .u32(status)
            .u8(0)
            .i32(0)
            .null_ext();
    }

    /// (policy, mode, [(token type, token security policy URI)])
    type TestEp = (Policy, u32, Vec<(u32, String)>);

    #[derive(Clone)]
    pub(crate) struct SrvCfg {
        endpoints: Vec<TestEp>,
        /// Answer secured OPNs with ERR BadSecurityChecksFailed.
        reject_secure: bool,
    }

    fn none_cfg() -> SrvCfg {
        SrvCfg {
            endpoints: vec![(
                Policy::None,
                1,
                vec![(0, String::new()), (1, String::new())],
            )],
            reject_secure: false,
        }
    }

    fn endpoints_body(w: &mut W, eps: &[TestEp], cert: &[u8]) {
        w.i32(eps.len() as i32);
        for (p, mode, toks) in eps {
            w.string(Some("opc.tcp://127.0.0.1:4840"));
            w.string(Some("urn:test:server"))
                .string(Some("urn:test"))
                .localized("Test Server")
                .u32(0)
                .string(None)
                .string(None)
                .empty_array();
            w.bytes((!cert.is_empty()).then_some(cert))
                .u32(*mode)
                .string(Some(&p.uri()));
            w.i32(toks.len() as i32);
            for (t, sp) in toks {
                w.string(Some(&format!("tok{t}")))
                    .u32(*t)
                    .string(None)
                    .string(None)
                    .string((!sp.is_empty()).then_some(sp.as_str()));
            }
            w.string(Some(
                "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
            ))
            .u8(*mode as u8 * 10);
        }
    }

    struct Srv {
        policy: Policy,
        encrypt: bool,
        client_cert: Vec<u8>,
        /// token id → (client→server keys, server→client keys)
        keys: Vec<(u32, Keys, Keys)>,
        session_nonce: Vec<u8>,
        seq: u32,
    }

    impl Srv {
        fn reply(
            &mut self,
            s: &mut TcpStream,
            kind: &[u8; 3],
            token: u32,
            req: u32,
            body: &[u8],
            split: bool,
        ) {
            let id = &uac::tests::ids().1;
            let parts: Vec<&[u8]> = if split {
                let mid = body.len() / 2;
                vec![&body[..mid], &body[mid..]]
            } else {
                vec![body]
            };
            let last = parts.len() - 1;
            for (i, p) in parts.into_iter().enumerate() {
                self.seq += 1;
                let mut payload = self.seq.to_le_bytes().to_vec();
                payload.extend_from_slice(&req.to_le_bytes());
                payload.extend_from_slice(p);
                let c = if i == last { b'F' } else { b'C' };
                let f = if kind == b"OPN" {
                    if self.policy == Policy::None {
                        uac::seal_asym(Policy::None, c, 7, None, &[], None, &payload).unwrap()
                    } else {
                        let ck = uac::cert_public_key(&self.client_cert).unwrap();
                        uac::seal_asym(
                            self.policy,
                            c,
                            7,
                            Some(&Local {
                                cert: &id.cert,
                                key: &id.key,
                            }),
                            &self.client_cert,
                            Some(&ck),
                            &payload,
                        )
                        .unwrap()
                    }
                } else {
                    let k = self.keys.iter().find(|k| k.0 == token).map(|k| &k.2);
                    uac::seal_sym(self.policy, self.encrypt, kind, c, 7, token, k, &payload)
                        .unwrap()
                };
                s.write_all(&f).unwrap();
            }
        }
    }

    /// A tiny server: endpoints (sent in two chunks), secured channels with
    /// the crypto module, session (with signatures and user checks: user
    /// "op" / password "secret"), browse with a continuation point, read,
    /// and a ServiceFault for unknown requests.
    pub(crate) fn test_server_cfg(cfg: SrvCfg) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut s) = conn else { return };
                let cfg = cfg.clone();
                std::thread::spawn(move || serve(&mut s, &cfg));
            }
        });
        port
    }

    pub(crate) fn test_server() -> u16 {
        test_server_cfg(none_cfg())
    }

    fn serve(s: &mut TcpStream, cfg: &SrvCfg) {
        let id = &uac::tests::ids().1;
        let server_cert = if cfg.endpoints.iter().any(|e| e.0 != Policy::None) {
            id.cert.clone()
        } else {
            Vec::new()
        };
        let Some((k, _, _)) = read_frame(s) else {
            return;
        };
        assert_eq!(&k, b"HEL");
        let mut ack = W::default();
        ack.u32(0).u32(65536).u32(65536).u32(0).u32(0);
        s.write_all(&frame(b"ACK", b'F', &ack.0)).unwrap();
        let mut st = Srv {
            policy: Policy::None,
            encrypt: false,
            client_cert: Vec::new(),
            keys: Vec::new(),
            session_nonce: Vec::new(),
            seq: 0,
        };
        let mut next_token = 1;
        while let Some((kind, chunk, b)) = read_frame(s) {
            let mut fr = kind.to_vec();
            fr.push(chunk);
            fr.extend_from_slice(&((b.len() + 8) as u32).to_le_bytes());
            fr.extend_from_slice(&b);
            let mut token = 0;
            let payload = if &kind == b"OPN" {
                let (h, _) = uac::asym_header(&fr).unwrap();
                let p = Policy::from_uri(&h.policy_uri).unwrap();
                if p != Policy::None && cfg.reject_secure {
                    let mut e = W::default();
                    e.u32(0x8013_0000).string(Some("certificate not trusted"));
                    s.write_all(&frame(b"ERR", b'F', &e.0)).unwrap();
                    return;
                }
                let (h, p2) = uac::open_asym(
                    &fr,
                    Some(&Local {
                        cert: &id.cert,
                        key: &id.key,
                    }),
                )
                .unwrap();
                st.policy = p;
                st.client_cert = h.sender_cert;
                p2
            } else {
                token = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
                let k = st.keys.iter().find(|k| k.0 == token).map(|k| &k.1);
                assert!(
                    st.policy == Policy::None || k.is_some(),
                    "unknown token {token}"
                );
                uac::open_sym(st.policy, st.encrypt, &fr, k).expect("client chunk verifies")
            };
            let mut r = R::new(&payload);
            r.u32().unwrap();
            let req = r.u32().unwrap();
            if &kind == b"CLO" {
                return;
            }
            let t = r.node_id().unwrap();
            // Skip the request header.
            r.node_id().unwrap();
            r.i64().unwrap();
            r.u32().unwrap();
            r.u32().unwrap();
            r.string().unwrap();
            r.u32().unwrap();
            r.extension_object().unwrap();
            let Ident::Num(t) = t.id else { panic!() };
            let mut w = W::default();
            let mut split = false;
            let mut reply_kind: &[u8; 3] = b"MSG";
            match t {
                id::OPN_REQ => {
                    r.u32().unwrap();
                    r.u32().unwrap();
                    let mode = r.u32().unwrap();
                    let client_nonce = r.bytes().unwrap().unwrap_or_default();
                    st.encrypt = mode == 3;
                    let server_nonce = uac::random(st.policy.nonce_len());
                    token = next_token;
                    next_token += 1;
                    if st.policy != Policy::None {
                        assert_eq!(client_nonce.len(), st.policy.nonce_len());
                        st.keys.push((
                            token,
                            uac::derive(st.policy, &server_nonce, &client_nonce),
                            uac::derive(st.policy, &client_nonce, &server_nonce),
                        ));
                    }
                    w.type_id(id::OPN_RESP);
                    resp_header(&mut w, 0);
                    w.u32(0)
                        .u32(7)
                        .u32(token)
                        .i64(now_ticks())
                        .u32(600_000)
                        .bytes((!server_nonce.is_empty()).then_some(&server_nonce[..]));
                    reply_kind = b"OPN";
                }
                id::GET_ENDPOINTS_REQ => {
                    w.type_id(id::GET_ENDPOINTS_RESP);
                    resp_header(&mut w, 0);
                    endpoints_body(&mut w, &cfg.endpoints, &server_cert);
                    split = true;
                }
                id::FIND_SERVERS_REQ => {
                    w.type_id(id::FIND_SERVERS_RESP);
                    resp_header(&mut w, 0);
                    w.i32(0);
                }
                id::CREATE_SESSION_REQ => {
                    let app_uri = r.str().unwrap();
                    r.string().unwrap();
                    r.localized().unwrap();
                    r.u32().unwrap();
                    r.string().unwrap();
                    r.string().unwrap();
                    r.array(|r| r.str()).unwrap();
                    r.string().unwrap();
                    r.string().unwrap();
                    r.string().unwrap();
                    let client_nonce = r.bytes().unwrap().unwrap_or_default();
                    let client_cert = r.bytes().unwrap().unwrap_or_default();
                    if st.policy != Policy::None {
                        assert_eq!(client_cert, st.client_cert);
                        assert_eq!(uac::cert_uris(&client_cert), vec![app_uri]);
                    }
                    st.session_nonce = uac::random(32);
                    w.type_id(id::CREATE_SESSION_RESP);
                    resp_header(&mut w, 0);
                    w.node_id(&NodeId::num(1, 1001))
                        .node_id(&NodeId {
                            ns: 0,
                            id: Ident::Bytes(vec![9; 8]),
                        })
                        .f64(60_000.0)
                        .bytes(Some(&st.session_nonce))
                        .bytes((!server_cert.is_empty()).then_some(&server_cert[..]));
                    endpoints_body(&mut w, &cfg.endpoints, &server_cert);
                    w.i32(0);
                    if st.policy != Policy::None {
                        let mut d = client_cert.clone();
                        d.extend_from_slice(&client_nonce);
                        w.string(Some(st.policy.sig_algorithm_uri()))
                            .bytes(Some(&uac::rsa_sign(st.policy, &id.key, &d).unwrap()));
                    } else {
                        w.string(None).bytes(None);
                    }
                    w.u32(0);
                }
                id::ACTIVATE_SESSION_REQ => {
                    let _alg = r.string().unwrap();
                    let sig = r.bytes().unwrap().unwrap_or_default();
                    r.array(|r| {
                        r.bytes()?;
                        r.bytes()
                    })
                    .unwrap();
                    r.array(|r| r.str()).unwrap();
                    let (tt, tb) = r.extension_object().unwrap();
                    r.string().unwrap();
                    let tsig = r.bytes().unwrap().unwrap_or_default();
                    let mut signed = server_cert.clone();
                    signed.extend_from_slice(&st.session_nonce);
                    let mut status = 0;
                    if st.policy != Policy::None {
                        let ck = uac::cert_public_key(&st.client_cert).unwrap();
                        if uac::rsa_verify(st.policy, &ck, &signed, &sig).is_err() {
                            status = 0x8058_0000;
                        }
                    }
                    let tb = tb.unwrap_or_default();
                    let mut tr = R::new(&tb);
                    let pid = tr.str().unwrap();
                    let ttype: u32 = pid[3..].parse().unwrap();
                    let token_sp = cfg
                        .endpoints
                        .iter()
                        .find(|e| e.0 == st.policy)
                        .and_then(|e| e.2.iter().find(|x| x.0 == ttype))
                        .map(|x| x.1.clone())
                        .unwrap_or_default();
                    let eff = Policy::from_uri(&token_sp).unwrap_or(st.policy);
                    match tt {
                        NodeId {
                            id: Ident::Num(id::USERNAME_TOKEN),
                            ..
                        } => {
                            let user = tr.str().unwrap();
                            let pw = tr.bytes().unwrap().unwrap_or_default();
                            let alg = tr.str().unwrap();
                            let pw = if alg.is_empty() {
                                assert_eq!(eff, Policy::None);
                                pw
                            } else {
                                assert_eq!(alg, eff.enc_algorithm_uri());
                                let p = uac::rsa_decrypt(eff, &id.key, &pw).unwrap();
                                let n = u32::from_le_bytes(p[..4].try_into().unwrap()) as usize;
                                assert_eq!(&p[4 + n - 32..4 + n], &st.session_nonce[..]);
                                p[4..4 + n - 32].to_vec()
                            };
                            if user != "op" || pw != b"secret" {
                                status = 0x801F_0000;
                            }
                        }
                        NodeId {
                            id: Ident::Num(id::X509_TOKEN),
                            ..
                        } => {
                            let uc = tr.bytes().unwrap().unwrap_or_default();
                            let uk = uac::cert_public_key(&uc).unwrap();
                            if uac::rsa_verify(eff, &uk, &signed, &tsig).is_err() {
                                status = 0x8057_0000;
                            }
                        }
                        _ => {}
                    }
                    w.type_id(id::ACTIVATE_SESSION_RESP);
                    resp_header(&mut w, status);
                    st.session_nonce = uac::random(32);
                    w.bytes(Some(&st.session_nonce)).i32(0).i32(0);
                }
                id::BROWSE_REQ | id::BROWSE_NEXT_REQ => {
                    let first = t == id::BROWSE_REQ;
                    w.type_id(if first {
                        id::BROWSE_RESP
                    } else {
                        id::BROWSE_NEXT_RESP
                    });
                    resp_header(&mut w, 0);
                    w.i32(1).u32(0);
                    if first {
                        w.bytes(Some(b"cp"));
                    } else {
                        w.bytes(None);
                    }
                    let name = if first { "Server" } else { "Demo" };
                    let node = if first {
                        NodeId::num(0, 2253)
                    } else {
                        NodeId {
                            ns: 2,
                            id: Ident::Str("Demo".into()),
                        }
                    };
                    w.i32(1)
                        .type_id(35)
                        .bool(true)
                        .node_id(&node)
                        .u16(node.ns)
                        .string(Some(name))
                        .localized(name)
                        .u32(1)
                        .type_id(61);
                    w.i32(0);
                }
                id::READ_REQ => {
                    r.f64().unwrap();
                    r.u32().unwrap();
                    let n = r.i32().unwrap();
                    w.type_id(id::READ_RESP);
                    resp_header(&mut w, 0);
                    w.i32(n);
                    for _ in 0..n {
                        let node = r.node_id().unwrap();
                        let attr = r.u32().unwrap();
                        r.string().unwrap();
                        r.qualified_name().unwrap();
                        if node == NodeId::num(0, 9999) {
                            w.u8(0x02).u32(0x8034_0000);
                        } else if attr == 13 {
                            w.u8(0x0d).u8(6).i32(42).u32(0).i64(now_ticks());
                        } else if attr == 4 {
                            w.u8(0x01).u8(21).localized("Name");
                        } else {
                            w.u8(0x02).u32(0x8035_0000);
                        }
                    }
                    w.i32(0);
                }
                id::CLOSE_SESSION_REQ => {
                    w.type_id(id::CLOSE_SESSION_RESP);
                    resp_header(&mut w, 0);
                }
                _ => {
                    w.type_id(id::SERVICE_FAULT);
                    resp_header(&mut w, 0x800B_0000);
                }
            }
            st.reply(s, reply_kind, token, req, &w.0, split);
        }
    }

    #[test]
    fn client_against_test_server() {
        let port = test_server();
        let url = format!("opc.tcp://127.0.0.1:{port}");
        let mut c = Client::connect(&url, Duration::from_secs(5)).unwrap();
        let d = discover(&mut c).unwrap();
        assert_eq!(d.endpoints.len(), 1);
        assert_eq!(d.endpoints[0].server.name, "Test Server");
        assert_eq!(d.endpoints[0].tokens.len(), 2);
        assert!(
            d.findings
                .iter()
                .any(|f| f.key == "Unsecured endpoint" && f.level == Level::Bad)
        );
        let (_, t) = pick_endpoint(&d.endpoints, Policy::None, 1, 0).unwrap();
        let (sid, timeout) = c.create_session().unwrap();
        assert_eq!(sid, NodeId::num(1, 1001));
        assert_eq!(timeout, 60_000.0);
        c.activate_session(&Identity::Anonymous(t.policy_id))
            .unwrap();
        let refs = c.browse(&NodeId::num(0, OBJECTS)).unwrap();
        assert_eq!(
            refs.iter().map(|r| r.display.as_str()).collect::<Vec<_>>(),
            vec!["Server", "Demo"]
        );
        assert_eq!(refs[1].node.to_string(), "ns=2;s=Demo");
        let attrs = read_attributes(&mut c, &refs[1].node).unwrap();
        assert!(
            attrs
                .iter()
                .any(|(a, v)| *a == 13 && v.value == Value::Int(42, 6) && v.source_ts.is_some())
        );
        assert!(
            attrs
                .iter()
                .any(|(a, v)| *a == 4 && v.value.display() == "Name")
        );
        let bad = c.read(&[(NodeId::num(0, 9999), 13)]).unwrap();
        assert_eq!(status_name(bad[0].status), "BadNodeIdUnknown");
        c.close();
    }

    fn secure_cfg() -> SrvCfg {
        let b256 = Policy::Basic256Sha256.uri();
        SrvCfg {
            endpoints: vec![
                (Policy::None, 1, vec![(0, String::new()), (1, b256.clone())]),
                (
                    Policy::Basic256Sha256,
                    3,
                    vec![(0, String::new()), (1, String::new())],
                ),
                (Policy::Aes256Sha256RsaPss, 2, vec![(1, b256.clone())]),
                (
                    Policy::Aes128Sha256RsaOaep,
                    3,
                    vec![(1, String::new()), (2, String::new())],
                ),
                (Policy::Basic256, 3, vec![(1, String::new())]),
                (Policy::Basic128Rsa15, 2, vec![(1, String::new())]),
            ],
            reject_secure: false,
        }
    }

    fn security(policy: Policy, mode: u32) -> Security {
        let (c, s) = uac::tests::ids();
        Security {
            policy,
            mode,
            identity: c.clone(),
            server_cert: s.cert.clone(),
        }
    }

    fn user(policy: &str, sp: &str, pw: &str) -> Identity {
        Identity::User {
            policy: policy.into(),
            security_policy: sp.into(),
            user: "op".into(),
            password: pw.into(),
        }
    }

    #[test]
    fn secured_sessions_end_to_end() {
        let port = test_server_cfg(secure_cfg());
        let url = format!("opc.tcp://127.0.0.1:{port}");
        let cases = [
            (Policy::Basic256Sha256, 3, ""),
            (
                Policy::Aes256Sha256RsaPss,
                2,
                "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            ),
            (Policy::Aes128Sha256RsaOaep, 3, ""),
            (Policy::Basic256, 3, ""),
            (Policy::Basic128Rsa15, 2, ""),
        ];
        for (p, mode, sp) in cases {
            let mut c = Client::connect_with(&url, Duration::from_secs(5), Some(security(p, mode)))
                .unwrap_or_else(|e| panic!("{p:?}: {e}"));
            assert_eq!(
                c.security_text(),
                format!("{} / {}", p.name(), mode_name(mode))
            );
            // Endpoints over the secured channel (two chunks).
            assert_eq!(c.get_endpoints().unwrap().len(), 6);
            c.create_session().unwrap();
            c.activate_session(&user("tok1", sp, "secret"))
                .unwrap_or_else(|e| panic!("{p:?}: {e}"));
            assert_eq!(c.browse(&NodeId::num(0, OBJECTS)).unwrap().len(), 2);
            // Token renewal: new keys, reads keep working.
            c.open_channel(true).unwrap();
            assert_eq!(c.keys.len(), 2);
            let v = c.read(&[(NodeId::num(2, 5), 13)]).unwrap();
            assert_eq!(v[0].value, Value::Int(42, 6));
            c.close();
            // A wrong password is refused (and decrypted correctly server-side).
            let mut c = Client::connect_with(&url, Duration::from_secs(5), Some(security(p, mode)))
                .unwrap();
            c.create_session().unwrap();
            let e = c.activate_session(&user("tok1", sp, "wrong")).unwrap_err();
            assert!(e.contains("BadUserAccessDenied"), "{e}");
            assert!(hint(&e).is_some());
        }
        // Anonymous on Basic256Sha256; X.509 user token on Aes128.
        let mut c = Client::connect_with(
            &url,
            Duration::from_secs(5),
            Some(security(Policy::Basic256Sha256, 3)),
        )
        .unwrap();
        c.create_session().unwrap();
        c.activate_session(&Identity::Anonymous("tok0".into()))
            .unwrap();
        c.close();
        let (uc, _) = uac::tests::ids();
        let mut c = Client::connect_with(
            &url,
            Duration::from_secs(5),
            Some(security(Policy::Aes128Sha256RsaOaep, 3)),
        )
        .unwrap();
        c.create_session().unwrap();
        c.activate_session(&Identity::Cert {
            policy: "tok2".into(),
            security_policy: String::new(),
            cert: uc.cert.clone(),
            key: Box::new(uc.key.clone()),
        })
        .unwrap();
        c.close();
        // Password encrypted with Basic256Sha256 over an unsecured channel.
        let mut c = Client::connect(&url, Duration::from_secs(5)).unwrap();
        c.create_session().unwrap();
        c.activate_session(&user("tok1", &Policy::Basic256Sha256.uri(), "secret"))
            .unwrap();
        c.close();
    }

    #[test]
    fn open_session_checks_trust_and_rejections() {
        let port = test_server_cfg(secure_cfg());
        let url = format!("opc.tcp://127.0.0.1:{port}");
        let (cid, sid) = uac::tests::ids();
        let dir = std::env::temp_dir().join(format!("na-opcua-sess-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cp, kp) = (dir.join("c.der"), dir.join("k.pem"));
        std::fs::write(&cp, &cid.cert).unwrap();
        std::fs::write(
            &kp,
            uac::pem_encode(
                "PRIVATE KEY",
                rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&cid.key)
                    .unwrap()
                    .as_bytes(),
            ),
        )
        .unwrap();
        let mut opts = SessionOpts {
            policy: Policy::Basic256Sha256,
            mode: 3,
            login: Login::User("op".into(), "secret".into()),
            client_cert: Some((cp.clone(), kp.clone())),
            accepted_server: None,
        };
        let log = |_: Level, _: String| {};
        let discover_at = |url: &str| {
            let mut c = Client::connect(url, Duration::from_secs(5)).unwrap();
            let d = discover(&mut c).unwrap();
            (c, d.endpoints)
        };
        // Not accepted → refused before any secured traffic.
        let (c, eps) = discover_at(&url);
        let e = open_session(c, &eps, &opts, &log, &|_| {}).err().unwrap();
        assert!(e.contains("not been accepted"), "{e}");
        // Wrong thumbprint → refused.
        opts.accepted_server = Some("00".repeat(20));
        let (c, eps) = discover_at(&url);
        let e = open_session(c, &eps, &opts, &log, &|_| {}).err().unwrap();
        assert!(e.contains("changed"), "{e}");
        // Accepted → session.
        opts.accepted_server = Some(uac::hex(&uac::thumbprint(&sid.cert)));
        let (c, eps) = discover_at(&url);
        let seen = std::cell::Cell::new(false);
        let mut o = open_session(c, &eps, &opts, &log, &|s| {
            assert_eq!(s.app_uri, "urn:test:client");
            seen.set(true)
        })
        .unwrap();
        assert!(seen.get());
        assert_eq!(o.identity, "user op");
        assert_eq!(o.client.browse(&NodeId::num(0, OBJECTS)).unwrap().len(), 2);
        o.client.close();
        // A login type the endpoint does not offer.
        opts.login = Login::Anonymous;
        opts.policy = Policy::Aes256Sha256RsaPss;
        opts.mode = 0;
        let (c, eps) = discover_at(&url);
        let e = open_session(c, &eps, &opts, &log, &|_| {}).err().unwrap();
        assert!(e.contains("does not accept anonymous"), "{e}");
        // A server that does not trust us.
        let mut cfg = secure_cfg();
        cfg.reject_secure = true;
        let port = test_server_cfg(cfg);
        let url2 = format!("opc.tcp://127.0.0.1:{port}");
        opts.policy = Policy::Basic256Sha256;
        opts.mode = 3;
        opts.login = Login::Anonymous;
        let (c, eps) = discover_at(&url2);
        let e = with_hint(open_session(c, &eps, &opts, &log, &|_| {}).err().unwrap());
        assert!(e.contains("BadSecurityChecksFailed"), "{e}");
        assert!(e.contains("trusted list"), "{e}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn worker_against_test_server() {
        let port = test_server();
        let (h, rx) = start(
            format!("opc.tcp://127.0.0.1:{port}"),
            Auth::Session(SessionOpts::anonymous_none()),
            Duration::from_secs(5),
        );
        let mut session = false;
        let mut browsed = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !(session && browsed) && Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Session(s) => {
                    assert_eq!(s.security, "None");
                    session = true
                }
                Event::Browsed(n, r) => {
                    assert_eq!(n, NodeId::num(0, OBJECTS));
                    assert_eq!(r.unwrap().len(), 2);
                    browsed = true;
                }
                Event::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
        h.send(Cmd::SetWatch(vec![NodeId::num(2, 5)]));
        loop {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Watch(v) => {
                    assert_eq!(v[0].1.value, Value::Int(42, 6));
                    break;
                }
                Event::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
        drop(h);
    }
}
