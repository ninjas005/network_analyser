//! BACnet/IP client: BVLC, NPDU (incl. routed devices), APDU and tag
//! encoding written by hand. Who-Is / I-Am discovery, ReadProperty with
//! Error / Reject / Abort handling, object-list reading with the index
//! fallback, and value formatting for common properties.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

pub const PORT: u16 = 47808;

// ---------------------------------------------------------------- names

pub const OBJECT_TYPES: &[&str] = &[
    "analog-input",
    "analog-output",
    "analog-value",
    "binary-input",
    "binary-output",
    "binary-value",
    "calendar",
    "command",
    "device",
    "event-enrollment",
    "file",
    "group",
    "loop",
    "multi-state-input",
    "multi-state-output",
    "notification-class",
    "program",
    "schedule",
    "averaging",
    "multi-state-value",
    "trend-log",
    "life-safety-point",
    "life-safety-zone",
    "accumulator",
    "pulse-converter",
    "event-log",
    "global-group",
    "trend-log-multiple",
    "load-control",
    "structured-view",
    "access-door",
    "timer",
    "access-credential",
    "access-point",
    "access-rights",
    "access-user",
    "access-zone",
    "credential-data-input",
    "network-security",
    "bitstring-value",
    "characterstring-value",
    "date-pattern-value",
    "date-value",
    "datetime-pattern-value",
    "datetime-value",
    "integer-value",
    "large-analog-value",
    "octetstring-value",
    "positive-integer-value",
    "time-pattern-value",
    "time-value",
    "notification-forwarder",
    "alert-enrollment",
    "channel",
    "lighting-output",
    "binary-lighting-output",
    "network-port",
    "elevator-group",
    "escalator",
    "lift",
];

pub const OBJ_DEVICE: u16 = 8;

pub fn object_type_name(t: u16) -> String {
    OBJECT_TYPES
        .get(t as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("type-{t}"))
}

/// Short form used in tables: AI, AO, BV, MSV…
pub fn object_type_abbr(t: u16) -> String {
    match t {
        0 => "AI".into(),
        1 => "AO".into(),
        2 => "AV".into(),
        3 => "BI".into(),
        4 => "BO".into(),
        5 => "BV".into(),
        8 => "DEV".into(),
        13 => "MSI".into(),
        14 => "MSO".into(),
        19 => "MSV".into(),
        20 => "TL".into(),
        _ => object_type_name(t),
    }
}

pub fn parse_object_type(s: &str) -> Option<u16> {
    let s = s.trim().to_ascii_lowercase();
    if let Ok(n) = s.parse::<u16>() {
        return (n < 1024).then_some(n);
    }
    let abbr = [
        ("ai", 0),
        ("ao", 1),
        ("av", 2),
        ("bi", 3),
        ("bo", 4),
        ("bv", 5),
        ("dev", 8),
        ("msi", 13),
        ("mso", 14),
        ("msv", 19),
        ("tl", 20),
    ];
    abbr.iter()
        .find(|(a, _)| *a == s)
        .map(|(_, n)| *n)
        .or_else(|| OBJECT_TYPES.iter().position(|n| *n == s).map(|p| p as u16))
}

pub const PROPERTIES: &[(u32, &str)] = &[
    (4, "active-text"),
    (12, "application-software-version"),
    (22, "cov-increment"),
    (28, "description"),
    (30, "device-address-binding"),
    (36, "event-state"),
    (44, "firmware-revision"),
    (46, "inactive-text"),
    (56, "local-date"),
    (57, "local-time"),
    (58, "location"),
    (62, "max-apdu-length-accepted"),
    (65, "max-pres-value"),
    (69, "min-pres-value"),
    (70, "model-name"),
    (74, "number-of-states"),
    (75, "object-identifier"),
    (76, "object-list"),
    (77, "object-name"),
    (79, "object-type"),
    (81, "out-of-service"),
    (85, "present-value"),
    (87, "priority-array"),
    (96, "protocol-object-types-supported"),
    (97, "protocol-services-supported"),
    (98, "protocol-version"),
    (103, "reliability"),
    (104, "relinquish-default"),
    (107, "segmentation-supported"),
    (110, "state-text"),
    (111, "status-flags"),
    (112, "system-status"),
    (117, "units"),
    (119, "utc-offset"),
    (120, "vendor-identifier"),
    (121, "vendor-name"),
    (139, "protocol-revision"),
    (155, "database-revision"),
    (371, "property-list"),
];

pub const P_OBJECT_LIST: u32 = 76;
pub const P_OBJECT_NAME: u32 = 77;
pub const P_PRESENT_VALUE: u32 = 85;
pub const P_STATUS_FLAGS: u32 = 111;
pub const P_UNITS: u32 = 117;

pub fn property_name(p: u32) -> String {
    PROPERTIES
        .iter()
        .find(|(n, _)| *n == p)
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| format!("property-{p}"))
}

pub fn parse_property(s: &str) -> Option<u32> {
    let s = s.trim().to_ascii_lowercase();
    if let Ok(n) = s.parse::<u32>() {
        return (n < 4_194_304).then_some(n);
    }
    let s = match s.as_str() {
        "pv" => "present-value",
        "name" => "object-name",
        other => other,
    };
    PROPERTIES.iter().find(|(_, n)| *n == s).map(|(p, _)| *p)
}

/// Engineering units (ASHRAE 135 enumeration, first 105 values).
const UNITS: &[&str] = &[
    "m²",
    "ft²",
    "mA",
    "A",
    "Ω",
    "V",
    "kV",
    "MV",
    "VA",
    "kVA",
    "MVA",
    "var",
    "kvar",
    "Mvar",
    "°φ",
    "PF",
    "J",
    "kJ",
    "Wh",
    "kWh",
    "BTU",
    "therm",
    "ton·h",
    "J/kg",
    "BTU/lb",
    "cycles/h",
    "cycles/min",
    "Hz",
    "g/kg",
    "%RH",
    "mm",
    "m",
    "in",
    "ft",
    "W/ft²",
    "W/m²",
    "lm",
    "lx",
    "fc",
    "kg",
    "lb",
    "ton",
    "kg/s",
    "kg/min",
    "kg/h",
    "lb/min",
    "lb/h",
    "W",
    "kW",
    "MW",
    "BTU/h",
    "hp",
    "ton(ref)",
    "Pa",
    "kPa",
    "bar",
    "psi",
    "cmH₂O",
    "inH₂O",
    "mmHg",
    "cmHg",
    "inHg",
    "°C",
    "K",
    "°F",
    "°C·d",
    "°F·d",
    "years",
    "months",
    "weeks",
    "days",
    "h",
    "min",
    "s",
    "m/s",
    "km/h",
    "ft/s",
    "ft/min",
    "mph",
    "ft³",
    "m³",
    "imp gal",
    "l",
    "US gal",
    "cfm",
    "m³/s",
    "imp gal/min",
    "l/s",
    "l/min",
    "US gpm",
    "°",
    "°C/h",
    "°C/min",
    "°F/h",
    "°F/min",
    "",
    "ppm",
    "ppb",
    "%",
    "%/s",
    "/min",
    "/s",
    "psi/°F",
    "rad",
    "rpm",
];

pub fn units_name(u: u32) -> String {
    UNITS
        .get(u as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("units-{u}"))
}

pub fn segmentation_name(s: u32) -> &'static str {
    match s {
        0 => "both",
        1 => "transmit",
        2 => "receive",
        3 => "none",
        _ => "?",
    }
}

pub fn vendor_name(v: u32) -> Option<&'static str> {
    const V: &[&str] = &[
        "ASHRAE",
        "NIST",
        "Trane",
        "McQuay",
        "PolarSoft",
        "Johnson Controls",
        "American Auto-Matrix",
        "Siemens Building Technologies",
        "Delta Controls",
        "Siemens Schweiz",
        "Schneider Electric",
        "TAC",
        "Orion Analysis",
        "Teletrol",
        "Cimetrics",
        "Cornell University",
        "Carrier",
        "Honeywell",
    ];
    V.get(v as usize).copied()
}

fn enum_name(prop: u32, v: u32) -> Option<String> {
    let s = match prop {
        117 => return Some(units_name(v)),
        79 => return Some(object_type_name(v as u16)),
        107 => segmentation_name(v),
        36 => [
            "normal",
            "fault",
            "offnormal",
            "high-limit",
            "low-limit",
            "life-safety-alarm",
        ]
        .get(v as usize)?,
        112 => [
            "operational",
            "operational-read-only",
            "download-required",
            "download-in-progress",
            "non-operational",
            "backup-in-progress",
        ]
        .get(v as usize)?,
        103 => [
            "no-fault-detected",
            "no-sensor",
            "over-range",
            "under-range",
            "open-loop",
            "shorted-loop",
            "no-output",
            "unreliable-other",
            "process-error",
            "multi-state-fault",
            "configuration-error",
        ]
        .get(v as usize)?,
        // Binary present-value / relinquish-default.
        85 | 104 => ["inactive", "active"].get(v as usize)?,
        _ => return None,
    };
    Some(s.to_string())
}

pub fn error_class_name(c: u32) -> &'static str {
    [
        "device",
        "object",
        "property",
        "resources",
        "security",
        "services",
        "vt",
        "communication",
    ]
    .get(c as usize)
    .copied()
    .unwrap_or("?")
}

pub fn error_code_name(c: u32) -> String {
    match c {
        0 => "other",
        2 => "configuration-in-progress",
        3 => "device-busy",
        9 => "invalid-data-type",
        25 => "operational-problem",
        27 => "read-access-denied",
        31 => "unknown-object",
        32 => "unknown-property",
        42 => "invalid-array-index",
        50 => "property-is-not-an-array",
        _ => return format!("code {c}"),
    }
    .into()
}

pub fn reject_reason(r: u8) -> &'static str {
    [
        "other",
        "buffer-overflow",
        "inconsistent-parameters",
        "invalid-parameter-data-type",
        "invalid-tag",
        "missing-required-parameter",
        "parameter-out-of-range",
        "too-many-arguments",
        "undefined-enumeration",
        "unrecognized-service",
    ]
    .get(r as usize)
    .copied()
    .unwrap_or("?")
}

pub fn abort_reason(r: u8) -> &'static str {
    [
        "other",
        "buffer-overflow",
        "invalid-apdu-in-this-state",
        "preempted-by-higher-priority-task",
        "segmentation-not-supported",
        "security-error",
        "insufficient-security",
        "window-size-out-of-range",
        "application-exceeded-reply-time",
        "out-of-resources",
        "tsm-timeout",
        "apdu-too-long",
    ]
    .get(r as usize)
    .copied()
    .unwrap_or("?")
}

// ---------------------------------------------------------------- tags

fn unsigned_bytes(v: u32) -> Vec<u8> {
    let b = v.to_be_bytes();
    let skip = b.iter().take(3).take_while(|x| **x == 0).count();
    b[skip..].to_vec()
}

fn tag_header(num: u8, ctx: bool, len: usize) -> Vec<u8> {
    let mut h = Vec::new();
    let class = if ctx { 0x08 } else { 0 };
    let (first_num, ext_num) = if num <= 14 {
        (num, None)
    } else {
        (15, Some(num))
    };
    let lvt = if len <= 4 { len as u8 } else { 5 };
    h.push((first_num << 4) | class | lvt);
    if let Some(n) = ext_num {
        h.push(n);
    }
    if len > 4 {
        if len <= 253 {
            h.push(len as u8);
        } else if len <= 65535 {
            h.push(254);
            h.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            h.push(255);
            h.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    h
}

pub fn ctx_unsigned(tag: u8, v: u32) -> Vec<u8> {
    let b = unsigned_bytes(v);
    let mut out = tag_header(tag, true, b.len());
    out.extend(b);
    out
}

pub fn objid(t: u16, inst: u32) -> u32 {
    ((t as u32) << 22) | (inst & 0x3f_ffff)
}

pub fn ctx_objid(tag: u8, t: u16, inst: u32) -> Vec<u8> {
    let mut out = tag_header(tag, true, 4);
    out.extend_from_slice(&objid(t, inst).to_be_bytes());
    out
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tag {
    pub num: u8,
    pub ctx: bool,
    /// Length, or the boolean value for application Boolean.
    pub len: usize,
    pub open: bool,
    pub close: bool,
}

/// Decode a tag header at `p`; returns the tag and the header length.
pub fn read_tag(b: &[u8], p: usize) -> Option<(Tag, usize)> {
    let x = *b.get(p)?;
    let mut i = p + 1;
    let mut num = x >> 4;
    if num == 15 {
        num = *b.get(i)?;
        i += 1;
    }
    let ctx = x & 0x08 != 0;
    let lvt = x & 0x07;
    let (mut len, mut open, mut close) = (lvt as usize, false, false);
    if ctx && lvt == 6 {
        open = true;
        len = 0;
    } else if ctx && lvt == 7 {
        close = true;
        len = 0;
    } else if lvt == 5 {
        let e = *b.get(i)?;
        i += 1;
        len = match e {
            254 => {
                let v = u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize;
                i += 2;
                v
            }
            255 => {
                let v = u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize;
                i += 4;
                v
            }
            n => n as usize,
        };
    }
    Some((
        Tag {
            num,
            ctx,
            len,
            open,
            close,
        },
        i - p,
    ))
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Real(f32),
    Double(f64),
    Octets(Vec<u8>),
    Str(String),
    Bits(Vec<bool>),
    Enum(u32),
    /// year, month, day, weekday (255 = any)
    Date(u16, u8, u8, u8),
    /// hour, minute, second, hundredths
    Time(u8, u8, u8, u8),
    ObjectId(u16, u32),
    /// Context-tagged primitive (meaning depends on the property).
    Ctx(u8, Vec<u8>),
    /// Constructed value between opening/closing context tags.
    List(u8, Vec<Value>),
}

fn be_uint(d: &[u8]) -> u64 {
    d.iter().take(8).fold(0u64, |a, b| (a << 8) | *b as u64)
}

fn decode_app(tag: Tag, d: &[u8]) -> Value {
    match tag.num {
        0 => Value::Null,
        1 => Value::Bool(tag.len != 0),
        2 => Value::Unsigned(be_uint(d)),
        3 => {
            let u = be_uint(d);
            let bits = d.len().min(8) * 8;
            Value::Signed(if bits == 0 || bits == 64 {
                u as i64
            } else {
                ((u << (64 - bits)) as i64) >> (64 - bits)
            })
        }
        4 if d.len() == 4 => Value::Real(f32::from_be_bytes(d.try_into().unwrap_or([0; 4]))),
        5 if d.len() == 8 => Value::Double(f64::from_be_bytes(d.try_into().unwrap_or([0; 8]))),
        6 => Value::Octets(d.to_vec()),
        7 => Value::Str(match d.first() {
            // UCS-2 big endian
            Some(4) => {
                let u: Vec<u16> = d[1..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes(*c))
                    .collect();
                String::from_utf16_lossy(&u)
            }
            // ISO 8859-1
            Some(5) => d[1..].iter().map(|&c| c as char).collect(),
            Some(_) => String::from_utf8_lossy(&d[1..]).into_owned(),
            None => String::new(),
        }),
        8 => {
            let unused = d.first().copied().unwrap_or(0) as usize;
            let mut bits = Vec::new();
            for byte in d.iter().skip(1) {
                for i in (0..8).rev() {
                    bits.push(byte >> i & 1 == 1);
                }
            }
            bits.truncate(bits.len().saturating_sub(unused));
            Value::Bits(bits)
        }
        9 => Value::Enum(be_uint(d) as u32),
        10 if d.len() == 4 => Value::Date(
            if d[0] == 255 {
                0xffff
            } else {
                1900 + d[0] as u16
            },
            d[1],
            d[2],
            d[3],
        ),
        11 if d.len() == 4 => Value::Time(d[0], d[1], d[2], d[3]),
        12 if d.len() == 4 => {
            let v = u32::from_be_bytes(d.try_into().unwrap_or([0; 4]));
            Value::ObjectId((v >> 22) as u16, v & 0x3f_ffff)
        }
        _ => Value::Octets(d.to_vec()),
    }
}

/// Decode a run of tagged values until the end or an unmatched closing tag.
pub fn decode_values(b: &[u8], mut p: usize) -> Result<(Vec<Value>, usize), String> {
    let mut out = Vec::new();
    while p < b.len() {
        let (t, h) = read_tag(b, p).ok_or("truncated tag")?;
        if t.close {
            return Ok((out, p));
        }
        p += h;
        if t.open {
            let (inner, q) = decode_values(b, p)?;
            let (ct, ch) = read_tag(b, q).ok_or("missing closing tag")?;
            if !ct.close || ct.num != t.num {
                return Err("mismatched closing tag".into());
            }
            out.push(Value::List(t.num, inner));
            p = q + ch;
            continue;
        }
        let dlen = if !t.ctx && t.num == 1 { 0 } else { t.len };
        let d = b.get(p..p + dlen).ok_or("truncated value")?;
        out.push(if t.ctx {
            Value::Ctx(t.num, d.to_vec())
        } else {
            decode_app(t, d)
        });
        p += dlen;
    }
    Ok((out, p))
}

fn fmt_num(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e15 {
        format!("{x:.0}")
    } else {
        let s = format!("{x:.4}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// Human-readable value, with property-specific names for enumerations.
pub fn format_value(prop: u32, v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Unsigned(u) if prop == 120 => match vendor_name(*u as u32) {
            Some(n) => format!("{u} ({n})"),
            None => u.to_string(),
        },
        Value::Unsigned(u) => u.to_string(),
        Value::Signed(i) => i.to_string(),
        Value::Real(f) => fmt_num(*f as f64),
        Value::Double(f) => fmt_num(*f),
        Value::Octets(o) => o
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        Value::Str(s) => s.clone(),
        Value::Bits(bits) if prop == P_STATUS_FLAGS => {
            let names = ["in-alarm", "fault", "overridden", "out-of-service"];
            let set: Vec<&str> = bits
                .iter()
                .zip(names)
                .filter(|(b, _)| **b)
                .map(|(_, n)| n)
                .collect();
            if set.is_empty() {
                "normal".into()
            } else {
                set.join(", ")
            }
        }
        Value::Bits(bits) => bits.iter().map(|b| if *b { '1' } else { '0' }).collect(),
        Value::Enum(e) => enum_name(prop, *e).unwrap_or_else(|| e.to_string()),
        Value::Date(y, m, d, w) => {
            let a = |v: u8| {
                if v == 255 {
                    "*".to_string()
                } else {
                    format!("{v:02}")
                }
            };
            let wd = ["", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
                .get(*w as usize)
                .copied()
                .unwrap_or("");
            format!(
                "{}-{}-{}{}",
                if *y == 0xffff {
                    "*".into()
                } else {
                    y.to_string()
                },
                a(*m),
                a(*d),
                if wd.is_empty() {
                    String::new()
                } else {
                    format!(" ({wd})")
                }
            )
        }
        Value::Time(h, m, s, c) => {
            let a = |v: u8| {
                if v == 255 {
                    "*".to_string()
                } else {
                    format!("{v:02}")
                }
            };
            format!("{}:{}:{}.{}", a(*h), a(*m), a(*s), a(*c))
        }
        Value::ObjectId(t, i) => format!("{},{i}", object_type_name(*t)),
        Value::Ctx(n, d) => format!(
            "[{n}] {}",
            d.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::List(n, inner) => format!(
            "[{n}]{{{}}}",
            inner
                .iter()
                .map(|v| format_value(prop, v))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub fn format_values(prop: u32, vs: &[Value]) -> String {
    match vs {
        [] => String::new(),
        [v] => format_value(prop, v),
        _ => {
            let shown: Vec<String> = vs.iter().take(64).map(|v| format_value(prop, v)).collect();
            let more = if vs.len() > 64 {
                format!(", … +{}", vs.len() - 64)
            } else {
                String::new()
            };
            format!("{{{}{more}}}", shown.join(", "))
        }
    }
}

// ---------------------------------------------------------------- packets

/// NPDU source / destination network address (network number, MAC).
pub type Route = (u16, Vec<u8>);

pub fn npdu(expect_reply: bool, dest: Option<&Route>) -> Vec<u8> {
    let mut n = vec![0x01, if expect_reply { 0x04 } else { 0x00 }];
    if let Some((net, mac)) = dest {
        n[1] |= 0x20;
        n.extend_from_slice(&net.to_be_bytes());
        n.push(mac.len() as u8);
        n.extend_from_slice(mac);
        n.push(0xff); // hop count
    }
    n
}

pub fn bvlc(broadcast: bool, npdu_apdu: &[u8]) -> Vec<u8> {
    let mut b = vec![0x81, if broadcast { 0x0b } else { 0x0a }];
    b.extend_from_slice(&((npdu_apdu.len() + 4) as u16).to_be_bytes());
    b.extend_from_slice(npdu_apdu);
    b
}

/// Who-Is (global broadcast network 0xFFFF so routers forward it).
pub fn who_is(broadcast: bool, low: Option<u32>, high: Option<u32>) -> Vec<u8> {
    let mut p = if broadcast {
        npdu(false, Some(&(0xffff, Vec::new())))
    } else {
        npdu(false, None)
    };
    p.extend_from_slice(&[0x10, 0x08]);
    if let (Some(l), Some(h)) = (low, high) {
        p.extend(ctx_unsigned(0, l));
        p.extend(ctx_unsigned(1, h));
    }
    bvlc(broadcast, &p)
}

pub fn read_property_apdu(invoke: u8, t: u16, inst: u32, prop: u32, index: Option<u32>) -> Vec<u8> {
    // Confirmed request, no segmentation accepted, max APDU 1476.
    let mut a = vec![0x00, 0x05, invoke, 12];
    a.extend(ctx_objid(0, t, inst));
    a.extend(ctx_unsigned(1, prop));
    if let Some(i) = index {
        a.extend(ctx_unsigned(2, i));
    }
    a
}

pub fn read_property(
    invoke: u8,
    route: Option<&Route>,
    t: u16,
    inst: u32,
    prop: u32,
    index: Option<u32>,
) -> Vec<u8> {
    let mut p = npdu(true, route);
    p.extend(read_property_apdu(invoke, t, inst, prop, index));
    bvlc(false, &p)
}

#[derive(Clone, Debug, PartialEq)]
pub struct IAm {
    pub device: u32,
    pub max_apdu: u32,
    pub segmentation: u32,
    pub vendor: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Apdu {
    IAm(IAm),
    WhoIs,
    ComplexAck {
        invoke: u8,
        service: u8,
        segmented: bool,
        data: Vec<u8>,
    },
    SimpleAck {
        invoke: u8,
    },
    Error {
        invoke: u8,
        class: u32,
        code: u32,
    },
    Reject {
        invoke: u8,
        reason: u8,
    },
    Abort {
        invoke: u8,
        reason: u8,
    },
    Other(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    /// Forwarded-NPDU: the original sender.
    pub forwarded_from: Option<SocketAddr>,
    /// NPDU SNET/SADR (device behind a BACnet router).
    pub source: Option<Route>,
    pub apdu: Apdu,
}

pub fn parse_packet(b: &[u8]) -> Option<Packet> {
    if b.len() < 4 || b[0] != 0x81 {
        return None;
    }
    let (mut p, fwd) = match b[1] {
        0x0a | 0x0b => (4, None),
        0x04 if b.len() >= 10 => (
            10,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7])),
                u16::from_be_bytes([b[8], b[9]]),
            )),
        ),
        _ => return None,
    };
    // NPDU
    if *b.get(p)? != 0x01 {
        return None;
    }
    let ctl = *b.get(p + 1)?;
    p += 2;
    if ctl & 0x80 != 0 {
        return None; // network-layer message
    }
    let mut dnet = false;
    if ctl & 0x20 != 0 {
        let dlen = *b.get(p + 2)? as usize;
        p += 3 + dlen;
        dnet = true;
    }
    let mut source = None;
    if ctl & 0x08 != 0 {
        let net = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]);
        let slen = *b.get(p + 2)? as usize;
        source = Some((net, b.get(p + 3..p + 3 + slen)?.to_vec()));
        p += 3 + slen;
    }
    if dnet {
        p += 1; // hop count
    }
    let a = b.get(p..)?;
    Some(Packet {
        forwarded_from: fwd,
        source,
        apdu: parse_apdu(a)?,
    })
}

fn app_values(a: &[u8]) -> Vec<Value> {
    decode_values(a, 0).map(|(v, _)| v).unwrap_or_default()
}

pub fn parse_apdu(a: &[u8]) -> Option<Apdu> {
    let kind = *a.first()? >> 4;
    Some(match kind {
        1 => match *a.get(1)? {
            0 => {
                let v = app_values(&a[2..]);
                match v.as_slice() {
                    [
                        Value::ObjectId(OBJ_DEVICE, inst),
                        Value::Unsigned(max),
                        Value::Enum(seg),
                        Value::Unsigned(vendor),
                        ..,
                    ] => Apdu::IAm(IAm {
                        device: *inst,
                        max_apdu: *max as u32,
                        segmentation: *seg,
                        vendor: *vendor as u32,
                    }),
                    _ => Apdu::Other(1),
                }
            }
            8 => Apdu::WhoIs,
            _ => Apdu::Other(1),
        },
        2 => Apdu::SimpleAck { invoke: *a.get(1)? },
        3 => {
            let segmented = a[0] & 0x08 != 0;
            let (invoke, service, start) = if segmented {
                (*a.get(1)?, *a.get(4)?, 5)
            } else {
                (*a.get(1)?, *a.get(2)?, 3)
            };
            Apdu::ComplexAck {
                invoke,
                service,
                segmented,
                data: a.get(start..)?.to_vec(),
            }
        }
        5 => {
            let v = app_values(a.get(3..)?);
            let (class, code) = match v.as_slice() {
                [Value::Enum(c), Value::Enum(d), ..] => (*c, *d),
                _ => (0, 0),
            };
            Apdu::Error {
                invoke: *a.get(1)?,
                class,
                code,
            }
        }
        6 => Apdu::Reject {
            invoke: *a.get(1)?,
            reason: *a.get(2)?,
        },
        7 => Apdu::Abort {
            invoke: *a.get(1)?,
            reason: *a.get(2)?,
        },
        k => Apdu::Other(k),
    })
}

/// Values of a ReadProperty ComplexACK (between opening/closing tag 3).
pub fn parse_rp_ack(d: &[u8]) -> Result<Vec<Value>, String> {
    let (vals, _) = decode_values(d, 0)?;
    for v in vals {
        if let Value::List(3, inner) = v {
            return Ok(inner);
        }
    }
    Err("no property value in the answer".into())
}

// ---------------------------------------------------------------- client

#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub addr: SocketAddr,
    pub route: Option<Route>,
    pub iam: IAm,
}

impl Peer {
    pub fn addr_str(&self) -> String {
        match &self.route {
            Some((net, mac)) => format!(
                "{} → net {net} mac {}",
                self.addr,
                mac.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":")
            ),
            None => self.addr.to_string(),
        }
    }
}

pub struct Client {
    sock: UdpSocket,
    /// Listener on 47808 (broadcast I-Ams), when the port is free.
    aux: Option<UdpSocket>,
    invoke: u8,
    pub timeout: Duration,
    pub retries: u32,
    /// I-Ams heard while waiting for something else.
    pub heard: Vec<Peer>,
}

impl Client {
    pub fn new() -> Result<Client, String> {
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
        sock.set_broadcast(true).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .map_err(|e| e.to_string())?;
        let aux = UdpSocket::bind(("0.0.0.0", PORT)).ok();
        if let Some(a) = &aux {
            let _ = a.set_read_timeout(Some(Duration::from_millis(5)));
        }
        Ok(Client {
            sock,
            aux,
            invoke: (std::process::id() & 0xff) as u8,
            timeout: Duration::from_millis(1500),
            retries: 1,
            heard: Vec::new(),
        })
    }

    pub fn listening_on_47808(&self) -> bool {
        self.aux.is_some()
    }

    fn recv(&self) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 1600];
        if let Ok((n, a)) = self.sock.recv_from(&mut buf) {
            return Some((buf[..n].to_vec(), a));
        }
        if let Some(aux) = &self.aux
            && let Ok((n, a)) = aux.recv_from(&mut buf)
        {
            return Some((buf[..n].to_vec(), a));
        }
        None
    }

    fn note_iam(&mut self, pkt: &Packet, from: SocketAddr) -> Option<Peer> {
        if let Apdu::IAm(i) = &pkt.apdu {
            let p = Peer {
                addr: pkt.forwarded_from.unwrap_or(from),
                route: pkt.source.clone(),
                iam: i.clone(),
            };
            self.heard.push(p.clone());
            return Some(p);
        }
        None
    }

    /// Send Who-Is and collect I-Ams for `wait`, calling `found` for each
    /// new device as it arrives.
    pub fn discover(
        &mut self,
        target: SocketAddr,
        broadcast: bool,
        low: Option<u32>,
        high: Option<u32>,
        wait: Duration,
        mut found: impl FnMut(&Peer),
    ) -> Result<Vec<Peer>, String> {
        let req = who_is(broadcast, low, high);
        self.sock
            .send_to(&req, target)
            .map_err(|e| format!("send Who-Is to {target}: {e}"))?;
        let mut out: Vec<Peer> = Vec::new();
        let end = Instant::now() + wait;
        let mut resent = false;
        while Instant::now() < end {
            // Second Who-Is halfway, for lossy links.
            if !resent && Instant::now() + wait / 2 >= end {
                resent = true;
                let _ = self.sock.send_to(&req, target);
            }
            let Some((b, from)) = self.recv() else {
                continue;
            };
            let Some(pkt) = parse_packet(&b) else {
                continue;
            };
            if let Some(p) = self.note_iam(&pkt, from)
                && !out.iter().any(|o| o.iam.device == p.iam.device)
            {
                found(&p);
                out.push(p);
            }
        }
        out.sort_by_key(|p| p.iam.device);
        Ok(out)
    }

    /// ReadProperty with retries; Err carries a readable reason.
    pub fn read(
        &mut self,
        peer: &Peer,
        t: u16,
        inst: u32,
        prop: u32,
        index: Option<u32>,
    ) -> Result<Vec<Value>, ReadError> {
        for _ in 0..=self.retries {
            self.invoke = self.invoke.wrapping_add(1);
            let inv = self.invoke;
            let req = read_property(inv, peer.route.as_ref(), t, inst, prop, index);
            self.sock
                .send_to(&req, peer.addr)
                .map_err(|e| ReadError::Io(e.to_string()))?;
            let end = Instant::now() + self.timeout;
            while Instant::now() < end {
                let Some((b, from)) = self.recv() else {
                    continue;
                };
                let Some(pkt) = parse_packet(&b) else {
                    continue;
                };
                if self.note_iam(&pkt, from).is_some() {
                    continue;
                }
                match pkt.apdu {
                    Apdu::ComplexAck {
                        invoke,
                        segmented,
                        data,
                        ..
                    } if invoke == inv => {
                        if segmented {
                            return Err(ReadError::Abort(4));
                        }
                        return parse_rp_ack(&data).map_err(ReadError::Io);
                    }
                    Apdu::Error {
                        invoke,
                        class,
                        code,
                    } if invoke == inv => return Err(ReadError::Error(class, code)),
                    Apdu::Reject { invoke, reason } if invoke == inv => {
                        return Err(ReadError::Reject(reason));
                    }
                    Apdu::Abort { invoke, reason } if invoke == inv => {
                        return Err(ReadError::Abort(reason));
                    }
                    _ => {}
                }
            }
        }
        Err(ReadError::Timeout)
    }

    /// object-list: whole array, else length (index 0) and each element.
    pub fn object_list(
        &mut self,
        peer: &Peer,
        mut progress: impl FnMut(usize, usize),
    ) -> Result<Vec<(u16, u32)>, ReadError> {
        let dev = peer.iam.device;
        let ids = |vs: &[Value]| -> Vec<(u16, u32)> {
            vs.iter()
                .filter_map(|v| match v {
                    Value::ObjectId(t, i) => Some((*t, *i)),
                    _ => None,
                })
                .collect()
        };
        // Large lists need segmentation, which this client doesn't accept:
        // the device then aborts or errors and the list is read by index.
        if let Ok(v) = self.read(peer, OBJ_DEVICE, dev, P_OBJECT_LIST, None) {
            return Ok(ids(&v));
        }
        let n = match self
            .read(peer, OBJ_DEVICE, dev, P_OBJECT_LIST, Some(0))?
            .first()
        {
            Some(Value::Unsigned(n)) => *n as usize,
            _ => return Err(ReadError::Io("object-list length is not a number".into())),
        };
        let mut out = Vec::new();
        for i in 1..=n {
            progress(i, n);
            if let Ok(v) = self.read(peer, OBJ_DEVICE, dev, P_OBJECT_LIST, Some(i as u32)) {
                out.extend(ids(&v));
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReadError {
    Timeout,
    Io(String),
    Error(u32, u32),
    Reject(u8),
    Abort(u8),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Timeout => write!(f, "no answer"),
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::Error(c, d) => {
                write!(
                    f,
                    "error: {} / {}",
                    error_class_name(*c),
                    error_code_name(*d)
                )
            }
            ReadError::Reject(r) => write!(f, "rejected: {}", reject_reason(*r)),
            ReadError::Abort(r) => write!(f, "aborted: {}", abort_reason(*r)),
        }
    }
}

// ---------------------------------------------------------------- worker

/// Device properties read after discovery.
pub const DEVICE_PROPS: &[u32] = &[77, 121, 70, 44, 12, 28, 58, 139, 98, 62, 107, 112];

#[derive(Clone, Debug)]
pub struct ObjRow {
    pub t: u16,
    pub inst: u32,
    pub name: String,
    pub value: String,
    pub units: String,
    pub flags: String,
    pub error: Option<String>,
}

/// Object types with present-value / status-flags.
pub fn has_present_value(t: u16) -> bool {
    matches!(t, 0..=5 | 13 | 14 | 19 | 23 | 39..=50 | 54)
}

pub fn has_units(t: u16) -> bool {
    matches!(t, 0..=2 | 23 | 45 | 46 | 48)
}

pub fn read_object(c: &mut Client, peer: &Peer, t: u16, inst: u32) -> ObjRow {
    let mut r = ObjRow {
        t,
        inst,
        name: String::new(),
        value: String::new(),
        units: String::new(),
        flags: String::new(),
        error: None,
    };
    match c.read(peer, t, inst, P_OBJECT_NAME, None) {
        Ok(v) => r.name = format_values(P_OBJECT_NAME, &v),
        Err(e) => r.error = Some(e.to_string()),
    }
    if has_present_value(t) {
        // Only binary objects name their enumerated value active / inactive.
        let fmt_prop = if matches!(t, 3..=5) {
            P_PRESENT_VALUE
        } else {
            0
        };
        match c.read(peer, t, inst, P_PRESENT_VALUE, None) {
            Ok(v) => r.value = format_values(fmt_prop, &v),
            Err(e) => r.error = Some(e.to_string()),
        }
        if let Ok(v) = c.read(peer, t, inst, P_STATUS_FLAGS, None) {
            r.flags = format_values(P_STATUS_FLAGS, &v);
        }
    }
    if has_units(t)
        && let Ok(v) = c.read(peer, t, inst, P_UNITS, None)
    {
        r.units = format_values(P_UNITS, &v);
    }
    r
}

pub enum Cmd {
    Discover {
        target: SocketAddr,
        broadcast: bool,
        low: Option<u32>,
        high: Option<u32>,
        wait: Duration,
    },
    ReadDevice(Peer),
    ReadObjects(Peer),
    Read {
        peer: Peer,
        t: u16,
        inst: u32,
        prop: u32,
        index: Option<u32>,
    },
}

pub enum Event {
    Ready { port_47808: bool },
    Status(String),
    Device(Peer),
    DiscoverDone(usize),
    DeviceProp(u32, u32, Result<String, String>),
    DevicePropsDone(u32),
    ObjectCount(u32, usize),
    Object(u32, ObjRow),
    ObjectsDone(u32, Result<usize, String>),
    ReadResult(String, Result<String, String>),
    Failed(String),
}

pub struct Worker {
    pub events: Receiver<Event>,
    cmds: Sender<Cmd>,
}

impl Worker {
    pub fn send(&self, c: Cmd) {
        let _ = self.cmds.send(c);
    }
}

pub fn start() -> Worker {
    let (tx, rx) = channel();
    let (ctx, crx) = channel::<Cmd>();
    std::thread::Builder::new()
        .name("bacnet".into())
        .spawn(move || {
            let mut c = match Client::new() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Event::Failed(e));
                    return;
                }
            };
            let _ = tx.send(Event::Ready {
                port_47808: c.listening_on_47808(),
            });
            let flush_heard = |c: &mut Client, tx: &Sender<Event>| {
                for p in c.heard.drain(..) {
                    let _ = tx.send(Event::Device(p));
                }
            };
            while let Ok(cmd) = crx.recv() {
                match cmd {
                    Cmd::Discover {
                        target,
                        broadcast,
                        low,
                        high,
                        wait,
                    } => {
                        let _ = tx.send(Event::Status(format!("Who-Is sent to {target}…")));
                        c.heard.clear();
                        let r = c.discover(target, broadcast, low, high, wait, |p| {
                            let _ = tx.send(Event::Device(p.clone()));
                        });
                        c.heard.clear();
                        match r {
                            Ok(list) => {
                                let _ = tx.send(Event::DiscoverDone(list.len()));
                            }
                            Err(e) => {
                                let _ = tx.send(Event::Failed(e));
                            }
                        }
                    }
                    Cmd::ReadDevice(peer) => {
                        let dev = peer.iam.device;
                        for &prop in DEVICE_PROPS {
                            let r = c
                                .read(&peer, OBJ_DEVICE, dev, prop, None)
                                .map(|v| format_values(prop, &v))
                                .map_err(|e| e.to_string());
                            let _ = tx.send(Event::DeviceProp(dev, prop, r));
                        }
                        let _ = tx.send(Event::DevicePropsDone(dev));
                        flush_heard(&mut c, &tx);
                    }
                    Cmd::ReadObjects(peer) => {
                        let dev = peer.iam.device;
                        let _ = tx.send(Event::Status(format!("Reading object list of device {dev}…")));
                        let list = c.object_list(&peer, |i, n| {
                            if i % 10 == 1 {
                                let _ = tx.send(Event::Status(format!(
                                    "Reading object list of device {dev}: {i}/{n} (one element at a time)…"
                                )));
                            }
                        });
                        match list {
                            Ok(list) => {
                                let _ = tx.send(Event::ObjectCount(dev, list.len()));
                                for (i, (t, inst)) in list.iter().enumerate() {
                                    if i % 5 == 0 {
                                        let _ = tx.send(Event::Status(format!(
                                            "Reading objects of device {dev}: {}/{}…",
                                            i + 1,
                                            list.len()
                                        )));
                                    }
                                    let row = read_object(&mut c, &peer, *t, *inst);
                                    let _ = tx.send(Event::Object(dev, row));
                                }
                                let _ = tx.send(Event::ObjectsDone(dev, Ok(list.len())));
                            }
                            Err(e) => {
                                let _ = tx.send(Event::ObjectsDone(dev, Err(e.to_string())));
                            }
                        }
                        flush_heard(&mut c, &tx);
                    }
                    Cmd::Read {
                        peer,
                        t,
                        inst,
                        prop,
                        index,
                    } => {
                        let what = format!(
                            "{},{inst} {}{}",
                            object_type_name(t),
                            property_name(prop),
                            index.map(|i| format!("[{i}]")).unwrap_or_default()
                        );
                        let r = c
                            .read(&peer, t, inst, prop, index)
                            .map(|v| format_values(prop, &v))
                            .map_err(|e| e.to_string());
                        let _ = tx.send(Event::ReadResult(what, r));
                        flush_heard(&mut c, &tx);
                    }
                }
            }
        })
        .expect("spawn bacnet thread");
    Worker {
        events: rx,
        cmds: ctx,
    }
}

/// Directed broadcast of the primary interface (255.255.255.255 if none).
pub fn default_broadcast() -> Ipv4Addr {
    crate::netinfo::local_interfaces()
        .first()
        .map(|i| directed_broadcast(i.ip, i.prefix))
        .unwrap_or(Ipv4Addr::BROADCAST)
}

pub fn directed_broadcast(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32) as u32)
    };
    Ipv4Addr::from(u32::from(ip) | !mask)
}

/// "10.0.0.5", "10.0.0.5:47809", or a host name.
pub fn parse_target(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, PORT));
    }
    use std::net::ToSocketAddrs;
    let with_port = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:{PORT}")
    };
    with_port
        .to_socket_addrs()
        .map_err(|e| format!("{s}: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("{s}: no IPv4 address"))
}

// ---------------------------------------------------------------- CLI

/// `--bacnet [TARGET] [--range LOW-HIGH] [--wait S] [--objects]`
pub fn cli(args: &[String]) {
    let mut target = None;
    let mut range = (None, None);
    let mut wait = 3u64;
    let mut objects = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--range" => {
                i += 1;
                let r = args.get(i).and_then(|v| v.split_once('-'));
                match r.and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?))) {
                    Some((a, b)) => range = (Some(a), Some(b)),
                    None => {
                        eprintln!("--range: expected LOW-HIGH device instances");
                        std::process::exit(2)
                    }
                }
            }
            "--wait" => {
                i += 1;
                wait = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(3)
            }
            "--objects" => objects = true,
            t if !t.starts_with('-') && target.is_none() => target = Some(t.to_string()),
            other => {
                eprintln!(
                    "unknown option '{other}'\nusage: --bacnet [TARGET] [--range LOW-HIGH] [--wait S] [--objects]"
                );
                std::process::exit(2)
            }
        }
        i += 1;
    }
    let (addr, bcast) = match &target {
        Some(t) => match parse_target(t) {
            Ok(a) => {
                let b = matches!(a.ip(), IpAddr::V4(v) if v.octets()[3] == 255 || v.is_broadcast());
                (a, b)
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2)
            }
        },
        None => (SocketAddr::new(IpAddr::V4(default_broadcast()), PORT), true),
    };
    let mut c = match Client::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    };
    if !c.listening_on_47808() {
        eprintln!("note: UDP 47808 is in use, broadcast I-Am replies may be missed");
    }
    eprintln!("Who-Is → {addr}");
    let peers = match c.discover(
        addr,
        bcast,
        range.0,
        range.1,
        Duration::from_secs(wait),
        |_| {},
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    };
    for p in &peers {
        let dev = p.iam.device;
        let get = |c: &mut Client, prop| {
            c.read(p, OBJ_DEVICE, dev, prop, None)
                .map(|v| format_values(prop, &v))
                .unwrap_or_default()
        };
        let name = get(&mut c, 77);
        let vendor = get(&mut c, 121);
        let model = get(&mut c, 70);
        let fw = get(&mut c, 44);
        println!(
            "device {dev:<8} {:<22} {name:<28} {vendor} {model} {fw}  (max APDU {}, segmentation {})",
            p.addr_str(),
            p.iam.max_apdu,
            segmentation_name(p.iam.segmentation)
        );
        if objects {
            match c.object_list(p, |_, _| {}) {
                Ok(list) => {
                    for (t, inst) in list {
                        let r = read_object(&mut c, p, t, inst);
                        println!(
                            "    {:<5} {:<8} {:<32} {} {} {}",
                            object_type_abbr(t),
                            inst,
                            r.name,
                            r.value,
                            r.units,
                            if r.flags.is_empty() || r.flags == "normal" {
                                String::new()
                            } else {
                                format!("[{}]", r.flags)
                            }
                        );
                    }
                }
                Err(e) => println!("    object-list: {e}"),
            }
        }
    }
    eprintln!("{} device(s)", peers.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_is_bytes() {
        // BVLC broadcast, NPDU global broadcast, Who-Is, no range.
        assert_eq!(
            who_is(true, None, None),
            vec![
                0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08
            ]
        );
        // Range 0..4194303 unicast.
        assert_eq!(
            who_is(false, Some(0), Some(4_194_303)),
            vec![
                0x81, 0x0a, 0x00, 0x0e, 0x01, 0x00, 0x10, 0x08, 0x09, 0x00, 0x1b, 0x3f, 0xff, 0xff
            ]
        );
    }

    #[test]
    fn read_property_bytes() {
        // ReadProperty device,1234 object-name, invoke 1.
        let p = read_property(1, None, 8, 1234, 77, None);
        assert_eq!(
            p,
            vec![
                0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0c, 0x0c, 0x02, 0x00, 0x04,
                0xd2, 0x19, 0x4d
            ]
        );
        // With array index 0 and a routed destination.
        let p = read_property(2, Some(&(5, vec![0x0a])), 8, 1, 76, Some(0));
        assert_eq!(&p[4..11], &[0x01, 0x24, 0x00, 0x05, 0x01, 0x0a, 0xff]);
        assert_eq!(&p[p.len() - 4..], &[0x19, 0x4c, 0x29, 0x00]);
    }

    #[test]
    fn i_am() {
        // I-Am device 260001, max APDU 1476, segmentation both, vendor 250.
        let b = [
            0x81, 0x0b, 0x00, 0x18, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x00, 0xc4, 0x02,
            0x03, 0xf7, 0xa1, 0x22, 0x05, 0xc4, 0x91, 0x00, 0x21, 0xfa,
        ];
        let p = parse_packet(&b).unwrap();
        assert_eq!(
            p.apdu,
            Apdu::IAm(IAm {
                device: 260001,
                max_apdu: 1476,
                segmentation: 0,
                vendor: 250
            })
        );
        // From behind a router: SNET 7, SADR 0x15; forwarded.
        let b = [
            0x81, 0x04, 0x00, 0x1e, 10, 0, 0, 9, 0xba, 0xc0, 0x01, 0x08, 0x00, 0x07, 0x01, 0x15,
            0x10, 0x00, 0xc4, 0x02, 0x00, 0x00, 0x05, 0x22, 0x01, 0xe0, 0x91, 0x03, 0x21, 0x08,
        ];
        let p = parse_packet(&b).unwrap();
        assert_eq!(p.source, Some((7, vec![0x15])));
        assert_eq!(p.forwarded_from, Some("10.0.0.9:47808".parse().unwrap()));
        assert!(matches!(
            p.apdu,
            Apdu::IAm(IAm {
                device: 5,
                max_apdu: 480,
                segmentation: 3,
                vendor: 8
            })
        ));
    }

    #[test]
    fn complex_ack_and_errors() {
        // ComplexACK RP: AI,1 present-value = 21.5 (REAL)
        let b = [
            0x81, 0x0a, 0x00, 0x17, 0x01, 0x00, 0x30, 0x07, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x01,
            0x19, 0x55, 0x3e, 0x44, 0x41, 0xac, 0x00, 0x00, 0x3f,
        ];
        let p = parse_packet(&b).unwrap();
        let Apdu::ComplexAck {
            invoke,
            service,
            data,
            ..
        } = p.apdu
        else {
            panic!()
        };
        assert_eq!((invoke, service), (7, 12));
        let v = parse_rp_ack(&data).unwrap();
        assert_eq!(v, vec![Value::Real(21.5)]);
        assert_eq!(format_values(85, &v), "21.5");
        // Error: property / unknown-property
        assert_eq!(
            parse_apdu(&[0x50, 0x07, 0x0c, 0x91, 0x02, 0x91, 0x20]).unwrap(),
            Apdu::Error {
                invoke: 7,
                class: 2,
                code: 32
            }
        );
        assert_eq!(
            ReadError::Error(2, 32).to_string(),
            "error: property / unknown-property"
        );
        assert_eq!(
            parse_apdu(&[0x60, 3, 9]).unwrap(),
            Apdu::Reject {
                invoke: 3,
                reason: 9
            }
        );
        assert_eq!(
            ReadError::Abort(4).to_string(),
            "aborted: segmentation-not-supported"
        );
    }

    #[test]
    fn tags_and_values() {
        // Character string "Room 1" UTF-8, status flags (4 bits, fault set), enum units °C.
        let b = [
            0x75, 0x07, 0x00, b'R', b'o', b'o', b'm', b' ', b'1', 0x82, 0x04, 0x40, 0x91, 62, 0x31,
            0xfe, 0xa4, 126, 11, 23, 1, 0xb4, 13, 45, 0, 0,
        ];
        let (v, _) = decode_values(&b, 0).unwrap();
        assert_eq!(v[0], Value::Str("Room 1".into()));
        assert_eq!(format_value(P_STATUS_FLAGS, &v[1]), "fault");
        assert_eq!(format_value(P_UNITS, &v[2]), "°C");
        assert_eq!(v[3], Value::Signed(-2));
        assert_eq!(format_value(0, &v[4]), "2026-11-23 (Mon)");
        assert_eq!(format_value(0, &v[5]), "13:45:00.00");
        // Long tag header (extended length) roundtrip.
        let h = tag_header(7, false, 300);
        assert_eq!(h, vec![0x75, 254, 0x01, 0x2c]);
        assert_eq!(
            read_tag(&h, 0).unwrap(),
            (
                Tag {
                    num: 7,
                    ctx: false,
                    len: 300,
                    open: false,
                    close: false
                },
                4
            )
        );
        // Unsigned encodings are minimal.
        assert_eq!(ctx_unsigned(1, 85), vec![0x19, 0x55]);
        assert_eq!(ctx_unsigned(1, 371), vec![0x1a, 0x01, 0x73]);
        assert_eq!(ctx_unsigned(2, 0), vec![0x29, 0x00]);
    }

    #[test]
    fn names() {
        assert_eq!(parse_object_type("AV"), Some(2));
        assert_eq!(parse_object_type("multi-state-value"), Some(19));
        assert_eq!(parse_property("pv"), Some(85));
        assert_eq!(parse_property("object-list"), Some(76));
        assert_eq!(units_name(98), "%");
        assert_eq!(units_name(95), "");
        assert_eq!(units_name(104), "rpm");
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(192, 168, 1, 20), 24),
            Ipv4Addr::new(192, 168, 1, 255)
        );
    }
}
