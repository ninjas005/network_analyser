//! Native reader and writer for capture files: classic pcap (either byte
//! order, µs or ns), pcapng (several sections, interfaces and link types,
//! comments, name resolution, interface statistics) and gzip-compressed
//! versions of both. No libpcap is needed to read a file.

use std::collections::BTreeMap;
use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Largest captured length accepted for one packet.
const MAX_CAPLEN: usize = 16 << 20;
/// Largest pcapng block accepted.
const MAX_BLOCK: usize = 64 << 20;

#[derive(Clone, Debug, Default)]
pub struct FileIface {
    pub name: String,
    pub desc: String,
    pub linktype: i32,
    pub snaplen: u32,
    /// Timestamp ticks per second.
    pub ticks: u64,
    /// Seconds added to every timestamp.
    pub offset: i64,
    pub filter: String,
    pub os: String,
    pub speed: Option<u64>,
    pub packets: u64,
    pub received: Option<u64>,
    pub dropped: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub format: String,
    pub gzip: bool,
    pub big_endian: bool,
    pub hardware: String,
    pub os: String,
    pub application: String,
    pub comments: Vec<String>,
    pub ifaces: Vec<FileIface>,
    /// Addresses named in the file (pcapng name resolution blocks).
    pub names: Vec<(IpAddr, String)>,
    /// pcapng block types and how many there are.
    pub blocks: BTreeMap<&'static str, u64>,
    pub packets: u64,
    pub packet_comments: u64,
    /// Packets shorter in the file than on the wire (snap length).
    pub cut: u64,
    pub first: Option<f64>,
    pub last: Option<f64>,
    /// The file ended early or was damaged; packets before that were read.
    pub problem: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub ts: f64,
    pub len: u32,
    pub iface: u32,
    pub linktype: i32,
    pub data: Vec<u8>,
    pub comment: Option<String>,
}

struct Rd {
    r: Box<dyn Read>,
}

impl Rd {
    /// Fill `buf`; `Ok(false)` = clean end of file before the first byte.
    fn fill(&mut self, buf: &mut [u8]) -> Result<bool, String> {
        let mut n = 0;
        while n < buf.len() {
            match self.r.read(&mut buf[n..]) {
                Ok(0) if n == 0 => return Ok(false),
                Ok(0) => return Err("file is cut off in the middle of a record".into()),
                Ok(k) => n += k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(true)
    }

    /// Like `fill`, but the end of the file is an error. The buffer grows as
    /// data arrives, so a bogus length cannot allocate gigabytes.
    fn take(&mut self, len: usize) -> Result<Vec<u8>, String> {
        let mut v = Vec::with_capacity(len.min(1 << 16));
        (&mut self.r)
            .take(len as u64)
            .read_to_end(&mut v)
            .map_err(|e| e.to_string())?;
        if v.len() < len {
            return Err("file is cut off in the middle of a record".into());
        }
        Ok(v)
    }
}

fn u16at(b: &[u8], i: usize, be: bool) -> u16 {
    let v = [b[i], b[i + 1]];
    if be {
        u16::from_be_bytes(v)
    } else {
        u16::from_le_bytes(v)
    }
}

fn u32at(b: &[u8], i: usize, be: bool) -> u32 {
    let v = [b[i], b[i + 1], b[i + 2], b[i + 3]];
    if be {
        u32::from_be_bytes(v)
    } else {
        u32::from_le_bytes(v)
    }
}

/// Read a capture file, passing each packet to `sink` until it returns false.
/// A damaged tail is reported in [`FileInfo::problem`], not as an error.
pub fn read(path: &Path, sink: &mut dyn FnMut(RawPacket) -> bool) -> Result<FileInfo, String> {
    let err = |e: String| format!("{}: {e}", path.display());
    let file = std::fs::File::open(path).map_err(|e| err(e.to_string()))?;
    let meta = file.metadata().map_err(|e| err(e.to_string()))?;
    if meta.is_dir() {
        return Err(err("is a directory".into()));
    }
    let mut info = FileInfo {
        path: path.to_path_buf(),
        size: meta.len(),
        ..Default::default()
    };
    let mut rd = Rd {
        r: Box::new(BufReader::with_capacity(1 << 18, file)),
    };
    let mut magic = [0u8; 4];
    if !rd.fill(&mut magic).map_err(err)? {
        return Err(err("file is empty".into()));
    }
    if magic[..2] == [0x1f, 0x8b] {
        info.gzip = true;
        let whole = std::io::Cursor::new(magic).chain(rd.r);
        rd = Rd {
            r: Box::new(BufReader::with_capacity(
                1 << 18,
                flate2::read::MultiGzDecoder::new(whole),
            )),
        };
        if !rd.fill(&mut magic).map_err(err)? {
            return Err(err("compressed file is empty".into()));
        }
    }
    let res = match u32::from_le_bytes(magic) {
        0xa1b2c3d4 => classic(&mut rd, &mut info, false, 1_000_000, 0, sink),
        0xd4c3b2a1 => classic(&mut rd, &mut info, true, 1_000_000, 0, sink),
        0xa1b23c4d => classic(&mut rd, &mut info, false, 1_000_000_000, 0, sink),
        0x4d3cb2a1 => classic(&mut rd, &mut info, true, 1_000_000_000, 0, sink),
        // Kuznetzov's modified pcap: 8 more bytes per record header.
        0xa1b2cd34 => classic(&mut rd, &mut info, false, 1_000_000, 8, sink),
        0x34cdb2a1 => classic(&mut rd, &mut info, true, 1_000_000, 8, sink),
        0x0a0d0d0a => pcapng(&mut rd, &mut info, sink),
        _ => {
            return Err(err(
                "not a capture file (expected pcap, pcapng or a gzip of one)".into(),
            ));
        }
    };
    if let Err(e) = res {
        if info.ifaces.is_empty() {
            return Err(err(e));
        }
        info.problem = Some(e);
    }
    Ok(info)
}

fn note(info: &mut FileInfo, p: &RawPacket) {
    info.packets += 1;
    if (p.data.len() as u32) < p.len {
        info.cut += 1;
    }
    if p.comment.is_some() {
        info.packet_comments += 1;
    }
    info.first = Some(info.first.map_or(p.ts, |f| f.min(p.ts)));
    info.last = Some(info.last.map_or(p.ts, |l| l.max(p.ts)));
    if let Some(i) = info.ifaces.get_mut(p.iface as usize) {
        i.packets += 1;
    }
}

fn classic(
    rd: &mut Rd,
    info: &mut FileInfo,
    be: bool,
    ticks: u64,
    extra: usize,
    sink: &mut dyn FnMut(RawPacket) -> bool,
) -> Result<(), String> {
    let h = rd.take(20)?;
    // The upper bits of the link type carry FCS information.
    let linktype = (u32at(&h, 16, be) & 0x0fff_ffff) as i32;
    info.big_endian = be;
    info.format = format!(
        "pcap {}.{}{}",
        u16at(&h, 0, be),
        u16at(&h, 2, be),
        if ticks > 1_000_000 {
            " (nanoseconds)"
        } else {
            ""
        }
    );
    info.ifaces.push(FileIface {
        linktype,
        snaplen: u32at(&h, 12, be),
        ticks,
        ..Default::default()
    });
    let mut rec = vec![0u8; 16 + extra];
    while rd.fill(&mut rec)? {
        let caplen = u32at(&rec, 8, be) as usize;
        if caplen > MAX_CAPLEN {
            return Err(format!(
                "damaged record after packet {}: captured length {caplen}",
                info.packets
            ));
        }
        let p = RawPacket {
            ts: u32at(&rec, 0, be) as f64 + u32at(&rec, 4, be) as f64 / ticks as f64,
            len: u32at(&rec, 12, be),
            iface: 0,
            linktype,
            data: rd.take(caplen)?,
            comment: None,
        };
        note(info, &p);
        if !sink(p) {
            return Ok(());
        }
    }
    Ok(())
}

/// pcapng options: (code, value) pairs.
fn options(mut b: &[u8], be: bool) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let (code, len) = (u16at(b, 0, be), u16at(b, 2, be) as usize);
        if code == 0 {
            break;
        }
        let Some(v) = b.get(4..4 + len) else { break };
        out.push((code, v));
        b = b.get(4 + len.next_multiple_of(4)..).unwrap_or(&[]);
    }
    out
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

fn pcapng(
    rd: &mut Rd,
    info: &mut FileInfo,
    sink: &mut dyn FnMut(RawPacket) -> bool,
) -> Result<(), String> {
    let mut be = false;
    // Interface IDs restart in every section.
    let mut base = 0usize;
    let mut first = true;
    loop {
        let mut th = [0u8; 8];
        if first {
            // The section header type was already consumed as the magic.
            th[..4].copy_from_slice(&0x0a0d0d0au32.to_le_bytes());
            let l = rd.take(4)?;
            th[4..].copy_from_slice(&l);
        } else if !rd.fill(&mut th)? {
            return Ok(());
        }
        let section = th[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        let mut bom = Vec::new();
        if section {
            bom = rd.take(4)?;
            be = match bom[..] {
                [0x1a, 0x2b, 0x3c, 0x4d] => true,
                [0x4d, 0x3c, 0x2b, 0x1a] => false,
                _ => return Err("bad pcapng byte-order magic".into()),
            };
            base = info.ifaces.len();
            if first {
                info.big_endian = be;
            }
        }
        let btype = u32at(&th, 0, be);
        let total = u32at(&th, 4, be) as usize;
        if total < 12 + bom.len() || !total.is_multiple_of(4) || total > MAX_BLOCK {
            return Err(format!(
                "damaged block after packet {} (length {total})",
                info.packets
            ));
        }
        // Body without the trailing copy of the length.
        let mut b = rd.take(total - 8 - bom.len())?;
        b.truncate(b.len() - 4);
        let name = match btype {
            0x0a0d0d0a => "Section header",
            1 => "Interface description",
            2 => "Packet (obsolete)",
            3 => "Simple packet",
            4 => "Name resolution",
            5 => "Interface statistics",
            6 => "Enhanced packet",
            0x0a => "Decryption secrets",
            0x80000001 => "Systemd journal",
            _ => "Other",
        };
        *info.blocks.entry(name).or_default() += 1;
        match btype {
            0x0a0d0d0a => {
                if b.len() < 12 {
                    return Err("short section header".into());
                }
                info.format = format!("pcapng {}.{}", u16at(&b, 0, be), u16at(&b, 2, be));
                for (c, v) in options(&b[12..], be) {
                    match c {
                        1 => info.comments.push(text(v)),
                        2 => info.hardware = text(v),
                        3 => info.os = text(v),
                        4 => info.application = text(v),
                        _ => {}
                    }
                }
            }
            1 if b.len() >= 8 => {
                let mut f = FileIface {
                    linktype: u16at(&b, 0, be) as i32,
                    snaplen: u32at(&b, 4, be),
                    ticks: 1_000_000,
                    ..Default::default()
                };
                for (c, v) in options(&b[8..], be) {
                    match c {
                        1 => info.comments.push(text(v)),
                        2 => f.name = text(v),
                        3 => f.desc = text(v),
                        8 if v.len() == 8 => {
                            let (a, z) = (u32at(v, 0, be) as u64, u32at(v, 4, be) as u64);
                            f.speed = Some(if be { a << 32 | z } else { z << 32 | a });
                        }
                        9 if !v.is_empty() => {
                            let n = (v[0] & 0x7f) as u32;
                            let t = if v[0] & 0x80 != 0 {
                                1u64.checked_shl(n)
                            } else {
                                10u64.checked_pow(n)
                            };
                            f.ticks = t.filter(|t| *t > 0).unwrap_or(1_000_000);
                        }
                        // First byte: 0 = text filter, 1 = BPF byte code.
                        11 if v.first() == Some(&0) => f.filter = text(&v[1..]),
                        12 => f.os = text(v),
                        14 if v.len() == 8 => {
                            let (a, z) = (u32at(v, 0, be) as u64, u32at(v, 4, be) as u64);
                            f.offset = (if be { a << 32 | z } else { z << 32 | a }) as i64;
                        }
                        _ => {}
                    }
                }
                info.ifaces.push(f);
            }
            2 | 3 | 6 => {
                let (iface, ts, caplen, len, at) = match btype {
                    6 if b.len() >= 20 => (
                        u32at(&b, 0, be) as usize,
                        Some((u32at(&b, 4, be), u32at(&b, 8, be))),
                        u32at(&b, 12, be) as usize,
                        u32at(&b, 16, be),
                        20,
                    ),
                    2 if b.len() >= 20 => (
                        u16at(&b, 0, be) as usize,
                        Some((u32at(&b, 4, be), u32at(&b, 8, be))),
                        u32at(&b, 12, be) as usize,
                        u32at(&b, 16, be),
                        20,
                    ),
                    3 if b.len() >= 4 => {
                        let len = u32at(&b, 0, be);
                        (0, None, (len as usize).min(b.len() - 4), len, 4)
                    }
                    _ => return Err(format!("short packet block after {}", info.packets)),
                };
                let Some(f) = info.ifaces.get(base + iface) else {
                    return Err(format!("packet for undefined interface {iface}"));
                };
                let Some(data) = b.get(at..caplen.saturating_add(at)) else {
                    return Err(format!("damaged packet after {}", info.packets));
                };
                let ts = match ts {
                    Some((hi, lo)) => {
                        let t = (hi as u64) << 32 | lo as u64;
                        // Split first: f64 alone would lose sub-µs digits.
                        (t / f.ticks) as f64
                            + (t % f.ticks) as f64 / f.ticks as f64
                            + f.offset as f64
                    }
                    None => info.last.unwrap_or(0.0),
                };
                let mut comment = None;
                if btype != 3 {
                    let opt_at = at + caplen.next_multiple_of(4);
                    for (c, v) in options(b.get(opt_at..).unwrap_or(&[]), be) {
                        if c == 1 {
                            comment = Some(text(v));
                        }
                    }
                }
                let p = RawPacket {
                    ts,
                    len,
                    iface: (base + iface) as u32,
                    linktype: f.linktype,
                    data: data.to_vec(),
                    comment,
                };
                note(info, &p);
                if !sink(p) {
                    return Ok(());
                }
            }
            4 => {
                let mut r = &b[..];
                while r.len() >= 4 && info.names.len() < 10_000 {
                    let (t, l) = (u16at(r, 0, be), u16at(r, 2, be) as usize);
                    if t == 0 {
                        break;
                    }
                    let Some(v) = r.get(4..4 + l) else { break };
                    let (ip, names) = match t {
                        1 if l >= 5 => {
                            (IpAddr::from(Ipv4Addr::new(v[0], v[1], v[2], v[3])), &v[4..])
                        }
                        2 if l >= 17 => (
                            IpAddr::from(Ipv6Addr::from(<[u8; 16]>::try_from(&v[..16]).unwrap())),
                            &v[16..],
                        ),
                        _ => {
                            r = r.get(4 + l.next_multiple_of(4)..).unwrap_or(&[]);
                            continue;
                        }
                    };
                    for n in names.split(|c| *c == 0).filter(|n| !n.is_empty()) {
                        info.names.push((ip, text(n)));
                    }
                    r = r.get(4 + l.next_multiple_of(4)..).unwrap_or(&[]);
                }
            }
            5 if b.len() >= 12 => {
                let id = u32at(&b, 0, be) as usize;
                if let Some(f) = info.ifaces.get_mut(base + id) {
                    for (c, v) in options(&b[12..], be) {
                        if v.len() != 8 {
                            continue;
                        }
                        let (a, z) = (u32at(v, 0, be) as u64, u32at(v, 4, be) as u64);
                        let n = if be { a << 32 | z } else { z << 32 | a };
                        match c {
                            4 => f.received = Some(n),
                            5 => f.dropped = Some(n),
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
        first = false;
    }
}

/// One packet to write.
pub struct Out<'a> {
    pub ts: f64,
    pub len: u32,
    pub linktype: i32,
    pub data: &'a [u8],
    pub comment: Option<&'a str>,
}

/// Seconds and microseconds of a timestamp.
pub fn split_ts(ts: f64) -> (u64, u32) {
    let us = (ts.max(0.0) * 1e6).round() as u64;
    (us / 1_000_000, (us % 1_000_000) as u32)
}

/// Classic pcap; every packet must have the same link type.
pub fn pcap_bytes(linktype: i32, packets: &[Out]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + packets.iter().map(|p| p.data.len() + 16).sum::<usize>());
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&262_144u32.to_le_bytes());
    out.extend_from_slice(&(linktype as u32).to_le_bytes());
    for p in packets {
        let (s, us) = split_ts(p.ts);
        out.extend_from_slice(&(s as u32).to_le_bytes());
        out.extend_from_slice(&us.to_le_bytes());
        out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&p.len.to_le_bytes());
        out.extend_from_slice(p.data);
    }
    out
}

/// pcapng with one interface per link type; keeps packet comments.
pub fn pcapng_bytes(packets: &[Out]) -> Vec<u8> {
    fn block(out: &mut Vec<u8>, btype: u32, body: &[u8]) {
        let total = (12 + body.len().next_multiple_of(4)) as u32;
        out.extend_from_slice(&btype.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(body);
        out.resize(out.len().next_multiple_of(4), 0);
        out.extend_from_slice(&total.to_le_bytes());
    }
    fn opt(b: &mut Vec<u8>, code: u16, v: &[u8]) {
        let v = &v[..v.len().min(u16::MAX as usize)];
        b.extend_from_slice(&code.to_le_bytes());
        b.extend_from_slice(&(v.len() as u16).to_le_bytes());
        b.extend_from_slice(v);
        b.resize(b.len().next_multiple_of(4), 0);
    }
    let mut out = Vec::new();
    let mut b = Vec::new();
    b.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    b.extend_from_slice(&[1, 0, 0, 0]);
    b.extend_from_slice(&u64::MAX.to_le_bytes());
    opt(
        &mut b,
        4,
        concat!("Network Analyser ", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    opt(&mut b, 0, &[]);
    block(&mut out, 0x0a0d0d0a, &b);
    let mut types: Vec<i32> = Vec::new();
    for p in packets {
        if !types.contains(&p.linktype) {
            types.push(p.linktype);
        }
    }
    for t in &types {
        let mut b = Vec::new();
        b.extend_from_slice(&(*t as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&0u32.to_le_bytes());
        block(&mut out, 1, &b);
    }
    for p in packets {
        let id = types.iter().position(|t| *t == p.linktype).unwrap_or(0) as u32;
        let (s, us) = split_ts(p.ts);
        let t = s * 1_000_000 + us as u64;
        let mut b = Vec::with_capacity(p.data.len() + 32);
        b.extend_from_slice(&id.to_le_bytes());
        b.extend_from_slice(&((t >> 32) as u32).to_le_bytes());
        b.extend_from_slice(&(t as u32).to_le_bytes());
        b.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        b.extend_from_slice(&p.len.to_le_bytes());
        b.extend_from_slice(p.data);
        b.resize(b.len().next_multiple_of(4), 0);
        if let Some(c) = p.comment {
            opt(&mut b, 1, c.as_bytes());
            opt(&mut b, 0, &[]);
        }
        block(&mut out, 6, &b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp(name: &str, bytes: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("na-{}-{name}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn load(name: &str, bytes: &[u8]) -> Result<(FileInfo, Vec<RawPacket>), String> {
        let p = temp(name, bytes);
        let mut v = Vec::new();
        let r = read(&p, &mut |x| {
            v.push(x);
            true
        });
        std::fs::remove_file(&p).ok();
        r.map(|i| (i, v))
    }

    #[test]
    fn pcapng_mixed_links_and_comments() {
        let a = [1u8, 2, 3, 4, 5];
        let pk = [
            Out {
                ts: 1_700_000_000.123456,
                len: 5,
                linktype: 1,
                data: &a,
                comment: Some("first"),
            },
            Out {
                ts: 1_700_000_001.5,
                len: 90,
                linktype: 101,
                data: &a,
                comment: None,
            },
        ];
        let bytes = pcapng_bytes(&pk);
        let (i, v) = load("mixed.pcapng", &bytes).unwrap();
        assert_eq!(i.format, "pcapng 1.0");
        assert!(i.application.starts_with("Network Analyser"));
        assert_eq!((i.ifaces.len(), i.packets, i.cut), (2, 2, 1));
        assert_eq!((v[0].linktype, v[1].linktype), (1, 101));
        assert_eq!(v[0].comment.as_deref(), Some("first"));
        assert!((v[0].ts - 1_700_000_000.123456).abs() < 1e-6);
        // Cut off inside the last block: the first packet survives.
        let (i, v) = load("cut.pcapng", &bytes[..bytes.len() - 6]).unwrap();
        assert_eq!(v.len(), 1);
        assert!(i.problem.unwrap().contains("cut off"));
    }

    #[test]
    fn classic_big_endian_nanoseconds_gzip() {
        let mut f = vec![0xa1, 0xb2, 0x3c, 0x4d, 0, 2, 0, 4];
        f.extend([0; 8]);
        f.extend(65535u32.to_be_bytes());
        f.extend(1u32.to_be_bytes());
        f.extend(1_700_000_000u32.to_be_bytes());
        f.extend(500_000_000u32.to_be_bytes());
        f.extend(3u32.to_be_bytes());
        f.extend(60u32.to_be_bytes());
        f.extend([9, 8, 7]);
        let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&f).unwrap();
        let (i, v) = load("be.pcap.gz", &z.finish().unwrap()).unwrap();
        assert!(i.gzip && i.big_endian);
        assert!(i.format.contains("nanoseconds"));
        assert_eq!((v[0].len, &v[0].data[..]), (60, &[9u8, 8, 7][..]));
        assert_eq!(v[0].ts, 1_700_000_000.5);
    }

    #[test]
    fn rejects_other_files_and_survives_damage() {
        assert!(load("x.txt", b"hello world").is_err());
        assert!(load("empty", b"").is_err());
        let d = [0u8; 40];
        let good = pcapng_bytes(&[Out {
            ts: 1.0,
            len: 40,
            linktype: 1,
            data: &d,
            comment: Some("c"),
        }]);
        // Every truncation and every single-byte change must be handled.
        for n in 0..good.len() {
            let _ = load("t.pcapng", &good[..n]);
            let mut m = good.clone();
            m[n] ^= 0xff;
            let _ = load("m.pcapng", &m);
        }
    }

    #[test]
    fn rounding_never_overflows_the_fraction() {
        assert_eq!(split_ts(1.999_999_9), (2, 0));
        assert_eq!(split_ts(1_700_000_000.25), (1_700_000_000, 250_000));
    }
}
