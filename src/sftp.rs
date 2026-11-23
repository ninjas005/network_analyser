//! SSH / SFTP tester.
//!
//! * Without credentials: read the server banner, exchange KEXINIT by hand
//!   and rate the offered algorithms (kex, host key, ciphers, MACs,
//!   compression, Terrapin exposure).
//! * With russh: finish the handshake for the host key and its SHA-256
//!   fingerprint (remembered per host; a change is reported and blocks
//!   logins), list the offered auth methods, log in by password or key and
//!   run SFTP (browse, download, upload, write test) on a worker thread.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gateway::{Finding, Level};

// ---------------------------------------------------------------- targets

/// "host", "host:port", "user@host[:port]", "[v6]:port"; default port 22.
pub fn parse_target(s: &str) -> Result<(Option<String>, String, u16), String> {
    let s = s.trim();
    let (user, hp) = match s.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, s),
    };
    if hp.is_empty() {
        return Err("enter a host".into());
    }
    if let Ok(sa) = hp.parse::<SocketAddr>() {
        return Ok((user, sa.ip().to_string(), sa.port()));
    }
    if hp.parse::<std::net::IpAddr>().is_ok() {
        return Ok((user, hp.to_string(), 22));
    }
    match hp.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port = p.parse().map_err(|_| format!("bad port '{p}'"))?;
            Ok((user, h.trim_matches(['[', ']']).to_string(), port))
        }
        _ => Ok((user, hp.trim_matches(['[', ']']).to_string(), 22)),
    }
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .min_by_key(|a| a.is_ipv6())
        .ok_or_else(|| format!("{host}: no address"))
}

// ---------------------------------------------------------------- raw probe

pub const CLIENT_ID: &str = "SSH-2.0-NetworkAnalyser_1.0";

#[derive(Clone, Debug, Default)]
pub struct Algos {
    pub kex: Vec<String>,
    pub host_key: Vec<String>,
    pub enc_c2s: Vec<String>,
    pub enc_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub comp_c2s: Vec<String>,
    pub comp_s2c: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Probe {
    pub addr: Option<SocketAddr>,
    pub banner: String,
    /// Lines the server printed before its identification string.
    pub pre_banner: Vec<String>,
    pub product: String,
    pub version: String,
    pub comment: String,
    pub algos: Option<Algos>,
    pub connect_ms: f64,
    pub banner_ms: f64,
    pub kexinit_ms: f64,
}

/// Our KEXINIT payload: broad lists so any server will answer.
pub fn kexinit_payload() -> Vec<u8> {
    let mut p = vec![20u8];
    let cookie: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
    p.extend_from_slice(&cookie);
    let lists = [
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,\
         ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,\
         diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256,\
         diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1",
        "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
        "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,\
         aes192-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc",
        "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,\
         aes192-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc",
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        "none,zlib@openssh.com,zlib",
        "none,zlib@openssh.com,zlib",
        "",
        "",
    ];
    for l in lists {
        p.extend_from_slice(&(l.len() as u32).to_be_bytes());
        p.extend_from_slice(l.as_bytes());
    }
    p.push(0); // first_kex_packet_follows
    p.extend_from_slice(&[0; 4]);
    p
}

/// Wrap a payload in an unencrypted binary packet (RFC 4253 §6).
pub fn packet(payload: &[u8]) -> Vec<u8> {
    let mut pad = 8 - ((payload.len() + 5) % 8);
    if pad < 4 {
        pad += 8;
    }
    let mut out = Vec::with_capacity(payload.len() + pad + 5);
    out.extend_from_slice(&((payload.len() + pad + 1) as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Parse a KEXINIT payload (message 20).
pub fn parse_kexinit(p: &[u8]) -> Result<Algos, String> {
    if p.first() != Some(&20) || p.len() < 17 {
        return Err("not a KEXINIT message".into());
    }
    let mut pos = 17;
    let mut lists = Vec::new();
    for _ in 0..10 {
        let len = p
            .get(pos..pos + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or("truncated KEXINIT")?;
        pos += 4;
        let s = p.get(pos..pos + len).ok_or("truncated KEXINIT")?;
        pos += len;
        lists.push(
            String::from_utf8_lossy(s)
                .split(',')
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect::<Vec<_>>(),
        );
    }
    let mut it = lists.into_iter();
    let mut n = || it.next().unwrap_or_default();
    Ok(Algos {
        kex: n(),
        host_key: n(),
        enc_c2s: n(),
        enc_s2c: n(),
        mac_c2s: n(),
        mac_s2c: n(),
        comp_c2s: n(),
        comp_s2c: n(),
    })
}

/// Split "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" into
/// (protocol, product, version, comment).
pub fn parse_banner(b: &str) -> (String, String, String, String) {
    let rest = b.trim().strip_prefix("SSH-").unwrap_or(b);
    let (proto, sw) = rest.split_once('-').unwrap_or((rest, ""));
    let (soft, comment) = sw.split_once(' ').unwrap_or((sw, ""));
    let (product, version) = match soft.split_once(['_', '-']) {
        Some((p, v)) => (p.to_string(), v.to_string()),
        None => (soft.to_string(), String::new()),
    };
    (proto.to_string(), product, version, comment.to_string())
}

fn read_exact_timeout(s: &mut TcpStream, n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

/// Connect, read the identification string, send ours and a KEXINIT and
/// read the server's KEXINIT. Nothing beyond that is sent.
pub fn probe(host: &str, port: u16, timeout: Duration) -> Result<Probe, String> {
    let addr = resolve(host, port)?;
    let t0 = Instant::now();
    let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("{addr}: {e}"))?;
    let mut p = Probe {
        addr: Some(addr),
        connect_ms: t0.elapsed().as_secs_f64() * 1000.0,
        ..Default::default()
    };
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    // Identification: lines until one starts with "SSH-" (RFC 4253 §4.2).
    let mut line = Vec::new();
    let mut total = 0;
    loop {
        let mut b = [0u8; 1];
        match s.read(&mut b) {
            Ok(0) => return Err("connection closed before the SSH banner".into()),
            Ok(_) => {}
            Err(e) => return Err(format!("no SSH banner ({e})")),
        }
        total += 1;
        if total > 16 * 1024 {
            return Err("no SSH banner in the first 16 KB".into());
        }
        if b[0] == b'\n' {
            let l = String::from_utf8_lossy(&line)
                .trim_end_matches('\r')
                .to_string();
            line.clear();
            if l.starts_with("SSH-") {
                p.banner = l;
                break;
            }
            p.pre_banner.push(l);
        } else {
            line.push(b[0]);
            if line.len() > 255 && !line.starts_with(b"SSH-") {
                return Err("not an SSH server (no identification string)".into());
            }
        }
    }
    p.banner_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let (_, product, version, comment) = parse_banner(&p.banner);
    (p.product, p.version, p.comment) = (product, version, comment);
    let mut out = format!("{CLIENT_ID}\r\n").into_bytes();
    out.extend(packet(&kexinit_payload()));
    s.write_all(&out).map_err(|e| e.to_string())?;
    let sent = Instant::now();
    for _ in 0..8 {
        let hdr = match read_exact_timeout(&mut s, 5) {
            Ok(h) => h,
            Err(e) => {
                // Banner but no KEXINIT: still report what we have.
                p.pre_banner.push(format!("(no KEXINIT: {e})"));
                return Ok(p);
            }
        };
        let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        if !(5..=256 * 1024).contains(&len) {
            return Err(format!("bad SSH packet length {len}"));
        }
        let body = read_exact_timeout(&mut s, len - 1)?;
        let pad = hdr[4] as usize;
        let payload = &body[..body.len().saturating_sub(pad)];
        match payload.first() {
            Some(20) => {
                p.kexinit_ms = sent.elapsed().as_secs_f64() * 1000.0;
                p.algos = Some(parse_kexinit(payload)?);
                return Ok(p);
            }
            Some(1) => return Err("server disconnected during key exchange".into()),
            _ => continue, // IGNORE / DEBUG / …
        }
    }
    Err("no KEXINIT from the server".into())
}

// ---------------------------------------------------------------- ratings

/// (level, note) for one algorithm name in a category.
pub fn rate(kind: &str, a: &str) -> (Level, &'static str) {
    use Level::*;
    match kind {
        "kex" => match a {
            "diffie-hellman-group1-sha1" => (Bad, "1024-bit DH with SHA-1 (Logjam)"),
            "rsa1024-sha1" => (Bad, "1024-bit RSA kex"),
            "diffie-hellman-group14-sha1" | "diffie-hellman-group-exchange-sha1" => {
                (Warn, "SHA-1 key exchange")
            }
            x if x.starts_with("gss-") && x.contains("sha1") => (Warn, "SHA-1 key exchange"),
            x if x.contains("mlkem") || x.contains("sntrup") => (Good, "post-quantum hybrid"),
            x if x.starts_with("curve25519") => (Good, ""),
            x if x.starts_with("kex-strict") || x.starts_with("ext-info") => (Info, ""),
            x if x.starts_with("ecdh-sha2-nistp") => (Info, "NIST curve"),
            _ => (Info, ""),
        },
        "host_key" => match a {
            "ssh-dss" => (Bad, "DSA (1024-bit, deprecated)"),
            "ssh-rsa" => (Warn, "RSA with SHA-1 signatures"),
            x if x.contains("ed25519") => (Good, ""),
            _ => (Info, ""),
        },
        "cipher" => match a {
            "none" => (Bad, "no encryption"),
            x if x.starts_with("arcfour") => (Bad, "RC4"),
            "3des-cbc" | "blowfish-cbc" | "cast128-cbc" | "des-cbc" => {
                (Bad, "64-bit block cipher (Sweet32)")
            }
            x if x.ends_with("-cbc") || x == "rijndael-cbc@lysator.liu.se" => (Warn, "CBC mode"),
            x if x.contains("gcm") || x.starts_with("chacha20") => (Good, ""),
            _ => (Info, ""),
        },
        "mac" => match a {
            "none" => (Bad, "no integrity"),
            x if x.contains("md5") => (Bad, "MD5"),
            x if x.contains("-96") => (Bad, "truncated 96-bit MAC"),
            x if x.contains("sha1") => (Warn, "SHA-1"),
            "umac-64@openssh.com" => (Warn, "64-bit tag"),
            x if x.contains("etm") => (Good, ""),
            _ => (Info, "encrypt-and-MAC"),
        },
        "comp" => match a {
            "zlib" => (Warn, "compression before authentication"),
            _ => (Info, ""),
        },
        _ => (Info, ""),
    }
}

/// Terrapin (CVE-2023-48795): exposed when ChaCha20-Poly1305 or a CBC
/// cipher with an EtM MAC is offered and strict kex is not.
pub fn terrapin(a: &Algos) -> Option<bool> {
    let chacha = a.enc_s2c.iter().any(|c| c.starts_with("chacha20-poly1305"));
    let cbc_etm = a.enc_s2c.iter().any(|c| c.ends_with("-cbc"))
        && a.mac_s2c.iter().any(|m| m.contains("etm"));
    if !chacha && !cbc_etm {
        return Some(false);
    }
    Some(!a.kex.iter().any(|k| k == "kex-strict-s-v00@openssh.com"))
}

fn banner_notes(p: &Probe) -> Vec<(Level, String)> {
    let mut out = Vec::new();
    let (proto, ..) = parse_banner(&p.banner);
    if proto == "1.99" || proto.starts_with("1.") {
        out.push((
            Level::Bad,
            format!("protocol {proto}: SSH-1 is still accepted"),
        ));
    }
    if p.product.eq_ignore_ascii_case("OpenSSH") {
        let v = &p.version;
        let num: Vec<u32> = v
            .split(|c: char| !c.is_ascii_digit())
            .take(2)
            .filter_map(|x| x.parse().ok())
            .collect();
        if let [maj, min] = num[..] {
            let ver = (maj, min);
            if ver < (7, 4) {
                out.push((
                    Level::Bad,
                    format!("OpenSSH {v} is very old (many known vulnerabilities)"),
                ));
            } else if ((8, 5)..(9, 8)).contains(&ver) {
                out.push((
                    Level::Warn,
                    format!(
                        "OpenSSH {v} is in the regreSSHion range (CVE-2024-6387) unless the \
                         vendor patched it{}",
                        if p.comment.is_empty() {
                            String::new()
                        } else {
                            format!(" — build '{}'", p.comment)
                        }
                    ),
                ));
            }
        }
    } else if p.product.eq_ignore_ascii_case("dropbear") {
        out.push((
            Level::Info,
            "Dropbear (embedded / router SSH server)".to_string(),
        ));
    }
    if p.comment.is_empty() && !p.version.is_empty() {
        out.push((Level::Info, "no OS / build comment in the banner".into()));
    }
    out
}

pub fn probe_findings(p: &Probe) -> Vec<Finding> {
    let mut f = Vec::new();
    let mut add = |sec: &str, k: &str, v: String, l: Level| {
        f.push(Finding {
            section: sec.into(),
            key: k.into(),
            value: v,
            level: l,
        })
    };
    let s = "Server";
    if let Some(a) = p.addr {
        add(s, "Address", a.to_string(), Level::Info);
    }
    add(s, "Banner", p.banner.clone(), Level::Info);
    add(
        s,
        "Software",
        format!(
            "{} {}{}",
            p.product,
            p.version,
            if p.comment.is_empty() {
                String::new()
            } else {
                format!(" ({})", p.comment)
            }
        ),
        Level::Info,
    );
    for (l, n) in banner_notes(p) {
        add(s, "Note", n, l);
    }
    for l in &p.pre_banner {
        add(s, "Pre-banner text", l.clone(), Level::Info);
    }
    add(
        "Timing",
        "TCP connect",
        format!("{:.1} ms", p.connect_ms),
        Level::Info,
    );
    add(
        "Timing",
        "Banner",
        format!("{:.1} ms after connect", p.banner_ms - p.connect_ms),
        Level::Info,
    );
    let Some(a) = &p.algos else {
        return f;
    };
    add(
        "Timing",
        "KEXINIT",
        format!("{:.1} ms", p.kexinit_ms),
        Level::Info,
    );
    let mut cat = |sec: &str, kind: &str, list: &[String]| {
        if list.is_empty() {
            add(sec, "(none)", String::new(), Level::Info);
        }
        for name in list {
            let (l, note) = rate(kind, name);
            add(sec, name, note.to_string(), l);
        }
    };
    cat("Key exchange", "kex", &a.kex);
    cat("Host key", "host_key", &a.host_key);
    cat("Ciphers (server → client)", "cipher", &a.enc_s2c);
    cat("MACs (server → client)", "mac", &a.mac_s2c);
    cat("Compression", "comp", &a.comp_s2c);
    if a.enc_c2s != a.enc_s2c || a.mac_c2s != a.mac_s2c || a.comp_c2s != a.comp_s2c {
        add(
            "Ciphers (server → client)",
            "Note",
            "client → server lists differ".into(),
            Level::Info,
        );
    }
    let only_sha1_rsa = a.host_key.iter().any(|h| h == "ssh-rsa")
        && !a.host_key.iter().any(|h| h.starts_with("rsa-sha2"))
        && !a
            .host_key
            .iter()
            .any(|h| h.contains("ed25519") || h.contains("ecdsa"));
    let sum = "Summary";
    if only_sha1_rsa {
        add(
            sum,
            "Host key",
            "only ssh-rsa (SHA-1) host signatures; modern clients refuse it".into(),
            Level::Bad,
        );
    }
    match terrapin(a) {
        Some(true) => add(
            sum,
            "Terrapin",
            "CVE-2023-48795: vulnerable cipher mode without strict key exchange".into(),
            Level::Bad,
        ),
        Some(false) if a.kex.iter().any(|k| k.starts_with("kex-strict")) => add(
            sum,
            "Terrapin",
            "strict key exchange supported".into(),
            Level::Good,
        ),
        _ => add(
            sum,
            "Terrapin",
            "not exposed (no affected cipher mode)".into(),
            Level::Good,
        ),
    }
    let worst = |kind: &str, list: &[String]| {
        list.iter()
            .map(|n| rate(kind, n).0)
            .filter(|l| matches!(l, Level::Bad | Level::Warn))
            .max_by_key(|l| matches!(l, Level::Bad))
    };
    let mut weak = 0;
    for (k, l) in [
        ("kex", &a.kex),
        ("host_key", &a.host_key),
        ("cipher", &a.enc_s2c),
        ("mac", &a.mac_s2c),
        ("comp", &a.comp_s2c),
    ] {
        if worst(k, l).is_some() {
            weak += l
                .iter()
                .filter(|n| matches!(rate(k, n).0, Level::Bad | Level::Warn))
                .count();
        }
    }
    add(
        sum,
        "Weak algorithms",
        if weak == 0 {
            "none offered".into()
        } else {
            format!("{weak} weak or legacy algorithm(s) offered")
        },
        if weak == 0 { Level::Good } else { Level::Warn },
    );
    f
}

// ---------------------------------------------------------------- known keys

fn known_path() -> Option<std::path::PathBuf> {
    crate::platform::data_dir().map(|d| d.join("ssh_fingerprints.txt"))
}

/// Remembered "host:port" → (algorithm, fingerprint).
pub fn known_fingerprint(hostport: &str) -> Option<(String, String)> {
    let text = std::fs::read_to_string(known_path()?).ok()?;
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == hostport).then(|| {
            (
                it.next().unwrap_or("").into(),
                it.next().unwrap_or("").into(),
            )
        })
    })
}

pub fn remember_fingerprint(hostport: &str, algo: &str, fp: &str) -> Result<(), String> {
    let path = known_path().ok_or("no data directory")?;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let old = std::fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<String> = old
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(hostport))
        .map(String::from)
        .collect();
    lines.push(format!("{hostport} {algo} {fp}"));
    std::fs::write(&path, lines.join("\n") + "\n").map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- russh session

#[derive(Clone, Debug, Default)]
pub struct HostKey {
    pub algorithm: String,
    pub fingerprint: String,
    /// Fingerprint remembered from an earlier connection, if different.
    pub changed_from: Option<String>,
    pub first_seen: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Negotiated {
    pub kex: String,
    pub host_key: String,
    pub cipher: String,
    pub mac: String,
}

#[derive(Default)]
struct Shared {
    key: Option<HostKey>,
    negotiated: Option<Negotiated>,
    kex_at: Option<Instant>,
    auth_banner: Option<String>,
}

struct H {
    hostport: String,
    accept_changed: bool,
    shared: Arc<Mutex<Shared>>,
}

impl client::Handler for H {
    type Error = russh::Error;

    async fn check_server_key(&mut self, k: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let (algorithm, fingerprint) = match k {
            PublicKeyOrCertificate::PublicKey { key, .. } => (
                key.algorithm().as_str().to_string(),
                key.fingerprint(HashAlg::Sha256).to_string(),
            ),
            PublicKeyOrCertificate::Certificate(c) => (
                format!("{} certificate", c.algorithm().as_str()),
                c.public_key().fingerprint(HashAlg::Sha256).to_string(),
            ),
        };
        let known = known_fingerprint(&self.hostport);
        let changed_from = known
            .as_ref()
            .filter(|(_, fp)| *fp != fingerprint)
            .map(|(a, fp)| format!("{a} {fp}"));
        let ok = changed_from.is_none() || self.accept_changed;
        if ok && (known.is_none() || changed_from.is_some()) {
            let _ = remember_fingerprint(&self.hostport, &algorithm, &fingerprint);
        }
        self.shared.lock().unwrap().key = Some(HostKey {
            algorithm,
            fingerprint,
            first_seen: known.is_none(),
            changed_from,
        });
        Ok(ok)
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.shared.lock().unwrap().auth_banner = Some(banner.trim().to_string());
        Ok(())
    }

    async fn kex_done(
        &mut self,
        _secret: Option<&[u8]>,
        names: &russh::Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let mut s = self.shared.lock().unwrap();
        s.kex_at.get_or_insert_with(Instant::now);
        s.negotiated.get_or_insert_with(|| Negotiated {
            kex: names.kex.as_ref().to_string(),
            host_key: names.key.as_str().to_string(),
            cipher: names.cipher.as_ref().to_string(),
            mac: names.server_mac.as_ref().to_string(),
        });
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum Auth {
    None,
    Password(String),
    Key { path: String, passphrase: String },
}

#[derive(Clone, Debug)]
pub struct ConnectCfg {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub accept_changed_key: bool,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct Handshake {
    pub key: Option<HostKey>,
    pub negotiated: Option<Negotiated>,
    pub methods: Vec<String>,
    pub none_accepted: bool,
    pub auth_banner: Option<String>,
    pub connect_ms: f64,
    pub kex_ms: f64,
    pub auth_ms: Option<f64>,
    pub logged_in: bool,
    pub auth_error: Option<String>,
}

fn err(e: impl std::fmt::Display) -> String {
    let s = e.to_string();
    if s.contains("UnknownKey") || s.contains("unknown key") {
        "host key rejected".into()
    } else {
        s
    }
}

/// Connect and authenticate. With `Auth::None` only the "none" method is
/// tried, which lists the methods the server offers.
async fn connect(
    cfg: &ConnectCfg,
) -> Result<(client::Handle<H>, Handshake), (String, Option<Box<Handshake>>)> {
    let addr = resolve(&cfg.host, cfg.port).map_err(|e| (e, None))?;
    let hostport = format!("{}:{}", cfg.host, cfg.port);
    let t0 = Instant::now();
    let tcp = tokio::time::timeout(cfg.timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| ("TCP connect timed out".to_string(), None))?
        .map_err(|e| (format!("{addr}: {e}"), None))?;
    let _ = tcp.set_nodelay(true);
    let connect_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let shared = Arc::new(Mutex::new(Shared::default()));
    let config = Arc::new(client::Config {
        client_id: russh::SshId::Standard(CLIENT_ID.into()),
        inactivity_timeout: Some(Duration::from_secs(600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let h = H {
        hostport,
        accept_changed: cfg.accept_changed_key,
        shared: shared.clone(),
    };
    let snapshot = |hs: &mut Handshake| {
        let s = shared.lock().unwrap();
        hs.key = s.key.clone();
        hs.negotiated = s.negotiated.clone();
        hs.auth_banner = s.auth_banner.clone();
        hs.kex_ms = s
            .kex_at
            .map(|k| k.duration_since(t0).as_secs_f64() * 1000.0 - connect_ms)
            .unwrap_or(0.0);
    };
    let mut hs = Handshake {
        connect_ms,
        ..Default::default()
    };
    let mut handle =
        match tokio::time::timeout(cfg.timeout, client::connect_stream(config, tcp, h)).await {
            Err(_) => return Err(("SSH handshake timed out".into(), None)),
            Ok(Err(e)) => {
                snapshot(&mut hs);
                let msg = match &hs.key {
                    Some(k) if k.changed_from.is_some() => format!(
                        "HOST KEY CHANGED: was {}, now {} {}. Connection refused — possible \
                     man-in-the-middle, or the server was reinstalled.",
                        k.changed_from.clone().unwrap_or_default(),
                        k.algorithm,
                        k.fingerprint
                    ),
                    _ => err(e),
                };
                return Err((msg, Some(Box::new(hs))));
            }
            Ok(Ok(h)) => h,
        };
    let user = if cfg.user.is_empty() {
        "anonymous".to_string()
    } else {
        cfg.user.clone()
    };
    let methods_of = |r: &russh::client::AuthResult| match r {
        russh::client::AuthResult::Success => Vec::new(),
        russh::client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods
            .iter()
            .map(|m| <&'static str>::from(m).to_string())
            .collect(),
    };
    match tokio::time::timeout(cfg.timeout, handle.authenticate_none(&user)).await {
        Ok(Ok(r)) => {
            hs.none_accepted = r.success();
            hs.methods = methods_of(&r);
        }
        Ok(Err(e)) => {
            snapshot(&mut hs);
            return Err((format!("authentication: {}", err(e)), Some(Box::new(hs))));
        }
        Err(_) => return Err(("authentication timed out".into(), Some(Box::new(hs)))),
    }
    snapshot(&mut hs);
    if hs.none_accepted {
        hs.logged_in = true;
        return Ok((handle, hs));
    }
    let t_auth = Instant::now();
    let r = match &cfg.auth {
        Auth::None => return Ok((handle, hs)),
        Auth::Password(p) => handle.authenticate_password(&user, p).await,
        Auth::Key { path, passphrase } => {
            let path = expand_home(path);
            let key = russh::keys::load_secret_key(
                &path,
                (!passphrase.is_empty()).then_some(passphrase.as_str()),
            )
            .map_err(|e| {
                (
                    format!("key file {}: {e}", path.display()),
                    Some(Box::new(hs.clone())),
                )
            })?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            handle
                .authenticate_publickey(&user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
        }
    };
    hs.auth_ms = Some(t_auth.elapsed().as_secs_f64() * 1000.0);
    match r {
        Ok(r) if r.success() => hs.logged_in = true,
        Ok(r) => {
            let m = methods_of(&r);
            hs.auth_error = Some(format!(
                "login refused for '{user}'{}",
                if m.is_empty() {
                    String::new()
                } else {
                    format!(" (server offers: {})", m.join(", "))
                }
            ));
        }
        Err(e) => hs.auth_error = Some(err(e)),
    }
    Ok((handle, hs))
}

fn expand_home(p: &str) -> std::path::PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => crate::platform::home_dir()
            .map(|h| h.join(rest))
            .unwrap_or_else(|| p.into()),
        None => p.into(),
    }
}

pub fn handshake_findings(hs: &Handshake) -> Vec<Finding> {
    let mut f = Vec::new();
    let mut add = |sec: &str, k: &str, v: String, l: Level| {
        f.push(Finding {
            section: sec.into(),
            key: k.into(),
            value: v,
            level: l,
        })
    };
    let s = "Host key";
    if let Some(k) = &hs.key {
        add(
            s,
            "Type",
            k.algorithm.clone(),
            rate("host_key", &k.algorithm).0,
        );
        add(s, "Fingerprint", k.fingerprint.clone(), Level::Info);
        if let Some(old) = &k.changed_from {
            add(
                s,
                "CHANGED",
                format!("previously {old} — verify before trusting this server"),
                Level::Bad,
            );
        } else if k.first_seen {
            add(
                s,
                "Status",
                "first connection: fingerprint remembered (compare it with the server's)".into(),
                Level::Warn,
            );
        } else {
            add(
                s,
                "Status",
                "matches the remembered fingerprint".into(),
                Level::Good,
            );
        }
    }
    if let Some(n) = &hs.negotiated {
        let s = "Negotiated";
        add(s, "Key exchange", n.kex.clone(), rate("kex", &n.kex).0);
        add(s, "Host key", n.host_key.clone(), Level::Info);
        add(s, "Cipher", n.cipher.clone(), rate("cipher", &n.cipher).0);
        let aead = n.cipher.contains("gcm") || n.cipher.starts_with("chacha20");
        add(
            s,
            "MAC",
            if aead {
                format!("implicit (AEAD cipher; {} unused)", n.mac)
            } else {
                n.mac.clone()
            },
            Level::Info,
        );
    }
    let s = "Authentication";
    if hs.none_accepted {
        add(
            s,
            "none",
            "server accepted login WITHOUT any credentials".into(),
            Level::Bad,
        );
    } else if !hs.methods.is_empty() {
        let pw = hs
            .methods
            .iter()
            .any(|m| m == "password" || m == "keyboard-interactive");
        add(
            s,
            "Methods offered",
            hs.methods.join(", "),
            if pw { Level::Warn } else { Level::Good },
        );
        if pw {
            add(
                s,
                "Note",
                "password logins are allowed; keys only is safer against guessing".into(),
                Level::Warn,
            );
        }
    }
    if let Some(b) = &hs.auth_banner {
        add(s, "Banner", b.replace('\n', " ⏎ "), Level::Info);
    }
    if let Some(e) = &hs.auth_error {
        add(s, "Login", e.clone(), Level::Bad);
    } else if hs.logged_in {
        add(s, "Login", "succeeded".into(), Level::Good);
    }
    let t = "Timing";
    add(
        t,
        "TCP connect",
        format!("{:.1} ms", hs.connect_ms),
        Level::Info,
    );
    if hs.kex_ms > 0.0 {
        add(
            t,
            "Key exchange",
            format!("{:.1} ms", hs.kex_ms),
            Level::Info,
        );
    }
    if let Some(a) = hs.auth_ms {
        add(t, "Authentication", format!("{a:.1} ms"), Level::Info);
    }
    f
}

// ---------------------------------------------------------------- SFTP worker

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub perms: String,
    pub mtime: Option<u32>,
    pub owner: String,
}

pub enum Cmd {
    List(String),
    Download {
        remote: String,
        local: std::path::PathBuf,
    },
    Upload {
        local: std::path::PathBuf,
        remote_dir: String,
    },
    WriteTest(String),
    Close,
}

pub enum Ev {
    Analysis(Vec<Finding>),
    Handshake(Box<Handshake>),
    Connected { home: String },
    Listing { path: String, entries: Vec<Entry> },
    Progress(String),
    Transfer(String),
    Error(String),
    Closed(String),
}

pub fn perms_string(mode: u32, is_dir: bool, is_link: bool) -> String {
    let mut s = String::with_capacity(10);
    s.push(if is_link {
        'l'
    } else if is_dir {
        'd'
    } else {
        '-'
    });
    for shift in [6, 3, 0] {
        let b = (mode >> shift) & 7;
        s.push(if b & 4 != 0 { 'r' } else { '-' });
        s.push(if b & 2 != 0 { 'w' } else { '-' });
        s.push(if b & 1 != 0 { 'x' } else { '-' });
    }
    s
}

/// Unix time → "YYYY-MM-DD HH:MM" (UTC).
pub fn fmt_time(t: u32) -> String {
    let days = (t / 86400) as i64;
    let rem = t % 86400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        rem / 60 % 60
    )
}

pub fn join_path(dir: &str, name: &str) -> String {
    if name.starts_with('/') {
        name.to_string()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

pub fn parent_path(p: &str) -> String {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => t[..i].to_string(),
    }
}

fn rate_text(bytes: u64, secs: f64) -> String {
    format!(
        "{:.2} MB in {:.2} s ({:.2} MB/s)",
        bytes as f64 / 1e6,
        secs,
        bytes as f64 / 1e6 / secs.max(0.001)
    )
}

/// Handle to a running analysis / SFTP session thread.
pub struct Worker {
    pub tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
}

impl Worker {
    pub fn send(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }
}

/// Analyse the server without credentials (raw probe + handshake + auth
/// methods).
pub fn analyse(cfg: ConnectCfg, ev: std::sync::mpsc::Sender<Ev>) {
    std::thread::spawn(move || {
        match probe(&cfg.host, cfg.port, cfg.timeout) {
            Ok(p) => {
                let _ = ev.send(Ev::Analysis(probe_findings(&p)));
            }
            Err(e) => {
                let _ = ev.send(Ev::Error(e));
                let _ = ev.send(Ev::Closed(String::new()));
                return;
            }
        }
        let _ = ev.send(Ev::Progress("Completing the handshake…".into()));
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                let _ = ev.send(Ev::Error(e.to_string()));
                return;
            }
        };
        let cfg = ConnectCfg {
            auth: Auth::None,
            ..cfg
        };
        rt.block_on(async {
            match connect(&cfg).await {
                Ok((h, hs)) => {
                    let _ = ev.send(Ev::Handshake(Box::new(hs)));
                    let _ = h
                        .disconnect(russh::Disconnect::ByApplication, "", "en")
                        .await;
                }
                Err((e, hs)) => {
                    if let Some(hs) = hs {
                        let _ = ev.send(Ev::Handshake(hs));
                    }
                    let _ = ev.send(Ev::Error(e));
                }
            }
        });
        let _ = ev.send(Ev::Closed("Analysis complete".into()));
    });
}

/// Log in and keep an SFTP session open; commands arrive on the returned
/// worker, events on `ev`.
pub fn open(cfg: ConnectCfg, write_test: bool, ev: std::sync::mpsc::Sender<Ev>) -> Worker {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                let _ = ev.send(Ev::Error(e.to_string()));
                return;
            }
        };
        rt.block_on(async move {
            let send = |e: Ev| {
                let _ = ev.send(e);
            };
            let (handle, hs) = match connect(&cfg).await {
                Ok(x) => x,
                Err((e, hs)) => {
                    if let Some(hs) = hs {
                        send(Ev::Handshake(hs));
                    }
                    send(Ev::Error(e));
                    send(Ev::Closed(String::new()));
                    return;
                }
            };
            let ok = hs.logged_in;
            let auth_err = hs.auth_error.clone();
            send(Ev::Handshake(Box::new(hs)));
            if !ok {
                send(Ev::Error(auth_err.unwrap_or_else(|| "login failed".into())));
                send(Ev::Closed(String::new()));
                return;
            }
            send(Ev::Progress("Starting the SFTP subsystem…".into()));
            let t = Instant::now();
            let sftp = async {
                let ch = handle.channel_open_session().await.map_err(err)?;
                ch.request_subsystem(true, "sftp").await.map_err(err)?;
                russh_sftp::client::SftpSession::new(ch.into_stream())
                    .await
                    .map_err(|e| format!("SFTP: {e}"))
            };
            let sftp = match tokio::time::timeout(cfg.timeout, sftp).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    send(Ev::Error(format!("SFTP not available: {e}")));
                    send(Ev::Closed(String::new()));
                    return;
                }
                Err(_) => {
                    send(Ev::Error("SFTP subsystem timed out".into()));
                    send(Ev::Closed(String::new()));
                    return;
                }
            };
            let home = sftp
                .canonicalize(".")
                .await
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "/".into());
            send(Ev::Transfer(format!(
                "SFTP session ready in {:.0} ms",
                t.elapsed().as_secs_f64() * 1000.0
            )));
            send(Ev::Connected { home: home.clone() });
            list(&sftp, &home, &send).await;
            if write_test {
                write_test_run(&sftp, &home, &send).await;
            }
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    Cmd::List(p) => list(&sftp, &p, &send).await,
                    Cmd::Download { remote, local } => {
                        download(&sftp, &remote, &local, &send).await
                    }
                    Cmd::Upload { local, remote_dir } => {
                        upload(&sftp, &local, &remote_dir, &send).await;
                        list(&sftp, &remote_dir, &send).await;
                    }
                    Cmd::WriteTest(dir) => write_test_run(&sftp, &dir, &send).await,
                    Cmd::Close => break,
                }
            }
            let _ = sftp.close().await;
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
            send(Ev::Closed("Disconnected".into()));
        });
    });
    Worker { tx }
}

async fn list(sftp: &russh_sftp::client::SftpSession, path: &str, send: &impl Fn(Ev)) {
    let path = sftp
        .canonicalize(path)
        .await
        .map(|s| s.to_string())
        .unwrap_or_else(|_| path.to_string());
    match sftp.read_dir(path.as_str()).await {
        Ok(rd) => {
            let mut entries: Vec<Entry> = rd
                .filter_map(|e| {
                    let name = e.file_name().to_string();
                    if name == "." || name == ".." {
                        return None;
                    }
                    let m = e.metadata();
                    let (is_dir, is_link) = (m.is_dir(), m.is_symlink());
                    Some(Entry {
                        perms: perms_string(m.permissions.unwrap_or(0), is_dir, is_link),
                        size: m.size.unwrap_or(0),
                        mtime: m.mtime,
                        owner: m
                            .user
                            .clone()
                            .or_else(|| m.uid.map(|u| u.to_string()))
                            .unwrap_or_default(),
                        name,
                        is_dir,
                        is_link,
                    })
                })
                .collect();
            entries.sort_by(|a, b| {
                b.is_dir
                    .cmp(&a.is_dir)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
            send(Ev::Listing { path, entries });
        }
        Err(e) => send(Ev::Error(format!("{path}: {e}"))),
    }
}

async fn download(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local: &std::path::Path,
    send: &impl Fn(Ev),
) {
    let t = Instant::now();
    let r: Result<u64, String> = async {
        let mut f = sftp.open(remote).await.map_err(|e| e.to_string())?;
        let mut out =
            std::fs::File::create(local).map_err(|e| format!("{}: {e}", local.display()))?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        let mut last = Instant::now();
        loop {
            let n = f.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            total += n as u64;
            if last.elapsed() > Duration::from_millis(300) {
                last = Instant::now();
                send(Ev::Progress(format!(
                    "Downloading… {}",
                    rate_text(total, t.elapsed().as_secs_f64())
                )));
            }
        }
        Ok(total)
    }
    .await;
    match r {
        Ok(n) => send(Ev::Transfer(format!(
            "Downloaded {remote} → {}: {}",
            local.display(),
            rate_text(n, t.elapsed().as_secs_f64())
        ))),
        Err(e) => send(Ev::Error(format!("download {remote}: {e}"))),
    }
}

async fn upload(
    sftp: &russh_sftp::client::SftpSession,
    local: &std::path::Path,
    remote_dir: &str,
    send: &impl Fn(Ev),
) {
    let name = local
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "upload.bin".into());
    let remote = join_path(remote_dir, &name);
    let t = Instant::now();
    let r: Result<u64, String> = async {
        let mut inp =
            std::fs::File::open(local).map_err(|e| format!("{}: {e}", local.display()))?;
        let mut f = sftp
            .create(remote.as_str())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        let mut last = Instant::now();
        loop {
            let n = inp.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            f.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
            total += n as u64;
            if last.elapsed() > Duration::from_millis(300) {
                last = Instant::now();
                send(Ev::Progress(format!(
                    "Uploading… {}",
                    rate_text(total, t.elapsed().as_secs_f64())
                )));
            }
        }
        f.shutdown().await.map_err(|e| e.to_string())?;
        Ok(total)
    }
    .await;
    match r {
        Ok(n) => send(Ev::Transfer(format!(
            "Uploaded {} → {remote}: {}",
            local.display(),
            rate_text(n, t.elapsed().as_secs_f64())
        ))),
        Err(e) => send(Ev::Error(format!("upload to {remote}: {e}"))),
    }
}

/// Create a 1 MB file, read it back, compare, delete.
async fn write_test_run(sftp: &russh_sftp::client::SftpSession, dir: &str, send: &impl Fn(Ev)) {
    let name = join_path(
        dir,
        &format!(".network_analyser_write_test_{}", std::process::id()),
    );
    let data: Vec<u8> = (0..1_048_576u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let t = Instant::now();
    let r: Result<String, String> = async {
        let mut f = sftp
            .create(name.as_str())
            .await
            .map_err(|e| format!("create: {e}"))?;
        f.write_all(&data)
            .await
            .map_err(|e| format!("write: {e}"))?;
        f.shutdown().await.map_err(|e| format!("close: {e}"))?;
        let w = t.elapsed().as_secs_f64();
        let t2 = Instant::now();
        let back = sftp
            .read(name.as_str())
            .await
            .map_err(|e| format!("read back: {e}"))?;
        let r = t2.elapsed().as_secs_f64();
        let same = back == data;
        sftp.remove_file(name.as_str())
            .await
            .map_err(|e| format!("delete: {e}"))?;
        if !same {
            return Err(format!("data read back differs ({} bytes)", back.len()));
        }
        Ok(format!(
            "Write test in {dir}: create/write {} · read back {} · verified and deleted",
            rate_text(data.len() as u64, w),
            rate_text(data.len() as u64, r)
        ))
    }
    .await;
    match r {
        Ok(s) => send(Ev::Transfer(s)),
        Err(e) => {
            let _ = sftp.remove_file(name.as_str()).await;
            send(Ev::Error(format!("write test in {dir} failed: {e}")));
        }
    }
}

/// Where downloads go: ~/Downloads if it exists, else home, else cwd.
pub fn download_dir() -> std::path::PathBuf {
    crate::platform::home_dir()
        .map(|h| {
            let d = h.join("Downloads");
            if d.is_dir() { d } else { h }
        })
        .unwrap_or_else(|| ".".into())
}

// ---------------------------------------------------------------- CLI

pub const CLI_USAGE: &str = "\
    --ssh [USER@]HOST[:PORT]
                  SSH server audit: banner, algorithms (weak / Terrapin), host key
                  fingerprint and offered login methods (no login attempted)
";

pub fn cli(args: &[String]) {
    let Some(target) = args.first() else {
        eprint!("usage:\n{CLI_USAGE}");
        std::process::exit(2)
    };
    let (user, host, port) = parse_target(target).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let (tx, rx) = std::sync::mpsc::channel();
    analyse(
        ConnectCfg {
            host,
            port,
            user: user
                .or_else(|| std::env::var("USER").ok())
                .or_else(|| std::env::var("USERNAME").ok())
                .unwrap_or_default(),
            auth: Auth::None,
            accept_changed_key: false,
            timeout: Duration::from_secs(8),
        },
        tx,
    );
    let mut failed = false;
    for ev in rx {
        match ev {
            Ev::Analysis(f) => print!("{}", crate::widgets::findings_text(&f)),
            Ev::Handshake(h) => {
                print!("{}", crate::widgets::findings_text(&handshake_findings(&h)))
            }
            Ev::Error(e) => {
                eprintln!("error: {e}");
                failed = true;
            }
            Ev::Closed(_) => break,
            _ => {}
        }
    }
    if failed {
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kexinit_from(lists: [&str; 10]) -> Vec<u8> {
        let mut p = vec![20u8];
        p.extend_from_slice(&[0; 16]);
        for l in lists {
            p.extend_from_slice(&(l.len() as u32).to_be_bytes());
            p.extend_from_slice(l.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&[0; 4]);
        p
    }

    #[test]
    fn kexinit_roundtrip() {
        let a = parse_kexinit(&kexinit_payload()).unwrap();
        assert!(a.kex.contains(&"curve25519-sha256".to_string()));
        assert_eq!(a.comp_c2s, vec!["none", "zlib@openssh.com", "zlib"]);
        let pk = packet(&kexinit_payload());
        assert_eq!(pk.len() % 8, 0);
        let len = u32::from_be_bytes([pk[0], pk[1], pk[2], pk[3]]) as usize;
        assert_eq!(len + 4, pk.len());
        assert!(pk[4] >= 4);
        assert!(parse_kexinit(&[20, 1, 2]).is_err());
    }

    #[test]
    fn banners() {
        let (proto, prod, ver, c) = parse_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5");
        assert_eq!(
            (proto.as_str(), prod.as_str(), ver.as_str(), c.as_str()),
            ("2.0", "OpenSSH", "9.6p1", "Ubuntu-3ubuntu13.5")
        );
        let (_, prod, ver, _) = parse_banner("SSH-2.0-dropbear_2022.83");
        assert_eq!((prod.as_str(), ver.as_str()), ("dropbear", "2022.83"));
        let p = Probe {
            banner: "SSH-1.99-OpenSSH_5.3".into(),
            product: "OpenSSH".into(),
            version: "5.3".into(),
            ..Default::default()
        };
        let notes = banner_notes(&p);
        assert!(
            notes
                .iter()
                .any(|(l, n)| matches!(l, Level::Bad) && n.contains("SSH-1"))
        );
        assert!(notes.iter().any(|(_, n)| n.contains("very old")));
    }

    #[test]
    fn ratings_and_terrapin() {
        assert!(matches!(
            rate("kex", "diffie-hellman-group1-sha1").0,
            Level::Bad
        ));
        assert!(matches!(rate("cipher", "aes128-cbc").0, Level::Warn));
        assert!(matches!(rate("cipher", "3des-cbc").0, Level::Bad));
        assert!(matches!(rate("mac", "hmac-sha1-96").0, Level::Bad));
        assert!(matches!(
            rate("mac", "hmac-sha2-256-etm@openssh.com").0,
            Level::Good
        ));
        assert!(matches!(rate("host_key", "ssh-dss").0, Level::Bad));
        let vulnerable = parse_kexinit(&kexinit_from([
            "curve25519-sha256",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
            "chacha20-poly1305@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ]))
        .unwrap();
        assert_eq!(terrapin(&vulnerable), Some(true));
        let mut fixed = vulnerable.clone();
        fixed.kex.push("kex-strict-s-v00@openssh.com".into());
        assert_eq!(terrapin(&fixed), Some(false));
        let f = probe_findings(&Probe {
            banner: "SSH-2.0-X".into(),
            algos: Some(vulnerable),
            ..Default::default()
        });
        assert!(
            f.iter()
                .any(|x| x.key == "Terrapin" && matches!(x.level, Level::Bad))
        );
    }

    /// Live SFTP round trip. Run with
    /// `NA_SFTP_TEST="user@host:port /path/to/key" cargo test live_sftp -- --ignored`.
    #[test]
    #[ignore]
    fn live_sftp() {
        let spec = std::env::var("NA_SFTP_TEST").expect("NA_SFTP_TEST not set");
        let (target, key) = spec.split_once(' ').unwrap();
        let (user, host, port) = parse_target(target).unwrap();
        let dir = std::env::temp_dir().join(format!("na_sftp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("upload.bin");
        std::fs::write(&src, vec![7u8; 300_000]).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let w = open(
            ConnectCfg {
                host,
                port,
                user: user.unwrap(),
                auth: Auth::Key {
                    path: key.into(),
                    passphrase: String::new(),
                },
                accept_changed_key: true,
                timeout: Duration::from_secs(10),
            },
            true,
            tx,
        );
        let next = || rx.recv_timeout(Duration::from_secs(20)).expect("event");
        let mut home = String::new();
        let mut transfers = 0;
        let mut step = 0;
        loop {
            match next() {
                Ev::Error(e) => panic!("{e}"),
                Ev::Connected { home: h } => home = h,
                Ev::Listing { path, entries } => {
                    println!("{path}: {} entries", entries.len());
                    if step == 1 {
                        assert!(
                            entries
                                .iter()
                                .any(|e| e.name == "upload.bin" && e.size == 300_000)
                        );
                        w.send(Cmd::Download {
                            remote: join_path(&path, "upload.bin"),
                            local: dir.join("back.bin"),
                        });
                    }
                }
                Ev::Transfer(t) => {
                    println!("{t}");
                    transfers += 1;
                    // 1: session ready, 2: write test, 3: upload, 4: download
                    if transfers == 2 {
                        step = 1;
                        w.send(Cmd::Upload {
                            local: src.clone(),
                            remote_dir: home.clone(),
                        });
                    } else if transfers == 4 {
                        w.send(Cmd::Close);
                    }
                }
                Ev::Closed(_) => break,
                _ => {}
            }
        }
        assert_eq!(
            std::fs::read(dir.join("back.bin")).unwrap(),
            vec![7u8; 300_000]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn helpers() {
        assert_eq!(perms_string(0o755, true, false), "drwxr-xr-x");
        assert_eq!(perms_string(0o640, false, false), "-rw-r-----");
        assert_eq!(fmt_time(0), "1970-01-01 00:00");
        assert_eq!(fmt_time(1_700_000_000), "2023-11-14 22:13");
        assert_eq!(parent_path("/home/user/"), "/home");
        assert_eq!(parent_path("/home"), "/");
        assert_eq!(join_path("/", "a"), "/a");
        assert_eq!(join_path("/x", "a"), "/x/a");
        assert_eq!(
            parse_target("bob@host.lan:2222").unwrap(),
            (Some("bob".into()), "host.lan".into(), 2222)
        );
        assert_eq!(
            parse_target("10.0.0.1").unwrap(),
            (None, "10.0.0.1".into(), 22)
        );
        assert_eq!(parse_target("[::1]:22").unwrap(), (None, "::1".into(), 22));
    }
}
