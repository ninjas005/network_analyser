//! TLS: certificate-chain scanner (trust, expiry, names, keys), protocol
//! version support (TLS 1.3/1.2 via rustls, legacy 1.0/1.1 via a raw
//! ClientHello), STARTTLS for mail/FTP, and a shared client config.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use sha2::{Digest, Sha256};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// OS trust store (loaded once).
pub fn roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            for c in rustls_native_certs::load_native_certs().certs {
                let _ = store.add(c);
            }
            Arc::new(store)
        })
        .clone()
}

/// Normal, verifying client config (used by the HTTPS download test).
pub fn client_config() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
}

/// Records the presented chain and the real verification result, but lets
/// the handshake continue so broken certificates can still be inspected.
#[derive(Debug)]
struct Recorder {
    inner: Arc<WebPkiServerVerifier>,
    chain: Mutex<Vec<CertificateDer<'static>>>,
    verdict: Mutex<Option<Result<(), String>>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.clone().into_owned()];
        chain.extend(intermediates.iter().map(|c| c.clone().into_owned()));
        *self.chain.lock().unwrap() = chain;
        let r = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now);
        *self.verdict.lock().unwrap() = Some(r.map(|_| ()).map_err(|e| describe_error(&e)));
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(m, c, d)
            .or_else(|e| verify_signature_raw(m, c, d).map_err(|_| e))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(m, c, d)
            .or_else(|e| verify_signature_raw(m, c, d).map_err(|_| e))
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Check a handshake signature with the certificate's public key directly.
/// webpki refuses to parse X.509 v1 certificates (still common on
/// self-made broker / device certificates), so when the certificate is not
/// being verified anyway this proves the peer holds the key without
/// webpki's certificate parser.
pub fn verify_signature_raw(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    let bad = || rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature);
    let (_, x) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| bad())?;
    let key = &x.public_key().subject_public_key.data;
    let provider = rustls::crypto::ring::default_provider();
    for (scheme, algs) in provider.signature_verification_algorithms.mapping {
        if *scheme != dss.scheme {
            continue;
        }
        if algs
            .iter()
            .any(|a| a.verify_signature(key, message, dss.signature()).is_ok())
        {
            return Ok(HandshakeSignatureValid::assertion());
        }
    }
    Err(bad())
}

fn describe_error(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => "certificate has expired".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "certificate is not valid yet".into(),
            C::NotValidForName | C::NotValidForNameContext { .. } => {
                "certificate does not match the host name".into()
            }
            C::UnknownIssuer => {
                "issued by an unknown / untrusted CA (self-signed or incomplete chain)".into()
            }
            C::Revoked => "certificate has been revoked".into(),
            C::BadSignature => "bad certificate signature".into(),
            C::Other(o) if format!("{o:?}").contains("UnsupportedCertVersion") => {
                "X.509 v1 certificate (no extensions), which TLS libraries no longer verify; \
                 re-issue it as v3 with a subjectAltName"
                    .into()
            }
            other => format!("{other:?}"),
        },
        other => other.to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StartTls {
    None,
    Smtp,
    Imap,
    Pop3,
    Ftp,
}

impl StartTls {
    pub fn for_port(port: u16) -> StartTls {
        match port {
            25 | 587 => StartTls::Smtp,
            143 => StartTls::Imap,
            110 => StartTls::Pop3,
            21 => StartTls::Ftp,
            _ => StartTls::None,
        }
    }
}

fn starttls(s: &mut TcpStream, mode: StartTls) -> Result<(), String> {
    if mode == StartTls::None {
        return Ok(());
    }
    let mut r = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    // Read a (possibly multi-line "250-…") reply; returns the last line.
    let mut read_reply = |r: &mut BufReader<TcpStream>| -> Result<String, String> {
        loop {
            line.clear();
            if r.read_line(&mut line)
                .map_err(|e| format!("STARTTLS: {e}"))?
                == 0
            {
                return Err("STARTTLS: connection closed".into());
            }
            let l = line.trim_end();
            let multi = l.len() > 3 && &l[3..4] == "-";
            if !multi {
                return Ok(l.to_string());
            }
        }
    };
    let send =
        |s: &mut TcpStream, cmd: &str| s.write_all(cmd.as_bytes()).map_err(|e| e.to_string());
    match mode {
        StartTls::Smtp => {
            read_reply(&mut r)?;
            send(s, "EHLO network-analyser\r\n")?;
            read_reply(&mut r)?;
            send(s, "STARTTLS\r\n")?;
            let l = read_reply(&mut r)?;
            if !l.starts_with("220") {
                return Err(format!("server refused STARTTLS: {l}"));
            }
        }
        StartTls::Imap => {
            read_reply(&mut r)?;
            send(s, "a1 STARTTLS\r\n")?;
            let l = read_reply(&mut r)?;
            if !l.to_uppercase().contains("OK") {
                return Err(format!("server refused STARTTLS: {l}"));
            }
        }
        StartTls::Pop3 => {
            read_reply(&mut r)?;
            send(s, "STLS\r\n")?;
            let l = read_reply(&mut r)?;
            if !l.starts_with("+OK") {
                return Err(format!("server refused STLS: {l}"));
            }
        }
        StartTls::Ftp => {
            read_reply(&mut r)?;
            send(s, "AUTH TLS\r\n")?;
            let l = read_reply(&mut r)?;
            if !l.starts_with("234") {
                return Err(format!("server refused AUTH TLS: {l}"));
            }
        }
        StartTls::None => {}
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub sans: Vec<String>,
    pub key: String,
    pub key_bits: usize,
    pub sig_alg: String,
    pub is_ca: bool,
    pub self_signed: bool,
    pub sha256: String,
}

fn sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA".into(),
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA".into(),
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA".into(),
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA (weak)".into(),
        "1.2.840.113549.1.1.4" => "MD5 with RSA (broken)".into(),
        "1.2.840.113549.1.1.10" => "RSA-PSS".into(),
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256".into(),
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384".into(),
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512".into(),
        "1.2.840.10045.4.1" => "ECDSA with SHA-1 (weak)".into(),
        "1.3.101.112" => "Ed25519".into(),
        o => o.to_string(),
    }
}

fn date(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{}-{m:02}-{d:02}", if m <= 2 { y + 1 } else { y })
}

pub fn parse_cert(der: &[u8]) -> Result<CertInfo, String> {
    use x509_parser::prelude::*;
    let (_, c) = parse_x509_certificate(der).map_err(|e| format!("bad certificate: {e}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let nb = c.validity().not_before.timestamp();
    let na = c.validity().not_after.timestamp();
    let sans = c
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|e| {
            e.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    GeneralName::IPAddress(b) => match b.len() {
                        4 => Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
                        16 => Some(
                            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b).ok()?).to_string(),
                        ),
                        _ => None,
                    },
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let spki = c.public_key();
    let alg = spki.algorithm.algorithm.to_id_string();
    let bits = spki.parsed().map(|k| k.key_size()).unwrap_or(0);
    let key = match alg.as_str() {
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())
                .unwrap_or_default();
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => "ECDSA P-256".into(),
                "1.3.132.0.34" => "ECDSA P-384".into(),
                "1.3.132.0.35" => "ECDSA P-521".into(),
                _ => "ECDSA".into(),
            }
        }
        "1.3.101.112" => "Ed25519".into(),
        o => o.to_string(),
    };
    Ok(CertInfo {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        serial: c.raw_serial_as_string(),
        not_before: date(nb),
        not_after: date(na),
        days_left: (na - now).div_euclid(86400),
        sans,
        key,
        key_bits: bits,
        sig_alg: sig_name(&c.signature_algorithm.algorithm.to_id_string()),
        is_ca: c.is_ca(),
        self_signed: c.subject().as_raw() == c.issuer().as_raw(),
        sha256: Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    })
}

/// RFC 6125-style match of a host name against the certificate's names.
pub fn name_matches(host: &str, names: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    names.iter().any(|n| {
        let n = n.to_ascii_lowercase();
        match n.strip_prefix("*.") {
            Some(suffix) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
            None => n == host,
        }
    })
}

#[derive(Clone, Debug)]
pub struct Report {
    pub host: String,
    pub addr: Option<SocketAddr>,
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    pub handshake_ms: f32,
    pub chain: Vec<CertInfo>,
    /// Ok = chain trusted by the OS store and valid for the name.
    pub trust: Result<(), String>,
    pub name_ok: bool,
    /// (label, Some(supported) / None = not tested)
    pub versions: Vec<(&'static str, Option<bool>)>,
}

/// "example.com", "example.com:8443", "10.0.0.5:443", "[::1]:443".
pub fn parse_target(t: &str) -> Result<(String, u16), String> {
    let t = t
        .trim()
        .trim_start_matches("https://")
        .trim_end_matches('/');
    if let Ok(a) = t.parse::<SocketAddr>() {
        return Ok((a.ip().to_string(), a.port()));
    }
    match t.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => Ok((
            h.to_string(),
            p.parse().map_err(|_| format!("bad port '{p}'"))?,
        )),
        _ => Ok((t.trim_matches(['[', ']']).to_string(), 443)),
    }
}

fn io_err(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => "timeout".into(),
        std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
        std::io::ErrorKind::ConnectionReset => "connection reset by the server".into(),
        _ => e.to_string(),
    }
}

/// A definite "no" from the server (alert / incompatible), not a network error.
const REFUSED: &str = "handshake refused (version / cipher not supported)";

/// TCP connection to the first of `host`'s addresses that answers (a name
/// such as "localhost" often has an IPv6 address nothing listens on).
pub fn connect(host: &str, port: u16, wait: Duration) -> Result<(TcpStream, SocketAddr), String> {
    let all: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect();
    if all.is_empty() {
        return Err(format!("{host}: no address"));
    }
    // At most two per family, in the resolver's order.
    let (mut v4, mut v6) = (0, 0);
    let addrs: Vec<SocketAddr> = all
        .into_iter()
        .filter(|a| {
            let n = if a.is_ipv4() { &mut v4 } else { &mut v6 };
            *n += 1;
            *n <= 2
        })
        .collect();
    connect_first(&addrs, wait)
}

fn connect_first(addrs: &[SocketAddr], wait: Duration) -> Result<(TcpStream, SocketAddr), String> {
    let mut errors = Vec::new();
    for addr in addrs {
        match TcpStream::connect_timeout(addr, wait) {
            Ok(s) => {
                s.set_read_timeout(Some(wait)).ok();
                s.set_write_timeout(Some(wait)).ok();
                return Ok((s, *addr));
            }
            Err(e) => errors.push(format!("{addr}: {}", io_err(&e))),
        }
    }
    Err(errors.join("; "))
}

fn handshake(
    host: &str,
    port: u16,
    versions: &[&'static rustls::SupportedProtocolVersion],
    wait: Duration,
    mode: StartTls,
) -> Result<(ClientConnection, Arc<Recorder>, SocketAddr, f32), String> {
    let recorder = Arc::new(Recorder {
        inner: WebPkiServerVerifier::builder_with_provider(roots(), provider())
            .build()
            .map_err(|e| e.to_string())?,
        chain: Mutex::new(Vec::new()),
        verdict: Mutex::new(None),
    });
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let name =
        ServerName::try_from(host.to_string()).map_err(|e| format!("bad server name: {e}"))?;
    let mut conn = ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
    let (mut sock, addr) = connect(host, port, wait)?;
    starttls(&mut sock, mode)?;
    let t = Instant::now();
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| {
            let m = e.to_string();
            if m.contains("peer is incompatible")
                || m.contains("HandshakeFailure")
                || m.contains("ProtocolVersion")
                || m.contains("received fatal alert")
            {
                REFUSED.to_string()
            } else {
                io_err(&e)
            }
        })?;
    }
    Ok((conn, recorder, addr, t.elapsed().as_secs_f32() * 1000.0))
}

/// What a legacy (TLS 1.0 / 1.1) handshake revealed.
pub struct Legacy {
    pub cipher: u16,
    pub chain: Vec<Vec<u8>>,
}

/// Raw ClientHello for an old protocol version. Ok(Some) = the server
/// agreed (with its certificate chain, sent in clear text before TLS 1.3),
/// Ok(None) = refused, Err = network problem (inconclusive).
pub fn legacy_probe(
    host: &str,
    port: u16,
    minor: u8,
    wait: Duration,
) -> Result<Option<Legacy>, String> {
    let (mut s, _) = connect(host, port, wait)?;
    let mut body = vec![3, minor];
    body.extend_from_slice(&[0x42; 32]); // random
    body.push(0); // session id
    let suites: [u16; 8] = [
        0xc013, 0xc014, 0xc009, 0xc00a, 0x002f, 0x0035, 0x000a, 0x00ff,
    ];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for c in suites {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // null compression
    let mut ext = Vec::new();
    if host.parse::<std::net::IpAddr>().is_err() {
        let h = host.as_bytes();
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&((h.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((h.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
        ext.extend_from_slice(h);
    }
    ext.extend_from_slice(&[0, 10, 0, 6, 0, 4, 0, 23, 0, 24]); // groups P-256, P-384
    ext.extend_from_slice(&[0, 11, 0, 2, 1, 0]); // point formats
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    s.write_all(&rec).map_err(|e| io_err(&e))?;

    // Collect handshake bytes until ServerHelloDone.
    let mut hsbuf: Vec<u8> = Vec::new();
    let mut legacy: Option<Legacy> = None;
    loop {
        let mut hdr = [0u8; 5];
        match s.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if legacy.is_some() || e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(legacy);
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Ok(None),
            Err(e) => return Err(io_err(&e)),
        }
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut rbody = vec![0u8; len];
        s.read_exact(&mut rbody).map_err(|e| io_err(&e))?;
        if hdr[0] == 0x15 {
            return Ok(legacy); // alert
        }
        if hdr[0] != 0x16 {
            return Ok(legacy);
        }
        hsbuf.extend(rbody);
        while hsbuf.len() >= 4 {
            let mlen = u32::from_be_bytes([0, hsbuf[1], hsbuf[2], hsbuf[3]]) as usize;
            if hsbuf.len() < 4 + mlen {
                break;
            }
            let msg: Vec<u8> = hsbuf.drain(..4 + mlen).collect();
            let m = &msg[4..];
            match msg[0] {
                2 => {
                    if m.len() < 38 || m[0] != 3 || m[1] != minor {
                        return Ok(None);
                    }
                    let sid = m[34] as usize;
                    let cipher = u16::from_be_bytes([
                        *m.get(35 + sid).unwrap_or(&0),
                        *m.get(36 + sid).unwrap_or(&0),
                    ]);
                    legacy = Some(Legacy {
                        cipher,
                        chain: Vec::new(),
                    });
                }
                11 => {
                    if let Some(l) = legacy.as_mut() {
                        let mut i = 3;
                        while i + 3 <= m.len() {
                            let n = u32::from_be_bytes([0, m[i], m[i + 1], m[i + 2]]) as usize;
                            if let Some(c) = m.get(i + 3..i + 3 + n) {
                                l.chain.push(c.to_vec());
                            }
                            i += 3 + n;
                        }
                    }
                }
                14 => return Ok(legacy),
                _ => {}
            }
        }
        if hsbuf.len() > 256 * 1024 {
            return Ok(legacy);
        }
    }
}

fn verify_chain(host: &str, chain: &[Vec<u8>]) -> Result<(), String> {
    let v = WebPkiServerVerifier::builder_with_provider(roots(), provider())
        .build()
        .map_err(|e| e.to_string())?;
    let certs: Vec<CertificateDer<'static>> = chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    let (ee, rest) = certs.split_first().ok_or("no certificate presented")?;
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    v.verify_server_cert(ee, rest, &name, &[], UnixTime::now())
        .map(|_| ())
        .map_err(|e| describe_error(&e))
}

fn legacy_cipher_name(c: u16) -> String {
    match c {
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".into(),
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".into(),
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".into(),
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".into(),
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA (weak)".into(),
        c => format!("0x{c:04x}"),
    }
}

pub fn scan(target: &str, wait: Duration) -> Result<Report, String> {
    let (host, port) = parse_target(target)?;
    let mode = StartTls::for_port(port);
    let mut r = Report {
        host: host.clone(),
        addr: None,
        version: String::new(),
        cipher: String::new(),
        alpn: None,
        handshake_ms: 0.0,
        chain: Vec::new(),
        trust: Ok(()),
        name_ok: false,
        versions: Vec::new(),
    };
    // Support of one version: Some(true/false), None when inconclusive.
    let classify = |res: Result<(), String>| match res {
        Ok(()) => Some(true),
        Err(e) if e == REFUSED => Some(false),
        Err(_) => None,
    };
    let modern = |v: &'static rustls::SupportedProtocolVersion| {
        let mut out = classify(handshake(&host, port, &[v], wait, mode).map(|_| ()));
        if out.is_none() {
            out = classify(handshake(&host, port, &[v], wait, mode).map(|_| ())); // one retry
        }
        out
    };
    let legacy = |minor: u8| -> (Option<bool>, Option<Legacy>) {
        if mode != StartTls::None {
            return (None, None);
        }
        match legacy_probe(&host, port, minor, wait) {
            Ok(Some(l)) => (Some(true), Some(l)),
            Ok(None) => (Some(false), None),
            Err(_) => (None, None),
        }
    };

    let first = match handshake(&host, port, rustls::ALL_VERSIONS, wait, mode) {
        Err(e) if e.contains("timeout") => handshake(&host, port, rustls::ALL_VERSIONS, wait, mode),
        r => r,
    };
    match first {
        Ok((conn, rec, addr, ms)) => {
            r.addr = Some(addr);
            r.handshake_ms = ms;
            let negotiated = conn.protocol_version();
            r.version = match negotiated {
                Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".into(),
                Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".into(),
                Some(v) => format!("{v:?}"),
                None => String::new(),
            };
            r.cipher = conn
                .negotiated_cipher_suite()
                .map(|c| format!("{:?}", c.suite()))
                .unwrap_or_default();
            r.alpn = conn
                .alpn_protocol()
                .map(|a| String::from_utf8_lossy(a).into_owned());
            let chain = rec.chain.lock().unwrap().clone();
            r.chain = chain.iter().filter_map(|c| parse_cert(c).ok()).collect();
            r.trust = rec
                .verdict
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(Err("no certificate presented".into()));
            let v13 = if negotiated == Some(rustls::ProtocolVersion::TLSv1_3) {
                Some(true)
            } else {
                modern(&rustls::version::TLS13)
            };
            let v12 = if negotiated == Some(rustls::ProtocolVersion::TLSv1_2) {
                Some(true)
            } else {
                modern(&rustls::version::TLS12)
            };
            r.versions.push(("TLS 1.3", v13));
            r.versions.push(("TLS 1.2", v12));
            r.versions.push(("TLS 1.1", legacy(2).0));
            r.versions.push(("TLS 1.0", legacy(1).0));
        }
        Err(e) if e == REFUSED => {
            // Only legacy protocols? Inspect them directly.
            let (v11, l11) = legacy(2);
            let (v10, l10) = legacy(1);
            let Some((name, l)) = l11.map(|l| ("TLS 1.1", l)).or(l10.map(|l| ("TLS 1.0", l)))
            else {
                return Err(e);
            };
            r.version = format!("{name} (legacy only)");
            r.cipher = legacy_cipher_name(l.cipher);
            r.chain = l.chain.iter().filter_map(|c| parse_cert(c).ok()).collect();
            r.trust = verify_chain(&host, &l.chain);
            r.versions = vec![
                ("TLS 1.3", Some(false)),
                ("TLS 1.2", Some(false)),
                ("TLS 1.1", v11),
                ("TLS 1.0", v10),
            ];
        }
        Err(e) => return Err(e),
    }
    r.name_ok = r
        .chain
        .first()
        .is_some_and(|c| name_matches(&host, &c.sans));
    Ok(r)
}

/// Handshake to `ip:port` with SNI `sni`, accepting any certificate.
/// Returns the stream and "TLS 1.3 <cipher>".
pub fn connect_insecure(
    sni: &str,
    ip: std::net::IpAddr,
    port: u16,
    wait: Duration,
) -> Result<(StreamOwned<ClientConnection, TcpStream>, String), String> {
    let recorder = Arc::new(Recorder {
        inner: WebPkiServerVerifier::builder_with_provider(roots(), provider())
            .build()
            .map_err(|e| e.to_string())?,
        chain: Mutex::new(Vec::new()),
        verdict: Mutex::new(None),
    });
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder)
        .with_no_client_auth();
    let name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
    let mut conn = ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
    let addr = SocketAddr::new(ip, port);
    let mut sock = TcpStream::connect_timeout(&addr, wait).map_err(|e| io_err(&e))?;
    sock.set_read_timeout(Some(wait)).ok();
    sock.set_write_timeout(Some(wait)).ok();
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| io_err(&e))?;
    }
    let v = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        _ => "TLS",
    };
    let c = conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_default();
    Ok((StreamOwned::new(conn, sock), format!("{v} {c}")))
}

/// A verifying TLS stream (for the HTTPS throughput test).
pub fn connect_tls(
    host: &str,
    port: u16,
    wait: Duration,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(client_config(), name).map_err(|e| e.to_string())?;
    let (sock, _) = connect(host, port, wait)?;
    Ok(StreamOwned::new(conn, sock))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_to_the_next_address() {
        // A closed port first, then a listener: the second must be used.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = closed.local_addr().unwrap();
        drop(closed);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let live = l.local_addr().unwrap();
        let wait = Duration::from_secs(5);
        let (_s, used) = connect_first(&[dead, live], wait).unwrap();
        assert_eq!(used, live);
        let e = connect_first(&[dead], wait).unwrap_err();
        assert!(e.contains(&dead.to_string()), "{e}");
    }

    #[test]
    fn names_and_targets() {
        let names = vec!["*.example.com".to_string(), "example.com".to_string()];
        assert!(name_matches("www.example.com", &names));
        assert!(name_matches("Example.COM.", &names));
        assert!(!name_matches("a.b.example.com", &names));
        assert!(!name_matches("example.org", &names));
        assert_eq!(
            parse_target("example.com").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_target("https://example.com:8443/").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(parse_target("[::1]:993").unwrap(), ("::1".into(), 993));
        assert_eq!(StartTls::for_port(587), StartTls::Smtp);
        assert_eq!(date(0), "1970-01-01");
    }

    #[test]
    fn rejects_garbage_certificates() {
        assert!(parse_cert(b"not a cert").is_err());
    }
}
