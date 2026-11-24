//! OPC UA security (Part 6): security policies, P_SHA key derivation,
//! asymmetric (OPN) and symmetric (MSG/CLO) message security with padding,
//! RSA signatures and encryption, the self-signed client application
//! instance certificate, PEM/DER files and the server trust store.
//!
//! The seal/open functions are role-neutral so the in-process test server
//! can use them too.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::sha2::{Digest, Sha256};
use rsa::traits::PublicKeyParts;
use rsa::{PrivateKey, PublicKey};
use sha1::Sha1;

use crate::opcua::{R, W};

pub type Res<T> = Result<T, String>;

// ---------------------------------------------------------------- policies

const POLICY_BASE: &str = "http://opcfoundation.org/UA/SecurityPolicy#";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Policy {
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
    Aes128Sha256RsaOaep,
    Aes256Sha256RsaPss,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsymEnc {
    Pkcs1,
    OaepSha1,
    OaepSha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsymSig {
    Sha1,
    Sha256,
    PssSha256,
}

impl Policy {
    pub const ALL: [Policy; 6] = [
        Policy::None,
        Policy::Basic128Rsa15,
        Policy::Basic256,
        Policy::Basic256Sha256,
        Policy::Aes128Sha256RsaOaep,
        Policy::Aes256Sha256RsaPss,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Policy::None => "None",
            Policy::Basic128Rsa15 => "Basic128Rsa15",
            Policy::Basic256 => "Basic256",
            Policy::Basic256Sha256 => "Basic256Sha256",
            Policy::Aes128Sha256RsaOaep => "Aes128_Sha256_RsaOaep",
            Policy::Aes256Sha256RsaPss => "Aes256_Sha256_RsaPss",
        }
    }

    pub fn uri(self) -> String {
        format!("{POLICY_BASE}{}", self.name())
    }

    pub fn from_uri(uri: &str) -> Option<Policy> {
        Policy::ALL.into_iter().find(|p| p.uri() == uri)
    }

    /// Case-insensitive name, URI or short form (none, basic256sha256,
    /// aes128, aes256, basic256, basic128rsa15).
    pub fn parse(s: &str) -> Option<Policy> {
        if let Some(p) = Policy::from_uri(s) {
            return Some(p);
        }
        let k: String = s
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        match k.as_str() {
            "none" => Some(Policy::None),
            "basic128rsa15" | "basic128" => Some(Policy::Basic128Rsa15),
            "basic256" => Some(Policy::Basic256),
            "basic256sha256" => Some(Policy::Basic256Sha256),
            "aes128sha256rsaoaep" | "aes128" => Some(Policy::Aes128Sha256RsaOaep),
            "aes256sha256rsapss" | "aes256" => Some(Policy::Aes256Sha256RsaPss),
            _ => None,
        }
    }

    /// SHA-1 based policies, deprecated since OPC UA 1.04.
    pub fn deprecated(self) -> bool {
        matches!(self, Policy::Basic128Rsa15 | Policy::Basic256)
    }

    fn sha1(self) -> bool {
        self.deprecated()
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Policy::None => 0,
            Policy::Basic128Rsa15 => 16,
            _ => 32,
        }
    }

    fn sig_key_len(self) -> usize {
        match self {
            Policy::None => 0,
            Policy::Basic128Rsa15 => 16,
            Policy::Basic256 => 24,
            _ => 32,
        }
    }

    fn enc_key_len(self) -> usize {
        match self {
            Policy::None => 0,
            Policy::Basic128Rsa15 | Policy::Aes128Sha256RsaOaep => 16,
            _ => 32,
        }
    }

    /// HMAC length of symmetric signatures.
    pub fn sym_sig_len(self) -> usize {
        match self {
            Policy::None => 0,
            p if p.sha1() => 20,
            _ => 32,
        }
    }

    fn asym_enc(self) -> AsymEnc {
        match self {
            Policy::Basic128Rsa15 => AsymEnc::Pkcs1,
            Policy::Aes256Sha256RsaPss => AsymEnc::OaepSha256,
            _ => AsymEnc::OaepSha1,
        }
    }

    fn asym_sig(self) -> AsymSig {
        match self {
            Policy::Basic128Rsa15 | Policy::Basic256 => AsymSig::Sha1,
            Policy::Aes256Sha256RsaPss => AsymSig::PssSha256,
            _ => AsymSig::Sha256,
        }
    }

    /// Bytes RSA encryption padding takes from each block.
    fn asym_overhead(self) -> usize {
        match self.asym_enc() {
            AsymEnc::Pkcs1 => 11,
            AsymEnc::OaepSha1 => 42,
            AsymEnc::OaepSha256 => 66,
        }
    }

    /// SignatureData.algorithm for CreateSession / ActivateSession.
    pub fn sig_algorithm_uri(self) -> &'static str {
        match self.asym_sig() {
            AsymSig::Sha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            AsymSig::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            AsymSig::PssSha256 => "http://opcfoundation.org/UA/security/rsa-pss-sha2-256",
        }
    }

    /// UserNameIdentityToken.encryptionAlgorithm.
    pub fn enc_algorithm_uri(self) -> &'static str {
        match self.asym_enc() {
            AsymEnc::Pkcs1 => "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
            AsymEnc::OaepSha1 => "http://www.w3.org/2001/04/xmlenc#rsa-oaep",
            AsymEnc::OaepSha256 => "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256",
        }
    }

    /// Allowed RSA key sizes (bits) for this policy.
    pub fn key_bits(self) -> (usize, usize) {
        match self {
            Policy::None => (0, usize::MAX),
            Policy::Basic128Rsa15 | Policy::Basic256 => (1024, 2048),
            _ => (2048, 4096),
        }
    }
}

// ---------------------------------------------------------------- primitives

/// Cryptographically secure random bytes from the OS.
pub fn random(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    if getrandom::fill(&mut v).is_err() {
        v = crate::websocket::random_bytes(n);
    }
    v
}

/// OS random generator for RSA key generation.
struct OsRng;

impl rsa::rand_core::TryRng for OsRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let b = random(4);
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let b = random(8);
        Ok(u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&random(dst.len()));
        Ok(())
    }
}

impl rsa::rand_core::TryCryptoRng for OsRng {}

fn hmac(sha1: bool, key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    if sha1 {
        let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("hmac key");
        for d in data {
            m.update(d);
        }
        m.finalize().into_bytes().to_vec()
    } else {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac key");
        for d in data {
            m.update(d);
        }
        m.finalize().into_bytes().to_vec()
    }
}

/// P_SHA1 / P_SHA256 (the TLS 1.0/1.2 P_hash function).
pub fn p_sha(sha1: bool, secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut a = hmac(sha1, secret, &[seed]);
    while out.len() < len {
        out.extend_from_slice(&hmac(sha1, secret, &[&a, seed]));
        a = hmac(sha1, secret, &[&a]);
    }
    out.truncate(len);
    out
}

/// One direction's symmetric keys.
#[derive(Clone, Debug, PartialEq)]
pub struct Keys {
    pub sign: Vec<u8>,
    pub enc: Vec<u8>,
    pub iv: Vec<u8>,
}

/// Derive keys: the sender's keys use the *other* side's nonce as the
/// secret and its own nonce as the seed (client keys = P(serverNonce,
/// clientNonce)).
pub fn derive(policy: Policy, secret: &[u8], seed: &[u8]) -> Keys {
    let (s, e) = (policy.sig_key_len(), policy.enc_key_len());
    let b = p_sha(policy.sha1(), secret, seed, s + e + 16);
    Keys {
        sign: b[..s].to_vec(),
        enc: b[s..s + e].to_vec(),
        iv: b[s + e..].to_vec(),
    }
}

fn aes_cbc(encrypt: bool, key: &[u8], iv: &[u8], data: &mut [u8]) -> Res<()> {
    if !data.len().is_multiple_of(16) || iv.len() != 16 {
        return Err("AES-CBC: data is not a whole number of blocks".into());
    }
    macro_rules! run {
        ($c:ty) => {{
            let c = <$c>::new_from_slice(key).map_err(|_| "AES key length")?;
            let mut prev: [u8; 16] = iv.try_into().unwrap();
            for blk in data.chunks_mut(16) {
                if encrypt {
                    for (b, p) in blk.iter_mut().zip(prev) {
                        *b ^= p;
                    }
                    let mut a = aes::Block::try_from(&*blk).map_err(|_| "block")?;
                    c.encrypt_block(&mut a);
                    blk.copy_from_slice(&a);
                    prev.copy_from_slice(blk);
                } else {
                    let ct: [u8; 16] = (&*blk).try_into().unwrap();
                    let mut a = aes::Block::try_from(&*blk).map_err(|_| "block")?;
                    c.decrypt_block(&mut a);
                    for ((b, x), p) in blk.iter_mut().zip(a.iter()).zip(prev) {
                        *b = x ^ p;
                    }
                    prev = ct;
                }
            }
        }};
    }
    match key.len() {
        16 => run!(aes::Aes128),
        32 => run!(aes::Aes256),
        n => return Err(format!("AES key of {n} bytes")),
    }
    Ok(())
}

pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

/// Certificate thumbprint (SHA-1 of the DER), as OPC UA uses it.
pub fn thumbprint(der: &[u8]) -> [u8; 20] {
    sha1_digest(der)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// "AB:CD:…" for display.
pub fn hex_colon(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// RSA public key from a DER certificate.
pub fn cert_public_key(der: &[u8]) -> Res<PublicKey> {
    use x509_parser::prelude::*;
    let (_, c) = parse_x509_certificate(der).map_err(|e| format!("bad server certificate: {e}"))?;
    PublicKey::from_public_key_der(c.tbs_certificate.subject_pki.raw)
        .map_err(|e| format!("certificate key is not RSA: {e}"))
}

/// RSA-encrypt any length (split into plain-text blocks).
pub fn rsa_encrypt(policy: Policy, key: &PublicKey, data: &[u8]) -> Res<Vec<u8>> {
    let block = key.size() - policy.asym_overhead();
    let mut out = Vec::new();
    for part in data.chunks(block) {
        let c = match policy.asym_enc() {
            AsymEnc::Pkcs1 => key.pkcs1v15_encrypt(part),
            AsymEnc::OaepSha1 => key.oaep_encrypt::<Sha1>(part),
            AsymEnc::OaepSha256 => key.oaep_encrypt::<Sha256>(part),
        }
        .map_err(|e| format!("RSA encrypt: {e}"))?;
        out.extend_from_slice(&c);
    }
    Ok(out)
}

pub fn rsa_decrypt(policy: Policy, key: &PrivateKey, data: &[u8]) -> Res<Vec<u8>> {
    let n = key.size();
    if data.is_empty() || !data.len().is_multiple_of(n) {
        return Err(format!(
            "encrypted part ({} bytes) is not a multiple of our key size ({n}) — wrong certificate?",
            data.len()
        ));
    }
    let mut out = Vec::new();
    for part in data.chunks(n) {
        let p = match policy.asym_enc() {
            AsymEnc::Pkcs1 => key.pkcs1v15_decrypt(part),
            AsymEnc::OaepSha1 => key.oaep_decrypt::<Sha1>(part),
            AsymEnc::OaepSha256 => key.oaep_decrypt::<Sha256>(part),
        }
        .map_err(|_| "RSA decrypt failed (message not encrypted for our certificate)")?;
        out.extend_from_slice(&p);
    }
    Ok(out)
}

pub fn rsa_sign(policy: Policy, key: &PrivateKey, data: &[u8]) -> Res<Vec<u8>> {
    match policy.asym_sig() {
        AsymSig::Sha1 => key.pkcs1v15_sign::<Sha1>(data),
        AsymSig::Sha256 => key.pkcs1v15_sign::<Sha256>(data),
        AsymSig::PssSha256 => key.pss_sign::<Sha256>(data),
    }
    .map_err(|e| format!("RSA sign: {e}"))
}

pub fn rsa_verify(policy: Policy, key: &PublicKey, data: &[u8], sig: &[u8]) -> Res<()> {
    match policy.asym_sig() {
        AsymSig::Sha1 => key.pkcs1v15_verify::<Sha1>(data, sig),
        AsymSig::Sha256 => key.pkcs1v15_verify::<Sha256>(data, sig),
        AsymSig::PssSha256 => key.pss_verify::<Sha256>(data, sig),
    }
    .map_err(|_| "signature check failed".to_string())
}

// ---------------------------------------------------------------- chunks

fn header(kind: &[u8; 3], chunk: u8, size: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(size);
    h.extend_from_slice(kind);
    h.push(chunk);
    h.extend_from_slice(&(size as u32).to_le_bytes());
    h
}

/// Padding bytes for `len` bytes of data to fill whole `block`s.
fn padding(len: usize, block: usize) -> usize {
    (block - len % block) % block
}

/// Asymmetric security header of an OPN chunk.
#[derive(Clone, Debug, Default)]
pub struct AsymHeader {
    pub channel_id: u32,
    pub policy_uri: String,
    pub sender_cert: Vec<u8>,
    pub receiver_thumbprint: Vec<u8>,
}

/// Parse the asymmetric header; returns it and the offset of the payload.
pub fn asym_header(frame: &[u8]) -> Res<(AsymHeader, usize)> {
    let mut r = R::new(frame.get(8..).ok_or("short chunk")?);
    let channel_id = r.u32()?;
    let policy_uri = r.str()?;
    let sender_cert = r.bytes()?.unwrap_or_default();
    let receiver_thumbprint = r.bytes()?.unwrap_or_default();
    Ok((
        AsymHeader {
            channel_id,
            policy_uri,
            sender_cert,
            receiver_thumbprint,
        },
        8 + r.pos,
    ))
}

/// One side of an asymmetric exchange.
pub struct Local<'a> {
    pub cert: &'a [u8],
    pub key: &'a PrivateKey,
}

/// Build an OPN chunk; `payload` = sequence header + body. With a security
/// policy other than None the chunk is signed and encrypted (OPN is always
/// encrypted, also in Sign mode).
pub fn seal_asym(
    policy: Policy,
    chunk: u8,
    channel_id: u32,
    local: Option<&Local>,
    remote_cert: &[u8],
    remote_key: Option<&PublicKey>,
    payload: &[u8],
) -> Res<Vec<u8>> {
    let mut sec = W::default();
    sec.u32(channel_id).string(Some(&policy.uri()));
    let (Some(local), Some(remote), false) = (local, remote_key, policy == Policy::None) else {
        sec.bytes(None).bytes(None);
        let size = 8 + sec.0.len() + payload.len();
        let mut out = header(b"OPN", chunk, size);
        out.extend_from_slice(&sec.0);
        out.extend_from_slice(payload);
        return Ok(out);
    };
    sec.bytes(Some(local.cert))
        .bytes(Some(&thumbprint(remote_cert)));
    let sig_len = local.key.size();
    let enc_size = remote.size();
    let plain_block = enc_size - policy.asym_overhead();
    let extra = enc_size > 256;
    let base = payload.len() + 1 + extra as usize + sig_len;
    let pad = padding(base, plain_block);
    let plain_len = base + pad;
    let cipher_len = plain_len / plain_block * enc_size;
    let hdr_len = 8 + sec.0.len();
    let mut m = header(b"OPN", chunk, hdr_len + cipher_len);
    m.extend_from_slice(&sec.0);
    m.extend_from_slice(payload);
    m.extend(std::iter::repeat_n((pad & 0xff) as u8, pad + 1));
    if extra {
        m.push((pad >> 8) as u8);
    }
    let sig = rsa_sign(policy, local.key, &m)?;
    m.extend_from_slice(&sig);
    let enc = rsa_encrypt(policy, remote, &m[hdr_len..])?;
    if enc.len() != cipher_len {
        return Err("internal: OPN size mismatch".into());
    }
    m.truncate(hdr_len);
    m.extend_from_slice(&enc);
    Ok(m)
}

/// Decrypt and verify an OPN chunk (full frame incl. the 8-byte header).
/// Returns the header and the payload (sequence header + body).
pub fn open_asym(frame: &[u8], local: Option<&Local>) -> Res<(AsymHeader, Vec<u8>)> {
    let (h, pos) = asym_header(frame)?;
    let policy = Policy::from_uri(&h.policy_uri)
        .ok_or_else(|| format!("unknown security policy {}", h.policy_uri))?;
    if policy == Policy::None {
        return Ok((h, frame[pos..].to_vec()));
    }
    let local = local.ok_or("secured OPN on an unsecured channel")?;
    if h.receiver_thumbprint != thumbprint(local.cert) {
        return Err("the server encrypted for a different client certificate".into());
    }
    let sender = cert_public_key(&h.sender_cert)?;
    let plain = rsa_decrypt(policy, local.key, &frame[pos..])?;
    let sig_len = sender.size();
    if plain.len() < sig_len + 9 {
        return Err("OPN response too short".into());
    }
    let mut signed = frame[..pos].to_vec();
    signed.extend_from_slice(&plain[..plain.len() - sig_len]);
    rsa_verify(policy, &sender, &signed, &plain[plain.len() - sig_len..])
        .map_err(|_| "the server's OPN signature does not verify".to_string())?;
    let end = plain.len() - sig_len;
    let extra = local.key.size() > 256;
    let pad = if extra {
        ((plain[end - 1] as usize) << 8 | plain[end - 2] as usize) + 2
    } else {
        plain[end - 1] as usize + 1
    };
    if pad > end - 8 {
        return Err("bad padding in the OPN response".into());
    }
    Ok((h, plain[..end - pad].to_vec()))
}

/// Largest body that fits in one symmetric chunk of `buf` bytes.
pub fn max_sym_body(policy: Policy, encrypt: bool, buf: usize) -> usize {
    let sig = policy.sym_sig_len();
    if policy == Policy::None {
        return buf - 24;
    }
    if encrypt {
        (buf - 16) / 16 * 16 - 8 - sig - 1
    } else {
        buf - 24 - sig
    }
}

/// Build a MSG/CLO chunk; `payload` = sequence header + body.
#[allow(clippy::too_many_arguments)]
pub fn seal_sym(
    policy: Policy,
    encrypt: bool,
    kind: &[u8; 3],
    chunk: u8,
    channel_id: u32,
    token_id: u32,
    keys: Option<&Keys>,
    payload: &[u8],
) -> Res<Vec<u8>> {
    let keys = match keys {
        Some(k) if policy != Policy::None => k,
        _ => {
            let mut m = header(kind, chunk, 16 + payload.len());
            m.extend_from_slice(&channel_id.to_le_bytes());
            m.extend_from_slice(&token_id.to_le_bytes());
            m.extend_from_slice(payload);
            return Ok(m);
        }
    };
    let sig = policy.sym_sig_len();
    let pad = if encrypt {
        padding(payload.len() + 1 + sig, 16)
    } else {
        0
    };
    let size = 16 + payload.len() + if encrypt { pad + 1 } else { 0 } + sig;
    let mut m = header(kind, chunk, size);
    m.extend_from_slice(&channel_id.to_le_bytes());
    m.extend_from_slice(&token_id.to_le_bytes());
    m.extend_from_slice(payload);
    if encrypt {
        m.extend(std::iter::repeat_n(pad as u8, pad + 1));
    }
    let mac = hmac(policy.sha1(), &keys.sign, &[&m]);
    m.extend_from_slice(&mac);
    if encrypt {
        aes_cbc(true, &keys.enc, &keys.iv, &mut m[16..])?;
    }
    Ok(m)
}

/// Verify (and decrypt) a MSG/CLO chunk; returns sequence header + body.
pub fn open_sym(
    policy: Policy,
    encrypted: bool,
    frame: &[u8],
    keys: Option<&Keys>,
) -> Res<Vec<u8>> {
    if frame.len() < 24 {
        return Err("short chunk".into());
    }
    let keys = match keys {
        Some(k) if policy != Policy::None => k,
        _ => return Ok(frame[16..].to_vec()),
    };
    let mut m = frame.to_vec();
    if encrypted {
        aes_cbc(false, &keys.enc, &keys.iv, &mut m[16..]).map_err(|e| format!("decrypt: {e}"))?;
    }
    let sig = policy.sym_sig_len();
    if m.len() < 16 + 8 + sig {
        return Err("short chunk".into());
    }
    let end = m.len() - sig;
    let mac = hmac(policy.sha1(), &keys.sign, &[&m[..end]]);
    if !ct_eq(&mac, &m[end..]) {
        return Err("BadSecurityChecksFailed: message signature does not verify".into());
    }
    let mut stop = end;
    if encrypted {
        let pad = m[end - 1] as usize + 1;
        if pad > end - 24 {
            return Err("bad padding".into());
        }
        stop -= pad;
    }
    Ok(m[16..stop].to_vec())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------- DER

fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let b = (n as u32).to_be_bytes();
        let skip = b.iter().take_while(|x| **x == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&b[skip..]);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(s: &str) -> Vec<u8> {
    let arcs: Vec<u64> = s.split('.').map(|a| a.parse().unwrap_or(0)).collect();
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut tmp = vec![(a & 0x7f) as u8];
        let mut v = a >> 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        body.extend_from_slice(&tmp);
    }
    tlv(0x06, &body)
}

fn uint(b: &[u8]) -> Vec<u8> {
    let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    let mut c = Vec::new();
    if b.first().is_none_or(|x| x & 0x80 != 0) {
        c.push(0);
    }
    c.extend_from_slice(&b);
    tlv(0x02, &c)
}

fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        (rem % 3600 / 60) as u32,
        (rem % 60) as u32,
    )
}

fn der_time(secs: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil(secs);
    if (1950..2050).contains(&y) {
        tlv(
            0x17,
            format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100).as_bytes(),
        )
    } else {
        tlv(
            0x18,
            format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes(),
        )
    }
}

fn name(cn: &str, org: &str, dc: &str) -> Vec<u8> {
    let rdn = |o: &str, v: Vec<u8>| tlv(0x31, &seq(&[&oid(o), &v]));
    seq(&[
        &rdn("2.5.4.3", tlv(0x0c, cn.as_bytes())),
        &rdn("2.5.4.10", tlv(0x0c, org.as_bytes())),
        &rdn("0.9.2342.19200300.100.1.25", tlv(0x16, dc.as_bytes())),
    ])
}

fn ext(id: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        seq(&[&oid(id), &tlv(0x01, &[0xff]), &tlv(0x04, value)])
    } else {
        seq(&[&oid(id), &tlv(0x04, value)])
    }
}

/// Self-signed RSA-2048 / SHA-256 application instance certificate
/// (Part 6 §6.2.2): SAN URI = application URI, DNS = host; key usage
/// digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
/// keyCertSign; EKU serverAuth + clientAuth; basicConstraints cA=false.
pub fn make_cert(key: &PrivateKey, app_uri: &str, host: &str, years: i64) -> Res<Vec<u8>> {
    let spki = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| e.to_string())?;
    let rsa_pub = key
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|e| e.to_string())?;
    let ski = sha1_digest(rsa_pub.as_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut serial = random(16);
    serial[0] = (serial[0] & 0x7f) | 0x10;
    let sig_alg = seq(&[&oid("1.2.840.113549.1.1.11"), &[0x05, 0x00]]);
    let subject = name(
        &format!("Network Analyser@{host}"),
        "Network Analyser",
        host,
    );
    let san = seq(&[&tlv(0x86, app_uri.as_bytes()), &tlv(0x82, host.as_bytes())]);
    let exts = seq(&[
        &ext("2.5.29.14", false, &tlv(0x04, &ski)),
        &ext("2.5.29.35", false, &seq(&[&tlv(0x80, &ski)])),
        &ext("2.5.29.19", true, &seq(&[])),
        &ext("2.5.29.15", true, &[0x03, 0x02, 0x02, 0xf4]),
        &ext(
            "2.5.29.37",
            false,
            &seq(&[&oid("1.3.6.1.5.5.7.3.1"), &oid("1.3.6.1.5.5.7.3.2")]),
        ),
        &ext("2.5.29.17", false, &san),
    ]);
    let tbs = seq(&[
        &[0xa0, 0x03, 0x02, 0x01, 0x02],
        &uint(&serial),
        &sig_alg,
        &subject,
        &seq(&[
            &der_time(now - 86_400),
            &der_time(now + years * 365 * 86_400),
        ]),
        &subject,
        spki.as_bytes(),
        &tlv(0xa3, &exts),
    ]);
    let sig = key
        .pkcs1v15_sign::<Sha256>(&tbs)
        .map_err(|e| format!("sign certificate: {e}"))?;
    let mut bits = vec![0u8];
    bits.extend_from_slice(&sig);
    Ok(seq(&[&tbs, &sig_alg, &tlv(0x03, &bits)]))
}

// ---------------------------------------------------------------- PEM

pub fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// First PEM block with one of `labels` → (label, DER).
pub fn pem_decode(text: &str, labels: &[&str]) -> Option<(String, Vec<u8>)> {
    use base64::Engine;
    for label in labels {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        if let Some(a) = text.find(&begin) {
            let rest = &text[a + begin.len()..];
            let b = rest.find(&end)?;
            let body: String = rest[..b]
                .lines()
                .filter(|l| !l.contains(':'))
                .collect::<String>()
                .split_whitespace()
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(body)
                .ok()?;
            return Some((label.to_string(), der));
        }
    }
    None
}

/// Certificate from a .der or .pem file.
pub fn read_cert_file(path: &Path) -> Res<Vec<u8>> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Ok(t) = std::str::from_utf8(&b)
        && t.contains("-----BEGIN")
    {
        return pem_decode(t, &["CERTIFICATE"])
            .map(|(_, d)| d)
            .ok_or_else(|| format!("{}: no CERTIFICATE block", path.display()));
    }
    Ok(b)
}

/// RSA private key from PKCS#8 / PKCS#1 PEM or DER (unencrypted).
pub fn read_key_file(path: &Path) -> Res<PrivateKey> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bad = |e: String| format!("{}: {e}", path.display());
    if let Ok(t) = std::str::from_utf8(&b)
        && t.contains("-----BEGIN")
    {
        if t.contains("ENCRYPTED PRIVATE KEY") || t.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(bad(
                "the key is password-protected; export it without a passphrase".into(),
            ));
        }
        return match pem_decode(t, &["PRIVATE KEY", "RSA PRIVATE KEY"]) {
            Some((l, der)) if l == "PRIVATE KEY" => {
                PrivateKey::from_pkcs8_der(&der).map_err(|e| bad(e.to_string()))
            }
            Some((_, der)) => PrivateKey::from_pkcs1_der(&der).map_err(|e| bad(e.to_string())),
            None => Err(bad("no PRIVATE KEY block".into())),
        };
    }
    PrivateKey::from_pkcs8_der(&b)
        .or_else(|_| PrivateKey::from_pkcs1_der(&b))
        .map_err(|e| bad(format!("not an RSA private key: {e}")))
}

// ---------------------------------------------------------------- identity

/// The client's application instance certificate and key.
#[derive(Clone)]
pub struct ClientIdentity {
    pub cert: Vec<u8>,
    pub key: PrivateKey,
    pub app_uri: String,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

/// What the UI shows about a certificate.
#[derive(Clone, Debug, Default)]
pub struct CertSummary {
    pub subject: String,
    pub app_uri: String,
    pub thumbprint: String,
    pub not_after: String,
    pub days_left: i64,
    pub key_bits: usize,
    pub path: Option<PathBuf>,
}

pub fn summarize(der: &[u8], path: Option<PathBuf>) -> CertSummary {
    let c = crate::tls::parse_cert(der).ok();
    CertSummary {
        subject: c.as_ref().map(|c| c.subject.clone()).unwrap_or_default(),
        app_uri: cert_uris(der).into_iter().next().unwrap_or_default(),
        thumbprint: hex_colon(&thumbprint(der)),
        not_after: c.as_ref().map(|c| c.not_after.clone()).unwrap_or_default(),
        days_left: c.as_ref().map(|c| c.days_left).unwrap_or(0),
        key_bits: c.as_ref().map(|c| c.key_bits).unwrap_or(0),
        path,
    }
}

/// URI subject-alternative names (OPC UA puts the ApplicationUri there).
pub fn cert_uris(der: &[u8]) -> Vec<String> {
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

pub fn default_app_uri() -> String {
    format!("urn:{}:network-analyser", host_name())
}

fn host_name() -> String {
    let h = crate::netconfig::hostname();
    let h = h.trim();
    if h.is_empty() || h == "?" {
        "localhost".into()
    } else {
        h.to_string()
    }
}

pub fn default_dir() -> Option<PathBuf> {
    crate::platform::data_dir().map(|d| d.join("opcua"))
}

const CERT_DER: &str = "client-cert.der";
const CERT_PEM: &str = "client-cert.pem";
const KEY_PEM: &str = "client-key.pem";

impl ClientIdentity {
    pub fn summary(&self) -> CertSummary {
        summarize(&self.cert, self.cert_path.clone())
    }

    /// New RSA key pair and self-signed certificate (not saved).
    pub fn generate(app_uri: &str, host: &str, bits: usize) -> Res<ClientIdentity> {
        let key = PrivateKey::new(&mut OsRng, bits).map_err(|e| format!("RSA key: {e}"))?;
        let cert = make_cert(&key, app_uri, host, 5)?;
        Ok(ClientIdentity {
            cert,
            key,
            app_uri: app_uri.to_string(),
            cert_path: None,
            key_path: None,
        })
    }

    /// User-supplied certificate and key files.
    pub fn load(cert_path: &Path, key_path: &Path) -> Res<ClientIdentity> {
        let cert = read_cert_file(cert_path)?;
        let key = read_key_file(key_path)?;
        let ck = cert_public_key(&cert)?;
        if ck != key.to_public_key() {
            return Err(format!(
                "{} does not belong to {}",
                key_path.display(),
                cert_path.display()
            ));
        }
        let app_uri = cert_uris(&cert).into_iter().next().unwrap_or_default();
        if app_uri.is_empty() {
            return Err(format!(
                "{}: no application URI (SubjectAltName URI) — OPC UA servers reject such certificates",
                cert_path.display()
            ));
        }
        Ok(ClientIdentity {
            cert,
            key,
            app_uri,
            cert_path: Some(cert_path.to_path_buf()),
            key_path: Some(key_path.to_path_buf()),
        })
    }

    /// An X.509 *user* certificate and its key (no application URI needed).
    pub fn load_user(cert_path: &Path, key_path: &Path) -> Res<(Vec<u8>, PrivateKey)> {
        let cert = read_cert_file(cert_path)?;
        let key = read_key_file(key_path)?;
        if cert_public_key(&cert)? != key.to_public_key() {
            return Err(format!(
                "{} does not belong to {}",
                key_path.display(),
                cert_path.display()
            ));
        }
        Ok((cert, key))
    }

    /// The built-in certificate in `dir`, created (and saved) on first use.
    /// Returns the identity and whether it was just created.
    pub fn load_or_create(dir: &Path) -> Res<(ClientIdentity, bool)> {
        let (c, k) = (dir.join(CERT_DER), dir.join(KEY_PEM));
        if c.exists() && k.exists() {
            return ClientIdentity::load(&c, &k).map(|i| (i, false));
        }
        let mut id = ClientIdentity::generate(&default_app_uri(), &host_name(), 2048)?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let pem = id
            .key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| e.to_string())?;
        write_private(&k, pem.as_bytes())?;
        std::fs::write(&c, &id.cert).map_err(|e| format!("{}: {e}", c.display()))?;
        let _ = std::fs::write(dir.join(CERT_PEM), pem_encode("CERTIFICATE", &id.cert));
        id.cert_path = Some(c);
        id.key_path = Some(k);
        Ok((id, true))
    }

    /// The built-in certificate's summary, if it exists (no key generation).
    pub fn peek(dir: &Path) -> Option<CertSummary> {
        let c = dir.join(CERT_DER);
        let der = std::fs::read(&c).ok()?;
        Some(summarize(&der, Some(c)))
    }
}

fn write_private(path: &Path, data: &[u8]) -> Res<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        f.write_all(data)
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).map_err(|e| format!("{}: {e}", path.display()))
    }
}

// ---------------------------------------------------------------- trust store

#[derive(Clone, Debug, Default, PartialEq)]
pub enum Trust {
    Trusted,
    #[default]
    Unknown,
    /// A different certificate was trusted before (its thumbprint).
    Changed(String),
}

/// Key for a server in the trust store: its application URI, or the URL's
/// host:port when the server has none.
pub fn trust_key(app_uri: &str, url: &str) -> String {
    if !app_uri.is_empty() {
        return app_uri.to_string();
    }
    crate::opcua::parse_url(url)
        .map(|(h, p)| format!("{h}:{p}"))
        .unwrap_or_else(|_| url.to_string())
}

pub fn trust_file() -> Option<PathBuf> {
    default_dir().map(|d| d.join("trusted.json"))
}

fn load_trust(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn trust_status_in(path: &Path, key: &str, cert: &[u8]) -> Trust {
    let thumb = hex(&thumbprint(cert));
    match load_trust(path).get(key) {
        Some(t) if *t == thumb => Trust::Trusted,
        Some(t) => Trust::Changed(t.clone()),
        None => Trust::Unknown,
    }
}

pub fn trust_in(path: &Path, key: &str, cert: &[u8]) -> Res<()> {
    let mut m = load_trust(path);
    m.insert(key.to_string(), hex(&thumbprint(cert)));
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let s = serde_json::to_string_pretty(&m).map_err(|e| e.to_string())?;
    std::fs::write(path, s).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn trust_status(key: &str, cert: &[u8]) -> Trust {
    match trust_file() {
        Some(p) => trust_status_in(&p, key, cert),
        None => Trust::Unknown,
    }
}

pub fn trust(key: &str, cert: &[u8]) -> Res<()> {
    let p = trust_file().ok_or("no data directory")?;
    trust_in(&p, key, cert)
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// Two shared 2048-bit identities (key generation is slow in debug).
    pub(crate) fn ids() -> &'static (ClientIdentity, ClientIdentity) {
        static IDS: OnceLock<(ClientIdentity, ClientIdentity)> = OnceLock::new();
        IDS.get_or_init(|| {
            (
                ClientIdentity::generate("urn:test:client", "client.test", 2048).unwrap(),
                ClientIdentity::generate("urn:test:server", "server.test", 2048).unwrap(),
            )
        })
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn policies() {
        for p in Policy::ALL {
            assert_eq!(Policy::from_uri(&p.uri()), Some(p));
            assert_eq!(Policy::parse(p.name()), Some(p));
        }
        assert_eq!(Policy::parse("aes256"), Some(Policy::Aes256Sha256RsaPss));
        assert_eq!(
            Policy::parse("Basic256Sha256"),
            Some(Policy::Basic256Sha256)
        );
        assert!(Policy::Basic256.deprecated() && !Policy::Basic256Sha256.deprecated());
        assert_eq!(Policy::Basic128Rsa15.nonce_len(), 16);
        assert_eq!(Policy::Basic256.sym_sig_len(), 20);
        assert_eq!(Policy::Aes128Sha256RsaOaep.sym_sig_len(), 32);
    }

    // Expected values computed independently with Python's hmac module.
    #[test]
    fn p_sha_vectors() {
        let secret = b"server-nonce-0123456789abcdef0123";
        let seed = b"client-nonce-fedcba9876543210fedc";
        assert_eq!(hex(&p_sha(false, secret, seed, 40)), P_SHA256_40);
        assert_eq!(hex(&p_sha(true, secret, seed, 30)), P_SHA1_30);
        let k = derive(Policy::Basic256Sha256, secret, seed);
        let all = p_sha(false, secret, seed, 80);
        assert_eq!((k.sign.len(), k.enc.len(), k.iv.len()), (32, 32, 16));
        assert_eq!([k.sign, k.enc, k.iv].concat(), all);
        let k = derive(Policy::Aes128Sha256RsaOaep, secret, seed);
        assert_eq!((k.sign.len(), k.enc.len(), k.iv.len()), (32, 16, 16));
        let k = derive(Policy::Basic256, secret, seed);
        assert_eq!((k.sign.len(), k.enc.len(), k.iv.len()), (24, 32, 16));
    }
    const P_SHA256_40: &str =
        "079FFF229AA03B1716CEE9CECC9BF76652E7A83F0903621FEDA53C11856B6CC6046547B69591DA8D";
    const P_SHA1_30: &str = "FD08FDD6BC0EADD99A281DC7823E8DA5BC0A89DE153E5E4EA31F86A83363";

    #[test]
    fn aes_cbc_vector() {
        // NIST SP 800-38A F.2.1 (CBC-AES128.Encrypt), first two blocks.
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let mut d = unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        aes_cbc(true, &key, &iv, &mut d).unwrap();
        assert_eq!(
            hex(&d),
            "7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B2"
        );
        aes_cbc(false, &key, &iv, &mut d).unwrap();
        assert_eq!(
            hex(&d),
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
        );
    }

    #[test]
    fn rsa_roundtrips() {
        let (a, _) = ids();
        let pubk = a.key.to_public_key();
        let data = vec![7u8; 600];
        for p in Policy::ALL.into_iter().skip(1) {
            let c = rsa_encrypt(p, &pubk, &data).unwrap();
            assert_eq!(c.len() % 256, 0, "{p:?}");
            assert_eq!(rsa_decrypt(p, &a.key, &c).unwrap(), data, "{p:?}");
            let s = rsa_sign(p, &a.key, b"msg").unwrap();
            assert_eq!(s.len(), 256);
            rsa_verify(p, &pubk, b"msg", &s).unwrap();
            assert!(rsa_verify(p, &pubk, b"msh", &s).is_err());
        }
    }

    #[test]
    fn generated_certificate_parses() {
        use x509_parser::prelude::*;
        let (a, _) = ids();
        let (_, c) = parse_x509_certificate(&a.cert).unwrap();
        assert_eq!(c.version(), X509Version::V3);
        assert_eq!(cert_uris(&a.cert), vec!["urn:test:client".to_string()]);
        assert_eq!(cert_public_key(&a.cert).unwrap(), a.key.to_public_key());
        let ku = c.key_usage().unwrap().unwrap();
        assert!(ku.critical);
        let k = ku.value;
        assert!(
            k.digital_signature()
                && k.non_repudiation()
                && k.key_encipherment()
                && k.data_encipherment()
                && k.key_cert_sign()
                && !k.crl_sign()
        );
        let eku = c.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && eku.server_auth);
        let bc = c.basic_constraints().unwrap().unwrap();
        assert!(bc.critical && !bc.value.ca);
        assert!(c.validity().is_valid());
        // Self-signed: the signature verifies with its own key.
        a.key
            .to_public_key()
            .pkcs1v15_verify::<Sha256>(c.tbs_certificate.as_ref(), &c.signature_value.data)
            .unwrap();
        let s = summarize(&a.cert, None);
        assert_eq!(s.key_bits, 2048);
        assert!(s.subject.contains("Network Analyser@client.test"));
        assert_eq!(s.thumbprint.len(), 59);
    }

    #[test]
    fn asymmetric_chunk_roundtrip() {
        let (c, s) = ids();
        let cl = Local {
            cert: &c.cert,
            key: &c.key,
        };
        let sl = Local {
            cert: &s.cert,
            key: &s.key,
        };
        let spub = s.key.to_public_key();
        let cpub = c.key.to_public_key();
        for p in Policy::ALL.into_iter().skip(1) {
            for n in [0usize, 1, 100, 189, 190, 191, 500] {
                let payload: Vec<u8> = (0..8 + n).map(|i| i as u8).collect();
                let f = seal_asym(p, b'F', 5, Some(&cl), &s.cert, Some(&spub), &payload).unwrap();
                assert_eq!(
                    u32::from_le_bytes(f[4..8].try_into().unwrap()) as usize,
                    f.len()
                );
                let (h, got) = open_asym(&f, Some(&sl)).unwrap();
                assert_eq!(h.channel_id, 5);
                assert_eq!(h.sender_cert, c.cert);
                assert_eq!(got, payload, "{p:?} {n}");
                // And back.
                let f = seal_asym(p, b'F', 5, Some(&sl), &c.cert, Some(&cpub), &payload).unwrap();
                assert_eq!(open_asym(&f, Some(&cl)).unwrap().1, payload);
            }
            // Tampering is detected.
            let mut f =
                seal_asym(p, b'F', 5, Some(&cl), &s.cert, Some(&spub), b"12345678").unwrap();
            let last = f.len() - 1;
            f[last] ^= 1;
            assert!(open_asym(&f, Some(&sl)).is_err());
            // Encrypted for someone else.
            let f = seal_asym(p, b'F', 5, Some(&cl), &c.cert, Some(&cpub), b"12345678").unwrap();
            assert!(open_asym(&f, Some(&sl)).is_err());
        }
        // None: plain.
        let f = seal_asym(Policy::None, b'F', 0, None, &[], None, b"abcdefgh").unwrap();
        assert_eq!(open_asym(&f, None).unwrap().1, b"abcdefgh");
    }

    #[test]
    fn padding_sizes() {
        // 2048-bit OAEP-SHA1: 214-byte plain blocks.
        let p = Policy::Basic256Sha256;
        assert_eq!(256 - p.asym_overhead(), 214);
        let base = 8 + 100 + 1 + 256;
        assert_eq!((base + padding(base, 214)) % 214, 0);
        assert_eq!(padding(214, 214), 0);
        assert_eq!(padding(215, 16), 9);
        // Symmetric chunk limits keep the encrypted part block-aligned.
        for buf in [8192usize, 65536, 65535] {
            for enc in [false, true] {
                for p in [Policy::Basic256Sha256, Policy::Basic128Rsa15] {
                    let b = max_sym_body(p, enc, buf);
                    let keys = derive(p, b"a", b"b");
                    let f =
                        seal_sym(p, enc, b"MSG", b'F', 1, 2, Some(&keys), &vec![0; 8 + b]).unwrap();
                    assert!(f.len() <= buf, "{p:?} {enc} {buf}: {}", f.len());
                    let f2 = seal_sym(
                        p,
                        enc,
                        b"MSG",
                        b'F',
                        1,
                        2,
                        Some(&keys),
                        &vec![0; 8 + b + 16],
                    )
                    .unwrap();
                    assert!(f2.len() > buf || !enc);
                }
            }
        }
    }

    #[test]
    fn symmetric_chunk_roundtrip() {
        for p in Policy::ALL.into_iter().skip(1) {
            let keys = derive(p, b"server-nonce", b"client-nonce");
            for enc in [false, true] {
                for n in 0..40 {
                    let payload: Vec<u8> = (0..8 + n).map(|i| (i * 7) as u8).collect();
                    let f = seal_sym(p, enc, b"MSG", b'F', 9, 3, Some(&keys), &payload).unwrap();
                    assert_eq!(
                        u32::from_le_bytes(f[4..8].try_into().unwrap()) as usize,
                        f.len()
                    );
                    if enc {
                        assert_eq!((f.len() - 16) % 16, 0);
                    } else {
                        assert_eq!(&f[16..16 + payload.len()], &payload[..]);
                    }
                    assert_eq!(open_sym(p, enc, &f, Some(&keys)).unwrap(), payload);
                    let mut bad = f.clone();
                    bad[20] ^= 0x40;
                    assert!(open_sym(p, enc, &bad, Some(&keys)).is_err());
                }
            }
            let other = derive(p, b"x", b"y");
            let f = seal_sym(p, true, b"MSG", b'F', 9, 3, Some(&keys), b"12345678").unwrap();
            assert!(open_sym(p, true, &f, Some(&other)).is_err());
        }
    }

    #[test]
    fn pem_and_files() {
        let (a, _) = ids();
        let dir = std::env::temp_dir().join(format!("na-opcua-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("c.pem");
        let kp = dir.join("k.pem");
        std::fs::write(&cp, pem_encode("CERTIFICATE", &a.cert)).unwrap();
        std::fs::write(
            &kp,
            a.key.to_pkcs8_pem(LineEnding::CRLF).unwrap().as_bytes(),
        )
        .unwrap();
        let id = ClientIdentity::load(&cp, &kp).unwrap();
        assert_eq!(id.cert, a.cert);
        assert_eq!(id.app_uri, "urn:test:client");
        // DER cert works too; a mismatched key is refused.
        let cd = dir.join("c.der");
        std::fs::write(&cd, &a.cert).unwrap();
        assert!(ClientIdentity::load(&cd, &kp).is_ok());
        let (_, b) = ids();
        let kb = dir.join("kb.pem");
        std::fs::write(&kb, b.key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
        assert!(
            ClientIdentity::load(&cd, &kb)
                .err()
                .unwrap()
                .contains("does not belong")
        );
        // Trust store.
        let tf = dir.join("trusted.json");
        assert_eq!(trust_status_in(&tf, "urn:s", &a.cert), Trust::Unknown);
        trust_in(&tf, "urn:s", &a.cert).unwrap();
        assert_eq!(trust_status_in(&tf, "urn:s", &a.cert), Trust::Trusted);
        assert!(matches!(
            trust_status_in(&tf, "urn:s", &b.cert),
            Trust::Changed(_)
        ));
        assert_eq!(trust_key("", "opc.tcp://plc:4841/x"), "plc:4841");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn der_helpers() {
        assert_eq!(
            oid("1.2.840.113549.1.1.11"),
            unhex("06092A864886F70D01010B")
        );
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[0, 0, 5]), vec![0x02, 0x01, 0x05]);
        let mut l = Vec::new();
        der_len(300, &mut l);
        assert_eq!(l, vec![0x82, 0x01, 0x2c]);
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(der_time(0), tlv(0x17, b"700101000000Z"));
        assert_eq!(der_time(2_524_608_000), tlv(0x18, b"20500101000000Z"));
    }
}
