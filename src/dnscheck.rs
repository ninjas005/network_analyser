//! DNS security checks for a domain (and the local resolver).

use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use crate::dns::{self, Query, Response};
use crate::gateway::{Finding, GwEvent, Level};

const WAIT: Duration = Duration::from_secs(4);

fn resolver() -> SocketAddr {
    dns::system_servers()
        .first()
        .map(|ip| SocketAddr::new(*ip, 53))
        .unwrap_or_else(|| "1.1.1.1:53".parse().unwrap())
}

fn q(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    dnssec: bool,
    tcp: bool,
    recursion: bool,
) -> Result<Response, String> {
    dns::query(&Query {
        name: name.into(),
        qtype,
        server,
        tcp,
        timeout: WAIT,
        recursion,
        dnssec,
    })
    .map(|a| a.response)
}

fn txts(r: &Response) -> Vec<String> {
    r.answers
        .iter()
        .filter(|a| a.rtype == 16)
        .map(|a| {
            // "\"part1\" \"part2\"" -> part1part2
            a.data
                .split('"')
                .enumerate()
                .filter(|(i, _)| i % 2 == 1)
                .map(|(_, s)| s)
                .collect::<String>()
        })
        .collect()
}

struct Out<'a>(&'a Sender<GwEvent>);

impl Out<'_> {
    fn add(&self, section: &str, key: &str, value: impl Into<String>, level: Level) {
        let _ = self.0.send(GwEvent::Finding(Finding {
            section: section.into(),
            key: key.into(),
            value: value.into(),
            level,
        }));
    }
    fn status(&self, s: &str) {
        let _ = self.0.send(GwEvent::Status(s.into()));
    }
}

/// SPF evaluation of a single record: (level, message).
pub fn judge_spf(rec: &str) -> (Level, String) {
    let terms: Vec<&str> = rec.split_whitespace().skip(1).collect();
    let lookups = terms
        .iter()
        .filter(|t| {
            let t = t
                .trim_start_matches(['+', '-', '~', '?'])
                .to_ascii_lowercase();
            t.starts_with("include:")
                || t == "a"
                || t.starts_with("a:")
                || t.starts_with("a/")
                || t == "mx"
                || t.starts_with("mx:")
                || t.starts_with("ptr")
                || t.starts_with("exists:")
                || t.starts_with("redirect=")
        })
        .count();
    let all = terms
        .iter()
        .find(|t| t.to_ascii_lowercase().ends_with("all"));
    let (mut level, mut msg) = match all.map(|t| t.chars().next().unwrap_or('+')) {
        Some('-') => (
            Level::Good,
            "hard fail (-all) for unlisted senders".to_string(),
        ),
        Some('~') => (
            Level::Good,
            "soft fail (~all) for unlisted senders".to_string(),
        ),
        Some('?') => (
            Level::Warn,
            "neutral (?all): unlisted senders are not rejected".to_string(),
        ),
        Some(_) => (
            Level::Bad,
            "+all: ANY server may send mail for this domain".to_string(),
        ),
        None if terms.iter().any(|t| t.starts_with("redirect=")) => {
            (Level::Info, "policy via redirect".to_string())
        }
        None => (
            Level::Warn,
            "no 'all' mechanism: unlisted senders are not rejected".to_string(),
        ),
    };
    if lookups > 10 {
        level = Level::Bad;
        msg.push_str(&format!(
            "; {lookups} DNS-lookup terms (limit is 10: SPF will permerror)"
        ));
    } else {
        msg.push_str(&format!("; {lookups} DNS-lookup terms (≤10)"));
    }
    (level, msg)
}

pub fn check(
    domain: String,
    dkim_selectors: Vec<String>,
    open_resolver: Option<IpAddr>,
) -> Receiver<GwEvent> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        run(&domain, &dkim_selectors, open_resolver, &tx);
        let _ = tx.send(GwEvent::Done);
    });
    rx
}

fn run(domain: &str, selectors: &[String], open_resolver: Option<IpAddr>, tx: &Sender<GwEvent>) {
    let out = Out(tx);
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let res = resolver();

    // --- Name servers
    out.status("Name servers…");
    let ns: Vec<String> = match q(res, &domain, 2, false, false, true) {
        Ok(r) if r.rcode == 3 => {
            out.add("Domain", &domain, "does not exist (NXDOMAIN)", Level::Bad);
            return;
        }
        Ok(r) => r
            .answers
            .iter()
            .filter(|a| a.rtype == 2)
            .map(|a| a.data.trim_end_matches('.').to_string())
            .collect(),
        Err(e) => {
            out.add("Domain", &domain, format!("lookup failed: {e}"), Level::Bad);
            return;
        }
    };
    if ns.is_empty() {
        out.add(
            "Name servers",
            "NS records",
            "none found (is this a zone apex?)",
            Level::Warn,
        );
    } else {
        out.add(
            "Name servers",
            "NS records",
            ns.join(", "),
            if ns.len() >= 2 {
                Level::Good
            } else {
                Level::Warn
            },
        );
        if ns.len() < 2 {
            out.add(
                "Name servers",
                "Redundancy",
                "only one name server: a single point of failure",
                Level::Warn,
            );
        }
    }
    let mut ns_ips: Vec<(String, IpAddr)> = Vec::new();
    for n in &ns {
        if let Ok(r) = q(res, n, 1, false, false, true)
            && let Some(ip) = r
                .answers
                .iter()
                .find(|a| a.rtype == 1)
                .and_then(|a| a.data.parse().ok())
        {
            ns_ips.push((n.clone(), ip));
        }
    }
    let nets: std::collections::BTreeSet<[u8; 3]> = ns_ips
        .iter()
        .filter_map(|(_, ip)| match ip {
            IpAddr::V4(v) => Some([v.octets()[0], v.octets()[1], v.octets()[2]]),
            _ => None,
        })
        .collect();
    if ns_ips.len() >= 2 {
        out.add(
            "Name servers",
            "Network diversity",
            format!("{} distinct /24 network(s)", nets.len()),
            if nets.len() >= 2 {
                Level::Good
            } else {
                Level::Warn
            },
        );
    }
    let mut serials = std::collections::BTreeSet::new();
    for (n, ip) in &ns_ips {
        match q(SocketAddr::new(*ip, 53), &domain, 6, false, false, false) {
            Ok(r) => {
                if let Some(soa) = r.answers.iter().find(|a| a.rtype == 6) {
                    serials.insert(soa.data.split_whitespace().nth(2).unwrap_or("").to_string());
                }
                if !r.authoritative {
                    out.add(
                        "Name servers",
                        n,
                        "answers but is not authoritative (lame delegation)",
                        Level::Warn,
                    );
                }
            }
            Err(e) => out.add("Name servers", n, format!("not answering: {e}"), Level::Bad),
        }
    }
    // Different DNS providers (e.g. NS1 + Route 53) keep independent serials.
    let providers: std::collections::BTreeSet<String> = ns
        .iter()
        .map(|n| {
            n.rsplit('.')
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(".")
        })
        .collect();
    if serials.len() > 1 && providers.len() > 1 {
        out.add(
            "Name servers",
            "SOA serial",
            format!(
                "differs ({}) — expected with {} DNS providers",
                serials.into_iter().collect::<Vec<_>>().join(", "),
                providers.len()
            ),
            Level::Info,
        );
    } else if serials.len() > 1 {
        out.add(
            "Name servers",
            "SOA serial",
            format!(
                "differs between servers: {}",
                serials.into_iter().collect::<Vec<_>>().join(", ")
            ),
            Level::Warn,
        );
    } else if let Some(s) = serials.first() {
        out.add(
            "Name servers",
            "SOA serial",
            format!("{s} (consistent)"),
            Level::Good,
        );
    }

    // --- Zone transfer
    out.status("Zone transfer (AXFR)…");
    for (n, ip) in &ns_ips {
        match q(SocketAddr::new(*ip, 53), &domain, 252, false, true, false) {
            Ok(r) if r.rcode == 0 && !r.answers.is_empty() => out.add(
                "Zone transfer",
                n,
                format!(
                    "AXFR ALLOWED — anyone can download the whole zone ({}+ records)",
                    r.answers.len()
                ),
                Level::Bad,
            ),
            Ok(_) | Err(_) => out.add("Zone transfer", n, "refused", Level::Good),
        }
    }

    // --- DNSSEC
    out.status("DNSSEC…");
    let ds = q(res, &domain, 43, true, false, true)
        .map(|r| r.answers.iter().filter(|a| a.rtype == 43).count())
        .unwrap_or(0);
    let keys = q(res, &domain, 48, true, false, true)
        .map(|r| r.answers.iter().filter(|a| a.rtype == 48).count())
        .unwrap_or(0);
    if ds == 0 && keys == 0 {
        out.add(
            "DNSSEC",
            "Status",
            "not signed (no DS / DNSKEY): answers can be spoofed",
            Level::Warn,
        );
    } else {
        out.add(
            "DNSSEC",
            "DS at parent",
            if ds > 0 {
                format!("{ds} record(s)")
            } else {
                "missing — the chain of trust is broken".into()
            },
            if ds > 0 { Level::Good } else { Level::Bad },
        );
        out.add(
            "DNSSEC",
            "DNSKEY",
            format!("{keys} key(s)"),
            if keys > 0 { Level::Good } else { Level::Bad },
        );
        let validator: SocketAddr = "1.1.1.1:53".parse().unwrap();
        match q(validator, &domain, 6, true, false, true) {
            Ok(r) if r.authentic => out.add(
                "DNSSEC",
                "Validation",
                "validates (AD flag from 1.1.1.1)",
                Level::Good,
            ),
            Ok(r) if r.rcode == 2 => out.add(
                "DNSSEC",
                "Validation",
                "FAILS validation (SERVFAIL from a validating resolver)",
                Level::Bad,
            ),
            Ok(_) => out.add(
                "DNSSEC",
                "Validation",
                "not validated by 1.1.1.1",
                Level::Warn,
            ),
            Err(e) => out.add("DNSSEC", "Validation", e, Level::Info),
        }
    }

    // --- Mail
    out.status("Mail records…");
    let mx = q(res, &domain, 15, false, false, true)
        .map(|r| {
            r.answers
                .iter()
                .filter(|a| a.rtype == 15)
                .map(|a| a.data.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if mx.is_empty() {
        out.add(
            "Mail",
            "MX",
            "none (the domain does not receive mail)",
            Level::Info,
        );
    } else if mx.iter().any(|m| m.trim() == "0 .") {
        out.add(
            "Mail",
            "MX",
            "null MX: the domain explicitly accepts no mail",
            Level::Info,
        );
    } else {
        out.add("Mail", "MX", mx.join(", "), Level::Info);
    }
    let spf: Vec<String> = q(res, &domain, 16, false, false, true)
        .map(|r| txts(&r))
        .unwrap_or_default()
        .into_iter()
        .filter(|t| t.to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    match spf.len() {
        0 => out.add(
            "Mail",
            "SPF",
            "missing: anyone can spoof mail from this domain",
            if mx.is_empty() {
                Level::Warn
            } else {
                Level::Bad
            },
        ),
        1 => {
            let (lvl, msg) = judge_spf(&spf[0]);
            out.add("Mail", "SPF", msg, lvl);
            out.add("Mail", "SPF record", spf[0].clone(), Level::Info);
        }
        n => out.add(
            "Mail",
            "SPF",
            format!("{n} SPF records: invalid (must be exactly one)"),
            Level::Bad,
        ),
    }
    let dmarc: Vec<String> = q(res, &format!("_dmarc.{domain}"), 16, false, false, true)
        .map(|r| txts(&r))
        .unwrap_or_default()
        .into_iter()
        .filter(|t| t.to_ascii_uppercase().starts_with("V=DMARC1"))
        .collect();
    match dmarc.first() {
        None => out.add(
            "Mail",
            "DMARC",
            "missing: receivers get no policy for spoofed mail",
            Level::Bad,
        ),
        Some(d) => {
            let tag = |k: &str| {
                d.split(';').find_map(|p| {
                    p.trim()
                        .strip_prefix(&format!("{k}="))
                        .map(|v| v.trim().to_ascii_lowercase())
                })
            };
            let (lvl, txt) = match tag("p").as_deref() {
                Some("reject") => (Level::Good, "p=reject".to_string()),
                Some("quarantine") => (Level::Good, "p=quarantine".to_string()),
                Some("none") => (
                    Level::Warn,
                    "p=none: monitoring only, spoofed mail is still delivered".to_string(),
                ),
                other => (Level::Warn, format!("policy {other:?}")),
            };
            let rua = if tag("rua").is_some() {
                ", aggregate reports enabled"
            } else {
                ", no rua= reports"
            };
            out.add("Mail", "DMARC", format!("{txt}{rua}"), lvl);
            out.add("Mail", "DMARC record", d.clone(), Level::Info);
        }
    }
    let mut sels: Vec<String> = [
        "default",
        "google",
        "selector1",
        "selector2",
        "k1",
        "mail",
        "dkim",
        "s1",
        "s2",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for s in selectors {
        if !sels.contains(s) {
            sels.insert(0, s.clone());
        }
    }
    let found: Vec<String> = sels
        .iter()
        .filter(|s| {
            q(
                res,
                &format!("{s}._domainkey.{domain}"),
                16,
                false,
                false,
                true,
            )
            .map(|r| txts(&r).iter().any(|t| t.contains("p=")))
            .unwrap_or(false)
        })
        .cloned()
        .collect();
    out.add(
        "Mail",
        "DKIM",
        if found.is_empty() {
            "no key found for common selectors (add yours above)".to_string()
        } else {
            format!("keys for selector(s): {}", found.join(", "))
        },
        if found.is_empty() {
            Level::Info
        } else {
            Level::Good
        },
    );
    let mta_sts = q(res, &format!("_mta-sts.{domain}"), 16, false, false, true)
        .map(|r| !txts(&r).is_empty())
        .unwrap_or(false);
    let tlsrpt = q(res, &format!("_smtp._tls.{domain}"), 16, false, false, true)
        .map(|r| !txts(&r).is_empty())
        .unwrap_or(false);
    if !mx.is_empty() {
        out.add(
            "Mail",
            "MTA-STS",
            if mta_sts {
                "published"
            } else {
                "not published (inbound TLS not enforced)"
            },
            if mta_sts { Level::Good } else { Level::Info },
        );
        out.add(
            "Mail",
            "TLS-RPT",
            if tlsrpt { "published" } else { "not published" },
            Level::Info,
        );
    }

    // --- CAA
    let caa: Vec<String> = q(res, &domain, 257, false, false, true)
        .map(|r| {
            r.answers
                .iter()
                .filter(|a| a.rtype == 257)
                .map(|a| a.data.clone())
                .collect()
        })
        .unwrap_or_default();
    out.add(
        "Certificates",
        "CAA",
        if caa.is_empty() {
            "none: any CA may issue certificates for this domain".to_string()
        } else {
            caa.join(" · ")
        },
        if caa.is_empty() {
            Level::Warn
        } else {
            Level::Good
        },
    );

    // --- Local resolver
    out.status("Local resolver…");
    match q(res, "dnssec-failed.org", 1, false, false, true) {
        Ok(r) if r.rcode == 2 => out.add(
            "This machine's resolver",
            &res.to_string(),
            "validates DNSSEC (rejects a deliberately broken zone)",
            Level::Good,
        ),
        Ok(r) if !r.answers.is_empty() => out.add(
            "This machine's resolver",
            &res.to_string(),
            "does NOT validate DNSSEC (accepted a broken signature)",
            Level::Warn,
        ),
        Ok(r) => out.add(
            "This machine's resolver",
            &res.to_string(),
            format!("answered {}", dns::rcode_name(r.rcode)),
            Level::Info,
        ),
        Err(e) => out.add("This machine's resolver", &res.to_string(), e, Level::Info),
    }

    if let Some(ip) = open_resolver {
        out.status("Open resolver test…");
        match q(SocketAddr::new(ip, 53), "example.com", 1, false, false, true) {
            Ok(r) if r.rcode == 0 && !r.answers.is_empty() && r.recursion_available => out.add(
                "Open resolver",
                &ip.to_string(),
                "answers recursive queries from this machine — if reachable from the internet it is an open resolver (DDoS amplification)",
                Level::Warn,
            ),
            Ok(r) => out.add("Open resolver", &ip.to_string(), format!("refuses recursion ({})", dns::rcode_name(r.rcode)), Level::Good),
            Err(e) => out.add("Open resolver", &ip.to_string(), format!("no answer: {e}"), Level::Good),
        }
    }
    out.status("Done");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_rules() {
        assert_eq!(
            judge_spf("v=spf1 include:_spf.google.com -all").0,
            Level::Good
        );
        assert_eq!(judge_spf("v=spf1 +all").0, Level::Bad);
        assert_eq!(judge_spf("v=spf1 mx ?all").0, Level::Warn);
        let many = format!(
            "v=spf1 {} -all",
            (0..11)
                .map(|i| format!("include:x{i}.com"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let (lvl, msg) = judge_spf(&many);
        assert_eq!(lvl, Level::Bad);
        assert!(msg.contains("11 DNS-lookup"));
    }
}
