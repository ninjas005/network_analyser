//! Headless versions of the diagnostic tools (`--dns`, `--trace`, …).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

pub fn dns(args: &[String]) {
    let Some(name) = args.first() else {
        fail("usage: --dns NAME [TYPE] [@SERVER]")
    };
    let mut qtype = 1;
    let mut server: Option<SocketAddr> = None;
    for a in &args[1..] {
        if let Some(s) = a.strip_prefix('@') {
            server = Some(crate::dns::parse_server(s).unwrap_or_else(|e| fail(e)));
        } else {
            qtype = crate::dns::parse_type(a).unwrap_or_else(|| fail(format!("unknown type {a}")));
        }
    }
    let server = server
        .or_else(|| {
            crate::dns::system_servers()
                .first()
                .map(|ip| SocketAddr::new(*ip, 53))
        })
        .unwrap_or_else(|| fail("no DNS server configured; pass @SERVER"));
    // A bare IP with type A means a reverse lookup.
    let (qname, qtype) = match name.parse::<IpAddr>() {
        Ok(ip) if qtype == 1 => (crate::dns::reverse_name(ip), 12),
        _ => (name.clone(), qtype),
    };
    let q = crate::dns::Query {
        name: qname,
        qtype,
        server,
        tcp: false,
        timeout: Duration::from_secs(3),
        recursion: true,
        dnssec: false,
    };
    let a = crate::dns::query(&q).unwrap_or_else(|e| fail(e));
    let r = &a.response;
    println!(
        ";; {} from {} in {:.1} ms ({} bytes{}){}{}",
        crate::dns::rcode_name(r.rcode),
        a.server,
        a.rtt.as_secs_f64() * 1000.0,
        r.size,
        if a.via_tcp { ", TCP" } else { "" },
        if r.authoritative { " aa" } else { "" },
        if r.authentic { " ad" } else { "" }
    );
    for (title, recs) in [
        ("ANSWER", &r.answers),
        ("AUTHORITY", &r.authority),
        ("ADDITIONAL", &r.additional),
    ] {
        if !recs.is_empty() {
            println!(";; {title}");
            for x in recs {
                println!(
                    "{:<40} {:>6} {:<6} {}",
                    x.name,
                    x.ttl,
                    crate::dns::type_name(x.rtype),
                    x.data
                );
            }
        }
    }
}

pub fn trace(args: &[String]) {
    let Some(target) = args.first() else {
        fail("usage: --trace HOST")
    };
    let h = crate::traceroute::start(crate::traceroute::TraceConfig {
        target: target.clone(),
        max_hops: 30,
        rounds: 3,
        timeout: Duration::from_secs(2),
        resolve_names: true,
        ipv6: false,
    });
    let mut hops = std::collections::BTreeMap::new();
    while let Ok(ev) = h.events.recv() {
        match ev {
            crate::traceroute::TraceEvent::Resolved(ip) => {
                eprintln!("traceroute to {target} ({ip})")
            }
            crate::traceroute::TraceEvent::Hop(hop) => {
                hops.insert(hop.ttl, hop);
            }
            crate::traceroute::TraceEvent::Error(e) => fail(e),
            crate::traceroute::TraceEvent::Finished { reached, elapsed } => {
                for h in hops.values() {
                    let rtts: Vec<String> = h
                        .rtts
                        .iter()
                        .map(|r| r.map(|v| format!("{v:.1} ms")).unwrap_or("*".into()))
                        .collect();
                    let who = match (&h.addr, &h.name) {
                        (Some(a), Some(n)) => format!("{n} ({a})"),
                        (Some(a), None) => a.to_string(),
                        _ => "*".into(),
                    };
                    println!("{:>2}  {:<50} {}", h.ttl, who, rtts.join("  "));
                }
                eprintln!(
                    "{} in {:.1}s",
                    if reached { "reached" } else { "not reached" },
                    elapsed.as_secs_f32()
                );
                break;
            }
        }
    }
}

pub fn gateway() {
    let rx = crate::gateway::start();
    let mut section = String::new();
    while let Ok(ev) = rx.recv() {
        match ev {
            crate::gateway::GwEvent::Finding(f) => {
                if f.section != section {
                    println!("\n[{}]", f.section);
                    section = f.section.clone();
                }
                let mark = match f.level {
                    crate::gateway::Level::Good => "ok ",
                    crate::gateway::Level::Warn => "!! ",
                    crate::gateway::Level::Bad => "XX ",
                    crate::gateway::Level::Info => "   ",
                };
                println!("{mark}{:<24} {}", f.key, f.value);
            }
            crate::gateway::GwEvent::Status(s) => eprintln!("… {s}"),
            crate::gateway::GwEvent::Done => break,
        }
    }
}

pub fn netconfig() {
    println!("Hostname: {}", crate::netconfig::hostname());
    println!("\nInterfaces:");
    for i in crate::netconfig::interfaces() {
        let state = match i.up {
            Some(true) => "up",
            Some(false) => "down",
            None => "?",
        };
        println!(
            "  {:<16} {:<9} {:<5} mtu {:<6} {}{}",
            i.name,
            i.kind,
            state,
            i.mtu.map(|m| m.to_string()).unwrap_or("-".into()),
            i.mac.unwrap_or_default(),
            i.speed_mbps
                .map(|s| format!("  {s} Mb/s"))
                .unwrap_or_default()
        );
        for (a, p) in i.addrs {
            println!("  {:<16} {a}/{p}", "");
        }
    }
    println!("\nRoutes:");
    for r in crate::netconfig::routes() {
        println!(
            "  {:<44} {:<28} {:<12} {}",
            r.dest,
            r.gateway.map(|g| format!("via {g}")).unwrap_or_default(),
            r.iface,
            r.metric.map(|m| format!("metric {m}")).unwrap_or_default()
        );
    }
    println!("\nDNS servers: {:?}", crate::dns::system_servers());
    let up = crate::dns::resolved_upstreams();
    if !up.is_empty() {
        println!("  (systemd-resolved upstreams: {up:?})");
    }
}

pub fn wol(args: &[String]) {
    let Some(mac) = args.first().and_then(|m| crate::dhcp::parse_mac(m)) else {
        fail("usage: --wol MAC [BROADCAST]")
    };
    let target: IpAddr = match args.get(1) {
        Some(t) => t
            .parse()
            .unwrap_or_else(|_| fail(format!("bad address {t}"))),
        None => crate::wol::broadcast_addresses()
            .first()
            .map(|(_, b)| IpAddr::V4(*b))
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::BROADCAST)),
    };
    match crate::wol::send(mac, &[], target, 9) {
        Ok(n) => println!("sent {n}-byte magic packet to {target}:9"),
        Err(e) => fail(e),
    }
}
