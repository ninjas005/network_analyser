//! Headless packet analysis: `--pcap FILE [REPORT]` and `--capture IFACE`.

use std::time::Duration;

use crate::capture::{self, CaptureConfig, CaptureEvent, Limits, Packet, Source};
use crate::capture_view::human_bytes;
use crate::pcapfile::FileInfo;
use crate::streams::{CLIENT, SERVER};

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

const USAGE: &str = "usage: --pcap FILE [info | packets | decode N | streams | follow N [hex] | http | http-body N [response|request] | handshakes | dns | stats] [-f BPF] [-d DISPLAY-FILTER]";

fn opt(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    match args.get(i + 1) {
        Some(v) => Some(v.clone()),
        None => fail(format!("{name}: missing value")),
    }
}

fn load(path: &str, filter: &str) -> (crate::session::Analysis, Option<FileInfo>) {
    let h = capture::start_brief(
        CaptureConfig {
            source: Source::File(path.into()),
            filter: filter.into(),
            save_to: None,
        },
        Limits::default(),
    );
    let mut a = crate::session::Analysis::default();
    let mut info = None;
    while let Ok(ev) = h.events.recv() {
        match ev {
            CaptureEvent::Packets(ps) => {
                for p in ps {
                    a.add(p);
                }
            }
            CaptureEvent::FileInfo(i) => info = Some(*i),
            CaptureEvent::Stopped(Some(e)) => fail(e),
            CaptureEvent::Stopped(None) => break,
            _ => {}
        }
    }
    a.finish();
    (a, info)
}

/// Terminal-safe text: captured bytes must not send escape sequences.
fn safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '.'
            } else {
                c
            }
        })
        .collect()
}

fn line(p: &Packet, t0: f64) -> String {
    format!(
        "{:>6} {:>12.6}  {:<22} {:<22} {:<10} {:>5}  {}",
        p.no,
        p.ts - t0,
        p.d.src,
        p.d.dst,
        p.d.proto,
        p.len,
        safe(&p.d.info)
    )
}

pub fn pcap(args: &[String]) {
    let Some(path) = args.first() else {
        fail(USAGE)
    };
    let bpf = opt(args, "-f").unwrap_or_default();
    let display = opt(args, "-d").unwrap_or_default();
    let mut words = Vec::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-f" || args[i] == "-d" {
            i += 2;
            continue;
        }
        words.push(args[i].as_str());
        i += 1;
    }
    let num = || -> usize {
        match words.get(1).and_then(|n| n.parse().ok()) {
            Some(n) => n,
            None => fail(USAGE),
        }
    };
    let (a, info) = load(path, &bpf);
    let t0 = a.stats.first.unwrap_or(0.0);
    let ms = |t: Option<f64>| t.map_or("-".into(), |t| format!("{:.1}ms", t * 1000.0));
    match words.first().copied().unwrap_or("info") {
        "info" => {
            if let Some(i) = &info {
                for (k, v) in crate::session::file_info_rows(i) {
                    println!("{k:<22} {}", safe(&v));
                }
                println!();
            }
            print!("{}", a.stats.report());
            println!(
                "\nTCP streams {}   HTTP exchanges {}   DNS transactions {}",
                a.tcp.streams.len(),
                a.http().count(),
                a.dns.txns.len()
            );
        }
        "packets" => {
            let terms = crate::session::filter_terms(&display);
            for p in a
                .packets
                .iter()
                .filter(|p| crate::session::matches(p, &terms))
            {
                println!("{}", line(p, t0));
            }
        }
        "decode" => {
            let n = num();
            let Some(p) = a.packets.iter().find(|p| p.no == n) else {
                fail(format!("no packet {n}"))
            };
            println!("{}", line(p, t0));
            let d = crate::dissect::dissect(p.linktype, &p.data);
            println!("Protocols: {}", d.path.join(" › "));
            if let Some(h) = d.how {
                println!("{} identified by {}", d.proto, h.text());
            }
            for l in &d.layers {
                println!("\n{}", l.name);
                for (k, v) in &l.fields {
                    println!("  {:<24} {}", safe(k), safe(v));
                }
            }
            println!();
            for l in crate::dissect::hexdump(&p.data) {
                println!("{l}");
            }
        }
        "streams" => {
            for s in &a.tcp.streams {
                println!(
                    "{:>5}  {:<26} → {:<26} {:<10} {:>7} pkts {:>10} ↑ {:>10} ↓  {:<16} {}{}{}",
                    s.id,
                    s.client(),
                    s.server(),
                    s.proto,
                    s.packets(),
                    human_bytes(s.dirs[CLIENT].bytes()),
                    human_bytes(s.dirs[SERVER].bytes()),
                    s.state().label(),
                    s.close().label(),
                    match s.retrans() {
                        0 => String::new(),
                        n => format!(", {n} retrans"),
                    },
                    match s.lost() {
                        0 => String::new(),
                        n => format!(", {n} bytes not captured"),
                    },
                );
            }
        }
        "follow" => {
            let (parts, cut) = a.tcp.follow(&a.packets, num(), None, 64 << 20);
            let hex = words.get(2) == Some(&"hex");
            for p in parts {
                let who = if p.dir == CLIENT { "client" } else { "server" };
                println!("--- {who}, packet {}, {:.6} s", p.no, p.ts - t0);
                if p.gap > 0 {
                    println!("[{} bytes missing from the capture]", p.gap);
                }
                if hex {
                    for l in crate::dissect::hexdump(&p.data) {
                        println!("{l}");
                    }
                } else {
                    println!("{}", safe(&String::from_utf8_lossy(&p.data)));
                }
            }
            if cut {
                println!("--- output cut at 64 MB");
            }
        }
        "http" => {
            for (n, (sid, e)) in a.http().enumerate() {
                let resp = e.resp.as_ref();
                println!(
                    "{n:>5}  stream {sid:<5} {:<7} {}  → {} {} {}  wait {} total {}{}",
                    e.req.as_ref().map_or("?", |r| r.method()),
                    safe(&e.url()),
                    resp.map_or("no response".into(), |r| r.status().to_string()),
                    resp.map_or("", |r| r.content_type()),
                    resp.map_or(String::new(), |r| human_bytes(r.body_len)),
                    ms(e.wait()),
                    ms(e.total()),
                    match resp {
                        Some(r) if !r.complete => "  [incomplete]",
                        _ => "",
                    }
                );
            }
        }
        "http-body" => {
            use std::io::Write;
            let Some((_, e)) = a.http().nth(num()) else {
                fail("no such exchange")
            };
            let m = if words.get(2) == Some(&"request") {
                e.req.as_ref()
            } else {
                e.resp.as_ref()
            };
            let Some(m) = m else { fail("no such message") };
            let (body, note) = m.decoded();
            std::io::stdout().write_all(&body).ok();
            if let Some(n) = note {
                eprintln!("note: {n}");
            }
        }
        "handshakes" => {
            for s in &a.tcp.streams {
                println!(
                    "{:>5}  {} → {}  {}  SYN→SYN/ACK {}  SYN/ACK→ACK {}  total {}",
                    s.id,
                    s.client(),
                    s.server(),
                    s.state().label(),
                    ms(s.hs.server_rtt()),
                    ms(s.hs.client_rtt()),
                    ms(s.hs.total())
                );
                for (l, t) in s.findings() {
                    println!("         [{l:?}] {t}");
                }
            }
        }
        "dns" => {
            for t in &a.dns.txns {
                println!(
                    "{:>12.6}  {:<5} {} → {}  {:<6} {:<40} {:<12} {:>9}  {}",
                    t.asked.or(t.answered).unwrap_or(t0) - t0,
                    t.proto,
                    t.client,
                    t.server,
                    crate::dns::type_name(t.qtype),
                    safe(&t.name),
                    t.status(a.dns.now).1,
                    ms(t.time()),
                    safe(&t.answers.join(", "))
                );
            }
            println!();
            for (l, t) in a.dns.findings() {
                println!("[{l:?}] {t}");
            }
        }
        "stats" => print!("{}", a.stats.report()),
        _ => fail(USAGE),
    }
    if let Some(p) = info.and_then(|i| i.problem) {
        eprintln!("warning: {p}; packets before that were read");
    }
}

pub fn live(args: &[String]) {
    let Some(iface) = args.first() else {
        fail(
            "usage: --capture IFACE [-n PACKETS] [-t SECONDS] [-f BPF] [-w FILE.pcap] [--no-promisc]",
        )
    };
    let num = |n: &str| -> Option<u64> {
        opt(args, n).map(|v| {
            v.parse()
                .unwrap_or_else(|_| fail(format!("{n}: expected a number")))
        })
    };
    let h = capture::start_brief(
        CaptureConfig {
            source: Source::Live {
                device: iface.clone(),
                promisc: !args.iter().any(|a| a == "--no-promisc"),
            },
            filter: opt(args, "-f").unwrap_or_default(),
            save_to: opt(args, "-w").map(Into::into),
        },
        Limits {
            packets: num("-n"),
            seconds: num("-t"),
            ..Default::default()
        },
    );
    let mut a = crate::session::Analysis::default();
    let mut dropped = 0;
    let mut first = None;
    while let Ok(ev) = h.events.recv_timeout(Duration::from_secs(86_400)) {
        match ev {
            CaptureEvent::Started { desc, .. } => eprintln!("capturing on {desc}"),
            CaptureEvent::Packets(ps) => {
                for p in ps {
                    let t0 = *first.get_or_insert(p.ts);
                    println!("{}", line(&p, t0));
                    a.add(p);
                }
            }
            CaptureEvent::Stats { dropped: d, .. } => dropped = d,
            CaptureEvent::Stopped(Some(e)) => {
                let hint = capture::permission_hint(&e).unwrap_or_default();
                fail(format!("{e}\n{hint}"))
            }
            CaptureEvent::Stopped(None) => break,
            _ => {}
        }
    }
    eprintln!("{} packets, {dropped} dropped\n", a.stats.packets);
    eprint!("{}", a.stats.report());
}
