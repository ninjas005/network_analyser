//! DNS Lookup and Reverse DNS tools.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::dns::{self, Answer, Query, Record};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, copy_button,
    empty_state, input, label, mono, progress, section_title, status_bar, table_header, toolbar,
};

#[derive(Clone, Copy, PartialEq)]
enum ServerChoice {
    System,
    Public(usize),
    Custom,
}

fn resolve_server(choice: ServerChoice, custom: &str) -> Result<SocketAddr, String> {
    match choice {
        ServerChoice::System => dns::system_servers()
            .first()
            .map(|ip| SocketAddr::new(*ip, 53))
            .ok_or_else(|| "no system DNS server configured".into()),
        ServerChoice::Public(i) => dns::parse_server(dns::PUBLIC_RESOLVERS[i].1),
        ServerChoice::Custom => {
            if custom.trim().is_empty() {
                Err("enter a DNS server address".into())
            } else {
                dns::parse_server(custom)
            }
        }
    }
}

fn server_chips<V: 'static>(
    view: &gpui::WeakEntity<V>,
    current: ServerChoice,
    get: fn(&mut V) -> &mut ServerChoice,
    custom: &Entity<TextInput>,
) -> gpui::Div {
    let mut row = div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap_1()
        .child(label("Server"))
        .child(chip(
            "srv-sys",
            "System",
            current == ServerChoice::System,
            act(view, move |t: &mut V, _, _| *get(t) = ServerChoice::System),
        ));
    for (i, (name, ip)) in dns::PUBLIC_RESOLVERS.iter().enumerate() {
        row = row.child(chip(
            ("srv", i),
            format!("{name} {ip}"),
            current == ServerChoice::Public(i),
            act(view, move |t: &mut V, _, _| {
                *get(t) = ServerChoice::Public(i)
            }),
        ));
    }
    row.child(chip(
        "srv-custom",
        "Custom",
        current == ServerChoice::Custom,
        act(view, move |t: &mut V, _, _| *get(t) = ServerChoice::Custom),
    ))
    .when(current == ServerChoice::Custom, |d| d.child(custom.clone()))
}

// ---------------------------------------------------------------- DNS lookup

const LOOKUP_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA", "HTTPS", "DS", "DNSKEY",
    "TLSA", "ANY",
];

pub struct DnsView {
    focus: FocusHandle,
    name: Entity<TextInput>,
    custom: Entity<TextInput>,
    qtype: &'static str,
    server: ServerChoice,
    tcp: bool,
    dnssec: bool,
    recursion: bool,
    rx: Option<Receiver<(String, Result<Answer, String>)>>,
    results: Vec<(String, Result<Answer, String>)>,
    compare: bool,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl DnsView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self {
            focus: cx.focus_handle(),
            name: input(
                window,
                cx,
                "",
                "example.com or an IP address",
                Accept::Any,
                |t| t.width(300.),
                |t: &mut Self, _, cx| t.run(false, cx),
            ),
            custom: input(
                window,
                cx,
                "",
                "10.0.0.53 or [::1]:5353",
                Accept::Any,
                |t| t.width(180.),
                |t: &mut Self, _, cx| t.run(false, cx),
            ),
            qtype: "A",
            server: ServerChoice::System,
            tcp: false,
            dnssec: false,
            recursion: true,
            rx: None,
            results: Vec::new(),
            compare: false,
            status: "Enter a name, choose a record type and press Query.".into(),
            _poll: None,
        }
    }

    fn run(&mut self, compare: bool, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let raw = self.name.read(cx).value.trim().to_string();
        if raw.is_empty() {
            self.name.update(cx, |t, cx| {
                t.error = true;
                cx.notify()
            });
            return;
        }
        // An IP address means "look up its PTR".
        let (name, qtype) = match raw.parse::<IpAddr>() {
            Ok(ip) => (dns::reverse_name(ip), 12),
            Err(_) => (raw.clone(), dns::parse_type(self.qtype).unwrap_or(1)),
        };
        let servers: Vec<(String, Result<SocketAddr, String>)> = if compare {
            let mut v: Vec<(String, Result<SocketAddr, String>)> = dns::system_servers()
                .into_iter()
                .chain(dns::resolved_upstreams())
                .map(|ip| (format!("System {ip}"), Ok(SocketAddr::new(ip, 53))))
                .collect();
            for (n, ip) in dns::PUBLIC_RESOLVERS {
                let addr = dns::parse_server(ip);
                // Skip public resolvers that are already the system's.
                if let Ok(a) = &addr
                    && v.iter().any(|(_, x)| x.as_ref().ok() == Some(a))
                {
                    continue;
                }
                v.push((format!("{n} {ip}"), addr));
            }
            v
        } else {
            let s = resolve_server(self.server, &self.custom.read(cx).value);
            vec![(s.as_ref().map(|a| a.to_string()).unwrap_or_default(), s)]
        };
        let (tx, rx) = channel();
        let (tcp, dnssec, recursion) = (self.tcp, self.dnssec, self.recursion);
        for (label, server) in servers {
            let (tx, name) = (tx.clone(), name.clone());
            std::thread::spawn(move || {
                let r = server.and_then(|server| {
                    dns::query(&Query {
                        name,
                        qtype,
                        server,
                        tcp,
                        timeout: Duration::from_secs(3),
                        recursion,
                        dnssec,
                    })
                });
                let _ = tx.send((label, r));
            });
        }
        self.results.clear();
        self.compare = compare;
        self.rx = Some(rx);
        self.status = format!("Querying {} {}…", dns::type_name(qtype), name).into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(80))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(rx) = &self.rx else { return false };
        loop {
            match rx.try_recv() {
                Ok(r) => self.results.push(r),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    cx.notify();
                    return true;
                }
                Err(_) => break,
            }
        }
        self.rx = None;
        self.results
            .sort_by_key(|(_, r)| r.as_ref().map(|a| a.rtt).unwrap_or(Duration::MAX));
        self.status = match self.results.first() {
            Some((_, Ok(a))) if !self.compare => format!(
                "{} — {} answer{} from {} in {:.1} ms",
                dns::rcode_name(a.response.rcode),
                a.response.answers.len(),
                if a.response.answers.len() == 1 {
                    ""
                } else {
                    "s"
                },
                a.server,
                a.rtt.as_secs_f64() * 1000.0
            )
            .into(),
            Some((_, Err(e))) if !self.compare => format!("Query failed: {e}").into(),
            _ => format!("Compared {} resolvers", self.results.len()).into(),
        };
        cx.notify();
        false
    }

    fn records(title: &str, recs: &[Record]) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .child(
                div()
                    .px_5()
                    .pt_3()
                    .child(section_title(&format!("{title} ({})", recs.len()))),
            )
            .child(table_header(&[
                ("NAME", 300.),
                ("TTL", 80.),
                ("TYPE", 80.),
                ("DATA", 0.),
            ]))
            .children(recs.iter().enumerate().map(|(i, r)| {
                div()
                    .flex()
                    .px_3()
                    .py_1()
                    .text_sm()
                    .font_family(mono())
                    .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                    .child(cell(300., r.name.clone()))
                    .child(cell(80., r.ttl.to_string()).text_color(rgb(C::MUTED)))
                    .child(cell(80., dns::type_name(r.rtype)).text_color(rgb(C::CYAN)))
                    .child(div().flex_1().min_w_0().child(r.data.clone()))
            }))
    }
}

impl Focusable for DnsView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for DnsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.rx.is_some();
        let body = if self.results.is_empty() {
            empty_state(
                if busy { "Querying…" } else { "No query yet" },
                "Tip: type an IP address to look up its PTR name.",
            )
            .into_any_element()
        } else if self.compare {
            div()
                .id("dns-compare")
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .child(table_header(&[
                    ("RESOLVER", 260.),
                    ("STATUS", 110.),
                    ("TIME", 90.),
                    ("FLAGS", 90.),
                    ("ANSWERS", 0.),
                ]))
                .children(self.results.iter().enumerate().map(|(i, (label, r))| {
                    let (status, time, flags, answers, color) = match r {
                        Ok(a) => (
                            dns::rcode_name(a.response.rcode).to_string(),
                            format!("{:.1} ms", a.rtt.as_secs_f64() * 1000.0),
                            format!(
                                "{}{}",
                                if a.response.authentic { "ad " } else { "" },
                                if a.via_tcp { "tcp" } else { "" }
                            ),
                            a.response
                                .answers
                                .iter()
                                .map(|r| r.data.clone())
                                .collect::<Vec<_>>()
                                .join(", "),
                            if a.response.rcode == 0 {
                                C::GREEN
                            } else {
                                C::AMBER
                            },
                        ),
                        Err(e) => ("error".into(), "—".into(), String::new(), e.clone(), C::RED),
                    };
                    div()
                        .flex()
                        .px_3()
                        .py_1()
                        .text_sm()
                        .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                        .child(cell(260., label.clone()))
                        .child(cell(110., status).text_color(rgb(color)))
                        .child(cell(90., time))
                        .child(cell(90., flags).text_color(rgb(C::MUTED)))
                        .child(div().flex_1().min_w_0().font_family(mono()).child(answers))
                }))
                .into_any_element()
        } else {
            match &self.results[0].1 {
                Err(e) => div()
                    .p_5()
                    .text_color(rgb(C::RED))
                    .child(e.clone())
                    .into_any_element(),
                Ok(a) => {
                    let r = &a.response;
                    let flags = [
                        (r.authoritative, "authoritative"),
                        (r.recursion_available, "recursion available"),
                        (r.authentic, "DNSSEC validated (AD)"),
                        (r.truncated || a.via_tcp, "retried over TCP"),
                    ]
                    .iter()
                    .filter(|(on, _)| *on)
                    .map(|(_, n)| *n)
                    .collect::<Vec<_>>()
                    .join(" · ");
                    div()
                        .id("dns-result")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .child(
                            div()
                                .flex()
                                .gap_4()
                                .px_5()
                                .py_3()
                                .text_sm()
                                .bg(if r.rcode == 0 {
                                    alpha(C::GREEN, 0.06)
                                } else {
                                    alpha(C::AMBER, 0.08)
                                })
                                .child(
                                    div()
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .child(dns::rcode_name(r.rcode)),
                                )
                                .child(format!("server {}", a.server))
                                .child(format!("{:.1} ms", a.rtt.as_secs_f64() * 1000.0))
                                .child(format!("{} bytes", r.size))
                                .child(div().text_color(rgb(C::MUTED)).child(flags)),
                        )
                        .when(!r.answers.is_empty(), |d| {
                            d.child(Self::records("Answer", &r.answers))
                        })
                        .when(!r.authority.is_empty(), |d| {
                            d.child(Self::records("Authority", &r.authority))
                        })
                        .when(!r.additional.is_empty(), |d| {
                            d.child(Self::records("Additional", &r.additional))
                        })
                        .when(r.answers.is_empty() && r.rcode == 0, |d| {
                            d.child(
                                div()
                                    .px_5()
                                    .py_3()
                                    .text_sm()
                                    .text_color(rgb(C::MUTED))
                                    .child("No records of this type (NODATA)."),
                            )
                        })
                        .into_any_element()
                }
            }
        };
        let text = self
            .results
            .iter()
            .map(|(l, r)| match r {
                Ok(a) => format!(
                    "; {l}: {} in {:.1} ms\n{}",
                    dns::rcode_name(a.response.rcode),
                    a.rtt.as_secs_f64() * 1000.0,
                    a.response
                        .answers
                        .iter()
                        .map(|x| format!(
                            "{} {} {} {}",
                            x.name,
                            x.ttl,
                            dns::type_name(x.rtype),
                            x.data
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
                Err(e) => format!("; {l}: {e}"),
            })
            .collect::<Vec<_>>()
            .join("\n");
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Name"))
                    .child(self.name.clone())
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_1()
                            .children(LOOKUP_TYPES.iter().map(|&t| {
                                chip(
                                    t,
                                    t,
                                    self.qtype == t,
                                    act(&view, move |v: &mut Self, _, _| v.qtype = t),
                                )
                            })),
                    )
                    .child(server_chips(
                        &view,
                        self.server,
                        |t: &mut Self| &mut t.server,
                        &self.custom,
                    ))
                    .child(chip(
                        "dns-tcp",
                        "TCP",
                        self.tcp,
                        act(&view, |t: &mut Self, _, _| t.tcp = !t.tcp),
                    ))
                    .child(chip(
                        "dns-sec",
                        "DNSSEC (DO)",
                        self.dnssec,
                        act(&view, |t: &mut Self, _, _| t.dnssec = !t.dnssec),
                    ))
                    .child(chip(
                        "dns-rd",
                        "Recursion",
                        self.recursion,
                        act(&view, |t: &mut Self, _, _| t.recursion = !t.recursion),
                    ))
                    .child(if busy {
                        button("dns-go", "Querying…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary(
                            "dns-go",
                            "▶ Query",
                            act(&view, |t: &mut Self, _, cx| t.run(false, cx)),
                        )
                    })
                    .child(button2(
                        "dns-cmp",
                        "Compare resolvers",
                        act(&view, |t: &mut Self, _, cx| t.run(true, cx)),
                    ))
                    .child(copy_button("dns-copy", text)),
            )
            .child(body)
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}

// ---------------------------------------------------------------- reverse DNS

#[derive(Clone)]
struct PtrRow {
    ip: IpAddr,
    name: Option<String>,
    confirmed: Option<bool>,
    rtt_ms: f32,
    error: Option<String>,
}

pub struct ReverseDnsView {
    focus: FocusHandle,
    targets: Entity<TextInput>,
    custom: Entity<TextInput>,
    server: ServerChoice,
    confirm: bool,
    only_named: bool,
    rows: Vec<PtrRow>,
    total: usize,
    rx: Option<Receiver<PtrRow>>,
    stop: Arc<AtomicBool>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

fn parse_targets(s: &str) -> Result<Vec<IpAddr>, String> {
    let mut out = Vec::new();
    for item in s
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
    {
        if let Ok(ip) = item.parse::<IpAddr>() {
            out.push(ip);
        } else {
            out.extend(
                crate::netinfo::parse_range(item)?
                    .into_iter()
                    .map(IpAddr::V4),
            );
        }
        if out.len() > 65_536 {
            return Err("too many addresses (max 65536)".into());
        }
    }
    if out.is_empty() {
        return Err("enter addresses or ranges".into());
    }
    Ok(out)
}

fn ptr_lookup(ip: IpAddr, server: SocketAddr, confirm: bool) -> PtrRow {
    let q = |name: String, qtype: u16| {
        dns::query(&Query {
            name,
            qtype,
            server,
            tcp: false,
            timeout: Duration::from_secs(2),
            recursion: true,
            dnssec: false,
        })
    };
    let mut row = PtrRow {
        ip,
        name: None,
        confirmed: None,
        rtt_ms: 0.0,
        error: None,
    };
    match q(dns::reverse_name(ip), 12) {
        Ok(a) => {
            row.rtt_ms = a.rtt.as_secs_f32() * 1000.0;
            row.name = a
                .response
                .answers
                .iter()
                .find(|r| r.rtype == 12)
                .map(|r| r.data.clone());
            if a.response.rcode != 0 && a.response.rcode != 3 {
                row.error = Some(dns::rcode_name(a.response.rcode).into());
            }
        }
        Err(e) => row.error = Some(e),
    }
    if confirm && let Some(name) = &row.name {
        let qtype = if ip.is_ipv4() { 1 } else { 28 };
        row.confirmed = q(name.clone(), qtype).ok().map(|a| {
            a.response
                .answers
                .iter()
                .any(|r| r.data.parse::<IpAddr>().ok() == Some(ip))
        });
    }
    row
}

impl ReverseDnsView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cidr = crate::netinfo::local_interfaces()
            .first()
            .map(|i| i.cidr())
            .unwrap_or_default();
        Self {
            focus: cx.focus_handle(),
            targets: input(
                window,
                cx,
                &cidr,
                "8.8.8.8, 2001:4860:4860::8888, 192.168.1.0/24",
                Accept::Any,
                |t| t.width(380.).max_len(4000),
                |t: &mut Self, _, cx| t.run(cx),
            ),
            custom: input(
                window,
                cx,
                "",
                "10.0.0.53",
                Accept::Any,
                |t| t.width(160.),
                |t: &mut Self, _, cx| t.run(cx),
            ),
            server: ServerChoice::System,
            confirm: true,
            only_named: false,
            rows: Vec::new(),
            total: 0,
            rx: None,
            stop: Arc::new(AtomicBool::new(false)),
            status: "Enter addresses or ranges and press Look up.".into(),
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let targets = match parse_targets(&self.targets.read(cx).value) {
            Ok(t) => t,
            Err(e) => {
                self.status = e.into();
                return;
            }
        };
        let server = match resolve_server(self.server, &self.custom.read(cx).value) {
            Ok(s) => s,
            Err(e) => {
                self.status = e.into();
                return;
            }
        };
        self.rows.clear();
        self.total = targets.len();
        self.stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        let (stop, confirm) = (self.stop.clone(), self.confirm);
        std::thread::spawn(move || {
            let next = Mutex::new(0usize);
            std::thread::scope(|s| {
                for _ in 0..targets.len().min(32) {
                    s.spawn(|| {
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                return;
                            }
                            let i = {
                                let mut n = next.lock().unwrap();
                                *n += 1;
                                *n - 1
                            };
                            let Some(ip) = targets.get(i) else { return };
                            if tx.send(ptr_lookup(*ip, server, confirm)).is_err() {
                                return;
                            }
                        }
                    });
                }
            });
        });
        self.rx = Some(rx);
        self.status = format!(
            "Looking up {} address{} via {server}…",
            self.total,
            if self.total == 1 { "" } else { "es" }
        )
        .into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(rx) = &self.rx else { return false };
        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(r) => {
                    let pos = self.rows.partition_point(|x| x.ip < r.ip);
                    self.rows.insert(pos, r);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(_) => {
                    finished = true;
                    break;
                }
            }
        }
        if finished {
            self.rx = None;
            let named = self.rows.iter().filter(|r| r.name.is_some()).count();
            let mismatched = self
                .rows
                .iter()
                .filter(|r| r.confirmed == Some(false))
                .count();
            self.status = format!(
                "{named} of {} addresses have a PTR name{}",
                self.rows.len(),
                if mismatched > 0 {
                    format!(", {mismatched} not forward-confirmed")
                } else {
                    String::new()
                }
            )
            .into();
        }
        cx.notify();
        !finished
    }
}

impl Focusable for ReverseDnsView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for ReverseDnsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.rx.is_some();
        let shown: Vec<&PtrRow> = self
            .rows
            .iter()
            .filter(|r| !self.only_named || r.name.is_some())
            .collect();
        let text = shown
            .iter()
            .map(|r| format!("{}\t{}", r.ip, r.name.clone().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("\n");
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Addresses"))
                    .child(self.targets.clone())
                    .child(server_chips(&view, self.server, |t: &mut Self| &mut t.server, &self.custom))
                    .child(chip("fcr", "Forward-confirm", self.confirm, act(&view, |t: &mut Self, _, _| t.confirm = !t.confirm)))
                    .child(chip("named", "Only named", self.only_named, act(&view, |t: &mut Self, _, _| t.only_named = !t.only_named)))
                    .child(if busy {
                        button("rd-go", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.stop.store(true, Ordering::Relaxed)))
                    } else {
                        button_primary("rd-go", "▶ Look up", act(&view, |t: &mut Self, _, cx| t.run(cx)))
                    })
                    .child(copy_button("rd-copy", text)),
            )
            .child(table_header(&[("ADDRESS", 240.), ("PTR NAME", 0.), ("FORWARD", 120.), ("TIME", 90.)]))
            .child(if shown.is_empty() {
                empty_state(if busy { "Looking up…" } else { "No results" }, "Forward-confirm checks that the PTR name resolves back to the same address (FCrDNS).").into_any_element()
            } else {
                div()
                    .id("rd-rows")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(shown.iter().enumerate().take(5000).map(|(i, r)| {
                        let (fwd, fc) = match r.confirmed {
                            Some(true) => ("✓ matches", C::GREEN),
                            Some(false) => ("✗ mismatch", C::AMBER),
                            None => ("", C::MUTED),
                        };
                        div()
                            .flex()
                            .px_3()
                            .h(px(28.))
                            .items_center()
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(cell(240., r.ip.to_string()).font_family(mono()))
                            .child(cell(0., r.name.clone().or_else(|| r.error.clone()).unwrap_or_else(|| "—".into())).text_color(rgb(if r.name.is_some() { C::TEXT } else { C::MUTED })))
                            .child(cell(120., fwd).text_color(rgb(fc)))
                            .child(cell(90., format!("{:.0} ms", r.rtt_ms)).text_color(rgb(C::MUTED)))
                    }))
                    .into_any_element()
            })
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .when(self.total > 0, |d| {
                        d.child(progress(self.rows.len() as f32 / self.total as f32, 160.))
                            .child(format!("{}/{}", self.rows.len(), self.total))
                    }),
            )
    }
}
