//! Open Port Audit and Service Versions tools.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::audit::{self, Severity};
use crate::portscan::{self, PortScanConfig, PortScanEvent, PortScanHandle, Target};
use crate::svcdetect::{self, Detection};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, copy_button,
    empty_state, input, label, progress, status_bar, table_header, tile, tip, toolbar,
};

fn sev_color(s: Severity) -> u32 {
    match s {
        Severity::Critical => 0xff4d6d,
        Severity::High => C::RED,
        Severity::Medium => C::AMBER,
        Severity::Low => C::CYAN,
        Severity::Info => C::MUTED,
    }
}

fn poll<V: 'static>(cx: &mut Context<V>, f: fn(&mut V, &mut Context<V>) -> bool) -> Task<()> {
    cx.spawn(async move |this, cx| {
        loop {
            cx.background_executor()
                .timer(Duration::from_millis(150))
                .await;
            match this.update(cx, f) {
                Ok(true) => {}
                _ => break,
            }
        }
    })
}

// ---------------------------------------------------------------- audit

pub struct AuditView {
    focus: FocusHandle,
    targets: Entity<TextInput>,
    scan: Option<PortScanHandle>,
    resolved: Vec<Target>,
    open: BTreeMap<usize, BTreeSet<u16>>,
    progress: (usize, usize),
    baseline: audit::Baseline,
    finished: bool,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl AuditView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cidr = crate::netinfo::local_interfaces()
            .first()
            .map(|i| i.cidr())
            .unwrap_or_default();
        Self {
            focus: cx.focus_handle(),
            targets: input(window, cx, &cidr, "192.168.1.0/24, server.example.com", Accept::Any, |t| t.width(380.).max_len(2000), |t: &mut Self, _, cx| t.run(cx)),
            scan: None,
            resolved: Vec::new(),
            open: BTreeMap::new(),
            progress: (0, 0),
            baseline: audit::load_baseline(),
            finished: false,
            status: format!("Checks {} ports against {} risk rules. Only audit networks you are responsible for.", audit::ports().len(), audit::RULES.len()).into(),
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.scan.is_some() {
            return;
        }
        self.open.clear();
        self.resolved.clear();
        self.finished = false;
        self.scan = Some(portscan::start(PortScanConfig {
            targets: self.targets.read(cx).value.clone(),
            ports: audit::ports(),
            timeout: Duration::from_millis(800),
            concurrency: 512,
            banners: false,
        }));
        self.status = "Scanning…".into();
        self._poll = Some(poll(cx, |t: &mut Self, cx| {
            let Some(s) = &t.scan else { return false };
            let mut done = false;
            while let Ok(ev) = s.events.try_recv() {
                match ev {
                    PortScanEvent::Resolved(r) => t.resolved = r,
                    PortScanEvent::Open(p) => {
                        t.open.entry(p.target).or_default().insert(p.port);
                    }
                    PortScanEvent::Progress { done: d, total, .. } => t.progress = (d, total),
                    PortScanEvent::Error(e) => t.status = e.into(),
                    PortScanEvent::Banner { .. } => {}
                    PortScanEvent::Finished { elapsed, .. } => {
                        done = true;
                        t.finished = true;
                        t.status =
                            format!("Audit finished in {:.1}s", elapsed.as_secs_f32()).into();
                    }
                }
            }
            if done {
                t.scan = None;
            }
            cx.notify();
            !done
        }));
    }

    fn key(t: &Target) -> String {
        t.ip.to_string()
    }

    fn save_baseline(&mut self) {
        for (i, t) in self.resolved.iter().enumerate() {
            let ports = self.open.get(&i).cloned().unwrap_or_default();
            if ports.is_empty() {
                self.baseline.remove(&Self::key(t));
            } else {
                self.baseline.insert(Self::key(t), ports);
            }
        }
        self.status = match audit::save_baseline(&self.baseline) {
            Ok(p) => format!(
                "Baseline saved ({} hosts) to {}",
                self.baseline.len(),
                p.display()
            )
            .into(),
            Err(e) => format!("Could not save baseline: {e}").into(),
        };
    }

    /// (target, port, rule severity, baseline state) rows, worst first.
    fn rows(&self) -> Vec<(usize, u16, Severity, &'static str)> {
        let mut v = Vec::new();
        for (ti, ports) in &self.open {
            let base = self
                .resolved
                .get(*ti)
                .and_then(|t| self.baseline.get(&Self::key(t)));
            for p in ports {
                let sev = audit::rule(*p)
                    .map(|r| r.severity)
                    .unwrap_or(Severity::Info);
                let state = match base {
                    None => "",
                    Some(b) if b.contains(p) => "known",
                    Some(_) => "NEW",
                };
                v.push((*ti, *p, sev, state));
            }
        }
        v.sort_by_key(|(t, p, s, _)| (std::cmp::Reverse(*s), *t, *p));
        v
    }

    fn report(&self) -> String {
        let mut out = String::from("severity\ttarget\tport\tservice\trisk\tadvice\n");
        for (ti, p, s, st) in self.rows() {
            let r = audit::rule(p);
            out.push_str(&format!(
                "{}\t{}\t{p}\t{}\t{}\t{}{}\n",
                s.label(),
                self.resolved
                    .get(ti)
                    .map(|t| t.ip.to_string())
                    .unwrap_or_default(),
                r.map(|r| r.service)
                    .unwrap_or(crate::netinfo::service_name(p)),
                r.map(|r| r.risk).unwrap_or("open port"),
                r.map(|r| r.advice).unwrap_or(""),
                if st == "NEW" {
                    "\t(new since baseline)"
                } else {
                    ""
                }
            ));
        }
        out
    }
}

impl Focusable for AuditView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for AuditView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let rows = self.rows();
        let count = |s: Severity| rows.iter().filter(|r| r.2 == s).count();
        let new = rows.iter().filter(|r| r.3 == "NEW").count();
        let closed: Vec<String> = self
            .resolved
            .iter()
            .enumerate()
            .filter_map(|(i, t)| {
                let base = self.baseline.get(&Self::key(t))?;
                let now = self.open.get(&i).cloned().unwrap_or_default();
                let (_, gone) = audit::diff(base, &now);
                (!gone.is_empty()).then(|| {
                    format!(
                        "{}: {}",
                        t.ip,
                        gone.iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
            })
            .collect();
        let (done, total) = self.progress;
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Targets"))
                    .child(self.targets.clone())
                    .child(if self.scan.is_some() {
                        button("au-go", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| {
                            if let Some(s) = &t.scan {
                                s.cancel();
                            }
                        }))
                    } else {
                        button_primary("au-go", "▶ Run audit", act(&view, |t: &mut Self, _, cx| t.run(cx)))
                    })
                    .child(button2("au-base", "Save as baseline", act(&view, |t: &mut Self, _, _| t.save_baseline())).tooltip(tip(
                        "Remember the open ports found now; later audits mark ports that appear or disappear.",
                    )))
                    .child(copy_button("au-copy", self.report())),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .content_start()
                    .gap_2()
                    .px_5()
                    .py_3()
                    .child(tile("Critical", count(Severity::Critical).to_string(), sev_color(Severity::Critical)))
                    .child(tile("High", count(Severity::High).to_string(), sev_color(Severity::High)))
                    .child(tile("Medium", count(Severity::Medium).to_string(), sev_color(Severity::Medium)))
                    .child(tile("Low / info", (count(Severity::Low) + count(Severity::Info)).to_string(), C::MUTED))
                    .child(tile("Hosts with open ports", self.open.len().to_string(), C::TEXT))
                    .child(tile("New since baseline", if self.baseline.is_empty() { "no baseline".into() } else { new.to_string() }, if new > 0 { C::AMBER } else { C::MUTED })),
            )
            .when(!closed.is_empty() && self.finished, |d| {
                d.child(div().px_5().pb_2().text_sm().text_color(rgb(C::GREEN)).child(format!("Closed since baseline — {}", closed.join("; "))))
            })
            .child(table_header(&[("SEVERITY", 100.), ("HOST", 170.), ("PORT", 70.), ("SERVICE", 140.), ("RISK", 0.), ("RECOMMENDATION", 360.), ("BASELINE", 90.)]))
            .child(if rows.is_empty() {
                empty_state(if self.scan.is_some() { "Auditing…" } else if self.finished { "No open ports found" } else { "No audit yet" }, "").into_any_element()
            } else {
                div()
                    .id("au-rows")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(rows.into_iter().enumerate().map(|(i, (ti, p, s, st))| {
                        let r = audit::rule(p);
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .min_h(px(30.))
                            .text_sm()
                            .bg(if st == "NEW" { alpha(C::AMBER, 0.08) } else { rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }).into() })
                            .child(cell(100., s.label()).text_color(rgb(sev_color(s))))
                            .child(cell(170., self.resolved.get(ti).map(|t| t.ip.to_string()).unwrap_or_default()))
                            .child(cell(70., p.to_string()))
                            .child(cell(140., r.map(|r| r.service).unwrap_or(crate::netinfo::service_name(p))))
                            .child(div().flex_1().min_w_0().pr_3().child(r.map(|r| r.risk).unwrap_or("open port, no specific rule")))
                            .child(div().w(px(360.)).flex_none().pr_3().text_color(rgb(C::MUTED)).child(r.map(|r| r.advice).unwrap_or("")))
                            .child(cell(90., st).text_color(rgb(if st == "NEW" { C::AMBER } else { C::MUTED })))
                    }))
                    .into_any_element()
            })
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .when(total > 0, |d| d.child(progress(done as f32 / total as f32, 160.)).child(format!("{done}/{total}"))),
            )
    }
}

// ---------------------------------------------------------------- service versions

struct SvcRow {
    target: usize,
    port: u16,
    det: Option<Detection>,
}

pub struct ServiceView {
    focus: FocusHandle,
    targets: Entity<TextInput>,
    ports: Entity<TextInput>,
    scan: Option<PortScanHandle>,
    resolved: Vec<Target>,
    rows: Vec<SvcRow>,
    det_rx: Option<Receiver<(usize, u16, Detection)>>,
    pending: usize,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl ServiceView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let run = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.run(cx);
        Self {
            focus: cx.focus_handle(),
            targets: input(
                window,
                cx,
                "",
                "host, IP or range",
                Accept::Any,
                |t| t.width(320.).max_len(2000),
                run,
            ),
            ports: input(
                window,
                cx,
                "top",
                "top, 1-1024, 22,80,443",
                Accept::Ports,
                |t| t.width(170.),
                run,
            ),
            scan: None,
            resolved: Vec::new(),
            rows: Vec::new(),
            det_rx: None,
            pending: 0,
            status: "Finds open ports, then talks to each service to identify product and version."
                .into(),
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.scan.is_some() || self.pending > 0 {
            return;
        }
        let ports = match portscan::parse_ports(&self.ports.read(cx).value) {
            Ok(p) => p,
            Err(e) => {
                self.status = e.into();
                return;
            }
        };
        self.rows.clear();
        self.resolved.clear();
        self.scan = Some(portscan::start(PortScanConfig {
            targets: self.targets.read(cx).value.clone(),
            ports,
            timeout: Duration::from_millis(1000),
            concurrency: 512,
            banners: false,
        }));
        let (tx, rx) = channel::<(usize, u16, Detection)>();
        self.det_rx = Some(rx);
        // Detection worker pool fed through this channel.
        let (jtx, jrx) = channel::<(usize, IpAddr, String, u16)>();
        let jrx = std::sync::Arc::new(std::sync::Mutex::new(jrx));
        for _ in 0..16 {
            let (jrx, tx) = (jrx.clone(), tx.clone());
            std::thread::spawn(move || {
                loop {
                    let job = jrx.lock().unwrap().recv();
                    let Ok((ti, ip, host, port)) = job else {
                        return;
                    };
                    let d = svcdetect::detect(ip, &host, port, Duration::from_secs(3));
                    if tx.send((ti, port, d)).is_err() {
                        return;
                    }
                }
            });
        }
        self.status = "Scanning for open ports…".into();
        let jobs = std::sync::Arc::new(std::sync::Mutex::new(Some(jtx)));
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                let alive = this.update(cx, |t, cx| {
                    let events: Vec<PortScanEvent> = t
                        .scan
                        .as_ref()
                        .map(|s| s.events.try_iter().collect())
                        .unwrap_or_default();
                    {
                        for ev in events {
                            match ev {
                                PortScanEvent::Resolved(r) => t.resolved = r,
                                PortScanEvent::Open(p) => {
                                    let target = &t.resolved[p.target];
                                    let host = target.name.clone();
                                    if let Some(j) = jobs.lock().unwrap().as_ref() {
                                        let _ = j.send((p.target, target.ip, host, p.port));
                                    }
                                    t.pending += 1;
                                    t.rows.push(SvcRow {
                                        target: p.target,
                                        port: p.port,
                                        det: None,
                                    });
                                }
                                PortScanEvent::Finished { .. } => {
                                    t.scan = None;
                                    jobs.lock().unwrap().take();
                                }
                                PortScanEvent::Error(e) => t.status = e.into(),
                                _ => {}
                            }
                        }
                    }
                    if let Some(rx) = &t.det_rx {
                        while let Ok((ti, port, d)) = rx.try_recv() {
                            if let Some(r) =
                                t.rows.iter_mut().find(|r| r.target == ti && r.port == port)
                            {
                                r.det = Some(d);
                            }
                            t.pending = t.pending.saturating_sub(1);
                        }
                    }
                    t.rows.sort_by_key(|r| (r.target, r.port));
                    let busy = t.scan.is_some() || t.pending > 0;
                    t.status = if t.scan.is_some() {
                        format!("Scanning… {} open port(s) so far", t.rows.len()).into()
                    } else if t.pending > 0 {
                        format!("Identifying {} service(s)…", t.pending).into()
                    } else {
                        let notes: usize = t
                            .rows
                            .iter()
                            .filter_map(|r| r.det.as_ref())
                            .map(|d| d.notes.len())
                            .sum();
                        format!(
                            "{} service(s) identified, {notes} security note(s)",
                            t.rows.len()
                        )
                        .into()
                    };
                    cx.notify();
                    busy
                });
                if !matches!(alive, Ok(true)) {
                    break;
                }
            }
        }));
    }

    fn report(&self) -> String {
        self.rows
            .iter()
            .map(|r| {
                let d = r.det.clone().unwrap_or_default();
                format!(
                    "{}\t{}/tcp\t{}\t{}\t{}\t{}{}",
                    self.resolved
                        .get(r.target)
                        .map(|t| t.ip.to_string())
                        .unwrap_or_default(),
                    r.port,
                    d.service,
                    d.product,
                    d.version,
                    d.detail,
                    d.notes
                        .iter()
                        .map(|n| format!("\n\t! {n}"))
                        .collect::<String>()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Focusable for ServiceView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for ServiceView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.scan.is_some() || self.pending > 0;
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Targets"))
                    .child(self.targets.clone())
                    .child(label("Ports"))
                    .child(self.ports.clone())
                    .child(if busy {
                        button("sv-go", "Working…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary("sv-go", "▶ Detect", act(&view, |t: &mut Self, _, cx| t.run(cx)))
                    })
                    .child(copy_button("sv-copy", self.report())),
            )
            .child(table_header(&[("HOST", 170.), ("PORT", 80.), ("SERVICE", 110.), ("PRODUCT", 200.), ("VERSION", 120.), ("DETAIL", 0.)]))
            .child(if self.rows.is_empty() {
                empty_state(if busy { "Scanning…" } else { "No results yet" }, "Probes: SSH, FTP, SMTP, POP3, IMAP, HTTP(S), MySQL, PostgreSQL, Redis, memcached, VNC, RDP, MQTT, DNS (version.bind), Docker, Elasticsearch, Modbus.").into_any_element()
            } else {
                div()
                    .id("sv-rows")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(self.rows.iter().enumerate().map(|(i, r)| {
                        let d = r.det.clone();
                        let pending = d.is_none();
                        let d = d.unwrap_or_default();
                        div()
                            .flex()
                            .flex_col()
                            .px_3()
                            .py_1()
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .child(cell(170., self.resolved.get(r.target).map(|t| t.ip.to_string()).unwrap_or_default()))
                                    .child(cell(80., format!("{}/tcp", r.port)).text_color(rgb(C::GREEN)))
                                    .child(cell(110., if pending { "…".into() } else { d.service.clone() }))
                                    .child(cell(200., d.product.clone()).font_weight(gpui::FontWeight::SEMIBOLD))
                                    .child(cell(120., d.version.clone()).text_color(rgb(C::CYAN)))
                                    .child(div().flex_1().min_w_0().text_color(rgb(C::MUTED)).child(d.detail.clone())),
                            )
                            .children(d.notes.iter().map(|n| div().pl(px(170.)).text_xs().text_color(rgb(C::AMBER)).child(format!("⚠ {n}"))))
                    }))
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
