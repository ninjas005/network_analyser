//! SNMP tool: device summary with interface rates, Get / GetNext / GetBulk /
//! Walk / Set, community-string check, SNMPv3 engine discovery and a sweep.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::gateway::Finding;
use crate::snmp::{
    self, IfRow, Session, SweepHit, SystemInfo, VarBind, Version, if_type_name, oid_name, oid_str,
    status_name,
};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, copy_button,
    empty_state, findings_cards, findings_text, input, kv_row, label, mbit, mono, section_title,
    status_bar, table_header, toolbar,
};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Summary,
    Query,
    Communities,
    V3,
    Sweep,
}

type Counters = BTreeMap<u32, (u64, u64)>;

enum Ev {
    Info(SystemInfo),
    Ifs(Vec<IfRow>),
    Rates(BTreeMap<u32, (f64, f64)>),
    Vbs(Vec<VarBind>, Option<String>),
    Findings(Vec<Finding>),
    Hit(SweepHit),
    Status(String),
    Error(String),
    Done(String),
}

const MAX_ROWS: usize = 3000;

pub struct SnmpView {
    focus: FocusHandle,
    mode: Mode,
    version: Version,
    host: Entity<TextInput>,
    community: Entity<TextInput>,
    oid: Entity<TextInput>,
    set_type: Entity<TextInput>,
    set_value: Entity<TextInput>,
    communities: Entity<TextInput>,
    range: Entity<TextInput>,
    test_write: bool,
    confirm_set: Option<String>,
    tx: Sender<Ev>,
    rx: Receiver<Ev>,
    busy: bool,
    cancel: Arc<AtomicBool>,
    polling: Option<Arc<AtomicBool>>,
    status: SharedString,
    error: Option<String>,
    info: Option<SystemInfo>,
    ifs: Vec<IfRow>,
    rates: BTreeMap<u32, (f64, f64)>,
    vbs: Vec<VarBind>,
    findings: Vec<Finding>,
    hits: Vec<SweepHit>,
    _poll: Task<()>,
}

impl SnmpView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (tx, rx) = channel();
        let run = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.run(cx);
        let range = crate::netinfo::local_interfaces()
            .first()
            .map(|i| i.cidr())
            .unwrap_or_default();
        let poll = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                if this.update(cx, |t, cx| t.drain(cx)).is_err() {
                    break;
                }
            }
        });
        Self {
            focus: cx.focus_handle(),
            mode: Mode::Summary,
            version: Version::V2c,
            host: input(
                window,
                cx,
                "",
                "host or host:port",
                Accept::Any,
                |t| t.width(220.),
                run,
            ),
            community: input(
                window,
                cx,
                "public",
                "community",
                Accept::Any,
                |t| t.width(130.),
                run,
            ),
            oid: input(
                window,
                cx,
                "system",
                "OID or name: 1.3.6.1.2.1.1, sysDescr.0, ifTable",
                Accept::Any,
                |t| t.width(340.).mono(),
                |t: &mut Self, _, cx| t.query(QueryOp::Walk, cx),
            ),
            set_type: input(
                window,
                cx,
                "s",
                "type",
                Accept::Any,
                |t| t.width(44.).max_len(1),
                |_, _, _| {},
            ),
            set_value: input(
                window,
                cx,
                "",
                "new value",
                Accept::Any,
                |t| t.width(220.),
                |_, _, _| {},
            ),
            communities: input(
                window,
                cx,
                "public, private",
                "comma-separated communities",
                Accept::Any,
                |t| t.width(320.).max_len(4000),
                run,
            ),
            range: input(
                window,
                cx,
                &range,
                "192.168.1.0/24",
                Accept::Range,
                |t| t.width(220.),
                run,
            ),
            test_write: false,
            confirm_set: None,
            tx,
            rx,
            busy: false,
            cancel: Arc::new(AtomicBool::new(false)),
            polling: None,
            status: "SNMP v1 / v2c over UDP 161. Enter a host and press Run.".into(),
            error: None,
            info: None,
            ifs: Vec::new(),
            rates: BTreeMap::new(),
            vbs: Vec::new(),
            findings: Vec::new(),
            hits: Vec::new(),
            _poll: poll,
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) {
        let mut changed = false;
        while let Ok(ev) = self.rx.try_recv() {
            changed = true;
            match ev {
                Ev::Info(i) => self.info = Some(i),
                Ev::Ifs(v) => self.ifs = v,
                Ev::Rates(r) => self.rates = r,
                Ev::Vbs(v, note) => {
                    self.status = format!(
                        "{} value(s){}",
                        v.len(),
                        note.map(|n| format!(" — {n}")).unwrap_or_default()
                    )
                    .into();
                    self.vbs = v;
                }
                Ev::Findings(f) => self.findings = f,
                Ev::Hit(h) => {
                    self.hits.push(h);
                    self.hits.sort_by_key(|h| h.ip);
                }
                Ev::Status(s) => self.status = s.into(),
                Ev::Error(e) => {
                    self.error = Some(e);
                    self.busy = false;
                }
                Ev::Done(s) => {
                    self.busy = false;
                    if !s.is_empty() {
                        self.status = s.into();
                    }
                }
            }
        }
        if changed {
            cx.notify();
        }
    }

    fn session(&self, cx: &App) -> Result<Session, String> {
        let addr = snmp::resolve(&self.host.read(cx).value)?;
        Ok(Session::new(
            addr,
            self.community.read(cx).value.trim(),
            self.version,
        ))
    }

    fn start(&mut self) -> Option<Sender<Ev>> {
        if self.busy {
            return None;
        }
        self.busy = true;
        self.error = None;
        self.cancel = Arc::new(AtomicBool::new(false));
        Some(self.tx.clone())
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        match self.mode {
            Mode::Summary => self.summary(cx),
            Mode::Query => self.query(QueryOp::Walk, cx),
            Mode::Communities => self.check(cx),
            Mode::V3 => self.v3(cx),
            Mode::Sweep => self.sweep(cx),
        }
    }

    fn summary(&mut self, cx: &mut Context<Self>) {
        let s = match self.session(cx) {
            Ok(s) => s,
            Err(e) => return self.error = Some(e),
        };
        let Some(tx) = self.start() else { return };
        self.stop_polling();
        self.info = None;
        self.ifs.clear();
        self.rates.clear();
        self.status = format!("Querying {}…", s.addr).into();
        std::thread::spawn(move || {
            match snmp::system_info(&s) {
                Ok(i) => {
                    let _ = tx.send(Ev::Info(i));
                }
                Err(e) => {
                    let _ = tx.send(Ev::Error(e));
                    return;
                }
            }
            let _ = tx.send(Ev::Status("Reading the interface table…".into()));
            let ifs = snmp::interfaces(&s);
            let n = ifs.len();
            let _ = tx.send(Ev::Ifs(ifs));
            let _ = tx.send(Ev::Done(format!("{n} interface(s)")));
        });
    }

    fn stop_polling(&mut self) {
        if let Some(p) = self.polling.take() {
            p.store(true, Ordering::Relaxed);
        }
    }

    fn toggle_polling(&mut self, cx: &mut Context<Self>) {
        if self.polling.is_some() {
            self.stop_polling();
            self.rates.clear();
            return;
        }
        let s = match self.session(cx) {
            Ok(s) => s,
            Err(e) => return self.error = Some(e),
        };
        let hc = self.ifs.iter().any(|r| r.hc);
        let stop = Arc::new(AtomicBool::new(false));
        self.polling = Some(stop.clone());
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let mut prev: Option<(Instant, Counters)> = None;
            while !stop.load(Ordering::Relaxed) {
                let now = Instant::now();
                let c = snmp::counters(&s, hc);
                if let Some((t0, p)) = &prev {
                    let dt = now.duration_since(*t0).as_secs_f64().max(0.001);
                    let rates = c
                        .iter()
                        .filter_map(|(k, (i, o))| {
                            let (pi, po) = p.get(k)?;
                            Some((
                                *k,
                                (
                                    snmp::counter_delta(*pi, *i, hc) as f64 * 8.0 / dt,
                                    snmp::counter_delta(*po, *o, hc) as f64 * 8.0 / dt,
                                ),
                            ))
                        })
                        .collect();
                    if tx.send(Ev::Rates(rates)).is_err() {
                        break;
                    }
                }
                prev = Some((now, c));
                for _ in 0..50 {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    fn query(&mut self, op: QueryOp, cx: &mut Context<Self>) {
        let s = match self.session(cx) {
            Ok(s) => s,
            Err(e) => return self.error = Some(e),
        };
        let oid = match snmp::parse_oid(&self.oid.read(cx).value) {
            Ok(o) => o,
            Err(e) => return self.error = Some(e),
        };
        if op == QueryOp::Bulk && self.version == Version::V1 {
            self.error = Some("GetBulk needs SNMP v2c".into());
            return;
        }
        let Some(tx) = self.start() else { return };
        self.vbs.clear();
        let cancel = self.cancel.clone();
        self.status = format!("{} {}…", op.label(), oid_name(&oid)).into();
        std::thread::spawn(move || {
            let r = match op {
                QueryOp::Get => s.get(&[oid]).map(|v| (v, None)),
                QueryOp::Next => s.get_next(&[oid]).map(|v| (v, None)),
                QueryOp::Bulk => s.get_bulk(0, 30, &[oid]).map(|v| (v, None)),
                QueryOp::Walk => {
                    let t = tx.clone();
                    s.walk(&oid, 100_000, |n| {
                        let _ = t.send(Ev::Status(format!("Walking… {n} values")));
                        !cancel.load(Ordering::Relaxed)
                    })
                    .map(|w| (w.vbs, w.note))
                }
            };
            let _ = tx.send(match r {
                Ok((v, note)) => Ev::Vbs(v, note),
                Err(e) => Ev::Error(e),
            });
            let _ = tx.send(Ev::Done(String::new()));
        });
    }

    fn set(&mut self, confirmed: bool, cx: &mut Context<Self>) {
        let s = match self.session(cx) {
            Ok(s) => s,
            Err(e) => return self.error = Some(e),
        };
        let oid = match snmp::parse_oid(&self.oid.read(cx).value) {
            Ok(o) => o,
            Err(e) => return self.error = Some(e),
        };
        let value = match snmp::parse_set_value(
            &self.set_type.read(cx).value,
            &self.set_value.read(cx).value,
        ) {
            Ok(v) => v,
            Err(e) => return self.error = Some(e),
        };
        if !confirmed {
            self.confirm_set = Some(format!(
                "Write {} = {} ({}) on {}?",
                oid_name(&oid),
                value,
                value.type_name(),
                s.addr
            ));
            return;
        }
        self.confirm_set = None;
        let Some(tx) = self.start() else { return };
        std::thread::spawn(move || {
            let r = s.set(&oid, value);
            let _ = tx.send(match r {
                Ok(v) => Ev::Vbs(v, Some("Set accepted".into())),
                Err(e) => Ev::Error(format!("Set failed: {e}")),
            });
            let _ = tx.send(Ev::Done(String::new()));
        });
    }

    fn check(&mut self, cx: &mut Context<Self>) {
        let addr = match snmp::resolve(&self.host.read(cx).value) {
            Ok(a) => a,
            Err(e) => return self.error = Some(e),
        };
        let list: Vec<String> = self
            .communities
            .read(cx)
            .value
            .split([',', '\n'])
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect();
        if list.is_empty() {
            self.error = Some("enter one or more communities".into());
            return;
        }
        let Some(tx) = self.start() else { return };
        self.findings.clear();
        let write = self.test_write;
        std::thread::spawn(move || {
            let t = tx.clone();
            let (found, f) = snmp::check_communities(addr, &list, write, |s| {
                let _ = t.send(Ev::Status(s));
            });
            let _ = tx.send(Ev::Findings(f));
            let _ = tx.send(Ev::Done(format!(
                "{} of {} communities accepted",
                found.len(),
                list.len()
            )));
        });
    }

    fn v3(&mut self, cx: &mut Context<Self>) {
        let addr = match snmp::resolve(&self.host.read(cx).value) {
            Ok(a) => a,
            Err(e) => return self.error = Some(e),
        };
        let Some(tx) = self.start() else { return };
        self.findings.clear();
        self.status = format!("SNMPv3 discovery to {addr}…").into();
        std::thread::spawn(move || {
            match snmp::v3_discover(addr, Duration::from_secs(2)) {
                Ok(e) => {
                    let _ = tx.send(Ev::Findings(snmp::engine_findings(&e)));
                    let _ = tx.send(Ev::Done("SNMPv3 agent found".into()));
                }
                Err(e) => {
                    let _ = tx.send(Ev::Error(e));
                }
            };
        });
    }

    fn sweep(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            self.cancel.store(true, Ordering::Relaxed);
            return;
        }
        let ips = match crate::netinfo::parse_range(&self.range.read(cx).value) {
            Ok(v) => v,
            Err(e) => return self.error = Some(e),
        };
        let community = self.community.read(cx).value.trim().to_string();
        let version = self.version;
        let Some(tx) = self.start() else { return };
        self.hits.clear();
        let cancel = self.cancel.clone();
        let total = ips.len();
        std::thread::spawn(move || {
            let t1 = tx.clone();
            let t2 = tx.clone();
            let r = snmp::sweep(
                &ips,
                &community,
                version,
                Duration::from_millis(1500),
                &cancel,
                |h| {
                    let _ = t1.send(Ev::Hit(h));
                },
                |n| {
                    let _ = t2.send(Ev::Status(format!(
                        "Sweeping… {}/{}",
                        n.min(total * 2),
                        total * 2
                    )));
                },
            );
            let _ = tx.send(match r {
                Ok(n) => Ev::Done(format!(
                    "{n} SNMP agent(s) answered '{community}' in {total} addresses"
                )),
                Err(e) => Ev::Error(e),
            });
        });
    }

    // ------------------------------------------------------------ rendering

    fn summary_body(&self, view: &gpui::WeakEntity<Self>) -> gpui::AnyElement {
        let Some(info) = &self.info else {
            return empty_state(
                if self.busy {
                    "Querying…"
                } else {
                    "No device yet"
                },
                "Reads the system group and the interface table.",
            )
            .into_any_element();
        };
        let polling = self.polling.is_some();
        let cols: [(&str, f32); 9] = [
            ("IDX", 50.),
            ("INTERFACE", 0.),
            ("TYPE", 110.),
            ("MBIT/S", 80.),
            ("ADMIN", 70.),
            ("OPER", 110.),
            (if polling { "IN RATE" } else { "IN" }, 110.),
            (if polling { "OUT RATE" } else { "OUT" }, 110.),
            ("ERR / DISC", 100.),
        ];
        div()
            .id("snmp-summary")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .p_4()
                    .rounded_md()
                    .bg(rgb(C::PANEL))
                    .border_1()
                    .border_color(rgb(C::BORDER))
                    .text_sm()
                    .child(section_title("System"))
                    .child(kv_row("Name", info.name.clone(), 130.))
                    .child(kv_row("Description", info.descr.clone(), 130.))
                    .child(kv_row(
                        "Object ID",
                        format!(
                            "{} {}",
                            info.object_id,
                            info.vendor.clone().unwrap_or_default()
                        ),
                        130.,
                    ))
                    .child(kv_row(
                        "Uptime",
                        info.uptime.map(snmp::ticks).unwrap_or_else(|| "-".into()),
                        130.,
                    ))
                    .child(kv_row("Contact", info.contact.clone(), 130.))
                    .child(kv_row("Location", info.location.clone(), 130.))
                    .when_some(info.services, |d, s| {
                        d.child(kv_row("Services", snmp::services_text(s), 130.))
                    })
                    .child(kv_row("Response", format!("{:.1} ms", info.rtt_ms), 130.)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(section_title(&format!("Interfaces ({})", self.ifs.len())))
                    .child(if polling {
                        button(
                            "snmp-poll",
                            "■ Stop rates",
                            C::RED,
                            C::RED_HOVER,
                            act(view, |t: &mut Self, _, cx| t.toggle_polling(cx)),
                        )
                    } else {
                        button2(
                            "snmp-poll",
                            "Poll rates (5 s)",
                            act(view, |t: &mut Self, _, cx| t.toggle_polling(cx)),
                        )
                    })
                    .when(polling && self.rates.is_empty(), |d| {
                        d.child(label("first sample in 5 s…"))
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(C::BORDER))
                    .child(table_header(&cols))
                    .children(self.ifs.iter().enumerate().map(|(i, r)| {
                        let oper_c = match r.oper {
                            1 => C::GREEN,
                            2 if r.admin == 1 => C::RED,
                            _ => C::MUTED,
                        };
                        let (inv, outv) = match self.rates.get(&r.index) {
                            Some((a, b)) if polling => (mbit(*a), mbit(*b)),
                            _ => (bytes(r.in_octets), bytes(r.out_octets)),
                        };
                        let errs = r.in_errors + r.out_errors;
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(30.))
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(cell(50., r.index.to_string()).text_color(rgb(C::MUTED)))
                            .child(cell(
                                0.,
                                if r.alias.is_empty() {
                                    r.label()
                                } else {
                                    format!("{} — {}", r.label(), r.alias)
                                },
                            ))
                            .child(cell(110., if_type_name(r.if_type)))
                            .child(cell(80., r.speed_mbps.to_string()))
                            .child(cell(70., status_name(r.admin)))
                            .child(cell(110., status_name(r.oper)).text_color(rgb(oper_c)))
                            .child(cell(110., inv))
                            .child(cell(110., outv))
                            .child(
                                cell(100., format!("{errs} / {}", r.in_discards + r.out_discards))
                                    .text_color(rgb(if errs > 0 { C::AMBER } else { C::MUTED })),
                            )
                    })),
            )
            .into_any_element()
    }

    fn vbs_body(&self) -> gpui::AnyElement {
        if self.vbs.is_empty() {
            return empty_state(
                if self.busy {
                    "Working…"
                } else {
                    "No results"
                },
                "Get / GetNext / GetBulk / Walk an OID. Names like sysDescr.0, ifTable or \
                 enterprises are accepted.",
            )
            .into_any_element();
        }
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .child(table_header(&[
                ("OID", 280.),
                ("NAME", 250.),
                ("TYPE", 110.),
                ("VALUE", 0.),
            ]))
            .child(
                div()
                    .id("snmp-vbs")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(self.vbs.iter().take(MAX_ROWS).enumerate().map(|(i, vb)| {
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(28.))
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(
                                cell(280., oid_str(&vb.oid))
                                    .font_family(mono())
                                    .text_color(rgb(C::MUTED)),
                            )
                            .child(cell(250., oid_name(&vb.oid)))
                            .child(cell(110., vb.value.type_name()).text_color(rgb(C::CYAN)))
                            .child(cell(0., vb.value.to_string().replace('\n', " ⏎ ")))
                    }))
                    .when(self.vbs.len() > MAX_ROWS, |d| {
                        d.child(div().p_3().child(label(format!(
                            "… {} more (use Copy for everything)",
                            self.vbs.len() - MAX_ROWS
                        ))))
                    }),
            )
            .into_any_element()
    }

    fn sweep_body(&self) -> gpui::AnyElement {
        if self.hits.is_empty() {
            return empty_state(
                if self.busy {
                    "Sweeping…"
                } else {
                    "No agents yet"
                },
                "Sends one sysDescr request per address with the community above (two passes).",
            )
            .into_any_element();
        }
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .child(table_header(&[
                ("ADDRESS", 130.),
                ("NAME", 180.),
                ("VENDOR", 160.),
                ("UPTIME", 130.),
                ("DESCRIPTION", 0.),
            ]))
            .child(
                div()
                    .id("snmp-hits")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(self.hits.iter().enumerate().map(|(i, h)| {
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(28.))
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(cell(130., h.ip.to_string()))
                            .child(cell(180., h.name.clone()))
                            .child(cell(160., h.vendor.clone()))
                            .child(cell(130., h.uptime.map(snmp::ticks).unwrap_or_default()))
                            .child(cell(0., h.descr.replace(['\n', '\r'], " ")))
                    })),
            )
            .into_any_element()
    }

    fn copy_text(&self) -> String {
        match self.mode {
            Mode::Summary => {
                let mut s = String::new();
                if let Some(i) = &self.info {
                    s.push_str(&format!(
                        "sysName: {}\nsysDescr: {}\nsysObjectID: {} {}\nsysUpTime: {}\nsysContact: {}\nsysLocation: {}\n\n",
                        i.name,
                        i.descr,
                        i.object_id,
                        i.vendor.clone().unwrap_or_default(),
                        i.uptime.map(snmp::ticks).unwrap_or_default(),
                        i.contact,
                        i.location
                    ));
                }
                for r in &self.ifs {
                    s.push_str(&format!(
                        "{}\t{}\t{}\t{} Mbit/s\t{}\t{}\tin {}\tout {}\terrors {}\n",
                        r.index,
                        r.label(),
                        if_type_name(r.if_type),
                        r.speed_mbps,
                        status_name(r.admin),
                        status_name(r.oper),
                        r.in_octets,
                        r.out_octets,
                        r.in_errors + r.out_errors
                    ));
                }
                s
            }
            Mode::Query => self
                .vbs
                .iter()
                .map(|v| {
                    format!(
                        "{} ({}) = {}: {}",
                        oid_str(&v.oid),
                        oid_name(&v.oid),
                        v.value.type_name(),
                        v.value
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
            Mode::Communities | Mode::V3 => findings_text(&self.findings),
            Mode::Sweep => self
                .hits
                .iter()
                .map(|h| format!("{}\t{}\t{}\t{}", h.ip, h.name, h.vendor, h.descr))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum QueryOp {
    Get,
    Next,
    Bulk,
    Walk,
}

impl QueryOp {
    fn label(self) -> &'static str {
        match self {
            QueryOp::Get => "Get",
            QueryOp::Next => "GetNext",
            QueryOp::Bulk => "GetBulk",
            QueryOp::Walk => "Walk",
        }
    }
}

fn bytes(n: u64) -> String {
    let f = n as f64;
    if f >= 1e12 {
        format!("{:.2} TB", f / 1e12)
    } else if f >= 1e9 {
        format!("{:.2} GB", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.1} MB", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.0} kB", f / 1e3)
    } else {
        format!("{n} B")
    }
}

impl Focusable for SnmpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Drop for SnmpView {
    fn drop(&mut self) {
        self.stop_polling();
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Render for SnmpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let mode = self.mode;
        let mode_chip = |id: &'static str, text: &'static str, m: Mode| {
            chip(
                id,
                text,
                mode == m,
                act(&view, move |t: &mut Self, _, _| {
                    t.mode = m;
                    t.error = None;
                    t.confirm_set = None;
                }),
            )
        };
        let ver_chip = |id: &'static str, v: Version| {
            chip(
                id,
                v.label(),
                self.version == v,
                act(&view, move |t: &mut Self, _, _| t.version = v),
            )
        };
        let run_label = match mode {
            Mode::Summary => "▶ Read device",
            Mode::Query => "▶ Walk",
            Mode::Communities => "▶ Check",
            Mode::V3 => "▶ Discover",
            Mode::Sweep => "▶ Sweep",
        };
        let run_btn = if self.busy && mode == Mode::Sweep {
            button(
                "snmp-run",
                "■ Stop",
                C::RED,
                C::RED_HOVER,
                act(&view, |t: &mut Self, _, cx| t.sweep(cx)),
            )
        } else if self.busy {
            button("snmp-run", "Working…", C::PANEL2, C::PANEL2, |_, _, _| {})
        } else {
            button_primary(
                "snmp-run",
                run_label,
                act(&view, |t: &mut Self, _, cx| t.run(cx)),
            )
        };
        let q = |id: &'static str, op: QueryOp| {
            button2(
                id,
                op.label(),
                act(&view, move |t: &mut Self, _, cx| t.query(op, cx)),
            )
        };
        let body = match mode {
            Mode::Summary => self.summary_body(&view),
            Mode::Query => self.vbs_body(),
            Mode::Sweep => self.sweep_body(),
            Mode::Communities | Mode::V3 if self.findings.is_empty() => empty_state(
                if self.busy {
                    "Working…"
                } else {
                    "No results"
                },
                if mode == Mode::V3 {
                    "Sends an unauthenticated SNMPv3 request; the agent's Report reveals its \
                     engine ID, boot count and uptime."
                } else {
                    "Tries each community with v2c and v1. Use only on devices you are \
                     authorised to test."
                },
            )
            .into_any_element(),
            Mode::Communities | Mode::V3 => div()
                .id("snmp-findings")
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .p_5()
                .child(findings_cards(&self.findings))
                .into_any_element(),
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(mode_chip("snmp-m-sum", "Device summary", Mode::Summary))
                    .child(mode_chip("snmp-m-q", "Get / Walk / Set", Mode::Query))
                    .child(mode_chip("snmp-m-c", "Community check", Mode::Communities))
                    .child(mode_chip("snmp-m-v3", "SNMPv3 engine", Mode::V3))
                    .child(mode_chip("snmp-m-sw", "Sweep", Mode::Sweep))
                    .child(div().w(px(10.)))
                    .when(mode != Mode::Sweep, |d| {
                        d.child(label("Host")).child(self.host.clone())
                    })
                    .when(mode == Mode::Sweep, |d| {
                        d.child(label("Range")).child(self.range.clone())
                    })
                    .when(
                        matches!(mode, Mode::Summary | Mode::Query | Mode::Sweep),
                        |d| {
                            d.child(label("Community"))
                                .child(self.community.clone())
                                .child(ver_chip("snmp-v1", Version::V1))
                                .child(ver_chip("snmp-v2", Version::V2c))
                        },
                    )
                    .when(mode == Mode::Communities, |d| {
                        d.child(label("Try"))
                            .child(self.communities.clone())
                            .child(chip(
                                "snmp-tw",
                                "Test write access",
                                self.test_write,
                                act(&view, |t: &mut Self, _, _| t.test_write = !t.test_write),
                            ))
                    })
                    .child(run_btn)
                    .child(copy_button("snmp-copy", self.copy_text())),
            )
            .when(mode == Mode::Query, |d| {
                d.child(
                    toolbar()
                        .child(label("OID"))
                        .child(self.oid.clone())
                        .child(q("snmp-get", QueryOp::Get))
                        .child(q("snmp-next", QueryOp::Next))
                        .child(q("snmp-bulk", QueryOp::Bulk))
                        .child(q("snmp-walk", QueryOp::Walk))
                        .when(self.busy, |d| {
                            d.child(button2(
                                "snmp-cancel",
                                "Stop",
                                act(&view, |t: &mut Self, _, _| {
                                    t.cancel.store(true, Ordering::Relaxed)
                                }),
                            ))
                        })
                        .child(div().w(px(16.)))
                        .child(label("Set type"))
                        .child(self.set_type.clone())
                        .child(self.set_value.clone())
                        .child(button(
                            "snmp-set",
                            "Set…",
                            C::PANEL2,
                            C::BORDER,
                            act(&view, |t: &mut Self, _, cx| t.set(false, cx)),
                        ))
                        .child(label(
                            "i int · u gauge · t ticks · a IP · o OID · s text · x hex",
                        )),
                )
            })
            .when(mode == Mode::Communities && self.test_write, |d| {
                d.child(
                    div()
                        .px_5()
                        .py_2()
                        .text_sm()
                        .text_color(rgb(C::AMBER))
                        .bg(alpha(C::AMBER, 0.08))
                        .child(
                            "Write test: reads sysLocation.0 and writes the same value back. \
                             Nothing changes, but the device may log the write.",
                        ),
                )
            })
            .children(self.confirm_set.clone().map(|msg| {
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_5()
                    .py_2()
                    .bg(alpha(C::AMBER, 0.10))
                    .text_sm()
                    .child(div().text_color(rgb(C::AMBER)).child(msg))
                    .child(button(
                        "snmp-set-yes",
                        "Write",
                        C::RED,
                        C::RED_HOVER,
                        act(&view, |t: &mut Self, _, cx| t.set(true, cx)),
                    ))
                    .child(button2(
                        "snmp-set-no",
                        "Cancel",
                        act(&view, |t: &mut Self, _, _| t.confirm_set = None),
                    ))
            }))
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .child(e)
            }))
            .child(div().flex().flex_col().flex_1().min_h_0().child(body))
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
