//! ARP Spoof Detector, DNS Security checker and Network Anomaly Detector.

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::anomaly::{self, Detector};
use crate::arpwatch::{self, Binding, WatchEvent, WatchHandle};
use crate::capture::{self, CaptureConfig, CaptureEvent, CaptureHandle, Interface, Source};
use crate::gateway::{Finding, GwEvent, Level};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, cell, chip, copy_button, dot,
    empty_state, findings_cards, findings_text, input, label, level_color, mbit, section_title,
    status_bar, table_header, tile, toolbar,
};

fn clock(t: SystemTime) -> String {
    let s = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{:02}:{:02}:{:02} UTC", s / 3600 % 24, s / 60 % 60, s % 60)
}

fn capture_ifaces() -> (Result<Vec<Interface>, String>, Option<usize>) {
    let ifaces = capture::interfaces().map(|l| {
        l.into_iter()
            .filter(|i| i.up && !i.loopback && !i.addrs.is_empty() && !i.name.starts_with("veth"))
            .collect::<Vec<_>>()
    });
    let primary = crate::netinfo::local_interfaces()
        .first()
        .map(|i| i.ip.to_string());
    let iface = ifaces.as_ref().ok().and_then(|l| {
        l.iter()
            .position(|i| primary.as_ref().is_some_and(|p| i.addrs.contains(p)))
            .or((!l.is_empty()).then_some(0))
    });
    (ifaces, iface)
}

fn iface_chips<V: 'static>(
    view: &gpui::WeakEntity<V>,
    ifaces: &[Interface],
    current: Option<usize>,
    set: fn(&mut V, usize),
) -> gpui::Div {
    div()
        .flex()
        .flex_wrap()
        .gap_1()
        .children(ifaces.iter().enumerate().map(|(i, f)| {
            chip(
                ("if", i),
                if cfg!(windows) && !f.desc.is_empty() {
                    f.desc.clone()
                } else {
                    f.name.clone()
                },
                current == Some(i),
                act(view, move |t: &mut V, _, _| set(t, i)),
            )
        }))
}

// ---------------------------------------------------------------- ARP

pub struct ArpView {
    focus: FocusHandle,
    ifaces: Result<Vec<Interface>, String>,
    iface: Option<usize>,
    wire: bool,
    handle: Option<WatchHandle>,
    bindings: Vec<Binding>,
    alerts: Vec<arpwatch::Alert>,
    capture_state: Option<Result<String, String>>,
    started: Option<Instant>,
    _poll: Option<Task<()>>,
}

impl ArpView {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (ifaces, iface) = capture_ifaces();
        let mut v = Self {
            focus: cx.focus_handle(),
            ifaces,
            iface,
            wire: false,
            handle: None,
            bindings: Vec::new(),
            alerts: Vec::new(),
            capture_state: None,
            started: None,
            _poll: None,
        };
        v.start(cx);
        v
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        let device = if self.wire {
            self.iface
                .and_then(|i| self.ifaces.as_ref().ok()?.get(i).map(|f| f.name.clone()))
        } else {
            None
        };
        self.capture_state = None;
        self.handle = Some(arpwatch::start(device));
        self.started = Some(Instant::now());
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(300))
                    .await;
                let ok = this.update(cx, |t, cx| {
                    let Some(h) = &t.handle else { return false };
                    while let Ok(ev) = h.events.try_recv() {
                        match ev {
                            WatchEvent::Alert(a) => t.alerts.push(a),
                            WatchEvent::Bindings(b) => t.bindings = b,
                            WatchEvent::CaptureState(s) => t.capture_state = Some(s),
                        }
                    }
                    cx.notify();
                    true
                });
                if !matches!(ok, Ok(true)) {
                    break;
                }
            }
        }));
    }
}

impl Focusable for ArpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for ArpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let gw = crate::platform::default_gateway().map(|(_, g)| g);
        let bad = self.alerts.iter().filter(|a| a.level == Level::Bad).count();
        let ifaces = self.ifaces.as_ref().map(|l| l.as_slice()).unwrap_or(&[]);
        let text = self
            .alerts
            .iter()
            .map(|a| format!("{} {}", clock(a.at), a.text))
            .collect::<Vec<_>>()
            .join("\n");
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(chip("arp-wire", "Also watch ARP traffic", self.wire, act(&view, |t: &mut Self, _, cx| {
                        t.wire = !t.wire;
                        t.start(cx);
                    })))
                    .when(self.wire, |d| d.child(iface_chips(&view, ifaces, self.iface, |t: &mut Self, i| t.iface = Some(i))))
                    .child(div().flex_1())
                    .child(copy_button("arp-copy", text))
                    .child(button_primary("arp-restart", "⟲ Restart", act(&view, |t: &mut Self, _, cx| {
                        t.alerts.clear();
                        t.start(cx);
                    }))),
            )
            .children(match &self.capture_state {
                Some(Err(e)) => Some(div().px_5().py_2().text_sm().text_color(rgb(C::RED)).bg(alpha(C::RED, 0.08)).child(format!("Wire monitoring unavailable: {e}"))),
                Some(Ok(d)) => Some(div().px_5().py_2().text_sm().text_color(rgb(C::GREEN)).child(format!("Watching ARP on {d}"))),
                None => None,
            })
            .child(
                div()
                    .flex()
                    .gap_2()
                    .px_5()
                    .py_3()
                    .child(tile("Status", if bad > 0 { "SPOOFING SUSPECTED" } else if self.alerts.is_empty() { "No anomalies" } else { "Check alerts" }, if bad > 0 { C::RED } else if self.alerts.is_empty() { C::GREEN } else { C::AMBER }))
                    .child(tile("Gateway", gw.map(|g| g.to_string()).unwrap_or_else(|| "—".into()), C::TEXT))
                    .child(tile("Gateway MAC", gw.and_then(|g| self.bindings.iter().find(|b| b.ip == g)).map(|b| b.mac.clone()).unwrap_or_else(|| "—".into()), C::TEXT))
                    .child(tile("Bindings", self.bindings.len().to_string(), C::MUTED))
                    .child(tile("Alerts", self.alerts.len().to_string(), if self.alerts.is_empty() { C::MUTED } else { C::AMBER }))
                    .child(tile("Watching for", self.started.map(|s| format!("{}s", s.elapsed().as_secs())).unwrap_or_default(), C::MUTED)),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .id("arp-alerts")
                            .w(px(560.))
                            .flex_none()
                            .p_4()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .overflow_y_scroll()
                            .border_r_1()
                            .border_color(rgb(C::BORDER))
                            .child(section_title("Alerts"))
                            .when(self.alerts.is_empty(), |d| d.child(div().text_sm().text_color(rgb(C::MUTED)).child("None yet. The OS ARP table is polled every 2 s; enable traffic watching (capture rights) to also catch spoofed replies and floods as they happen.")))
                            .children(self.alerts.iter().rev().map(|a| {
                                div().flex().gap_2().text_sm().child(div().pt(px(6.)).child(dot(level_color(a.level)))).child(div().text_color(rgb(C::MUTED)).child(clock(a.at))).child(div().flex_1().min_w_0().child(a.text.clone()))
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(table_header(&[("IP", 150.), ("MAC", 170.), ("VENDOR", 0.), ("SINCE", 110.), ("SEEN", 70.), ("CHANGES", 200.)]))
                            .child(
                                div()
                                    .id("arp-binds")
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scroll()
                                    .children(self.bindings.iter().enumerate().map(|(i, b)| {
                                        let is_gw = Some(b.ip) == gw;
                                        div()
                                            .flex()
                                            .items_center()
                                            .px_3()
                                            .h(px(28.))
                                            .text_sm()
                                            .bg(if !b.history.is_empty() { alpha(C::AMBER, 0.10) } else { rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }).into() })
                                            .child(cell(150., if is_gw { format!("{} (gw)", b.ip) } else { b.ip.to_string() }))
                                            .child(cell(170., b.mac.clone()))
                                            .child(cell(0., crate::netinfo::mac_vendor(&b.mac).unwrap_or_default()).text_color(rgb(C::MUTED)))
                                            .child(cell(110., clock(b.first)).text_color(rgb(C::MUTED)))
                                            .child(cell(70., b.seen.to_string()).text_color(rgb(C::MUTED)))
                                            .child(cell(200., if b.history.is_empty() { String::new() } else { format!("was {}", b.history.join(", ")) }).text_color(rgb(C::AMBER)))
                                    })),
                            ),
                    ),
            )
    }
}

// ---------------------------------------------------------------- DNS security

pub struct DnsSecView {
    focus: FocusHandle,
    domain: Entity<TextInput>,
    selectors: Entity<TextInput>,
    resolver: Entity<TextInput>,
    rx: Option<Receiver<GwEvent>>,
    findings: Vec<Finding>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl DnsSecView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let run = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.run(cx);
        Self {
            focus: cx.focus_handle(),
            domain: input(window, cx, "", "example.com", Accept::Any, |t| t.width(260.), run),
            selectors: input(window, cx, "", "optional DKIM selectors", Accept::Any, |t| t.width(200.), run),
            resolver: input(window, cx, "", "optional: resolver IP to test as open resolver", Accept::Any, |t| t.width(300.), run),
            rx: None,
            findings: Vec::new(),
            status: "Checks name servers, zone transfer, DNSSEC, SPF, DMARC, DKIM, MTA-STS, CAA and your resolver.".into(),
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let domain = self.domain.read(cx).value.trim().to_string();
        if domain.is_empty() {
            return;
        }
        let sels: Vec<String> = self
            .selectors
            .read(cx)
            .value
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let resolver = self.resolver.read(cx).value.trim().parse().ok();
        self.findings.clear();
        self.rx = Some(crate::dnscheck::check(domain, sels, resolver));
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                let ok = this.update(cx, |t, cx| {
                    let Some(rx) = &t.rx else { return false };
                    let mut done = false;
                    while let Ok(ev) = rx.try_recv() {
                        match ev {
                            GwEvent::Finding(f) => t.findings.push(f),
                            GwEvent::Status(s) => t.status = s.into(),
                            GwEvent::Done => done = true,
                        }
                    }
                    if done {
                        t.rx = None;
                        let bad = t.findings.iter().filter(|f| f.level == Level::Bad).count();
                        let warn = t.findings.iter().filter(|f| f.level == Level::Warn).count();
                        t.status = format!("Done — {bad} problem(s), {warn} warning(s)").into();
                    }
                    cx.notify();
                    !done
                });
                if !matches!(ok, Ok(true)) {
                    break;
                }
            }
        }));
    }
}

impl Focusable for DnsSecView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for DnsSecView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.rx.is_some();
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Domain"))
                    .child(self.domain.clone())
                    .child(label("DKIM"))
                    .child(self.selectors.clone())
                    .child(self.resolver.clone())
                    .child(if busy {
                        button("ds-go", "Checking…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary(
                            "ds-go",
                            "▶ Check",
                            act(&view, |t: &mut Self, _, cx| t.run(cx)),
                        )
                    })
                    .child(copy_button("ds-copy", findings_text(&self.findings))),
            )
            .child(if self.findings.is_empty() {
                empty_state(
                    if busy { "Checking…" } else { "No check yet" },
                    "Enter a domain you manage or want to assess.",
                )
                .into_any_element()
            } else {
                div()
                    .id("ds-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_5()
                    .child(findings_cards(&self.findings))
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}

// ---------------------------------------------------------------- anomaly

pub struct AnomalyView {
    focus: FocusHandle,
    ifaces: Result<Vec<Interface>, String>,
    iface: Option<usize>,
    handle: Option<CaptureHandle>,
    linktype: i32,
    detector: Detector,
    alerts: Vec<anomaly::Alert>,
    started: Option<Instant>,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl AnomalyView {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (ifaces, iface) = capture_ifaces();
        let _ = cx;
        Self {
            focus: cx.focus_handle(),
            error: ifaces.as_ref().err().cloned(),
            ifaces,
            iface,
            handle: None,
            linktype: 1,
            detector: Detector::new(),
            alerts: Vec::new(),
            started: None,
            _poll: None,
        }
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            if let Some(h) = self.handle.take() {
                h.stop();
            }
            return;
        }
        let Some(iface) = self
            .iface
            .and_then(|i| self.ifaces.as_ref().ok()?.get(i).cloned())
        else {
            return;
        };
        self.detector = Detector::new();
        self.alerts.clear();
        self.error = None;
        self.handle = Some(capture::start(CaptureConfig {
            source: Source::Live {
                device: iface.name.clone(),
                promisc: true,
            },
            filter: String::new(),
            save_to: None,
        }));
        self.started = Some(Instant::now());
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                let ok = this.update(cx, |t, cx| {
                    let Some(h) = &t.handle else { return false };
                    let mut stopped = None;
                    let now = Instant::now();
                    while let Ok(ev) = h.events.try_recv() {
                        match ev {
                            CaptureEvent::Started { linktype, .. } => t.linktype = linktype,
                            CaptureEvent::Packets(pkts) => {
                                for p in &pkts {
                                    let a = t.detector.feed(p, t.linktype, now);
                                    t.alerts.extend(a);
                                }
                            }
                            CaptureEvent::Stopped(e) => stopped = Some(e),
                            _ => {}
                        }
                    }
                    if let Some(e) = stopped {
                        t.handle = None;
                        if let Some(e) = e {
                            t.error = Some(match capture::permission_hint(&e) {
                                Some(h) => format!("{e}\n{h}"),
                                None => e,
                            });
                        }
                        cx.notify();
                        return false;
                    }
                    // Close idle windows too.
                    if t.detector.totals.packets > 0 {
                        let extra = t.detector.feed_tick(now);
                        t.alerts.extend(extra);
                    }
                    cx.notify();
                    true
                });
                if !matches!(ok, Ok(true)) {
                    break;
                }
            }
        }));
    }
}

impl Focusable for AnomalyView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for AnomalyView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let tot = self.detector.totals.clone();
        let ifaces = self.ifaces.as_ref().map(|l| l.as_slice()).unwrap_or(&[]);
        let learning = self
            .started
            .is_some_and(|s| s.elapsed() < Duration::from_secs(60));
        let mut kinds: Vec<(&str, usize)> = Vec::new();
        for a in &self.alerts {
            match kinds.iter_mut().find(|k| k.0 == a.kind) {
                Some(k) => k.1 += 1,
                None => kinds.push((a.kind, 1)),
            }
        }
        let text = self
            .alerts
            .iter()
            .map(|a| format!("{} [{}] {}", clock(a.at), a.kind, a.text))
            .collect::<Vec<_>>()
            .join("\n");
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Interface"))
                    .child(iface_chips(&view, ifaces, self.iface, |t: &mut Self, i| {
                        if t.handle.is_none() {
                            t.iface = Some(i)
                        }
                    }))
                    .child(div().flex_1())
                    .child(copy_button("an-copy", text))
                    .child(if running {
                        button("an-go", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, cx| t.start(cx)))
                    } else {
                        button_primary("an-go", "▶ Start monitoring", act(&view, |t: &mut Self, _, cx| t.start(cx)))
                    }),
            )
            .children(self.error.clone().map(|e| div().px_5().py_2().text_sm().text_color(rgb(C::RED)).bg(alpha(C::RED, 0.08)).children(e.lines().map(|l| div().child(l.to_string())).collect::<Vec<_>>())))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .content_start()
                    .gap_2()
                    .px_5()
                    .py_3()
                    .child(tile("Traffic", mbit(tot.last_bps), C::TEXT))
                    .child(tile("Packets/s", format!("{:.0}", tot.last_pps), C::TEXT))
                    .child(tile("Packets", tot.packets.to_string(), C::MUTED))
                    .child(tile("Devices seen", tot.devices.to_string(), C::MUTED))
                    .child(tile("Alerts", self.alerts.len().to_string(), if self.alerts.iter().any(|a| a.level == Level::Bad) { C::RED } else if self.alerts.is_empty() { C::GREEN } else { C::AMBER }))
                    .children(kinds.into_iter().map(|(k, n)| tile(k, n.to_string(), C::AMBER)))
                    .when(running && learning, |d| d.child(label("Learning the network for the first minute (no new-device alerts yet)…"))),
            )
            .child(table_header(&[("TIME", 110.), ("", 20.), ("TYPE", 150.), ("DETAIL", 0.)]))
            .child(if self.alerts.is_empty() {
                empty_state(
                    if running { "Monitoring… no anomalies" } else { "Not monitoring" },
                    "Detects port scans, host sweeps, SYN / ICMP floods, broadcast and ARP storms, DHCP starvation, DNS tunnelling and NXDOMAIN bursts, duplicate IPs, clear-text logins, new devices and traffic spikes. Needs packet-capture rights.",
                )
                .into_any_element()
            } else {
                div()
                    .id("an-rows")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(self.alerts.iter().rev().enumerate().map(|(i, a)| {
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .min_h(px(28.))
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(cell(110., clock(a.at)).text_color(rgb(C::MUTED)))
                            .child(div().w(px(20.)).child(dot(level_color(a.level))))
                            .child(cell(150., a.kind))
                            .child(div().flex_1().min_w_0().child(a.text.clone()))
                    }))
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(if running {
                format!("Monitoring for {}s", self.started.map(|s| s.elapsed().as_secs()).unwrap_or(0))
            } else {
                "Stopped".into()
            })))
    }
}
