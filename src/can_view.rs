//! CAN Bus Analyser: SocketCAN / slcan monitor with a frame log, per-ID
//! table (rate, period jitter, changing bytes), bus load, filters and a
//! one-shot / periodic sender.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, ScrollStrategy, SharedString, Task,
    UniformListScrollHandle, Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::can::{self, Backend, CanEvent, CanHandle, Frame, IdStats};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, copy_button,
    empty_state, input, label, mono, status_bar, table_header, tile, tip, toolbar,
};

const MAX_LOG: usize = 20_000;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    SocketCan,
    Slcan,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Log,
    ById,
}

pub struct CanView {
    focus: FocusHandle,
    kind: Kind,
    sock_ifaces: Vec<(String, String)>,
    sock_sel: Option<usize>,
    ports: Vec<String>,
    port_sel: Option<usize>,
    bitrate: u32,
    listen_only: bool,
    data_bitrate: Entity<TextInput>,
    filter: Entity<TextInput>,
    send: Entity<TextInput>,
    period: Entity<TextInput>,
    handle: Option<CanHandle>,
    opened: Option<String>,
    log: VecDeque<Frame>,
    ids: BTreeMap<(bool, u32), IdStats>,
    window_bits: VecDeque<(f64, f64)>,
    load: f64,
    total: u64,
    errors: u64,
    periodic_on: bool,
    tab: Tab,
    paused: bool,
    follow: bool,
    scroll: UniformListScrollHandle,
    t0: Option<f64>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl CanView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let sock_ifaces = can::socketcan_interfaces();
        let ports: Vec<String> = crate::serial::list_ports()
            .map(|l| l.into_iter().map(|p| p.name).collect())
            .unwrap_or_default();
        let kind = if sock_ifaces.is_empty() && !ports.is_empty() || !cfg!(target_os = "linux") {
            Kind::Slcan
        } else {
            Kind::SocketCan
        };
        let mut v = Self {
            focus: cx.focus_handle(),
            kind,
            sock_sel: (!sock_ifaces.is_empty()).then_some(0),
            sock_ifaces,
            port_sel: (!ports.is_empty()).then_some(0),
            ports,
            bitrate: 500_000,
            listen_only: false,
            data_bitrate: input(
                window,
                cx,
                "2000000",
                "data bit/s",
                Accept::Digits,
                |t| t.width(100.).max_len(8),
                |_: &mut Self, _, _| {},
            ),
            filter: input(
                window,
                cx,
                "",
                "ID filter: 123, 100:7F0, 100-1FF",
                Accept::Any,
                |t| t.width(220.).max_len(40).mono(),
                |_: &mut Self, _, _| {},
            ),
            send: input(
                window,
                cx,
                "123#DEADBEEF",
                "123#11223344, 1ABCDEF0#R, 123##1AABB (FD)",
                Accept::Any,
                |t| t.width(300.).max_len(160).mono(),
                |t: &mut Self, _, cx| t.send_now(cx),
            ),
            period: input(
                window,
                cx,
                "100",
                "ms",
                Accept::Digits,
                |t| t.width(70.).max_len(6),
                |_: &mut Self, _, _| {},
            ),
            handle: None,
            opened: None,
            log: VecDeque::new(),
            ids: BTreeMap::new(),
            window_bits: VecDeque::new(),
            load: 0.0,
            total: 0,
            errors: 0,
            periodic_on: false,
            tab: Tab::Log,
            paused: false,
            follow: true,
            scroll: UniformListScrollHandle::new(),
            t0: None,
            status: "".into(),
            error: None,
            _poll: None,
        };
        v.status = v.hint().into();
        v
    }

    fn hint(&self) -> String {
        if !cfg!(target_os = "linux") {
            "SocketCAN is Linux-only; on this system connect an slcan (Lawicel ASCII) adapter, e.g. CANable or USBtin.".into()
        } else if self.sock_ifaces.is_empty() {
            "No SocketCAN interfaces found. Bring one up (sudo ip link set can0 up type can bitrate 500000) or use an slcan adapter.".into()
        } else {
            "Choose an interface and press Open. SocketCAN bit rate is set with `ip link`.".into()
        }
    }

    fn refresh(&mut self) {
        self.sock_ifaces = can::socketcan_interfaces();
        self.ports = crate::serial::list_ports()
            .map(|l| l.into_iter().map(|p| p.name).collect())
            .unwrap_or_default();
        self.sock_sel = (!self.sock_ifaces.is_empty()).then_some(0);
        self.port_sel = (!self.ports.is_empty()).then_some(0);
        self.status = self.hint().into();
    }

    fn backend(&self) -> Option<Backend> {
        match self.kind {
            Kind::SocketCan => self
                .sock_sel
                .and_then(|i| self.sock_ifaces.get(i))
                .map(|(n, _)| Backend::SocketCan(n.clone())),
            Kind::Slcan => self
                .port_sel
                .and_then(|i| self.ports.get(i))
                .map(|p| Backend::Slcan {
                    port: p.clone(),
                    baud: 115_200,
                    bitrate: self.bitrate,
                    listen_only: self.listen_only,
                }),
        }
    }

    fn open(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let Some(b) = self.backend() else {
            self.error = Some(match self.kind {
                Kind::SocketCan => "Select a SocketCAN interface".into(),
                Kind::Slcan => "Select a serial port".into(),
            });
            return;
        };
        if let Backend::SocketCan(n) = &b {
            let (nominal, data) = can::socketcan_bitrates(n);
            if let Some(nominal) = nominal {
                self.bitrate = nominal;
            }
            if let Some(d) = data {
                self.data_bitrate
                    .update(cx, |t, cx| t.set(d.to_string(), cx));
            }
        }
        self.error = None;
        self.status = format!("Opening {}…", b.label()).into();
        self.handle = Some(can::open(b));
        self.periodic_on = false;
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                match this.update(cx, |t, cx| t.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn close(&mut self) {
        if let Some(h) = &self.handle {
            h.close();
        }
    }

    fn clear(&mut self) {
        self.log.clear();
        self.ids.clear();
        self.window_bits.clear();
        self.total = 0;
        self.errors = 0;
        self.t0 = None;
    }

    fn data_ratio(&self, cx: &App) -> f64 {
        let d: f64 = self.data_bitrate.read(cx).value.parse().unwrap_or(0.0);
        if d > 0.0 {
            self.bitrate as f64 / d
        } else {
            1.0
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let ratio = self.data_ratio(cx);
        let mut closed = None;
        let mut got = false;
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                CanEvent::Opened(d) => {
                    self.status = format!("Open: {d}").into();
                    self.opened = Some(d);
                }
                CanEvent::Frames(fs) => {
                    for f in fs {
                        got = true;
                        self.t0.get_or_insert(f.ts);
                        self.total += 1;
                        if f.err {
                            self.errors += 1;
                        } else {
                            self.window_bits.push_back((f.ts, f.wire_bits(ratio)));
                            self.ids.entry((f.ext, f.id)).or_default().update(&f);
                        }
                        if !self.paused {
                            if self.log.len() >= MAX_LOG {
                                self.log.pop_front();
                            }
                            self.log.push_back(f);
                        }
                    }
                }
                CanEvent::Warning(w) => self.error = Some(w),
                CanEvent::Closed(e) => closed = Some(e),
            }
        }
        let now = can::now();
        while self.window_bits.front().is_some_and(|(t, _)| now - t > 1.0) {
            self.window_bits.pop_front();
        }
        let bits: f64 = self.window_bits.iter().map(|(_, b)| b).sum();
        self.load = if self.bitrate > 0 {
            bits / self.bitrate as f64
        } else {
            0.0
        };
        if got && self.follow && self.tab == Tab::Log {
            let filt = self.filt(cx);
            let n = self.log.iter().filter(|f| can::filter_ok(f, filt)).count();
            if n > 0 {
                self.scroll.scroll_to_item(n - 1, ScrollStrategy::Bottom);
            }
        }
        if let Some(e) = closed {
            self.handle = None;
            self.periodic_on = false;
            self.opened = None;
            match e {
                Some(e) => {
                    self.error = Some(e);
                    self.status = "Closed with an error".into();
                }
                None => self.status = format!("Closed — {} frames", self.total).into(),
            }
            cx.notify();
            return false;
        }
        cx.notify();
        true
    }

    fn parse_send(&mut self, cx: &App) -> Option<Frame> {
        match can::parse_cansend(&self.send.read(cx).value) {
            Ok(f) => Some(f),
            Err(e) => {
                self.error = Some(e);
                None
            }
        }
    }

    fn send_now(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_none() {
            self.error = Some("Open an interface first".into());
            return;
        }
        let Some(f) = self.parse_send(cx) else { return };
        self.error = None;
        if let Some(h) = &self.handle {
            h.send(f);
        }
    }

    fn toggle_periodic(&mut self, cx: &mut Context<Self>) {
        let Some(h) = &self.handle else {
            self.error = Some("Open an interface first".into());
            return;
        };
        if self.periodic_on {
            h.periodic(None);
            self.periodic_on = false;
            return;
        }
        let ms: u64 = self.period.read(cx).value.parse().unwrap_or(0);
        if ms == 0 {
            self.error = Some("Enter a period in milliseconds".into());
            return;
        }
        let Some(f) = self.parse_send(cx) else { return };
        if let Some(h) = &self.handle {
            h.periodic(Some((f, Duration::from_millis(ms))));
        }
        self.periodic_on = true;
        self.error = None;
    }

    fn filt(&self, cx: &App) -> Option<(u32, u32, bool)> {
        can::parse_filter(&self.filter.read(cx).value).unwrap_or(None)
    }

    fn render_log_row(&self, f: &Frame, i: usize) -> gpui::AnyElement {
        let t = f.ts - self.t0.unwrap_or(f.ts);
        let (data, color) = if f.err {
            (can::describe_error(f), C::RED)
        } else if f.rtr {
            (format!("remote request ({} bytes)", f.rtr_len), C::PURPLE)
        } else {
            (f.hex(), C::TEXT)
        };
        div()
            .flex()
            .items_center()
            .px_3()
            .h(px(24.))
            .text_sm()
            .font_family(mono())
            .bg(if f.err {
                alpha(C::RED, 0.08)
            } else {
                rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }).into()
            })
            .child(cell(110., format!("{t:.6}")).text_color(rgb(C::MUTED)))
            .child(
                cell(40., if f.tx { "TX" } else { "RX" }).text_color(rgb(if f.tx {
                    C::AMBER
                } else {
                    C::CYAN
                })),
            )
            .child(cell(100., f.id_str()).text_color(rgb(C::ACCENT)))
            .child(cell(50., f.dlc().to_string()))
            .child(cell(0., data).text_color(rgb(color)))
            .child(
                cell(
                    110.,
                    if f.err {
                        String::new()
                    } else {
                        can::ascii(&f.data)
                    },
                )
                .text_color(rgb(C::MUTED)),
            )
            .child(cell(110., f.flags()).text_color(rgb(C::MUTED)))
            .into_any_element()
    }

    fn render_ids(&self, filt: Option<(u32, u32, bool)>) -> impl IntoElement {
        let now = can::now();
        let rows: Vec<&IdStats> = self
            .ids
            .values()
            .filter(|s| filter_ok_id(s, filt))
            .collect();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .child(table_header(&[
                ("ID", 100.),
                ("COUNT", 90.),
                ("RATE", 90.),
                ("PERIOD", 100.),
                ("JITTER", 90.),
                ("MIN / MAX", 150.),
                ("LAST DATA (changed bytes highlighted)", 0.),
            ]))
            .child(
                div()
                    .id("can-ids")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(rows.into_iter().enumerate().map(|(i, s)| {
                        let ms = |x: f64| format!("{:.1} ms", x * 1000.0);
                        let stale = now - s.last > 2.0 * s.period().unwrap_or(1.0).max(0.5);
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(26.))
                            .text_sm()
                            .font_family(mono())
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(
                                cell(
                                    100.,
                                    if s.ext {
                                        format!("{:08X}", s.id)
                                    } else {
                                        format!("{:03X}", s.id)
                                    },
                                )
                                .text_color(rgb(if stale {
                                    C::MUTED
                                } else {
                                    C::ACCENT
                                })),
                            )
                            .child(cell(90., s.count.to_string()))
                            .child(cell(90., format!("{:.1}/s", s.rate())))
                            .child(cell(100., s.period().map(ms).unwrap_or_default()))
                            .child(cell(90., s.jitter().map(ms).unwrap_or_default()))
                            .child(cell(
                                150.,
                                if s.count > 1 {
                                    format!(
                                        "{:.1} / {:.1}",
                                        s.min_period * 1000.0,
                                        s.max_period * 1000.0
                                    )
                                } else {
                                    String::new()
                                },
                            ))
                            .child(
                                div()
                                    .flex_1()
                                    .flex()
                                    .gap(px(6.))
                                    .overflow_hidden()
                                    .children(s.last_data.iter().enumerate().map(|(j, b)| {
                                        let age = now - s.changed_at.get(j).copied().unwrap_or(0.0);
                                        let hot =
                                            s.count > 1 && age < 1.0 && s.changed_at[j] > s.first;
                                        div()
                                            .px(px(2.))
                                            .rounded_sm()
                                            .when(hot, |d| {
                                                d.bg(alpha(C::AMBER, 0.35))
                                                    .text_color(rgb(C::AMBER))
                                            })
                                            .child(format!("{b:02X}"))
                                    }))
                                    .when(s.tx, |d| {
                                        d.child(div().text_color(rgb(C::AMBER)).child("TX"))
                                    }),
                            )
                    })),
            )
    }
}

fn filter_ok_id(s: &IdStats, filt: Option<(u32, u32, bool)>) -> bool {
    let f = Frame::new(s.id, s.ext, Vec::new());
    can::filter_ok(&f, filt)
}

impl Focusable for CanView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for CanView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let open = self.handle.is_some();
        let filt_text = self.filter.read(cx).value.clone();
        let filt_err = can::parse_filter(&filt_text).is_err();
        let filt = self.filt(cx);
        let shown: Vec<usize> = (0..self.log.len())
            .filter(|&i| can::filter_ok(&self.log[i], filt))
            .collect();
        let load_color = if self.load > 0.7 {
            C::RED
        } else if self.load > 0.4 {
            C::AMBER
        } else {
            C::GREEN
        };
        let backend_row = match self.kind {
            Kind::SocketCan => div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap_2()
                .when(self.sock_ifaces.is_empty(), |d| {
                    d.child(label(if cfg!(target_os = "linux") {
                        "no CAN interfaces"
                    } else {
                        "SocketCAN is Linux-only"
                    }))
                })
                .children(self.sock_ifaces.iter().enumerate().map(|(i, (n, st))| {
                    chip(
                        ("can-if", i),
                        format!("{n} ({st})"),
                        self.sock_sel == Some(i),
                        act(&view, move |t: &mut Self, _, _| {
                            if t.handle.is_none() {
                                t.sock_sel = Some(i)
                            }
                        }),
                    )
                })),
            Kind::Slcan => div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap_2()
                .when(self.ports.is_empty(), |d| d.child(label("no serial ports")))
                .children(self.ports.iter().enumerate().map(|(i, p)| {
                    chip(
                        ("can-port", i),
                        p.clone(),
                        self.port_sel == Some(i),
                        act(&view, move |t: &mut Self, _, _| {
                            if t.handle.is_none() {
                                t.port_sel = Some(i)
                            }
                        }),
                    )
                }))
                .child(label("Bit rate"))
                .children(can::SLCAN_RATES.iter().map(|(r, _)| {
                    let r = *r;
                    chip(
                        ("can-br", r as usize),
                        if r >= 1_000_000 { "1M".to_string() } else { format!("{}k", r / 1000) },
                        self.bitrate == r,
                        act(&view, move |t: &mut Self, _, _| {
                            if t.handle.is_none() {
                                t.bitrate = r
                            }
                        }),
                    )
                }))
                .child(
                    chip(
                        "can-listen",
                        "Listen only",
                        self.listen_only,
                        act(&view, |t: &mut Self, _, _| {
                            if t.handle.is_none() {
                                t.listen_only = !t.listen_only
                            }
                        }),
                    )
                    .tooltip(tip("Open the adapter silently (L command): it never acknowledges or sends frames.")),
                ),
        };
        let log = if shown.is_empty() {
            empty_state(
                if open {
                    "Waiting for frames…"
                } else {
                    "Not connected"
                },
                if self.log.is_empty() {
                    "Open a CAN interface to see traffic."
                } else {
                    "No frames match the filter."
                },
            )
            .into_any_element()
        } else {
            let shown2 = shown.clone();
            uniform_list(
                "can-log",
                shown.len(),
                cx.processor(move |this, range: Range<usize>, _, _| {
                    range
                        .map(|i| this.render_log_row(&this.log[shown2[i]], i))
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };
        let copy_text = shown
            .iter()
            .rev()
            .take(2000)
            .rev()
            .map(|&i| {
                let f = &self.log[i];
                format!(
                    "({:.6}) {} {}",
                    f.ts,
                    if f.tx { "TX" } else { "RX" },
                    if f.err {
                        format!("ERROR {}", can::describe_error(f))
                    } else {
                        can::to_cansend(f)
                    }
                )
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
                    .child(chip("can-k-sock", "SocketCAN", self.kind == Kind::SocketCan, act(&view, |t: &mut Self, _, _| {
                        if t.handle.is_none() {
                            t.kind = Kind::SocketCan
                        }
                    })))
                    .child(chip("can-k-sl", "slcan (serial)", self.kind == Kind::Slcan, act(&view, |t: &mut Self, _, _| {
                        if t.handle.is_none() {
                            t.kind = Kind::Slcan
                        }
                    })))
                    .child(backend_row)
                    .child(div().flex_1())
                    .child(button2("can-refresh", "↻", act(&view, |t: &mut Self, _, _| {
                        if t.handle.is_none() {
                            t.refresh()
                        }
                    })).tooltip(tip("Rescan interfaces and serial ports")))
                    .child(if open {
                        button("can-open", "■ Close", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.close()))
                    } else {
                        button_primary("can-open", "▶ Open", act(&view, |t: &mut Self, _, cx| t.open(cx)))
                    }),
            )
            .child(
                toolbar()
                    .child(label("Send"))
                    .child(self.send.clone())
                    .child(button2("can-send", "Send", act(&view, |t: &mut Self, _, cx| t.send_now(cx))).tooltip(tip(
                        "cansend syntax: 123#DEADBEEF (standard), 12345678#00 (extended), 123#R (remote), 123##1AABB (CAN FD, flags 1 = bit-rate switch).",
                    )))
                    .child(label("every"))
                    .child(self.period.clone())
                    .child(label("ms"))
                    .child(if self.periodic_on {
                        button("can-per", "■ Stop periodic", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, cx| t.toggle_periodic(cx)))
                    } else {
                        button2("can-per", "Start periodic", act(&view, |t: &mut Self, _, cx| t.toggle_periodic(cx)))
                    })
                    .child(div().flex_1())
                    .child(label("Filter"))
                    .child(self.filter.clone())
                    .when(filt_err, |d| d.child(div().text_xs().text_color(rgb(C::RED)).child("invalid"))),
            )
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .child(e)
            }))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .px_5()
                    .py_3()
                    .items_center()
                    .child(tile("Frames", self.total.to_string(), C::TEXT))
                    .child(tile("IDs", self.ids.len().to_string(), C::ACCENT))
                    .child(tile(
                        "Frames/s",
                        format!("{}", self.window_bits.len()),
                        C::CYAN,
                    ))
                    .child(
                        tile("Bus load", format!("{:.1} %", self.load * 100.0), load_color).id("can-load").tooltip(tip(
                            "Estimated from frame lengths (with worst-case bit stuffing) over the last second, at the nominal bit rate. CAN FD data phases are scaled by the data bit rate.",
                        )),
                    )
                    .child(tile("Error frames", self.errors.to_string(), if self.errors > 0 { C::RED } else { C::MUTED }))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(label(format!("Nominal {} kbit/s", self.bitrate / 1000)))
                            .child(div().flex().items_center().gap_2().child(label("FD data")).child(self.data_bitrate.clone())),
                    )
                    .child(div().flex_1())
                    .child(chip("can-tab-log", "Frame log", self.tab == Tab::Log, act(&view, |t: &mut Self, _, _| t.tab = Tab::Log)))
                    .child(chip("can-tab-id", "By ID", self.tab == Tab::ById, act(&view, |t: &mut Self, _, _| t.tab = Tab::ById)))
                    .child(chip("can-follow", "Follow", self.follow, act(&view, |t: &mut Self, _, _| t.follow = !t.follow)))
                    .child(chip("can-pause", "Pause log", self.paused, act(&view, |t: &mut Self, _, _| t.paused = !t.paused)))
                    .child(button2("can-clear", "Clear", act(&view, |t: &mut Self, _, _| t.clear())))
                    .child(copy_button("can-copy", copy_text)),
            )
            .child(match self.tab {
                Tab::Log => div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .border_t_1()
                    .border_color(rgb(C::BORDER))
                    .child(table_header(&[
                        ("TIME (s)", 110.),
                        ("DIR", 40.),
                        ("ID", 100.),
                        ("DLC", 50.),
                        ("DATA", 0.),
                        ("ASCII", 110.),
                        ("FLAGS", 110.),
                    ]))
                    .child(log)
                    .into_any_element(),
                Tab::ById => self.render_ids(filt).into_any_element(),
            })
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .child(format!("{} in log{}", self.log.len(), if self.paused { " (paused)" } else { "" })),
            )
    }
}
