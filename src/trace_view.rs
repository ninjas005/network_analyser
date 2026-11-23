//! Traceroute tool.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::traceroute::{self, Hop, TraceConfig, TraceEvent, TraceHandle};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, cell, chip, copy_button, empty_state,
    input, label, mono, status_bar, table_header, toolbar,
};

const COLS: [(&str, f32); 10] = [
    ("HOP", 50.),
    ("ADDRESS", 200.),
    ("HOSTNAME", 0.),
    ("LOSS", 70.),
    ("LAST", 80.),
    ("AVG", 80.),
    ("BEST", 80.),
    ("WORST", 80.),
    ("", 10.),
    ("LATENCY", 220.),
];

pub struct TraceView {
    focus: FocusHandle,
    target: Entity<TextInput>,
    max_hops: Entity<TextInput>,
    rounds: Entity<TextInput>,
    timeout: Entity<TextInput>,
    ipv6: bool,
    names: bool,
    handle: Option<TraceHandle>,
    dest: Option<IpAddr>,
    hops: BTreeMap<u8, Hop>,
    reached: Option<bool>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl TraceView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let go = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.start(cx);
        Self {
            focus: cx.focus_handle(),
            target: input(
                window,
                cx,
                "",
                "Host or IP, e.g. 8.8.8.8 or example.com",
                Accept::Any,
                |t| t.width(320.),
                go,
            ),
            max_hops: input(
                window,
                cx,
                "30",
                "30",
                Accept::Digits,
                |t| t.width(56.).max_len(2),
                go,
            ),
            rounds: input(
                window,
                cx,
                "3",
                "3",
                Accept::Digits,
                |t| t.width(48.).max_len(2),
                go,
            ),
            timeout: input(
                window,
                cx,
                "2000",
                "ms",
                Accept::Digits,
                |t| t.width(70.).max_len(5),
                go,
            ),
            ipv6: false,
            names: true,
            handle: None,
            dest: None,
            hops: BTreeMap::new(),
            reached: None,
            status: "Enter a destination and press Trace.".into(),
            error: None,
            _poll: None,
        }
    }

    fn num(&self, e: &Entity<TextInput>, cx: &App, def: u64) -> u64 {
        e.read(cx).value.parse().unwrap_or(def)
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let target = self.target.read(cx).value.trim().to_string();
        if target.is_empty() {
            self.target.update(cx, |t, cx| {
                t.error = true;
                cx.notify()
            });
            return;
        }
        self.hops.clear();
        self.dest = None;
        self.reached = None;
        self.error = None;
        self.handle = Some(traceroute::start(TraceConfig {
            target: target.clone(),
            max_hops: self.num(&self.max_hops, cx, 30).clamp(1, 64) as u8,
            rounds: self.num(&self.rounds, cx, 3).clamp(1, 50) as u8,
            timeout: Duration::from_millis(self.num(&self.timeout, cx, 2000).clamp(200, 10_000)),
            resolve_names: self.names,
            ipv6: self.ipv6,
        }));
        self.status = format!("Tracing {target}…").into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
        cx.notify();
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let mut done = false;
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                TraceEvent::Resolved(ip) => {
                    self.dest = Some(ip);
                    self.status = format!("Tracing {ip}…").into();
                }
                TraceEvent::Hop(hop) => {
                    self.hops.insert(hop.ttl, hop);
                }
                TraceEvent::Error(e) => self.error = Some(e),
                TraceEvent::Finished { reached, elapsed } => {
                    done = true;
                    self.reached = Some(reached);
                    let n = self.hops.len();
                    self.status = if self.error.is_some() {
                        "Trace failed".into()
                    } else if reached {
                        format!(
                            "Reached {} in {n} hops ({:.1}s)",
                            self.dest.map(|d| d.to_string()).unwrap_or_default(),
                            elapsed.as_secs_f32()
                        )
                        .into()
                    } else {
                        format!("Destination not reached within {n} hops ({:.1}s) — ICMP may be filtered", elapsed.as_secs_f32()).into()
                    };
                }
            }
        }
        if done {
            self.handle = None;
        }
        cx.notify();
        !done
    }

    fn as_text(&self) -> String {
        let mut out = format!(
            "traceroute to {}\n",
            self.dest.map(|d| d.to_string()).unwrap_or_default()
        );
        for h in self.hops.values() {
            let rtts: Vec<String> = h
                .rtts
                .iter()
                .map(|r| r.map(|v| format!("{v:.1} ms")).unwrap_or("*".into()))
                .collect();
            out.push_str(&format!(
                "{:>2}  {:<40} {:<40} {}\n",
                h.ttl,
                h.addr.map(|a| a.to_string()).unwrap_or("*".into()),
                h.name.clone().unwrap_or_default(),
                rtts.join("  ")
            ));
        }
        out
    }

    fn row(&self, i: usize, h: &Hop, scale: f32) -> impl IntoElement {
        let stats = h.stats();
        let last = h.rtts.iter().rev().flatten().next().copied();
        let approx = if h.estimated { "≈" } else { "" };
        let ms = |v: Option<f32>| {
            v.map(|x| format!("{approx}{x:.1} ms"))
                .unwrap_or_else(|| "—".into())
        };
        let loss = h.loss_pct();
        let loss_color = if h.addr.is_none() || h.estimated {
            C::MUTED
        } else if loss >= 50.0 {
            C::RED
        } else if loss > 0.0 {
            C::AMBER
        } else {
            C::GREEN
        };
        let bar = stats
            .map(|(_, avg, _)| (avg / scale).clamp(0.02, 1.0))
            .unwrap_or(0.0);
        div()
            .flex()
            .flex_row()
            .items_center()
            .h(px(30.))
            .px_3()
            .text_sm()
            .bg(if h.reached {
                alpha(C::GREEN, 0.08)
            } else if i % 2 == 1 {
                rgb(C::ROW_ALT).into()
            } else {
                rgb(C::BG).into()
            })
            .child(cell(COLS[0].1, h.ttl.to_string()).text_color(rgb(C::MUTED)))
            .child(
                cell(
                    COLS[1].1,
                    h.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".into()),
                )
                .font_family(mono()),
            )
            .child(
                cell(
                    0.,
                    h.name.clone().unwrap_or_else(|| {
                        if h.addr.is_some() {
                            "—".into()
                        } else {
                            "no reply".into()
                        }
                    }),
                )
                .text_color(rgb(C::MUTED)),
            )
            .child(
                cell(
                    COLS[3].1,
                    if h.estimated {
                        "n/a".into()
                    } else if h.rtts.is_empty() {
                        "—".into()
                    } else {
                        format!("{loss:.0}%")
                    },
                )
                .text_color(rgb(loss_color)),
            )
            .child(cell(COLS[4].1, ms(last)))
            .child(cell(COLS[5].1, ms(stats.map(|s| s.1))))
            .child(cell(COLS[6].1, ms(stats.map(|s| s.0))).text_color(rgb(C::MUTED)))
            .child(cell(COLS[7].1, ms(stats.map(|s| s.2))).text_color(rgb(C::MUTED)))
            .child(div().w(px(COLS[8].1)))
            .child(
                div()
                    .w(px(COLS[9].1))
                    .h(px(8.))
                    .rounded_full()
                    .bg(rgb(C::PANEL2))
                    .child(
                        div()
                            .h_full()
                            .rounded_full()
                            .bg(rgb(if bar > 0.6 { C::AMBER } else { C::ACCENT }))
                            .w(px(COLS[9].1 * bar)),
                    ),
            )
    }
}

impl Focusable for TraceView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for TraceView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let scale = self
            .hops
            .values()
            .filter_map(|h| h.stats().map(|s| s.1))
            .fold(1.0f32, f32::max);
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Destination"))
                    .child(self.target.clone())
                    .child(label("Max hops"))
                    .child(self.max_hops.clone())
                    .child(label("Probes"))
                    .child(self.rounds.clone())
                    .child(label("Timeout ms"))
                    .child(self.timeout.clone())
                    .child(chip("tr-v6", "Prefer IPv6", self.ipv6, act(&view, |t: &mut Self, _, _| t.ipv6 = !t.ipv6)))
                    .child(chip("tr-names", "Resolve names", self.names, act(&view, |t: &mut Self, _, _| t.names = !t.names)))
                    .child(if running {
                        button("tr-go", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| {
                            if let Some(h) = &t.handle {
                                h.cancel();
                            }
                        }))
                    } else {
                        button_primary("tr-go", "▶ Trace", act(&view, |t: &mut Self, _, cx| t.start(cx)))
                    })
                    .child(copy_button("tr-copy", self.as_text())),
            )
            .children(self.error.clone().map(|e| div().px_5().py_2().text_sm().text_color(rgb(C::RED)).child(e)))
            .child(table_header(&COLS))
            .child(if self.hops.is_empty() {
                empty_state(
                    if running { "Tracing…" } else { "No trace yet" },
                    "Uses the system ping with increasing TTL (no admin rights needed); each hop is then timed with direct echoes.",
                )
                .into_any_element()
            } else {
                div()
                    .id("tr-rows")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(self.hops.values().enumerate().map(|(i, h)| self.row(i, h, scale)))
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
