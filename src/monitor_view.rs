//! Latency Monitor, Jitter Tester, Packet Loss Tester and Uptime Monitor:
//! one view over the shared probe engine, laid out per purpose.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::monitor::{self, Kind, SeriesEvent, SeriesHandle, Stats, Target};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, bar_chart, bar_chart_slots, button, button_primary, chip,
    copy_button, dot, empty_state, input, label, section_title, status_bar, tile, tip, toolbar,
};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Purpose {
    Latency,
    Jitter,
    Loss,
    Uptime,
}

impl Purpose {
    fn defaults(self) -> (u64, Option<u64>, u64) {
        // (interval ms, count, timeout ms)
        match self {
            Purpose::Latency => (1000, None, 2000),
            Purpose::Jitter => (200, Some(150), 1500),
            Purpose::Loss => (200, Some(500), 1500),
            Purpose::Uptime => (10_000, None, 5000),
        }
    }
    fn intro(self) -> &'static str {
        match self {
            Purpose::Latency => "Round-trip time to several targets, continuously.",
            Purpose::Jitter => {
                "Latency variation (RFC 3550 jitter) and the voice-call quality it implies. Use TCP or UDP echo for intervals under 200 ms."
            }
            Purpose::Loss => {
                "Long probe series to measure loss and how losses cluster into bursts."
            }
            Purpose::Uptime => {
                "Checks every target at the interval; two failures in a row count as an outage."
            }
        }
    }
}

#[derive(Default)]
struct Series {
    /// seq -> result
    results: BTreeMap<u32, Result<f32, String>>,
    walls: BTreeMap<u32, SystemTime>,
    error: Option<String>,
    /// Uptime: (down since, back up at)
    outages: Vec<(SystemTime, Option<SystemTime>)>,
    fails_in_row: u32,
    down: bool,
}

impl Series {
    fn ordered(&self) -> Vec<Option<f32>> {
        self.results
            .values()
            .map(|r| r.as_ref().ok().copied())
            .collect()
    }
    fn last_error(&self) -> Option<&String> {
        self.results
            .values()
            .next_back()
            .and_then(|r| r.as_ref().err())
    }
}

pub struct MonitorView {
    purpose: Purpose,
    focus: FocusHandle,
    targets: Vec<Target>,
    kind: Kind,
    new_target: Entity<TextInput>,
    interval: Entity<TextInput>,
    count: Entity<TextInput>,
    timeout: Entity<TextInput>,
    handle: Option<SeriesHandle>,
    series: Vec<Series>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

fn fmt_ms(v: f32) -> String {
    if v >= 100.0 {
        format!("{v:.0} ms")
    } else {
        format!("{v:.1} ms")
    }
}

fn time_of(t: SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{:02}:{:02}:{:02} UTC",
        secs / 3600 % 24,
        secs / 60 % 60,
        secs % 60
    )
}

fn dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h {:02}m", s / 3600, s / 60 % 60)
    } else if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

impl MonitorView {
    pub fn new(purpose: Purpose, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (iv, count, to) = purpose.defaults();
        let add = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.add_target(cx);
        let mut targets = Vec::new();
        if let Some((_, gw)) = crate::platform::default_gateway() {
            targets.push(Target {
                kind: Kind::Icmp,
                text: gw.to_string(),
            });
        }
        if purpose != Purpose::Jitter && purpose != Purpose::Loss || targets.is_empty() {
            targets.push(Target {
                kind: Kind::Icmp,
                text: "1.1.1.1".into(),
            });
        }
        if purpose == Purpose::Uptime {
            targets.push(Target {
                kind: Kind::Dns,
                text: "1.1.1.1".into(),
            });
        }
        Self {
            purpose,
            focus: cx.focus_handle(),
            targets,
            kind: Kind::Icmp,
            new_target: input(
                window,
                cx,
                "",
                "target",
                Accept::Any,
                |t| t.width(200.),
                add,
            ),
            interval: input(
                window,
                cx,
                &iv.to_string(),
                "ms",
                Accept::Digits,
                |t| t.width(80.).max_len(7),
                |_: &mut Self, _, _| {},
            ),
            count: input(
                window,
                cx,
                &count.map(|c| c.to_string()).unwrap_or_default(),
                "∞",
                Accept::Digits,
                |t| t.width(70.).max_len(6),
                |_: &mut Self, _, _| {},
            ),
            timeout: input(
                window,
                cx,
                &to.to_string(),
                "ms",
                Accept::Digits,
                |t| t.width(70.).max_len(6),
                |_: &mut Self, _, _| {},
            ),
            handle: None,
            series: Vec::new(),
            status: purpose.intro().into(),
            _poll: None,
        }
    }

    fn add_target(&mut self, cx: &mut Context<Self>) {
        let text = self.new_target.read(cx).value.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.targets.push(Target {
            kind: self.kind,
            text,
        });
        self.new_target.update(cx, |t, cx| t.set("", cx));
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() || self.targets.is_empty() {
            return;
        }
        let num = |e: &Entity<TextInput>, cx: &App| e.read(cx).value.trim().parse::<u64>().ok();
        let min_iv = if self
            .targets
            .iter()
            .any(|t| matches!(t.kind, Kind::Icmp | Kind::Http))
        {
            100
        } else {
            10
        };
        let iv = num(&self.interval, cx)
            .unwrap_or(1000)
            .clamp(min_iv, 3_600_000);
        let count = num(&self.count, cx)
            .filter(|c| *c > 0)
            .map(|c| c.min(100_000) as u32);
        let to = num(&self.timeout, cx).unwrap_or(2000).clamp(100, 60_000);
        self.series = (0..self.targets.len()).map(|_| Series::default()).collect();
        self.handle = Some(monitor::run_series(
            self.targets.clone(),
            Duration::from_millis(iv),
            count,
            Duration::from_millis(to),
        ));
        self.status = match count {
            Some(c) => format!(
                "Probing {} target(s), {c} probes every {iv} ms…",
                self.targets.len()
            ),
            None => format!(
                "Probing {} target(s) every {iv} ms until stopped…",
                self.targets.len()
            ),
        }
        .into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(200))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn stop(&mut self) {
        if let Some(h) = &self.handle {
            h.stop();
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let mut done = false;
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                SeriesEvent::Sample(s) => {
                    let Some(series) = self.series.get_mut(s.target) else {
                        continue;
                    };
                    let ok = s.result.is_ok();
                    series.walls.insert(s.seq, s.wall);
                    series.results.insert(s.seq, s.result);
                    // Uptime state machine (results arrive roughly in order).
                    if ok {
                        series.fails_in_row = 0;
                        if series.down {
                            series.down = false;
                            if let Some(o) = series.outages.last_mut() {
                                o.1 = Some(s.wall);
                            }
                        }
                    } else {
                        series.fails_in_row += 1;
                        if series.fails_in_row == 2 && !series.down {
                            series.down = true;
                            series.outages.push((s.wall, None));
                        }
                    }
                }
                SeriesEvent::Error { target, error } => {
                    if let Some(s) = self.series.get_mut(target) {
                        s.error = Some(error);
                    }
                }
                SeriesEvent::Done => done = true,
            }
        }
        if done {
            self.handle = None;
            self.status = "Finished".into();
        }
        cx.notify();
        !done
    }

    fn summary_text(&self) -> String {
        let mut out = String::new();
        for (t, s) in self.targets.iter().zip(&self.series) {
            let st = Stats::from(&s.ordered());
            out.push_str(&format!(
                "{}: sent {} lost {} ({:.1}%) min {:.1} avg {:.1} max {:.1} p95 {:.1} jitter {:.2} ms{}\n",
                t.label(),
                st.sent,
                st.sent - st.received,
                st.loss_pct,
                st.min,
                st.avg,
                st.max,
                st.p95,
                st.jitter,
                st.mos().map(|m| format!(" MOS {m:.2}")).unwrap_or_default()
            ));
            for (a, b) in &s.outages {
                out.push_str(&format!(
                    "   outage {} → {}\n",
                    time_of(*a),
                    b.map(time_of).unwrap_or_else(|| "ongoing".into())
                ));
            }
        }
        out
    }

    fn card(
        &self,
        i: usize,
        t: &Target,
        s: Option<&Series>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let samples = s.map(|s| s.ordered()).unwrap_or_default();
        let st = Stats::from(&samples);
        let last = samples.last().copied().flatten();
        let width = 860.0;
        let tail: Vec<Option<f32>> = samples
            .iter()
            .rev()
            .take(match self.purpose {
                Purpose::Loss => 600,
                _ => 150,
            })
            .rev()
            .copied()
            .collect();
        let header = div()
            .flex()
            .items_center()
            .gap_3()
            .child(dot(match s {
                Some(s) if s.down => C::RED,
                Some(s) if !s.results.is_empty() && s.fails_in_row == 0 => C::GREEN,
                Some(s) if s.fails_in_row > 0 => C::AMBER,
                _ => 0x3a4252,
            }))
            .child(
                div()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(t.text.clone()),
            )
            .child(label(t.kind.label()))
            .child(div().flex_1())
            .when(!running, |d| {
                d.child(
                    button(
                        ("rm", i),
                        "✕",
                        C::PANEL2,
                        C::RED,
                        act(&view, move |v: &mut Self, _, _| {
                            v.targets.remove(i);
                            v.series.clear();
                        }),
                    )
                    .tooltip(tip("Remove target")),
                )
            });
        let mut body = div().flex().flex_col().gap_2();
        if let Some(e) = s.and_then(|s| s.error.clone()) {
            body = body.child(div().text_sm().text_color(rgb(C::RED)).child(e));
        }
        let tiles = match self.purpose {
            Purpose::Latency => div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(tile(
                    "Last",
                    last.map(fmt_ms).unwrap_or_else(|| "—".into()),
                    C::TEXT,
                ))
                .child(tile(
                    "Average",
                    if st.received > 0 {
                        fmt_ms(st.avg)
                    } else {
                        "—".into()
                    },
                    C::TEXT,
                ))
                .child(tile(
                    "Min / Max",
                    if st.received > 0 {
                        format!("{:.0} / {:.0}", st.min, st.max)
                    } else {
                        "—".into()
                    },
                    C::MUTED,
                ))
                .child(tile(
                    "p95",
                    if st.received > 0 {
                        fmt_ms(st.p95)
                    } else {
                        "—".into()
                    },
                    C::MUTED,
                ))
                .child(tile(
                    "Loss",
                    format!("{:.1}%", st.loss_pct),
                    if st.loss_pct > 1.0 { C::RED } else { C::GREEN },
                )),
            Purpose::Jitter => {
                let mos = st.mos();
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(tile(
                        "Jitter",
                        if st.received > 1 {
                            fmt_ms(st.jitter)
                        } else {
                            "—".into()
                        },
                        if st.jitter > 30.0 {
                            C::RED
                        } else if st.jitter > 10.0 {
                            C::AMBER
                        } else {
                            C::GREEN
                        },
                    ))
                    .child(tile(
                        "Std deviation",
                        if st.received > 1 {
                            fmt_ms(st.stddev)
                        } else {
                            "—".into()
                        },
                        C::TEXT,
                    ))
                    .child(tile(
                        "Average RTT",
                        if st.received > 0 {
                            fmt_ms(st.avg)
                        } else {
                            "—".into()
                        },
                        C::TEXT,
                    ))
                    .child(tile(
                        "Loss",
                        format!("{:.1}%", st.loss_pct),
                        if st.loss_pct > 1.0 { C::RED } else { C::GREEN },
                    ))
                    .child(tile(
                        "VoIP MOS",
                        mos.map(|m| format!("{m:.2} {}", monitor::mos_label(m)))
                            .unwrap_or_else(|| "—".into()),
                        match mos {
                            Some(m) if m >= 4.0 => C::GREEN,
                            Some(m) if m >= 3.6 => C::AMBER,
                            Some(_) => C::RED,
                            None => C::MUTED,
                        },
                    ))
                    .child(tile(
                        "Probes",
                        format!("{}/{}", st.received, st.sent),
                        C::MUTED,
                    ))
            }
            Purpose::Loss => div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(tile(
                    "Loss",
                    format!("{:.2}%", st.loss_pct),
                    if st.loss_pct > 1.0 {
                        C::RED
                    } else if st.loss_pct > 0.0 {
                        C::AMBER
                    } else {
                        C::GREEN
                    },
                ))
                .child(tile(
                    "Lost / sent",
                    format!("{} / {}", st.sent - st.received, st.sent),
                    C::TEXT,
                ))
                .child(tile("Loss bursts", st.loss_bursts.to_string(), C::TEXT))
                .child(tile(
                    "Longest burst",
                    format!("{} probe(s)", st.max_burst_loss),
                    if st.max_burst_loss > 3 {
                        C::RED
                    } else {
                        C::TEXT
                    },
                ))
                .child(tile(
                    "Average RTT",
                    if st.received > 0 {
                        fmt_ms(st.avg)
                    } else {
                        "—".into()
                    },
                    C::MUTED,
                )),
            Purpose::Uptime => {
                let up_pct = if st.sent > 0 {
                    100.0 - st.loss_pct
                } else {
                    0.0
                };
                let state = match s {
                    Some(s) if s.down => ("DOWN", C::RED),
                    Some(s) if !s.results.is_empty() => ("UP", C::GREEN),
                    _ => ("—", C::MUTED),
                };
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(tile("Status", state.0, state.1))
                    .child(tile(
                        "Availability",
                        if st.sent > 0 {
                            format!("{up_pct:.2}%")
                        } else {
                            "—".into()
                        },
                        if up_pct >= 99.9 { C::GREEN } else { C::AMBER },
                    ))
                    .child(tile(
                        "Response",
                        last.map(fmt_ms).unwrap_or_else(|| "—".into()),
                        C::TEXT,
                    ))
                    .child(tile("Checks", st.sent.to_string(), C::MUTED))
                    .child(tile(
                        "Outages",
                        s.map(|s| s.outages.len()).unwrap_or(0).to_string(),
                        C::TEXT,
                    ))
            }
        };
        body = body.child(tiles);
        if self.purpose == Purpose::Jitter && st.received > 3 {
            // RTT histogram, 12 bins between min and max.
            let bins = 12;
            let span = (st.max - st.min).max(0.1);
            let mut h = vec![0f32; bins];
            for v in samples.iter().flatten() {
                let b = (((v - st.min) / span) * (bins as f32 - 1.0)).round() as usize;
                h[b.min(bins - 1)] += 1.0;
            }
            body = body.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(label(format!(
                        "RTT distribution {:.1} – {:.1} ms",
                        st.min, st.max
                    )))
                    .child(bar_chart(
                        &h.into_iter().map(Some).collect::<Vec<_>>(),
                        360.0,
                        70.0,
                        0.0,
                        C::PURPLE,
                    )),
            );
        }
        if self.purpose == Purpose::Loss {
            let strip: Vec<Option<f32>> = tail.iter().map(|v| v.map(|_| 1.0)).collect();
            body = body
                .child(label("Timeline (green = answered, red = lost)"))
                .child(bar_chart_slots(&strip, 600, width, 24.0, 1.0, C::GREEN));
        }
        let slots = match self.purpose {
            Purpose::Loss => 600,
            _ => 150,
        };
        body = body.child(bar_chart_slots(&tail, slots, width, 90.0, 0.0, C::ACCENT));
        if self.purpose == Purpose::Uptime
            && let Some(s) = s
            && !s.outages.is_empty()
        {
            body =
                body.child(section_title("Outages"))
                    .children(s.outages.iter().rev().take(20).map(|(a, b)| {
                        let d = b
                            .unwrap_or_else(SystemTime::now)
                            .duration_since(*a)
                            .unwrap_or_default();
                        div()
                            .flex()
                            .gap_4()
                            .text_sm()
                            .child(
                                div()
                                    .text_color(rgb(C::RED))
                                    .child(format!("down {}", time_of(*a))),
                            )
                            .child(match b {
                                Some(b) => format!("back {}", time_of(*b)),
                                None => "ongoing".into(),
                            })
                            .child(div().text_color(rgb(C::MUTED)).child(dur(d)))
                    }));
            if let Some(e) = s.last_error() {
                body = body.child(
                    div()
                        .text_xs()
                        .text_color(rgb(C::MUTED))
                        .child(format!("last error: {e}")),
                );
            }
        }
        div()
            .flex()
            .flex_col()
            .gap_2()
            .p_4()
            .rounded_md()
            .bg(rgb(C::PANEL))
            .border_1()
            .border_color(rgb(if s.is_some_and(|s| s.down) {
                C::RED
            } else {
                C::BORDER
            }))
            .child(header)
            .child(body)
    }
}

impl Focusable for MonitorView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for MonitorView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let kinds = Kind::ALL.iter().enumerate().map(|(i, &k)| {
            chip(
                ("kind", i),
                k.label(),
                self.kind == k,
                act(&view, move |t: &mut Self, _, _| t.kind = k),
            )
        });
        let cards: Vec<_> = self
            .targets
            .clone()
            .iter()
            .enumerate()
            .map(|(i, t)| self.card(i, t, self.series.get(i), cx).into_any_element())
            .collect();
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .children(kinds)
                    .child(self.new_target.clone())
                    .child(label(self.kind.hint()))
                    .child(button(
                        "add-target",
                        "+ Add",
                        C::PANEL2,
                        C::BORDER,
                        act(&view, |t: &mut Self, _, cx| t.add_target(cx)),
                    ))
                    .child(div().w(px(10.)))
                    .child(label("Interval ms"))
                    .child(self.interval.clone())
                    .when(
                        self.purpose != Purpose::Uptime && self.purpose != Purpose::Latency,
                        |d| d.child(label("Probes")).child(self.count.clone()),
                    )
                    .child(label("Timeout ms"))
                    .child(self.timeout.clone())
                    .child(if running {
                        button(
                            "mon-go",
                            "■ Stop",
                            C::AMBER,
                            C::AMBER,
                            act(&view, |t: &mut Self, _, _| t.stop()),
                        )
                    } else {
                        button_primary(
                            "mon-go",
                            "▶ Start",
                            act(&view, |t: &mut Self, _, cx| t.start(cx)),
                        )
                    })
                    .child(copy_button("mon-copy", self.summary_text())),
            )
            .child(
                div()
                    .px_5()
                    .py_2()
                    .text_xs()
                    .text_color(rgb(C::MUTED))
                    .bg(alpha(C::ACCENT, 0.05))
                    .child(self.purpose.intro()),
            )
            .child(if self.targets.is_empty() {
                empty_state(
                    "No targets",
                    "Choose a probe type, enter a target and press + Add.",
                )
                .into_any_element()
            } else {
                div()
                    .id("mon-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_5()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .children(cards)
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
