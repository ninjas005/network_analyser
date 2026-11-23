//! NTP Analyser tool: query several time servers, compare them and judge
//! the local clock.

use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::ntp::{self, Event, RunHandle, Sample, ServerResult};
use crate::widgets::{
    Accept, C, TextInput, act, bar_chart, button, button_primary, cell, chip, copy_button, dot,
    empty_state, findings_cards, findings_text, input, kv_row, label, level_color, section_title,
    status_bar, table_header, tile, toolbar,
};

pub struct NtpView {
    focus: FocusHandle,
    servers: Entity<TextInput>,
    samples: usize,
    all_addrs: bool,
    handle: Option<RunHandle>,
    results: Vec<ServerResult>,
    errors: Vec<(String, String)>,
    selected: Option<usize>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl NtpView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let sys = ntp::system_servers();
        let status = if sys.is_empty() {
            "No system time server found; public servers are listed.".to_string()
        } else {
            format!(
                "System time servers: {}",
                sys.iter()
                    .map(|(h, s)| format!("{h} ({s})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        Self {
            focus: cx.focus_handle(),
            servers: input(
                window,
                cx,
                &ntp::default_servers().join(", "),
                "pool.ntp.org, time.google.com, 192.168.1.1",
                Accept::Any,
                |t| t.width(520.).max_len(2000),
                |t: &mut Self, _, cx| t.run(cx),
            ),
            samples: 4,
            all_addrs: true,
            handle: None,
            results: Vec::new(),
            errors: Vec::new(),
            selected: None,
            status: status.into(),
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let servers: Vec<String> = self
            .servers
            .read(cx)
            .value
            .split([',', ' ', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if servers.is_empty() {
            self.servers.update(cx, |t, cx| {
                t.error = true;
                cx.notify()
            });
            return;
        }
        self.results.clear();
        self.errors.clear();
        self.selected = None;
        self.handle = Some(ntp::run(
            servers,
            self.samples,
            Duration::from_secs(2),
            self.all_addrs,
        ));
        self.status = format!("Querying… {} sample(s) per server, 2 s apart", self.samples).into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                match this.update(cx, |t, cx| t.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.stop();
        }
        self.status = "Stopped.".into();
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let mut done = false;
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                Event::Resolved(name, Ok(addrs)) => {
                    for a in addrs {
                        self.results.push(ServerResult {
                            name: name.clone(),
                            addr: a,
                            samples: Vec::new(),
                            expected: self.samples,
                        });
                    }
                }
                Event::Resolved(name, Err(e)) => self.errors.push((name, e)),
                Event::Sample(n, a, s) => {
                    if let Some(r) = self.results.iter_mut().find(|r| r.addr == a && r.name == n) {
                        r.samples.push(s);
                    }
                }
                Event::Done => done = true,
            }
        }
        if self.selected.is_none() && self.results.iter().any(|r| r.best().is_some()) {
            self.selected = self.results.iter().position(|r| r.best().is_some());
        }
        if done {
            self.handle = None;
            let v = ntp::verdict(&self.results);
            self.status = match v.offset_ms {
                Some(o) => format!(
                    "Done: local clock offset {} from {} agreeing server(s)",
                    ntp::fmt_ms(o),
                    v.truechimers
                ),
                None => "Done: no synchronised server answered.".into(),
            }
            .into();
        } else {
            let got: usize = self.results.iter().map(|r| r.samples.len()).sum();
            let want: usize = self.results.iter().map(|r| r.expected).sum();
            let finished = self.results.iter().filter(|r| r.done()).count();
            self.status = format!(
                "Querying… {got}/{want} samples, {finished}/{} servers complete",
                self.results.len()
            )
            .into();
        }
        cx.notify();
        !done
    }

    fn offset_chart(&self) -> impl IntoElement {
        let rows: Vec<(&ServerResult, &Sample)> = self
            .results
            .iter()
            .filter_map(|r| Some((r, r.best()?)))
            .collect();
        let scale = rows
            .iter()
            .map(|(_, b)| b.offset_ms.abs() + b.delay_ms / 2.0)
            .fold(1.0f64, f64::max);
        let half = 260.0f32;
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
            .child(section_title(
                "Offset by server (bar) ± half the round trip (whisker)",
            ))
            .child(
                div()
                    .flex()
                    .text_xs()
                    .text_color(rgb(C::MUTED))
                    .child(div().w(px(260.)).flex_none())
                    .child(
                        div()
                            .w(px(half * 2.0))
                            .flex()
                            .justify_between()
                            .child(format!("local clock ahead  {}", ntp::fmt_ms(-scale)))
                            .child("0")
                            .child(format!("{}  behind", ntp::fmt_ms(scale))),
                    ),
            )
            .children(rows.into_iter().map(|(r, b)| {
                let w = (b.offset_ms.abs() / scale) as f32 * half;
                let err = (b.delay_ms / 2.0 / scale) as f32 * half;
                let col = level_color(r.status().1);
                let center = half;
                let (bar_left, whisk_left) = if b.offset_ms >= 0.0 {
                    (center, center + w - err)
                } else {
                    (center - w, center - w - err)
                };
                div()
                    .flex()
                    .items_center()
                    .h(px(22.))
                    .child(
                        cell(260., format!("{} {}", r.name, r.addr.ip())).text_color(rgb(C::MUTED)),
                    )
                    .child(
                        div()
                            .relative()
                            .w(px(half * 2.0))
                            .h(px(14.))
                            .flex_none()
                            .bg(rgb(C::BG))
                            .rounded_sm()
                            .child(
                                div()
                                    .absolute()
                                    .left(px(center))
                                    .top_0()
                                    .w(px(1.))
                                    .h_full()
                                    .bg(rgb(C::BORDER)),
                            )
                            .child(
                                div()
                                    .absolute()
                                    .left(px(whisk_left.clamp(0.0, half * 2.0)))
                                    .top(px(6.))
                                    .w(px((err * 2.0).min(half * 2.0)))
                                    .h(px(2.))
                                    .bg(rgb(C::MUTED)),
                            )
                            .child(
                                div()
                                    .absolute()
                                    .left(px(bar_left))
                                    .top(px(2.))
                                    .w(px(w.max(2.0)))
                                    .h(px(10.))
                                    .rounded_sm()
                                    .bg(rgb(col)),
                            ),
                    )
                    .child(div().pl_3().child(ntp::fmt_ms(b.offset_ms)))
            }))
    }

    fn detail(&self, r: &ServerResult) -> impl IntoElement {
        let delays: Vec<Option<f32>> = r
            .samples
            .iter()
            .map(|s| s.as_ref().ok().map(|s| s.delay_ms as f32))
            .collect();
        div()
            .id("ntp-detail")
            .w(px(420.))
            .flex_none()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_1()
            .overflow_y_scroll()
            .bg(rgb(C::PANEL))
            .border_l_1()
            .border_color(rgb(C::BORDER))
            .text_sm()
            .child(section_title(&format!("{} — {}", r.name, r.addr)))
            .map(|d| match r.best() {
                None => d.child(div().text_color(rgb(C::RED)).child(r.status().0)),
                Some(b) => d
                    .child(kv_row("Offset", ntp::fmt_ms(b.offset_ms), 150.))
                    .child(kv_row(
                        "Round-trip delay",
                        format!("{:.2} ms", b.delay_ms),
                        150.,
                    ))
                    .child(kv_row(
                        "Jitter",
                        r.jitter_ms()
                            .map(|j| format!("{j:.2} ms"))
                            .unwrap_or("-".into()),
                        150.,
                    ))
                    .child(kv_row("Stratum", b.stratum.to_string(), 150.))
                    .child(kv_row("Reference ID", ntp::describe_refid(b), 150.))
                    .child(kv_row(
                        "Reference time",
                        if b.ref_time > 0.0 {
                            let age = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs_f64())
                                .unwrap_or(0.0)
                                - b.ref_time;
                            format!("last synced {age:.0} s ago")
                        } else {
                            "never".into()
                        },
                        150.,
                    ))
                    .child(kv_row(
                        "Leap indicator",
                        format!("{} ({})", b.leap, ntp::leap_name(b.leap)),
                        150.,
                    ))
                    .child(kv_row("Version", format!("NTPv{}", b.version), 150.))
                    .child(kv_row(
                        "Precision",
                        format!(
                            "2^{} s ({:.3} µs)",
                            b.precision,
                            2f64.powi(b.precision as i32) * 1e6
                        ),
                        150.,
                    ))
                    .child(kv_row("Poll interval", format!("2^{} s", b.poll), 150.))
                    .child(kv_row(
                        "Root delay",
                        format!("{:.2} ms", b.root_delay_ms),
                        150.,
                    ))
                    .child(kv_row(
                        "Root dispersion",
                        format!("{:.2} ms", b.root_disp_ms),
                        150.,
                    ))
                    .child(kv_row(
                        "Root distance",
                        format!("{:.2} ms (max error vs. reference)", b.root_distance_ms()),
                        150.,
                    )),
            })
            .child(div().pt_3().child(section_title("Samples (delay)")))
            .child(bar_chart(&delays, 380., 60., 0.0, C::ACCENT))
            .children(r.samples.iter().enumerate().map(|(i, s)| {
                let best = r.best();
                div()
                    .flex()
                    .text_xs()
                    .child(cell(30., format!("#{}", i + 1)).text_color(rgb(C::MUTED)))
                    .child(match s {
                        Ok(s) => div()
                            .flex()
                            .child(cell(110., ntp::fmt_ms(s.offset_ms)))
                            .child(cell(110., format!("{:.2} ms", s.delay_ms)))
                            .when(best == Some(s), |d| {
                                d.child(
                                    div().text_color(rgb(C::GREEN)).child("best (lowest delay)"),
                                )
                            }),
                        Err(e) => div().text_color(rgb(C::RED)).child(e.to_string()),
                    })
            }))
    }
}

impl Focusable for NtpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for NtpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let findings = if running {
            Vec::new()
        } else {
            ntp::findings(&self.results)
        };
        let v = ntp::verdict(&self.results);
        let ok = self.results.iter().filter(|r| r.best().is_some()).count();
        let best = self
            .results
            .iter()
            .filter_map(|r| Some((r, r.best()?)))
            .filter(|(_, b)| !b.unsynchronised())
            .min_by(|a, b| a.1.root_distance_ms().total_cmp(&b.1.root_distance_ms()));
        let copy = {
            let mut t = String::new();
            for r in &self.results {
                match r.best() {
                    Some(b) => t.push_str(&format!(
                        "{} {} stratum {} refid {} offset {} delay {:.1} ms\n",
                        r.name,
                        r.addr,
                        b.stratum,
                        b.refid,
                        ntp::fmt_ms(b.offset_ms),
                        b.delay_ms
                    )),
                    None => t.push_str(&format!("{} {} {}\n", r.name, r.addr, r.status().0)),
                }
            }
            t + &findings_text(&findings)
        };
        let table = div()
            .flex()
            .flex_col()
            .rounded_md()
            .border_1()
            .border_color(rgb(C::BORDER))
            .overflow_hidden()
            .child(table_header(&[
                ("", 22.),
                ("SERVER", 190.),
                ("ADDRESS", 200.),
                ("ST", 40.),
                ("REFERENCE", 180.),
                ("OFFSET", 100.),
                ("DELAY", 90.),
                ("JITTER", 80.),
                ("STATUS", 0.),
            ]))
            .children(self.results.iter().enumerate().map(|(i, r)| {
                let (st, lvl) = r.status();
                let b = r.best();
                div()
                    .id(("ntp-row", i))
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(30.))
                    .text_sm()
                    .cursor_pointer()
                    .bg(rgb(if self.selected == Some(i) {
                        C::SELECT
                    } else if i % 2 == 1 {
                        C::ROW_ALT
                    } else {
                        C::BG
                    }))
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .on_click(act(&view, move |t: &mut Self, _, _| t.selected = Some(i)))
                    .child(div().w(px(22.)).flex_none().child(dot(level_color(lvl))))
                    .child(cell(190., r.name.clone()))
                    .child(cell(200., r.addr.ip().to_string()).text_color(rgb(C::MUTED)))
                    .child(cell(
                        40.,
                        b.map(|b| b.stratum.to_string()).unwrap_or_default(),
                    ))
                    .child(cell(180., b.map(ntp::describe_refid).unwrap_or_default()))
                    .child(cell(
                        100.,
                        b.map(|b| ntp::fmt_ms(b.offset_ms)).unwrap_or_default(),
                    ))
                    .child(cell(
                        90.,
                        b.map(|b| format!("{:.1} ms", b.delay_ms))
                            .unwrap_or_default(),
                    ))
                    .child(cell(
                        80.,
                        r.jitter_ms().map(|j| format!("{j:.2}")).unwrap_or_default(),
                    ))
                    .child(
                        cell(0., format!("{st} · {}/{}", r.samples.len(), r.expected))
                            .text_color(rgb(level_color(lvl))),
                    )
            }))
            .children(self.errors.iter().map(|(n, e)| {
                div()
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(30.))
                    .text_sm()
                    .child(div().w(px(22.)).flex_none().child(dot(C::RED)))
                    .child(cell(190., n.clone()))
                    .child(cell(0., e.clone()).text_color(rgb(C::RED)))
            }));
        let offset_color = match v.offset_ms.map(f64::abs) {
            Some(a) if a < 50.0 => C::GREEN,
            Some(a) if a < 500.0 => C::AMBER,
            Some(_) => C::RED,
            None => C::MUTED,
        };
        let body = if self.results.is_empty() && self.errors.is_empty() {
            empty_state(
                if running { "Resolving…" } else { "No query yet" },
                "List NTP servers (names, addresses or pools) and press Query. Pools are expanded to every address.",
            )
            .into_any_element()
        } else {
            div()
                .flex()
                .flex_row()
                .flex_1()
                .min_h_0()
                .child(
                    div()
                        .id("ntp-main")
                        .flex_1()
                        .min_w_0()
                        .p_4()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .overflow_y_scroll()
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap_3()
                                .child(tile(
                                    "Local clock offset",
                                    v.offset_ms.map(ntp::fmt_ms).unwrap_or("-".into()),
                                    offset_color,
                                ))
                                .child(tile(
                                    "Servers answering",
                                    format!("{ok} / {}", self.results.len()),
                                    if ok == self.results.len() {
                                        C::GREEN
                                    } else {
                                        C::AMBER
                                    },
                                ))
                                .child(tile(
                                    "Falsetickers",
                                    v.falsetickers.len().to_string(),
                                    if v.falsetickers.is_empty() {
                                        C::GREEN
                                    } else {
                                        C::RED
                                    },
                                ))
                                .child(tile(
                                    "Best source",
                                    best.map(|(r, b)| {
                                        format!("{} (±{:.1} ms)", r.addr.ip(), b.root_distance_ms())
                                    })
                                    .unwrap_or("-".into()),
                                    C::TEXT,
                                )),
                        )
                        .child(table)
                        .when(self.results.iter().any(|r| r.best().is_some()), |d| {
                            d.child(self.offset_chart())
                        })
                        .when(!findings.is_empty(), |d| d.child(findings_cards(&findings))),
                )
                .when_some(self.selected.and_then(|i| self.results.get(i)), |d, r| {
                    d.child(self.detail(r))
                })
                .into_any_element()
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Servers"))
                    .child(self.servers.clone())
                    .child(label("Samples"))
                    .children([1usize, 4, 8].into_iter().map(|n| {
                        chip(
                            ("ntp-n", n),
                            n.to_string(),
                            self.samples == n,
                            act(&view, move |t: &mut Self, _, _| {
                                if t.handle.is_none() {
                                    t.samples = n
                                }
                            }),
                        )
                    }))
                    .child(chip(
                        "ntp-all",
                        "Every pool address",
                        self.all_addrs,
                        act(&view, |t: &mut Self, _, _| t.all_addrs = !t.all_addrs),
                    ))
                    .child(if running {
                        button(
                            "ntp-go",
                            "■ Stop",
                            C::RED,
                            C::RED_HOVER,
                            act(&view, |t: &mut Self, _, _| t.stop()),
                        )
                    } else {
                        button_primary(
                            "ntp-go",
                            "▶ Query",
                            act(&view, |t: &mut Self, _, cx| t.run(cx)),
                        )
                    })
                    .child(copy_button("ntp-copy", copy)),
            )
            .child(body)
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
