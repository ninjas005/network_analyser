//! DNS Client Tester tool: benchmark and validate resolvers.

use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::dns_client::{self, Config, Event, Report, RunHandle, Transport, TransportStats, ms};
use crate::widgets::{
    Accept, C, TextInput, act, bar_chart, button, button_primary, cell, chip, copy_button, dot,
    empty_state, findings_cards, findings_text, input, label, level_color, progress, section_title,
    status_bar, table_header, tile, toolbar,
};

const SERIES: [(&str, u32); 4] = [
    ("UDP cached", C::GREEN),
    ("UDP uncached", C::CYAN),
    ("TCP", C::AMBER),
    ("DoT", C::PURPLE),
];

pub struct DnsClientView {
    focus: FocusHandle,
    resolvers: Entity<TextInput>,
    cfg: Config,
    handle: Option<RunHandle>,
    reports: Vec<Option<Report>>,
    errors: Vec<String>,
    selected: Option<usize>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

fn series(r: &Report) -> [Option<f32>; 4] {
    let udp = r.get(Transport::Udp);
    let med = |t| {
        r.get(t)
            .filter(|s: &&TransportStats| s.error.is_none())
            .and_then(|s| s.median())
    };
    [
        udp.and_then(|s| TransportStats::median_of(&s.cached)),
        udp.and_then(|s| TransportStats::median_of(&s.uncached)),
        med(Transport::Tcp),
        med(Transport::Dot),
    ]
}

impl DnsClientView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self {
            focus: cx.focus_handle(),
            resolvers: input(
                window,
                cx,
                &dns_client::default_resolvers().join(", "),
                "1.1.1.1, 8.8.8.8, 9.9.9.9#dns.quad9.net, dns.google, 192.168.1.1",
                Accept::Any,
                |t| t.width(480.).max_len(2000),
                |t: &mut Self, _, cx| t.run(cx),
            ),
            cfg: Config::default(),
            handle: None,
            reports: Vec::new(),
            errors: Vec::new(),
            selected: None,
            status: "Resolvers: IP, IP:port, IP#tls-name (for DoT) or a host name.".into(),
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let mut list = Vec::new();
        self.errors.clear();
        for s in self
            .resolvers
            .read(cx)
            .value
            .split([',', ' ', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match dns_client::parse_resolver(s) {
                Ok(r) if !list.contains(&r) => list.push(r),
                Ok(_) => {}
                Err(e) => self.errors.push(e),
            }
        }
        if list.is_empty() {
            self.resolvers.update(cx, |t, cx| {
                t.error = true;
                cx.notify()
            });
            return;
        }
        self.reports = vec![None; list.len()];
        self.selected = None;
        let n = list.len();
        self.handle = Some(dns_client::run(list, self.cfg));
        self.status = format!("Testing {n} resolver(s)…").into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(200))
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
                Event::Update(i, r) => {
                    if let Some(slot) = self.reports.get_mut(i) {
                        *slot = Some(*r);
                    }
                }
                Event::Done => done = true,
            }
        }
        let reports: Vec<Report> = self.reports.iter().flatten().cloned().collect();
        if done {
            self.handle = None;
            let rank = dns_client::ranking(&reports);
            self.status = match rank.first().map(|i| &reports[*i]) {
                Some(best) if best.score().is_some() => format!(
                    "Done. Fastest: {} (UDP median {})",
                    best.resolver.label,
                    ms(best.get(Transport::Udp).and_then(|s| s.median()))
                ),
                _ => "Done. No resolver answered.".into(),
            }
            .into();
            if self.selected.is_none() {
                self.selected = rank.first().copied();
            }
        } else {
            let (d, t) = reports
                .iter()
                .fold((0, 0), |(d, t), r| (d + r.done, t + r.total));
            self.status = format!("Testing… {d}/{t} queries").into();
        }
        cx.notify();
        !done
    }

    fn chart(&self, reports: &[&Report]) -> impl IntoElement {
        let max = reports
            .iter()
            .flat_map(|r| series(r))
            .flatten()
            .fold(1.0f32, f32::max);
        let w = 420.0f32;
        div()
            .flex()
            .flex_col()
            .gap_2()
            .p_4()
            .rounded_md()
            .bg(rgb(C::PANEL))
            .border_1()
            .border_color(rgb(C::BORDER))
            .text_sm()
            .child(section_title("Median latency"))
            .child(
                div()
                    .flex()
                    .gap_4()
                    .text_xs()
                    .children(SERIES.iter().map(|(n, c)| {
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(dot(*c))
                            .child(div().text_color(rgb(C::MUTED)).child(*n))
                    })),
            )
            .children(reports.iter().map(|r| {
                let s = series(r);
                div()
                    .flex()
                    .items_start()
                    .child(cell(240., r.resolver.label.clone()).text_color(rgb(C::MUTED)))
                    .child(div().flex().flex_col().gap(px(2.)).children(
                        s.into_iter().zip(SERIES).map(move |(v, (_, c))| {
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .h(px(10.))
                                .text_xs()
                                .child(
                                    div()
                                        .w(px(v.map(|v| (v / max * w).max(2.0)).unwrap_or(0.0)))
                                        .h(px(8.))
                                        .rounded_sm()
                                        .bg(rgb(c)),
                                )
                                .child(div().text_color(rgb(C::MUTED)).child(match v {
                                    Some(_) => ms(v),
                                    None => "n/a".into(),
                                }))
                        }),
                    ))
            }))
    }

    fn detail(&self, r: &Report) -> impl IntoElement {
        div()
            .id("dnsc-detail")
            .w(px(420.))
            .flex_none()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_2()
            .overflow_y_scroll()
            .bg(rgb(C::PANEL))
            .border_l_1()
            .border_color(rgb(C::BORDER))
            .text_sm()
            .child(section_title(&format!(
                "{} — {}",
                r.resolver.label, r.resolver.addr
            )))
            .child(label(format!("DoT name: {}", r.resolver.tls_name)))
            .children(r.stats.iter().map(|(t, s)| {
                let samples: Vec<Option<f32>> =
                    s.cached.iter().chain(&s.uncached).copied().collect();
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .pt_2()
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(t.label()),
                            )
                            .child(div().text_xs().text_color(rgb(C::MUTED)).child(
                                match &s.error {
                                    Some(e) => e.clone(),
                                    None => format!(
                                        "median {} · p95 {} · {} timeouts · {} failed",
                                        ms(s.median()),
                                        ms(s.p95()),
                                        s.timeouts,
                                        s.failures
                                    ),
                                },
                            )),
                    )
                    .when(s.error.is_none() && !samples.is_empty(), |d| {
                        d.child(bar_chart(&samples, 380., 44., 0.0, C::ACCENT))
                            .child(label(
                                "cached names first, then uncached (random) names; red = lost",
                            ))
                    })
                    .when(!s.failed.is_empty(), |d| {
                        d.child(
                            div()
                                .text_xs()
                                .text_color(rgb(C::AMBER))
                                .child(s.failed.join(" · ")),
                        )
                    })
            }))
            .when(!r.checks.is_empty(), |d| {
                d.child(div().pt_3().child(section_title("Behaviour")))
                    .children(r.checks.iter().map(|c| {
                        div()
                            .flex()
                            .items_start()
                            .gap_2()
                            .child(div().pt(px(6.)).child(dot(level_color(c.level))))
                            .child(
                                div()
                                    .w(px(130.))
                                    .flex_none()
                                    .text_color(rgb(C::MUTED))
                                    .child(c.key.clone()),
                            )
                            .child(div().flex_1().min_w_0().child(c.value.clone()))
                    }))
            })
    }
}

impl Focusable for DnsClientView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for DnsClientView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let all: Vec<Report> = self.reports.iter().flatten().cloned().collect();
        let findings = if running {
            Vec::new()
        } else {
            dns_client::findings(&all)
        };
        let rank = dns_client::ranking(&all);
        let bad = findings
            .iter()
            .filter(|f| f.level == crate::gateway::Level::Bad)
            .count();
        let best = rank
            .first()
            .map(|i| &all[*i])
            .filter(|r| r.score().is_some());
        let copy = {
            let mut t = String::new();
            for i in &rank {
                let r = &all[*i];
                let s = series(r);
                t.push_str(&format!(
                    "{}: UDP cached {} uncached {} TCP {} DoT {}\n",
                    r.resolver.label,
                    ms(s[0]),
                    ms(s[1]),
                    ms(s[2]),
                    ms(s[3])
                ));
            }
            t + &findings_text(&findings)
        };
        // Index into self.reports for each ranked entry.
        let slots: Vec<usize> = self
            .reports
            .iter()
            .enumerate()
            .filter(|(_, r)| r.is_some())
            .map(|(i, _)| i)
            .collect();
        let ordered: Vec<(usize, usize, &Report)> = if running {
            slots
                .iter()
                .enumerate()
                .map(|(k, s)| (k, *s, &all[k]))
                .collect()
        } else {
            rank.iter().map(|k| (*k, slots[*k], &all[*k])).collect()
        };
        let table = div()
            .flex()
            .flex_col()
            .rounded_md()
            .border_1()
            .border_color(rgb(C::BORDER))
            .overflow_hidden()
            .child(table_header(&[
                ("#", 34.),
                ("RESOLVER", 230.),
                ("UDP CACHED", 100.),
                ("UNCACHED", 90.),
                ("UDP P95", 80.),
                ("TCP", 80.),
                ("DoT", 110.),
                ("FAILED", 70.),
                ("", 0.),
            ]))
            .children(ordered.iter().enumerate().map(|(pos, (_, slot, r))| {
                let slot = *slot;
                let s = series(r);
                let udp = r.get(Transport::Udp);
                let fr = udp.map(|u| u.fail_rate()).unwrap_or(0.0);
                let dot_txt = match r.get(Transport::Dot) {
                    Some(d) if d.error.is_some() => "n/a".to_string(),
                    Some(d) => format!(
                        "{}{}",
                        ms(d.median()),
                        d.handshake_ms
                            .map(|h| format!(" (+{h:.0})"))
                            .unwrap_or_default()
                    ),
                    None => "-".into(),
                };
                let na = |t: Transport, v: Option<f32>| match r.get(t) {
                    Some(x) if x.error.is_some() => "n/a".to_string(),
                    _ => ms(v),
                };
                div()
                    .id(("dnsc-row", slot))
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(30.))
                    .text_sm()
                    .cursor_pointer()
                    .bg(rgb(if self.selected == Some(slot) {
                        C::SELECT
                    } else if pos % 2 == 1 {
                        C::ROW_ALT
                    } else {
                        C::BG
                    }))
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .on_click(act(&view, move |t: &mut Self, _, _| {
                        t.selected = Some(slot)
                    }))
                    .child(cell(
                        34.,
                        if running {
                            "".into()
                        } else {
                            (pos + 1).to_string()
                        },
                    ))
                    .child(cell(230., r.resolver.label.clone()))
                    .child(cell(100., na(Transport::Udp, s[0])).text_color(rgb(C::GREEN)))
                    .child(cell(90., na(Transport::Udp, s[1])))
                    .child(cell(80., ms(udp.and_then(|u| u.p95()))))
                    .child(cell(80., na(Transport::Tcp, s[2])))
                    .child(cell(110., dot_txt))
                    .child(
                        cell(70., format!("{:.0}%", fr * 100.0)).text_color(rgb(if fr > 0.1 {
                            C::RED
                        } else if fr > 0.0 {
                            C::AMBER
                        } else {
                            C::MUTED
                        })),
                    )
                    .child(div().flex_1().flex().items_center().map(|d| {
                        if r.finished {
                            d.child(label("done"))
                        } else {
                            d.child(progress(r.done as f32 / r.total.max(1) as f32, 120.))
                        }
                    }))
            }))
            .children(self.errors.iter().map(|e| {
                div()
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(30.))
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .child(e.clone())
            }));
        let chart_rows: Vec<&Report> = ordered.iter().map(|(_, _, r)| *r).collect();
        let body = if self.reports.is_empty() && self.errors.is_empty() {
            empty_state(
                "No test yet",
                "Press Run to benchmark the resolvers over UDP, TCP and DNS-over-TLS and check how they behave.",
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
                        .id("dnsc-main")
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
                                    "Fastest",
                                    best.map(|r| r.resolver.label.clone()).unwrap_or("-".into()),
                                    C::GREEN,
                                ))
                                .child(tile(
                                    "Its UDP median",
                                    ms(best.and_then(|r| r.get(Transport::Udp)?.median())),
                                    C::TEXT,
                                ))
                                .child(tile("Resolvers", all.len().to_string(), C::TEXT))
                                .child(tile(
                                    "Problems",
                                    if running {
                                        "…".into()
                                    } else {
                                        bad.to_string()
                                    },
                                    if bad > 0 { C::RED } else { C::GREEN },
                                )),
                        )
                        .child(table)
                        .when(!chart_rows.is_empty(), |d| d.child(self.chart(&chart_rows)))
                        .when(!findings.is_empty(), |d| d.child(findings_cards(&findings))),
                )
                .when_some(
                    self.selected
                        .and_then(|i| self.reports.get(i))
                        .and_then(|r| r.as_ref()),
                    |d, r| d.child(self.detail(r)),
                )
                .into_any_element()
        };
        let tr = self.cfg.transports;
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Resolvers"))
                    .child(self.resolvers.clone())
                    .child(label("Rounds"))
                    .children([1usize, 2, 5].into_iter().map(|n| {
                        chip(
                            ("dnsc-n", n),
                            n.to_string(),
                            self.cfg.rounds == n,
                            act(&view, move |t: &mut Self, _, _| t.cfg.rounds = n),
                        )
                    }))
                    .children(Transport::ALL.into_iter().enumerate().map(|(i, t)| {
                        chip(
                            ("dnsc-t", i),
                            t.label(),
                            tr[i],
                            act(&view, move |v: &mut Self, _, _| {
                                v.cfg.transports[i] = !v.cfg.transports[i];
                                if !v.cfg.transports.iter().any(|x| *x) {
                                    v.cfg.transports[0] = true;
                                }
                            }),
                        )
                    }))
                    .child(chip(
                        "dnsc-checks",
                        "Behaviour checks",
                        self.cfg.checks,
                        act(&view, |t: &mut Self, _, _| t.cfg.checks = !t.cfg.checks),
                    ))
                    .child(if running {
                        button(
                            "dnsc-go",
                            "■ Stop",
                            C::RED,
                            C::RED_HOVER,
                            act(&view, |t: &mut Self, _, _| t.stop()),
                        )
                    } else {
                        button_primary(
                            "dnsc-go",
                            "▶ Run",
                            act(&view, |t: &mut Self, _, cx| t.run(cx)),
                        )
                    })
                    .child(copy_button("dnsc-copy", copy)),
            )
            .child(body)
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
