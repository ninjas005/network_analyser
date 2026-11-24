//! DNS Monitor: queries with their answers and times, totals per name,
//! server and client, on the shared capture session.

use std::ops::Range;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, UniformListScrollHandle, Window, div, prelude::*,
    px, rgb, uniform_list,
};

use crate::capture_view::{SourceBar, clip, error_line, ms, session_status};
use crate::dnsmon::{Agg, Txn};
use crate::gateway::Level;
use crate::session::{OpenTool, Session};
use crate::tools::Tool;
use crate::widgets::{
    Accept, C, TextInput, act, cell, chip, dot, empty_state, input, label, level_color, mono,
    status_bar, table_header, tile, toolbar,
};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Queries,
    Names,
    Servers,
    Clients,
}

const COLS: [(&str, f32); 8] = [
    ("TIME", 96.),
    ("CLIENT", 160.),
    ("SERVER", 160.),
    ("TYPE", 70.),
    ("NAME", 280.),
    ("RESULT", 130.),
    ("RESPONSE", 90.),
    ("ANSWER", 0.),
];

const AGG_COLS: [(&str, f32); 8] = [
    ("NAME", 360.),
    ("QUERIES", 90.),
    ("ANSWERS", 90.),
    ("NXDOMAIN", 90.),
    ("ERRORS", 80.),
    ("AVERAGE", 100.),
    ("SLOWEST", 100.),
    ("DISTINCT NAMES", 0.),
];

pub struct DnsMonView {
    focus: FocusHandle,
    session: Entity<Session>,
    bar: Entity<SourceBar>,
    filter: Entity<TextInput>,
    mode: Mode,
    problems: bool,
    newest: bool,
    selected: Option<(u64, usize)>,
    scroll: UniformListScrollHandle,
}

impl DnsMonView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let session = Session::shared(cx);
        cx.observe(&session, |_, _, cx| cx.notify()).detach();
        let filter = input(
            window,
            cx,
            "",
            "Filter: name, address, type, answer",
            Accept::Any,
            |t| t.width(280.),
            |_: &mut Self, _, _| {},
        );
        cx.observe(&filter, |_, _, cx| cx.notify()).detach();
        Self {
            focus: cx.focus_handle(),
            session,
            bar: cx.new(SourceBar::new),
            filter,
            mode: Mode::Queries,
            problems: false,
            newest: true,
            selected: None,
            scroll: UniformListScrollHandle::new(),
        }
    }

    fn rows(&self, cx: &App) -> Vec<usize> {
        let q = self.filter.read(cx).value.to_lowercase();
        let terms: Vec<&str> = q.split_whitespace().collect();
        let m = &self.session.read(cx).a.dns;
        let hit = |t: &Txn| {
            if self.problems {
                let (l, _) = t.status(m.now);
                let slow = t.time().is_some_and(|x| x > 0.2);
                if !matches!(l, Level::Bad | Level::Warn) && !slow && t.retries == 0 {
                    return false;
                }
            }
            if terms.is_empty() {
                return true;
            }
            let hay = format!(
                "{} {} {} {} {} {}",
                t.name,
                t.client,
                t.server,
                t.proto,
                crate::dns::type_name(t.qtype),
                t.answers.join(" ")
            )
            .to_lowercase();
            terms.iter().all(|w| hay.contains(w))
        };
        let mut v: Vec<usize> = m
            .txns
            .iter()
            .enumerate()
            .filter(|(_, t)| hit(t))
            .map(|(i, _)| i)
            .collect();
        if self.newest {
            v.reverse();
        }
        v
    }

    fn render_row(&self, i: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let s = self.session.read(cx);
        let Some(t) = s.a.dns.txns.get(i) else {
            return div().into_any_element();
        };
        let key = (s.generation, i);
        let t0 = s.a.stats.first.unwrap_or(0.0);
        let (l, status) = t.status(s.a.dns.now);
        let at = t.asked.or(t.answered).unwrap_or(t0) - t0;
        let slow = t.time().is_some_and(|x| x > 0.2);
        let status = match t.retries {
            0 => status,
            n => format!("{status} (×{})", n + 1),
        };
        div()
            .id(("dns", i))
            .w_full()
            .flex()
            .items_center()
            .h(px(26.))
            .px_3()
            .text_xs()
            .font_family(mono())
            .cursor_pointer()
            .when(self.selected == Some(key), |d| d.bg(rgb(C::SELECT)))
            .hover(|s| s.bg(rgb(C::PANEL2)))
            .child(cell(COLS[0].1, format!("{at:.3}")).text_color(rgb(C::MUTED)))
            .child(cell(COLS[1].1, t.client.to_string()))
            .child(cell(
                COLS[2].1,
                if t.multicast {
                    t.proto.clone()
                } else {
                    t.server.to_string()
                },
            ))
            .child(cell(COLS[3].1, crate::dns::type_name(t.qtype)).text_color(rgb(C::CYAN)))
            .child(cell(COLS[4].1, clip(&t.name, 255)))
            .child(cell(COLS[5].1, status).text_color(rgb(match l {
                Level::Info => C::MUTED,
                l => level_color(l),
            })))
            .child(cell(COLS[6].1, ms(t.time())).text_color(rgb(if slow {
                C::AMBER
            } else {
                C::TEXT
            })))
            .child(cell(0., clip(&t.answers.join(", "), 300)))
            .on_click(cx.listener(move |v, _, _, cx| {
                v.selected = if v.selected == Some(key) {
                    None
                } else {
                    Some(key)
                };
                cx.notify();
            }))
            .into_any_element()
    }

    fn render_detail(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let s = self.session.read(cx);
        let (g, i) = self.selected?;
        if g != s.generation || self.mode != Mode::Queries {
            return None;
        }
        let t = s.a.dns.txns.get(i)?;
        let mut rows: Vec<(&str, String)> = vec![
            ("Name", clip(&t.name, 255)),
            ("Type", crate::dns::type_name(t.qtype)),
            (
                "Transport",
                format!("{} over {}", t.proto, if t.tcp { "TCP" } else { "UDP" }),
            ),
            ("Client", t.client.to_string()),
            ("Server", t.server.to_string()),
            ("Transaction ID", format!("0x{:04x}", t.id)),
            ("Result", t.status(s.a.dns.now).1),
            ("Response time", ms(t.time()).to_string()),
            ("Repeated", t.retries.to_string()),
        ];
        if t.truncated {
            rows.push(("Truncated", "yes: the client should retry over TCP".into()));
        }
        if let Some(n) = t.min_ttl {
            rows.push(("Lowest TTL", format!("{n} s")));
        }
        for a in &t.answers {
            rows.push(("Answer", clip(a, 500)));
        }
        let show = |name: &'static str, no: Option<usize>| {
            no.map(|n| {
                chip(
                    name,
                    name,
                    false,
                    act(&self.session.downgrade(), move |s: &mut Session, _, cx| {
                        s.goto = s.a.packets.iter().position(|p| p.no == n);
                        cx.emit(OpenTool(Tool::Capture));
                    }),
                )
            })
        };
        Some(
            div()
                .id("dns-detail")
                .h(px(240.))
                .flex_none()
                .p_4()
                .flex()
                .flex_col()
                .gap_1()
                .overflow_y_scroll()
                .border_t_1()
                .border_color(rgb(C::BORDER))
                .bg(rgb(C::PANEL))
                .text_sm()
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .pb_1()
                        .children(show("Show query packet", t.nos.0))
                        .children(show("Show answer packet", t.nos.1)),
                )
                .children(
                    rows.into_iter()
                        .map(|(k, v)| crate::widgets::kv_row(k, v, 150.)),
                )
                .into_any_element(),
        )
    }

    fn render_aggs(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let q = self.filter.read(cx).value.trim().to_lowercase();
        let m = &self.session.read(cx).a.dns;
        let mut rows: Vec<(String, &Agg)> = match self.mode {
            Mode::Servers => m.servers.iter().map(|(k, v)| (k.to_string(), v)).collect(),
            Mode::Clients => m.clients.iter().map(|(k, v)| (k.to_string(), v)).collect(),
            _ => m.names.iter().map(|(k, v)| (k.clone(), v)).collect(),
        };
        rows.retain(|(k, a)| {
            (q.is_empty() || k.to_lowercase().contains(&q))
                && (!self.problems || a.nxdomain + a.errors > 0 || a.answers < a.queries)
        });
        rows.sort_by(|a, b| (b.1.queries, &a.0).cmp(&(a.1.queries, &b.0)));
        if rows.is_empty() {
            return empty_state("Nothing here", "No DNS traffic matches.").into_any_element();
        }
        let names = self.mode == Mode::Names;
        div()
            .id("dns-aggs")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .children(rows.into_iter().take(500).map(|(k, a)| {
                let warn = |n: u64| if n > 0 { C::AMBER } else { C::MUTED };
                div()
                    .flex()
                    .items_center()
                    .h(px(26.))
                    .px_3()
                    .text_xs()
                    .font_family(mono())
                    .child(cell(AGG_COLS[0].1, clip(&k, 255)))
                    .child(cell(AGG_COLS[1].1, a.queries.to_string()))
                    .child(cell(AGG_COLS[2].1, a.answers.to_string()))
                    .child(
                        cell(AGG_COLS[3].1, a.nxdomain.to_string())
                            .text_color(rgb(warn(a.nxdomain))),
                    )
                    .child(
                        cell(AGG_COLS[4].1, a.errors.to_string()).text_color(rgb(warn(a.errors))),
                    )
                    .child(cell(AGG_COLS[5].1, ms(a.avg())))
                    .child(cell(AGG_COLS[6].1, ms((a.timed > 0).then_some(a.time_max))))
                    .child(cell(
                        0.,
                        if names {
                            String::new()
                        } else {
                            a.names.len().to_string()
                        },
                    ))
            }))
            .into_any_element()
    }
}

impl Focusable for DnsMonView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for DnsMonView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let mut count = None;
        let body = if self.mode == Mode::Queries {
            let rows = self.rows(cx);
            let n = rows.len();
            count = Some(n);
            let list = if n == 0 {
                empty_state(
                    "No DNS traffic",
                    "Plain DNS, mDNS and LLMNR appear here. DNS over TLS or HTTPS is encrypted.",
                )
                .into_any_element()
            } else {
                uniform_list(
                    "dns-list",
                    n,
                    cx.processor(move |t, range: Range<usize>, _, cx| {
                        range
                            .filter_map(|i| rows.get(i).copied())
                            .map(|i| t.render_row(i, cx))
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(self.scroll.clone())
                .flex_1()
                .into_any_element()
            };
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .child(table_header(&COLS))
                .child(list)
        } else {
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_h_0()
                .child(table_header(&AGG_COLS))
                .child(self.render_aggs(cx))
        };
        let detail = self.render_detail(cx);
        let s = self.session.read(cx);
        let m = &s.a.dns;
        let un = m.unanswered();
        let sum = |f: fn(&Agg) -> u64| m.servers.values().map(f).sum::<u64>();
        let (nx, err) = (sum(|a| a.nxdomain), sum(|a| a.errors));
        let warn = |n: u64, c: u32| if n > 0 { c } else { C::TEXT };
        let mut types: Vec<_> = m.types.iter().collect();
        types.sort_by_key(|t| (std::cmp::Reverse(*t.1), *t.0));
        let types: Vec<String> = types
            .iter()
            .take(6)
            .map(|(t, n)| format!("{} {n}", crate::dns::type_name(**t)))
            .collect();
        let mode_chip = |mode: Mode, name: &'static str| {
            chip(
                name,
                name,
                self.mode == mode,
                act(&view, move |t: &mut Self, _, _| t.mode = mode),
            )
        };
        let findings = m.findings();
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(toolbar().child(self.bar.clone()).child(self.filter.clone()))
            .children(error_line(&s.error))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .px_5()
                    .py_3()
                    .child(tile("Queries", m.queries.to_string(), C::TEXT))
                    .child(tile("Answers", m.responses.to_string(), C::TEXT))
                    .child(tile("Average time", ms(m.avg()), C::TEXT))
                    .child(tile("No answer", un.to_string(), warn(un as u64, C::RED)))
                    .child(tile("NXDOMAIN", nx.to_string(), warn(nx, C::AMBER)))
                    .child(tile("Errors", err.to_string(), warn(err, C::RED)))
                    .child(tile("Names", m.names.len().to_string(), C::TEXT))
                    .child(tile("Servers", m.servers.len().to_string(), C::TEXT))
                    .child(tile("Clients", m.clients.len().to_string(), C::TEXT)),
            )
            .child(
                div()
                    .px_5()
                    .pb_2()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .text_sm()
                    .children(findings.into_iter().map(|(l, t)| {
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(dot(level_color(l)))
                            .child(t)
                    })),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_5()
                    .py_2()
                    .bg(rgb(C::PANEL))
                    .border_t_1()
                    .border_color(rgb(C::BORDER))
                    .child(mode_chip(Mode::Queries, "Queries"))
                    .child(mode_chip(Mode::Names, "Names"))
                    .child(mode_chip(Mode::Servers, "DNS servers"))
                    .child(mode_chip(Mode::Clients, "Client devices"))
                    .child(div().w(px(8.)))
                    .child(chip(
                        "dns-problems",
                        "Problems only",
                        self.problems,
                        act(&view, |t: &mut Self, _, _| t.problems = !t.problems),
                    ))
                    .when(self.mode == Mode::Queries, |d| {
                        d.child(chip(
                            "dns-newest",
                            "Newest first",
                            self.newest,
                            act(&view, |t: &mut Self, _, _| t.newest = !t.newest),
                        ))
                    })
                    .children(count.map(|n| label(format!("{n} shown"))))
                    .child(div().flex_1())
                    .child(label(types.join(" · "))),
            )
            .child(body)
            .children(detail)
            .when(m.ignored > 0, |d| {
                d.child(status_bar().child(format!("{} more queries not listed", m.ignored)))
            })
            .child(session_status(s))
    }
}
