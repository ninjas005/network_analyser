//! TCP Streams (follow a conversation), HTTP Reconstruction and TCP
//! Handshakes, on the shared capture session.

use std::ops::Range;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, UniformListScrollHandle, Window, div, prelude::*,
    px, rgb, uniform_list,
};

use crate::capture_view::{
    SourceBar, clip, error_line, human_bytes, ms, proto_color, session_status,
};
use crate::gateway::Level;
use crate::httpstream::{Exchange, Message};
use crate::session::{OpenTool, Session};
use crate::streams::{CLIENT, Close, HsState, SERVER, Stream};
use crate::tools::Tool;
use crate::widgets::{
    Accept, C, TextInput, act, cell, chip, copy_button, dot, empty_state, input, kv_row, label,
    level_color, mono, section_title, table_header, tile, toolbar,
};

/// Stream data shown / copied at most.
const MAX_FOLLOW: usize = 2 << 20;
const WRAP: usize = 150;
/// Wrap for the half-width HTTP panes.
const WRAP_HALF: usize = 76;

fn level_text(l: Level) -> u32 {
    match l {
        Level::Info => C::MUTED,
        l => level_color(l),
    }
}

fn contains(q: &str, hay: &str) -> bool {
    let hay = hay.to_lowercase();
    q.to_lowercase().split_whitespace().all(|t| hay.contains(t))
}

fn list_row(id: (&'static str, usize), selected: bool) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .w_full()
        .flex()
        .flex_row()
        .items_center()
        .h(px(26.))
        .px_3()
        .text_xs()
        .font_family(mono())
        .cursor_pointer()
        .when(selected, |d| d.bg(rgb(C::SELECT)))
        .hover(|s| s.bg(rgb(C::PANEL2)))
}

fn detail_pane(h: f32) -> gpui::Div {
    div()
        .h(px(h))
        .flex_none()
        .flex()
        .flex_col()
        .border_t_1()
        .border_color(rgb(C::BORDER))
        .bg(rgb(C::PANEL))
}

fn goto_chip(
    s: &Entity<Session>,
    name: &'static str,
    stream: usize,
    tool: Tool,
) -> impl IntoElement {
    chip(
        name,
        name,
        false,
        act(&s.downgrade(), move |s: &mut Session, _, cx| {
            s.stream = Some(stream);
            cx.emit(OpenTool(tool));
        }),
    )
}

fn filter_input<V: 'static>(hint: &str, window: &Window, cx: &mut Context<V>) -> Entity<TextInput> {
    let e = input(
        window,
        cx,
        "",
        hint,
        Accept::Any,
        |t| t.width(300.),
        |_: &mut V, _, _| {},
    );
    cx.observe(&e, |_, _, cx| cx.notify()).detach();
    e
}

// ---------------------------------------------------------------- TCP streams

const STREAM_COLS: [(&str, f32); 9] = [
    ("#", 56.),
    ("CLIENT", 200.),
    ("SERVER", 200.),
    ("PROTOCOL", 130.),
    ("PACKETS", 74.),
    ("SENT", 84.),
    ("RECEIVED", 84.),
    ("DURATION", 84.),
    ("STATE", 0.),
];

struct Line {
    dir: usize,
    text: String,
    /// Header of a run of data, or a gap note.
    note: bool,
}

pub struct StreamsView {
    focus: FocusHandle,
    session: Entity<Session>,
    bar: Entity<SourceBar>,
    filter: Entity<TextInput>,
    only: Option<usize>,
    hex: bool,
    /// Lines of the followed stream and what they were made from.
    lines: Vec<Line>,
    cut: bool,
    key: Option<(u64, usize, usize, Option<usize>, bool)>,
    scroll: UniformListScrollHandle,
    body: UniformListScrollHandle,
}

impl StreamsView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let session = Session::shared(cx);
        cx.observe(&session, |_, _, cx| cx.notify()).detach();
        Self {
            focus: cx.focus_handle(),
            session,
            bar: cx.new(SourceBar::new),
            filter: filter_input("Filter: address, port, protocol, server name", window, cx),
            only: None,
            hex: false,
            lines: Vec::new(),
            cut: false,
            key: None,
            scroll: UniformListScrollHandle::new(),
            body: UniformListScrollHandle::new(),
        }
    }

    fn rows(&self, cx: &App) -> Vec<usize> {
        let q = self.filter.read(cx).value.trim().to_string();
        let s = self.session.read(cx);
        s.a.tcp
            .streams
            .iter()
            .filter(|x| {
                q.is_empty()
                    || contains(
                        &q,
                        &format!(
                            "{} {} {} {} {} {}",
                            x.client(),
                            x.server(),
                            x.proto,
                            x.sni.as_deref().unwrap_or(""),
                            x.state().label(),
                            x.close().label()
                        ),
                    )
            })
            .map(|x| x.id)
            .collect()
    }

    /// Rebuild the followed text when the stream or the options changed.
    fn refresh(&mut self, cx: &App) {
        let s = self.session.read(cx);
        let Some(st) = s.stream.and_then(|i| s.a.tcp.streams.get(i)) else {
            self.lines.clear();
            self.key = None;
            return;
        };
        let key = (s.generation, st.id, st.chunks.len(), self.only, self.hex);
        if self.key == Some(key) {
            return;
        }
        self.key = Some(key);
        self.lines.clear();
        let (parts, cut) = s.a.tcp.follow(&s.a.packets, st.id, self.only, MAX_FOLLOW);
        self.cut = cut;
        let t0 = st.first;
        for p in parts {
            let dir = p.dir;
            let who = if dir == CLIENT { "Client" } else { "Server" };
            self.lines.push(Line {
                dir,
                text: format!(
                    "{who} · packet {} · +{:.6} s · {} bytes",
                    p.no,
                    p.ts - t0,
                    p.data.len()
                ),
                note: true,
            });
            if p.gap > 0 {
                self.lines.push(Line {
                    dir,
                    text: format!("[{} bytes missing from the capture]", p.gap),
                    note: true,
                });
            }
            if self.hex {
                self.lines.extend(
                    crate::dissect::hexdump(&p.data)
                        .into_iter()
                        .map(|text| Line {
                            dir,
                            text,
                            note: false,
                        }),
                );
            } else {
                for text in text_lines(&p.data, WRAP) {
                    self.lines.push(Line {
                        dir,
                        text,
                        note: false,
                    });
                }
            }
        }
    }

    fn render_row(&self, id: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let s = self.session.read(cx);
        let Some(x) = s.a.tcp.streams.get(id) else {
            return div().into_any_element();
        };
        let proto = match &x.sni {
            Some(n) => format!("{} {n}", x.proto),
            None => x.proto.clone(),
        };
        let mut state = format!("{} · {}", x.state().label(), x.close().label());
        if x.retrans() > 0 {
            state += &format!(" · {} retransmissions", x.retrans());
        }
        if x.lost() > 0 {
            state += &format!(" · {} not captured", human_bytes(x.lost()));
        }
        if x.cut {
            state += " · packets not kept";
        }
        let color = proto_color(&x.proto);
        let row = list_row(("stream", id), s.stream == Some(id))
            .child(cell(STREAM_COLS[0].1, id.to_string()).text_color(rgb(C::MUTED)))
            .child(cell(STREAM_COLS[1].1, x.client()))
            .child(cell(STREAM_COLS[2].1, x.server()))
            .child(cell(STREAM_COLS[3].1, proto).text_color(rgb(color)))
            .child(cell(STREAM_COLS[4].1, x.packets().to_string()))
            .child(cell(STREAM_COLS[5].1, human_bytes(x.dirs[CLIENT].bytes())))
            .child(cell(STREAM_COLS[6].1, human_bytes(x.dirs[SERVER].bytes())))
            .child(cell(STREAM_COLS[7].1, format!("{:.3} s", x.duration())))
            .child(cell(0., state).text_color(rgb(level_text(x.state().level()))));
        row.on_click(cx.listener(move |t, _, _, cx| {
            t.session.update(cx, |s, cx| {
                s.stream = Some(id);
                cx.notify();
            });
            t.body = UniformListScrollHandle::new();
            cx.notify();
        }))
        .into_any_element()
    }

    fn render_follow(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let view = cx.entity().downgrade();
        let s = self.session.read(cx);
        let x = s.stream.and_then(|i| s.a.tcp.streams.get(i))?;
        let id = x.id;
        let has_http = x.http.as_ref().is_some_and(|h| !h.exchanges.is_empty());
        let upgraded = x.http.as_ref().and_then(|h| h.upgraded.clone());
        let title = format!("Stream {id}: {} → {}", x.client(), x.server());
        let how = x.how.map(|h| format!("{} by {}", x.proto, h.text()));
        let only = self.only;
        let dir_chip = |name: &'static str, o: Option<usize>| {
            chip(
                name,
                name,
                self.only == o,
                act(&view, move |t: &mut Self, _, _| t.only = o),
            )
        };
        let body = if self.lines.is_empty() {
            empty_state("No data", "This connection carried no payload.").into_any_element()
        } else {
            uniform_list(
                "follow",
                self.lines.len(),
                cx.processor(|t, range: Range<usize>, _, _| {
                    range
                        .filter_map(|i| t.lines.get(i))
                        .map(|l| {
                            let c = match (l.note, l.dir) {
                                (true, CLIENT) => C::ACCENT,
                                (true, _) => C::GREEN,
                                (_, CLIENT) => 0xb9d0ff,
                                _ => 0xbfeccf,
                            };
                            div()
                                .h(px(17.))
                                .px_4()
                                .whitespace_nowrap()
                                .text_color(rgb(c))
                                .when(l.note, |d| d.font_weight(gpui::FontWeight::SEMIBOLD))
                                .child(l.text.clone())
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.body.clone())
            .flex_1()
            .font_family(mono())
            .text_xs()
            .into_any_element()
        };
        Some(
            detail_pane(380.)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_wrap()
                        .gap_2()
                        .px_4()
                        .py_2()
                        .child(section_title(&title))
                        .children(how.map(label))
                        .children(upgraded.map(|u| label(format!("switched to {}", clip(&u, 40)))))
                        .child(div().flex_1())
                        .child(dir_chip("Both", None))
                        .child(dir_chip("Client only", Some(CLIENT)))
                        .child(dir_chip("Server only", Some(SERVER)))
                        .child(chip(
                            "hex",
                            "Hex",
                            self.hex,
                            act(&view, |t: &mut Self, _, _| t.hex = !t.hex),
                        ))
                        .child(chip(
                            "copy-stream",
                            "Copy",
                            false,
                            cx.listener(|t, _, _, cx| {
                                let text: Vec<&str> =
                                    t.lines.iter().map(|l| l.text.as_str()).collect();
                                cx.write_to_clipboard(gpui::ClipboardItem::new_string(
                                    text.join("\n"),
                                ));
                            }),
                        ))
                        .child(chip(
                            "save-stream",
                            "Save raw",
                            false,
                            act(&self.session.downgrade(), move |s: &mut Session, _, _| {
                                let (parts, _) = s.a.tcp.follow(&s.a.packets, id, only, usize::MAX);
                                let data: Vec<u8> =
                                    parts.into_iter().flat_map(|p| p.data).collect();
                                let name = match only {
                                    None => format!("stream-{id}"),
                                    Some(CLIENT) => format!("stream-{id}-client"),
                                    Some(_) => format!("stream-{id}-server"),
                                };
                                s.save_bytes(&name, "bin", &data);
                            }),
                        ))
                        .child(goto_chip(&self.session, "Handshake", id, Tool::Handshake))
                        .when(has_http, |d| {
                            d.child(goto_chip(&self.session, "HTTP", id, Tool::HttpStreams))
                        }),
                )
                .when(self.cut, |d| {
                    d.child(
                        div().px_4().child(
                            label("Only the first 2 MB are shown; Save raw writes everything.")
                                .text_color(rgb(C::AMBER)),
                        ),
                    )
                })
                .child(body)
                .into_any_element(),
        )
    }
}

/// Text view of binary data: control characters as dots, long lines split.
fn text_lines(data: &[u8], wrap: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let mut cur = String::new();
        let mut n = 0;
        for c in line.chars() {
            if n == wrap {
                out.push(std::mem::take(&mut cur));
                n = 0;
            }
            match c {
                '\t' => cur.push_str("    "),
                c if c.is_control() || c == '\u{fffd}' => cur.push('.'),
                c => cur.push(c),
            }
            n += 1;
        }
        out.push(cur);
    }
    if out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}

impl Focusable for StreamsView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for StreamsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.refresh(cx);
        let rows = self.rows(cx);
        let n = rows.len();
        let list = if n == 0 {
            empty_state(
                "No TCP streams",
                "Start a capture or open a capture file containing TCP traffic.",
            )
            .into_any_element()
        } else {
            uniform_list(
                "streams",
                n,
                cx.processor(move |t, range: Range<usize>, _, cx| {
                    range
                        .filter_map(|i| rows.get(i).copied())
                        .map(|id| t.render_row(id, cx))
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };
        let follow = self.render_follow(cx);
        let s = self.session.read(cx);
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(self.bar.clone())
                    .child(self.filter.clone())
                    .child(label(format!("{n} streams")))
                    .when(s.a.tcp.ignored > 0, |d| {
                        d.child(
                            label(format!("{} packets of further streams", s.a.tcp.ignored))
                                .text_color(rgb(C::AMBER)),
                        )
                    }),
            )
            .children(error_line(&s.error))
            .child(table_header(&STREAM_COLS))
            .child(list)
            .children(follow)
            .child(session_status(s))
    }
}

// ---------------------------------------------------------------- HTTP

const HTTP_COLS: [(&str, f32); 9] = [
    ("STREAM", 70.),
    ("METHOD", 80.),
    ("HOST", 200.),
    ("STATUS", 70.),
    ("TYPE", 170.),
    ("SIZE", 90.),
    ("WAIT", 90.),
    ("TOTAL", 90.),
    ("TARGET", 0.),
];

pub struct HttpView {
    focus: FocusHandle,
    session: Entity<Session>,
    bar: Entity<SourceBar>,
    filter: Entity<TextInput>,
    errors: bool,
    /// (stream, exchange)
    selected: Option<(usize, usize)>,
    generation: u64,
    hex: bool,
    /// Decoded bodies for the selection: request, response.
    bodies: [Option<Body>; 2],
    key: Option<(u64, usize, usize, u64, u64)>,
    scroll: UniformListScrollHandle,
}

#[derive(Default)]
struct Body {
    data: Vec<u8>,
    note: Option<String>,
}

impl HttpView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let session = Session::shared(cx);
        cx.observe(&session, |_, _, cx| cx.notify()).detach();
        Self {
            focus: cx.focus_handle(),
            session,
            bar: cx.new(SourceBar::new),
            filter: filter_input("Filter: host, path, method, status, type", window, cx),
            errors: false,
            selected: None,
            generation: 0,
            hex: false,
            bodies: [None, None],
            key: None,
            scroll: UniformListScrollHandle::new(),
        }
    }

    fn exchange(s: &Session, sel: (usize, usize)) -> Option<&Exchange> {
        let st = s.a.tcp.streams.get(sel.0)?;
        st.http.as_ref()?.exchanges.get(sel.1)
    }

    /// Matching exchanges, oldest first.
    fn rows(&self, cx: &App) -> Vec<(usize, usize)> {
        let q = self.filter.read(cx).value.trim().to_string();
        let s = self.session.read(cx);
        let mut v: Vec<(f64, (usize, usize))> = Vec::new();
        for st in &s.a.tcp.streams {
            let Some(h) = &st.http else { continue };
            for (i, e) in h.exchanges.iter().enumerate() {
                let status = e.resp.as_ref().map_or(0, |r| r.status());
                if self.errors && (200..400).contains(&status) {
                    continue;
                }
                if !q.is_empty() {
                    let hay = format!(
                        "{} {} {status} {} stream{}",
                        e.req.as_ref().map_or("", |r| r.method()),
                        e.url(),
                        e.resp.as_ref().map_or("", |r| r.content_type()),
                        st.id
                    );
                    if !contains(&q, &hay) {
                        continue;
                    }
                }
                v.push((e.start(), (st.id, i)));
            }
        }
        v.sort_by(|a, b| a.0.total_cmp(&b.0));
        v.into_iter().map(|x| x.1).collect()
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let s = self.session.read(cx);
        if s.generation != self.generation {
            self.generation = s.generation;
            self.selected = None;
        }
        // "HTTP" chosen for a stream elsewhere: select its first exchange.
        if let Some(st) = s.stream
            && self.selected.is_none_or(|x| x.0 != st)
            && Self::exchange(s, (st, 0)).is_some()
        {
            self.selected = Some((st, 0));
        }
        let Some((sel, e)) = self.selected.and_then(|x| Some((x, Self::exchange(s, x)?))) else {
            self.bodies = [None, None];
            self.key = None;
            return;
        };
        let len = |m: &Option<Message>| m.as_ref().map_or(0, |m| m.body_len);
        let key = (s.generation, sel.0, sel.1, len(&e.req), len(&e.resp));
        if self.key != Some(key) {
            self.key = Some(key);
            self.bodies = [&e.req, &e.resp].map(|m| {
                m.as_ref().map(|m| {
                    let (data, note) = m.decoded();
                    Body { data, note }
                })
            });
        }
    }

    fn render_row(&self, r: (usize, usize), n: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let s = self.session.read(cx);
        let Some(e) = Self::exchange(s, r) else {
            return div().into_any_element();
        };
        let req = e.req.as_ref();
        let resp = e.resp.as_ref();
        let status = resp.map_or(0, |r| r.status());
        let sc = match status {
            200..=299 => C::GREEN,
            300..=399 => C::CYAN,
            400..=499 => C::AMBER,
            500..=599 => C::RED,
            _ => C::MUTED,
        };
        let row = list_row(("http", n), self.selected == Some(r))
            .child(cell(HTTP_COLS[0].1, r.0.to_string()).text_color(rgb(C::MUTED)))
            .child(cell(
                HTTP_COLS[1].1,
                clip(req.map_or("—", |r| r.method()), 20),
            ))
            .child(cell(HTTP_COLS[2].1, clip(e.host(), 80)))
            .child(
                cell(
                    HTTP_COLS[3].1,
                    if resp.is_some() {
                        status.to_string()
                    } else {
                        "—".into()
                    },
                )
                .text_color(rgb(sc)),
            )
            .child(cell(
                HTTP_COLS[4].1,
                clip(resp.map_or("", |r| r.content_type()), 60),
            ))
            .child(cell(
                HTTP_COLS[5].1,
                resp.map_or(String::new(), |r| human_bytes(r.body_len)),
            ))
            .child(cell(HTTP_COLS[6].1, ms(e.wait())))
            .child(cell(HTTP_COLS[7].1, ms(e.total())))
            .child(cell(
                0.,
                clip(req.map_or("(request not captured)", |r| r.target()), 300),
            ));
        row.on_click(cx.listener(move |t, _, _, cx| {
            t.selected = Some(r);
            // Keep the stream tools on the same connection.
            t.session.update(cx, |s, _| s.stream = Some(r.0));
            cx.notify();
        }))
        .into_any_element()
    }

    fn render_message(
        &self,
        side: usize,
        m: &Message,
        name: String,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let title = if side == 0 { "Request" } else { "Response" };
        let body = self.bodies[side].as_ref();
        let data = body.map_or(&[][..], |b| &b.data[..]);
        let mut notes: Vec<(u32, String)> = Vec::new();
        if m.missing > 0 {
            notes.push((
                C::AMBER,
                format!("{} bytes of the body were not captured", m.missing),
            ));
        } else if !m.complete {
            notes.push((C::AMBER, "Message is not complete in the capture".into()));
        }
        if m.body_len > m.body.len() as u64 {
            notes.push((
                C::AMBER,
                format!(
                    "{} of {} body kept",
                    human_bytes(m.body.len() as u64),
                    human_bytes(m.body_len)
                ),
            ));
        }
        if let Some(n) = body.and_then(|b| b.note.clone()) {
            notes.push((C::AMBER, n));
        }
        let shown = &data[..data.len().min(32 << 10)];
        let binary = shown
            .iter()
            .filter(|b| **b < 9 || (14..32).contains(*b))
            .count()
            * 20
            > shown.len();
        let lines: Vec<String> = if self.hex || binary {
            crate::dissect::hexdump(&shown[..shown.len().min(8 << 10)])
        } else {
            text_lines(shown, WRAP_HALF)
        };
        let total = lines.len();
        let ext = body_ext(m.content_type());
        let info = format!(
            "{} body bytes{}",
            m.body_len,
            match m.header("content-encoding") {
                Some(e) => format!(", {} ({} decoded)", clip(e, 20), data.len()),
                None => String::new(),
            }
        );
        let copy = String::from_utf8_lossy(data).into_owned();
        let save = data.to_vec();
        let id = if side == 0 { "http-req" } else { "http-resp" };
        div()
            .id(id)
            .flex_1()
            .min_w_0()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_1()
            .overflow_y_scroll()
            .text_sm()
            .when(side == 1, |d| d.border_l_1().border_color(rgb(C::BORDER)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(section_title(title))
                    .child(label(format!("packet {}", m.no)))
                    .child(div().flex_1())
                    .when(!data.is_empty(), |d| {
                        d.child(copy_button(
                            if side == 0 { "copy-req" } else { "copy-resp" },
                            copy,
                        ))
                        .child(chip(
                            if side == 0 { "save-req" } else { "save-resp" },
                            "Save body",
                            false,
                            cx.listener(move |t, _, _, cx| {
                                let (name, save) = (name.clone(), save.clone());
                                t.session.update(cx, |s, cx| {
                                    s.save_bytes(&name, ext, &save);
                                    cx.notify();
                                });
                            }),
                        ))
                    }),
            )
            .child(
                div()
                    .font_family(mono())
                    .text_xs()
                    .child(clip(&m.line, 600)),
            )
            .children(notes.into_iter().map(|(c, t)| label(t).text_color(rgb(c))))
            .children(
                m.headers
                    .iter()
                    .take(60)
                    .map(|(k, v)| kv_row(clip(k, 60), clip(v, 600), 170.)),
            )
            .when(m.body_len > 0, |d| {
                d.child(div().pt_2().child(label(info)))
                    .child(
                        div().font_family(mono()).text_xs().children(
                            lines
                                .into_iter()
                                .take(400)
                                .map(|l| div().whitespace_nowrap().min_h(px(16.)).child(l)),
                        ),
                    )
                    .when(total > 400 || data.len() > shown.len(), |d| {
                        d.child(label("Preview only: use Save body for everything"))
                    })
            })
            .into_any_element()
    }

    fn render_detail(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let sel = self.selected?;
        let e = Self::exchange(self.session.read(cx), sel)?.clone();
        let view = cx.entity().downgrade();
        let name = format!("http-{}-{}", sel.0, sel.1);
        let none = |t: &str| {
            div()
                .flex_1()
                .p_4()
                .child(label(t.to_string()))
                .into_any_element()
        };
        let left = match &e.req {
            Some(m) => self.render_message(0, m, format!("{name}-request"), cx),
            None => none("The request was not captured"),
        };
        let right = match &e.resp {
            Some(m) => self.render_message(1, m, format!("{name}-response"), cx),
            None => none("No response in the capture"),
        };
        Some(
            detail_pane(400.)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_4()
                        .py_2()
                        .child(label(clip(&e.url(), 160)).text_color(rgb(C::TEXT)))
                        .children(e.interim.iter().take(3).map(|l| label(clip(l, 60))))
                        .child(div().flex_1())
                        .child(chip(
                            "http-hex",
                            "Hex bodies",
                            self.hex,
                            act(&view, |t: &mut Self, _, _| t.hex = !t.hex),
                        ))
                        .children(e.curl().map(|c| {
                            chip(
                                "copy-curl",
                                "Copy as curl",
                                false,
                                move |_, _, cx: &mut App| {
                                    cx.write_to_clipboard(gpui::ClipboardItem::new_string(
                                        c.clone(),
                                    ))
                                },
                            )
                        }))
                        .child(goto_chip(
                            &self.session,
                            "Follow stream",
                            sel.0,
                            Tool::TcpStreams,
                        )),
                )
                .child(div().flex().flex_1().min_h_0().child(left).child(right))
                .into_any_element(),
        )
    }
}

/// File extension for a saved body (never taken from the traffic itself).
fn body_ext(ct: &str) -> &'static str {
    match ct.to_ascii_lowercase().as_str() {
        "text/html" => "html",
        "application/json" => "json",
        "text/css" => "css",
        "text/xml" | "application/xml" | "application/soap+xml" => "xml",
        "text/csv" => "csv",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        t if t.starts_with("text/") => "txt",
        _ => "bin",
    }
}

impl Focusable for HttpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for HttpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.refresh(cx);
        let view = cx.entity().downgrade();
        let rows = self.rows(cx);
        let n = rows.len();
        let list = if n == 0 {
            empty_state(
                "No HTTP traffic",
                "Unencrypted HTTP/1.x on any port appears here. HTTPS content is encrypted and cannot be reconstructed.",
            )
            .into_any_element()
        } else {
            uniform_list(
                "http-list",
                n,
                cx.processor(move |t, range: Range<usize>, _, cx| {
                    range
                        .filter_map(|i| Some((i, rows.get(i).copied()?)))
                        .map(|(i, r)| t.render_row(r, i, cx))
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };
        let detail = self.render_detail(cx);
        let s = self.session.read(cx);
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(self.bar.clone())
                    .child(self.filter.clone())
                    .child(chip(
                        "http-err",
                        "Problems only",
                        self.errors,
                        act(&view, |t: &mut Self, _, _| t.errors = !t.errors),
                    ))
                    .child(label(format!("{n} exchanges"))),
            )
            .children(error_line(&s.error))
            .child(table_header(&HTTP_COLS))
            .child(list)
            .children(detail)
            .child(session_status(s))
    }
}

// ---------------------------------------------------------------- handshakes

const HS_COLS: [(&str, f32); 9] = [
    ("#", 56.),
    ("CLIENT", 200.),
    ("SERVER", 200.),
    ("RESULT", 140.),
    ("SERVER RTT", 110.),
    ("CLIENT RTT", 110.),
    ("TOTAL", 84.),
    ("SYNS", 60.),
    ("CLOSE", 0.),
];

pub struct HandshakeView {
    focus: FocusHandle,
    session: Entity<Session>,
    bar: Entity<SourceBar>,
    filter: Entity<TextInput>,
    state: Option<HsState>,
    scroll: UniformListScrollHandle,
}

impl HandshakeView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let session = Session::shared(cx);
        cx.observe(&session, |_, _, cx| cx.notify()).detach();
        Self {
            focus: cx.focus_handle(),
            session,
            bar: cx.new(SourceBar::new),
            filter: filter_input("Filter: address or port", window, cx),
            state: None,
            scroll: UniformListScrollHandle::new(),
        }
    }

    fn render_row(&self, id: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let s = self.session.read(cx);
        let Some(x) = s.a.tcp.streams.get(id) else {
            return div().into_any_element();
        };
        let close = x.close();
        let cc = match close {
            Close::Reset(_) => C::AMBER,
            Close::Fin(_) => C::MUTED,
            _ => C::TEXT,
        };
        let row = list_row(("hs", id), s.stream == Some(id))
            .child(cell(HS_COLS[0].1, id.to_string()).text_color(rgb(C::MUTED)))
            .child(cell(HS_COLS[1].1, x.client()))
            .child(cell(HS_COLS[2].1, x.server()))
            .child(
                cell(HS_COLS[3].1, x.state().label())
                    .text_color(rgb(level_text(x.state().level()))),
            )
            .child(cell(HS_COLS[4].1, ms(x.hs.server_rtt())))
            .child(cell(HS_COLS[5].1, ms(x.hs.client_rtt())))
            .child(cell(HS_COLS[6].1, ms(x.hs.total())))
            .child(
                cell(HS_COLS[7].1, x.hs.syns.to_string()).text_color(rgb(if x.hs.syns > 1 {
                    C::AMBER
                } else {
                    C::MUTED
                })),
            )
            .child(cell(0., close.label()).text_color(rgb(cc)));
        row.on_click(cx.listener(move |t, _, _, cx| {
            t.session.update(cx, |s, cx| {
                s.stream = Some(id);
                cx.notify();
            });
        }))
        .into_any_element()
    }

    /// Ladder of the three packets with their delays.
    fn ladder(&self, x: &Stream) -> gpui::Div {
        let h = &x.hs;
        let t0 = h.syn_first.or(h.synack).unwrap_or(x.first);
        let step = |right: bool, name: &str, t: Option<f64>, no: Option<usize>, extra: String| {
            let (c, text) = match t {
                Some(t) => (
                    if h.refused && !right {
                        C::RED
                    } else {
                        C::GREEN
                    },
                    format!(
                        "{name}{extra}   +{:.3} ms{}",
                        (t - t0) * 1000.0,
                        no.map_or(String::new(), |n| format!("   packet {n}"))
                    ),
                ),
                None => (C::RED, format!("{name} not seen")),
            };
            let line = || div().h(px(1.)).flex_1().bg(rgb(c));
            div()
                .flex()
                .items_center()
                .gap_2()
                .h(px(26.))
                .text_xs()
                .text_color(rgb(c))
                .when(!right, |d| d.child("◀"))
                .child(line())
                .child(div().whitespace_nowrap().child(text))
                .child(line())
                .when(right, |d| d.child("▶"))
        };
        let times = |n: u32| {
            if n > 1 {
                format!(" (×{n})")
            } else {
                String::new()
            }
        };
        let second = if h.refused {
            step(false, "RST (refused)", Some(x.last), None, String::new())
        } else {
            step(false, "SYN, ACK", h.synack, h.nos[1], times(h.synacks))
        };
        div()
            .flex()
            .flex_col()
            .w(px(520.))
            .flex_none()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .text_xs()
                    .child(x.client())
                    .child(x.server()),
            )
            .child(step(true, "SYN", h.syn_first, h.nos[0], times(h.syns)))
            .child(second)
            .when(!h.refused, |d| {
                d.child(step(true, "ACK", h.ack, h.nos[2], String::new()))
            })
    }

    fn render_detail(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let s = self.session.read(cx);
        let x = s.stream.and_then(|i| s.a.tcp.streams.get(i))?;
        let yes = |b: bool| if b { "yes" } else { "no" }.to_string();
        let opt = |o: Option<String>| o.unwrap_or_else(|| "—".into());
        let opts: Vec<(&str, [String; 2])> = vec![
            (
                "MSS",
                [0, 1].map(|i| opt(x.dirs[i].opts.mss.map(|m| m.to_string()))),
            ),
            (
                "Window scale",
                [0, 1].map(|i| opt(x.dirs[i].opts.wscale.map(|w| format!("×{}", 1u32 << w)))),
            ),
            (
                "SACK permitted",
                [0, 1].map(|i| yes(x.dirs[i].opts.sack_ok)),
            ),
            ("Timestamps", [0, 1].map(|i| yes(x.dirs[i].opts.timestamps))),
            ("Multipath TCP", [0, 1].map(|i| yes(x.dirs[i].opts.mptcp))),
            (
                "Initial window",
                [0, 1].map(|i| x.dirs[i].syn_window.to_string()),
            ),
            (
                "Largest window",
                [0, 1].map(|i| human_bytes(x.dirs[i].max_window)),
            ),
            (
                "Retransmissions",
                [0, 1].map(|i| x.dirs[i].retrans.to_string()),
            ),
            (
                "Out of order",
                [0, 1].map(|i| x.dirs[i].out_of_order.to_string()),
            ),
            (
                "Duplicate ACKs",
                [0, 1].map(|i| x.dirs[i].dup_acks.to_string()),
            ),
            (
                "Zero window",
                [0, 1].map(|i| x.dirs[i].zero_window.to_string()),
            ),
            (
                "Keep-alives",
                [0, 1].map(|i| x.dirs[i].keepalives.to_string()),
            ),
        ];
        let id = x.id;
        let syn_no = x.hs.nos[0].or(x.hs.nos[1]);
        // Packet numbers start at 1 in list order.
        let goto = syn_no.map(|n| {
            chip(
                "goto-syn",
                "Show packet",
                false,
                act(&self.session.downgrade(), move |s: &mut Session, _, cx| {
                    s.goto = s.a.packets.iter().position(|p| p.no == n);
                    cx.emit(OpenTool(Tool::Capture));
                }),
            )
        });
        Some(
            detail_pane(330.)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_4()
                        .py_2()
                        .child(section_title(&format!("Connection {id}")))
                        .child(div().flex_1())
                        .children(goto)
                        .child(goto_chip(
                            &self.session,
                            "Follow stream",
                            id,
                            Tool::TcpStreams,
                        )),
                )
                .child(
                    div()
                        .id("hs-detail")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .px_4()
                        .pb_4()
                        .flex()
                        .flex_row()
                        .gap_5()
                        .text_sm()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_3()
                                .child(self.ladder(x))
                                .children(x.findings().into_iter().map(|(l, t)| {
                                    div()
                                        .w(px(520.))
                                        .flex()
                                        .items_start()
                                        .gap_2()
                                        .child(div().pt(px(6.)).child(dot(level_color(l))))
                                        .child(div().flex_1().min_w_0().child(t))
                                })),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    div()
                                        .flex()
                                        .text_xs()
                                        .text_color(rgb(C::MUTED))
                                        .child(cell(150., ""))
                                        .child(cell(120., "CLIENT"))
                                        .child(cell(120., "SERVER")),
                                )
                                .children(opts.into_iter().map(|(k, [a, b])| {
                                    div()
                                        .flex()
                                        .h(px(22.))
                                        .child(cell(150., k).text_color(rgb(C::MUTED)))
                                        .child(cell(120., a))
                                        .child(cell(120., b))
                                })),
                        ),
                )
                .into_any_element(),
        )
    }
}

impl Focusable for HandshakeView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for HandshakeView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let q = self.filter.read(cx).value.trim().to_string();
        let s = self.session.read(cx);
        let mut counts = [0usize; HsState::ALL.len()];
        let mut rtts: Vec<f64> = Vec::new();
        let mut rows: Vec<usize> = Vec::new();
        // Unfinished connections per server: SYN floods and dead services.
        let mut unfinished: std::collections::HashMap<(std::net::IpAddr, u16), usize> =
            Default::default();
        for x in &s.a.tcp.streams {
            let st = x.state();
            if let Some(i) = HsState::ALL.iter().position(|a| *a == st) {
                counts[i] += 1;
            }
            rtts.extend(x.hs.server_rtt());
            if matches!(st, HsState::HalfOpen | HsState::NoAnswer) {
                *unfinished.entry(x.ends[SERVER]).or_default() += 1;
            }
            if self.state.is_none_or(|w| w == st)
                && (q.is_empty() || contains(&q, &format!("{} {}", x.client(), x.server())))
            {
                rows.push(x.id);
            }
        }
        rtts.sort_by(f64::total_cmp);
        let median = rtts.get(rtts.len() / 2).copied();
        let worst = rtts.last().copied();
        let flood = unfinished
            .iter()
            .max_by_key(|(_, n)| **n)
            .filter(|(_, n)| **n >= 20)
            .map(|(e, n)| {
                format!(
                    "{n} unfinished handshakes to {}: SYN flood, port scan or a dead service",
                    crate::streams::endpoint(*e)
                )
            });
        let n = rows.len();
        let tiles = div()
            .flex()
            .flex_wrap()
            .gap_3()
            .px_5()
            .py_3()
            .children(HsState::ALL.iter().zip(counts).map(|(st, c)| {
                tile(
                    st.label(),
                    c.to_string(),
                    if c == 0 {
                        C::MUTED
                    } else {
                        level_text(st.level())
                    },
                )
            }))
            .child(tile("Median round trip", ms(median), C::TEXT))
            .child(tile("Slowest", ms(worst), C::TEXT));
        let chips = std::iter::once((None, "All"))
            .chain(HsState::ALL.iter().map(|s| (Some(*s), s.label())))
            .map(|(st, name)| {
                chip(
                    name,
                    name,
                    self.state == st,
                    act(&view, move |t: &mut Self, _, _| t.state = st),
                )
            })
            .collect::<Vec<_>>();
        let list = if n == 0 {
            empty_state(
                "No TCP connections",
                "Start a capture or open a capture file containing TCP traffic.",
            )
            .into_any_element()
        } else {
            uniform_list(
                "handshakes",
                n,
                cx.processor(move |t, range: Range<usize>, _, cx| {
                    range
                        .filter_map(|i| rows.get(i).copied())
                        .map(|id| t.render_row(id, cx))
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };
        let detail = self.render_detail(cx);
        let s = self.session.read(cx);
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(self.bar.clone())
                    .child(self.filter.clone())
                    .children(chips),
            )
            .children(error_line(&s.error))
            .children(flood.map(|f| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::AMBER))
                    .child(f)
            }))
            .child(tiles)
            .child(table_header(&HS_COLS))
            .child(list)
            .children(detail)
            .child(session_status(s))
    }
}
