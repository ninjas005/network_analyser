//! WebSocket tool: connect to ws:// or wss:// with custom headers and
//! subprotocols, inspect the upgrade handshake, send text / binary / ping,
//! follow a frame log with payload inspector, ping RTT and close codes.

use std::ops::Range;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use gpui::{
    App, ClipboardItem, Context, Entity, FocusHandle, Focusable, ScrollStrategy, SharedString,
    Task, UniformListScrollHandle, Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::mqtt_view::{mono_block, payload_text};
use crate::websocket::{
    self, Cmd, Config, Event, HandshakeInfo, LogFrame, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG,
    OP_TEXT, Session, close_code_name, opcode_name,
};
use crate::widgets::{
    Accept, C, TextArea, TextInput, act, alpha, button, button_primary, button2, cell, chip,
    empty_state, input, kv_row, label, mono, section_title, status_bar, table_header, tile,
    toolbar,
};

#[derive(Clone, Copy, PartialEq)]
enum SendMode {
    Text,
    Hex,
}

enum Item {
    Frame(LogFrame),
    Note(f64, String, u32),
}

pub struct WsView {
    focus: FocusHandle,
    url: Entity<TextInput>,
    protocols: Entity<TextInput>,
    origin: Entity<TextInput>,
    headers: Entity<TextArea>,
    message: Entity<TextInput>,
    insecure: bool,
    mode: SendMode,
    auto_ping: bool,

    session: Option<Session>,
    rx: Option<Receiver<Event>>,
    started: Option<Instant>,
    handshake: Option<HandshakeInfo>,
    open: bool,
    items: Vec<Item>,
    selected: Option<usize>,
    follow: bool,
    scroll: UniformListScrollHandle,
    frames_in: u64,
    frames_out: u64,
    bytes_in: u64,
    bytes_out: u64,
    messages_in: u64,
    rtts: Vec<f64>,
    last_ping: Option<Instant>,
    close_info: Option<String>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl WsView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self {
            focus: cx.focus_handle(),
            url: input(
                window,
                cx,
                "wss://echo.websocket.org",
                "ws://host:port/path or wss://…",
                Accept::Any,
                |t| t.width(380.).max_len(2048),
                |t: &mut Self, _, cx| t.connect(cx),
            ),
            protocols: input(
                window,
                cx,
                "",
                "e.g. mqtt, graphql-ws, v12.stomp",
                Accept::Any,
                |t| t,
                |_: &mut Self, _, _| {},
            ),
            origin: input(
                window,
                cx,
                "",
                "Origin (optional)",
                Accept::Any,
                |t| t,
                |_: &mut Self, _, _| {},
            ),
            headers: cx.new(|cx| {
                TextArea::new(
                    cx,
                    "Extra headers, one per line:\nAuthorization: Bearer …",
                    86.,
                )
            }),
            message: input(
                window,
                cx,
                "",
                "message — Enter to send",
                Accept::Any,
                |t| t.max_len(1 << 20),
                |t: &mut Self, _, cx| t.send_message(cx),
            ),
            insecure: false,
            mode: SendMode::Text,
            auto_ping: false,
            session: None,
            rx: None,
            started: None,
            handshake: None,
            open: false,
            items: Vec::new(),
            selected: None,
            follow: true,
            scroll: UniformListScrollHandle::new(),
            frames_in: 0,
            frames_out: 0,
            bytes_in: 0,
            bytes_out: 0,
            messages_in: 0,
            rtts: Vec::new(),
            last_ping: None,
            close_info: None,
            status: "Public echo server: wss://echo.websocket.org".into(),
            error: None,
            _poll: None,
        }
    }

    fn at(&self) -> f64 {
        self.started
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0)
    }

    fn note(&mut self, text: String, color: u32) {
        let at = self.at();
        self.items.push(Item::Note(at, text, color));
    }

    fn connect(&mut self, cx: &mut Context<Self>) {
        if self.session.is_some() {
            return;
        }
        let url = self.url.read(cx).value.trim().to_string();
        if let Err(e) = websocket::parse_url(&url) {
            self.error = Some(e);
            return;
        }
        let protocols: Vec<String> = self
            .protocols
            .read(cx)
            .value
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let origin = self.origin.read(cx).value.trim().to_string();
        let cfg = Config {
            url: url.clone(),
            headers: websocket::parse_header_lines(&self.headers.read(cx).value),
            protocols,
            origin: (!origin.is_empty()).then_some(origin),
            insecure: self.insecure,
            timeout: Duration::from_secs(10),
        };
        self.error = None;
        self.handshake = None;
        self.close_info = None;
        self.items.clear();
        self.selected = None;
        self.frames_in = 0;
        self.frames_out = 0;
        self.bytes_in = 0;
        self.bytes_out = 0;
        self.messages_in = 0;
        self.rtts.clear();
        self.started = Some(Instant::now());
        self.note(format!("Connecting to {url}…"), C::MUTED);
        let (s, rx) = websocket::connect(cfg);
        self.session = Some(s);
        self.rx = Some(rx);
        self.status = format!("Connecting to {url}…").into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(60))
                    .await;
                let alive = this.update(cx, |t, cx| {
                    t.drain();
                    cx.notify();
                    t.rx.is_some()
                });
                if !matches!(alive, Ok(true)) {
                    break;
                }
            }
        }));
    }

    fn drain(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut events = Vec::new();
        let mut ended = false;
        loop {
            match rx.try_recv() {
                Ok(e) => events.push(e),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    ended = true;
                    break;
                }
            }
        }
        let grew = !events.is_empty();
        for e in events {
            match e {
                Event::Handshake(h) => {
                    self.open = true;
                    self.note(
                        format!(
                            "Upgraded: HTTP {} in {:.1} ms{}",
                            h.status,
                            h.handshake_ms,
                            h.subprotocol
                                .as_ref()
                                .map(|p| format!(", subprotocol {p}"))
                                .unwrap_or_default()
                        ),
                        C::GREEN,
                    );
                    if let Some(e) = &h.conn.cert_error {
                        self.note(format!("Certificate not trusted: {e}"), C::AMBER);
                    }
                    if h.extensions.is_some() {
                        self.note(
                            "Server negotiated an extension: compressed frames are shown but not decoded"
                                .into(),
                            C::AMBER,
                        );
                    }
                    self.status = format!(
                        "Open — {}",
                        h.conn.addr.map(|a| a.to_string()).unwrap_or_default()
                    )
                    .into();
                    self.handshake = Some(*h);
                }
                Event::Frame(f) => {
                    if f.outgoing {
                        self.frames_out += 1;
                        self.bytes_out += f.wire_len as u64;
                    } else {
                        self.frames_in += 1;
                        self.bytes_in += f.wire_len as u64;
                    }
                    if f.frame.opcode == OP_CLOSE {
                        let (code, reason) = websocket::parse_close(&f.frame.payload);
                        self.note(
                            format!(
                                "{} close {}{}",
                                if f.outgoing { "Sent" } else { "Received" },
                                code.map(|c| format!("{c} ({})", close_code_name(c)))
                                    .unwrap_or_else(|| "without a code".into()),
                                if reason.is_empty() {
                                    String::new()
                                } else {
                                    format!(": {reason}")
                                }
                            ),
                            C::AMBER,
                        );
                    }
                    self.items.push(Item::Frame(f));
                }
                Event::Message {
                    fragments,
                    payload,
                    text,
                } => {
                    self.messages_in += 1;
                    if fragments > 1 {
                        self.note(
                            format!(
                                "Reassembled a {}-byte {} message from {fragments} fragments",
                                payload.len(),
                                if text { "text" } else { "binary" }
                            ),
                            C::CYAN,
                        );
                    }
                }
                Event::Rtt(ms) => {
                    self.rtts.push(ms);
                    self.note(format!("Ping RTT {ms:.1} ms"), C::CYAN);
                }
                Event::Note(n) => self.note(n, C::AMBER),
                Event::Closed {
                    code,
                    reason,
                    by_server,
                } => {
                    let s = format!(
                        "Closed by {}: {}{}",
                        if by_server { "server" } else { "client" },
                        code.map(|c| format!("{c} — {}", close_code_name(c)))
                            .unwrap_or_else(|| "no status code".into()),
                        if reason.is_empty() {
                            String::new()
                        } else {
                            format!(" ({reason})")
                        }
                    );
                    self.note(s.clone(), if by_server { C::AMBER } else { C::MUTED });
                    self.close_info = Some(s.clone());
                    self.status = s.into();
                    ended = true;
                }
                Event::Error(e) => {
                    let first = e.lines().next().unwrap_or("").to_string();
                    self.note(first.clone(), C::RED);
                    self.status = first.into();
                    self.error = Some(e);
                    ended = true;
                }
            }
        }
        if self.items.len() > 20_000 {
            self.items.drain(..5_000);
            self.selected = None;
        }
        if grew && self.follow && !self.items.is_empty() {
            self.scroll
                .scroll_to_item(self.items.len() - 1, ScrollStrategy::Bottom);
        }
        if self.auto_ping
            && self.open
            && self
                .last_ping
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
            && let Some(s) = &self.session
        {
            s.send(Cmd::Ping(Vec::new()));
            self.last_ping = Some(Instant::now());
        }
        if ended {
            self.rx = None;
            self.session = None;
            self.open = false;
        }
    }

    fn send_message(&mut self, cx: &mut Context<Self>) {
        let Some(s) = &self.session else {
            self.error = Some("Not connected".into());
            return;
        };
        let text = self.message.read(cx).value.clone();
        match self.mode {
            SendMode::Text => s.send(Cmd::Text(text)),
            SendMode::Hex => match websocket::parse_hex(&text) {
                Ok(b) => s.send(Cmd::Binary(b)),
                Err(e) => {
                    self.error = Some(format!("Binary payload: {e}"));
                    return;
                }
            },
        }
        self.error = None;
    }

    fn render_row(&self, i: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let view = cx.entity().downgrade();
        let sel = self.selected == Some(i);
        let row = div()
            .id(("ws-row", i))
            .flex()
            .items_center()
            .h(px(26.))
            .px_3()
            .text_xs()
            .font_family(mono())
            .cursor_pointer()
            .bg(rgb(if sel { C::SELECT } else { C::BG }))
            .hover(|s| s.bg(rgb(C::PANEL2)))
            .on_click(act(&view, move |t: &mut Self, _, _| {
                t.selected = Some(i);
                t.follow = false;
            }));
        match &self.items[i] {
            Item::Note(at, text, color) => row
                .child(cell(80., format!("{at:.3}")).text_color(rgb(C::MUTED)))
                .child(cell(0., text.clone()).text_color(rgb(*color)))
                .into_any_element(),
            Item::Frame(f) => {
                let op = f.frame.opcode;
                let color = match op {
                    OP_TEXT => C::TEXT,
                    OP_BINARY => C::PURPLE,
                    OP_PING | OP_PONG => C::CYAN,
                    OP_CLOSE => C::AMBER,
                    _ => C::MUTED,
                };
                let flags = format!(
                    "{}{}{}",
                    if f.frame.fin { "" } else { "frag " },
                    if f.frame.masked { "masked " } else { "" },
                    if f.frame.rsv != 0 { "rsv " } else { "" }
                );
                row.child(cell(80., format!("{:.3}", f.at)).text_color(rgb(C::MUTED)))
                    .child(
                        cell(34., if f.outgoing { "→" } else { "←" })
                            .text_color(rgb(if f.outgoing { C::ACCENT } else { C::GREEN })),
                    )
                    .child(cell(72., opcode_name(op)).text_color(rgb(color)))
                    .child(cell(70., f.frame.payload.len().to_string()))
                    .child(cell(100., flags).text_color(rgb(C::MUTED)))
                    .child(cell(
                        0.,
                        websocket::preview(&f.frame.payload, op == OP_TEXT, 160),
                    ))
                    .into_any_element()
            }
        }
    }

    fn inspector(&self) -> gpui::AnyElement {
        let Some(Item::Frame(f)) = self.selected.and_then(|i| self.items.get(i)) else {
            return div().into_any_element();
        };
        let (text, kind) = if f.frame.opcode == OP_CLOSE {
            let (code, reason) = websocket::parse_close(&f.frame.payload);
            (
                format!(
                    "code {}\nreason {reason}",
                    code.map(|c| format!("{c} ({})", close_code_name(c)))
                        .unwrap_or_else(|| "-".into())
                ),
                "close",
            )
        } else {
            payload_text(&f.frame.payload, 64 * 1024)
        };
        let copy = text.clone();
        div()
            .id("ws-inspector")
            .h(px(220.))
            .flex_none()
            .p_3()
            .overflow_y_scroll()
            .border_t_1()
            .border_color(rgb(C::BORDER))
            .bg(rgb(C::PANEL))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pb_2()
                    .child(section_title(&format!(
                        "{} {} frame · {} bytes payload · {} on the wire · {kind}",
                        if f.outgoing { "Sent" } else { "Received" },
                        opcode_name(f.frame.opcode),
                        f.frame.payload.len(),
                        f.wire_len
                    )))
                    .child(div().flex_1())
                    .child(chip("ws-copy", "Copy", false, move |_, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()))
                    })),
            )
            .child(mono_block(&text))
            .into_any_element()
    }

    fn side_panel(&self) -> gpui::AnyElement {
        let h = self.handshake.as_ref();
        let avg = if self.rtts.is_empty() {
            None
        } else {
            Some(self.rtts.iter().sum::<f64>() / self.rtts.len() as f64)
        };
        div()
            .id("ws-side")
            .w(px(400.))
            .flex_none()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .overflow_y_scroll()
            .border_r_1()
            .border_color(rgb(C::BORDER))
            .text_sm()
            .child(section_title("Options"))
            .child(label("Subprotocols (comma separated)"))
            .child(div().flex().child(self.protocols.clone()))
            .child(label("Origin"))
            .child(div().flex().child(self.origin.clone()))
            .child(label("Headers"))
            .child(self.headers.clone())
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(tile(
                        "Frames in / out",
                        format!("{} / {}", self.frames_in, self.frames_out),
                        C::TEXT,
                    ))
                    .child(tile("Messages in", self.messages_in.to_string(), C::TEXT))
                    .child(tile(
                        "Bytes in / out",
                        format!("{} / {}", self.bytes_in, self.bytes_out),
                        C::MUTED,
                    ))
                    .child(tile(
                        "Ping RTT",
                        match (self.rtts.last(), avg) {
                            (Some(l), Some(a)) => format!("{l:.1} ms (avg {a:.1})"),
                            _ => "-".into(),
                        },
                        C::CYAN,
                    )),
            )
            .when_some(h, |d, h| {
                d.child(section_title("Handshake"))
                    .child(kv_row(
                        "Status",
                        format!(
                            "{} {}",
                            h.status,
                            if h.accept_ok {
                                "· Sec-WebSocket-Accept ✓"
                            } else {
                                ""
                            }
                        ),
                        110.,
                    ))
                    .child(kv_row(
                        "Timing",
                        format!(
                            "TCP{} {:.1} ms · upgrade {:.1} ms",
                            if h.conn.tls.is_some() { "+TLS" } else { "" },
                            h.conn.connect_ms,
                            h.handshake_ms
                        ),
                        110.,
                    ))
                    .child(kv_row(
                        "Address",
                        h.conn.addr.map(|a| a.to_string()).unwrap_or_default(),
                        110.,
                    ))
                    .child(kv_row(
                        "Subprotocol",
                        h.subprotocol.clone().unwrap_or_else(|| "none".into()),
                        110.,
                    ))
                    .child(kv_row(
                        "Extensions",
                        h.extensions.clone().unwrap_or_else(|| "none".into()),
                        110.,
                    ))
                    .when_some(h.server.clone(), |d, s| d.child(kv_row("Server", s, 110.)))
                    .when_some(h.conn.tls.clone(), |d, t| d.child(kv_row("TLS", t, 110.)))
                    .when_some(h.conn.cert.clone(), |d, c| {
                        d.child(kv_row("Certificate", c, 110.))
                    })
                    .when_some(h.conn.cert_error.clone(), |d, e| {
                        d.child(
                            div()
                                .text_color(rgb(C::AMBER))
                                .child(format!("⚠ certificate: {e}")),
                        )
                    })
                    .child(label("Request"))
                    .child(mono_block(h.request.trim_end()))
                    .child(label("Response"))
                    .child(mono_block(&h.response))
            })
            .when_some(self.error.clone().filter(|e| e.contains('\n')), |d, e| {
                d.child(section_title("Server response"))
                    .child(mono_block(&e))
            })
            .into_any_element()
    }
}

impl Focusable for WsView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for WsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.session.is_some();
        let log = if self.items.is_empty() {
            empty_state(
                "No connection",
                "Enter a ws:// or wss:// URL and press Connect.",
            )
            .into_any_element()
        } else {
            uniform_list(
                "ws-log",
                self.items.len(),
                cx.processor(|this, range: Range<usize>, _, cx| {
                    range.map(|i| this.render_row(i, cx)).collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("URL"))
                    .child(self.url.clone())
                    .child(chip(
                        "ws-insecure",
                        "Accept invalid cert",
                        self.insecure,
                        act(&view, |t: &mut Self, _, _| t.insecure = !t.insecure),
                    ))
                    .child(if running {
                        button(
                            "ws-go",
                            if self.open { "■ Close" } else { "Cancel" },
                            C::RED,
                            C::RED_HOVER,
                            act(&view, |t: &mut Self, _, _| {
                                if let Some(s) = &t.session {
                                    if t.open {
                                        s.send(Cmd::Close(1000, "bye".into()));
                                    } else {
                                        s.send(Cmd::Abort);
                                    }
                                }
                            }),
                        )
                    } else {
                        button_primary(
                            "ws-go",
                            "▶ Connect",
                            act(&view, |t: &mut Self, _, cx| t.connect(cx)),
                        )
                    }),
            )
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .child(e.lines().next().unwrap_or("").to_string())
            }))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(self.side_panel())
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(table_header(&[
                                ("TIME", 80.),
                                ("", 34.),
                                ("TYPE", 72.),
                                ("LENGTH", 70.),
                                ("FLAGS", 100.),
                                ("PAYLOAD", 0.),
                            ]))
                            .child(log)
                            .child(self.inspector())
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap_2()
                                    .px_3()
                                    .py_2()
                                    .border_t_1()
                                    .border_color(rgb(C::BORDER))
                                    .bg(rgb(C::PANEL))
                                    .child(chip(
                                        "ws-mode-text",
                                        "Text",
                                        self.mode == SendMode::Text,
                                        act(&view, |t: &mut Self, _, _| t.mode = SendMode::Text),
                                    ))
                                    .child(chip(
                                        "ws-mode-hex",
                                        "Binary (hex)",
                                        self.mode == SendMode::Hex,
                                        act(&view, |t: &mut Self, _, _| t.mode = SendMode::Hex),
                                    ))
                                    .child(self.message.clone())
                                    .child(button2(
                                        "ws-send",
                                        "Send",
                                        act(&view, |t: &mut Self, _, cx| t.send_message(cx)),
                                    ))
                                    .child(button2(
                                        "ws-ping",
                                        "Ping",
                                        act(&view, |t: &mut Self, _, _| {
                                            if let Some(s) = &t.session {
                                                s.send(Cmd::Ping(Vec::new()));
                                            }
                                        }),
                                    ))
                                    .child(chip(
                                        "ws-autoping",
                                        "Ping every 1 s",
                                        self.auto_ping,
                                        act(&view, |t: &mut Self, _, _| t.auto_ping = !t.auto_ping),
                                    ))
                                    .child(chip(
                                        "ws-follow",
                                        "Follow",
                                        self.follow,
                                        act(&view, |t: &mut Self, _, _| t.follow = !t.follow),
                                    )),
                            ),
                    ),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .when_some(self.close_info.clone(), |d, _| d)
                    .when_some(self.handshake.as_ref().filter(|_| self.open), |d, h| {
                        d.child(
                            h.subprotocol
                                .as_ref()
                                .map(|p| format!("subprotocol {p}"))
                                .unwrap_or_default(),
                        )
                    }),
            )
    }
}
