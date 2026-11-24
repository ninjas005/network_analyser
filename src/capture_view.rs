//! Packet list tools on the shared capture session: Live Packet Capture,
//! PCAP / PCAPNG Viewer and Protocol Decoder. Also the source bar shown by
//! every packet-analysis tool.

use std::ops::Range;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, ScrollStrategy, SharedString,
    UniformListScrollHandle, Window, deferred, div, prelude::*, px, rgb, uniform_list,
};

use crate::dissect::{self, Dissected};
use crate::session::{self, OpenTool, Session};
use crate::tools::Tool;
use crate::widgets::{
    Accept, C, Changed, TextArea, TextInput, act, alpha, button, button_primary, button2, cell,
    chip, copy_button, dot, empty_state, input, kv_row, label, mono, section_title, status_bar,
    table_header, tip, toolbar,
};

/// Narrower columns next to the protocol tree.
const DECODE_COLS: [(&str, f32); 7] = [
    ("NO.", 60.),
    ("TIME", 90.),
    ("SOURCE", 140.),
    ("DESTINATION", 140.),
    ("PROTOCOL", 100.),
    ("LENGTH", 64.),
    ("INFO", 0.),
];

const COLS: [(&str, f32); 7] = [
    ("NO.", 70.),
    ("TIME", 96.),
    ("SOURCE", 210.),
    ("DESTINATION", 210.),
    ("PROTOCOL", 110.),
    ("LENGTH", 70.),
    ("INFO", 0.),
];

// ---------------------------------------------------------------- source bar

/// Interface picker, Start / Stop, Open file and what is loaded.
pub struct SourceBar {
    session: Entity<Session>,
    picker: bool,
}

impl SourceBar {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let session = Session::shared(cx);
        cx.observe(&session, |_, _, cx| cx.notify()).detach();
        SourceBar {
            session,
            picker: false,
        }
    }

    fn render_picker(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let view = cx.entity().downgrade();
        let s = self.session.read(cx);
        let list = s.ifaces.as_ref().cloned().unwrap_or_default();
        let current = s.iface;
        div()
            .id("iface-list")
            .absolute()
            .top(px(36.))
            .left(px(0.))
            .w(px(520.))
            .max_h(px(420.))
            .overflow_y_scroll()
            .occlude()
            .p_1()
            .rounded_md()
            .bg(rgb(C::PANEL2))
            .border_1()
            .border_color(rgb(C::BORDER))
            .shadow_lg()
            .children(list.into_iter().enumerate().map(|(i, f)| {
                let name = if cfg!(windows) && !f.desc.is_empty() {
                    f.desc.clone()
                } else {
                    f.name.clone()
                };
                let mut sub = f.addrs.clone();
                if !cfg!(windows) && !f.desc.is_empty() {
                    sub.push(f.desc.clone());
                }
                div()
                    .id(("iface", i))
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .cursor_pointer()
                    .bg(rgb(if current == Some(i) {
                        C::SELECT
                    } else {
                        C::PANEL2
                    }))
                    .hover(|s| s.bg(rgb(C::BORDER)))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .items_center()
                            .child(dot(if f.up { C::GREEN } else { 0x3a4252 }))
                            .child(div().text_sm().child(name))
                            .when(f.loopback, |d| d.child(label("loopback"))),
                    )
                    .child(label(sub.join(" · ")).pl(px(16.)))
                    .on_click(act(&view, move |t: &mut Self, _, cx| {
                        t.picker = false;
                        t.session.update(cx, |s, cx| {
                            s.iface = Some(i);
                            cx.notify();
                        });
                    }))
            }))
    }
}

impl Render for SourceBar {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let weak = self.session.downgrade();
        let s = self.session.read(cx);
        let running = s.running();
        let live = s.live();
        let source = match (s.source.is_empty(), live, s.is_file) {
            (true, ..) => "Nothing loaded".to_string(),
            (_, true, _) => format!("Live: {}", s.source),
            (_, _, true) => {
                // The full path is in the status bar.
                let name = std::path::Path::new(&s.source)
                    .file_name()
                    .map_or(s.source.clone(), |n| n.to_string_lossy().into_owned());
                format!("File: {}", clip(&name, 60))
            }
            _ if s.a.stats.packets == 0 => "Nothing captured".to_string(),
            _ => format!("Captured on {}", s.source),
        };
        let packets = s.a.stats.packets;
        let iface = s.iface_label();
        let iface_button = button2(
            "iface-pick",
            format!("{iface}  ▾"),
            act(&view, |t: &mut Self, _, _| t.picker = !t.picker),
        )
        .max_w(px(300.))
        .overflow_hidden();
        div()
            .flex()
            .items_center()
            .gap_3()
            .child(
                div()
                    .relative()
                    .child(iface_button)
                    .when(self.picker && !running, |d| {
                        d.child(deferred(self.render_picker(cx)).with_priority(1))
                    }),
            )
            .child(if live {
                button(
                    "cap-start",
                    "■ Stop",
                    C::AMBER,
                    C::AMBER,
                    act(&weak, |s: &mut Session, _, _| s.stop()),
                )
            } else {
                button_primary(
                    "cap-start",
                    "▶ Start capture",
                    act(&weak, |s: &mut Session, _, cx| s.start_live(cx)),
                )
            })
            .child(button2(
                "cap-browse",
                "Open file…",
                act(&weak, |s: &mut Session, _, cx| s.browse(cx)),
            ))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_xs()
                    .text_color(rgb(C::MUTED))
                    .child(dot(if running {
                        C::GREEN
                    } else if packets > 0 {
                        C::ACCENT
                    } else {
                        0x3a4252
                    }))
                    .child(
                        div()
                            .max_w(px(420.))
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .child(source),
                    )
                    .when(packets > 0, |d| d.child(format!("{packets} packets"))),
            )
    }
}

/// Error line of the session, shown under the toolbar.
pub fn error_line(e: &Option<String>) -> Option<gpui::Div> {
    e.as_ref().map(|e| {
        div()
            .px_5()
            .py_2()
            .text_sm()
            .text_color(rgb(C::RED))
            .bg(alpha(C::RED, 0.08))
            .children(e.lines().map(|l| div().child(l.to_string())))
    })
}

/// Status bar common to the packet tools.
pub fn session_status(s: &Session) -> gpui::Div {
    let elapsed = s.started.map(|t| t.elapsed());
    status_bar()
        .child(div().text_color(rgb(C::TEXT)).child(s.status.clone()))
        .child(format!("{} packets", s.a.stats.packets))
        .child(human_bytes(s.a.stats.bytes))
        .when_some(s.pcap_stats, |d, (rx, drop, ifd)| {
            d.child(format!(
                "kernel: {rx} received, {drop} dropped, {ifd} by interface"
            ))
        })
        .when(s.a.not_kept > 0, |d| {
            d.child(div().text_color(rgb(C::AMBER)).child(format!(
                "list full: {} packets counted but not kept",
                s.a.not_kept
            )))
        })
        .children(elapsed.map(|e| format!("{:.1}s", e.as_secs_f32())))
}

// ---------------------------------------------------------------- packet list

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Live,
    File,
    Decode,
}

#[derive(Clone, Copy, PartialEq)]
enum Pane {
    Packets,
    FileInfo,
    Hex,
}

pub struct CaptureView {
    kind: Kind,
    focus: FocusHandle,
    session: Entity<Session>,
    bar: Entity<SourceBar>,
    bpf: Entity<TextInput>,
    display: Entity<TextInput>,
    file: Entity<TextInput>,
    limit: Entity<TextInput>,
    hex: Entity<TextArea>,
    hex_link: i32,
    pane: Pane,
    /// Only packets containing this protocol (Protocol Decoder).
    proto: Option<&'static str>,
    visible: Vec<usize>,
    seen: usize,
    generation: u64,
    selected: Option<usize>,
    /// Decoded selected packet: (generation, index).
    detail: Option<((u64, usize), Dissected)>,
    follow: bool,
    scroll: UniformListScrollHandle,
}

impl CaptureView {
    pub fn new(kind: Kind, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let session = Session::shared(cx);
        cx.observe(&session, |t, _, cx| {
            t.sync(cx);
            cx.notify();
        })
        .detach();
        let bpf = input(
            window,
            cx,
            "",
            "Capture filter (BPF): tcp port 502, not arp",
            Accept::Any,
            |t| t.width(330.),
            |t: &mut Self, _, cx| {
                if t.kind == Kind::Live {
                    t.session.update(cx, |s, cx| s.start_live(cx));
                } else {
                    t.open_typed(cx);
                }
            },
        );
        cx.observe(&bpf, |t, b, cx| {
            let v = b.read(cx).value.clone();
            let live = t.kind == Kind::Live;
            t.session.update(cx, |s, _| {
                if live {
                    s.bpf = v;
                } else {
                    s.file_bpf = v;
                }
            });
        })
        .detach();
        let display = input(
            window,
            cx,
            "",
            "Display filter: dns, 10.0.0.5, modbus, !arp",
            Accept::Any,
            |t| t.width(330.),
            |_: &mut Self, _, _| {},
        );
        cx.observe(&display, |t, _, cx| {
            t.refilter(cx);
            cx.notify();
        })
        .detach();
        let file = input(
            window,
            cx,
            "",
            "path/to/file.pcap, .pcapng or .gz",
            Accept::Any,
            |t| t.width(330.).max_len(4096),
            |t: &mut Self, _, cx| t.open_typed(cx),
        );
        let limit = input(
            window,
            cx,
            "",
            "Stop after: 1000, 60s, 50MB",
            Accept::Any,
            |t| t.width(190.),
            |t: &mut Self, _, cx| {
                t.session.update(cx, |s, cx| s.start_live(cx));
            },
        );
        cx.observe(&limit, |t, l, cx| {
            let parsed = session::parse_limit(&l.read(cx).value);
            t.session.update(cx, |s, _| {
                let snaplen = s.limits.snaplen;
                s.limits = parsed.clone().unwrap_or_default();
                s.limits.snaplen = snaplen;
            });
            let bad = parsed.is_err();
            if l.read(cx).error != bad {
                l.update(cx, |l, cx| {
                    l.error = bad;
                    cx.notify();
                });
            }
        })
        .detach();
        let hex = cx.new(|cx| {
            TextArea::new(
                cx,
                "Paste a frame as hex or a hex dump (Wireshark, tcpdump -x, xxd, hexdump -C)",
                180.,
            )
        });
        cx.subscribe(&hex, |_, _, _: &Changed, cx| cx.notify())
            .detach();
        let bar = cx.new(SourceBar::new);
        let mut v = Self {
            kind,
            focus: cx.focus_handle(),
            session,
            bar,
            bpf,
            display,
            file,
            limit,
            hex,
            hex_link: 1,
            pane: Pane::Packets,
            proto: None,
            visible: Vec::new(),
            seen: 0,
            generation: 0,
            selected: None,
            detail: None,
            follow: kind == Kind::Live,
            scroll: UniformListScrollHandle::new(),
        };
        v.sync(cx);
        v
    }

    fn cols(&self) -> &'static [(&'static str, f32); 7] {
        if self.kind == Kind::Decode {
            &DECODE_COLS
        } else {
            &COLS
        }
    }

    fn open_typed(&mut self, cx: &mut Context<Self>) {
        match session::user_path(&self.file.read(cx).value) {
            Some(p) => self.session.update(cx, |s, cx| s.open(p, cx)),
            None => self.file.update(cx, |t, cx| {
                t.error = true;
                cx.notify();
            }),
        }
    }

    /// Take over packets added since the last call.
    fn sync(&mut self, cx: &mut Context<Self>) {
        let s = self.session.read(cx);
        if s.generation != self.generation {
            self.generation = s.generation;
            self.visible.clear();
            self.seen = 0;
            self.selected = None;
            self.detail = None;
            self.proto = None;
        }
        let terms = session::filter_terms(&self.display.read(cx).value);
        let packets = &s.a.packets;
        let before = self.visible.len();
        for (i, p) in packets.iter().enumerate().skip(self.seen) {
            if session::matches(p, &terms) && self.proto.is_none_or(|n| p.d.path.contains(&n)) {
                self.visible.push(i);
            }
        }
        self.seen = packets.len();
        if self.follow && s.live() && self.visible.len() > before {
            self.scroll
                .scroll_to_item(self.visible.len() - 1, ScrollStrategy::Bottom);
        }
        // "Show packet" from another tool.
        if let Some(i) = s.goto
            && i < packets.len()
            && self.kind == Kind::Live
        {
            self.session.update(cx, |s, _| s.goto = None);
            self.pane = Pane::Packets;
            if !self.visible.contains(&i) {
                self.display.update(cx, |d, cx| d.set("", cx));
                self.proto = None;
                self.refilter(cx);
            }
            self.selected = Some(i);
            self.follow = false;
            if let Some(at) = self.visible.iter().position(|v| *v == i) {
                self.scroll.scroll_to_item(at, ScrollStrategy::Center);
            }
        }
    }

    fn refilter(&mut self, cx: &mut Context<Self>) {
        self.visible.clear();
        self.seen = 0;
        let follow = std::mem::replace(&mut self.follow, false);
        self.sync(cx);
        self.follow = follow;
        if let Some(sel) = self.selected
            && !self.visible.contains(&sel)
        {
            self.selected = None;
        }
    }

    fn set_proto(&mut self, name: &'static str, cx: &mut Context<Self>) {
        self.proto = if self.proto == Some(name) {
            None
        } else {
            Some(name)
        };
        self.refilter(cx);
    }

    // ------------------------------------------------------------ rendering

    fn render_toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let view = cx.entity().downgrade();
        let weak = self.session.downgrade();
        let s = self.session.read(cx);
        let mut first = toolbar().child(self.bar.clone());
        match self.kind {
            Kind::Live => {
                let headers = s.limits.snaplen.is_some();
                first = first
                    .child(self.bpf.clone())
                    .child(self.limit.clone())
                    .child(
                        chip(
                            "promisc",
                            "Promiscuous",
                            s.promisc,
                            act(&weak, |s: &mut Session, _, _| s.promisc = !s.promisc),
                        )
                        .tooltip(tip(
                            "Capture all frames seen by the interface, not only those addressed to this machine.",
                        )),
                    )
                    .child(
                        chip(
                            "snap",
                            "Headers only",
                            headers,
                            act(&weak, |s: &mut Session, _, _| {
                                s.limits.snaplen = match s.limits.snaplen {
                                    None => Some(128),
                                    Some(_) => None,
                                }
                            }),
                        )
                        .tooltip(tip(
                            "Keep only the first 128 bytes of each packet. Payloads cannot be reconstructed.",
                        )),
                    )
                    .child(
                        chip(
                            "save",
                            "Save to .pcap",
                            s.save,
                            act(&weak, |s: &mut Session, _, _| s.save = !s.save),
                        )
                        .tooltip(tip(
                            "Also write every captured packet to ~/capture-<time>.pcap",
                        )),
                    );
            }
            Kind::File => {
                first = first
                    .child(self.file.clone())
                    .child(button2(
                        "cap-open",
                        "Open",
                        act(&view, |t: &mut Self, _, cx| t.open_typed(cx)),
                    ))
                    .child(self.bpf.clone());
            }
            Kind::Decode => {}
        }
        let panes: &[(Pane, &str)] = match self.kind {
            Kind::Live => &[],
            Kind::File => &[(Pane::Packets, "Packets"), (Pane::FileInfo, "File details")],
            Kind::Decode => &[(Pane::Packets, "Packets"), (Pane::Hex, "Paste hex")],
        };
        let panes: Vec<_> = panes
            .iter()
            .map(|(p, name)| {
                let p = *p;
                chip(
                    *name,
                    *name,
                    self.pane == p,
                    act(&view, move |t: &mut Self, _, _| t.pane = p),
                )
            })
            .collect();
        let shown = self.visible.clone();
        div().flex().flex_col().child(first).child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_3()
                .px_5()
                .py_2()
                .bg(rgb(C::PANEL))
                .border_b_1()
                .border_color(rgb(C::BORDER))
                .children(panes)
                .when(self.pane == Pane::Packets, |d| {
                    d.child(self.display.clone())
                        .when(self.kind == Kind::Live, |d| {
                            d.child(chip(
                                "follow",
                                "Auto-scroll",
                                self.follow,
                                act(&view, |t: &mut Self, _, _| t.follow = !t.follow),
                            ))
                        })
                        .children(self.proto.map(|p| {
                            chip(
                                "proto-clear",
                                format!("{p}  ✕"),
                                true,
                                act(&view, move |t: &mut Self, _, cx| t.set_proto(p, cx)),
                            )
                        }))
                        .child(label(format!("{} shown", self.visible.len())))
                })
                .child(div().flex_1())
                .child(button2(
                    "cap-save",
                    "Save shown…",
                    act(&weak, move |s: &mut Session, _, _| s.save_packets(&shown)),
                ))
                .child(button2(
                    "cap-clear",
                    "Clear",
                    act(&weak, |s: &mut Session, _, _| s.clear()),
                )),
        )
    }

    fn render_row(&self, vi: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let s = self.session.read(cx);
        let Some((idx, p)) = self
            .visible
            .get(vi)
            .and_then(|&i| Some((i, s.a.packets.get(i)?)))
        else {
            return div().into_any_element();
        };
        let t0 = s.a.stats.first.unwrap_or(p.ts);
        let selected = self.selected == Some(idx);
        let cols = self.cols();
        let color = proto_color(&p.d.proto);
        let info = match &p.comment {
            Some(c) => format!("{}  ✎ {c}", p.d.info),
            None => p.d.info.clone(),
        };
        div()
            .id(("pkt", idx))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .h(px(26.))
            .px_3()
            .text_xs()
            .font_family(mono())
            .bg(if selected {
                rgb(C::SELECT).into()
            } else {
                alpha(color, 0.07)
            })
            .hover(|s| s.bg(rgb(C::PANEL2)))
            .cursor_pointer()
            .child(cell(cols[0].1, p.no.to_string()).text_color(rgb(C::MUTED)))
            .child(cell(cols[1].1, format!("{:.6}", p.ts - t0)).text_color(rgb(C::MUTED)))
            .child(cell(cols[2].1, p.d.src.clone()))
            .child(cell(cols[3].1, p.d.dst.clone()))
            .child(cell(cols[4].1, p.d.proto.clone()).text_color(rgb(color)))
            .child(cell(cols[5].1, p.len.to_string()))
            .child(cell(0., clip(&info, 400)))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected = if this.selected == Some(idx) {
                    None
                } else {
                    Some(idx)
                };
                this.follow = false;
                cx.notify();
            }))
            .into_any_element()
    }

    fn render_packets(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let s = self.session.read(cx);
        let body = if self.visible.is_empty() {
            let (title, hint) = if s.running() {
                (
                    "Waiting for packets…",
                    "Generate some traffic, or check the capture filter.",
                )
            } else if !s.a.packets.is_empty() {
                (
                    "No packets match the display filter",
                    "Terms match protocol, addresses, ports and info; prefix with ! to exclude.",
                )
            } else if self.kind == Kind::File {
                (
                    "No file open",
                    "Open a .pcap or .pcapng file (gzip is fine). No capture rights are needed.",
                )
            } else {
                (
                    "No packets",
                    "Choose an interface and start a capture, or open a capture file.",
                )
            };
            empty_state(title, hint).into_any_element()
        } else {
            uniform_list(
                "packets",
                self.visible.len(),
                cx.processor(|this, range: Range<usize>, _, cx| {
                    range.map(|vi| this.render_row(vi, cx)).collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };
        let recent = (self.kind == Kind::File && self.visible.is_empty())
            .then(|| self.render_recent().into_any_element());
        let detail = self
            .selected
            .and_then(|i| self.render_detail(i, cx).map(|d| d.into_any_element()));
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .child(table_header(self.cols()))
            .child(body)
            .children(recent)
            .children(detail)
    }

    fn render_recent(&self) -> impl IntoElement + use<> {
        let weak = self.session.downgrade();
        let list = crate::settings::get().recent_captures;
        div()
            .p_5()
            .flex()
            .flex_col()
            .gap_1()
            .when(!list.is_empty(), |d| d.child(section_title("Recent files")))
            .children(list.into_iter().enumerate().map(|(i, p)| {
                div()
                    .id(("recent", i))
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .text_sm()
                    .cursor_pointer()
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .child(p.clone())
                    .on_click(act(&weak, move |s: &mut Session, _, cx| {
                        s.open(p.clone().into(), cx)
                    }))
            }))
    }

    fn render_detail(
        &mut self,
        idx: usize,
        cx: &mut Context<Self>,
    ) -> Option<impl IntoElement + use<>> {
        let s = self.session.read(cx);
        let p = s.a.packets.get(idx)?;
        let key = (self.generation, idx);
        if self.detail.as_ref().is_none_or(|(k, _)| *k != key) {
            self.detail = Some((key, dissect::dissect(p.linktype, &p.data)));
        }
        let (_, d) = self.detail.as_ref()?;
        let mut frame = dissect::Layer::new(format!("Frame {}", p.no));
        frame
            .f(
                "Length",
                format!("{} bytes ({} captured)", p.len, p.data.len()),
            )
            .f("Arrival", session::format_ts(p.ts))
            .f("Link type", dissect::linktype_name(p.linktype))
            .f("Protocols", d.path.join(" › "));
        if let Some(h) = d.how {
            frame.f("Identified by", format!("{}: {}", d.proto, h.text()));
        }
        if let Some(f) = s.info.as_ref().and_then(|i| i.ifaces.get(p.iface as usize))
            && !f.name.is_empty()
        {
            frame.f("Interface", &f.name);
        }
        if let Some(c) = &p.comment {
            frame.f("Comment", c);
        }
        let stream = s.a.stream_of.get(idx).copied().flatten();
        let layers: Vec<_> = std::iter::once(frame)
            .chain(d.layers.iter().cloned())
            .collect();
        let dump = dissect::hexdump(&p.data);
        let copy = dump.join("\n");
        let weak = self.session.downgrade();
        Some(
            div()
                .flex()
                .flex_row()
                .h(px(300.))
                .flex_none()
                .border_t_1()
                .border_color(rgb(C::BORDER))
                .bg(rgb(C::PANEL))
                .child(
                    div()
                        .id("layers")
                        .flex_1()
                        .min_w_0()
                        .p_4()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .overflow_y_scroll()
                        .text_sm()
                        .children(stream.map(|id| {
                            let go = |tool: Tool, name: &'static str| {
                                chip(
                                    name,
                                    name,
                                    false,
                                    act(&weak, move |s: &mut Session, _, cx| {
                                        s.stream = Some(id as usize);
                                        cx.emit(OpenTool(tool));
                                    }),
                                )
                            };
                            div()
                                .flex()
                                .gap_2()
                                .child(go(Tool::TcpStreams, "Follow TCP stream"))
                                .child(go(Tool::Handshake, "Handshake"))
                        }))
                        .children(layers.into_iter().map(layer_block)),
                )
                .child(
                    div()
                        .id("hexdump")
                        .w(px(600.))
                        .flex_none()
                        .p_4()
                        .border_l_1()
                        .border_color(rgb(C::BORDER))
                        .overflow_y_scroll()
                        .font_family(mono())
                        .text_xs()
                        .text_color(rgb(C::MUTED))
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .items_center()
                                .child(section_title("Bytes"))
                                .child(div().flex_1())
                                .child(copy_button("copy-hex", copy))
                                .child(chip(
                                    "close-detail",
                                    "✕",
                                    false,
                                    cx.listener(|this, _, _, cx| {
                                        this.selected = None;
                                        cx.notify();
                                    }),
                                )),
                        )
                        .children(
                            dump.into_iter()
                                .take(256)
                                .map(|l| div().whitespace_nowrap().child(l)),
                        ),
                ),
        )
    }

    fn render_file_info(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let s = self.session.read(cx);
        match &s.info {
            None => empty_state(
                if s.running() {
                    "Reading…"
                } else {
                    "No file open"
                },
                "Details appear when a capture file has been read.",
            )
            .into_any_element(),
            Some(i) => div()
                .id("file-info")
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .p_5()
                .flex()
                .flex_col()
                .gap_2()
                .text_sm()
                .child(section_title("Capture file"))
                .children(
                    session::file_info_rows(i)
                        .into_iter()
                        .map(|(k, v)| kv_row(k, v, 180.)),
                )
                .into_any_element(),
        }
    }

    /// Protocol tree of the capture; a click filters the list.
    fn render_protocols(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let view = cx.entity().downgrade();
        let st = &self.session.read(cx).a.stats;
        let total = st.packets.max(1);
        let rows = st.hierarchy();
        let (sig, port) = (st.by_signature, st.by_port);
        let active = self.proto;
        div()
            .id("protocols")
            .w(px(300.))
            .flex_none()
            .h_full()
            .p_3()
            .flex()
            .flex_col()
            .overflow_y_scroll()
            .border_r_1()
            .border_color(rgb(C::BORDER))
            .bg(rgb(C::PANEL))
            .text_sm()
            .child(section_title("Protocols found"))
            .child(label(format!("By content {sig} · by port only {port}")).pb_2())
            .children(rows.into_iter().enumerate().map(|(i, r)| {
                let name = r.name;
                div()
                    .id(("proto", i))
                    .flex()
                    .flex_none()
                    .items_center()
                    .h(px(24.))
                    .pl(px(4. + 14. * r.depth as f32))
                    .pr_2()
                    .rounded_md()
                    .cursor_pointer()
                    .when(active == Some(name), |d| d.bg(rgb(C::SELECT)))
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_color(rgb(proto_color(name)))
                            .child(name),
                    )
                    .child(label(format!(
                        "{} · {:.1}%",
                        r.packets,
                        r.packets as f64 * 100. / total as f64
                    )))
                    .on_click(act(&view, move |t: &mut Self, _, cx| t.set_proto(name, cx)))
            }))
    }

    fn render_hex(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let view = cx.entity().downgrade();
        let text = self.hex.read(cx).value.clone();
        let parsed = dissect::parse_hex(&text);
        let links = [(1, "Ethernet"), (101, "Raw IP"), (113, "Linux cooked")];
        let result = match &parsed {
            Err(e) => label(e.clone()).text_color(rgb(C::RED)).into_any_element(),
            Ok(b) if b.is_empty() => label("Nothing to decode yet").into_any_element(),
            Ok(b) => {
                let d = dissect::dissect(self.hex_link, b);
                let mut top = dissect::Layer::new(format!("{} bytes", b.len()));
                top.f("Protocols", d.path.join(" › "))
                    .f("Summary", format!("{}  {}", d.proto, d.info));
                if let Some(h) = d.how {
                    top.f("Identified by", h.text());
                }
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(layer_block(top))
                    .children(d.layers.into_iter().map(layer_block))
                    .into_any_element()
            }
        };
        div()
            .id("hex-pane")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .p_5()
            .flex()
            .flex_col()
            .gap_3()
            .text_sm()
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(label("First layer"))
                    .children(links.map(|(lt, name)| {
                        chip(
                            name,
                            name,
                            self.hex_link == lt,
                            act(&view, move |t: &mut Self, _, _| t.hex_link = lt),
                        )
                    })),
            )
            .child(self.hex.clone())
            .child(result)
    }
}

/// A decoded layer with its fields.
fn layer_block(l: dissect::Layer) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(section_title(&l.name))
        .children(
            l.fields
                .into_iter()
                .map(|(k, v)| kv_row(k, clip(&v, 2000), 170.)),
        )
}

/// Text cut to `n` characters, control characters removed (one-line cells).
pub fn clip(s: &str, n: usize) -> String {
    let mut out: String = s
        .chars()
        .take(n)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if s.chars().nth(n).is_some() {
        out.push('…');
    }
    out
}

pub fn proto_color(p: &str) -> u32 {
    match p {
        "TCP" => 0x8fb3ff,
        "UDP" => 0x7fd4e8,
        "HTTP" | "HTTP/2" | "WebSocket" => C::GREEN,
        "TLS" | "QUIC" | "DTLS" => 0x9aa8ff,
        "DNS" | "mDNS" | "LLMNR" => C::CYAN,
        "ARP" => C::AMBER,
        "ICMP" | "ICMPv6" | "IGMP" => 0xf28fb3,
        "DHCP" | "DHCPv6" | "NTP" | "SSDP" | "NBNS" | "SNMP" => 0xc4a7ff,
        "Modbus/TCP" | "Modbus/UDP" | "PROFINET" | "EtherCAT" | "BACnet" | "EtherNet/IP"
        | "S7comm" | "OPC UA" | "DNP3" | "IEC 104" | "MQTT" | "CoAP" => C::PURPLE,
        "SSH" | "Telnet" | "RDP" | "SMB" | "VNC" => 0xffb86b,
        _ => C::MUTED,
    }
}

pub fn human_bytes(b: u64) -> String {
    let b = b as f64;
    if b < 1024.0 {
        format!("{b:.0} B")
    } else if b < 1024.0 * 1024.0 {
        format!("{:.1} KB", b / 1024.0)
    } else if b < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB", b / 1048576.0)
    } else {
        format!("{:.2} GB", b / 1073741824.0)
    }
}

pub fn human_bits(b: f64) -> String {
    if b < 1e3 {
        format!("{b:.0} bit")
    } else if b < 1e6 {
        format!("{:.1} kbit", b / 1e3)
    } else if b < 1e9 {
        format!("{:.1} Mbit", b / 1e6)
    } else {
        format!("{:.2} Gbit", b / 1e9)
    }
}

/// Milliseconds with a sensible precision, or "—".
pub fn ms(t: Option<f64>) -> SharedString {
    match t {
        None => "—".into(),
        Some(t) if t < 0.01 => format!("{:.2} ms", t * 1000.0).into(),
        Some(t) if t < 1.0 => format!("{:.1} ms", t * 1000.0).into(),
        Some(t) => format!("{t:.2} s").into(),
    }
}

impl Focusable for CaptureView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for CaptureView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let body = match self.pane {
            Pane::Packets => {
                let side = (self.kind == Kind::Decode)
                    .then(|| self.render_protocols(cx).into_any_element());
                let list = self.render_packets(cx).into_any_element();
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .children(side)
                    .child(list)
                    .into_any_element()
            }
            Pane::FileInfo => self.render_file_info(cx).into_any_element(),
            Pane::Hex => self.render_hex(cx).into_any_element(),
        };
        let bar = self.render_toolbar(cx).into_any_element();
        let s = self.session.read(cx);
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(bar)
            .children(error_line(&s.error))
            .child(body)
            .child(session_status(s))
    }
}
