//! Packet Capture tab: live capture (libpcap/Npcap) or .pcap file, packet
//! list with display filter, layer details + hex dump, and traffic analysis
//! (protocol hierarchy, top talkers, conversations).

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Range;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, ScrollStrategy, SharedString, Task,
    UniformListScrollHandle, Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::capture::{self, CaptureConfig, CaptureEvent, CaptureHandle, Interface, Packet, Source};
use crate::dissect;
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, empty_state,
    input, kv_row, label, mono, section_title, status_bar, table_header, tip, toolbar,
};

/// Packets kept for display; statistics keep counting beyond this.
const MAX_PACKETS: usize = 200_000;

const COLS: [(&str, f32); 7] = [
    ("NO.", 70.),
    ("TIME", 96.),
    ("SOURCE", 210.),
    ("DESTINATION", 210.),
    ("PROTOCOL", 110.),
    ("LENGTH", 70.),
    ("INFO", 0.),
];

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Packets,
    Analysis,
}

#[derive(Default)]
struct Stats {
    packets: u64,
    bytes: u64,
    first: Option<f64>,
    last: f64,
    protos: HashMap<String, (u64, u64)>,
    talkers: HashMap<IpAddr, (u64, u64, u64, u64)>, // tx pkts, tx bytes, rx pkts, rx bytes
    convs: HashMap<(String, String, &'static str), Conv>,
}

#[derive(Default)]
struct Conv {
    packets: u64,
    bytes: u64,
    first: f64,
    last: f64,
}

impl Stats {
    fn add(&mut self, p: &Packet) {
        let len = p.len as u64;
        self.packets += 1;
        self.bytes += len;
        self.first.get_or_insert(p.ts);
        self.last = p.ts;
        let e = self.protos.entry(p.d.proto.clone()).or_default();
        e.0 += 1;
        e.1 += len;
        if let (Some(s), Some(d)) = (p.d.src_ip, p.d.dst_ip) {
            let t = self.talkers.entry(s).or_default();
            t.0 += 1;
            t.1 += len;
            let t = self.talkers.entry(d).or_default();
            t.2 += 1;
            t.3 += len;
            let ep = |ip: IpAddr, port: Option<u16>| match (ip, port) {
                (IpAddr::V6(v6), Some(p)) => format!("[{v6}]:{p}"),
                (ip, Some(p)) => format!("{ip}:{p}"),
                (ip, None) => ip.to_string(),
            };
            let a = ep(s, p.d.src_port);
            let b = ep(d, p.d.dst_port);
            // Direction-independent key.
            let key = if a <= b {
                (a, b, p.d.transport.unwrap_or("IP"))
            } else {
                (b, a, p.d.transport.unwrap_or("IP"))
            };
            let c = self.convs.entry(key).or_insert_with(|| Conv {
                first: p.ts,
                ..Default::default()
            });
            c.packets += 1;
            c.bytes += len;
            c.last = p.ts;
        }
    }

    fn duration(&self) -> f64 {
        self.first.map(|f| (self.last - f).max(0.0)).unwrap_or(0.0)
    }
}

pub struct CaptureView {
    focus: FocusHandle,
    ifaces: Result<Vec<Interface>, String>,
    iface: Option<usize>,
    picker_open: bool,
    bpf: Entity<TextInput>,
    display: Entity<TextInput>,
    file: Entity<TextInput>,
    promisc: bool,
    save: bool,
    handle: Option<CaptureHandle>,
    packets: Vec<Packet>,
    visible: Vec<usize>,
    selected: Option<usize>,
    linktype: i32,
    source: String,
    stats: Stats,
    pcap_stats: Option<(u32, u32, u32)>,
    dropped_ui: u64,
    mode: Mode,
    follow: bool,
    status: SharedString,
    error: Option<String>,
    started: Option<Instant>,
    scroll: UniformListScrollHandle,
    _poll: Option<Task<()>>,
}

impl CaptureView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ifaces = capture::interfaces();
        // Default to the interface carrying the default route.
        let primary = crate::netinfo::local_interfaces()
            .into_iter()
            .next()
            .map(|i| i.ip.to_string());
        let iface = ifaces.as_ref().ok().and_then(|l| {
            l.iter()
                .position(|i| primary.as_ref().is_some_and(|p| i.addrs.contains(p)))
                .or((!l.is_empty()).then_some(0))
        });
        let bpf = input(
            window,
            cx,
            "",
            "Capture filter (BPF): tcp port 502, host 10.0.0.5, not arp",
            Accept::Any,
            |t| t.width(330.).mono(),
            |this: &mut Self, _, cx| this.start_live(cx),
        );
        let display = input(
            window,
            cx,
            "",
            "Display filter: dns, 10.0.0.5, modbus, !arp",
            Accept::Any,
            |t| t.width(330.),
            |_: &mut Self, _, _| {},
        );
        cx.observe(&display, |this, _, cx| {
            this.recompute_visible(cx);
            cx.notify();
        })
        .detach();
        let file = input(
            window,
            cx,
            "",
            "path/to/file.pcap",
            Accept::Any,
            |t| t.width(240.),
            |this: &mut Self, _, cx| this.open_file(cx),
        );
        let status = match &ifaces {
            Ok(l) => format!(
                "{} capture interfaces. Pick one and press Start, or open a .pcap file.",
                l.len()
            ),
            Err(e) => format!("Packet capture unavailable: {e}"),
        };
        Self {
            focus: cx.focus_handle(),
            error: ifaces.as_ref().err().cloned(),
            ifaces,
            iface,
            picker_open: false,
            bpf,
            display,
            file,
            promisc: true,
            save: false,
            handle: None,
            packets: Vec::new(),
            visible: Vec::new(),
            selected: None,
            linktype: 1,
            source: String::new(),
            stats: Stats::default(),
            pcap_stats: None,
            dropped_ui: 0,
            mode: Mode::Packets,
            follow: true,
            status: status.into(),
            started: None,
            scroll: UniformListScrollHandle::new(),
            _poll: None,
        }
    }

    fn reset(&mut self) {
        self.packets.clear();
        self.visible.clear();
        self.selected = None;
        self.stats = Stats::default();
        self.pcap_stats = None;
        self.dropped_ui = 0;
        self.error = None;
    }

    fn start_live(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let Some(iface) = self
            .iface
            .and_then(|i| self.ifaces.as_ref().ok()?.get(i).cloned())
        else {
            self.error = Some("Select a capture interface first".into());
            return;
        };
        let save_to = self.save.then(|| {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            crate::platform::home_dir()
                .unwrap_or_else(|| ".".into())
                .join(format!("capture-{ts}.pcap"))
        });
        let cfg = CaptureConfig {
            source: Source::Live {
                device: iface.name.clone(),
                promisc: self.promisc,
            },
            filter: self.bpf.read(cx).value.clone(),
            save_to: save_to.clone(),
        };
        self.begin(cfg, cx);
        self.status = match save_to {
            Some(p) => format!("Capturing on {} → {}", iface.label(), p.display()),
            None => format!("Capturing on {}", iface.label()),
        }
        .into();
    }

    fn open_file(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let raw = self
            .file
            .read(cx)
            .value
            .trim()
            .trim_matches('"')
            .to_string();
        if raw.is_empty() {
            self.file.update(cx, |t, cx| {
                t.error = true;
                cx.notify()
            });
            return;
        }
        let path = match raw.strip_prefix("~/") {
            Some(rest) => crate::platform::home_dir().unwrap_or_default().join(rest),
            None => PathBuf::from(&raw),
        };
        let cfg = CaptureConfig {
            source: Source::File(path.clone()),
            filter: self.bpf.read(cx).value.clone(),
            save_to: None,
        };
        self.begin(cfg, cx);
        self.status = format!("Reading {}", path.display()).into();
    }

    fn begin(&mut self, cfg: CaptureConfig, cx: &mut Context<Self>) {
        self.reset();
        self.picker_open = false;
        self.handle = Some(capture::start(cfg));
        self.started = Some(Instant::now());
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

    fn stop(&mut self) {
        if let Some(h) = &self.handle {
            h.stop();
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let mut stopped = None;
        let mut new = Vec::new();
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                CaptureEvent::Started { linktype, desc } => {
                    self.linktype = linktype;
                    self.source = desc;
                }
                CaptureEvent::Packets(p) => new.extend(p),
                CaptureEvent::Stats {
                    received,
                    dropped,
                    if_dropped,
                } => self.pcap_stats = Some((received, dropped, if_dropped)),
                CaptureEvent::Stopped(err) => stopped = Some(err),
            }
        }
        if !new.is_empty() {
            let terms = filter_terms(&self.display.read(cx).value);
            for p in new {
                self.stats.add(&p);
                if self.packets.len() >= MAX_PACKETS {
                    self.dropped_ui += 1;
                    continue;
                }
                if matches(&p, &terms) {
                    self.visible.push(self.packets.len());
                }
                self.packets.push(p);
            }
            if self.follow && self.mode == Mode::Packets && !self.visible.is_empty() {
                self.scroll
                    .scroll_to_item(self.visible.len() - 1, ScrollStrategy::Bottom);
            }
        }
        let finished = stopped.is_some();
        if let Some(err) = stopped {
            self.handle = None;
            self.started = None;
            self.status = match &err {
                Some(e) => {
                    let hint = capture::permission_hint(e);
                    self.error = Some(match hint {
                        Some(h) => format!("{e}\n{h}"),
                        None => e.clone(),
                    });
                    format!("Capture failed: {e}").into()
                }
                None => format!(
                    "Stopped — {} packets, {} from {}",
                    self.stats.packets,
                    human_bytes(self.stats.bytes),
                    self.source
                )
                .into(),
            };
        }
        cx.notify();
        !finished
    }

    fn recompute_visible(&mut self, cx: &App) {
        let terms = filter_terms(&self.display.read(cx).value);
        self.visible = (0..self.packets.len())
            .filter(|&i| matches(&self.packets[i], &terms))
            .collect();
        if let Some(sel) = self.selected
            && !self.visible.contains(&sel)
        {
            self.selected = None;
        }
    }

    fn save_visible(&mut self) {
        if self.visible.is_empty() {
            self.status = "Nothing to save".into();
            return;
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = crate::platform::home_dir()
            .unwrap_or_else(|| ".".into())
            .join(format!("packets-{ts}.pcap"));
        let pkts: Vec<&Packet> = self.visible.iter().map(|&i| &self.packets[i]).collect();
        self.status = match capture::write_pcap(&path, self.linktype, &pkts) {
            Ok(()) => format!("Saved {} packets to {}", pkts.len(), path.display()).into(),
            Err(e) => format!("Save failed: {e}").into(),
        };
    }

    // ------------------------------------------------------------ rendering

    fn render_toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let iface_label = match (&self.ifaces, self.iface) {
            (Ok(l), Some(i)) => l.get(i).map(|i| i.label()).unwrap_or_default(),
            (Ok(_), None) => "Select interface".into(),
            (Err(_), _) => "Capture unavailable".into(),
        };
        div()
            .flex()
            .flex_col()
            .child(
                toolbar()
                    .child(label("Interface"))
                    .child(
                        button2("iface-pick", format!("{iface_label}  ▾"), act(&view, |t: &mut Self, _, _| t.picker_open = !t.picker_open))
                            .max_w(px(320.))
                            .overflow_hidden(),
                    )
                    .child(self.bpf.clone())
                    .child(chip("promisc", "Promiscuous", self.promisc, act(&view, |t: &mut Self, _, _| t.promisc = !t.promisc)).tooltip(tip("Capture all frames seen by the interface, not only those addressed to this machine.")))
                    .child(chip("save", "Save to .pcap", self.save, act(&view, |t: &mut Self, _, _| t.save = !t.save)).tooltip(tip("Also write every captured packet to ~/capture-<time>.pcap")))
                    .child(if running {
                        button("cap-start", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.stop()))
                    } else {
                        button_primary("cap-start", "▶ Start", act(&view, |t: &mut Self, _, cx| t.start_live(cx)))
                    })
                    .child(div().w(px(1.)).h(px(24.)).bg(rgb(C::BORDER)))
                    .child(self.file.clone())
                    .child(button2("cap-open", "Open .pcap", act(&view, |t: &mut Self, _, cx| t.open_file(cx)))),
            )
            .child(
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
                    .child(chip("mode-pk", "Packets", self.mode == Mode::Packets, act(&view, |t: &mut Self, _, _| t.mode = Mode::Packets)))
                    .child(chip("mode-an", "Analysis", self.mode == Mode::Analysis, act(&view, |t: &mut Self, _, _| t.mode = Mode::Analysis)))
                    .child(div().w(px(8.)))
                    .child(self.display.clone())
                    .child(chip("follow", "Auto-scroll", self.follow, act(&view, |t: &mut Self, _, _| t.follow = !t.follow)))
                    .child(div().flex_1())
                    .child(button2("cap-save", "Save shown as .pcap", act(&view, |t: &mut Self, _, _| t.save_visible())))
                    .child(button2("cap-clear", "Clear", act(&view, |t: &mut Self, _, _| t.reset()))),
            )
    }

    fn render_picker(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let list = self.ifaces.as_ref().map(|l| l.as_slice()).unwrap_or(&[]);
        div()
            .id("iface-list")
            .absolute()
            .top(px(56.))
            .left(px(90.))
            .w(px(520.))
            .max_h(px(420.))
            .overflow_y_scroll()
            .p_1()
            .rounded_md()
            .bg(rgb(C::PANEL2))
            .border_1()
            .border_color(rgb(C::BORDER))
            .shadow_lg()
            .children(list.iter().enumerate().map(|(i, f)| {
                let active = self.iface == Some(i);
                div()
                    .id(("iface", i))
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .cursor_pointer()
                    .bg(rgb(if active { C::SELECT } else { C::PANEL2 }))
                    .hover(|s| s.bg(rgb(C::BORDER)))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .items_center()
                            .child(div().size(px(8.)).rounded_full().bg(rgb(if f.up {
                                C::GREEN
                            } else {
                                0x3a4252
                            })))
                            .child(
                                div()
                                    .text_sm()
                                    .child(if cfg!(windows) && !f.desc.is_empty() {
                                        f.desc.clone()
                                    } else {
                                        f.name.clone()
                                    }),
                            )
                            .when(f.loopback, |d| d.child(label("loopback"))),
                    )
                    .child(
                        label(
                            [
                                f.addrs.join(", "),
                                if cfg!(windows) {
                                    String::new()
                                } else {
                                    f.desc.clone()
                                },
                            ]
                            .into_iter()
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join(" · "),
                        )
                        .pl(px(16.)),
                    )
                    .on_click(act(&view, move |t: &mut Self, _, _| {
                        t.iface = Some(i);
                        t.picker_open = false;
                    }))
            }))
    }

    fn render_row(&self, vi: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let idx = self.visible[vi];
        let p = &self.packets[idx];
        let t0 = self.stats.first.unwrap_or(p.ts);
        let selected = self.selected == Some(idx);
        let color = proto_color(&p.d.proto);
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
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected = if this.selected == Some(idx) {
                    None
                } else {
                    Some(idx)
                };
                this.follow = false;
                cx.notify();
            }))
            .child(cell(COLS[0].1, p.no.to_string()).text_color(rgb(C::MUTED)))
            .child(cell(COLS[1].1, format!("{:.6}", p.ts - t0)).text_color(rgb(C::MUTED)))
            .child(cell(COLS[2].1, p.d.src.clone()))
            .child(cell(COLS[3].1, p.d.dst.clone()))
            .child(cell(COLS[4].1, p.d.proto.clone()).text_color(rgb(color)))
            .child(cell(COLS[5].1, p.len.to_string()))
            .child(cell(0., p.d.info.clone()))
            .into_any_element()
    }

    fn render_packets(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let body = if self.visible.is_empty() {
            let (title, hint) = if self.handle.is_some() {
                (
                    "Waiting for packets…",
                    "Generate some traffic, or check the capture filter.",
                )
            } else if !self.packets.is_empty() {
                (
                    "No packets match the display filter",
                    "Terms match protocol, addresses, ports and info; prefix with ! to exclude.",
                )
            } else {
                (
                    "No packets",
                    "Choose an interface and press Start, or open a .pcap / .pcapng file.",
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
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .child(table_header(&COLS))
            .child(body)
            .children(self.selected.map(|i| self.render_detail(i, cx)))
    }

    fn render_detail(&self, idx: usize, cx: &mut Context<Self>) -> impl IntoElement {
        let p = &self.packets[idx];
        let mut layers = vec![{
            let mut l = dissect::Layer {
                name: format!("Frame {}", p.no),
                fields: Vec::new(),
            };
            l.fields.push((
                "Length".into(),
                format!("{} bytes ({} captured)", p.len, p.data.len()),
            ));
            l.fields.push(("Arrival".into(), format_ts(p.ts)));
            l.fields.push((
                "Link type".into(),
                dissect::linktype_name(self.linktype).into(),
            ));
            l
        }];
        layers.extend(p.d.layers.iter().cloned());
        div()
            .flex()
            .flex_row()
            .h(px(280.))
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
                    .children(layers.into_iter().map(|l| {
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(section_title(&l.name))
                            .children(l.fields.into_iter().map(|(k, v)| kv_row(k, v, 150.)))
                    })),
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
                            .justify_between()
                            .child(section_title("Bytes"))
                            .child(
                                div()
                                    .id("close-detail")
                                    .px_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .hover(|s| s.bg(rgb(C::PANEL2)))
                                    .child("✕")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.selected = None;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .children(
                        dissect::hexdump(&p.data)
                            .into_iter()
                            .take(256)
                            .map(|l| div().whitespace_nowrap().child(l)),
                    ),
            )
    }

    fn render_analysis(&self) -> impl IntoElement {
        let s = &self.stats;
        let dur = s.duration();
        let mut protos: Vec<_> = s.protos.iter().collect();
        protos.sort_by_key(|a| std::cmp::Reverse(a.1.0));
        let mut talkers: Vec<_> = s.talkers.iter().collect();
        talkers.sort_by_key(|a| std::cmp::Reverse(a.1.1 + a.1.3));
        let mut convs: Vec<_> = s.convs.iter().collect();
        convs.sort_by_key(|a| std::cmp::Reverse(a.1.bytes));

        let tile = |k: &str, v: String| {
            div()
                .flex()
                .flex_col()
                .px_4()
                .py_3()
                .rounded_md()
                .bg(rgb(C::PANEL))
                .border_1()
                .border_color(rgb(C::BORDER))
                .child(label(k.to_string()))
                .child(
                    div()
                        .text_xl()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(v),
                )
        };
        let panel = |title: String| {
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
                .child(section_title(&title))
        };
        let row = |cols: Vec<(f32, String, u32)>| {
            div().flex().flex_row().items_center().h(px(24.)).children(
                cols.into_iter()
                    .map(|(w, t, c)| cell(w, t).text_color(rgb(c))),
            )
        };
        let total = s.packets.max(1) as f32;

        div()
            .id("analysis")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(tile("Packets", s.packets.to_string()))
                    .child(tile("Data", human_bytes(s.bytes)))
                    .child(tile("Duration", format!("{dur:.1} s")))
                    .child(tile(
                        "Avg rate",
                        if dur > 0.0 {
                            format!("{:.0} pkt/s", s.packets as f64 / dur)
                        } else {
                            "—".into()
                        },
                    ))
                    .child(tile(
                        "Avg throughput",
                        if dur > 0.0 {
                            format!("{}/s", human_bits(s.bytes as f64 * 8.0 / dur))
                        } else {
                            "—".into()
                        },
                    ))
                    .child(tile(
                        "Avg size",
                        s.bytes
                            .checked_div(s.packets)
                            .map(|b| format!("{b} B"))
                            .unwrap_or_else(|| "—".into()),
                    ))
                    .child(tile("Hosts", s.talkers.len().to_string()))
                    .child(tile("Conversations", s.convs.len().to_string()))
                    .when_some(self.pcap_stats, |d, (_, dropped, ifd)| {
                        d.child(tile("Dropped (kernel/if)", format!("{dropped} / {ifd}")))
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_4()
                    .items_start()
                    .child(
                        panel(format!("Protocols ({})", protos.len()))
                            .w(px(440.))
                            .flex_none()
                            .child(row(vec![
                                (130., "PROTOCOL".into(), C::MUTED),
                                (80., "PACKETS".into(), C::MUTED),
                                (90., "BYTES".into(), C::MUTED),
                                (0., "SHARE".into(), C::MUTED),
                            ]))
                            .children(protos.iter().take(40).map(|(name, (n, b))| {
                                let frac = *n as f32 / total;
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .h(px(24.))
                                    .child(
                                        cell(130., name.to_string())
                                            .text_color(rgb(proto_color(name))),
                                    )
                                    .child(cell(80., n.to_string()))
                                    .child(cell(90., human_bytes(*b)))
                                    .child(
                                        div()
                                            .flex_1()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .h(px(8.))
                                                    .w(px(100. * frac))
                                                    .rounded_sm()
                                                    .bg(rgb(proto_color(name))),
                                            )
                                            .child(label(format!("{:.1}%", frac * 100.))),
                                    )
                            })),
                    )
                    .child(
                        panel(format!("Top talkers ({})", talkers.len()))
                            .flex_1()
                            .min_w_0()
                            .child(row(vec![
                                (240., "ADDRESS".into(), C::MUTED),
                                (110., "SENT".into(), C::MUTED),
                                (110., "RECEIVED".into(), C::MUTED),
                                (0., "TOTAL".into(), C::MUTED),
                            ]))
                            .children(talkers.iter().take(25).map(|(ip, (tp, tb, rp, rb))| {
                                row(vec![
                                    (240., ip.to_string(), C::TEXT),
                                    (110., format!("{tp} · {}", human_bytes(*tb)), C::MUTED),
                                    (110., format!("{rp} · {}", human_bytes(*rb)), C::MUTED),
                                    (0., human_bytes(tb + rb), C::TEXT),
                                ])
                            })),
                    ),
            )
            .child(
                panel(format!("Conversations ({})", convs.len()))
                    .child(row(vec![
                        (70., "PROTO".into(), C::MUTED),
                        (300., "ENDPOINT A".into(), C::MUTED),
                        (300., "ENDPOINT B".into(), C::MUTED),
                        (90., "PACKETS".into(), C::MUTED),
                        (100., "BYTES".into(), C::MUTED),
                        (0., "DURATION".into(), C::MUTED),
                    ]))
                    .children(convs.iter().take(60).map(|((a, b, proto), c)| {
                        row(vec![
                            (70., proto.to_string(), C::CYAN),
                            (300., a.clone(), C::TEXT),
                            (300., b.clone(), C::TEXT),
                            (90., c.packets.to_string(), C::MUTED),
                            (100., human_bytes(c.bytes), C::MUTED),
                            (0., format!("{:.2} s", c.last - c.first), C::MUTED),
                        ])
                    })),
            )
    }
}

fn filter_terms(q: &str) -> Vec<(bool, String)> {
    q.split_whitespace()
        .map(|t| match t.strip_prefix('!') {
            Some(neg) => (false, neg.to_lowercase()),
            None => (true, t.to_lowercase()),
        })
        .filter(|(_, t)| !t.is_empty())
        .collect()
}

fn matches(p: &Packet, terms: &[(bool, String)]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let hay = format!(
        "{} {} {} {} {} {}",
        p.d.proto,
        p.d.src,
        p.d.dst,
        p.d.src_port.map(|p| p.to_string()).unwrap_or_default(),
        p.d.dst_port.map(|p| p.to_string()).unwrap_or_default(),
        p.d.info
    )
    .to_lowercase();
    terms
        .iter()
        .all(|(want, t)| hay.contains(t.as_str()) == *want)
}

fn proto_color(p: &str) -> u32 {
    match p {
        "TCP" => 0x8fb3ff,
        "UDP" => 0x7fd4e8,
        "HTTP" => C::GREEN,
        "TLS" | "QUIC" => 0x9aa8ff,
        "DNS" | "mDNS" | "LLMNR" => C::CYAN,
        "ARP" => C::AMBER,
        "ICMP" | "ICMPv6" | "IGMP" => 0xf28fb3,
        "DHCP" | "NTP" | "SSDP" | "NBNS" => 0xc4a7ff,
        "Modbus/TCP" | "Modbus/UDP" | "PROFINET" | "EtherCAT" | "BACnet" | "EtherNet/IP" => {
            C::PURPLE
        }
        "SSH" | "Telnet" | "RDP" | "SMB" => 0xffb86b,
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

fn human_bits(b: f64) -> String {
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

/// UTC wall-clock time of a capture timestamp.
fn format_ts(ts: f64) -> String {
    let secs = ts.floor() as i64;
    let frac = ts - ts.floor();
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}.{:06} UTC", (frac * 1e6) as u32)
}

impl Focusable for CaptureView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for CaptureView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let elapsed = self.started.map(|s| s.elapsed());
        div()
            .track_focus(&self.focus)
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .child(self.render_toolbar(cx))
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .children(
                        e.lines()
                            .map(|l| div().child(l.to_string()))
                            .collect::<Vec<_>>(),
                    )
            }))
            .child(match self.mode {
                Mode::Packets => self.render_packets(cx).into_any_element(),
                Mode::Analysis => self.render_analysis().into_any_element(),
            })
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .child(format!("{} packets", self.stats.packets))
                    .child(format!("{} shown", self.visible.len()))
                    .child(human_bytes(self.stats.bytes))
                    .when_some(self.pcap_stats, |d, (rx, drop, _)| {
                        d.child(format!("kernel: {rx} received, {drop} dropped"))
                    })
                    .when(self.dropped_ui > 0, |d| {
                        d.child(div().text_color(rgb(C::AMBER)).child(format!(
                            "list full: {} packets not kept (stats still counted)",
                            self.dropped_ui
                        )))
                    })
                    .children(elapsed.map(|e| format!("{:.1}s", e.as_secs_f32()))),
            )
            .when(self.picker_open, |d| d.child(self.render_picker(cx)))
    }
}
