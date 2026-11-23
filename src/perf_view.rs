//! Bandwidth Monitor, Throughput Tester and Wi-Fi Analyser.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::bandwidth::Counters;
use crate::throughput::{self, ClientEvent, ClientHandle, Mode, ServerEvent, ServerHandle};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, bar_chart_slots, button, button_primary, button2, cell, chip,
    copy_button, empty_state, input, label, mbit, section_title, status_bar, table_header, tile,
    tip, toolbar,
};
use crate::wifi::{self, Network};

fn poll<V: 'static>(
    cx: &mut Context<V>,
    ms: u64,
    f: fn(&mut V, &mut Context<V>) -> bool,
) -> Task<()> {
    cx.spawn(async move |this, cx| {
        loop {
            cx.background_executor()
                .timer(Duration::from_millis(ms))
                .await;
            match this.update(cx, f) {
                Ok(true) => {}
                _ => break,
            }
        }
    })
}

fn bytes(b: u64) -> String {
    crate::capture_view::human_bytes(b)
}

// ---------------------------------------------------------------- bandwidth

#[derive(Default)]
struct IfaceRate {
    first: Option<Counters>,
    last: Option<(Instant, Counters)>,
    rx: VecDeque<f32>,
    tx: VecDeque<f32>,
    pps: f64,
    peak_rx: f64,
    peak_tx: f64,
    new_errors: u64,
}

pub struct BandwidthView {
    focus: FocusHandle,
    rx: Receiver<Vec<Counters>>,
    stop: Arc<AtomicBool>,
    ifaces: BTreeMap<String, IfaceRate>,
    selected: Option<String>,
    show_idle: bool,
    _poll: Option<Task<()>>,
}

impl Drop for BandwidthView {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

const HISTORY: usize = 120;

impl BandwidthView {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (tx, rx) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                let t = Instant::now();
                if tx.send(crate::bandwidth::read()).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1).saturating_sub(t.elapsed()));
            }
        });
        let mut v = Self {
            focus: cx.focus_handle(),
            rx,
            stop,
            ifaces: BTreeMap::new(),
            selected: None,
            show_idle: false,
            _poll: None,
        };
        v._poll = Some(poll(cx, 250, Self::drain));
        v
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let mut changed = false;
        while let Ok(list) = self.rx.try_recv() {
            let now = Instant::now();
            for c in list {
                let e = self.ifaces.entry(c.name.clone()).or_default();
                if let Some((t, prev)) = &e.last {
                    let secs = now.duration_since(*t).as_secs_f64().max(0.2);
                    let rx = c.rx_bytes.saturating_sub(prev.rx_bytes) as f64 * 8.0 / secs;
                    let tx = c.tx_bytes.saturating_sub(prev.tx_bytes) as f64 * 8.0 / secs;
                    e.pps = (c.rx_packets + c.tx_packets)
                        .saturating_sub(prev.rx_packets + prev.tx_packets)
                        as f64
                        / secs;
                    e.peak_rx = e.peak_rx.max(rx);
                    e.peak_tx = e.peak_tx.max(tx);
                    e.new_errors = (c.errors + c.drops)
                        .saturating_sub(e.first.as_ref().map(|f| f.errors + f.drops).unwrap_or(0));
                    e.rx.push_back(rx as f32);
                    e.tx.push_back(tx as f32);
                    if e.rx.len() > HISTORY {
                        e.rx.pop_front();
                        e.tx.pop_front();
                    }
                }
                if e.first.is_none() {
                    e.first = Some(c.clone());
                }
                e.last = Some((now, c));
            }
            changed = true;
        }
        if self.selected.is_none() {
            // Busiest interface by default.
            self.selected = self
                .ifaces
                .iter()
                .filter(|(n, _)| n.as_str() != "lo")
                .max_by(|a, b| a.1.peak_rx.total_cmp(&b.1.peak_rx))
                .map(|(n, _)| n.clone());
        }
        if changed {
            cx.notify();
        }
        true
    }
}

impl Focusable for BandwidthView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for BandwidthView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let rows: Vec<(&String, &IfaceRate)> = self
            .ifaces
            .iter()
            .filter(|(n, r)| {
                self.show_idle || (r.peak_rx + r.peak_tx > 0.0 && !n.starts_with("veth"))
            })
            .collect();
        let sel = self
            .selected
            .as_ref()
            .and_then(|s| self.ifaces.get(s).map(|r| (s.clone(), r)));
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(div().text_sm().text_color(rgb(C::MUTED)).child(
                        "Live traffic per interface, sampled every second from the OS counters.",
                    ))
                    .child(div().flex_1())
                    .child(chip(
                        "bw-idle",
                        "Show idle / virtual",
                        self.show_idle,
                        act(&view, |t: &mut Self, _, _| t.show_idle = !t.show_idle),
                    )),
            )
            .child(table_header(&[
                ("INTERFACE", 200.),
                ("DOWNLOAD (RX)", 150.),
                ("UPLOAD (TX)", 150.),
                ("PEAK RX", 130.),
                ("PEAK TX", 130.),
                ("TOTAL RX / TX", 220.),
                ("PACKETS/S", 100.),
                ("ERR+DROP", 0.),
            ]))
            .child(
                div()
                    .id("bw-rows")
                    .max_h(px(260.))
                    .overflow_y_scroll()
                    .children(rows.iter().enumerate().map(|(i, (name, r))| {
                        let name = (*name).clone();
                        let n2 = name.clone();
                        let (crx, ctx) = (
                            r.rx.back().copied().unwrap_or(0.0) as f64,
                            r.tx.back().copied().unwrap_or(0.0) as f64,
                        );
                        let totals = match (&r.first, &r.last) {
                            (Some(f), Some((_, l))) => format!(
                                "{} / {}",
                                bytes(l.rx_bytes - f.rx_bytes.min(l.rx_bytes)),
                                bytes(l.tx_bytes - f.tx_bytes.min(l.tx_bytes))
                            ),
                            _ => "—".into(),
                        };
                        div()
                            .id(("bw", i))
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(30.))
                            .text_sm()
                            .cursor_pointer()
                            .bg(rgb(if self.selected.as_ref() == Some(&name) {
                                C::SELECT
                            } else if i % 2 == 1 {
                                C::ROW_ALT
                            } else {
                                C::BG
                            }))
                            .hover(|s| s.bg(rgb(C::PANEL2)))
                            .on_click(act(&view, move |t: &mut Self, _, _| {
                                t.selected = Some(n2.clone())
                            }))
                            .child(cell(200., name))
                            .child(cell(150., mbit(crx)).text_color(rgb(C::GREEN)))
                            .child(cell(150., mbit(ctx)).text_color(rgb(C::ACCENT)))
                            .child(cell(130., mbit(r.peak_rx)).text_color(rgb(C::MUTED)))
                            .child(cell(130., mbit(r.peak_tx)).text_color(rgb(C::MUTED)))
                            .child(cell(220., totals))
                            .child(cell(100., format!("{:.0}", r.pps)))
                            .child(cell(0., r.new_errors.to_string()).text_color(rgb(
                                if r.new_errors > 0 { C::AMBER } else { C::MUTED },
                            )))
                    })),
            )
            .child(match sel {
                None => {
                    empty_state("Collecting…", "Rates appear after two samples.").into_any_element()
                }
                Some((name, r)) => {
                    // Fixed two-minute window, filling from the right.
                    let pad = HISTORY.saturating_sub(r.rx.len());
                    let rx: Vec<Option<f32>> = std::iter::repeat_n(Some(0.0), pad)
                        .chain(r.rx.iter().map(|v| Some(*v)))
                        .collect();
                    let tx: Vec<Option<f32>> = std::iter::repeat_n(Some(0.0), pad)
                        .chain(r.tx.iter().map(|v| Some(*v)))
                        .collect();
                    let top = r.peak_rx.max(r.peak_tx) as f32;
                    div()
                        .flex_1()
                        .min_h_0()
                        .p_5()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(section_title(&format!(
                            "{name} — last {} s (same scale)",
                            r.rx.len()
                        )))
                        .child(label(format!(
                            "Download {}",
                            mbit(r.rx.back().copied().unwrap_or(0.0) as f64)
                        )))
                        .child(bar_chart_slots(&rx, HISTORY, 960.0, 110.0, top, C::GREEN))
                        .child(label(format!(
                            "Upload {}",
                            mbit(r.tx.back().copied().unwrap_or(0.0) as f64)
                        )))
                        .child(bar_chart_slots(&tx, HISTORY, 960.0, 110.0, top, C::ACCENT))
                        .into_any_element()
                }
            })
    }
}

// ---------------------------------------------------------------- throughput

pub struct ThroughputView {
    focus: FocusHandle,
    srv_port: Entity<TextInput>,
    server: Option<ServerHandle>,
    server_log: Vec<String>,
    host: Entity<TextInput>,
    port: Entity<TextInput>,
    secs: Entity<TextInput>,
    streams: Entity<TextInput>,
    url: Entity<TextInput>,
    mode: Mode,
    client: Option<ClientHandle>,
    label: String,
    seconds: Vec<Option<f32>>,
    result: Option<String>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
    _srv_poll: Option<Task<()>>,
}

impl ThroughputView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let dp = throughput::DEFAULT_PORT.to_string();
        let run = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.run_client(cx);
        Self {
            focus: cx.focus_handle(),
            srv_port: input(window, cx, &dp, &dp, Accept::Digits, |t| t.width(80.).max_len(5), |t: &mut Self, _, cx| t.toggle_server(cx)),
            server: None,
            server_log: Vec::new(),
            host: input(window, cx, "", "IP of the machine running the server", Accept::Any, |t| t.width(260.), run),
            port: input(window, cx, &dp, &dp, Accept::Digits, |t| t.width(80.).max_len(5), run),
            secs: input(window, cx, "10", "s", Accept::Digits, |t| t.width(60.).max_len(3), run),
            streams: input(window, cx, "4", "1-16", Accept::Digits, |t| t.width(50.).max_len(2), run),
            url: input(window, cx, &crate::settings::get().speed_url, crate::settings::DEFAULT_SPEED_URL, Accept::Any, |t| t.width(440.).max_len(500), |t: &mut Self, _, cx| t.run_http(cx)),
            mode: Mode::Download,
            client: None,
            label: String::new(),
            seconds: Vec::new(),
            result: None,
            status: "Start the server on one machine, then run the client on another — or use the HTTP download test.".into(),
            error: None,
            _poll: None,
            _srv_poll: None,
        }
    }

    fn toggle_server(&mut self, cx: &mut Context<Self>) {
        if let Some(s) = self.server.take() {
            s.stop();
            self.server_log.push("server stopped".into());
            return;
        }
        let port = self
            .srv_port
            .read(cx)
            .value
            .parse()
            .unwrap_or(throughput::DEFAULT_PORT);
        self.server = Some(throughput::serve(port));
        self._srv_poll = Some(poll(cx, 300, |t: &mut Self, cx| {
            let Some(s) = &t.server else { return false };
            let mut alive = true;
            while let Ok(ev) = s.events.try_recv() {
                let line = match ev {
                    ServerEvent::Listening(p) => {
                        let ips: Vec<String> = crate::netinfo::local_interfaces()
                            .iter()
                            .map(|i| i.ip.to_string())
                            .collect();
                        format!(
                            "listening on TCP/UDP {p} — clients connect to {}",
                            ips.join(" or ")
                        )
                    }
                    ServerEvent::Session {
                        peer,
                        mode,
                        bytes: b,
                        secs,
                    } => format!(
                        "{peer} {mode}: {} in {secs:.1} s = {}",
                        bytes(b),
                        mbit(throughput::mbps(b, secs) * 1e6)
                    ),
                    ServerEvent::Error(e) => format!("error: {e}"),
                    ServerEvent::Stopped => {
                        alive = false;
                        "server stopped".into()
                    }
                };
                t.server_log.push(line);
            }
            if !alive {
                t.server = None;
            }
            cx.notify();
            alive
        }));
    }

    fn start_poll(&mut self, cx: &mut Context<Self>) {
        self.seconds.clear();
        self.result = None;
        self.error = None;
        self._poll = Some(poll(cx, 200, |t: &mut Self, cx| {
            let Some(c) = &t.client else { return false };
            let mut done = false;
            while let Ok(ev) = c.events.try_recv() {
                match ev {
                    ClientEvent::Connected(s) => t.status = format!("{}: {s}", t.label).into(),
                    ClientEvent::Interval { second, bytes } => {
                        let i = second as usize - 1;
                        if t.seconds.len() <= i {
                            t.seconds.resize(i + 1, None);
                        }
                        t.seconds[i] = Some((bytes as f64 * 8.0 / 1e6) as f32);
                    }
                    ClientEvent::Done {
                        bytes: b,
                        secs,
                        server_bytes,
                    } => {
                        done = true;
                        let mut r = format!(
                            "{}: {} in {secs:.1} s = {}",
                            t.label,
                            bytes(b),
                            mbit(throughput::mbps(b, secs) * 1e6)
                        );
                        if let Some(sb) = server_bytes {
                            r.push_str(&format!(" (server received {})", bytes(sb)));
                        }
                        t.status = "Done".into();
                        t.result = Some(r);
                    }
                    ClientEvent::Error(e) => {
                        done = true;
                        t.error = Some(e);
                        t.status = "Test failed".into();
                    }
                }
            }
            if done {
                t.client = None;
            }
            cx.notify();
            !done
        }));
    }

    fn run_client(&mut self, cx: &mut Context<Self>) {
        if self.client.is_some() {
            return;
        }
        let host = self.host.read(cx).value.trim().to_string();
        if host.is_empty() {
            self.error = Some("Enter the server's address".into());
            return;
        }
        let num = |e: &Entity<TextInput>, d: u32| e.read(cx).value.parse::<u32>().unwrap_or(d);
        let (port, secs, streams) = (
            num(&self.port, throughput::DEFAULT_PORT as u32) as u16,
            num(&self.secs, 10).clamp(1, 120),
            num(&self.streams, 4).clamp(1, 16),
        );
        self.label = format!(
            "{} to {host}, {streams} stream(s)",
            if self.mode == Mode::Upload {
                "Upload"
            } else {
                "Download"
            }
        );
        self.client = Some(throughput::run_client(host, port, self.mode, secs, streams));
        self.status = format!("{}…", self.label).into();
        self.start_poll(cx);
    }

    fn run_http(&mut self, cx: &mut Context<Self>) {
        if self.client.is_some() {
            return;
        }
        let url = self.url.read(cx).value.trim().to_string();
        let secs = self
            .secs
            .read(cx)
            .value
            .parse::<u32>()
            .unwrap_or(10)
            .clamp(1, 120);
        let _ = crate::settings::update(|s| s.speed_url = url.clone());
        self.label = format!(
            "HTTP download from {}",
            url.split('/').nth(2).unwrap_or(&url)
        );
        self.client = Some(throughput::http_download(url, secs));
        self.status = format!("{}…", self.label).into();
        self.start_poll(cx);
    }
}

impl Focusable for ThroughputView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for ThroughputView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.client.is_some();
        let panel = || {
            div()
                .flex()
                .flex_col()
                .gap_2()
                .p_4()
                .rounded_md()
                .bg(rgb(C::PANEL))
                .border_1()
                .border_color(rgb(C::BORDER))
        };
        let row = || div().flex().flex_wrap().items_center().gap_2();
        let vals: Vec<f32> = self.seconds.iter().flatten().copied().collect();
        let avg = if vals.is_empty() {
            0.0
        } else {
            vals.iter().sum::<f32>() / vals.len() as f32
        };
        let peak = vals.iter().copied().fold(0.0f32, f32::max);
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .children(self.error.clone().map(|e| div().px_5().py_2().text_sm().text_color(rgb(C::RED)).bg(alpha(C::RED, 0.08)).child(e)))
            .child(
                div()
                    .id("tp-body")
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
                            .content_start()
                            .gap_4()
                            .child(
                                panel()
                                    .w(px(520.))
                                    .child(section_title("Server (this machine)"))
                                    .child(row().child(label("Port")).child(self.srv_port.clone()).child(if self.server.is_some() {
                                        button("srv", "■ Stop server", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, cx| t.toggle_server(cx)))
                                    } else {
                                        button_primary("srv", "▶ Start server", act(&view, |t: &mut Self, _, cx| t.toggle_server(cx)))
                                    }))
                                    .child(label("Also answers UDP echo for the Latency / Jitter / Loss tools. Allow the port in the firewall."))
                                    .children(self.server_log.iter().rev().take(8).map(|l| div().text_xs().child(l.clone()))),
                            )
                            .child(
                                panel()
                                    .w(px(620.))
                                    .child(section_title("Client"))
                                    .child(row().child(label("Server")).child(self.host.clone()).child(label("Port")).child(self.port.clone()))
                                    .child(
                                        row()
                                            .child(chip("tp-down", "Download", self.mode == Mode::Download, act(&view, |t: &mut Self, _, _| t.mode = Mode::Download)))
                                            .child(chip("tp-up", "Upload", self.mode == Mode::Upload, act(&view, |t: &mut Self, _, _| t.mode = Mode::Upload)))
                                            .child(label("Seconds"))
                                            .child(self.secs.clone())
                                            .child(label("Streams"))
                                            .child(self.streams.clone())
                                            .child(if busy {
                                                button("tp-go", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| {
                                                    if let Some(c) = &t.client {
                                                        c.stop();
                                                    }
                                                }))
                                            } else {
                                                button_primary("tp-go", "▶ Run test", act(&view, |t: &mut Self, _, cx| t.run_client(cx)))
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        panel()
                            .child(section_title("Internet download test (HTTP / HTTPS)"))
                            .child(row().child(self.url.clone()).child(
                                button2("tp-http", "▶ Download test", act(&view, |t: &mut Self, _, cx| t.run_http(cx)))
                                    .tooltip(tip("Downloads from this URL for the chosen number of seconds. The host is contacted only when you press the button; the URL is saved.")),
                            ))
                            .child(label("Default: Cloudflare's speed-test endpoint. Any large file URL works (no redirects).")),
                    )
                    .child(
                        panel()
                            .child(section_title(if self.label.is_empty() { "Result" } else { &self.label }))
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .child(tile("Last second", vals.last().map(|v| mbit(*v as f64 * 1e6)).unwrap_or_else(|| "—".into()), C::GREEN))
                                    .child(tile("Average", if vals.is_empty() { "—".into() } else { mbit(avg as f64 * 1e6) }, C::TEXT))
                                    .child(tile("Peak", if vals.is_empty() { "—".into() } else { mbit(peak as f64 * 1e6) }, C::MUTED)),
                            )
                            .child(bar_chart_slots(&self.seconds, 30, 900.0, 120.0, 0.0, C::GREEN))
                            .children(self.result.clone().map(|r| div().flex().items_center().gap_2().text_sm().child(r.clone()).child(copy_button("tp-copy", r)))),
                    ),
            )
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}

// ---------------------------------------------------------------- wi-fi

pub struct WifiView {
    focus: FocusHandle,
    nets: Result<Vec<Network>, String>,
    rx: Option<Receiver<Result<Vec<Network>, String>>>,
    auto: bool,
    last: Option<Instant>,
    _poll: Option<Task<()>>,
}

impl WifiView {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut v = Self {
            focus: cx.focus_handle(),
            nets: Ok(Vec::new()),
            rx: None,
            auto: false,
            last: None,
            _poll: None,
        };
        v.scan(false, cx);
        v
    }

    fn scan(&mut self, rescan: bool, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(wifi::scan(rescan));
        });
        self.rx = Some(rx);
        self._poll = Some(poll(cx, 200, |t: &mut Self, cx| {
            if let Some(rx) = &t.rx {
                match rx.try_recv() {
                    Ok(r) => {
                        let mut r = r;
                        if let Ok(v) = r.as_mut() {
                            v.sort_by_key(|n| {
                                (!n.in_use, std::cmp::Reverse(n.signal.unwrap_or(0)))
                            });
                        }
                        t.nets = r;
                        t.rx = None;
                        t.last = Some(Instant::now());
                        cx.notify();
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(_) => t.rx = None,
                }
            }
            if t.auto
                && t.rx.is_none()
                && t.last
                    .is_some_and(|l| l.elapsed() > Duration::from_secs(10))
            {
                let (tx, rx) = channel();
                std::thread::spawn(move || {
                    let _ = tx.send(wifi::scan(true));
                });
                t.rx = Some(rx);
            }
            t.rx.is_some() || t.auto
        }));
    }

    fn channel_bars(nets: &[Network], channels: &[u32]) -> impl IntoElement {
        let max = channels
            .iter()
            .map(|c| wifi::congestion(nets, *c))
            .max()
            .unwrap_or(1)
            .max(1);
        div()
            .flex()
            .items_end()
            .gap_1()
            .h(px(110.))
            .children(channels.iter().map(|&c| {
                let v = wifi::congestion(nets, c);
                let own = nets.iter().filter(|n| n.channel == c).count();
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_1()
                    .child(div().text_xs().text_color(rgb(C::MUTED)).child(if own > 0 {
                        own.to_string()
                    } else {
                        String::new()
                    }))
                    .child(
                        div()
                            .w(px(22.))
                            .h(px(4.0 + 70.0 * v as f32 / max as f32))
                            .rounded_sm()
                            .bg(rgb(if v * 3 > max * 2 {
                                C::RED
                            } else if v * 3 > max {
                                C::AMBER
                            } else {
                                C::GREEN
                            })),
                    )
                    .child(div().text_xs().child(c.to_string()))
            }))
    }
}

impl Focusable for WifiView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for WifiView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.rx.is_some();
        let body = match &self.nets {
            Err(e) => div()
                .p_5()
                .text_color(rgb(C::RED))
                .child(e.clone())
                .into_any_element(),
            Ok(nets) if nets.is_empty() => empty_state(
                if busy { "Scanning…" } else { "No networks" },
                "Is Wi-Fi switched on?",
            )
            .into_any_element(),
            Ok(nets) => {
                let current = nets.iter().find(|n| n.in_use);
                let (b24, b5) = wifi::recommend(nets);
                let ch5: Vec<u32> = {
                    let mut v: Vec<u32> = nets
                        .iter()
                        .filter(|n| n.channel > 14)
                        .map(|n| n.channel)
                        .collect();
                    v.extend([36, 40, 44, 48, 149, 153, 157, 161]);
                    v.sort();
                    v.dedup();
                    v
                };
                div()
                    .id("wifi-body")
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
                            .content_start()
                            .gap_3()
                            .when_some(current, |d, c| {
                                d.child(tile("Connected to", c.ssid.clone(), C::TEXT))
                                    .child(tile("Signal", c.signal.map(|s| format!("{s}%")).unwrap_or_else(|| "—".into()), if c.signal.unwrap_or(0) >= 60 { C::GREEN } else { C::AMBER }))
                                    .child(tile("Channel", format!("{} ({})", c.channel, wifi::band(c.channel, c.freq_mhz)), C::TEXT))
                                    .child(tile("Link rate", c.rate.clone().unwrap_or_else(|| "—".into()), C::MUTED))
                                    .child(tile("Same-channel networks", nets.iter().filter(|n| n.channel == c.channel && !n.in_use).count().to_string(), C::MUTED))
                            })
                            .child(tile("Networks", nets.len().to_string(), C::MUTED)),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .content_start()
                            .gap_6()
                            .child(div().flex().flex_col().gap_2().child(section_title("2.4 GHz congestion (overlap-weighted)")).child(Self::channel_bars(nets, &(1..=13).collect::<Vec<_>>())))
                            .child(div().flex().flex_col().gap_2().child(section_title("5 GHz congestion")).child(Self::channel_bars(nets, &ch5)))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .text_sm()
                                    .child(section_title("Recommendation"))
                                    .child(format!("2.4 GHz: use channel {b24} (only 1, 6 and 11 don't overlap)"))
                                    .child(format!("5 GHz: channel {b5} is least used (non-DFS)")),
                            ),
                    )
                    .child(table_header(&[("", 20.), ("SSID", 230.), ("BSSID", 160.), ("VENDOR", 180.), ("BAND", 80.), ("CH", 50.), ("SIGNAL", 140.), ("SECURITY", 0.)]))
                    .children(nets.iter().enumerate().map(|(i, n)| {
                        let sig = n.signal.unwrap_or(0) as f32 / 100.0;
                        let weak_sec = n.security == "Open" || n.security.contains("WEP") || (n.security.contains("WPA1") || n.security == "WPA");
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(28.))
                            .text_sm()
                            .bg(if n.in_use { alpha(C::GREEN, 0.10) } else { rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }).into() })
                            .child(cell(20., if n.in_use { "●" } else { "" }).text_color(rgb(C::GREEN)))
                            .child(cell(230., if n.ssid.is_empty() { "(hidden)".to_string() } else { n.ssid.clone() }))
                            .child(cell(160., n.bssid.clone().unwrap_or_default()).text_color(rgb(C::MUTED)))
                            .child(cell(180., n.bssid.as_deref().and_then(crate::netinfo::mac_vendor).unwrap_or_default()).text_color(rgb(C::MUTED)))
                            .child(cell(80., wifi::band(n.channel, n.freq_mhz)))
                            .child(cell(50., n.channel.to_string()))
                            .child(
                                div()
                                    .w(px(140.))
                                    .flex_none()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().w(px(70.)).h(px(6.)).rounded_full().bg(rgb(C::PANEL2)).child(div().h_full().rounded_full().w(px(70.0 * sig)).bg(rgb(if sig >= 0.6 { C::GREEN } else if sig >= 0.35 { C::AMBER } else { C::RED }))))
                                    .child(label(n.signal.map(|s| format!("{s}%")).unwrap_or_default())),
                            )
                            .child(cell(0., if weak_sec { format!("{} ⚠ weak", n.security) } else { n.security.clone() }).text_color(rgb(if weak_sec { C::AMBER } else { C::TEXT })))
                    }))
                    .into_any_element()
            }
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(button_primary("wifi-scan", if busy { "Scanning…" } else { "⟲ Rescan" }, act(&view, |t: &mut Self, _, cx| t.scan(true, cx))))
                    .child(chip("wifi-auto", "Auto-refresh (10 s)", self.auto, act(&view, |t: &mut Self, _, cx| {
                        t.auto = !t.auto;
                        if t.auto {
                            t.scan(true, cx);
                        }
                    })))
                    .child(div().text_xs().text_color(rgb(C::MUTED)).child("Linux: NetworkManager (nmcli) · macOS: system_profiler (no BSSIDs) · Windows: netsh (needs Location access)")),
            )
            .child(body)
    }
}
