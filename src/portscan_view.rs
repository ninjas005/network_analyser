//! Port Scan tab: TCP connect scan of domain names, IPs and ranges.

use std::ops::Range;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, UniformListScrollHandle,
    Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::portscan::{
    self, OpenPort, PortScanConfig, PortScanEvent, PortScanHandle, Preset, Target,
};
use crate::widgets::{
    Accept, C, TextInput, act, button, button_primary, button2, cell, chip, empty_state, input,
    label, progress, status_bar, table_header, toolbar,
};

const COLS: [(&str, f32); 6] = [
    ("TARGET", 220.),
    ("ADDRESS", 200.),
    ("PORT", 100.),
    ("SERVICE", 110.),
    ("CONNECT", 90.),
    ("BANNER / TITLE", 0.),
];

pub struct PortScanView {
    focus: FocusHandle,
    targets: Entity<TextInput>,
    ports: Entity<TextInput>,
    timeout: Entity<TextInput>,
    banners: bool,
    resolved: Vec<Target>,
    open: Vec<OpenPort>,
    scan: Option<PortScanHandle>,
    started: Option<Instant>,
    elapsed: Option<Duration>,
    progress: (usize, usize, usize, usize),
    status: SharedString,
    error: Option<String>,
    scroll: UniformListScrollHandle,
    _poll: Option<Task<()>>,
}

impl PortScanView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let targets = input(
            window,
            cx,
            "",
            "example.com, 192.168.1.10, 10.0.0.0/28, 2001:db8::1",
            Accept::Any,
            |t| t.width(320.).max_len(2000),
            |this: &mut Self, _, cx| this.start(cx),
        );
        let ports = input(
            window,
            cx,
            "top",
            "top, 1-1024, 22,80,443",
            Accept::Ports,
            |t| t.width(170.),
            |this: &mut Self, _, cx| this.start(cx),
        );
        let timeout = input(
            window,
            cx,
            "1000",
            "ms",
            Accept::Digits,
            |t| t.width(70.).max_len(5),
            |this: &mut Self, _, cx| this.start(cx),
        );
        Self {
            focus: cx.focus_handle(),
            targets,
            ports,
            timeout,
            banners: true,
            resolved: Vec::new(),
            open: Vec::new(),
            scan: None,
            started: None,
            elapsed: None,
            progress: (0, 0, 0, 0),
            status: "Enter a domain name, IP address or range and press Scan.".into(),
            error: None,
            scroll: UniformListScrollHandle::new(),
            _poll: None,
        }
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        if self.scan.is_some() {
            return;
        }
        let targets = self.targets.read(cx).value.trim().to_string();
        if targets.is_empty() {
            self.targets.update(cx, |t, cx| {
                t.error = true;
                cx.notify()
            });
            self.error = Some("Enter at least one target".into());
            return;
        }
        let ports = match portscan::parse_ports(&self.ports.read(cx).value) {
            Ok(p) => p,
            Err(e) => {
                self.ports.update(cx, |t, cx| {
                    t.error = true;
                    cx.notify()
                });
                self.error = Some(e);
                return;
            }
        };
        let ms: u64 = self
            .timeout
            .read(cx)
            .value
            .parse()
            .unwrap_or(1000)
            .clamp(50, 30_000);
        self.error = None;
        self.open.clear();
        self.resolved.clear();
        self.progress = (0, 0, 0, 0);
        let n = ports.len();
        self.scan = Some(portscan::start(PortScanConfig {
            targets,
            ports,
            timeout: Duration::from_millis(ms),
            // Fewer parallel connects for slow timeouts on remote hosts.
            concurrency: if ms > 2000 { 256 } else { 512 },
            banners: self.banners,
        }));
        self.started = Some(Instant::now());
        self.elapsed = None;
        self.status = format!("Resolving and scanning {n} ports…").into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
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
        if let Some(s) = &self.scan {
            s.cancel();
            self.status = "Stopping…".into();
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(scan) = &self.scan else { return false };
        let mut finished = None;
        while let Ok(ev) = scan.events.try_recv() {
            match ev {
                PortScanEvent::Resolved(t) => self.resolved = t,
                PortScanEvent::Open(p) => {
                    let pos = self
                        .open
                        .partition_point(|o| (o.target, o.port) < (p.target, p.port));
                    self.open.insert(pos, p);
                }
                PortScanEvent::Banner {
                    target,
                    port,
                    banner,
                } => {
                    if let Some(p) = self
                        .open
                        .iter_mut()
                        .find(|p| p.target == target && p.port == port)
                    {
                        p.banner = banner.text;
                        p.http_title = banner.http_title;
                        p.http_server = banner.http_server;
                    }
                }
                PortScanEvent::Progress {
                    done,
                    total,
                    closed,
                    filtered,
                } => self.progress = (done, total, closed, filtered),
                PortScanEvent::Error(e) => self.error = Some(e),
                PortScanEvent::Finished { elapsed, cancelled } => {
                    finished = Some((elapsed, cancelled))
                }
            }
        }
        if let Some((elapsed, cancelled)) = finished {
            self.scan = None;
            self.started = None;
            self.elapsed = Some(elapsed);
            self.status = if let Some(e) = &self.error {
                format!("Scan failed: {e}").into()
            } else {
                format!(
                    "{} — {} open ports on {} address{} in {:.1}s",
                    if cancelled {
                        "Scan stopped"
                    } else {
                        "Scan complete"
                    },
                    self.open.len(),
                    self.resolved.len(),
                    if self.resolved.len() == 1 { "" } else { "es" },
                    elapsed.as_secs_f32()
                )
                .into()
            };
        }
        cx.notify();
        finished.is_none()
    }

    fn export(&mut self) {
        let dir = crate::platform::home_dir().unwrap_or_else(|| ".".into());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = dir.join(format!("port-scan-{ts}.csv"));
        let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let mut out =
            String::from("target,address,port,service,connect_ms,banner,http_title,http_server\n");
        for p in &self.open {
            let t = &self.resolved[p.target];
            out.push_str(&format!(
                "{},{},{},{},{:.1},{},{},{}\n",
                q(&t.name),
                t.ip,
                p.port,
                p.service,
                p.connect_ms,
                q(p.banner.as_deref().unwrap_or("")),
                q(p.http_title.as_deref().unwrap_or("")),
                q(p.http_server.as_deref().unwrap_or(""))
            ));
        }
        self.status = match std::fs::write(&path, out) {
            Ok(()) => format!("Exported to {}", path.display()).into(),
            Err(e) => format!("Export failed: {e}").into(),
        };
    }

    fn render_row(&self, i: usize) -> gpui::AnyElement {
        let p = &self.open[i];
        let t = &self.resolved[p.target];
        let new_target = i == 0 || self.open[i - 1].target != p.target;
        let detail = [
            p.http_title.clone().map(|t| format!("“{t}”")),
            p.banner.clone(),
            p.http_server.clone(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("  ·  ");
        div()
            .id(("open", i))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .h(px(30.))
            .px_3()
            .text_sm()
            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
            .when(new_target && i > 0, |d| {
                d.border_t_1().border_color(rgb(C::BORDER))
            })
            .child(cell(
                COLS[0].1,
                if new_target {
                    t.name.clone()
                } else {
                    String::new()
                },
            ))
            .child(
                cell(
                    COLS[1].1,
                    if new_target {
                        t.ip.to_string()
                    } else {
                        String::new()
                    },
                )
                .text_color(rgb(C::MUTED)),
            )
            .child(cell(COLS[2].1, format!("{}/tcp", p.port)).text_color(rgb(C::GREEN)))
            .child(cell(
                COLS[3].1,
                if p.service.is_empty() {
                    "unknown"
                } else {
                    p.service
                },
            ))
            .child(cell(COLS[4].1, format!("{:.0} ms", p.connect_ms)).text_color(rgb(C::MUTED)))
            .child(
                cell(
                    0.,
                    if detail.is_empty() {
                        "—".to_string()
                    } else {
                        detail
                    },
                )
                .text_color(rgb(C::MUTED)),
            )
            .into_any_element()
    }
}

impl Focusable for PortScanView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for PortScanView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let scanning = self.scan.is_some();
        let presets = Preset::ALL.iter().enumerate().map(|(i, &p)| {
            let spec = p.spec();
            let active = self.ports.read(cx).value == spec;
            let ports = self.ports.clone();
            chip(("preset", i), p.label(), active, move |_, _, cx| {
                ports.update(cx, |t, cx| t.set(spec.clone(), cx));
            })
        });
        let bar = toolbar()
            .child(label("Targets"))
            .child(self.targets.clone())
            .child(label("Ports"))
            .child(self.ports.clone())
            .child(div().flex().gap_1().children(presets))
            .child(label("Timeout ms"))
            .child(self.timeout.clone())
            .child(chip(
                "banners",
                "Grab banners",
                self.banners,
                act(&view, |t: &mut Self, _, _| t.banners = !t.banners),
            ))
            .child(if scanning {
                button(
                    "ps-start",
                    "■ Stop",
                    C::AMBER,
                    C::AMBER,
                    act(&view, |t: &mut Self, _, _| t.stop()),
                )
            } else {
                button_primary(
                    "ps-start",
                    "▶ Scan",
                    act(&view, |t: &mut Self, _, cx| t.start(cx)),
                )
            })
            .child(button2(
                "ps-export",
                "Export CSV",
                act(&view, |t: &mut Self, _, _| t.export()),
            ));

        let resolved = (!self.resolved.is_empty()).then(|| {
            let mut names: Vec<String> = Vec::new();
            for t in self.resolved.iter().take(8) {
                if t.name == t.ip.to_string() {
                    names.push(t.name.clone());
                } else {
                    names.push(format!("{} → {}", t.name, t.ip));
                }
            }
            if self.resolved.len() > 8 {
                names.push(format!("… {} more", self.resolved.len() - 8));
            }
            div()
                .px_5()
                .py_2()
                .text_xs()
                .text_color(rgb(C::MUTED))
                .border_b_1()
                .border_color(rgb(C::BORDER))
                .child(format!("Targets: {}", names.join("   ")))
        });

        let body = if self.open.is_empty() {
            let (title, hint) = if scanning {
                (
                    "Scanning…",
                    "Open ports will appear here as they are found.",
                )
            } else if self.elapsed.is_some() {
                (
                    "No open ports found",
                    "All probed ports were closed or filtered. Try a longer timeout or more ports.",
                )
            } else {
                (
                    "No scan yet",
                    "Only scan hosts you own or are authorised to test.",
                )
            };
            empty_state(title, hint).into_any_element()
        } else {
            uniform_list(
                "open-ports",
                self.open.len(),
                cx.processor(|this, range: Range<usize>, _, _| {
                    range.map(|i| this.render_row(i)).collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };

        let (done, total, closed, filtered) = self.progress;
        let elapsed = self.started.map(|s| s.elapsed()).or(self.elapsed);
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(bar)
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .child(e)
            }))
            .children(resolved)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .child(table_header(&COLS))
                    .child(body),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .when(total > 0, |d| {
                        d.child(progress(done as f32 / total as f32, 180.))
                            .child(format!("{done}/{total} probed"))
                            .child(
                                div()
                                    .text_color(rgb(C::GREEN))
                                    .child(format!("{} open", self.open.len())),
                            )
                            .child(format!("{closed} closed"))
                            .child(format!("{filtered} filtered"))
                    })
                    .children(elapsed.map(|e| format!("{:.1}s", e.as_secs_f32()))),
            )
    }
}
