//! LAN scan tab: toolbar, host table, detail panel, status bar.

use std::ops::Range;
use std::time::{Duration, Instant};

use gpui::{
    App, ClickEvent, Context, FocusHandle, Focusable, Hsla, KeyDownEvent, SharedString, Task,
    UniformListScrollHandle, Window, actions, div, prelude::*, px, rgb, uniform_list,
};

use crate::netinfo::{self, LocalIface};
use crate::scanner::{self, HostInfo, ScanConfig, ScanEvent, ScanHandle, Status};
use crate::widgets::{C, Tip, cell, section_title};

actions!(
    network_analyser,
    [StartStop, ToggleFilter, Export, FocusSearch, ClearSearch]
);

#[derive(Clone, Copy, PartialEq)]
enum Filter {
    Alive,
    All,
}

pub struct ScannerView {
    focus: FocusHandle,
    input_focus: FocusHandle,
    search_focus: FocusHandle,
    search: String,
    kiosk: bool,
    range_input: String,
    range_error: Option<String>,
    iface: Option<LocalIface>,
    hosts: Vec<HostInfo>,
    visible: Vec<usize>,
    selected: Option<usize>,
    filter: Filter,
    /// (column index, descending). None = natural IP order.
    sort: Option<(usize, bool)>,
    scan: Option<ScanHandle>,
    scan_started: Option<Instant>,
    last_elapsed: Option<Duration>,
    status_msg: SharedString,
    intercepted: Vec<u16>,
    list_scroll: UniformListScrollHandle,
    _poll: Option<Task<()>>,
}

impl ScannerView {
    pub fn new(kiosk: bool, cx: &mut Context<Self>) -> Self {
        let iface = netinfo::local_interfaces().into_iter().next();
        let range_input = iface
            .as_ref()
            .map(|i| i.cidr())
            .unwrap_or_else(|| "192.168.1.0/24".into());
        let status_msg = match &iface {
            Some(i) => format!("Interface {} — {} / {}", i.name, i.ip, i.prefix),
            None => "No IPv4 interface detected".into(),
        };
        Self {
            focus: cx.focus_handle(),
            input_focus: cx.focus_handle(),
            search_focus: cx.focus_handle(),
            search: String::new(),
            kiosk,
            range_input,
            range_error: None,
            iface,
            hosts: Vec::new(),
            visible: Vec::new(),
            selected: None,
            filter: Filter::Alive,
            sort: None,
            scan: None,
            scan_started: None,
            last_elapsed: None,
            status_msg: status_msg.into(),
            intercepted: Vec::new(),
            list_scroll: UniformListScrollHandle::new(),
            _poll: None,
        }
    }

    fn scanning(&self) -> bool {
        self.scan.is_some()
    }

    // ------------------------------------------------------------ actions

    fn start_stop(&mut self, _: &StartStop, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(scan) = &self.scan {
            scan.cancel();
            self.status_msg = "Stopping…".into();
        } else {
            self.start_scan(cx);
        }
        cx.notify();
    }

    pub fn start_scan(&mut self, cx: &mut Context<Self>) {
        let targets = match netinfo::parse_range(&self.range_input) {
            Ok(t) => t,
            Err(e) => {
                self.range_error = Some(e);
                cx.notify();
                return;
            }
        };
        self.range_error = None;
        self.hosts = targets.iter().map(|ip| HostInfo::new(*ip)).collect();
        self.selected = None;
        self.intercepted.clear();
        self.recompute_visible();
        let local = netinfo::local_interfaces();
        let iface = local
            .iter()
            .find(|i| targets.contains(&i.ip))
            .cloned()
            .or(self.iface.clone());
        let n = targets.len();
        self.scan = Some(scanner::start(ScanConfig {
            targets,
            ports: netinfo::DEFAULT_PORTS.to_vec(),
            host_concurrency: 64,
            connect_timeout: Duration::from_millis(700),
            local: iface,
        }));
        self.scan_started = Some(Instant::now());
        self.last_elapsed = None;
        self.status_msg = format!("Scanning {n} addresses…").into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                match this.update(cx, |this, cx| this.drain_events(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    /// Pull scanner events into view state. Returns false once the scan ended.
    fn drain_events(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(scan) = &self.scan else { return false };
        let mut changed = false;
        let mut finished = None;
        while let Ok(ev) = scan.events.try_recv() {
            changed = true;
            match ev {
                ScanEvent::Host(idx, info) => {
                    if let Some(slot) = self.hosts.get_mut(idx) {
                        *slot = *info;
                    }
                }
                ScanEvent::Intercepted(ports) => self.intercepted = ports,
                ScanEvent::Finished { elapsed, cancelled } => finished = Some((elapsed, cancelled)),
            }
        }
        if let Some((elapsed, cancelled)) = finished {
            self.scan = None;
            self.scan_started = None;
            self.last_elapsed = Some(elapsed);
            let alive = self.hosts.iter().filter(|h| h.is_alive()).count();
            self.status_msg = format!(
                "{} — {alive} live hosts of {} in {:.1}s",
                if cancelled {
                    "Scan stopped"
                } else {
                    "Scan complete"
                },
                self.hosts.len(),
                elapsed.as_secs_f32()
            )
            .into();
        }
        if changed {
            self.recompute_visible();
        }
        // Keep repainting while scanning so the timer/progress tick.
        cx.notify();
        finished.is_none()
    }

    fn recompute_visible(&mut self) {
        self.visible = self
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| self.filter == Filter::All || h.is_alive())
            .filter(|(_, h)| matches_search(h, &self.search))
            .map(|(i, _)| i)
            .collect();
        if let Some((col, desc)) = self.sort {
            let hosts = &self.hosts;
            // Stable sort: ties keep IP order. Missing values always sink.
            self.visible.sort_by(|&a, &b| {
                match (sort_value(&hosts[a], col), sort_value(&hosts[b], col)) {
                    (Some(x), Some(y)) => {
                        let o = x.cmp(&y);
                        if desc { o.reverse() } else { o }
                    }
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            });
        }
    }

    /// Header click: ascending -> descending -> back to IP order.
    fn toggle_sort(&mut self, col: usize, cx: &mut Context<Self>) {
        self.sort = match self.sort {
            Some((c, false)) if c == col => Some((col, true)),
            Some((c, true)) if c == col => None,
            _ => Some((col, false)),
        };
        self.recompute_visible();
        cx.notify();
    }

    fn toggle_filter(&mut self, _: &ToggleFilter, _: &mut Window, cx: &mut Context<Self>) {
        self.filter = if self.filter == Filter::Alive {
            Filter::All
        } else {
            Filter::Alive
        };
        self.recompute_visible();
        cx.notify();
    }

    /// Live hosts with a known MAC from the last scan: (ip, mac, name).
    pub fn known_macs(&self) -> Vec<(std::net::Ipv4Addr, String, Option<String>)> {
        self.hosts
            .iter()
            .filter_map(|h| Some((h.ip, h.mac.clone()?, h.hostname())))
            .collect()
    }

    /// Stop any running scan (app is quitting).
    pub fn cancel(&self) {
        if let Some(s) = &self.scan {
            s.cancel();
        }
    }

    fn export(&mut self, _: &Export, _: &mut Window, cx: &mut Context<Self>) {
        self.status_msg = match self.export_csv() {
            Ok(path) => format!("Exported to {path}").into(),
            Err(e) => format!("Export failed: {e}").into(),
        };
        cx.notify();
    }

    fn export_csv(&self) -> std::io::Result<String> {
        let dir = crate::platform::home_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".into());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = std::path::Path::new(&dir).join(format!("network-scan-{ts}.csv"));
        let path = path.to_string_lossy().into_owned();
        let q = |s: Option<&str>| format!("\"{}\"", s.unwrap_or("").replace('"', "\"\""));
        let mut out = String::from(
            "ip,status,ping_ms,ttl,hostname,dns,mdns,netbios,workgroup,mac,vendor,device,os,open_ports,http_title,http_server,upnp_name,upnp_model,mdns_friendly,mdns_model,mdns_services\n",
        );
        for h in self.hosts.iter().filter(|h| h.is_alive()) {
            let nb = h.netbios.as_ref();
            let up = h.upnp.as_ref();
            out.push_str(
                &[
                    h.ip.to_string(),
                    "alive".into(),
                    h.rtt_ms.map(|r| format!("{r:.1}")).unwrap_or_default(),
                    h.ttl.map(|t| t.to_string()).unwrap_or_default(),
                    q(h.hostname().as_deref()),
                    q(h.dns_name.as_deref()),
                    q(h.mdns_name.as_deref()),
                    q(nb.and_then(|n| n.name.as_deref())),
                    q(nb.and_then(|n| n.group.as_deref())),
                    q(h.mac.as_deref()),
                    q(h.vendor.as_deref()),
                    q(h.device_type.as_deref()),
                    q(h.os_guess.as_deref()),
                    q(Some(&h.ports_summary())),
                    q(h.http_title.as_deref()),
                    q(h.http_server.as_deref()),
                    q(up.and_then(|u| u.friendly_name.as_deref())),
                    q(up.and_then(|u| u.model.as_deref())),
                    q(h.mdns_friendly.as_deref()),
                    q(h.mdns_model.as_deref()),
                    q(Some(
                        &h.mdns_services
                            .iter()
                            .map(|s| s.label())
                            .collect::<Vec<_>>()
                            .join("; "),
                    )),
                ]
                .join(","),
            );
            out.push('\n');
        }
        std::fs::write(&path, out)?;
        Ok(path)
    }

    fn on_input_key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let ks = &ev.keystroke;
        if ks.modifiers.control || ks.modifiers.alt || ks.modifiers.platform {
            return;
        }
        match ks.key.as_str() {
            "backspace" => {
                self.range_input.pop();
            }
            "enter" => {
                if !self.scanning() {
                    self.start_scan(cx);
                }
            }
            _ => match ks.key_char.as_deref() {
                Some(c) if c.chars().all(|c| c.is_ascii_digit() || "./- ".contains(c)) => {
                    if self.range_input.len() < 40 {
                        self.range_input.push_str(c);
                    }
                }
                _ => return,
            },
        }
        self.range_error = None;
        cx.stop_propagation();
        cx.notify();
    }

    fn on_search_key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let ks = &ev.keystroke;
        if ks.modifiers.control || ks.modifiers.alt || ks.modifiers.platform {
            return;
        }
        match ks.key.as_str() {
            "backspace" => {
                self.search.pop();
            }
            "enter" | "tab" => return,
            _ => match ks.key_char.as_deref() {
                Some(c) if !c.chars().any(char::is_control) && self.search.len() < 60 => {
                    self.search.push_str(c)
                }
                _ => return,
            },
        }
        self.recompute_visible();
        cx.stop_propagation();
        cx.notify();
    }

    fn focus_search(&mut self, _: &FocusSearch, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.search_focus);
        cx.notify();
    }

    /// Esc inside the search box: clear it, or leave the box if already empty.
    fn clear_search(&mut self, _: &ClearSearch, window: &mut Window, cx: &mut Context<Self>) {
        if self.search.is_empty() {
            window.focus(&self.focus);
        } else {
            self.search.clear();
            self.recompute_visible();
        }
        cx.notify();
    }

    fn render_search(&self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.search_focus.is_focused(window);
        let empty = self.search.is_empty();
        div()
            .id("search")
            .key_context("SearchBox")
            .track_focus(&self.search_focus)
            .on_key_down(cx.listener(Self::on_search_key))
            .on_action(cx.listener(Self::clear_search))
            .on_click(cx.listener(|this, _, window, _| window.focus(&this.search_focus)))
            .w(px(280.))
            .h(px(34.))
            .px_3()
            .flex()
            .items_center()
            .gap_2()
            .rounded_md()
            .bg(rgb(C::BG))
            .border_1()
            .border_color(rgb(if focused { C::ACCENT } else { C::BORDER }))
            .cursor_text()
            .text_sm()
            .child(div().text_color(rgb(C::MUTED)).child("⌕"))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .items_center()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .when(empty && !focused, |d| {
                        d.text_color(rgb(C::MUTED))
                            .child(if cfg!(target_os = "macos") {
                                "Search hosts (⌘F)"
                            } else {
                                "Search hosts (Ctrl+F)"
                            })
                    })
                    .when(!empty, |d| {
                        d.text_color(rgb(C::TEXT)).child(self.search.clone())
                    })
                    .when(focused, |d| {
                        d.child(div().w(px(1.5)).h(px(16.)).ml(px(1.)).bg(rgb(C::ACCENT)))
                    }),
            )
            .when(!empty, |d| {
                d.child(
                    div()
                        .id("search-clear")
                        .px_1()
                        .rounded_sm()
                        .cursor_pointer()
                        .text_color(rgb(C::MUTED))
                        .hover(|s| s.text_color(rgb(C::TEXT)).bg(rgb(C::PANEL2)))
                        .child("✕")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.search.clear();
                            this.recompute_visible();
                            cx.stop_propagation();
                            cx.notify();
                        })),
                )
            })
    }

    // ------------------------------------------------------------ render helpers

    fn render_toolbar(&self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.input_focus.is_focused(window);
        let scanning = self.scanning();
        let view = cx.entity().downgrade();
        let act = move |f: fn(&mut Self, &mut Window, &mut Context<Self>)| {
            let view = view.clone();
            move |_: &ClickEvent, window: &mut Window, cx: &mut App| {
                view.update(cx, |this, cx| f(this, window, cx)).ok();
            }
        };

        let input = div()
            .id("range-input")
            .track_focus(&self.input_focus)
            .on_key_down(cx.listener(Self::on_input_key))
            .on_click(cx.listener(|this, _, window, _| window.focus(&this.input_focus)))
            .w(px(260.))
            .h(px(34.))
            .px_3()
            .flex()
            .items_center()
            .rounded_md()
            .bg(rgb(C::BG))
            .border_1()
            .border_color(rgb(if self.range_error.is_some() {
                C::RED
            } else if focused {
                C::ACCENT
            } else {
                C::BORDER
            }))
            .cursor_text()
            .text_sm()
            .text_color(rgb(C::TEXT))
            .child(self.range_input.clone())
            .when(focused, |d| {
                d.child(div().w(px(1.5)).h(px(16.)).ml(px(1.)).bg(rgb(C::ACCENT)))
            });

        let iface_btn = self.iface.as_ref().map(|i| {
            let cidr = i.cidr();
            let label = format!("⟲ {}", i.name);
            crate::widgets::button("iface", label, C::PANEL2, C::BORDER, {
                let view = cx.entity().downgrade();
                move |_, _, cx| {
                    let cidr = cidr.clone();
                    view.update(cx, |this, cx| {
                        this.range_input = cidr;
                        this.range_error = None;
                        cx.notify();
                    })
                    .ok();
                }
            })
        });

        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_3()
            .px_5()
            .h(px(60.))
            .bg(rgb(C::PANEL))
            .border_b_1()
            .border_color(rgb(C::BORDER))
            .child(div().text_sm().text_color(rgb(C::MUTED)).child("Range"))
            .child(input)
            .children(iface_btn)
            .child(if scanning {
                crate::widgets::button(
                    "start",
                    "■ Stop",
                    C::AMBER,
                    C::AMBER,
                    act(|t, w, cx| t.start_stop(&StartStop, w, cx)),
                )
                .into_any_element()
            } else {
                crate::widgets::button(
                    "start",
                    "▶ Scan",
                    C::ACCENT,
                    C::ACCENT_HOVER,
                    act(|t, w, cx| t.start_stop(&StartStop, w, cx)),
                )
                .into_any_element()
            })
            .children(
                self.range_error
                    .clone()
                    .map(|e| div().text_sm().text_color(rgb(C::RED)).child(e)),
            )
            .child(div().flex_1())
            .child(self.render_search(window, cx))
            .child(crate::widgets::button(
                "filter",
                if self.filter == Filter::Alive {
                    "Showing: live hosts"
                } else {
                    "Showing: all addresses"
                },
                C::PANEL2,
                C::BORDER,
                act(|t, w, cx| t.toggle_filter(&ToggleFilter, w, cx)),
            ))
            .child(crate::widgets::button(
                "export",
                "Export CSV",
                C::PANEL2,
                C::BORDER,
                act(|t, w, cx| t.export(&Export, w, cx)),
            ))
    }

    fn render_table(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let header = div()
            .flex()
            .flex_row()
            .items_center()
            .h(px(34.))
            .px_3()
            .bg(rgb(C::PANEL2))
            .border_b_1()
            .border_color(rgb(C::BORDER))
            .text_xs()
            .font_weight(gpui::FontWeight::SEMIBOLD)
            .text_color(rgb(C::MUTED))
            .children(COLUMNS.iter().enumerate().map(|(i, (name, w))| {
                let arrow = match self.sort {
                    Some((c, desc)) if c == i => {
                        if desc {
                            " ▼"
                        } else {
                            " ▲"
                        }
                    }
                    _ => "",
                };
                let active = !arrow.is_empty();
                cell(*w, format!("{name}{arrow}"))
                    .id(("hdr", i))
                    .h_full()
                    .flex()
                    .items_center()
                    .cursor_pointer()
                    .when(active, |d| d.text_color(rgb(C::ACCENT)))
                    .hover(|s| s.text_color(rgb(C::TEXT)))
                    .on_click(cx.listener(move |this, _, _, cx| this.toggle_sort(i, cx)))
            }));

        let body = if self.hosts.is_empty() {
            div()
                .flex_1()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap_2()
                .text_color(rgb(C::MUTED))
                .child(div().text_xl().child("No scan yet"))
                .child("Enter an IP range (CIDR, a.b.c.d-e or a single IP) and press Scan or F5.")
                .into_any_element()
        } else if self.visible.is_empty() {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_color(rgb(C::MUTED))
                .child(if !self.search.is_empty() {
                    "No hosts match the search."
                } else if self.scanning() {
                    "Probing… live hosts will appear here."
                } else {
                    "No live hosts found."
                })
                .into_any_element()
        } else {
            uniform_list(
                "hosts",
                self.visible.len(),
                cx.processor(|this, range: Range<usize>, _window, cx| {
                    range
                        .map(|vi| {
                            let idx = this.visible[vi];
                            this.render_row(vi, idx, cx)
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.list_scroll.clone())
            .flex_1()
            .into_any_element()
        };

        div()
            .flex()
            .flex_col()
            .flex_1()
            .h_full()
            .min_w_0()
            .child(header)
            .child(body)
    }

    fn render_row(&self, vi: usize, idx: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let h = &self.hosts[idx];
        let selected = self.selected == Some(idx);
        let (dot, _) = status_color(h.status);
        let muted = !h.is_alive();
        let text =
            |s: Option<String>| s.unwrap_or_else(|| if muted { String::new() } else { "—".into() });
        let mut ip = h.ip.to_string();
        if h.is_gateway {
            ip.push_str("  (gw)");
        } else if h.is_self {
            ip.push_str("  (you)");
        }
        let values: [String; 9] = [
            ip,
            text(h.rtt_ms.map(|r| format!("{r:.1} ms"))),
            text(h.ttl.map(|t| t.to_string())),
            text(h.hostname()),
            text(h.mac.clone()),
            text(h.vendor.clone()),
            text(h.device_type.clone()),
            text(h.os_guess.clone()),
            if h.ports.is_empty() {
                text(None)
            } else {
                h.ports_summary()
            },
        ];
        div()
            .id(("row", idx))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .h(px(32.))
            .px_3()
            .text_sm()
            .text_color(rgb(if muted { C::MUTED } else { C::TEXT }))
            .bg(rgb(if selected {
                C::SELECT
            } else if vi % 2 == 1 {
                C::ROW_ALT
            } else {
                C::BG
            }))
            .hover(|s| s.bg(rgb(C::PANEL2)))
            .cursor_pointer()
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected = if this.selected == Some(idx) {
                    None
                } else {
                    Some(idx)
                };
                cx.notify();
            }))
            .child(
                div()
                    .w(px(20.))
                    .flex_none()
                    .child(div().size(px(9.)).rounded_full().bg(dot)),
            )
            .children(
                COLUMNS[1..]
                    .iter()
                    .zip(values)
                    .map(|((_, w), v)| cell(*w, v)),
            )
            .into_any_element()
    }

    fn render_details(&self, idx: usize, cx: &mut Context<Self>) -> impl IntoElement {
        let h = &self.hosts[idx];
        let mut sections: Vec<(&str, Vec<(String, String)>)> = Vec::new();
        let kv = |pairs: &mut Vec<(String, String)>, k: &str, v: Option<String>| {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                pairs.push((k.to_string(), v));
            }
        };

        let mut general = Vec::new();
        kv(&mut general, "Status", Some(status_label(h.status).into()));
        kv(&mut general, "Detected via", Some(h.seen_by.join(", ")));
        kv(&mut general, "Ping", h.rtt_ms.map(|r| format!("{r:.2} ms")));
        kv(&mut general, "TTL", h.ttl.map(|t| t.to_string()));
        kv(&mut general, "Device type", h.device_type.clone());
        kv(&mut general, "OS guess", h.os_guess.clone());
        sections.push(("General", general));

        let mut names = Vec::new();
        kv(&mut names, "Reverse DNS", h.dns_name.clone());
        kv(&mut names, "mDNS", h.mdns_name.clone());
        kv(&mut names, "Bonjour name", h.mdns_friendly.clone());
        kv(&mut names, "Bonjour model", h.mdns_model.clone());
        if let Some(nb) = &h.netbios {
            kv(&mut names, "NetBIOS name", nb.name.clone());
            kv(&mut names, "Workgroup", nb.group.clone());
            kv(&mut names, "Logged-in user", nb.user.clone());
        }
        sections.push(("Names", names));

        let mut hw = Vec::new();
        kv(&mut hw, "MAC", h.mac.clone());
        kv(&mut hw, "Vendor", h.vendor.clone());
        sections.push(("Hardware", hw));

        let mut web = Vec::new();
        kv(&mut web, "HTTP title", h.http_title.clone());
        kv(&mut web, "HTTP server", h.http_server.clone());
        if let Some(u) = &h.upnp {
            kv(&mut web, "UPnP name", u.friendly_name.clone());
            kv(&mut web, "Manufacturer", u.manufacturer.clone());
            kv(&mut web, "Model", u.model.clone());
            kv(&mut web, "UPnP type", u.device_type.clone());
            kv(&mut web, "UPnP server", u.server.clone());
        }
        sections.push(("Web / UPnP", web));

        let bonjour = h
            .mdns_services
            .iter()
            .map(|s| {
                let k = crate::mdns::service_label(&s.kind).to_string();
                let v = if s.port == 0 {
                    format!("{} ({})", s.instance, s.kind)
                } else {
                    format!("{} ({}:{})", s.instance, s.kind, s.port)
                };
                (k, v)
            })
            .collect();
        sections.push(("Bonjour / mDNS services", bonjour));

        let ports =
            h.ports.iter().map(|p| {
                div()
                    .flex()
                    .flex_col()
                    .py_1()
                    .border_b_1()
                    .border_color(rgb(C::BORDER))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .w(px(60.))
                                    .text_color(rgb(C::GREEN))
                                    .child(format!("{}/tcp", p.port)),
                            )
                            .child(div().text_color(rgb(C::MUTED)).child(
                                if p.service.is_empty() {
                                    "unknown"
                                } else {
                                    p.service
                                },
                            )),
                    )
                    .children(
                        p.banner
                            .clone()
                            .map(|b| div().text_xs().text_color(rgb(C::MUTED)).child(b)),
                    )
            });

        div()
            .id("details")
            .w(px(380.))
            .flex_none()
            .h_full()
            .flex()
            .flex_col()
            .gap_4()
            .p_5()
            .bg(rgb(C::PANEL))
            .border_l_1()
            .border_color(rgb(C::BORDER))
            .overflow_y_scroll()
            .text_sm()
            .child(
                div()
                    .flex()
                    .items_start()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .text_xl()
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .child(h.ip.to_string()),
                            )
                            .child(
                                div()
                                    .text_color(rgb(C::MUTED))
                                    .child(h.hostname().unwrap_or_else(|| "unknown host".into())),
                            ),
                    )
                    .child(
                        div()
                            .id("close-details")
                            .px_2()
                            .rounded_md()
                            .cursor_pointer()
                            .text_color(rgb(C::MUTED))
                            .hover(|s| s.bg(rgb(C::PANEL2)))
                            .child("✕")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.selected = None;
                                cx.notify();
                            })),
                    ),
            )
            .children(
                sections
                    .into_iter()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(title, pairs)| {
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(section_title(title))
                            .children(pairs.into_iter().map(|(k, v)| {
                                div()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        div()
                                            .w(px(120.))
                                            .flex_none()
                                            .text_color(rgb(C::MUTED))
                                            .child(k),
                                    )
                                    .child(div().flex_1().min_w_0().child(v))
                            }))
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(section_title(&format!("Open ports ({})", h.ports.len())))
                    .children(ports)
                    .when(h.ports.is_empty(), |d| {
                        d.child(div().text_color(rgb(C::MUTED)).child(
                            if h.status == Status::Done {
                                "No open ports among the probed set"
                            } else {
                                "Scanning…"
                            },
                        ))
                    }),
            )
    }

    fn render_status_bar(&self) -> impl IntoElement {
        let total = self.hosts.len();
        let done = self
            .hosts
            .iter()
            .filter(|h| matches!(h.status, Status::Dead | Status::Done))
            .count();
        let alive = self.hosts.iter().filter(|h| h.is_alive()).count();
        let open: usize = self.hosts.iter().map(|h| h.ports.len()).sum();
        let frac = if total == 0 {
            0.0
        } else {
            done as f32 / total as f32
        };
        let elapsed = self.scan_started.map(|s| s.elapsed()).or(self.last_elapsed);
        let keys = if self.kiosk {
            if cfg!(target_os = "macos") {
                "F5 scan · ⌘F search · F6 filter · Esc / ⌘Q quit"
            } else {
                "F5 scan · Ctrl+F search · F6 filter · Esc / Ctrl+Q quit"
            }
        } else {
            if cfg!(target_os = "macos") {
                "F5 scan · ⌘F search · F6 filter · F11 fullscreen · Esc / ⌘Q quit"
            } else {
                "F5 scan · Ctrl+F search · F6 filter · F11 fullscreen · Esc / Ctrl+Q quit"
            }
        };
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_4()
            .px_5()
            .h(px(36.))
            .bg(rgb(C::PANEL))
            .border_t_1()
            .border_color(rgb(C::BORDER))
            .text_xs()
            .text_color(rgb(C::MUTED))
            .child(div().text_color(rgb(C::TEXT)).child(self.status_msg.clone()))
            .when(total > 0, |d| {
                d.child(
                    div()
                        .w(px(180.))
                        .h(px(6.))
                        .rounded_full()
                        .bg(rgb(C::PANEL2))
                        .child(div().h_full().rounded_full().bg(rgb(C::ACCENT)).w(px(180. * frac))),
                )
                .child(format!("{done}/{total} probed"))
                .child(div().text_color(rgb(C::GREEN)).child(format!("{alive} alive")))
                .child(format!("{open} open ports"))
            })
            .children(elapsed.map(|e| format!("{:.1}s", e.as_secs_f32())))
            .when(!self.intercepted.is_empty(), |d| {
                let list = self.intercepted.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
                d.child(
                    div()
                        .id("intercept-warning")
                        .text_color(rgb(C::AMBER))
                        .child(format!("⚠ TCP {list} intercepted by a local proxy — not verifiable, excluded"))
                        .tooltip(move |_, cx| {
                            cx.new(|_| Tip("A transparent proxy / security agent on this machine or network accepts connections on these ports for every address, so their real state on the target can't be determined.".into())).into()
                        }),
                )
            })
            .child(div().flex_1())
            .child(keys)
    }
}

const COLUMNS: [(&str, f32); 10] = [
    ("", 20.),
    ("IP ADDRESS", 170.),
    ("PING", 76.),
    ("TTL", 46.),
    ("HOSTNAME", 200.),
    ("MAC ADDRESS", 150.),
    ("VENDOR", 190.),
    ("DEVICE", 160.),
    ("OS GUESS", 190.),
    ("OPEN PORTS", 0.), // 0 = flexible
];

/// Case-insensitive match against everything shown for a host. Every
/// whitespace-separated term must match (e.g. "raspberry 22").
fn matches_search(h: &HostInfo, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    let mut hay = vec![h.ip.to_string()];
    hay.extend(
        [
            h.hostname(),
            h.dns_name.clone(),
            h.mdns_name.clone(),
            h.mdns_friendly.clone(),
            h.mdns_model.clone(),
            h.mac.clone(),
            h.vendor.clone(),
            h.device_type.clone(),
            h.os_guess.clone(),
            h.http_title.clone(),
            h.http_server.clone(),
            h.netbios.as_ref().and_then(|n| n.group.clone()),
            h.upnp.as_ref().and_then(|u| u.friendly_name.clone()),
            h.upnp.as_ref().and_then(|u| u.manufacturer.clone()),
            h.upnp.as_ref().and_then(|u| u.model.clone()),
        ]
        .into_iter()
        .flatten(),
    );
    for s in &h.mdns_services {
        hay.push(s.label());
    }
    for p in &h.ports {
        hay.push(p.port.to_string());
        hay.push(p.service.to_string());
        hay.extend(p.banner.clone());
    }
    let hay = hay.join("\n").to_lowercase();
    query.split_whitespace().all(|term| hay.contains(term))
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortVal {
    Num(u64),
    Text(String),
}

/// Sort key for a column (indices match COLUMNS). None = no value.
fn sort_value(h: &HostInfo, col: usize) -> Option<SortVal> {
    let text = |s: Option<String>| {
        s.filter(|s| !s.is_empty())
            .map(|s| SortVal::Text(s.to_lowercase()))
    };
    match col {
        0 => Some(SortVal::Num(match h.status {
            Status::Done | Status::Enriching => 0,
            Status::Probing => 1,
            Status::Pending => 2,
            Status::Dead => 3,
        })),
        1 => Some(SortVal::Num(u32::from(h.ip) as u64)),
        2 => h.rtt_ms.map(|r| SortVal::Num((r * 1000.0) as u64)),
        3 => h.ttl.map(|t| SortVal::Num(t as u64)),
        4 => text(h.hostname()),
        5 => text(h.mac.clone()),
        6 => text(h.vendor.clone()),
        7 => text(h.device_type.clone()),
        8 => text(h.os_guess.clone()),
        9 => (!h.ports.is_empty()).then_some(SortVal::Num(h.ports.len() as u64)),
        _ => None,
    }
}

fn status_color(s: Status) -> (Hsla, &'static str) {
    match s {
        Status::Pending => (rgb(0x3a4252).into(), "pending"),
        Status::Probing => (rgb(C::AMBER).into(), "probing"),
        Status::Dead => (rgb(0x5a3a3a).into(), "dead"),
        Status::Enriching => (rgb(C::ACCENT).into(), "alive"),
        Status::Done => (rgb(C::GREEN).into(), "alive"),
    }
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Pending => "Pending",
        Status::Probing => "Probing",
        Status::Dead => "No response",
        Status::Enriching => "Alive — gathering details…",
        Status::Done => "Alive",
    }
}

impl Focusable for ScannerView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for ScannerView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .key_context("Scanner")
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::start_stop))
            .on_action(cx.listener(Self::toggle_filter))
            .on_action(cx.listener(Self::export))
            .on_action(cx.listener(Self::focus_search))
            .flex()
            .flex_col()
            .size_full()
            .child(self.render_toolbar(window, cx))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(self.render_table(cx))
                    .children(self.selected.map(|i| self.render_details(i, cx))),
            )
            .child(self.render_status_bar())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortInfo;

    #[test]
    fn search_matches_all_terms() {
        let mut h = HostInfo::new("192.168.1.20".parse().unwrap());
        h.vendor = Some("Raspberry Pi Trading Ltd".into());
        h.mdns_name = Some("pihole.local".into());
        h.ports.push(PortInfo {
            port: 22,
            service: "ssh",
            banner: Some("SSH-2.0-OpenSSH_10.0p2 Debian".into()),
        });
        assert!(matches_search(&h, ""));
        assert!(matches_search(&h, "RASPBERRY"));
        assert!(matches_search(&h, "raspberry 22"));
        assert!(matches_search(&h, "1.20"));
        assert!(matches_search(&h, "debian pihole"));
        assert!(!matches_search(&h, "raspberry 3389"));
    }
}
