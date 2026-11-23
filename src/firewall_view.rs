//! Firewall Tester and Rogue DHCP Tester.

use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::capture::Interface;
use crate::dhcp::{self, Offer, ProbeEvent};
use crate::firewall::{self, Check, FwEvent, PortState};
use crate::settings;
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, cell, chip, copy_button, dot,
    empty_state, input, label, status_bar, table_header, tile, tip, toolbar,
};

fn poll<V: 'static>(cx: &mut Context<V>, f: fn(&mut V, &mut Context<V>) -> bool) -> Task<()> {
    cx.spawn(async move |this, cx| {
        loop {
            cx.background_executor()
                .timer(Duration::from_millis(150))
                .await;
            match this.update(cx, f) {
                Ok(true) => {}
                _ => break,
            }
        }
    })
}

#[derive(Clone, Copy, PartialEq)]
enum FwMode {
    Egress,
    Path,
}

pub struct FirewallView {
    focus: FocusHandle,
    mode: FwMode,
    host: Entity<TextInput>,
    target: Entity<TextInput>,
    ports: Entity<TextInput>,
    rx: Option<Receiver<FwEvent>>,
    resolved: Option<std::net::IpAddr>,
    checks: Vec<Check>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl FirewallView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let run = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.run(cx);
        Self {
            focus: cx.focus_handle(),
            mode: FwMode::Egress,
            host: input(window, cx, &settings::get().firewall_host, settings::DEFAULT_FIREWALL_HOST, Accept::Any, |t| t.width(220.), run),
            target: input(window, cx, "", "host or IP behind the firewall", Accept::Any, |t| t.width(260.), run),
            ports: input(window, cx, "top", "top, 1-1024, 22,80,443", Accept::Ports, |t| t.width(170.), run),
            rx: None,
            resolved: None,
            checks: Vec::new(),
            status: "Outbound: what this network lets out. Target path: what a firewall in front of a host lets in.".into(),
            error: None,
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        self.checks.clear();
        self.error = None;
        self.resolved = None;
        let wait = Duration::from_secs(3);
        self.rx = Some(match self.mode {
            FwMode::Egress => {
                let host = self.host.read(cx).value.trim().to_string();
                let _ = settings::update(|s| s.firewall_host = host.clone());
                self.status = format!("Testing outbound connections to {host}…").into();
                firewall::egress(host, wait)
            }
            FwMode::Path => {
                let target = self.target.read(cx).value.trim().to_string();
                let ports = match crate::portscan::parse_ports(&self.ports.read(cx).value) {
                    Ok(p) => p,
                    Err(e) => {
                        self.error = Some(e);
                        return;
                    }
                };
                self.status = format!("Testing {} ports on {target}…", ports.len()).into();
                firewall::path(target, ports, Duration::from_millis(1500))
            }
        });
        self._poll = Some(poll(cx, |t: &mut Self, cx| {
            let Some(rx) = &t.rx else { return false };
            let mut done = false;
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    FwEvent::Resolved(ip) => t.resolved = Some(ip),
                    FwEvent::Check(c) => t.checks.push(c),
                    FwEvent::Error(e) => t.error = Some(e),
                    FwEvent::Done => done = true,
                }
            }
            if done {
                t.rx = None;
                t.checks.sort_by_key(|c| {
                    let port: u32 = c
                        .name
                        .split_whitespace()
                        .nth(1)
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(99999);
                    (!c.name.starts_with("TCP"), port)
                });
                t.status = if t.mode == FwMode::Path {
                    firewall::interpret(&t.checks).into()
                } else {
                    "Done".into()
                };
            }
            cx.notify();
            !done
        }));
    }
}

impl Focusable for FirewallView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for FirewallView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.rx.is_some();
        let count = |s: PortState| self.checks.iter().filter(|c| c.state == Ok(s)).count();
        // In path mode, hide the long tail of closed ports unless asked.
        let shown: Vec<&Check> = self
            .checks
            .iter()
            .filter(|c| {
                self.mode == FwMode::Egress
                    || c.state != Ok(PortState::Closed)
                    || self.checks.len() <= 60
            })
            .collect();
        let text = self
            .checks
            .iter()
            .map(|c| {
                format!(
                    "{}\t{}\t{}",
                    c.name,
                    c.state.as_ref().map(|s| s.label()).unwrap_or("error"),
                    c.note
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(chip("fw-egress", "Outbound policy", self.mode == FwMode::Egress, act(&view, |t: &mut Self, _, _| t.mode = FwMode::Egress)))
                    .child(chip("fw-path", "Target path", self.mode == FwMode::Path, act(&view, |t: &mut Self, _, _| t.mode = FwMode::Path)))
                    .child(div().w(px(10.)))
                    .when(self.mode == FwMode::Egress, |d| {
                        d.child(label("Any-port test host")).child(self.host.clone()).child(div().text_xs().text_color(rgb(C::MUTED)).child("(contacted only when you press Test)"))
                    })
                    .when(self.mode == FwMode::Path, |d| d.child(label("Target")).child(self.target.clone()).child(label("Ports")).child(self.ports.clone()))
                    .child(if busy {
                        button("fw-go", "Testing…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary("fw-go", "▶ Test", act(&view, |t: &mut Self, _, cx| t.run(cx)))
                    })
                    .child(copy_button("fw-copy", text)),
            )
            .children(self.error.clone().map(|e| div().px_5().py_2().text_sm().text_color(rgb(C::RED)).bg(alpha(C::RED, 0.08)).child(e)))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .px_5()
                    .py_3()
                    .child(tile(if self.mode == FwMode::Egress { "Allowed" } else { "Open" }, count(PortState::Open).to_string(), C::GREEN))
                    .child(tile(if self.mode == FwMode::Egress { "Rejected" } else { "Closed (reset)" }, count(PortState::Closed).to_string(), C::AMBER))
                    .child(tile(if self.mode == FwMode::Egress { "Blocked" } else { "Filtered" }, count(PortState::Filtered).to_string(), C::RED))
                    .children(self.resolved.map(|ip| tile("Address", ip.to_string(), C::MUTED))),
            )
            .child(table_header(&[("CHECK", 260.), ("RESULT", 180.), ("TIME", 90.), ("MEANING", 0.)]))
            .child(if self.checks.is_empty() {
                empty_state(if busy { "Testing…" } else { "No test yet" }, "Closed = something sent a TCP reset; filtered = no answer at all (dropped by a firewall).").into_any_element()
            } else {
                div()
                    .id("fw-rows")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(shown.into_iter().enumerate().map(|(i, c)| {
                        let (txt, col) = match &c.state {
                            Ok(PortState::Open) => (if self.mode == FwMode::Egress { "allowed" } else { "open" }, C::GREEN),
                            Ok(PortState::Closed) => ("closed (reset)", C::AMBER),
                            Ok(PortState::Filtered) => (if self.mode == FwMode::Egress { "blocked" } else { "filtered" }, C::RED),
                            Err(_) => ("error", C::MUTED),
                        };
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(28.))
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(cell(260., c.name.clone()))
                            .child(div().w(px(180.)).flex_none().flex().items_center().gap_2().child(dot(col)).child(div().text_color(rgb(col)).child(txt)))
                            .child(cell(90., if c.ms > 0.0 { format!("{:.0} ms", c.ms) } else { "—".into() }).text_color(rgb(C::MUTED)))
                            .child(cell(0., c.note.clone()).text_color(rgb(C::MUTED)))
                    }))
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}

// ---------------------------------------------------------------- rogue DHCP

pub struct RogueDhcpView {
    focus: FocusHandle,
    ifaces: Result<Vec<Interface>, String>,
    iface: Option<usize>,
    authorised: Entity<TextInput>,
    rx: Option<Receiver<ProbeEvent>>,
    offers: Vec<Offer>,
    status: SharedString,
    error: Option<String>,
    done: bool,
    _poll: Option<Task<()>>,
}

impl RogueDhcpView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ifaces = crate::capture::interfaces().map(|l| {
            l.into_iter()
                .filter(|i| {
                    i.up && !i.loopback && !i.addrs.is_empty() && !i.name.starts_with("veth")
                })
                .collect::<Vec<_>>()
        });
        let primary = crate::netinfo::local_interfaces()
            .first()
            .map(|i| i.ip.to_string());
        let iface = ifaces.as_ref().ok().and_then(|l| {
            l.iter()
                .position(|i| primary.as_ref().is_some_and(|p| i.addrs.contains(p)))
                .or((!l.is_empty()).then_some(0))
        });
        let saved = settings::get().dhcp_servers.join(", ");
        Self {
            focus: cx.focus_handle(),
            error: ifaces.as_ref().err().cloned(),
            ifaces,
            iface,
            authorised: input(window, cx, &saved, "authorised DHCP server IPs, e.g. 192.168.1.1, 192.168.1.2", Accept::Any, |t| t.width(380.), |t: &mut Self, _, cx| t.run(cx)),
            rx: None,
            offers: Vec::new(),
            status: "Sends DHCPDISCOVERs (no address is leased) and compares the servers that answer with your authorised list.".into(),
            done: false,
            _poll: None,
        }
    }

    fn authorised_list(&self, cx: &App) -> Vec<Ipv4Addr> {
        self.authorised
            .read(cx)
            .value
            .split([',', ' ', ';'])
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let Some(iface) = self
            .iface
            .and_then(|i| self.ifaces.as_ref().ok()?.get(i).cloned())
        else {
            self.error = Some("Select an interface".into());
            return;
        };
        let list: Vec<String> = self
            .authorised_list(cx)
            .iter()
            .map(|i| i.to_string())
            .collect();
        let _ = settings::update(|s| s.dhcp_servers = list);
        let mac = iface
            .addrs
            .iter()
            .find_map(|a| a.parse::<Ipv4Addr>().ok())
            .and_then(|ip| crate::platform::iface_mac(&iface.name, ip))
            .and_then(|m| dhcp::parse_mac(&m))
            .unwrap_or([0x02, 0x4e, 0x41, 0x52, 0x44, 0x01]);
        self.offers.clear();
        self.error = None;
        self.done = false;
        self.rx = Some(dhcp::find_servers(
            iface.name.clone(),
            mac,
            3,
            Duration::from_secs(4),
        ));
        self.status = format!("Probing on {}…", iface.label()).into();
        self._poll = Some(poll(cx, |t: &mut Self, cx| {
            let Some(rx) = &t.rx else { return false };
            let mut finished = false;
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    ProbeEvent::Status(s) => t.status = s.into(),
                    ProbeEvent::Offer(o) => t.offers.push(*o),
                    ProbeEvent::Done(r) => {
                        finished = true;
                        match r {
                            Ok(_) => {}
                            Err(e) => t.error = Some(e),
                        }
                    }
                }
            }
            if finished {
                t.rx = None;
                t.done = true;
                t.status = "Done".into();
            }
            cx.notify();
            !finished
        }));
    }
}

impl Focusable for RogueDhcpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for RogueDhcpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let busy = self.rx.is_some();
        let auth = self.authorised_list(cx);
        let mut servers: Vec<(Ipv4Addr, Option<String>, Vec<&Offer>)> = Vec::new();
        for o in &self.offers {
            match servers.iter_mut().find(|s| s.0 == o.server) {
                Some(s) => s.2.push(o),
                None => servers.push((o.server, o.server_mac.clone(), vec![o])),
            }
        }
        let rogue = servers
            .iter()
            .filter(|s| !auth.is_empty() && !auth.contains(&s.0))
            .count();
        let ifaces = self.ifaces.as_ref().map(|l| l.as_slice()).unwrap_or(&[]);
        let verdict = if !self.done {
            None
        } else if servers.is_empty() {
            Some(("No DHCP server answered.".to_string(), C::AMBER))
        } else if auth.is_empty() {
            Some((
                format!(
                    "{} DHCP server(s) answered. Enter your authorised server(s) to flag rogues.",
                    servers.len()
                ),
                if servers.len() > 1 { C::AMBER } else { C::TEXT },
            ))
        } else if rogue > 0 {
            Some((format!("{rogue} ROGUE DHCP server(s) found!"), C::RED))
        } else {
            Some((
                "Only authorised DHCP servers answered.".to_string(),
                C::GREEN,
            ))
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Interface"))
                    .children(ifaces.iter().enumerate().map(|(i, f)| {
                        chip(
                            ("rd-if", i),
                            if cfg!(windows) && !f.desc.is_empty() {
                                f.desc.clone()
                            } else {
                                f.name.clone()
                            },
                            self.iface == Some(i),
                            act(&view, move |t: &mut Self, _, _| t.iface = Some(i)),
                        )
                    }))
                    .child(label("Authorised"))
                    .child(self.authorised.clone())
                    .child(if busy {
                        button("rd-go", "Probing…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary(
                            "rd-go",
                            "▶ Find DHCP servers",
                            act(&view, |t: &mut Self, _, cx| t.run(cx)),
                        )
                        .tooltip(tip("Needs packet-capture rights (same as Packet Capture)."))
                    }),
            )
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .child(e)
            }))
            .children(verdict.map(|(v, c)| {
                div()
                    .px_5()
                    .py_3()
                    .text_lg()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(rgb(c))
                    .child(v)
            }))
            .child(table_header(&[
                ("", 30.),
                ("SERVER", 150.),
                ("MAC / VENDOR", 300.),
                ("OFFERED", 140.),
                ("ROUTER", 140.),
                ("DNS", 200.),
                ("STATUS", 0.),
            ]))
            .child(if servers.is_empty() {
                empty_state(
                    if busy {
                        "Waiting for offers…"
                    } else {
                        "No probe yet"
                    },
                    "",
                )
                .into_any_element()
            } else {
                div()
                    .id("rd-rows")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(servers.iter().enumerate().map(|(i, (ip, mac, offers))| {
                        let m = &offers[0].message;
                        let ok = auth.is_empty() || auth.contains(ip);
                        let vendor = mac
                            .as_deref()
                            .and_then(crate::netinfo::mac_vendor)
                            .unwrap_or_default();
                        div()
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(30.))
                            .text_sm()
                            .bg(if ok {
                                rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }).into()
                            } else {
                                alpha(C::RED, 0.12)
                            })
                            .child(
                                div()
                                    .w(px(30.))
                                    .child(dot(if ok { C::GREEN } else { C::RED })),
                            )
                            .child(
                                cell(150., ip.to_string()).font_weight(gpui::FontWeight::SEMIBOLD),
                            )
                            .child(
                                cell(
                                    300.,
                                    format!("{} {vendor}", mac.clone().unwrap_or_default()),
                                )
                                .text_color(rgb(C::MUTED)),
                            )
                            .child(cell(140., offers[0].offered.to_string()))
                            .child(cell(
                                140.,
                                m.routers.first().map(|r| r.to_string()).unwrap_or_default(),
                            ))
                            .child(cell(
                                200.,
                                m.dns
                                    .iter()
                                    .map(|d| d.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ))
                            .child(
                                cell(
                                    0.,
                                    if auth.is_empty() {
                                        format!("{} offer(s)", offers.len())
                                    } else if ok {
                                        "authorised".into()
                                    } else {
                                        "ROGUE — not on the authorised list".into()
                                    },
                                )
                                .text_color(rgb(if ok {
                                    C::TEXT
                                } else {
                                    C::RED
                                })),
                            )
                    }))
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
