//! Network Configuration viewer: interfaces, routes, DNS, neighbours.

use std::net::IpAddr;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use gpui::{
    App, Context, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px, rgb,
};

use crate::netconfig::{Iface, Route};
use crate::widgets::{
    C, act, button_primary, cell, chip, copy_button, dot, empty_state, mono, section_title,
    status_bar, table_header, toolbar,
};

struct Snapshot {
    hostname: String,
    ifaces: Vec<Iface>,
    routes: Vec<Route>,
    dns: Vec<IpAddr>,
    upstreams: Vec<IpAddr>,
    neighbours: Vec<(IpAddr, String)>,
}

fn collect() -> Snapshot {
    Snapshot {
        hostname: crate::netconfig::hostname(),
        ifaces: crate::netconfig::interfaces(),
        routes: crate::netconfig::routes(),
        dns: crate::dns::system_servers(),
        upstreams: crate::dns::resolved_upstreams(),
        neighbours: crate::netconfig::neighbours(),
    }
}

pub struct NetConfigView {
    focus: FocusHandle,
    snap: Option<Snapshot>,
    rx: Option<Receiver<Snapshot>>,
    show_virtual: bool,
    show_v6_routes: bool,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl NetConfigView {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut v = Self {
            focus: cx.focus_handle(),
            snap: None,
            rx: None,
            show_virtual: false,
            show_v6_routes: false,
            status: "Reading configuration…".into(),
            _poll: None,
        };
        v.refresh(cx);
        v
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(collect());
        });
        self.rx = Some(rx);
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
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(rx) = &self.rx else { return false };
        match rx.try_recv() {
            Ok(s) => {
                self.status = format!(
                    "{} interfaces, {} routes, {} DNS servers",
                    s.ifaces.len(),
                    s.routes.len(),
                    s.dns.len()
                )
                .into();
                self.snap = Some(s);
                self.rx = None;
                cx.notify();
                false
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => true,
            Err(_) => {
                self.rx = None;
                false
            }
        }
    }

    fn visible<'a>(&self, s: &'a Snapshot) -> Vec<&'a Iface> {
        s.ifaces
            .iter()
            .filter(|i| {
                self.show_virtual
                    || !(i.name.starts_with("veth") || (i.kind == "virtual" && i.addrs.is_empty()))
            })
            .collect()
    }

    fn as_text(&self) -> String {
        let Some(s) = &self.snap else {
            return String::new();
        };
        let mut out = format!("Hostname: {}\n\nInterfaces\n", s.hostname);
        for i in self.visible(s) {
            out.push_str(&format!(
                "  {} ({}, {}) MAC {} MTU {}\n",
                i.name,
                i.kind,
                match i.up {
                    Some(true) => "up",
                    Some(false) => "down",
                    None => "?",
                },
                i.mac.clone().unwrap_or("-".into()),
                i.mtu.map(|m| m.to_string()).unwrap_or("-".into())
            ));
            for (a, p) in &i.addrs {
                out.push_str(&format!("      {a}/{p}\n"));
            }
        }
        out.push_str("\nRoutes\n");
        for r in &s.routes {
            out.push_str(&format!(
                "  {} {} dev {}{}\n",
                r.dest,
                r.gateway.map(|g| format!("via {g}")).unwrap_or_default(),
                r.iface,
                r.metric.map(|m| format!(" metric {m}")).unwrap_or_default()
            ));
        }
        out.push_str(&format!(
            "\nDNS: {}\n",
            s.dns
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out
    }

    fn iface_card(i: &Iface) -> impl IntoElement {
        let (state, color) = match i.up {
            Some(true) => ("up", C::GREEN),
            Some(false) => ("down", C::RED),
            None => ("", 0x3a4252),
        };
        let vendor = i.mac.as_deref().and_then(crate::netinfo::mac_vendor);
        div()
            .w(px(380.))
            .flex()
            .flex_col()
            .gap_1()
            .p_3()
            .rounded_md()
            .bg(rgb(C::PANEL))
            .border_1()
            .border_color(rgb(C::BORDER))
            .text_sm()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(dot(color))
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(i.name.clone()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(C::MUTED))
                            .child(format!("{} {state}", i.kind)),
                    ),
            )
            .when_some(i.mac.clone(), |d, m| {
                d.child(div().text_xs().text_color(rgb(C::MUTED)).child(format!(
                    "{m}{}",
                    vendor.map(|v| format!("  ·  {v}")).unwrap_or_default()
                )))
            })
            .child(
                div().text_xs().text_color(rgb(C::MUTED)).child(
                    [
                        i.mtu.map(|m| format!("MTU {m}")),
                        i.speed_mbps.map(|s| format!("{s} Mb/s")),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("  ·  "),
                ),
            )
            .children(i.addrs.iter().map(|(a, p)| {
                let note = match a {
                    IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80 => "  link-local",
                    a => match crate::webapi::classify(*a) {
                        "public" => "  public",
                        "carrier-grade NAT (RFC 6598)" => "  CGNAT range",
                        _ => "",
                    },
                };
                div().font_family(mono()).child(format!("{a}/{p}{note}"))
            }))
    }
}

impl Focusable for NetConfigView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for NetConfigView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let body = match &self.snap {
            None => empty_state("Reading configuration…", "").into_any_element(),
            Some(s) => {
                let ifaces = self.visible(s);
                let routes: Vec<&Route> = s
                    .routes
                    .iter()
                    .filter(|r| self.show_v6_routes || !r.v6)
                    .collect();
                div()
                    .id("nc-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_5()
                    .flex()
                    .flex_col()
                    .gap_5()
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .content_start()
                            .gap_5()
                            .text_sm()
                            .child(format!("Hostname: {}", s.hostname))
                            .child(format!(
                                "DNS servers: {}",
                                if s.dns.is_empty() {
                                    "none".into()
                                } else {
                                    s.dns
                                        .iter()
                                        .map(|d| d.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                }
                            ))
                            .when(!s.upstreams.is_empty(), |d| {
                                d.child(div().text_color(rgb(C::MUTED)).child(format!(
                                        "upstream (systemd-resolved): {}",
                                        s.upstreams
                                            .iter()
                                            .map(|d| d.to_string())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    )))
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(section_title(&format!("Interfaces ({})", ifaces.len())))
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .content_start()
                                    .gap_3()
                                    .children(ifaces.into_iter().map(Self::iface_card)),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(section_title(&format!("Routes ({})", routes.len())))
                            .child(table_header(&[
                                ("DESTINATION", 300.),
                                ("GATEWAY", 260.),
                                ("INTERFACE", 200.),
                                ("METRIC", 0.),
                            ]))
                            .children(routes.into_iter().enumerate().map(|(i, r)| {
                                div()
                                    .flex()
                                    .px_3()
                                    .py_1()
                                    .text_sm()
                                    .font_family(mono())
                                    .bg(rgb(if r.is_default() {
                                        C::SELECT
                                    } else if i % 2 == 1 {
                                        C::ROW_ALT
                                    } else {
                                        C::BG
                                    }))
                                    .child(cell(
                                        300.,
                                        if r.is_default() {
                                            format!("{} (default)", r.dest)
                                        } else {
                                            r.dest.clone()
                                        },
                                    ))
                                    .child(cell(
                                        260.,
                                        r.gateway
                                            .map(|g| g.to_string())
                                            .unwrap_or_else(|| "on-link".into()),
                                    ))
                                    .child(cell(200., r.iface.clone()))
                                    .child(cell(
                                        0.,
                                        r.metric.map(|m| m.to_string()).unwrap_or_default(),
                                    ))
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(section_title(&format!(
                                "Neighbours / ARP cache ({})",
                                s.neighbours.len()
                            )))
                            .child(table_header(&[
                                ("ADDRESS", 200.),
                                ("MAC", 200.),
                                ("VENDOR", 0.),
                            ]))
                            .children(s.neighbours.iter().enumerate().map(|(i, (ip, mac))| {
                                div()
                                    .flex()
                                    .px_3()
                                    .py_1()
                                    .text_sm()
                                    .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                                    .child(cell(200., ip.to_string()).font_family(mono()))
                                    .child(cell(200., mac.clone()).font_family(mono()))
                                    .child(
                                        cell(
                                            0.,
                                            crate::netinfo::mac_vendor(mac).unwrap_or_default(),
                                        )
                                        .text_color(rgb(C::MUTED)),
                                    )
                            })),
                    )
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
                    .child(chip(
                        "nc-virt",
                        "Show virtual interfaces",
                        self.show_virtual,
                        act(&view, |t: &mut Self, _, _| t.show_virtual = !t.show_virtual),
                    ))
                    .child(chip(
                        "nc-v6",
                        "IPv6 routes",
                        self.show_v6_routes,
                        act(&view, |t: &mut Self, _, _| {
                            t.show_v6_routes = !t.show_v6_routes
                        }),
                    ))
                    .child(div().flex_1())
                    .child(copy_button("nc-copy", self.as_text()))
                    .child(button_primary(
                        "nc-refresh",
                        "⟲ Refresh",
                        act(&view, |t: &mut Self, _, cx| t.refresh(cx)),
                    )),
            )
            .child(body)
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
