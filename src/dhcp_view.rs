//! DHCP Analyser: passive DHCP capture, per-server summary (multiple /
//! rogue server warning) and an active DISCOVER probe.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px, rgb,
};

use crate::capture::{self, CaptureConfig, CaptureEvent, CaptureHandle, Interface, Source};
use crate::dhcp::{self, Message};
use crate::widgets::{
    C, act, alpha, button, button_primary, button2, cell, chip, empty_state, kv_row, label, mono,
    section_title, status_bar, table_header, tip, toolbar,
};

struct Row {
    ts: f64,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_mac: Option<String>,
    msg: Message,
    /// Answer to our own DISCOVER probe.
    probe_reply: bool,
}

#[derive(Default)]
struct Server {
    mac: Option<String>,
    offers: u32,
    acks: u32,
    naks: u32,
    last: Option<Message>,
    answered_probe: bool,
}

pub struct DhcpView {
    focus: FocusHandle,
    ifaces: Result<Vec<Interface>, String>,
    iface: Option<usize>,
    random_mac: bool,
    handle: Option<CaptureHandle>,
    linktype: i32,
    rows: Vec<Row>,
    servers: BTreeMap<Ipv4Addr, Server>,
    probes: Vec<(u32, Instant)>,
    selected: Option<usize>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

fn random_u32() -> u32 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (t as u32) ^ ((t >> 32) as u32).rotate_left(13) ^ std::process::id()
}

impl DhcpView {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ifaces = capture::interfaces().map(|l| {
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
        Self {
            focus: cx.focus_handle(),
            error: ifaces.as_ref().err().cloned(),
            ifaces,
            iface,
            random_mac: false,
            handle: None,
            linktype: 1,
            rows: Vec::new(),
            servers: BTreeMap::new(),
            probes: Vec::new(),
            selected: None,
            status: "Start listening, then press Find DHCP servers (or wait for clients to renew)."
                .into(),
            _poll: None,
        }
    }

    fn current(&self) -> Option<Interface> {
        self.iface
            .and_then(|i| self.ifaces.as_ref().ok()?.get(i).cloned())
    }

    fn listen(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let Some(iface) = self.current() else {
            self.error = Some("Select an interface".into());
            return;
        };
        self.error = None;
        self.handle = Some(capture::start(CaptureConfig {
            source: Source::Live {
                device: iface.name.clone(),
                promisc: false,
            },
            filter: "udp and (port 67 or port 68)".into(),
            save_to: None,
        }));
        self.status = format!("Listening for DHCP on {}…", iface.label()).into();
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
    }

    fn stop(&mut self) {
        if let Some(h) = &self.handle {
            h.stop();
        }
    }

    fn probe(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_none() {
            self.listen(cx);
        }
        let Some(iface) = self.current() else { return };
        let mac = if self.random_mac {
            let r = random_u32().to_be_bytes();
            let s = random_u32().to_be_bytes();
            Some([0x02, r[0], r[1], r[2], s[0], s[1]])
        } else {
            iface
                .addrs
                .iter()
                .find_map(|a| a.parse::<Ipv4Addr>().ok())
                .and_then(|ip| crate::platform::iface_mac(&iface.name, ip))
                .and_then(|m| dhcp::parse_mac(&m))
        };
        let Some(mac) = mac else {
            self.error =
                Some("Could not read this interface's MAC address; enable Random MAC".into());
            return;
        };
        let xid = random_u32();
        if let Some(h) = &self.handle {
            h.inject(dhcp::discover_frame(mac, xid));
            self.probes.push((xid, Instant::now()));
            self.status = format!(
                "Sent DHCPDISCOVER (xid {xid:#010x}) from {} — waiting for offers…",
                mac.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":")
            )
            .into();
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let mut stopped = None;
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                CaptureEvent::Started { linktype, .. } => self.linktype = linktype,
                CaptureEvent::Packets(pkts) => {
                    for p in pkts {
                        let Some(u) = dhcp::udp_payload(self.linktype, &p.data) else {
                            continue;
                        };
                        if !matches!((u.sport, u.dport), (67, 68) | (68, 67) | (67, 67)) {
                            continue;
                        }
                        let Some(msg) = dhcp::parse(u.payload) else {
                            continue;
                        };
                        let probe_reply =
                            msg.op == 2 && self.probes.iter().any(|(x, _)| *x == msg.xid);
                        if msg.op == 2 {
                            let id = msg.server_id.unwrap_or(u.src);
                            let s = self.servers.entry(id).or_default();
                            s.mac = s.mac.clone().or(u.src_mac.clone());
                            match msg.msg_type {
                                Some(2) => s.offers += 1,
                                Some(5) => s.acks += 1,
                                Some(6) => s.naks += 1,
                                _ => {}
                            }
                            s.answered_probe |= probe_reply;
                            s.last = Some(msg.clone());
                        }
                        self.rows.push(Row {
                            ts: p.ts,
                            src: u.src,
                            dst: u.dst,
                            src_mac: u.src_mac,
                            msg,
                            probe_reply,
                        });
                    }
                }
                CaptureEvent::InjectFailed(e) => {
                    self.error = Some(format!("Could not send DISCOVER: {e}"))
                }
                CaptureEvent::Stats { .. } | CaptureEvent::FileInfo(_) => {}
                CaptureEvent::Stopped(err) => stopped = Some(err),
            }
        }
        if let Some(err) = stopped {
            self.handle = None;
            if let Some(e) = err {
                let hint = capture::permission_hint(&e);
                self.error = Some(match hint {
                    Some(h) => format!("{e}\n{h}"),
                    None => e,
                });
                self.status = "Capture failed".into();
            } else {
                self.status = format!(
                    "Stopped — {} DHCP messages, {} server(s)",
                    self.rows.len(),
                    self.servers.len()
                )
                .into();
            }
            cx.notify();
            return false;
        }
        if let Some((_, at)) = self.probes.last()
            && at.elapsed() > Duration::from_secs(4)
            && self.status.starts_with("Sent DHCPDISCOVER")
        {
            let n = self.servers.values().filter(|s| s.answered_probe).count();
            self.status = match n {
                0 => "No DHCP server answered the DISCOVER within 4 s".into(),
                1 => "1 DHCP server answered".into(),
                n => format!("{n} DHCP servers answered — check for a rogue server").into(),
            };
        }
        cx.notify();
        true
    }

    fn render_servers(&self) -> impl IntoElement {
        let multi = self.servers.len() > 1;
        div()
            .flex()
            .flex_col()
            .gap_2()
            .p_4()
            .border_b_1()
            .border_color(rgb(C::BORDER))
            .child(section_title(&format!("DHCP servers seen ({})", self.servers.len())))
            .when(multi, |d| {
                d.child(
                    div()
                        .px_3()
                        .py_2()
                        .rounded_md()
                        .bg(alpha(C::AMBER, 0.12))
                        .text_sm()
                        .text_color(rgb(C::AMBER))
                        .child("More than one DHCP server is answering on this segment. Unless this is intentional (failover / split scopes), one of them may be a rogue or misconfigured device."),
                )
            })
            .when(self.servers.is_empty(), |d| {
                d.child(div().text_sm().text_color(rgb(C::MUTED)).child("None yet."))
            })
            .children(self.servers.iter().map(|(ip, s)| {
                let m = s.last.as_ref();
                let vendor = s.mac.as_deref().and_then(crate::netinfo::mac_vendor);
                div()
                    .flex()
                    .flex_wrap()
                    .gap_x_5()
                    .gap_y_1()
                    .text_sm()
                    .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(ip.to_string()))
                    .child(div().text_color(rgb(C::MUTED)).child(format!(
                        "{}{}",
                        s.mac.clone().unwrap_or_default(),
                        vendor.map(|v| format!(" ({v})")).unwrap_or_default()
                    )))
                    .child(format!("{} offers · {} ACKs · {} NAKs", s.offers, s.acks, s.naks))
                    .when_some(m.and_then(|m| m.subnet_mask), |d, v| d.child(format!("mask {v}")))
                    .when_some(m.filter(|m| !m.routers.is_empty()), |d, m| {
                        d.child(format!("router {}", m.routers.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")))
                    })
                    .when_some(m.filter(|m| !m.dns.is_empty()), |d, m| {
                        d.child(format!("DNS {}", m.dns.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")))
                    })
                    .when_some(m.and_then(|m| m.lease_secs), |d, l| d.child(format!("lease {}", dhcp::duration(l))))
                    .when_some(m.and_then(|m| m.domain.clone()), |d, v| d.child(format!("domain {v}")))
                    .when(s.answered_probe, |d| d.child(div().text_color(rgb(C::GREEN)).child("answered our DISCOVER")))
            }))
    }

    fn render_detail(&self, r: &Row, cx: &mut Context<Self>) -> impl IntoElement {
        let m = &r.msg;
        div()
            .id("dhcp-detail")
            .w(px(420.))
            .flex_none()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_1()
            .overflow_y_scroll()
            .bg(rgb(C::PANEL))
            .border_l_1()
            .border_color(rgb(C::BORDER))
            .text_sm()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(section_title(&format!(
                        "DHCP{} xid {:#010x}",
                        m.msg_type.map(dhcp::msg_type_name).unwrap_or("?"),
                        m.xid
                    )))
                    .child(
                        div()
                            .id("dhcp-close")
                            .px_2()
                            .cursor_pointer()
                            .rounded_md()
                            .hover(|s| s.bg(rgb(C::PANEL2)))
                            .child("✕")
                            .on_click(cx.listener(|t, _, _, cx| {
                                t.selected = None;
                                cx.notify();
                            })),
                    ),
            )
            .child(kv_row(
                "Direction",
                if m.op == 1 {
                    "client → server"
                } else {
                    "server → client"
                },
                130.,
            ))
            .child(kv_row(
                "Sender",
                format!("{} {}", r.src, r.src_mac.clone().unwrap_or_default()),
                130.,
            ))
            .child(kv_row("Destination", r.dst.to_string(), 130.))
            .child(kv_row("Client MAC", m.chaddr.clone(), 130.))
            .child(kv_row("Client IP (ciaddr)", m.ciaddr.to_string(), 130.))
            .child(kv_row("Your IP (yiaddr)", m.yiaddr.to_string(), 130.))
            .child(kv_row("Next server", m.siaddr.to_string(), 130.))
            .child(kv_row("Relay (giaddr)", m.giaddr.to_string(), 130.))
            .child(kv_row(
                "Broadcast flag",
                if m.broadcast { "set" } else { "clear" },
                130.,
            ))
            .child(kv_row("Seconds", m.secs.to_string(), 130.))
            .child(div().pt_2().child(section_title("Options")))
            .children(
                m.options
                    .iter()
                    .map(|o| kv_row(format!("{} {}", o.code, o.name), o.value.clone(), 190.)),
            )
    }
}

impl Focusable for DhcpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for DhcpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let listening = self.handle.is_some();
        let t0 = self.rows.first().map(|r| r.ts).unwrap_or(0.0);
        let ifaces = self.ifaces.as_ref().map(|l| l.as_slice()).unwrap_or(&[]);
        let rows = div()
            .id("dhcp-rows")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .children(self.rows.iter().enumerate().rev().take(2000).map(|(i, r)| {
                let m = &r.msg;
                let t = m.msg_type.map(dhcp::msg_type_name).unwrap_or("BOOTP");
                let color = match m.msg_type {
                    Some(1 | 3) => C::ACCENT,
                    Some(2 | 5) => C::GREEN,
                    Some(6 | 4) => C::RED,
                    _ => C::MUTED,
                };
                let addr = [
                    (!m.yiaddr.is_unspecified()).then(|| m.yiaddr.to_string()),
                    m.requested_ip.map(|x| format!("req {x}")),
                    (!m.ciaddr.is_unspecified()).then(|| m.ciaddr.to_string()),
                ]
                .into_iter()
                .flatten()
                .next()
                .unwrap_or_default();
                let vendor = crate::netinfo::mac_vendor(&m.chaddr).unwrap_or_default();
                div()
                    .id(("dhcp-row", i))
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(28.))
                    .text_sm()
                    .cursor_pointer()
                    .bg(if self.selected == Some(i) {
                        rgb(C::SELECT).into()
                    } else if r.probe_reply {
                        alpha(C::GREEN, 0.10)
                    } else {
                        rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }).into()
                    })
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .on_click(cx.listener(move |t, _, _, cx| {
                        t.selected = Some(i);
                        cx.notify();
                    }))
                    .child(cell(80., format!("{:.2}", r.ts - t0)).text_color(rgb(C::MUTED)))
                    .child(cell(100., t).text_color(rgb(color)))
                    .child(cell(160., m.chaddr.clone()).font_family(mono()))
                    .child(cell(170., vendor).text_color(rgb(C::MUTED)))
                    .child(cell(150., m.hostname.clone().unwrap_or_default()))
                    .child(cell(150., addr))
                    .child(cell(
                        130.,
                        m.server_id.map(|s| s.to_string()).unwrap_or_default(),
                    ))
                    .child(
                        cell(0., m.vendor_class.clone().unwrap_or_default())
                            .text_color(rgb(C::MUTED)),
                    )
            }));
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Interface"))
                    .children(ifaces.iter().enumerate().map(|(i, f)| {
                        chip(("dhcp-if", i), if cfg!(windows) && !f.desc.is_empty() { f.desc.clone() } else { f.name.clone() }, self.iface == Some(i), act(&view, move |t: &mut Self, _, _| {
                            if t.handle.is_none() {
                                t.iface = Some(i)
                            }
                        }))
                    }))
                    .child(div().flex_1())
                    .child(chip("rand-mac", "Random MAC", self.random_mac, act(&view, |t: &mut Self, _, _| t.random_mac = !t.random_mac)).tooltip(tip(
                        "Send the DISCOVER from a random locally administered MAC instead of this interface's own. No REQUEST is ever sent, so no lease is taken either way.",
                    )))
                    .child(if listening {
                        button("dhcp-listen", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.stop()))
                    } else {
                        button2("dhcp-listen", "Listen", act(&view, |t: &mut Self, _, cx| t.listen(cx)))
                    })
                    .child(button_primary("dhcp-probe", "Find DHCP servers", act(&view, |t: &mut Self, _, cx| t.probe(cx))).tooltip(tip(
                        "Broadcast a DHCPDISCOVER and list every server that offers an address.",
                    ))),
            )
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .children(e.lines().map(|l| div().child(l.to_string())).collect::<Vec<_>>())
            }))
            .child(self.render_servers())
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(table_header(&[("TIME", 80.), ("TYPE", 100.), ("CLIENT MAC", 160.), ("VENDOR", 170.), ("HOSTNAME", 150.), ("ADDRESS", 150.), ("SERVER", 130.), ("VENDOR CLASS", 0.)]))
                            .child(if self.rows.is_empty() {
                                empty_state(
                                    if listening { "Waiting for DHCP traffic…" } else { "Not listening" },
                                    "Packet capture rights are needed (same as the Packet Capture tool).",
                                )
                                .into_any_element()
                            } else {
                                rows.into_any_element()
                            }),
                    )
                    .children(self.selected.and_then(|i| self.rows.get(i)).map(|r| self.render_detail(r, cx))),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .child(format!("{} messages", self.rows.len())),
            )
    }
}
