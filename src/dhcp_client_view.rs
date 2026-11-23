//! DHCP Client Tester tool: a full DHCP exchange from a test MAC with
//! per-step timing, every OFFER, the leased options, and clean-up.

use std::net::Ipv4Addr;
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::capture::{self, Interface};
use crate::dhcp;
use crate::dhcp_client::{self, Config, Event, RunConfig, RunHandle, RunResult};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, bar_chart, button, button_primary, cell, chip, copy_button,
    empty_state, findings_cards, findings_text, input, kv_row, label, mono, section_title,
    status_bar, table_header, tile, toolbar,
};

pub struct DhcpClientView {
    focus: FocusHandle,
    ifaces: Result<Vec<Interface>, String>,
    iface: Option<usize>,
    mac: Entity<TextInput>,
    request: Entity<TextInput>,
    run_cfg: RunConfig,
    repeat: u32,
    handle: Option<RunHandle>,
    runs: Vec<RunResult>,
    selected: Option<usize>,
    error: Option<String>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

fn opt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.0} ms")).unwrap_or_default()
}

impl DhcpClientView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
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
            mac: input(
                window,
                cx,
                "",
                "random per run",
                Accept::Any,
                |t| t.width(170.).max_len(17).mono(),
                |t: &mut Self, _, cx| t.run(cx),
            ),
            request: input(
                window,
                cx,
                "",
                "any",
                Accept::Range,
                |t| t.width(130.).max_len(15),
                |t: &mut Self, _, cx| t.run(cx),
            ),
            run_cfg: RunConfig::default(),
            repeat: 1,
            handle: None,
            runs: Vec::new(),
            selected: None,
            status: "Runs a real DHCP exchange from a test MAC (needs packet-capture rights). The lease is released afterwards.".into(),
            _poll: None,
        }
    }

    fn current(&self) -> Option<Interface> {
        self.iface
            .and_then(|i| self.ifaces.as_ref().ok()?.get(i).cloned())
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() {
            return;
        }
        let Some(iface) = self.current() else {
            self.error = Some("Select an interface".into());
            return;
        };
        let mac_s = self.mac.read(cx).value.trim().to_string();
        let mac = if mac_s.is_empty() {
            None
        } else {
            match dhcp::parse_mac(&mac_s) {
                Some(m) if m[0] & 1 == 0 => Some(m),
                _ => {
                    self.mac.update(cx, |t, cx| {
                        t.error = true;
                        cx.notify()
                    });
                    self.error = Some("Test MAC must be a unicast MAC address".into());
                    return;
                }
            }
        };
        let req_s = self.request.read(cx).value.trim().to_string();
        let requested = if req_s.is_empty() {
            None
        } else {
            match req_s.parse::<Ipv4Addr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    self.request.update(cx, |t, cx| {
                        t.error = true;
                        cx.notify()
                    });
                    return;
                }
            }
        };
        self.error = None;
        self.runs.clear();
        self.selected = None;
        let mut run = self.run_cfg.clone();
        run.requested_ip = requested;
        self.handle = Some(dhcp_client::start(Config {
            device: iface.name.clone(),
            mac,
            run,
            repeat: self.repeat,
        }));
        self.status = format!("Opening {}…", iface.label()).into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                match this.update(cx, |t, cx| t.drain(cx)) {
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
        self.status = "Stopping (releasing any lease)…".into();
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let mut finished = None;
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                Event::Status(s) => self.status = s.into(),
                Event::Update(r) => {
                    let pos = match self.runs.iter().position(|x| x.run == r.run) {
                        Some(p) => {
                            self.runs[p] = *r;
                            p
                        }
                        None => {
                            self.runs.push(*r);
                            self.runs.len() - 1
                        }
                    };
                    if self.selected.is_none() || self.handle.is_some() {
                        self.selected = Some(pos);
                    }
                }
                Event::Finished(r) => finished = Some(r),
            }
        }
        if let Some(r) = finished {
            self.handle = None;
            match r {
                Ok(()) => {
                    let ok = self.runs.iter().filter(|r| r.ok()).count();
                    self.status =
                        format!("Done: {ok} of {} run(s) got a lease.", self.runs.len()).into();
                }
                Err(e) => {
                    self.error = Some(e);
                    self.status = "Failed.".into();
                }
            }
        }
        cx.notify();
        self.handle.is_some()
    }

    fn detail(&self, r: &RunResult) -> impl IntoElement {
        div()
            .id("dhcpc-detail")
            .w(px(460.))
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
            .child(section_title(&format!(
                "Run {} — {} — xid {:#010x}",
                r.run, r.mac, r.xid
            )))
            .children(r.log.iter().map(|l| {
                div()
                    .flex()
                    .gap_2()
                    .text_xs()
                    .font_family(mono())
                    .child(
                        div()
                            .w(px(70.))
                            .flex_none()
                            .text_color(rgb(C::MUTED))
                            .child(format!("{:>8.1}", l.t_ms)),
                    )
                    .child(
                        div()
                            .w(px(14.))
                            .flex_none()
                            .text_color(rgb(if l.outgoing { C::ACCENT } else { C::GREEN }))
                            .child(if l.outgoing { "→" } else { "←" }),
                    )
                    .child(div().flex_1().min_w_0().child(l.text.clone()))
            }))
            .when(!r.offers.is_empty(), |d| {
                d.child(div().pt_3().child(section_title("Offers")))
                    .children(r.offers.iter().enumerate().map(|(i, o)| {
                        let vendor = o.server_mac.as_deref().and_then(crate::netinfo::mac_vendor);
                        div()
                            .flex()
                            .flex_col()
                            .p_2()
                            .rounded_md()
                            .bg(if r.chosen == Some(i) {
                                alpha(C::GREEN, 0.10)
                            } else {
                                rgb(C::BG).into()
                            })
                            .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(format!(
                                "{} offered by {} in {:.0} ms",
                                o.ip, o.server, o.ms
                            )))
                            .child(label(format!(
                                "{}{}{}",
                                o.server_mac.clone().unwrap_or_default(),
                                vendor.map(|v| format!(" ({v})")).unwrap_or_default(),
                                if r.chosen == Some(i) {
                                    " — accepted"
                                } else {
                                    ""
                                }
                            )))
                            .child(label(
                                [
                                    o.msg.subnet_mask.map(|m| format!("mask {m}")),
                                    (!o.msg.routers.is_empty())
                                        .then(|| format!("router {}", o.msg.routers[0])),
                                    (!o.msg.dns.is_empty()).then(|| {
                                        format!(
                                            "DNS {}",
                                            o.msg
                                                .dns
                                                .iter()
                                                .map(|d| d.to_string())
                                                .collect::<Vec<_>>()
                                                .join(", ")
                                        )
                                    }),
                                    o.msg
                                        .lease_secs
                                        .map(|l| format!("lease {}", dhcp::duration(l))),
                                ]
                                .into_iter()
                                .flatten()
                                .collect::<Vec<_>>()
                                .join(" · "),
                            ))
                    }))
            })
            .when_some(r.ack.as_ref(), |d, m| {
                d.child(div().pt_3().child(section_title("ACK options")))
                    .child(kv_row("Your IP", m.yiaddr.to_string(), 190.))
                    .child(kv_row("Next server", m.siaddr.to_string(), 190.))
                    .when(!m.giaddr.is_unspecified(), |d| {
                        d.child(kv_row("Relay agent", m.giaddr.to_string(), 190.))
                    })
                    .children(
                        m.options.iter().map(|o| {
                            kv_row(format!("{} {}", o.code, o.name), o.value.clone(), 190.)
                        }),
                    )
            })
            .when_some(r.inform.as_ref(), |d, i| {
                d.child(div().pt_3().child(section_title("DHCPINFORM")))
                    .child(match i {
                        Ok((ms, m)) => div()
                            .flex()
                            .flex_col()
                            .child(format!("answered in {ms:.0} ms"))
                            .children(m.options.iter().map(|o| {
                                kv_row(format!("{} {}", o.code, o.name), o.value.clone(), 190.)
                            })),
                        Err(e) => div().text_color(rgb(C::MUTED)).child(e.clone()),
                    })
            })
    }
}

impl Focusable for DhcpClientView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for DhcpClientView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.handle.is_some();
        let findings = if running {
            Vec::new()
        } else {
            dhcp_client::findings(&self.runs)
        };
        let ifaces = self.ifaces.as_ref().map(|l| l.as_slice()).unwrap_or(&[]);
        let random = self.mac.read(cx).value.trim().is_empty();
        let leaves_leases = !self.run_cfg.release && (self.repeat > 1 || random);
        let totals: Vec<Option<f32>> = self
            .runs
            .iter()
            .map(|r| r.total_ms.map(|v| v as f32))
            .collect();
        let copy = {
            let mut t = String::new();
            for r in &self.runs {
                t.push_str(&format!(
                    "run {} {} offer {} ack {} total {} — {}\n",
                    r.run,
                    r.mac,
                    opt_ms(r.first_offer_ms()),
                    opt_ms(r.ack_ms),
                    opt_ms(r.total_ms),
                    r.summary()
                ));
            }
            t + &findings_text(&findings)
        };
        let ok = self.runs.iter().filter(|r| r.ok()).count();
        let table = div()
            .flex()
            .flex_col()
            .rounded_md()
            .border_1()
            .border_color(rgb(C::BORDER))
            .overflow_hidden()
            .child(table_header(&[
                ("RUN", 50.),
                ("TEST MAC", 160.),
                ("SERVER", 130.),
                ("OFFERS", 70.),
                ("OFFER", 80.),
                ("ACK", 80.),
                ("TOTAL", 90.),
                ("RESULT", 0.),
            ]))
            .children(self.runs.iter().enumerate().map(|(i, r)| {
                let color = if r.ok() {
                    C::GREEN
                } else if r.finished {
                    C::RED
                } else {
                    C::MUTED
                };
                div()
                    .id(("dhcpc-row", i))
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(30.))
                    .text_sm()
                    .cursor_pointer()
                    .bg(rgb(if self.selected == Some(i) {
                        C::SELECT
                    } else if i % 2 == 1 {
                        C::ROW_ALT
                    } else {
                        C::BG
                    }))
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .on_click(act(&view, move |t: &mut Self, _, _| t.selected = Some(i)))
                    .child(cell(50., r.run.to_string()))
                    .child(cell(160., r.mac.clone()).font_family(mono()))
                    .child(cell(
                        130.,
                        r.chosen
                            .and_then(|c| r.offers.get(c))
                            .map(|o| o.server.to_string())
                            .unwrap_or_default(),
                    ))
                    .child(cell(70., r.offers.len().to_string()))
                    .child(cell(80., opt_ms(r.first_offer_ms())))
                    .child(cell(80., opt_ms(r.ack_ms)))
                    .child(cell(90., opt_ms(r.total_ms)))
                    .child(cell(0., r.summary()).text_color(rgb(color)))
            }));
        let body = if self.runs.is_empty() {
            empty_state(
                if running { "Starting…" } else { "No test yet" },
                "Pick the interface and press Run. Offers are collected for 1 s, the first is accepted, the address is ARP-checked and then released.",
            )
            .into_any_element()
        } else {
            div()
                .flex()
                .flex_row()
                .flex_1()
                .min_h_0()
                .child(
                    div()
                        .id("dhcpc-main")
                        .flex_1()
                        .min_w_0()
                        .p_4()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .overflow_y_scroll()
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap_3()
                                .child(tile(
                                    "Leases",
                                    format!("{ok} / {}", self.runs.len()),
                                    if ok == self.runs.len() {
                                        C::GREEN
                                    } else {
                                        C::AMBER
                                    },
                                ))
                                .child(tile(
                                    "First OFFER",
                                    opt_ms(self.runs.last().and_then(|r| r.first_offer_ms())),
                                    C::TEXT,
                                ))
                                .child(tile(
                                    "REQUEST → ACK",
                                    opt_ms(self.runs.last().and_then(|r| r.ack_ms)),
                                    C::TEXT,
                                ))
                                .child(tile(
                                    "Servers",
                                    {
                                        let mut s: Vec<Ipv4Addr> = self
                                            .runs
                                            .iter()
                                            .flat_map(|r| r.offers.iter().map(|o| o.server))
                                            .collect();
                                        s.sort();
                                        s.dedup();
                                        s.len().to_string()
                                    },
                                    C::TEXT,
                                )),
                        )
                        .child(table)
                        .when(self.runs.len() > 1, |d| {
                            d.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(section_title("Full exchange time per run"))
                                    .child(bar_chart(&totals, 600., 70., 0.0, C::ACCENT)),
                            )
                        })
                        .when(!findings.is_empty(), |d| d.child(findings_cards(&findings))),
                )
                .when_some(self.selected.and_then(|i| self.runs.get(i)), |d, r| {
                    d.child(self.detail(r))
                })
                .into_any_element()
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
                            ("dhcpc-if", i),
                            if cfg!(windows) && !f.desc.is_empty() {
                                f.desc.clone()
                            } else {
                                f.name.clone()
                            },
                            self.iface == Some(i),
                            act(&view, move |t: &mut Self, _, _| {
                                if t.handle.is_none() {
                                    t.iface = Some(i)
                                }
                            }),
                        )
                    }))
                    .child(label("Test MAC"))
                    .child(self.mac.clone())
                    .child(label("Request IP"))
                    .child(self.request.clone())
                    .child(chip(
                        "dhcpc-rel",
                        "Release",
                        self.run_cfg.release,
                        act(&view, |t: &mut Self, _, _| t.run_cfg.release = !t.run_cfg.release),
                    ))
                    .child(chip(
                        "dhcpc-arp",
                        "ARP check",
                        self.run_cfg.arp_check,
                        act(&view, |t: &mut Self, _, _| {
                            t.run_cfg.arp_check = !t.run_cfg.arp_check
                        }),
                    ))
                    .child(chip(
                        "dhcpc-inf",
                        "INFORM",
                        self.run_cfg.inform,
                        act(&view, |t: &mut Self, _, _| t.run_cfg.inform = !t.run_cfg.inform),
                    ))
                    .child(label("Runs"))
                    .children([1u32, 3, 5, 10].into_iter().map(|n| {
                        chip(
                            ("dhcpc-n", n as usize),
                            n.to_string(),
                            self.repeat == n,
                            act(&view, move |t: &mut Self, _, _| t.repeat = n),
                        )
                    }))
                    .child(if running {
                        button("dhcpc-go", "■ Stop", C::RED, C::RED_HOVER, act(&view, |t: &mut Self, _, _| t.stop()))
                    } else {
                        button_primary("dhcpc-go", "▶ Run", act(&view, |t: &mut Self, _, cx| t.run(cx)))
                    })
                    .child(copy_button("dhcpc-copy", copy)),
            )
            .when(leaves_leases, |d| {
                d.child(
                    div()
                        .px_5()
                        .py_2()
                        .text_sm()
                        .bg(alpha(C::AMBER, 0.12))
                        .text_color(rgb(C::AMBER))
                        .child("Release is off: every run with a new MAC keeps an address until its lease expires and can exhaust a small pool."),
                )
            })
            .when_some(self.error.clone(), |d, e| {
                d.child(
                    div()
                        .px_5()
                        .py_2()
                        .text_sm()
                        .bg(alpha(C::RED, 0.12))
                        .text_color(rgb(C::RED))
                        .child(e),
                )
            })
            .child(body)
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
