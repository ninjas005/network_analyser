//! PROFINET tool: DCP Identify All, device table and detail, DCP Set
//! NameOfStation / IP and Signal (with confirmation), and passive watching
//! of DCP, PN-RT cyclic, alarm and LLDP frames.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::capture::{self, CaptureEvent, CaptureHandle, Interface};
use crate::profinet::{self as pn, Device, Devices};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, copy_button,
    empty_state, input, kv_row, label, mono, section_title, status_bar, table_header, tip, toolbar,
};

#[derive(Clone, Debug)]
enum Pending {
    Name {
        mac: [u8; 6],
        name: String,
        permanent: bool,
    },
    Ip {
        mac: [u8; 6],
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gw: Ipv4Addr,
        permanent: bool,
    },
}

impl Pending {
    fn describe(&self) -> String {
        match self {
            Pending::Name {
                mac,
                name,
                permanent,
            } => format!(
                "Set NameOfStation of {} to \"{name}\" ({})?",
                pn::mac_str(mac),
                if *permanent { "permanent" } else { "temporary" }
            ),
            Pending::Ip {
                mac,
                ip,
                mask,
                gw,
                permanent,
            } => format!(
                "Set IP of {} to {ip} / {mask}, gateway {gw} ({})? A running IO connection may drop.",
                pn::mac_str(mac),
                if *permanent { "permanent" } else { "temporary" }
            ),
        }
    }
}

pub struct ProfinetView {
    focus: FocusHandle,
    ifaces: Result<Vec<Interface>, String>,
    iface: Option<usize>,
    own_mac: Option<[u8; 6]>,
    handle: Option<CaptureHandle>,
    devs: Devices,
    xids: Vec<u32>,
    identify_at: Option<Instant>,
    sets: Vec<(u32, String)>,
    selected: Option<[u8; 6]>,
    name_in: Entity<TextInput>,
    ip_in: Entity<TextInput>,
    mask_in: Entity<TextInput>,
    gw_in: Entity<TextInput>,
    permanent: bool,
    pending: Option<Pending>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl ProfinetView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ifaces = capture::interfaces().map(|l| {
            l.into_iter()
                .filter(|i| i.up && !i.loopback && !i.name.starts_with("veth"))
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
        let mk = |cx: &mut Context<Self>, window: &mut Window, ph: &str, w: f32, acc: Accept| {
            input(
                window,
                cx,
                "",
                ph,
                acc,
                |t| t.width(w).max_len(240),
                |_: &mut Self, _, _| {},
            )
        };
        let name_in = mk(cx, window, "new-station-name", 220., Accept::Any);
        let ip_in = mk(cx, window, "192.168.0.10", 130., Accept::Range);
        let mask_in = mk(cx, window, "255.255.255.0", 130., Accept::Range);
        let gw_in = mk(cx, window, "0.0.0.0", 130., Accept::Range);
        let mut v = Self {
            focus: cx.focus_handle(),
            error: ifaces.as_ref().err().cloned(),
            ifaces,
            iface,
            own_mac: None,
            handle: None,
            devs: Devices::default(),
            xids: Vec::new(),
            identify_at: None,
            sets: Vec::new(),
            selected: None,
            name_in,
            ip_in,
            mask_in,
            gw_in,
            permanent: true,
            pending: None,
            status: "Press Identify All to find PROFINET devices, or Listen to watch DCP, RT and LLDP traffic.".into(),
            _poll: None,
        };
        v.own_mac = v.current().as_ref().and_then(pn::iface_mac);
        v
    }

    fn current(&self) -> Option<Interface> {
        self.iface
            .and_then(|i| self.ifaces.as_ref().ok()?.get(i).cloned())
    }

    fn listen(&mut self, cx: &mut Context<Self>) -> bool {
        if self.handle.is_some() {
            return true;
        }
        let Some(iface) = self.current() else {
            self.error = Some("Select an interface".into());
            return false;
        };
        self.own_mac = pn::iface_mac(&iface);
        self.error = None;
        self.handle = Some(pn::start_capture(&iface.name));
        self.status = format!("Listening on {}…", iface.label()).into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                match this.update(cx, |t, cx| t.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
        true
    }

    fn stop(&mut self) {
        if let Some(h) = &self.handle {
            h.stop();
        }
    }

    fn inject(&mut self, frame: Vec<u8>) {
        if let Some(h) = &self.handle {
            h.inject(frame);
        }
    }

    fn identify(&mut self, cx: &mut Context<Self>) {
        if !self.listen(cx) {
            return;
        }
        let Some(mac) = self.own_mac else {
            self.error = Some("Could not read this interface's MAC address".into());
            return;
        };
        let xid = pn::new_xid();
        self.xids.push(xid);
        self.inject(pn::identify_all(mac, xid));
        self.identify_at = Some(Instant::now());
        self.status = "Identify All sent — waiting for responses…".into();
    }

    fn signal(&mut self, dev: [u8; 6], cx: &mut Context<Self>) {
        if !self.listen(cx) {
            return;
        }
        let Some(mac) = self.own_mac else { return };
        let xid = pn::new_xid();
        self.sets.push((xid, "Signal".into()));
        self.inject(pn::signal(mac, dev, xid));
        self.status = format!(
            "Signal sent to {} — its LED should flash",
            pn::mac_str(&dev)
        )
        .into();
    }

    fn prepare_name(&mut self, dev: [u8; 6], cx: &mut Context<Self>) {
        let name = self.name_in.read(cx).value.trim().to_string();
        if let Err(e) = pn::validate_name(&name) {
            self.error = Some(format!("Name of station: {e}"));
            return;
        }
        self.error = None;
        self.pending = Some(Pending::Name {
            mac: dev,
            name,
            permanent: self.permanent,
        });
    }

    fn prepare_ip(&mut self, dev: [u8; 6], cx: &mut Context<Self>) {
        let p = |e: &Entity<TextInput>| e.read(cx).value.trim().parse::<Ipv4Addr>();
        let (Ok(ip), Ok(mask)) = (p(&self.ip_in), p(&self.mask_in)) else {
            self.error = Some("Enter a valid IP address and subnet mask".into());
            return;
        };
        let gw = p(&self.gw_in).unwrap_or(Ipv4Addr::UNSPECIFIED);
        let m = u32::from(mask);
        if m.leading_ones() + m.trailing_zeros() != 32 {
            self.error = Some("The subnet mask is not contiguous".into());
            return;
        }
        self.error = None;
        self.pending = Some(Pending::Ip {
            mac: dev,
            ip,
            mask,
            gw,
            permanent: self.permanent,
        });
    }

    fn confirm(&mut self, cx: &mut Context<Self>) {
        let Some(p) = self.pending.take() else { return };
        if !self.listen(cx) {
            return;
        }
        let Some(me) = self.own_mac else { return };
        let xid = pn::new_xid();
        let (frame, what) = match &p {
            Pending::Name {
                mac,
                name,
                permanent,
            } => (
                pn::set_name(me, *mac, xid, name, *permanent),
                format!("Set name \"{name}\""),
            ),
            Pending::Ip {
                mac,
                ip,
                mask,
                gw,
                permanent,
            } => (
                pn::set_ip(me, *mac, xid, *ip, *mask, *gw, *permanent),
                format!("Set IP {ip}"),
            ),
        };
        self.sets.push((xid, what.clone()));
        self.inject(frame);
        self.status = format!("{what}: sent, waiting for the device's answer…").into();
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(h) = &self.handle else { return false };
        let own = self.own_mac.unwrap_or([0; 6]);
        let mut stopped = None;
        let mut set_results = Vec::new();
        while let Ok(ev) = h.events.try_recv() {
            match ev {
                CaptureEvent::Packets(ps) => {
                    for p in ps {
                        if let Some(f) = pn::parse_frame(&p.data)
                            && let Some(r) = self.devs.apply(&f, p.ts, own, &self.xids)
                        {
                            set_results.push(r);
                        }
                    }
                }
                CaptureEvent::InjectFailed(e) => self.error = Some(format!("Could not send: {e}")),
                CaptureEvent::Stopped(e) => stopped = Some(e),
                _ => {}
            }
        }
        for r in set_results {
            if let Some((_, what)) = self.sets.iter().find(|(x, _)| *x == r.xid) {
                let msg = format!("{what} on {}: {}", pn::mac_str(&r.from), r.describe());
                if r.ok() {
                    self.status = msg.into();
                    // Refresh the device's data.
                    if let Some(me) = self.own_mac {
                        let xid = pn::new_xid();
                        self.xids.push(xid);
                        if let Some(h) = &self.handle {
                            h.inject(pn::identify_all(me, xid));
                        }
                    }
                } else {
                    self.error = Some(msg);
                }
            }
        }
        if let Some(at) = self.identify_at
            && at.elapsed() > Duration::from_secs(3)
        {
            self.identify_at = None;
            let n = self
                .devs
                .map
                .values()
                .filter(|d| d.answered_identify)
                .count();
            self.status = format!("{n} device(s) answered Identify All").into();
            if self.selected.is_none() {
                self.selected = self
                    .devs
                    .map
                    .values()
                    .find(|d| d.answered_identify)
                    .map(|d| d.mac);
            }
        }
        if let Some(e) = stopped {
            self.handle = None;
            if let Some(e) = e {
                self.error = Some(match capture::permission_hint(&e) {
                    Some(h) => format!("{e}\n{h}"),
                    None => e,
                });
                self.status = "Capture failed".into();
            } else {
                self.status = format!("Stopped — {} PROFINET/LLDP frames", self.devs.frames).into();
            }
            cx.notify();
            return false;
        }
        cx.notify();
        true
    }

    fn render_detail(&self, d: &Device, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let mac = d.mac;
        let kw = 150.;
        div()
            .id("pn-detail")
            .w(px(500.))
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
            .child(section_title(&format!("Device {}", pn::mac_str(&d.mac))))
            .child(kv_row("Name of station", d.name.clone(), kw))
            .when(!d.alias.is_empty(), |e| e.child(kv_row("Alias", d.alias.clone(), kw)))
            .child(kv_row("Type of station", d.station_type.clone(), kw))
            .child(kv_row("Vendor", d.vendor(), kw))
            .child(kv_row(
                "Device ID",
                d.device_id.map(|v| format!("{v:#06x}")).unwrap_or_default(),
                kw,
            ))
            .when_some(d.oem, |e, (v, i)| e.child(kv_row("OEM ID", format!("{v:#06x} / {i:#06x}"), kw)))
            .child(kv_row("Role", d.role.map(pn::role_str).unwrap_or_default(), kw))
            .when_some(d.instance, |e, (h, l)| e.child(kv_row("Instance", format!("{h}.{l}"), kw)))
            .child(kv_row("MAC vendor", crate::netinfo::mac_vendor(&pn::mac_str(&d.mac)).unwrap_or_default(), kw))
            .child(kv_row("IP address", d.ip.map(|i| i.to_string()).unwrap_or_default(), kw))
            .child(kv_row("Subnet mask", d.mask.map(|i| i.to_string()).unwrap_or_default(), kw))
            .child(kv_row("Gateway", d.gw.map(|i| i.to_string()).unwrap_or_default(), kw))
            .when_some(d.ip_info, |e, i| {
                e.child(
                    div()
                        .flex()
                        .gap_2()
                        .child(div().w(px(kw)).flex_none().text_color(rgb(C::MUTED)).child("IP state"))
                        .child(div().text_color(rgb(if i & 0x80 != 0 { C::RED } else { C::TEXT })).child(pn::ip_info_str(i))),
                )
            })
            .when_some(d.vlan, |e, v| e.child(kv_row("VLAN", v.to_string(), kw)))
            .when(!d.options.is_empty(), |e| {
                e.child(kv_row(
                    "Supported options",
                    d.options
                        .iter()
                        .map(|(o, s)| pn::block_name(*o, *s))
                        .filter(|n| *n != "unknown")
                        .collect::<Vec<_>>()
                        .join(", "),
                    kw,
                ))
            })
            .when_some(d.lldp.as_ref(), |e, l| {
                e.child(div().pt_3().child(section_title("LLDP")))
                    .child(kv_row("Chassis", l.chassis.clone(), kw))
                    .child(kv_row("Port", l.port.clone(), kw))
                    .when(!l.port_desc.is_empty(), |e| e.child(kv_row("Port description", l.port_desc.clone(), kw)))
                    .when(!l.sys_name.is_empty(), |e| e.child(kv_row("System name", l.sys_name.clone(), kw)))
                    .when(!l.sys_desc.is_empty(), |e| e.child(kv_row("System description", l.sys_desc.clone(), kw)))
                    .when_some(l.mgmt_ip, |e, ip| e.child(kv_row("Management IP", ip.to_string(), kw)))
                    .child(kv_row("TTL", format!("{} s", l.ttl), kw))
            })
            .when(!d.rt.is_empty(), |e| {
                e.child(div().pt_3().child(section_title("Real-time frames sent")))
                    .children(d.rt.iter().map(|(fid, s)| {
                        div()
                            .flex()
                            .flex_col()
                            .py_1()
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .child(div().font_family(mono()).text_color(rgb(C::ACCENT)).child(format!("{fid:#06x}")))
                                    .child(pn::classify(*fid))
                                    .child(div().text_color(rgb(C::MUTED)).child(format!(
                                        "{} frames · {} · {} bytes → {}",
                                        s.count,
                                        s.interval_ms().map(|m| format!("every {m:.2} ms")).unwrap_or_default(),
                                        s.len,
                                        pn::mac_str(&s.dst)
                                    ))),
                            )
                            .child(div().text_xs().text_color(rgb(if s.data_status & 0x14 == 0x14 { C::GREEN } else { C::AMBER })).child(pn::data_status_str(s.data_status)))
                    }))
            })
            .when(d.alarms > 0, |e| e.child(kv_row("Alarms seen", d.alarms.to_string(), kw)))
            .child(div().pt_3().child(section_title("Commissioning (DCP Set)")))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(button2("pn-signal", "Flash LED", act(&view, move |t: &mut Self, _, cx| t.signal(mac, cx))).tooltip(tip("DCP Signal: the device flashes its identification LED so you can find it in the cabinet.")))
                    .child(chip("pn-perm", "Permanent", self.permanent, act(&view, |t: &mut Self, _, _| t.permanent = true)).tooltip(tip("Stored in the device and kept after a power cycle.")))
                    .child(chip("pn-temp", "Temporary", !self.permanent, act(&view, |t: &mut Self, _, _| t.permanent = false)).tooltip(tip("Lost at the next power cycle."))),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(label("Name"))
                    .child(self.name_in.clone())
                    .child(button2("pn-setname", "Set name…", act(&view, move |t: &mut Self, _, cx| t.prepare_name(mac, cx)))),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .items_center()
                    .child(label("IP"))
                    .child(self.ip_in.clone())
                    .child(label("Mask"))
                    .child(self.mask_in.clone())
                    .child(label("Gateway"))
                    .child(self.gw_in.clone())
                    .child(button2("pn-setip", "Set IP…", act(&view, move |t: &mut Self, _, cx| t.prepare_ip(mac, cx)))),
            )
            .children(self.pending.as_ref().map(|p| {
                div()
                    .mt_2()
                    .p_3()
                    .rounded_md()
                    .bg(alpha(C::AMBER, 0.12))
                    .border_1()
                    .border_color(rgb(C::AMBER))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(div().text_color(rgb(C::AMBER)).child(p.describe()))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(button("pn-confirm", "Confirm", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, cx| t.confirm(cx))))
                            .child(button2("pn-cancel", "Cancel", act(&view, |t: &mut Self, _, _| t.pending = None))),
                    )
            }))
    }
}

impl Focusable for ProfinetView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for ProfinetView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let listening = self.handle.is_some();
        let ifaces = self.ifaces.as_ref().map(|l| l.as_slice()).unwrap_or(&[]);
        let mut list: Vec<&Device> = self.devs.map.values().collect();
        list.sort_by_key(|d| (!d.dcp, d.rt.is_empty(), d.display_name(), d.mac));
        let text = list
            .iter()
            .map(|d| {
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    pn::mac_str(&d.mac),
                    d.display_name(),
                    d.ip.map(|i| i.to_string()).unwrap_or_default(),
                    d.station_type,
                    d.vendor(),
                    d.role.map(pn::role_str).unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let detail = self
            .selected
            .and_then(|m| self.devs.map.get(&m))
            .map(|d| self.render_detail(d, cx).into_any_element());
        let rows = div()
            .id("pn-rows")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .children(list.iter().enumerate().map(|(i, d)| {
                let mac = d.mac;
                let mut src = Vec::new();
                if d.dcp {
                    src.push("DCP");
                }
                if !d.rt.is_empty() {
                    src.push("RT");
                }
                if d.lldp.is_some() {
                    src.push("LLDP");
                }
                let conflict = d.ip_info.is_some_and(|i| i & 0x80 != 0);
                div()
                    .id(("pn-row", i))
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(30.))
                    .text_sm()
                    .cursor_pointer()
                    .bg(rgb(if self.selected == Some(mac) {
                        C::SELECT
                    } else if i % 2 == 1 {
                        C::ROW_ALT
                    } else {
                        C::BG
                    }))
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .on_click(act(&view, move |t: &mut Self, _, _| {
                        t.selected = Some(mac);
                        t.pending = None;
                    }))
                    .child(cell(150., pn::mac_str(&d.mac)).font_family(mono()))
                    .child(cell(200., d.display_name()).text_color(rgb(
                        if d.name.is_empty() && d.dcp {
                            C::AMBER
                        } else {
                            C::TEXT
                        },
                    )))
                    .child(
                        cell(130., d.ip.map(|i| i.to_string()).unwrap_or_default())
                            .text_color(rgb(if conflict { C::RED } else { C::TEXT })),
                    )
                    .child(cell(190., d.station_type.clone()))
                    .child(cell(170., d.vendor()).text_color(rgb(C::MUTED)))
                    .child(cell(120., d.role.map(pn::role_str).unwrap_or_default()))
                    .child(cell(110., src.join(" ")).text_color(rgb(C::CYAN)))
                    .child(
                        cell(
                            0.,
                            d.rt.values()
                                .find_map(|s| s.interval_ms())
                                .map(|m| format!("{m:.2} ms"))
                                .unwrap_or_default(),
                        )
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
                        chip(
                            ("pn-if", i),
                            if cfg!(windows) && !f.desc.is_empty() { f.desc.clone() } else { f.name.clone() },
                            self.iface == Some(i),
                            act(&view, move |t: &mut Self, _, _| {
                                if t.handle.is_none() {
                                    t.iface = Some(i);
                                    t.own_mac = t.current().as_ref().and_then(pn::iface_mac);
                                }
                            }),
                        )
                    }))
                    .child(div().flex_1())
                    .child(if listening {
                        button("pn-listen", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.stop()))
                    } else {
                        button2("pn-listen", "Listen", act(&view, |t: &mut Self, _, cx| {
                            t.listen(cx);
                        }))
                        .tooltip(tip("Watch DCP, PN-RT cyclic, alarm and LLDP frames. Cyclic traffic between other stations is only visible on a mirror port or TAP."))
                    })
                    .child(button_primary("pn-ident", "Identify All", act(&view, |t: &mut Self, _, cx| t.identify(cx))).tooltip(tip(
                        "Send a DCP Identify All multicast; every PROFINET device on this Ethernet segment answers with its name, type, IDs and IP settings.",
                    )))
                    .child(button2("pn-clear", "Clear", act(&view, |t: &mut Self, _, _| {
                        t.devs = Devices::default();
                        t.selected = None;
                    })))
                    .child(copy_button("pn-copy", text)),
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
                            .child(table_header(&[
                                ("MAC", 150.),
                                ("NAME OF STATION", 200.),
                                ("IP", 130.),
                                ("TYPE OF STATION", 190.),
                                ("VENDOR", 170.),
                                ("ROLE", 120.),
                                ("SEEN VIA", 110.),
                                ("CYCLE", 0.),
                            ]))
                            .child(if list.is_empty() {
                                empty_state(
                                    if listening { "No PROFINET devices yet" } else { "Not listening" },
                                    "Identify All needs packet-capture rights (same as the Packet Capture tool).",
                                )
                                .into_any_element()
                            } else {
                                rows.into_any_element()
                            }),
                    )
                    .children(detail),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .child(format!(
                        "{} devices · {} frames{}",
                        self.devs.map.len(),
                        self.devs.frames,
                        self.own_mac.map(|m| format!(" · this host {}", pn::mac_str(&m))).unwrap_or_default()
                    )),
            )
    }
}
