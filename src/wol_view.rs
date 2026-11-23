//! Wake-on-LAN tool: send magic packets, save devices, confirm wake-up.

use std::net::IpAddr;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::settings::{self, WolDevice};
use crate::ui::ScannerView;
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, input, label,
    mono, section_title, status_bar, tip,
};

pub struct WolView {
    focus: FocusHandle,
    lan: Entity<ScannerView>,
    name: Entity<TextInput>,
    mac: Entity<TextInput>,
    target: Entity<TextInput>,
    port: u16,
    password: Entity<TextInput>,
    verify_ip: Entity<TextInput>,
    broadcasts: Vec<(String, std::net::Ipv4Addr)>,
    devices: Vec<WolDevice>,
    waiting: Option<(Receiver<Option<Duration>>, Instant, String)>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl WolView {
    pub fn new(lan: Entity<ScannerView>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let broadcasts = crate::wol::broadcast_addresses();
        let default_target = broadcasts
            .first()
            .map(|(_, b)| b.to_string())
            .unwrap_or_else(|| "255.255.255.255".into());
        let send = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.send(cx);
        Self {
            focus: cx.focus_handle(),
            lan,
            name: input(
                window,
                cx,
                "",
                "optional, e.g. Workshop PC",
                Accept::Any,
                |t| t.width(220.),
                send,
            ),
            mac: input(
                window,
                cx,
                "",
                "AA:BB:CC:DD:EE:FF",
                Accept::Any,
                |t| t.width(200.).max_len(20).mono(),
                send,
            ),
            target: input(
                window,
                cx,
                &default_target,
                "broadcast or host address",
                Accept::Any,
                |t| t.width(200.),
                send,
            ),
            port: 9,
            password: input(
                window,
                cx,
                "",
                "optional",
                Accept::Any,
                |t| t.width(200.).mono(),
                send,
            ),
            verify_ip: input(
                window,
                cx,
                "",
                "optional: device IP to ping",
                Accept::Any,
                |t| t.width(200.),
                send,
            ),
            broadcasts,
            devices: settings::get().wol_devices,
            waiting: None,
            status: "Enter the device's MAC address and press Wake.".into(),
            error: None,
            _poll: None,
        }
    }

    fn fill(&mut self, d: &WolDevice, cx: &mut Context<Self>) {
        self.name.update(cx, |t, cx| t.set(d.name.clone(), cx));
        self.mac.update(cx, |t, cx| t.set(d.mac.clone(), cx));
        if !d.target.is_empty() {
            self.target.update(cx, |t, cx| t.set(d.target.clone(), cx));
        }
        self.verify_ip.update(cx, |t, cx| t.set(d.ip.clone(), cx));
        if d.port != 0 {
            self.port = d.port;
        }
    }

    fn current(&self, cx: &App) -> WolDevice {
        WolDevice {
            name: self.name.read(cx).value.trim().to_string(),
            mac: self.mac.read(cx).value.trim().to_string(),
            target: self.target.read(cx).value.trim().to_string(),
            port: self.port,
            ip: self.verify_ip.read(cx).value.trim().to_string(),
        }
    }

    fn send(&mut self, cx: &mut Context<Self>) {
        let d = self.current(cx);
        let Some(mac) = crate::dhcp::parse_mac(&d.mac) else {
            self.error = Some("Enter a valid MAC address (12 hex digits)".into());
            return;
        };
        let target: IpAddr = match d.target.parse() {
            Ok(t) => t,
            Err(_) => {
                self.error = Some("Enter a broadcast or host IP address as target".into());
                return;
            }
        };
        let pw = match crate::wol::parse_password(&self.password.read(cx).value) {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        match crate::wol::send(mac, &pw, target, d.port) {
            Ok(n) => {
                self.error = None;
                self.status = format!(
                    "Magic packet ({n} bytes) sent to {target}:{} for {}",
                    d.port,
                    d.mac.to_uppercase()
                )
                .into();
            }
            Err(e) => {
                self.error = Some(e);
                return;
            }
        }
        if let Ok(ip) = d.ip.parse::<IpAddr>() {
            self.verify(ip, cx);
        }
    }

    /// Ping the device every 2 s for up to 3 minutes.
    fn verify(&mut self, ip: IpAddr, cx: &mut Context<Self>) {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            let start = Instant::now();
            let up = rt.block_on(async {
                while start.elapsed() < Duration::from_secs(180) {
                    if let crate::traceroute::ProbeResult::Reached(_) =
                        crate::traceroute::probe(ip, 64, Duration::from_secs(1)).await
                    {
                        return Some(start.elapsed());
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                None
            });
            let _ = tx.send(up);
        });
        self.waiting = Some((rx, Instant::now(), ip.to_string()));
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(500))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some((rx, started, ip)) = &self.waiting else {
            return false;
        };
        match rx.try_recv() {
            Ok(Some(t)) => {
                self.status =
                    format!("{ip} is awake — answered after {:.0} s", t.as_secs_f32()).into();
                self.waiting = None;
            }
            Ok(None) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.status = format!(
                    "{ip} did not answer within 3 minutes. Check that WoL is enabled in BIOS/UEFI and the OS, and that the target reaches the device's subnet."
                )
                .into();
                self.waiting = None;
            }
            Err(_) => {
                self.status = format!(
                    "Waiting for {ip} to wake… {:.0} s",
                    started.elapsed().as_secs_f32()
                )
                .into();
            }
        }
        cx.notify();
        self.waiting.is_some()
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let mut d = self.current(cx);
        if crate::dhcp::parse_mac(&d.mac).is_none() {
            self.error = Some("Enter a valid MAC address before saving".into());
            return;
        }
        if d.name.is_empty() {
            d.name = d.mac.to_uppercase();
        }
        self.devices.retain(|x| !x.mac.eq_ignore_ascii_case(&d.mac));
        self.devices.push(d);
        self.devices.sort_by_key(|d| d.name.to_lowercase());
        self.persist();
    }

    fn persist(&mut self) {
        let list = self.devices.clone();
        match settings::update(|s| s.wol_devices = list) {
            Ok(()) => self.status = "Saved devices updated".into(),
            Err(e) => self.error = Some(format!("Could not save: {e}")),
        }
    }
}

impl Focusable for WolView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for WolView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let scanned = self.lan.read(cx).known_macs();
        let row = || div().flex().flex_wrap().items_center().gap_2();
        let form = div()
            .flex()
            .flex_col()
            .gap_3()
            .p_5()
            .w(px(560.))
            .flex_none()
            .h_full()
            .border_r_1()
            .border_color(rgb(C::BORDER))
            .bg(rgb(C::PANEL))
            .child(section_title("Device"))
            .child(row().child(label("Name").w(px(90.))).child(self.name.clone()))
            .child(row().child(label("MAC address").w(px(90.))).child(self.mac.clone()))
            .child(
                row()
                    .child(label("Send to").w(px(90.)))
                    .child(self.target.clone())
                    .children(self.broadcasts.iter().enumerate().map(|(i, (n, b))| {
                        let b = b.to_string();
                        let target = self.target.clone();
                        chip(("bc", i), format!("{n} {b}"), self.target.read(cx).value == b, move |_, _, cx| {
                            target.update(cx, |t, cx| t.set(b.clone(), cx))
                        })
                    }))
                    .child({
                        let target = self.target.clone();
                        chip("bc-all", "255.255.255.255", self.target.read(cx).value == "255.255.255.255", move |_, _, cx| {
                            target.update(cx, |t, cx| t.set("255.255.255.255", cx))
                        })
                    }),
            )
            .child(
                row()
                    .child(label("UDP port").w(px(90.)))
                    .children([9u16, 7].map(|p| {
                        chip(("port", p as usize), p.to_string(), self.port == p, act(&view, move |t: &mut Self, _, _| t.port = p))
                    })),
            )
            .child(
                row()
                    .child(label("SecureOn").w(px(90.)))
                    .child(self.password.clone())
                    .child(label("password, if the NIC needs one")),
            )
            .child(row().child(label("Confirm by ping").w(px(90.))).child(self.verify_ip.clone()))
            .child(
                row()
                    .child(button_primary("wol-send", "⏻ Wake", act(&view, |t: &mut Self, _, cx| t.send(cx))))
                    .child(button2("wol-save", "Save device", act(&view, |t: &mut Self, _, cx| t.save(cx)))),
            )
            .child(div().text_xs().text_color(rgb(C::MUTED)).child(
                "To wake a device on another subnet, send to that subnet's broadcast (router must forward directed broadcasts) or to the device's IP if the router keeps its ARP entry.",
            ));

        let saved = div()
            .flex()
            .flex_col()
            .gap_1()
            .child(section_title(&format!(
                "Saved devices ({})",
                self.devices.len()
            )))
            .when(self.devices.is_empty(), |d| {
                d.child(
                    div()
                        .text_sm()
                        .text_color(rgb(C::MUTED))
                        .child("None yet. Fill in the form and press Save device."),
                )
            })
            .children(self.devices.iter().enumerate().map(|(i, d)| {
                let (d1, d2) = (d.clone(), d.clone());
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                    .text_sm()
                    .child(cell(200., d.name.clone()))
                    .child(cell(170., d.mac.to_uppercase()).font_family(mono()))
                    .child(cell(150., d.target.clone()).text_color(rgb(C::MUTED)))
                    .child(div().flex_1())
                    .child(button_primary(
                        ("wake", i),
                        "Wake",
                        act(&view, move |t: &mut Self, _, cx| {
                            t.fill(&d1, cx);
                            t.send(cx);
                        }),
                    ))
                    .child(button2(
                        ("edit", i),
                        "Edit",
                        act(&view, move |t: &mut Self, _, cx| t.fill(&d2, cx)),
                    ))
                    .child(
                        button(
                            ("del", i),
                            "✕",
                            C::PANEL2,
                            C::RED,
                            act(&view, move |t: &mut Self, _, _| {
                                t.devices.remove(i);
                                t.persist();
                            }),
                        )
                        .tooltip(tip("Delete")),
                    )
            }));

        let from_scan = div()
            .flex()
            .flex_col()
            .gap_1()
            .child(section_title(&format!("From the last LAN scan ({})", scanned.len())))
            .when(scanned.is_empty(), |d| {
                d.child(div().text_sm().text_color(rgb(C::MUTED)).child("Run a LAN Scan first to pick devices here (they must be on to learn their MAC)."))
            })
            .children(scanned.into_iter().take(200).enumerate().map(|(i, (ip, mac, name))| {
                let dev = WolDevice {
                    name: name.clone().unwrap_or_default(),
                    mac: mac.clone(),
                    target: String::new(),
                    port: 0,
                    ip: ip.to_string(),
                };
                div()
                    .id(("scan", i))
                    .flex()
                    .items_center()
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .text_sm()
                    .child(cell(140., ip.to_string()).font_family(mono()))
                    .child(cell(170., mac).font_family(mono()))
                    .child(cell(0., name.unwrap_or_default()).text_color(rgb(C::MUTED)))
                    .on_click(act(&view, move |t: &mut Self, _, cx| t.fill(&dev, cx)))
            }));

        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .child(e)
            }))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(form)
                    .child(
                        div()
                            .id("wol-lists")
                            .flex_1()
                            .min_w_0()
                            .p_5()
                            .flex()
                            .flex_col()
                            .gap_5()
                            .overflow_y_scroll()
                            .child(saved)
                            .child(from_scan),
                    ),
            )
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
