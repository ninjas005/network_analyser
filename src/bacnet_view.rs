//! BACnet/IP tool: Who-Is discovery, device properties, object table
//! (name, present value, units, status) and a manual ReadProperty form.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::bacnet::{self as bn, Cmd, Event, ObjRow, Peer, Worker};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, copy_button,
    empty_state, input, kv_row, label, mono, section_title, status_bar, table_header, tip, toolbar,
};

#[derive(Clone, PartialEq)]
enum Objects {
    NotRead,
    Reading,
    Done(Result<usize, String>),
}

struct Dev {
    peer: Peer,
    props: BTreeMap<u32, Result<String, String>>,
    props_reading: bool,
    objects: Vec<ObjRow>,
    obj_total: Option<usize>,
    obj_state: Objects,
}

impl Dev {
    fn prop(&self, p: u32) -> String {
        match self.props.get(&p) {
            Some(Ok(v)) => v.clone(),
            _ => String::new(),
        }
    }
}

pub struct BacnetView {
    focus: FocusHandle,
    worker: Worker,
    port_47808: Option<bool>,
    target: Entity<TextInput>,
    low: Entity<TextInput>,
    high: Entity<TextInput>,
    obj_in: Entity<TextInput>,
    prop_in: Entity<TextInput>,
    index_in: Entity<TextInput>,
    devs: Vec<Dev>,
    selected: Option<u32>,
    discovering: bool,
    reads: Vec<(String, Result<String, String>)>,
    status: SharedString,
    error: Option<String>,
    _poll: Task<()>,
}

impl BacnetView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let bcast = bn::default_broadcast();
        let poll = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                if this.update(cx, |t, cx| t.drain(cx)).is_err() {
                    break;
                }
            }
        });
        Self {
            focus: cx.focus_handle(),
            worker: bn::start(),
            port_47808: None,
            target: input(
                window,
                cx,
                "",
                &format!("broadcast {bcast} (or a device / BBMD address)"),
                Accept::Any,
                |t| t.width(320.).max_len(120),
                |t: &mut Self, _, cx| t.discover(cx),
            ),
            low: input(
                window,
                cx,
                "",
                "min",
                Accept::Digits,
                |t| t.width(90.).max_len(7),
                |_: &mut Self, _, _| {},
            ),
            high: input(
                window,
                cx,
                "",
                "max",
                Accept::Digits,
                |t| t.width(90.).max_len(7),
                |_: &mut Self, _, _| {},
            ),
            obj_in: input(
                window,
                cx,
                "device",
                "AV,3  or  analog-input 1",
                Accept::Any,
                |t| t.width(190.).max_len(60),
                |t: &mut Self, _, cx| t.manual_read(cx),
            ),
            prop_in: input(
                window,
                cx,
                "object-name",
                "present-value or 85",
                Accept::Any,
                |t| t.width(190.).max_len(60),
                |t: &mut Self, _, cx| t.manual_read(cx),
            ),
            index_in: input(
                window,
                cx,
                "",
                "index",
                Accept::Digits,
                |t| t.width(70.).max_len(6),
                |t: &mut Self, _, cx| t.manual_read(cx),
            ),
            devs: Vec::new(),
            selected: None,
            discovering: false,
            reads: Vec::new(),
            status: "Press Discover to broadcast a Who-Is (UDP 47808). Devices answer with I-Am."
                .into(),
            error: None,
            _poll: poll,
        }
    }

    fn dev(&self, id: u32) -> Option<&Dev> {
        self.devs.iter().find(|d| d.peer.iam.device == id)
    }

    fn dev_mut(&mut self, id: u32) -> Option<&mut Dev> {
        self.devs.iter_mut().find(|d| d.peer.iam.device == id)
    }

    fn discover(&mut self, cx: &mut Context<Self>) {
        if self.discovering {
            return;
        }
        let t = self.target.read(cx).value.trim().to_string();
        let (target, broadcast) = if t.is_empty() {
            (
                SocketAddr::new(IpAddr::V4(bn::default_broadcast()), bn::PORT),
                true,
            )
        } else {
            match bn::parse_target(&t) {
                Ok(a) => {
                    let b =
                        matches!(a.ip(), IpAddr::V4(v) if v.octets()[3] == 255 || v.is_broadcast());
                    (a, b)
                }
                Err(e) => {
                    self.error = Some(e);
                    return;
                }
            }
        };
        let num = |e: &Entity<TextInput>| e.read(cx).value.trim().parse::<u32>().ok();
        let (low, high) = match (num(&self.low), num(&self.high)) {
            (Some(a), Some(b)) if a <= b && b <= 4_194_303 => (Some(a), Some(b)),
            (None, None) => (None, None),
            (Some(a), None) => (Some(a), Some(a)),
            _ => {
                self.error = Some("Device instance range: min ≤ max ≤ 4194303".into());
                return;
            }
        };
        self.error = None;
        self.discovering = true;
        self.worker.send(Cmd::Discover {
            target,
            broadcast,
            low,
            high,
            wait: Duration::from_secs(3),
        });
    }

    fn read_objects(&mut self, id: u32) {
        let Some(d) = self.dev_mut(id) else { return };
        if d.obj_state == Objects::Reading {
            return;
        }
        d.obj_state = Objects::Reading;
        d.objects.clear();
        d.obj_total = None;
        let peer = d.peer.clone();
        self.worker.send(Cmd::ReadObjects(peer));
    }

    fn select(&mut self, id: u32) {
        self.selected = Some(id);
        if self
            .dev(id)
            .is_some_and(|d| d.obj_state == Objects::NotRead)
        {
            self.read_objects(id);
        }
    }

    fn manual_read(&mut self, cx: &mut Context<Self>) {
        let Some(d) = self.selected.and_then(|id| self.dev(id)) else {
            self.error = Some("Select a device first".into());
            return;
        };
        let peer = d.peer.clone();
        let obj = self.obj_in.read(cx).value.trim().to_string();
        let parts: Vec<&str> = obj
            .split([',', ' ', ':'])
            .filter(|s| !s.is_empty())
            .collect();
        let (t, inst) = match parts.as_slice() {
            [t] => match bn::parse_object_type(t) {
                Some(bn::OBJ_DEVICE) => (bn::OBJ_DEVICE, peer.iam.device),
                _ => {
                    self.error = Some("Object: type and instance, e.g. AV,3".into());
                    return;
                }
            },
            [t, i] => match (bn::parse_object_type(t), i.parse::<u32>()) {
                (Some(t), Ok(i)) if i <= 4_194_303 => (t, i),
                _ => {
                    self.error = Some(format!("Unknown object '{obj}'"));
                    return;
                }
            },
            _ => {
                self.error = Some("Object: type and instance, e.g. AV,3".into());
                return;
            }
        };
        let Some(prop) = bn::parse_property(&self.prop_in.read(cx).value) else {
            self.error =
                Some("Unknown property (use a name such as present-value, or a number)".into());
            return;
        };
        let index = self.index_in.read(cx).value.trim().parse::<u32>().ok();
        self.error = None;
        self.worker.send(Cmd::Read {
            peer,
            t,
            inst,
            prop,
            index,
        });
    }

    fn drain(&mut self, cx: &mut Context<Self>) {
        let mut changed = false;
        while let Ok(ev) = self.worker.events.try_recv() {
            changed = true;
            match ev {
                Event::Ready { port_47808 } => self.port_47808 = Some(port_47808),
                Event::Status(s) => self.status = s.into(),
                Event::Device(p) => {
                    let id = p.iam.device;
                    if let Some(d) = self.dev_mut(id) {
                        d.peer = p;
                    } else {
                        self.devs.push(Dev {
                            peer: p.clone(),
                            props: BTreeMap::new(),
                            props_reading: true,
                            objects: Vec::new(),
                            obj_total: None,
                            obj_state: Objects::NotRead,
                        });
                        self.devs.sort_by_key(|d| d.peer.iam.device);
                        self.worker.send(Cmd::ReadDevice(p));
                    }
                }
                Event::DiscoverDone(n) => {
                    self.discovering = false;
                    self.status = match n {
                        0 => "No device answered the Who-Is. BACnet/IP devices on other subnets need a BBMD address as the target.".into(),
                        n => format!("{n} device(s) answered — reading their properties…").into(),
                    };
                    if self.selected.is_none()
                        && let Some(id) = self.devs.first().map(|d| d.peer.iam.device)
                    {
                        self.select(id);
                    }
                }
                Event::DeviceProp(id, prop, r) => {
                    if let Some(d) = self.dev_mut(id) {
                        d.props.insert(prop, r);
                    }
                }
                Event::DevicePropsDone(id) => {
                    if let Some(d) = self.dev_mut(id) {
                        d.props_reading = false;
                    }
                }
                Event::ObjectCount(id, n) => {
                    if let Some(d) = self.dev_mut(id) {
                        d.obj_total = Some(n);
                    }
                }
                Event::Object(id, row) => {
                    if let Some(d) = self.dev_mut(id) {
                        d.objects.push(row);
                    }
                }
                Event::ObjectsDone(id, r) => {
                    self.status = match &r {
                        Ok(n) => format!("Device {id}: {n} objects read"),
                        Err(e) => format!("Device {id}: object-list: {e}"),
                    }
                    .into();
                    if let Some(d) = self.dev_mut(id) {
                        d.obj_state = Objects::Done(r);
                    }
                }
                Event::ReadResult(what, r) => {
                    self.reads.insert(0, (what, r));
                    self.reads.truncate(50);
                }
                Event::Failed(e) => {
                    self.discovering = false;
                    self.error = Some(e);
                }
            }
        }
        if changed {
            cx.notify();
        }
    }

    fn render_detail(&self, d: &Dev, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let id = d.peer.iam.device;
        let kw = 190.;
        let prop_row = |p: u32| {
            let (v, col) = match d.props.get(&p) {
                Some(Ok(v)) => (v.clone(), C::TEXT),
                Some(Err(e)) => (e.clone(), C::MUTED),
                None if d.props_reading => ("…".into(), C::MUTED),
                None => (String::new(), C::MUTED),
            };
            div()
                .flex()
                .gap_2()
                .child(
                    div()
                        .w(px(kw))
                        .flex_none()
                        .text_color(rgb(C::MUTED))
                        .child(bn::property_name(p)),
                )
                .child(div().flex_1().min_w_0().text_color(rgb(col)).child(v))
        };
        let obj_status = match &d.obj_state {
            Objects::NotRead => String::new(),
            Objects::Reading => format!(
                "reading… {}{}",
                d.objects.len(),
                d.obj_total.map(|n| format!(" / {n}")).unwrap_or_default()
            ),
            Objects::Done(Ok(n)) => format!("{n} objects"),
            Objects::Done(Err(e)) => e.clone(),
        };
        div()
            .id("bn-detail")
            .flex_1()
            .min_w_0()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_1()
            .overflow_y_scroll()
            .text_sm()
            .child(section_title(&format!("Device {id}")))
            .child(kv_row("Address", d.peer.addr_str(), kw))
            .child(kv_row(
                "Max APDU (I-Am)",
                d.peer.iam.max_apdu.to_string(),
                kw,
            ))
            .child(kv_row(
                "Segmentation (I-Am)",
                bn::segmentation_name(d.peer.iam.segmentation),
                kw,
            ))
            .child(kv_row(
                "Vendor ID",
                match bn::vendor_name(d.peer.iam.vendor) {
                    Some(n) => format!("{} ({n})", d.peer.iam.vendor),
                    None => d.peer.iam.vendor.to_string(),
                },
                kw,
            ))
            .children(bn::DEVICE_PROPS.iter().map(|&p| prop_row(p)))
            .child(
                div()
                    .pt_3()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(section_title("Objects"))
                    .child(label(obj_status))
                    .child(div().flex_1())
                    .child(button2(
                        "bn-objs",
                        "Re-read objects",
                        act(&view, move |t: &mut Self, _, _| t.read_objects(id)),
                    )),
            )
            .child(table_header(&[
                ("TYPE", 70.),
                ("INSTANCE", 90.),
                ("NAME", 240.),
                ("PRESENT VALUE", 160.),
                ("UNITS", 80.),
                ("STATUS", 0.),
            ]))
            .children(d.objects.iter().enumerate().map(|(i, o)| {
                let (t, inst) = (o.t, o.inst);
                let bad = !o.flags.is_empty() && o.flags != "normal";
                div()
                    .id(("bn-obj", i))
                    .flex()
                    .items_center()
                    .px_3()
                    .h(px(26.))
                    .cursor_pointer()
                    .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let s = format!("{},{inst}", bn::object_type_abbr(t));
                        this.obj_in.update(cx, |e, cx| e.set(s, cx));
                        this.prop_in.update(cx, |e, cx| e.set("present-value", cx));
                        cx.notify();
                    }))
                    .child(cell(70., bn::object_type_abbr(o.t)).text_color(rgb(C::ACCENT)))
                    .child(cell(90., o.inst.to_string()).font_family(mono()))
                    .child(cell(240., o.name.clone()))
                    .child(cell(160., o.value.clone()).font_weight(gpui::FontWeight::SEMIBOLD))
                    .child(cell(80., o.units.clone()).text_color(rgb(C::MUTED)))
                    .child(
                        cell(
                            0.,
                            o.error
                                .clone()
                                .map(|e| format!("{} {e}", o.flags))
                                .unwrap_or(o.flags.clone()),
                        )
                        .text_color(rgb(if bad || o.error.is_some() {
                            C::AMBER
                        } else {
                            C::MUTED
                        })),
                    )
            }))
            .child(div().pt_3().child(section_title("ReadProperty")))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(label("Object"))
                    .child(self.obj_in.clone())
                    .child(label("Property"))
                    .child(self.prop_in.clone())
                    .child(label("Index"))
                    .child(self.index_in.clone())
                    .child(button_primary(
                        "bn-read",
                        "Read",
                        act(&view, |t: &mut Self, _, cx| t.manual_read(cx)),
                    )),
            )
            .children(self.reads.iter().map(|(w, r)| {
                div()
                    .flex()
                    .gap_3()
                    .py_1()
                    .child(
                        div()
                            .w(px(300.))
                            .flex_none()
                            .text_color(rgb(C::MUTED))
                            .child(w.clone()),
                    )
                    .child(match r {
                        Ok(v) => div()
                            .flex_1()
                            .min_w_0()
                            .font_family(mono())
                            .child(v.clone()),
                        Err(e) => div()
                            .flex_1()
                            .min_w_0()
                            .text_color(rgb(C::RED))
                            .child(e.clone()),
                    })
            }))
    }
}

impl Focusable for BacnetView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for BacnetView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let text = self
            .devs
            .iter()
            .flat_map(|d| {
                let mut lines = vec![format!(
                    "device {}\t{}\t{}\t{}\t{}\t{}",
                    d.peer.iam.device,
                    d.peer.addr_str(),
                    d.prop(77),
                    d.prop(121),
                    d.prop(70),
                    d.prop(44)
                )];
                lines.extend(d.objects.iter().map(|o| {
                    format!(
                        "  {}\t{}\t{}\t{} {}\t{}",
                        bn::object_type_abbr(o.t),
                        o.inst,
                        o.name,
                        o.value,
                        o.units,
                        o.flags
                    )
                }));
                lines
            })
            .collect::<Vec<_>>()
            .join("\n");
        let detail = self
            .selected
            .and_then(|id| self.dev(id))
            .map(|d| self.render_detail(d, cx).into_any_element());
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Target"))
                    .child(self.target.clone())
                    .child(label("Instances"))
                    .child(self.low.clone())
                    .child(label("–"))
                    .child(self.high.clone())
                    .child(if self.discovering {
                        button("bn-go", "Discovering…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary("bn-go", "▶ Discover", act(&view, |t: &mut Self, _, cx| t.discover(cx))).tooltip(tip(
                            "Send a Who-Is (global broadcast, or unicast to the target) and list every device that answers with I-Am. Each device's properties are then read with ReadProperty.",
                        ))
                    })
                    .child(button2("bn-clear", "Clear", act(&view, |t: &mut Self, _, _| {
                        t.devs.clear();
                        t.selected = None;
                        t.reads.clear();
                    })))
                    .child(copy_button("bn-copy", text)),
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
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .w(px(560.))
                            .flex_none()
                            .h_full()
                            .flex()
                            .flex_col()
                            .border_r_1()
                            .border_color(rgb(C::BORDER))
                            .child(table_header(&[
                                ("INSTANCE", 90.),
                                ("ADDRESS", 150.),
                                ("NAME", 0.),
                                ("VENDOR", 140.),
                            ]))
                            .child(
                                div()
                                    .id("bn-devs")
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scroll()
                                    .children(self.devs.iter().enumerate().map(|(i, d)| {
                                        let id = d.peer.iam.device;
                                        let vendor = match d.prop(121) {
                                            v if !v.is_empty() => v,
                                            _ => bn::vendor_name(d.peer.iam.vendor)
                                                .map(String::from)
                                                .unwrap_or_else(|| d.peer.iam.vendor.to_string()),
                                        };
                                        div()
                                            .id(("bn-dev", i))
                                            .flex()
                                            .items_center()
                                            .px_3()
                                            .h(px(30.))
                                            .text_sm()
                                            .cursor_pointer()
                                            .bg(rgb(if self.selected == Some(id) { C::SELECT } else { C::BG }))
                                            .hover(|s| s.bg(rgb(C::PANEL2)))
                                            .on_click(act(&view, move |t: &mut Self, _, _| t.select(id)))
                                            .child(cell(90., id.to_string()).font_family(mono()).text_color(rgb(C::ACCENT)))
                                            .child(cell(150., d.peer.addr.to_string()))
                                            .child(cell(0., d.prop(77)))
                                            .child(cell(140., vendor).text_color(rgb(C::MUTED)))
                                    })),
                            ),
                    )
                    .child(detail.unwrap_or_else(|| {
                        empty_state(
                            if self.discovering { "Discovering…" } else { "No device selected" },
                            "Discover devices, then pick one to read its objects.",
                        )
                        .into_any_element()
                    })),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .child(format!("{} devices", self.devs.len()))
                    .child(match self.port_47808 {
                        Some(true) => "listening on UDP 47808".to_string(),
                        Some(false) => "UDP 47808 busy — broadcast replies may be missed".to_string(),
                        None => String::new(),
                    }),
            )
    }
}
