//! Serial tab: find ports, connect with chosen line settings, monitor and
//! analyse traffic (text / hex / Modbus RTU decode), send data, detect baud.

use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, ScrollStrategy, SharedString, Task,
    UniformListScrollHandle, WeakEntity, Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::modbus;
use crate::serial::{
    self, BaudEvent, BaudScore, PortEntry, SerialEvent, SerialHandle, SerialSettings,
};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, empty_state,
    input, label, mono, section_title, status_bar, table_header, tip,
};

// ---------------------------------------------------------------- shared editors

/// Port list with a refresh button. Used by the Serial and Modbus tabs.
pub fn port_list<V: 'static>(
    view: &WeakEntity<V>,
    ports: &Result<Vec<PortEntry>, String>,
    selected: &str,
    on_pick: fn(&mut V, String, &mut Context<V>),
    on_refresh: fn(&mut V),
) -> impl IntoElement {
    let list = match ports {
        Ok(l) if l.is_empty() => div()
            .text_xs()
            .text_color(rgb(C::MUTED))
            .child("No serial ports found. Plug in a USB-serial adapter and refresh, or type a device path below.")
            .into_any_element(),
        Ok(l) => div()
            .flex()
            .flex_col()
            .gap_1()
            .children(l.iter().enumerate().map(|(i, p)| {
                let active = p.name == selected;
                let name = p.name.clone();
                div()
                    .id(("port", i))
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .border_1()
                    .border_color(rgb(if active { C::ACCENT } else { C::BORDER }))
                    .bg(rgb(if active { C::SELECT } else { C::BG }))
                    .hover(|s| s.bg(rgb(C::PANEL2)))
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .child(div().text_sm().child(p.name.clone()))
                            .child(label(p.kind.clone())),
                    )
                    .when(!p.detail.is_empty(), |d| d.child(label(p.detail.clone())))
                    .on_click(act(view, move |t: &mut V, _, cx| on_pick(t, name.clone(), cx)))
            }))
            .into_any_element(),
        Err(e) => div().text_xs().text_color(rgb(C::RED)).child(e.clone()).into_any_element(),
    };
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(section_title("Ports"))
                .child(chip(
                    "refresh-ports",
                    "⟲ Refresh",
                    false,
                    act(view, move |t: &mut V, _, _| on_refresh(t)),
                )),
        )
        .child(list)
}

/// Baud / data bits / parity / stop bits / flow control.
pub fn line_settings<V: 'static>(
    view: &WeakEntity<V>,
    s: &SerialSettings,
    baud: &Entity<TextInput>,
    get: fn(&mut V) -> &mut SerialSettings,
) -> impl IntoElement {
    let row = |name: &str| {
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_1()
            .child(label(name.to_string()).w(px(64.)))
    };
    let bauds = [9600u32, 19200, 38400, 57600, 115200].into_iter().map(|b| {
        let baud = baud.clone();
        let active = s.baud == b;
        chip(
            ("baud", b as usize),
            b.to_string(),
            active,
            act(view, move |t: &mut V, _, cx| {
                get(t).baud = b;
                baud.update(cx, |i, cx| i.set(b.to_string(), cx));
            }),
        )
    });
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(row("Baud").child(baud.clone()).children(bauds))
        .child(row("Data bits").children([7u8, 8].map(|n| {
            chip(
                ("db", n as usize),
                n.to_string(),
                s.data_bits == n,
                act(view, move |t: &mut V, _, _| get(t).data_bits = n),
            )
        })))
        .child(
            row("Parity").children([('N', "None"), ('E', "Even"), ('O', "Odd")].map(|(c, n)| {
                chip(
                    ("par", c as usize),
                    n,
                    s.parity == c,
                    act(view, move |t: &mut V, _, _| get(t).parity = c),
                )
            })),
        )
        .child(
            row("Stop bits")
                .children([1u8, 2].map(|n| {
                    chip(
                        ("sb", n as usize),
                        n.to_string(),
                        s.stop_bits == n,
                        act(view, move |t: &mut V, _, _| get(t).stop_bits = n),
                    )
                }))
                .child(div().w(px(8.)))
                .child(chip(
                    "rtscts",
                    "RTS/CTS",
                    s.rtscts,
                    act(view, move |t: &mut V, _, _| {
                        let s = get(t);
                        s.rtscts = !s.rtscts;
                    }),
                )),
        )
}

// ---------------------------------------------------------------- view

#[derive(Clone, Copy, PartialEq)]
enum Display {
    Text,
    Hex,
    Modbus,
}

#[derive(Clone, Copy, PartialEq)]
enum Ending {
    None,
    Cr,
    Lf,
    CrLf,
}

struct Entry {
    t: Instant,
    last: Instant,
    tx: bool,
    bytes: Vec<u8>,
}

pub struct SerialView {
    focus: FocusHandle,
    ports: Result<Vec<PortEntry>, String>,
    settings: SerialSettings,
    port_input: Entity<TextInput>,
    baud: Entity<TextInput>,
    gap: Entity<TextInput>,
    send: Entity<TextInput>,
    send_hex: bool,
    ending: Ending,
    add_crc: bool,
    display: Display,
    handle: Option<SerialHandle>,
    connected: Option<String>,
    session: Instant,
    log: Vec<Entry>,
    rx_bytes: u64,
    tx_bytes: u64,
    paused: bool,
    follow: bool,
    baud_scan: Option<(Receiver<BaudEvent>, Arc<AtomicBool>)>,
    baud_results: Vec<BaudScore>,
    baud_trying: Option<u32>,
    status: SharedString,
    error: Option<String>,
    scroll: UniformListScrollHandle,
    _poll: Option<Task<()>>,
}

const MAX_ENTRIES: usize = 50_000;

impl SerialView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ports = serial::list_ports();
        let first = ports
            .as_ref()
            .ok()
            .and_then(|l| l.first())
            .map(|p| p.name.clone())
            .unwrap_or_default();
        let settings = SerialSettings {
            port: first.clone(),
            ..Default::default()
        };
        let port_input = input(
            window,
            cx,
            &first,
            if cfg!(windows) {
                "COM3"
            } else {
                "/dev/ttyUSB0"
            },
            Accept::Any,
            |t| t,
            |this: &mut Self, _, cx| this.connect(cx),
        );
        let baud = input(
            window,
            cx,
            "9600",
            "baud",
            Accept::Digits,
            |t| t.width(84.).max_len(7),
            |this: &mut Self, _, cx| this.connect(cx),
        );
        let gap = input(
            window,
            cx,
            "",
            "auto",
            Accept::Digits,
            |t| t.width(64.).max_len(5),
            |_: &mut Self, _, _| {},
        );
        let send = input(
            window,
            cx,
            "",
            "Text to send (\\r \\n \\xNN escapes)",
            Accept::Any,
            |t| t.mono().max_len(1024),
            |this: &mut Self, _, cx| this.send(cx),
        );
        let n = ports.as_ref().map(|l| l.len()).unwrap_or(0);
        Self {
            focus: cx.focus_handle(),
            status: format!("{n} serial port{} found", if n == 1 { "" } else { "s" }).into(),
            ports,
            settings,
            port_input,
            baud,
            gap,
            send,
            send_hex: false,
            ending: Ending::CrLf,
            add_crc: true,
            display: Display::Text,
            handle: None,
            connected: None,
            session: Instant::now(),
            log: Vec::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            paused: false,
            follow: true,
            baud_scan: None,
            baud_results: Vec::new(),
            baud_trying: None,
            error: None,
            scroll: UniformListScrollHandle::new(),
            _poll: None,
        }
    }

    fn refresh(&mut self) {
        self.ports = serial::list_ports();
        let n = self.ports.as_ref().map(|l| l.len()).unwrap_or(0);
        self.status = format!("{n} serial port{} found", if n == 1 { "" } else { "s" }).into();
    }

    fn sync_settings(&mut self, cx: &App) {
        self.settings.port = self.port_input.read(cx).value.trim().to_string();
        if let Ok(b) = self.baud.read(cx).value.parse::<u32>()
            && b >= 50
        {
            self.settings.baud = b;
        }
    }

    fn connect(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() || self.baud_scan.is_some() {
            return;
        }
        self.sync_settings(cx);
        if self.settings.port.is_empty() {
            self.error = Some("Choose a serial port".into());
            return;
        }
        self.error = None;
        self.handle = Some(serial::open_monitor(self.settings.clone()));
        self.status = format!("Opening {}…", self.settings.port).into();
        self.ensure_poll(cx);
    }

    fn disconnect(&mut self) {
        if let Some(h) = &self.handle {
            h.close();
        }
    }

    fn ensure_poll(&mut self, cx: &mut Context<Self>) {
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(40))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn frame_gap(&self, cx: &App) -> Duration {
        match self.gap.read(cx).value.parse::<u64>() {
            Ok(ms) if ms > 0 => Duration::from_millis(ms),
            // Text: lines arrive in bursts; Modbus/hex: RTU silence.
            _ if self.display == Display::Text => Duration::from_millis(50),
            _ => modbus::rtu_gap(self.settings.baud),
        }
    }

    fn push(&mut self, t: Instant, tx: bool, bytes: &[u8], gap: Duration) {
        if let Some(last) = self.log.last_mut()
            && last.tx == tx
            && t.duration_since(last.last) <= gap
            && last.bytes.len() < 4096
            && !(self.display == Display::Text && last.bytes.last() == Some(&b'\n'))
        {
            last.bytes.extend_from_slice(bytes);
            last.last = t;
            return;
        }
        if self.log.len() >= MAX_ENTRIES {
            self.log.drain(..MAX_ENTRIES / 10);
        }
        self.log.push(Entry {
            t,
            last: t,
            tx,
            bytes: bytes.to_vec(),
        });
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let mut alive = false;
        let gap = self.frame_gap(cx);
        let mut changed = false;
        if let Some(h) = &self.handle {
            alive = true;
            let events: Vec<SerialEvent> = h.events.try_iter().collect();
            for ev in events {
                match ev {
                    SerialEvent::Opened(desc) => {
                        self.session = Instant::now();
                        self.status = format!("Connected: {desc}").into();
                        self.connected = Some(desc);
                    }
                    SerialEvent::Data(t, b) => {
                        self.rx_bytes += b.len() as u64;
                        if !self.paused {
                            self.push(t, false, &b, gap);
                            changed = true;
                        }
                    }
                    SerialEvent::Sent(t, b) => {
                        self.tx_bytes += b.len() as u64;
                        self.push(t, true, &b, Duration::ZERO);
                        changed = true;
                    }
                    SerialEvent::Closed(err) => {
                        self.handle = None;
                        self.connected = None;
                        alive = false;
                        self.status = match &err {
                            Some(e) => {
                                self.error = Some(match serial::permission_hint(e) {
                                    Some(h) => format!("{e}. {h}"),
                                    None => e.clone(),
                                });
                                format!("Disconnected: {e}").into()
                            }
                            None => "Disconnected".into(),
                        };
                        break;
                    }
                }
            }
        }
        if let Some((rx, _)) = &self.baud_scan {
            alive = true;
            let events: Vec<BaudEvent> = rx.try_iter().collect();
            for ev in events {
                match ev {
                    BaudEvent::Trying(b) => self.baud_trying = Some(b),
                    BaudEvent::Score(s) => self.baud_results.push(s),
                    BaudEvent::Done(r) => {
                        self.baud_scan = None;
                        self.baud_trying = None;
                        match r {
                            Ok(Some(b)) => {
                                self.settings.baud = b;
                                self.baud.update(cx, |i, cx| i.set(b.to_string(), cx));
                                self.status = format!("Baud detection: best match {b}").into();
                            }
                            Ok(None) => self.status = "Baud detection: no data received at any rate (the device must be transmitting)".into(),
                            Err(e) => {
                                self.error = Some(match serial::permission_hint(&e) {
                                    Some(h) => format!("{e}. {h}"),
                                    None => e.clone(),
                                });
                                self.status = "Baud detection failed".into();
                            }
                        }
                        break;
                    }
                }
            }
        }
        if changed && self.follow && !self.log.is_empty() {
            self.scroll
                .scroll_to_item(self.log.len() - 1, ScrollStrategy::Bottom);
        }
        cx.notify();
        alive
    }

    fn start_baud_scan(&mut self, cx: &mut Context<Self>) {
        if self.handle.is_some() || self.baud_scan.is_some() {
            return;
        }
        self.sync_settings(cx);
        if self.settings.port.is_empty() {
            self.error = Some("Choose a serial port".into());
            return;
        }
        self.error = None;
        self.baud_results.clear();
        self.baud_scan = Some(serial::baud_scan(
            self.settings.clone(),
            serial::BAUD_RATES.to_vec(),
            Duration::from_millis(1500),
        ));
        self.status = "Detecting baud rate — listening at each rate…".into();
        self.ensure_poll(cx);
    }

    fn send(&mut self, cx: &mut Context<Self>) {
        let Some(h) = &self.handle else {
            self.error = Some("Not connected".into());
            return;
        };
        let text = self.send.read(cx).value.clone();
        let mut bytes = if self.send_hex {
            match modbus::parse_hex(&text) {
                Ok(b) => b,
                Err(e) => {
                    self.error = Some(format!("Hex: {e}"));
                    return;
                }
            }
        } else {
            serial::unescape(&text)
        };
        if self.send_hex && self.add_crc && !bytes.is_empty() {
            let crc = modbus::crc16(&bytes);
            bytes.extend_from_slice(&crc.to_le_bytes());
        }
        if !self.send_hex {
            bytes.extend_from_slice(match self.ending {
                Ending::None => b"",
                Ending::Cr => b"\r",
                Ending::Lf => b"\n",
                Ending::CrLf => b"\r\n",
            });
        }
        if bytes.is_empty() {
            return;
        }
        self.error = None;
        h.send(bytes);
    }

    fn export(&mut self) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = crate::platform::home_dir()
            .unwrap_or_else(|| ".".into())
            .join(format!("serial-log-{ts}.txt"));
        let mut out = String::new();
        for e in &self.log {
            out.push_str(&format!(
                "{:>10.3} {} {:>4}  {}  |{}|",
                e.t.saturating_duration_since(self.session).as_secs_f64(),
                if e.tx { "TX" } else { "RX" },
                e.bytes.len(),
                modbus::hex(&e.bytes),
                serial::ascii(&e.bytes)
            ));
            if let Some(d) = modbus::decode_rtu(&e.bytes).filter(|d| d.crc_ok) {
                out.push_str(&format!("  modbus unit {}: {}", d.unit, d.text));
            }
            out.push('\n');
        }
        self.status = match std::fs::write(&path, out) {
            Ok(()) => format!("Log saved to {}", path.display()).into(),
            Err(e) => format!("Save failed: {e}").into(),
        };
    }

    fn render_row(&self, i: usize) -> gpui::AnyElement {
        let e = &self.log[i];
        let dt = i
            .checked_sub(1)
            .map(|p| e.t.saturating_duration_since(self.log[p].last))
            .map(|d| format!("+{:.1}", d.as_secs_f64() * 1000.0))
            .unwrap_or_default();
        let (data, data_color) = match self.display {
            Display::Text => (serial::ascii(&e.bytes), C::TEXT),
            Display::Hex => (modbus::hex(&e.bytes), C::TEXT),
            Display::Modbus => match modbus::decode_rtu(&e.bytes) {
                Some(d) if d.crc_ok => (format!("unit {}  {}", d.unit, d.text), C::PURPLE),
                _ if is_text(&e.bytes) => (serial::ascii(&e.bytes), C::MUTED),
                Some(_) => (format!("CRC ✗  {}", modbus::hex(&e.bytes)), C::RED),
                None => (modbus::hex(&e.bytes), C::MUTED),
            },
        };
        div()
            .id(("ser", i))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .h(px(24.))
            .px_3()
            .text_xs()
            .font_family(mono())
            .bg(if e.tx {
                alpha(C::ACCENT, 0.08)
            } else if i % 2 == 1 {
                rgb(C::ROW_ALT).into()
            } else {
                rgb(C::BG).into()
            })
            .child(
                cell(
                    90.,
                    format!(
                        "{:.3}",
                        e.t.saturating_duration_since(self.session).as_secs_f64()
                    ),
                )
                .text_color(rgb(C::MUTED)),
            )
            .child(cell(80., dt).text_color(rgb(C::MUTED)))
            .child(
                cell(40., if e.tx { "TX" } else { "RX" }).text_color(rgb(if e.tx {
                    C::ACCENT
                } else {
                    C::GREEN
                })),
            )
            .child(cell(50., e.bytes.len().to_string()).text_color(rgb(C::MUTED)))
            .child(cell(0., data).text_color(rgb(data_color)))
            .into_any_element()
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let connected = self.handle.is_some();
        let scanning = self.baud_scan.is_some();
        div()
            .id("serial-side")
            .w(px(360.))
            .flex_none()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_4()
            .bg(rgb(C::PANEL))
            .border_r_1()
            .border_color(rgb(C::BORDER))
            .overflow_y_scroll()
            .child(port_list(
                &view,
                &self.ports,
                &self.settings.port,
                |t: &mut Self, name, cx| {
                    t.port_input.update(cx, |i, cx| i.set(name.clone(), cx));
                    t.settings.port = name;
                },
                |t: &mut Self| t.refresh(),
            ))
            .child(div().flex().items_center().gap_2().child(label("Device")).child(self.port_input.clone()))
            .child(section_title("Line settings"))
            .child(line_settings(&view, &self.settings, &self.baud, |t: &mut Self| &mut t.settings))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(if connected {
                        button("ser-conn", "Disconnect", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.disconnect()))
                    } else {
                        button_primary("ser-conn", "Connect", act(&view, |t: &mut Self, _, cx| t.connect(cx)))
                    })
                    .child(if scanning {
                        button("baud-scan", "■ Stop detection", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| {
                            if let Some((_, stop)) = &t.baud_scan {
                                stop.store(true, Ordering::Relaxed);
                            }
                        }))
                    } else {
                        button2("baud-scan", "Detect baud", act(&view, |t: &mut Self, _, cx| t.start_baud_scan(cx)))
                            .tooltip(tip("Listen at each baud rate for 1.5 s and score what arrives (readable text, valid Modbus RTU CRCs). The device must be transmitting."))
                    }),
            )
            .when(scanning || !self.baud_results.is_empty(), |d| {
                d.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(section_title("Baud detection"))
                        .children(self.baud_results.iter().map(|s| {
                            div()
                                .flex()
                                .text_xs()
                                .child(cell(70., s.baud.to_string()))
                                .child(cell(70., format!("{} B", s.bytes)).text_color(rgb(C::MUTED)))
                                .child(cell(0., s.verdict()).text_color(rgb(if s.modbus_frames > 0 || s.printable > 0.9 { C::GREEN } else { C::MUTED })))
                        }))
                        .children(self.baud_trying.filter(|_| scanning).map(|b| label(format!("listening at {b}…")))),
                )
            })
            .when_some(self.connected.clone(), |d, c| {
                d.child(div().flex().items_center().gap_2().text_sm().child(div().size(px(8.)).rounded_full().bg(rgb(C::GREEN))).child(c))
            })
    }

    fn render_main(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let header = div()
            .flex()
            .flex_row()
            .flex_wrap()
            .items_center()
            .gap_2()
            .px_4()
            .py_2()
            .bg(rgb(C::PANEL))
            .border_b_1()
            .border_color(rgb(C::BORDER))
            .child(label("View"))
            .child(chip("d-text", "Text", self.display == Display::Text, act(&view, |t: &mut Self, _, _| t.display = Display::Text)))
            .child(chip("d-hex", "Hex", self.display == Display::Hex, act(&view, |t: &mut Self, _, _| t.display = Display::Hex)))
            .child(chip("d-mb", "Modbus RTU", self.display == Display::Modbus, act(&view, |t: &mut Self, _, _| t.display = Display::Modbus)).tooltip(tip("Split traffic into frames at 3.5-character silences and decode Modbus RTU (CRC checked).")))
            .child(div().w(px(8.)))
            .child(label("Frame gap ms"))
            .child(self.gap.clone())
            .child(chip("follow", "Auto-scroll", self.follow, act(&view, |t: &mut Self, _, _| t.follow = !t.follow)))
            .child(chip("pause", "Pause RX", self.paused, act(&view, |t: &mut Self, _, _| t.paused = !t.paused)))
            .child(div().flex_1())
            .child(button2("ser-save", "Save log", act(&view, |t: &mut Self, _, _| t.export())))
            .child(button2("ser-clear", "Clear", act(&view, |t: &mut Self, _, _| {
                t.log.clear();
                t.rx_bytes = 0;
                t.tx_bytes = 0;
            })));

        let body = if self.log.is_empty() {
            empty_state(
                if self.handle.is_some() {
                    "Listening…"
                } else {
                    "Not connected"
                },
                if self.handle.is_some() {
                    "Received data will appear here."
                } else {
                    "Pick a port, set the line parameters and press Connect."
                },
            )
            .into_any_element()
        } else {
            uniform_list(
                "serial-log",
                self.log.len(),
                cx.processor(|this, range: Range<usize>, _, _| {
                    range.map(|i| this.render_row(i)).collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.scroll.clone())
            .flex_1()
            .into_any_element()
        };

        let sender = div()
            .flex()
            .flex_row()
            .flex_wrap()
            .items_center()
            .gap_2()
            .px_4()
            .py_2()
            .bg(rgb(C::PANEL))
            .border_t_1()
            .border_color(rgb(C::BORDER))
            .child(chip(
                "s-text",
                "Text",
                !self.send_hex,
                act(&view, |t: &mut Self, _, _| t.send_hex = false),
            ))
            .child(chip(
                "s-hex",
                "Hex",
                self.send_hex,
                act(&view, |t: &mut Self, _, _| t.send_hex = true),
            ))
            .child(self.send.clone())
            .when(!self.send_hex, |d| {
                d.children(
                    [
                        (Ending::None, "No EOL"),
                        (Ending::Cr, "CR"),
                        (Ending::Lf, "LF"),
                        (Ending::CrLf, "CR+LF"),
                    ]
                    .into_iter()
                    .enumerate()
                    .map(|(i, (e, n))| {
                        chip(
                            ("eol", i),
                            n,
                            self.ending == e,
                            act(&view, move |t: &mut Self, _, _| t.ending = e),
                        )
                    }),
                )
            })
            .when(self.send_hex, |d| {
                d.child(chip(
                    "crc",
                    "+ Modbus CRC",
                    self.add_crc,
                    act(&view, |t: &mut Self, _, _| t.add_crc = !t.add_crc),
                ))
            })
            .child(button_primary(
                "ser-send",
                "Send",
                act(&view, |t: &mut Self, _, cx| t.send(cx)),
            ));

        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .child(header)
            .child(table_header(&[
                ("TIME s", 90.),
                ("Δ ms", 80.),
                ("DIR", 40.),
                ("LEN", 50.),
                ("DATA", 0.),
            ]))
            .child(div().flex().flex_col().flex_1().min_h_0().child(body))
            .child(sender)
    }

    /// Frame / CRC statistics for the status bar.
    fn frame_stats(&self) -> (usize, usize, usize) {
        let rx: Vec<&Entry> = self.log.iter().filter(|e| !e.tx).collect();
        let (mut ok, mut bad) = (0, 0);
        for e in &rx {
            match modbus::rtu_crc_ok(&e.bytes) {
                Some(true) => ok += 1,
                Some(false) if !is_text(&e.bytes) => bad += 1,
                _ => {}
            }
        }
        (rx.len(), ok, bad)
    }
}

/// Console text rather than a binary frame (shown as text in Modbus view).
fn is_text(b: &[u8]) -> bool {
    b.len() >= 4
        && b.iter()
            .all(|&c| (0x20..0x7f).contains(&c) || matches!(c, b'\r' | b'\n' | b'\t'))
}

impl Focusable for SerialView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for SerialView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (frames, ok, bad) = if self.display == Display::Modbus {
            self.frame_stats()
        } else {
            (0, 0, 0)
        };
        let secs = self.session.elapsed().as_secs_f64().max(0.001);
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
                    .child(self.render_sidebar(cx))
                    .child(self.render_main(cx)),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .child(format!("RX {} B", self.rx_bytes))
                    .child(format!("TX {} B", self.tx_bytes))
                    .when(self.handle.is_some(), |d| {
                        d.child(format!("avg {:.0} B/s", self.rx_bytes as f64 / secs))
                    })
                    .when(self.display == Display::Modbus, |d| {
                        d.child(format!("{frames} frames"))
                            .child(
                                div()
                                    .text_color(rgb(C::GREEN))
                                    .child(format!("{ok} CRC ok")),
                            )
                            .child(
                                div()
                                    .text_color(rgb(if bad > 0 { C::RED } else { C::MUTED }))
                                    .child(format!("{bad} CRC errors")),
                            )
                    }),
            )
    }
}
