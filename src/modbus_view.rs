//! Modbus tab: master/client for Modbus TCP and RTU (read/poll/write),
//! unit-ID and TCP host scans, live value table and decoded traffic log.

use std::ops::Range;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, ScrollStrategy, SharedString, Task,
    UniformListScrollHandle, Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::modbus::{self, Command, Endpoint, Event, Master, Request, Response, Table};
use crate::netinfo;
use crate::serial::{self, PortEntry, SerialSettings};
use crate::serial_view::{line_settings, port_list};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, empty_state,
    input, label, mono, progress, section_title, status_bar, table_header, tip,
};

#[derive(Clone, Copy, PartialEq)]
enum Transport {
    Tcp,
    Rtu,
}

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Unsigned,
    Signed,
    Hex,
    Binary,
    Float32,
    UInt32,
}

impl Format {
    const ALL: [Format; 6] = [
        Format::Unsigned,
        Format::Signed,
        Format::Hex,
        Format::Binary,
        Format::Float32,
        Format::UInt32,
    ];
    fn label(self) -> &'static str {
        match self {
            Format::Unsigned => "UInt16",
            Format::Signed => "Int16",
            Format::Hex => "Hex",
            Format::Binary => "Binary",
            Format::Float32 => "Float32",
            Format::UInt32 => "UInt32",
        }
    }
}

enum LogItem {
    Wire {
        t: Instant,
        tx: bool,
        bytes: Vec<u8>,
        rtu: bool,
    },
    Note {
        t: Instant,
        text: String,
        color: u32,
    },
}

/// Last read: table, start address, registers, bits, when, response time.
type Values = (Table, u16, Vec<u16>, Vec<bool>, Instant, Duration);

#[derive(Default)]
struct Counters {
    requests: u64,
    ok: u64,
    exceptions: u64,
    errors: u64,
    rtt_sum: Duration,
}

pub struct ModbusView {
    focus: FocusHandle,
    transport: Transport,
    host: Entity<TextInput>,
    tcp_port: Entity<TextInput>,
    ports: Result<Vec<PortEntry>, String>,
    serial: SerialSettings,
    dev: Entity<TextInput>,
    baud: Entity<TextInput>,
    unit: Entity<TextInput>,
    timeout: Entity<TextInput>,
    table: Table,
    addr: Entity<TextInput>,
    qty: Entity<TextInput>,
    interval: Entity<TextInput>,
    waddr: Entity<TextInput>,
    wvalue: Entity<TextInput>,
    scan_from: Entity<TextInput>,
    scan_to: Entity<TextInput>,
    scan_range: Entity<TextInput>,
    format: Format,
    swap_words: bool,
    master: Option<Master>,
    host_scan: Option<Master>,
    connected: Option<String>,
    polling: bool,
    values: Option<Values>,
    found: Vec<(String, String)>,
    scan_progress: Option<(usize, usize)>,
    log: Vec<LogItem>,
    counters: Counters,
    session: Instant,
    status: SharedString,
    error: Option<String>,
    log_scroll: UniformListScrollHandle,
    _poll: Option<Task<()>>,
}

const MAX_LOG: usize = 20_000;

impl ModbusView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ports = serial::list_ports();
        let first = ports
            .as_ref()
            .ok()
            .and_then(|l| l.first())
            .map(|p| p.name.clone())
            .unwrap_or_default();
        let gw = netinfo::default_gateway()
            .map(|(_, ip)| ip.to_string())
            .unwrap_or_default();
        let cidr = netinfo::local_interfaces()
            .into_iter()
            .next()
            .map(|i| i.cidr())
            .unwrap_or_default();
        let submit_connect =
            |this: &mut Self, _: &mut Window, cx: &mut Context<Self>| this.connect(cx);
        let submit_read =
            |this: &mut Self, _: &mut Window, cx: &mut Context<Self>| this.read(false, cx);
        Self {
            focus: cx.focus_handle(),
            transport: Transport::Tcp,
            host: input(
                window,
                cx,
                "",
                if gw.is_empty() {
                    "192.168.1.50 or plc.local"
                } else {
                    "PLC IP or hostname"
                },
                Accept::Any,
                |t| t,
                submit_connect,
            ),
            tcp_port: input(
                window,
                cx,
                "502",
                "502",
                Accept::Digits,
                |t| t.width(70.).max_len(5),
                submit_connect,
            ),
            ports,
            serial: SerialSettings {
                port: first.clone(),
                parity: 'E',
                ..Default::default()
            },
            dev: input(
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
                submit_connect,
            ),
            baud: input(
                window,
                cx,
                "9600",
                "baud",
                Accept::Digits,
                |t| t.width(84.).max_len(7),
                submit_connect,
            ),
            unit: input(
                window,
                cx,
                "1",
                "1",
                Accept::Digits,
                |t| t.width(56.).max_len(3),
                submit_read,
            ),
            timeout: input(
                window,
                cx,
                "1000",
                "ms",
                Accept::Digits,
                |t| t.width(70.).max_len(5),
                submit_connect,
            ),
            table: Table::HoldingRegisters,
            addr: input(
                window,
                cx,
                "0",
                "0",
                Accept::Digits,
                |t| t.width(80.).max_len(5),
                submit_read,
            ),
            qty: input(
                window,
                cx,
                "10",
                "10",
                Accept::Digits,
                |t| t.width(64.).max_len(4),
                submit_read,
            ),
            interval: input(
                window,
                cx,
                "1000",
                "ms",
                Accept::Digits,
                |t| t.width(70.).max_len(6),
                |this: &mut Self, _, cx| this.read(true, cx),
            ),
            waddr: input(
                window,
                cx,
                "0",
                "0",
                Accept::Digits,
                |t| t.width(80.).max_len(5),
                |_: &mut Self, _, _| {},
            ),
            wvalue: input(
                window,
                cx,
                "",
                "123 or 1,2,3 (coils: 1/0, on/off)",
                Accept::Any,
                |t| t,
                |this: &mut Self, _, cx| this.write(false, cx),
            ),
            scan_from: input(
                window,
                cx,
                "1",
                "1",
                Accept::Digits,
                |t| t.width(56.).max_len(3),
                |_: &mut Self, _, _| {},
            ),
            scan_to: input(
                window,
                cx,
                "247",
                "247",
                Accept::Digits,
                |t| t.width(56.).max_len(3),
                |_: &mut Self, _, _| {},
            ),
            scan_range: input(
                window,
                cx,
                &cidr,
                "192.168.1.0/24",
                Accept::Range,
                |t| t,
                |this: &mut Self, _, cx| this.scan_hosts(cx),
            ),
            format: Format::Unsigned,
            swap_words: false,
            master: None,
            host_scan: None,
            connected: None,
            polling: false,
            values: None,
            found: Vec::new(),
            scan_progress: None,
            log: Vec::new(),
            counters: Counters::default(),
            session: Instant::now(),
            status: "Choose TCP or RTU, enter the device and press Connect.".into(),
            error: None,
            log_scroll: UniformListScrollHandle::new(),
            _poll: None,
        }
    }

    fn num<T: std::str::FromStr>(&self, e: &Entity<TextInput>, cx: &App) -> Option<T> {
        e.read(cx).value.trim().parse().ok()
    }

    fn mark(e: &Entity<TextInput>, cx: &mut Context<Self>) {
        e.update(cx, |t, cx| {
            t.error = true;
            cx.notify();
        });
    }

    fn wait(&self, cx: &App) -> Duration {
        Duration::from_millis(
            self.num::<u64>(&self.timeout, cx)
                .unwrap_or(1000)
                .clamp(50, 30_000),
        )
    }

    fn unit_id(&mut self, cx: &mut Context<Self>) -> Option<u8> {
        match self.num::<u8>(&self.unit, cx) {
            Some(u) if u <= 247 => Some(u),
            _ => {
                Self::mark(&self.unit, cx);
                self.error = Some("Unit ID must be 0-247".into());
                None
            }
        }
    }

    fn connect(&mut self, cx: &mut Context<Self>) {
        if self.master.is_some() {
            return;
        }
        let ep = match self.transport {
            Transport::Tcp => {
                let host = self.host.read(cx).value.trim().to_string();
                if host.is_empty() {
                    Self::mark(&self.host, cx);
                    self.error = Some("Enter the device's IP address or hostname".into());
                    return;
                }
                let Some(port) = self.num::<u16>(&self.tcp_port, cx).filter(|p| *p > 0) else {
                    Self::mark(&self.tcp_port, cx);
                    return;
                };
                Endpoint::Tcp { host, port }
            }
            Transport::Rtu => {
                self.serial.port = self.dev.read(cx).value.trim().to_string();
                if let Some(b) = self.num::<u32>(&self.baud, cx).filter(|b| *b >= 50) {
                    self.serial.baud = b;
                }
                if self.serial.port.is_empty() {
                    Self::mark(&self.dev, cx);
                    self.error = Some("Choose a serial port".into());
                    return;
                }
                Endpoint::Rtu(self.serial.clone())
            }
        };
        self.error = None;
        self.status = format!("Connecting to {}…", ep.label()).into();
        self.master = Some(modbus::connect(ep, self.wait(cx)));
        self.ensure_poll(cx);
    }

    fn disconnect(&mut self) {
        self.master = None;
        self.connected = None;
        self.polling = false;
        self.status = "Disconnected".into();
    }

    fn ensure_poll(&mut self, cx: &mut Context<Self>) {
        if self._poll.is_some() {
            return;
        }
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(50))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn note(&mut self, text: String, color: u32) {
        self.push_log(LogItem::Note {
            t: Instant::now(),
            text,
            color,
        });
    }

    fn push_log(&mut self, item: LogItem) {
        if self.log.len() >= MAX_LOG {
            self.log.drain(..MAX_LOG / 10);
        }
        self.log.push(item);
    }

    fn read(&mut self, poll: bool, cx: &mut Context<Self>) {
        if self.master.is_none() {
            self.connect(cx);
        }
        let Some(unit) = self.unit_id(cx) else { return };
        let Some(addr) = self.num::<u16>(&self.addr, cx) else {
            Self::mark(&self.addr, cx);
            return;
        };
        let qty = match self.num::<u16>(&self.qty, cx) {
            Some(q) if q >= 1 && q <= self.table.max_qty() => q,
            _ => {
                Self::mark(&self.qty, cx);
                self.error = Some(format!("Quantity must be 1-{}", self.table.max_qty()));
                return;
            }
        };
        let every = poll.then(|| {
            Duration::from_millis(
                self.num::<u64>(&self.interval, cx)
                    .unwrap_or(1000)
                    .clamp(20, 3_600_000),
            )
        });
        let Some(m) = &self.master else { return };
        self.error = None;
        self.polling = poll;
        m.send(Command::Run {
            unit,
            req: Request::Read {
                table: self.table,
                addr,
                qty,
            },
            every,
        });
    }

    fn stop(&mut self) {
        if let Some(m) = &self.master {
            m.send(Command::Stop);
        }
        if let Some(m) = &self.host_scan {
            m.send(Command::Stop);
        }
        self.polling = false;
    }

    fn write(&mut self, multiple: bool, cx: &mut Context<Self>) {
        if !self.table.writable() {
            self.error = Some(
                "Only coils and holding registers are writable — select one of those tables".into(),
            );
            return;
        }
        if self.master.is_none() {
            self.connect(cx);
        }
        let Some(unit) = self.unit_id(cx) else { return };
        let Some(addr) = self.num::<u16>(&self.waddr, cx) else {
            Self::mark(&self.waddr, cx);
            return;
        };
        let text = self.wvalue.read(cx).value.clone();
        let req = if self.table == Table::Coils {
            match modbus::parse_bits(&text) {
                Ok(v) if v.len() == 1 && !multiple => Request::WriteCoil { addr, value: v[0] },
                Ok(values) => Request::WriteCoils { addr, values },
                Err(e) => {
                    Self::mark(&self.wvalue, cx);
                    self.error = Some(e);
                    return;
                }
            }
        } else {
            match modbus::parse_words(&text) {
                Ok(v) if v.len() == 1 && !multiple => Request::WriteRegister { addr, value: v[0] },
                Ok(values) => Request::WriteRegisters { addr, values },
                Err(e) => {
                    Self::mark(&self.wvalue, cx);
                    self.error = Some(e);
                    return;
                }
            }
        };
        let Some(m) = &self.master else { return };
        self.error = None;
        self.polling = false;
        m.send(Command::Run {
            unit,
            req,
            every: None,
        });
    }

    fn device_id(&mut self, cx: &mut Context<Self>) {
        if self.master.is_none() {
            self.connect(cx);
        }
        let Some(unit) = self.unit_id(cx) else { return };
        if let Some(m) = &self.master {
            self.polling = false;
            m.send(Command::Run {
                unit,
                req: Request::ReadDeviceId { category: 1 },
                every: None,
            });
        }
    }

    fn scan_units(&mut self, cx: &mut Context<Self>) {
        if self.master.is_none() {
            self.connect(cx);
        }
        let from = self.num::<u8>(&self.scan_from, cx).unwrap_or(1).min(247);
        let to = self
            .num::<u8>(&self.scan_to, cx)
            .unwrap_or(247)
            .clamp(from, 247);
        if let Some(m) = &self.master {
            self.found.clear();
            self.polling = false;
            self.scan_progress = Some((0, (to - from) as usize + 1));
            m.send(Command::ScanUnits { from, to });
            self.status = format!("Scanning unit IDs {from}-{to}…").into();
        }
    }

    fn scan_hosts(&mut self, cx: &mut Context<Self>) {
        let targets = match netinfo::parse_range(&self.scan_range.read(cx).value) {
            Ok(t) => t,
            Err(e) => {
                Self::mark(&self.scan_range, cx);
                self.error = Some(e);
                return;
            }
        };
        let port = self
            .num::<u16>(&self.tcp_port, cx)
            .filter(|p| *p > 0)
            .unwrap_or(502);
        let unit = self.num::<u8>(&self.unit, cx).unwrap_or(1);
        self.error = None;
        self.found.clear();
        self.scan_progress = Some((0, targets.len()));
        let m = modbus::host_scanner(self.wait(cx));
        self.status = format!(
            "Looking for Modbus TCP servers on port {port} in {} addresses…",
            targets.len()
        )
        .into();
        m.send(Command::ScanHosts {
            targets,
            port,
            unit,
        });
        self.host_scan = Some(m);
        self.ensure_poll(cx);
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let mut events = Vec::new();
        if let Some(m) = &self.master {
            events.extend(m.events.try_iter());
        }
        let mut host_events: Vec<Event> = Vec::new();
        if let Some(m) = &self.host_scan {
            host_events.extend(m.events.try_iter());
        }
        let rtu = self.transport == Transport::Rtu;
        let had_traffic = !events.is_empty();
        for ev in events.into_iter().chain(host_events) {
            match ev {
                Event::Connected(desc) => {
                    self.session = Instant::now();
                    self.status = format!("Connected: {desc}").into();
                    self.note(format!("Connected to {desc}"), C::GREEN);
                    self.connected = Some(desc);
                }
                Event::Disconnected(err) => {
                    let msg = err.clone().unwrap_or_else(|| "closed".into());
                    let hint = serial::permission_hint(&msg);
                    self.error = Some(match hint {
                        Some(h) => format!("{msg}. {h}"),
                        None => msg.clone(),
                    });
                    self.note(format!("Connection failed: {msg}"), C::RED);
                    self.master = None;
                    self.connected = None;
                    self.polling = false;
                    self.status = format!("Not connected: {msg}").into();
                }
                Event::Traffic(t, (tx, bytes)) => {
                    self.push_log(LogItem::Wire { t, tx, bytes, rtu })
                }
                Event::Reply {
                    unit,
                    req,
                    result,
                    rtt,
                } => {
                    self.counters.requests += 1;
                    match result {
                        Ok(Response::Words(w)) => {
                            self.counters.ok += 1;
                            self.counters.rtt_sum += rtt;
                            if let Request::Read { table, addr, .. } = req {
                                self.values =
                                    Some((table, addr, w, Vec::new(), Instant::now(), rtt));
                            }
                        }
                        Ok(Response::Bits(b)) => {
                            self.counters.ok += 1;
                            self.counters.rtt_sum += rtt;
                            if let Request::Read { table, addr, .. } = req {
                                self.values =
                                    Some((table, addr, Vec::new(), b, Instant::now(), rtt));
                            }
                        }
                        Ok(Response::Written(a, v)) => {
                            self.counters.ok += 1;
                            self.counters.rtt_sum += rtt;
                            self.status =
                                format!("Unit {unit}: {} — OK (echo {a}, {v})", req.describe())
                                    .into();
                            self.note(format!("{} — OK", req.describe()), C::GREEN);
                        }
                        Ok(Response::DeviceId(objs)) => {
                            self.counters.ok += 1;
                            self.counters.rtt_sum += rtt;
                            let text = objs
                                .iter()
                                .map(|(id, v)| format!("{}: {v}", modbus::device_object_name(*id)))
                                .collect::<Vec<_>>()
                                .join(" · ");
                            self.found.push((format!("unit {unit}"), text.clone()));
                            self.note(format!("Device ID: {text}"), C::CYAN);
                            self.status = format!("Unit {unit} identified").into();
                        }
                        Ok(Response::Exception { function, code }) => {
                            self.counters.exceptions += 1;
                            let msg = format!(
                                "Unit {unit}: exception {code} ({}) to FC{function} {}",
                                modbus::exception_name(code),
                                modbus::function_name(function)
                            );
                            self.note(msg.clone(), C::AMBER);
                            self.status = msg.into();
                        }
                        Err(e) => {
                            self.counters.errors += 1;
                            let msg = format!("Unit {unit}: {} — {e}", req.describe());
                            self.note(msg.clone(), C::RED);
                            self.status = msg.into();
                        }
                    }
                }
                Event::Found { who, detail } => {
                    self.note(format!("Found {who}: {detail}"), C::GREEN);
                    self.found.push((who, detail));
                }
                Event::Progress { done, total } => self.scan_progress = Some((done, total)),
                Event::ScanDone => {
                    self.scan_progress = None;
                    self.status =
                        format!("Scan finished — {} device(s) found", self.found.len()).into();
                }
            }
        }
        if self.host_scan.as_ref().is_some_and(|m| !m.busy()) && self.scan_progress.is_none() {
            self.host_scan = None;
        }
        if had_traffic && !self.log.is_empty() {
            self.log_scroll
                .scroll_to_item(self.log.len() - 1, ScrollStrategy::Bottom);
        }
        cx.notify();
        let alive = self.master.is_some() || self.host_scan.is_some();
        if !alive {
            self._poll = None;
        }
        alive
    }

    // ------------------------------------------------------------ rendering

    fn value_rows(&self) -> Vec<(String, String, String, String)> {
        let Some((table, start, words, bits, _, _)) = &self.values else {
            return Vec::new();
        };
        let base = match table {
            Table::Coils => 1,
            Table::DiscreteInputs => 10001,
            Table::InputRegisters => 30001,
            Table::HoldingRegisters => 40001,
        };
        let reference = |a: u16| format!("{}", base + a as u32);
        if table.is_bits() {
            return bits
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    let a = start.wrapping_add(i as u16);
                    (
                        a.to_string(),
                        reference(a),
                        if *b { "ON".into() } else { "OFF".into() },
                        if *b { "1".into() } else { "0".into() },
                    )
                })
                .collect();
        }
        let pair = |i: usize| -> Option<u32> {
            let (hi, lo) = (*words.get(i)?, *words.get(i + 1)?);
            let (hi, lo) = if self.swap_words { (lo, hi) } else { (hi, lo) };
            Some(((hi as u32) << 16) | lo as u32)
        };
        words
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                let a = start.wrapping_add(i as u16);
                let v = match self.format {
                    Format::Unsigned => w.to_string(),
                    Format::Signed => (w as i16).to_string(),
                    Format::Hex => format!("0x{w:04X}"),
                    Format::Binary => format!("{:08b} {:08b}", w >> 8, w & 0xff),
                    Format::Float32 if i % 2 == 0 => pair(i)
                        .map(|v| fmt_float(f32::from_bits(v)))
                        .unwrap_or_else(|| "—".into()),
                    Format::UInt32 if i % 2 == 0 => {
                        pair(i).map(|v| v.to_string()).unwrap_or_else(|| "—".into())
                    }
                    _ => "↑".into(),
                };
                (a.to_string(), reference(a), v, format!("{w:04X}"))
            })
            .collect()
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let connected = self.master.is_some();
        let row = || div().flex().flex_wrap().items_center().gap_2();
        let conn = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_title("Connection"))
            .child(
                row()
                    .child(chip(
                        "t-tcp",
                        "Modbus TCP",
                        self.transport == Transport::Tcp,
                        act(&view, |t: &mut Self, _, _| {
                            if t.master.is_none() {
                                t.transport = Transport::Tcp
                            }
                        }),
                    ))
                    .child(chip(
                        "t-rtu",
                        "Modbus RTU (serial)",
                        self.transport == Transport::Rtu,
                        act(&view, |t: &mut Self, _, _| {
                            if t.master.is_none() {
                                t.transport = Transport::Rtu
                            }
                        }),
                    )),
            )
            .when(self.transport == Transport::Tcp, |d| {
                d.child(
                    row()
                        .child(label("Host"))
                        .child(self.host.clone())
                        .child(label("Port"))
                        .child(self.tcp_port.clone()),
                )
            })
            .when(self.transport == Transport::Rtu, |d| {
                d.child(port_list(
                    &view,
                    &self.ports,
                    &self.serial.port,
                    |t: &mut Self, name, cx| {
                        t.dev.update(cx, |i, cx| i.set(name.clone(), cx));
                        t.serial.port = name;
                    },
                    |t: &mut Self| t.ports = serial::list_ports(),
                ))
                .child(row().child(label("Device")).child(self.dev.clone()))
                .child(line_settings(
                    &view,
                    &self.serial,
                    &self.baud,
                    |t: &mut Self| &mut t.serial,
                ))
            })
            .child(
                row()
                    .child(label("Unit ID"))
                    .child(self.unit.clone())
                    .child(label("Timeout ms"))
                    .child(self.timeout.clone()),
            )
            .child(
                row()
                    .child(if connected {
                        button(
                            "mb-conn",
                            "Disconnect",
                            C::AMBER,
                            C::AMBER,
                            act(&view, |t: &mut Self, _, _| t.disconnect()),
                        )
                    } else {
                        button_primary(
                            "mb-conn",
                            "Connect",
                            act(&view, |t: &mut Self, _, cx| t.connect(cx)),
                        )
                    })
                    .when_some(self.connected.clone(), |d, c| {
                        d.child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .text_xs()
                                .child(div().size(px(8.)).rounded_full().bg(rgb(C::GREEN)))
                                .child(c),
                        )
                    }),
            );

        let read = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_title("Read"))
            .child(row().children(Table::ALL.iter().enumerate().map(|(i, &tb)| {
                chip(("tbl", i), tb.label(), self.table == tb, act(&view, move |t: &mut Self, _, _| t.table = tb))
            })))
            .child(row().child(label("Start addr")).child(self.addr.clone()).child(label("Quantity")).child(self.qty.clone()))
            .child(
                row()
                    .child(button2("mb-read", "Read once", act(&view, |t: &mut Self, _, cx| t.read(false, cx))))
                    .child(if self.polling {
                        button("mb-poll", "■ Stop polling", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.stop()))
                    } else {
                        button_primary("mb-poll", "▶ Poll", act(&view, |t: &mut Self, _, cx| t.read(true, cx)))
                    })
                    .child(label("every"))
                    .child(self.interval.clone())
                    .child(label("ms")),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(C::MUTED))
                    .child("Addresses are 0-based protocol addresses; REF shows the 1-based 4xxxx / 3xxxx reference."),
            );

        let write = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_title(if self.table.writable() {
                "Write"
            } else {
                "Write (select coils or holding registers)"
            }))
            .child(row().child(label("Address")).child(self.waddr.clone()))
            .child(row().child(label("Value(s)")).child(self.wvalue.clone()))
            .child(
                row()
                    .child(button2(
                        "mb-w1",
                        if self.table == Table::Coils {
                            "Write coil (FC5)"
                        } else {
                            "Write register (FC6)"
                        },
                        act(&view, |t: &mut Self, _, cx| t.write(false, cx)),
                    ))
                    .child(button2(
                        "mb-wn",
                        if self.table == Table::Coils {
                            "Write multiple (FC15)"
                        } else {
                            "Write multiple (FC16)"
                        },
                        act(&view, |t: &mut Self, _, cx| t.write(true, cx)),
                    )),
            );

        let scanning = self.scan_progress.is_some();
        let scan = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_title("Discover"))
            .child(
                row()
                    .child(label("Unit IDs"))
                    .child(self.scan_from.clone())
                    .child(label("to"))
                    .child(self.scan_to.clone())
                    .child(button2("mb-scan-u", "Scan IDs", act(&view, |t: &mut Self, _, cx| t.scan_units(cx))).tooltip(tip("Poll each unit ID on the current connection (RTU bus or TCP gateway); any reply, even an exception, means a device answers on that ID."))),
            )
            .child(button2("mb-devid", "Read device identification (FC43)", act(&view, |t: &mut Self, _, cx| t.device_id(cx))))
            .child(
                row()
                    .child(label("TCP range"))
                    .child(self.scan_range.clone())
                    .child(button2("mb-scan-h", "Find servers", act(&view, |t: &mut Self, _, cx| t.scan_hosts(cx))).tooltip(tip("Connect to the Modbus port (from Port above, default 502) on every address in the range and ask for device identification."))),
            )
            .when(scanning, |d| {
                let (done, total) = self.scan_progress.unwrap_or((0, 1));
                d.child(
                    row()
                        .child(progress(done as f32 / total.max(1) as f32, 160.))
                        .child(label(format!("{done}/{total}")))
                        .child(button("mb-scan-stop", "■ Stop", C::AMBER, C::AMBER, act(&view, |t: &mut Self, _, _| t.stop()))),
                )
            });

        div()
            .id("mb-side")
            .w(px(420.))
            .flex_none()
            .h_full()
            .p_4()
            .flex()
            .flex_col()
            .gap_5()
            .bg(rgb(C::PANEL))
            .border_r_1()
            .border_color(rgb(C::BORDER))
            .overflow_y_scroll()
            .child(conn)
            .child(read)
            .child(write)
            .child(scan)
    }

    fn render_values(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let rows = self.value_rows();
        let info = match &self.values {
            Some((table, addr, w, b, at, rtt)) => format!(
                "{} @{addr} ×{} — updated {:.1}s ago, response {:.1} ms",
                table.label(),
                w.len().max(b.len()),
                at.elapsed().as_secs_f32(),
                rtt.as_secs_f64() * 1000.0
            ),
            None => "No data yet".into(),
        };
        let is_bits = self.values.as_ref().is_some_and(|v| v.0.is_bits());
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .px_4()
                    .py_2()
                    .bg(rgb(C::PANEL))
                    .border_b_1()
                    .border_color(rgb(C::BORDER))
                    .child(div().text_sm().child(info))
                    .child(div().flex_1())
                    .when(!is_bits, |d| {
                        d.children(Format::ALL.iter().enumerate().map(|(i, &f)| {
                            chip(("fmt", i), f.label(), self.format == f, act(&view, move |t: &mut Self, _, _| t.format = f))
                        }))
                        .child(chip("swap", "Swap words", self.swap_words, act(&view, |t: &mut Self, _, _| t.swap_words = !t.swap_words)).tooltip(tip("32-bit values: low word first (CDAB) instead of high word first (ABCD).")))
                    }),
            )
            .child(table_header(&[("ADDR", 90.), ("REF", 90.), ("VALUE", 220.), ("RAW", 0.)]))
            .child(if rows.is_empty() {
                empty_state("No values", "Connect, pick a table and press Read once or Poll.").into_any_element()
            } else {
                div()
                    .id("values")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(rows.into_iter().enumerate().map(|(i, (a, r, v, raw))| {
                        let on = v == "ON";
                        let addr = a.clone();
                        div()
                            .id(("val", i))
                            .w_full()
                            .flex()
                            .flex_row()
                            .items_center()
                            .h(px(26.))
                            .px_3()
                            .text_sm()
                            .font_family(mono())
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .hover(|s| s.bg(rgb(C::PANEL2)))
                            .cursor_pointer()
                            .tooltip(tip("Click to use this address for writing"))
                            .on_click({
                                let waddr = self.waddr.clone();
                                move |_, _, cx| waddr.update(cx, |t, cx| t.set(addr.clone(), cx))
                            })
                            .child(cell(90., a))
                            .child(cell(90., r).text_color(rgb(C::MUTED)))
                            .child(cell(220., v.clone()).text_color(rgb(if is_bits { if on { C::GREEN } else { C::MUTED } } else { C::TEXT })))
                            .child(cell(0., raw).text_color(rgb(C::MUTED)))
                    }))
                    .into_any_element()
            })
    }

    fn render_log_row(&self, i: usize) -> gpui::AnyElement {
        let base = div()
            .id(("mblog", i))
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .h(px(22.))
            .px_3()
            .text_xs()
            .font_family(mono());
        match &self.log[i] {
            LogItem::Note { t, text, color } => base
                .child(
                    cell(
                        80.,
                        format!(
                            "{:.3}",
                            t.saturating_duration_since(self.session).as_secs_f64()
                        ),
                    )
                    .text_color(rgb(C::MUTED)),
                )
                .child(cell(0., text.clone()).text_color(rgb(*color)))
                .into_any_element(),
            LogItem::Wire { t, tx, bytes, rtu } => {
                let decoded = if *rtu {
                    modbus::decode_rtu(bytes)
                        .map(|d| format!("{}{}", if d.crc_ok { "" } else { "CRC ✗ " }, d.text))
                        .unwrap_or_default()
                } else {
                    modbus::decode_tcp(bytes, Some(*tx)).join(" | ")
                };
                base.bg(if *tx {
                    alpha(C::ACCENT, 0.07)
                } else {
                    rgb(C::BG).into()
                })
                .child(
                    cell(
                        80.,
                        format!(
                            "{:.3}",
                            t.saturating_duration_since(self.session).as_secs_f64()
                        ),
                    )
                    .text_color(rgb(C::MUTED)),
                )
                .child(
                    cell(36., if *tx { "TX" } else { "RX" }).text_color(rgb(if *tx {
                        C::ACCENT
                    } else {
                        C::GREEN
                    })),
                )
                .child(cell(330., modbus::hex(bytes)))
                .child(cell(0., decoded).text_color(rgb(C::PURPLE)))
                .into_any_element()
            }
        }
    }

    fn render_found(&self) -> impl IntoElement {
        div()
            .id("found")
            .flex()
            .flex_col()
            .max_h(px(180.))
            .flex_none()
            .overflow_y_scroll()
            .px_4()
            .py_2()
            .border_t_1()
            .border_color(rgb(C::BORDER))
            .bg(rgb(C::PANEL))
            .child(section_title(&format!("Discovered ({})", self.found.len())))
            .children(self.found.iter().map(|(who, d)| {
                div()
                    .flex()
                    .text_sm()
                    .child(cell(200., who.clone()).text_color(rgb(C::GREEN)))
                    .child(cell(0., d.clone()))
            }))
    }
}

/// Compact float: plain for everyday magnitudes, scientific otherwise.
fn fmt_float(v: f32) -> String {
    let a = v.abs();
    if v == 0.0 || (1e-3..1e7).contains(&a) {
        let s = format!("{v:.4}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else if v.is_finite() {
        format!("{v:.4e}")
    } else {
        v.to_string()
    }
}

impl Focusable for ModbusView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for ModbusView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let c = &self.counters;
        let avg = if c.ok > 0 {
            c.rtt_sum.as_secs_f64() * 1000.0 / c.ok as f64
        } else {
            0.0
        };
        let log = if self.log.is_empty() {
            div()
                .flex_1()
                .p_4()
                .text_sm()
                .text_color(rgb(C::MUTED))
                .child("Traffic will appear here.")
                .into_any_element()
        } else {
            uniform_list(
                "mb-log",
                self.log.len(),
                cx.processor(|this, range: Range<usize>, _, _| {
                    range.map(|i| this.render_log_row(i)).collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.log_scroll.clone())
            .flex_1()
            .into_any_element()
        };
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
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(self.render_values(cx))
                            .when(!self.found.is_empty(), |d| d.child(self.render_found()))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .h(px(260.))
                                    .flex_none()
                                    .border_t_1()
                                    .border_color(rgb(C::BORDER))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .px_4()
                                            .py_1()
                                            .bg(rgb(C::PANEL2))
                                            .child(section_title("Traffic"))
                                            .child(chip(
                                                "mb-clear",
                                                "Clear",
                                                false,
                                                act(&view, |t: &mut Self, _, _| {
                                                    t.log.clear();
                                                    t.counters = Counters::default();
                                                }),
                                            )),
                                    )
                                    .child(log),
                            ),
                    ),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .child(format!("{} requests", c.requests))
                    .child(
                        div()
                            .text_color(rgb(C::GREEN))
                            .child(format!("{} ok", c.ok)),
                    )
                    .child(
                        div()
                            .text_color(rgb(if c.exceptions > 0 { C::AMBER } else { C::MUTED }))
                            .child(format!("{} exceptions", c.exceptions)),
                    )
                    .child(
                        div()
                            .text_color(rgb(if c.errors > 0 { C::RED } else { C::MUTED }))
                            .child(format!("{} errors", c.errors)),
                    )
                    .when(c.ok > 0, |d| d.child(format!("avg {avg:.1} ms"))),
            )
    }
}
