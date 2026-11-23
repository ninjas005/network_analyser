//! MQTT tool: connect to a broker (TCP/TLS, 3.1.1 or 5.0), subscribe with
//! wildcards, browse a live topic tree with counts and rates, inspect
//! payloads (text / JSON / hex), publish with QoS and retain, read $SYS
//! broker statistics, and follow a connection log.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Range;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use gpui::{
    App, ClipboardItem, Context, Entity, FocusHandle, Focusable, KeyDownEvent, SharedString, Task,
    UniformListScrollHandle, Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::mqtt::{self, Cmd, Config, Event, Lvl, Session};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, empty_state,
    input, kv_row, label, mono, section_title, status_bar, table_header, tile, toolbar,
};

// ---------------------------------------------------------------- masked input

/// Single-line password field (shows bullets), cursor at the end.
pub struct SecretInput {
    pub focus: FocusHandle,
    pub value: String,
    placeholder: SharedString,
    width: f32,
}

impl SecretInput {
    pub fn new(cx: &mut Context<Self>, placeholder: &str, width: f32) -> Self {
        Self {
            focus: cx.focus_handle(),
            value: String::new(),
            placeholder: placeholder.to_string().into(),
            width,
        }
    }

    fn on_key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let ks = &ev.keystroke;
        let cmd = ks.modifiers.control || ks.modifiers.platform;
        match ks.key.as_str() {
            "backspace" if cmd => self.value.clear(),
            "backspace" => {
                self.value.pop();
            }
            "u" if cmd => self.value.clear(),
            "v" if cmd => {
                if let Some(t) = cx.read_from_clipboard().and_then(|c| c.text()) {
                    self.value
                        .extend(t.lines().next().unwrap_or("").chars().take(256));
                }
            }
            "enter" | "tab" | "escape" => return,
            _ => {
                if ks.modifiers.control || ks.modifiers.alt || ks.modifiers.platform {
                    return;
                }
                match ks.key_char.as_deref() {
                    Some(c) if !c.chars().any(char::is_control) && self.value.len() < 256 => {
                        self.value.push_str(c)
                    }
                    _ => return,
                }
            }
        }
        cx.stop_propagation();
        cx.notify();
    }
}

impl Render for SecretInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus.is_focused(window);
        let empty = self.value.is_empty();
        div()
            .id("secret-input")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::on_key))
            .on_click(cx.listener(|this, _, window, _| window.focus(&this.focus)))
            .w(px(self.width))
            .flex_none()
            .h(px(32.))
            .px_2()
            .flex()
            .items_center()
            .overflow_hidden()
            .whitespace_nowrap()
            .rounded_md()
            .bg(rgb(C::BG))
            .border_1()
            .border_color(rgb(if focused { C::ACCENT } else { C::BORDER }))
            .cursor_text()
            .text_sm()
            .when(empty && !focused, |d| {
                d.text_color(rgb(C::MUTED)).child(self.placeholder.clone())
            })
            .when(!empty, |d| {
                d.text_color(rgb(C::TEXT))
                    .child("•".repeat(self.value.chars().count().min(40)))
            })
            .when(focused, |d| {
                d.child(
                    div()
                        .w(px(1.5))
                        .h(px(16.))
                        .ml(px(1.))
                        .flex_none()
                        .bg(rgb(C::ACCENT)),
                )
            })
    }
}

// ---------------------------------------------------------------- payload display

/// Text, pretty JSON, or a hex dump.
pub fn payload_text(p: &[u8], max: usize) -> (String, &'static str) {
    if p.is_empty() {
        return ("(empty)".into(), "empty");
    }
    if let Ok(s) = std::str::from_utf8(p) {
        let t = s.trim_start();
        if (t.starts_with('{') || t.starts_with('['))
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(s)
        {
            let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
            return (truncate(&pretty, max), "JSON");
        }
        if !s.chars().any(|c| c.is_control() && !"\r\n\t".contains(c)) {
            return (truncate(s, max), "text");
        }
    }
    let mut out = String::new();
    for (i, row) in p.chunks(16).take(max / 64 + 1).enumerate() {
        let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
        let asc: String = row
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{:04x}  {:<48} {asc}\n", i * 16, hex.join(" ")));
    }
    if p.len() > (max / 64 + 1) * 16 {
        out.push_str(&format!("… {} bytes total\n", p.len()));
    }
    (out, "binary")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!(
            "{}\n… ({} bytes)",
            &s[..s.floor_char_boundary(max)],
            s.len()
        )
    } else {
        s.to_string()
    }
}

/// Multi-line monospace block.
pub fn mono_block(text: &str) -> gpui::Div {
    div()
        .p_2()
        .rounded_md()
        .bg(rgb(C::BG))
        .border_1()
        .border_color(rgb(C::BORDER))
        .font_family(mono())
        .text_xs()
        .children(
            text.lines()
                .take(400)
                .map(|l| div().min_h(px(15.)).child(l.to_string())),
        )
}

pub fn ago(t: Instant) -> String {
    let s = t.elapsed().as_secs_f64();
    if s < 1.0 {
        "now".into()
    } else if s < 60.0 {
        format!("{s:.0} s")
    } else if s < 3600.0 {
        format!("{:.0} min", s / 60.0)
    } else {
        format!("{:.1} h", s / 3600.0)
    }
}

// ---------------------------------------------------------------- model

const MAX_TOPICS: usize = 20_000;
const HISTORY: usize = 20;

struct TopicStat {
    count: u64,
    bytes: u64,
    first: Instant,
    last: Instant,
    qos: u8,
    retained: bool,
    dup: bool,
    props: Vec<(String, String)>,
    history: VecDeque<(Instant, Vec<u8>, bool)>,
}

impl TopicStat {
    fn rate(&self) -> Option<f64> {
        let span = self.last.duration_since(self.first).as_secs_f64();
        (self.count > 2 && span >= 1.0).then(|| (self.count - 1) as f64 / span)
    }
}

#[derive(Clone)]
struct Row {
    path: String,
    name: String,
    depth: usize,
    has_children: bool,
    is_topic: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Pane {
    Topic,
    Broker,
    Log,
}

pub struct MqttView {
    focus: FocusHandle,
    broker: Entity<TextInput>,
    client_id: Entity<TextInput>,
    user: Entity<TextInput>,
    pass: Entity<SecretInput>,
    keepalive: Entity<TextInput>,
    sub_filter: Entity<TextInput>,
    pub_topic: Entity<TextInput>,
    pub_payload: Entity<TextInput>,
    search: Entity<TextInput>,
    tls: bool,
    insecure: bool,
    v5: bool,
    clean: bool,
    sub_qos: u8,
    pub_qos: u8,
    pub_retain: bool,

    session: Option<Session>,
    rx: Option<Receiver<Event>>,
    connected: bool,
    connected_at: Option<Instant>,
    conn_props: Vec<(String, String)>,
    conn_desc: String,
    subs: Vec<(String, u8)>,

    topics: HashMap<String, TopicStat>,
    topic_set: BTreeSet<String>,
    agg: HashMap<String, u64>,
    expanded: HashSet<String>,
    rows: Vec<Row>,
    rows_dirty: bool,
    last_search: String,
    selected: Option<String>,
    dropped_topics: u64,

    total_msgs: u64,
    total_bytes: u64,
    recent: VecDeque<Instant>,
    pkts_in: u64,
    pkts_out: u64,
    wire_in: u64,
    wire_out: u64,
    rtt: Option<f64>,
    log: Vec<(Instant, Lvl, String)>,
    pane: Pane,
    tree_scroll: UniformListScrollHandle,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

impl MqttView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let pass = cx.new(|cx| SecretInput::new(cx, "password", 120.));
        Self {
            focus: cx.focus_handle(),
            broker: input(
                window,
                cx,
                "test.mosquitto.org",
                "broker (host[:port] or mqtts://host)",
                Accept::Any,
                |t| t.width(260.),
                |t: &mut Self, _, cx| t.connect(cx),
            ),
            client_id: input(
                window,
                cx,
                &mqtt::random_client_id(),
                "client id",
                Accept::Any,
                |t| t.width(200.).max_len(64),
                |_: &mut Self, _, _| {},
            ),
            user: input(
                window,
                cx,
                "",
                "user (optional)",
                Accept::Any,
                |t| t.width(130.),
                |_: &mut Self, _, _| {},
            ),
            pass,
            keepalive: input(
                window,
                cx,
                "30",
                "s",
                Accept::Digits,
                |t| t.width(50.).max_len(5),
                |_: &mut Self, _, _| {},
            ),
            sub_filter: input(
                window,
                cx,
                "#",
                "topic filter (+ and # wildcards)",
                Accept::Any,
                |t| t,
                |t: &mut Self, _, cx| t.subscribe(cx),
            ),
            pub_topic: input(
                window,
                cx,
                "",
                "topic",
                Accept::Any,
                |t| t.width(200.),
                |_: &mut Self, _, _| {},
            ),
            pub_payload: input(
                window,
                cx,
                "",
                "payload (text or JSON)",
                Accept::Any,
                |t| t.max_len(65_536),
                |t: &mut Self, _, cx| t.publish(cx),
            ),
            search: input(
                window,
                cx,
                "",
                "search topics",
                Accept::Any,
                |t| t,
                |_: &mut Self, _, _| {},
            ),
            tls: false,
            insecure: false,
            v5: false,
            clean: true,
            sub_qos: 0,
            pub_qos: 0,
            pub_retain: false,
            session: None,
            rx: None,
            connected: false,
            connected_at: None,
            conn_props: Vec::new(),
            conn_desc: String::new(),
            subs: Vec::new(),
            topics: HashMap::new(),
            topic_set: BTreeSet::new(),
            agg: HashMap::new(),
            expanded: HashSet::new(),
            rows: Vec::new(),
            rows_dirty: false,
            last_search: String::new(),
            selected: None,
            dropped_topics: 0,
            total_msgs: 0,
            total_bytes: 0,
            recent: VecDeque::new(),
            pkts_in: 0,
            pkts_out: 0,
            wire_in: 0,
            wire_out: 0,
            rtt: None,
            log: Vec::new(),
            pane: Pane::Log,
            tree_scroll: UniformListScrollHandle::new(),
            status: "Public test brokers: test.mosquitto.org, broker.hivemq.com, broker.emqx.io"
                .into(),
            error: None,
            _poll: None,
        }
    }

    fn running(&self) -> bool {
        self.session.is_some()
    }

    fn connect(&mut self, cx: &mut Context<Self>) {
        if self.running() {
            return;
        }
        self.error = None;
        let (host, port, tls_implied) = match mqtt::parse_broker(&self.broker.read(cx).value) {
            Ok(x) => x,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let tls = self.tls || tls_implied;
        self.tls = tls;
        let user = self.user.read(cx).value.trim().to_string();
        let pass = self.pass.read(cx).value.clone();
        let mut client_id = self.client_id.read(cx).value.trim().to_string();
        if client_id.is_empty() {
            client_id = mqtt::random_client_id();
            self.client_id
                .update(cx, |t, cx| t.set(client_id.clone(), cx));
        }
        let keepalive = self.keepalive.read(cx).value.parse().unwrap_or(30u16);
        let cfg = Config {
            host: host.clone(),
            port,
            tls,
            insecure: self.insecure,
            client_id,
            username: (!user.is_empty()).then_some(user),
            password: (!pass.is_empty()).then_some(pass),
            keepalive,
            clean: self.clean,
            v5: self.v5,
            timeout: Duration::from_secs(10),
        };
        self.conn_desc = format!(
            "{host}:{port}{} · MQTT {}",
            if tls { " TLS" } else { "" },
            if self.v5 { "5.0" } else { "3.1.1" }
        );
        let (s, rx) = mqtt::connect(cfg);
        // Re-subscribe previous filters, or the one in the box.
        if self.subs.is_empty() {
            let f = self.sub_filter.read(cx).value.trim().to_string();
            if mqtt::validate_filter(&f).is_ok() {
                self.subs.push((f, self.sub_qos));
            }
        }
        for (f, q) in &self.subs {
            s.send(Cmd::Subscribe(f.clone(), *q));
        }
        self.session = Some(s);
        self.rx = Some(rx);
        self.connected = false;
        self.pane = Pane::Log;
        self.status = format!("Connecting to {}…", self.conn_desc).into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                let alive = this.update(cx, |t, cx| {
                    t.drain();
                    cx.notify();
                    t.rx.is_some()
                });
                if !matches!(alive, Ok(true)) {
                    break;
                }
            }
        }));
    }

    fn disconnect(&mut self) {
        if let Some(s) = self.session.take() {
            s.send(Cmd::Disconnect);
        }
    }

    fn push_log(&mut self, l: Lvl, s: String) {
        self.log.push((Instant::now(), l, s));
        if self.log.len() > 2000 {
            self.log.drain(..500);
        }
    }

    fn drain(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut events = Vec::new();
        let mut ended = false;
        loop {
            match rx.try_recv() {
                Ok(e) => events.push(e),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    ended = true;
                    break;
                }
            }
            if events.len() > 20_000 {
                break;
            }
        }
        for e in events {
            match e {
                Event::Log(l, s) => self.push_log(l, s),
                Event::Connected {
                    conn,
                    session_present,
                    props,
                    ms,
                } => {
                    self.connected = true;
                    self.connected_at = Some(Instant::now());
                    self.conn_props = props;
                    if let Some(c) = &conn.cert {
                        self.push_log(Lvl::Info, format!("Certificate: {c}"));
                    }
                    for (k, v) in self.conn_props.clone() {
                        self.push_log(Lvl::Info, format!("  {k}: {v}"));
                    }
                    self.status = format!(
                        "Connected to {} in {ms:.0} ms{}",
                        self.conn_desc,
                        if session_present {
                            " (session resumed)"
                        } else {
                            ""
                        }
                    )
                    .into();
                    if self.pane == Pane::Log && self.log.len() < 12 {
                        self.pane = Pane::Topic;
                    }
                }
                Event::Message(m) => self.on_message(m),
                Event::Wire(out, n) => {
                    if out {
                        self.pkts_out += 1;
                        self.wire_out += n as u64;
                    } else {
                        self.pkts_in += 1;
                        self.wire_in += n as u64;
                    }
                }
                Event::Rtt(ms) => self.rtt = Some(ms),
                Event::Closed(s) => {
                    self.push_log(Lvl::Info, s.clone());
                    self.status = s.into();
                    ended = true;
                }
                Event::Error(e) => {
                    self.push_log(Lvl::Bad, e.clone());
                    self.status = format!("Disconnected: {e}").into();
                    self.error = Some(e);
                    self.pane = Pane::Log;
                    ended = true;
                }
            }
        }
        while self
            .recent
            .front()
            .is_some_and(|t| t.elapsed() > Duration::from_secs(5))
        {
            self.recent.pop_front();
        }
        if ended {
            self.rx = None;
            self.session = None;
            self.connected = false;
        }
    }

    fn on_message(&mut self, m: mqtt::Msg) {
        let now = Instant::now();
        self.total_msgs += 1;
        self.total_bytes += m.payload.len() as u64;
        self.recent.push_back(now);
        if self.recent.len() > 100_000 {
            self.recent.pop_front();
        }
        if !self.topics.contains_key(&m.topic) {
            if self.topics.len() >= MAX_TOPICS {
                self.dropped_topics += 1;
                return;
            }
            self.topic_set.insert(m.topic.clone());
            self.rows_dirty = true;
        }
        let mut prefix = String::new();
        for (i, level) in m.topic.split('/').enumerate() {
            if i > 0 {
                prefix.push('/');
            }
            prefix.push_str(level);
            *self.agg.entry(prefix.clone()).or_default() += 1;
        }
        let st = self.topics.entry(m.topic).or_insert_with(|| TopicStat {
            count: 0,
            bytes: 0,
            first: now,
            last: now,
            qos: 0,
            retained: false,
            dup: false,
            props: Vec::new(),
            history: VecDeque::new(),
        });
        st.count += 1;
        st.bytes += m.payload.len() as u64;
        st.last = now;
        st.qos = m.qos;
        st.retained = m.retain;
        st.dup = m.dup;
        st.props = m.props;
        let mut p = m.payload;
        p.truncate(16 * 1024);
        st.history.push_front((now, p, m.retain));
        st.history.truncate(HISTORY);
    }

    fn rebuild_rows(&mut self, search: &str) {
        self.rows.clear();
        if !search.is_empty() {
            let s = search.to_lowercase();
            for t in &self.topic_set {
                if t.to_lowercase().contains(&s) {
                    self.rows.push(Row {
                        path: t.clone(),
                        name: t.clone(),
                        depth: 0,
                        has_children: false,
                        is_topic: true,
                    });
                }
            }
            return;
        }
        let mut emitted: HashSet<String> = HashSet::new();
        let topics: Vec<&String> = self.topic_set.iter().collect();
        for t in &topics {
            let levels: Vec<&str> = t.split('/').collect();
            let mut prefix = String::new();
            for (d, l) in levels.iter().enumerate() {
                if d > 0 {
                    prefix.push('/');
                }
                prefix.push_str(l);
                if emitted.contains(&prefix) {
                    if !self.expanded.contains(&prefix) {
                        break;
                    }
                    continue;
                }
                emitted.insert(prefix.clone());
                let is_topic = d == levels.len() - 1;
                // A deeper topic shares this prefix (sorted order: it's next).
                let child = format!("{prefix}/");
                let has_children = !is_topic
                    || self
                        .topic_set
                        .range(child.clone()..)
                        .next()
                        .is_some_and(|n| n.starts_with(&child));
                self.rows.push(Row {
                    path: prefix.clone(),
                    name: if l.is_empty() {
                        "(empty)".into()
                    } else {
                        l.to_string()
                    },
                    depth: d,
                    has_children,
                    is_topic: self.topic_set.contains(&prefix),
                });
                if !self.expanded.contains(&prefix) {
                    break;
                }
            }
        }
    }

    fn subscribe(&mut self, cx: &mut Context<Self>) {
        let f = self.sub_filter.read(cx).value.trim().to_string();
        if let Err(e) = mqtt::validate_filter(&f) {
            self.error = Some(e);
            return;
        }
        self.error = None;
        if !self.subs.iter().any(|(x, _)| *x == f) {
            self.subs.push((f.clone(), self.sub_qos));
        }
        if let Some(s) = &self.session {
            s.send(Cmd::Subscribe(f, self.sub_qos));
        }
    }

    fn unsubscribe(&mut self, i: usize) {
        if i >= self.subs.len() {
            return;
        }
        let (f, _) = self.subs.remove(i);
        if let Some(s) = &self.session {
            s.send(Cmd::Unsubscribe(f));
        }
    }

    fn publish(&mut self, cx: &mut Context<Self>) {
        let topic = self.pub_topic.read(cx).value.trim().to_string();
        if let Err(e) = mqtt::validate_topic(&topic) {
            self.error = Some(e);
            return;
        }
        let Some(s) = &self.session else {
            self.error = Some("Not connected".into());
            return;
        };
        self.error = None;
        s.send(Cmd::Publish {
            topic,
            payload: self.pub_payload.read(cx).value.clone().into_bytes(),
            qos: self.pub_qos,
            retain: self.pub_retain,
        });
    }

    fn clear(&mut self) {
        self.topics.clear();
        self.topic_set.clear();
        self.agg.clear();
        self.rows.clear();
        self.selected = None;
        self.total_msgs = 0;
        self.total_bytes = 0;
        self.dropped_topics = 0;
        self.recent.clear();
    }

    // ------------------------------------------------ rendering

    fn render_row(&self, i: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(r) = self.rows.get(i) else {
            return div().into_any_element();
        };
        let view = cx.entity().downgrade();
        let st = self.topics.get(&r.path);
        let count = self.agg.get(&r.path).copied().unwrap_or(0);
        let open = self.expanded.contains(&r.path);
        let sel = self.selected.as_deref() == Some(r.path.as_str());
        let path = r.path.clone();
        let has_children = r.has_children;
        let is_topic = r.is_topic;
        div()
            .id(("mq-row", i))
            .flex()
            .items_center()
            .h(px(26.))
            .px_3()
            .text_sm()
            .cursor_pointer()
            .bg(rgb(if sel { C::SELECT } else { C::BG }))
            .hover(|s| s.bg(rgb(C::PANEL2)))
            .on_click(act(&view, move |t: &mut Self, _, _| {
                if has_children {
                    if !t.expanded.remove(&path) {
                        t.expanded.insert(path.clone());
                    }
                    t.rows_dirty = true;
                }
                if is_topic {
                    t.selected = Some(path.clone());
                    t.pane = Pane::Topic;
                }
            }))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .items_center()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .pl(px(r.depth as f32 * 16.))
                    .child(
                        div()
                            .w(px(16.))
                            .flex_none()
                            .text_color(rgb(C::MUTED))
                            .child(if r.has_children {
                                if open { "▾" } else { "▸" }
                            } else {
                                ""
                            }),
                    )
                    .child(
                        div()
                            .text_color(rgb(if r.path.starts_with('$') {
                                C::PURPLE
                            } else if r.is_topic {
                                C::TEXT
                            } else {
                                C::CYAN
                            }))
                            .child(r.name.clone()),
                    )
                    .when_some(st.filter(|_| !r.has_children || open), |d, st| {
                        let (prev, _) = payload_text(
                            st.history.front().map(|h| h.1.as_slice()).unwrap_or(&[]),
                            80,
                        );
                        d.child(
                            div()
                                .pl_3()
                                .text_xs()
                                .text_color(rgb(C::MUTED))
                                .child(format!(
                                    "= {}",
                                    prev.lines()
                                        .next()
                                        .unwrap_or("")
                                        .chars()
                                        .take(60)
                                        .collect::<String>()
                                )),
                        )
                    }),
            )
            .child(cell(70., count.to_string()).text_color(rgb(C::MUTED)))
            .child(
                cell(
                    70.,
                    st.and_then(|s| s.rate())
                        .map(|r| format!("{r:.1}/s"))
                        .unwrap_or_default(),
                )
                .text_color(rgb(C::MUTED)),
            )
            .child(cell(60., st.map(|s| ago(s.last)).unwrap_or_default()).text_color(rgb(C::MUTED)))
            .child(
                cell(
                    44.,
                    st.map(|s| format!("{}{}", s.qos, if s.retained { " R" } else { "" }))
                        .unwrap_or_default(),
                )
                .text_color(rgb(C::MUTED)),
            )
            .into_any_element()
    }

    fn topic_pane(&self) -> gpui::AnyElement {
        let Some((topic, st)) = self
            .selected
            .as_ref()
            .and_then(|t| self.topics.get(t).map(|s| (t, s)))
        else {
            return empty_state(
                "No topic selected",
                "Click a topic in the tree to see its payloads.",
            )
            .into_any_element();
        };
        let (latest, kind) = payload_text(
            st.history.front().map(|h| h.1.as_slice()).unwrap_or(&[]),
            32 * 1024,
        );
        let copy = latest.clone();
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(topic.clone()),
                    )
                    .child(chip("mq-copy-payload", "Copy", false, move |_, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()))
                    })),
            )
            .child(label(format!(
                "{} messages · {} bytes · QoS {} · {} · last {} ago{}",
                st.count,
                st.bytes,
                st.qos,
                kind,
                ago(st.last),
                if st.retained { " · retained" } else { "" }
            )))
            .when_some(st.rate(), |d, r| {
                d.child(label(format!(
                    "{r:.2} msg/s (≈ every {:.1} s)",
                    1.0 / r.max(1e-6)
                )))
            })
            .when(st.dup, |d| {
                d.child(label(
                    "Last message had the DUP flag (a QoS 1/2 redelivery)",
                ))
            })
            .children(
                st.props
                    .iter()
                    .map(|(k, v)| kv_row(k.clone(), v.clone(), 150.)),
            )
            .child(label(format!(
                "Matched by: {}",
                self.subs
                    .iter()
                    .filter(|(f, _)| mqtt::topic_matches(f, topic))
                    .map(|(f, _)| f.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
            .child(mono_block(&latest))
            .when(st.history.len() > 1, |d| {
                d.child(section_title("History"))
                    .children(st.history.iter().skip(1).map(|(t, p, r)| {
                        let (txt, _) = payload_text(p, 200);
                        div()
                            .flex()
                            .gap_2()
                            .text_xs()
                            .child(
                                div()
                                    .w(px(60.))
                                    .flex_none()
                                    .text_color(rgb(C::MUTED))
                                    .child(ago(*t)),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .font_family(mono())
                                    .child(format!(
                                        "{}{}",
                                        if *r { "[R] " } else { "" },
                                        txt.replace('\n', " ")
                                            .chars()
                                            .take(160)
                                            .collect::<String>()
                                    )),
                            )
                    }))
            })
            .into_any_element()
    }

    fn broker_pane(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let view = cx.entity().downgrade();
        let sys: Vec<(&String, &TopicStat)> = self
            .topic_set
            .iter()
            .filter(|t| t.starts_with("$SYS/"))
            .filter_map(|t| self.topics.get(t).map(|s| (t, s)))
            .collect();
        let val = |suffix: &str| -> Option<String> {
            sys.iter()
                .find(|(t, _)| t.ends_with(suffix))
                .and_then(|(_, s)| s.history.front())
                .map(|h| String::from_utf8_lossy(&h.1).trim().to_string())
        };
        let known = [
            ("Version", "/broker/version"),
            ("Uptime", "/broker/uptime"),
            ("Clients connected", "/broker/clients/connected"),
            ("Clients total", "/broker/clients/total"),
            ("Clients maximum", "/broker/clients/maximum"),
            ("Subscriptions", "/broker/subscriptions/count"),
            ("Retained messages", "/broker/retained messages/count"),
            ("Messages received", "/broker/messages/received"),
            ("Messages sent", "/broker/messages/sent"),
            ("Messages stored", "/broker/messages/stored"),
            ("Msgs in / min", "/broker/load/messages/received/1min"),
            ("Msgs out / min", "/broker/load/messages/sent/1min"),
            ("Bytes in / min", "/broker/load/bytes/received/1min"),
            ("Bytes out / min", "/broker/load/bytes/sent/1min"),
            ("Heap", "/broker/heap/current"),
        ];
        let subscribed = self.subs.iter().any(|(f, _)| f.starts_with("$SYS"));
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(label(
                        "Broker statistics from $SYS topics (Mosquitto, EMQX, VerneMQ, HiveMQ with plugin).",
                    ))
                    .when(!subscribed, |d| {
                        d.child(button2(
                            "mq-sys",
                            "Subscribe $SYS/#",
                            act(&view, |t: &mut Self, _, _| {
                                t.subs.push(("$SYS/#".into(), 0));
                                if let Some(s) = &t.session {
                                    s.send(Cmd::Subscribe("$SYS/#".into(), 0));
                                }
                            }),
                        ))
                    }),
            )
            .when(sys.is_empty(), |d| {
                d.child(label(if subscribed {
                    "No $SYS messages yet (the broker may not publish them, or publishes every 10 s or more)."
                } else {
                    "Not subscribed to $SYS/# ('#' does not include $ topics)."
                }))
            })
            .child(
                div().flex().flex_wrap().gap_2().children(
                    known
                        .iter()
                        .filter_map(|(k, s)| val(s).map(|v| tile(*k, v, C::TEXT))),
                ),
            )
            .when(!sys.is_empty(), |d| {
                d.child(section_title(&format!("All $SYS topics ({})", sys.len())))
                    .children(sys.iter().map(|(t, s)| {
                        div()
                            .flex()
                            .gap_2()
                            .text_xs()
                            .child(
                                div()
                                    .w(px(320.))
                                    .flex_none()
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .text_color(rgb(C::MUTED))
                                    .child(t.trim_start_matches("$SYS/").to_string()),
                            )
                            .child(
                                div().flex_1().min_w_0().font_family(mono()).child(
                                    s.history
                                        .front()
                                        .map(|h| {
                                            String::from_utf8_lossy(&h.1)
                                                .chars()
                                                .take(120)
                                                .collect::<String>()
                                        })
                                        .unwrap_or_default(),
                                ),
                            )
                    }))
            })
            .into_any_element()
    }

    fn log_pane(&self) -> gpui::AnyElement {
        let start = self.log.first().map(|l| l.0);
        div()
            .flex()
            .flex_col()
            .gap_1()
            .text_xs()
            .font_family(mono())
            .when(self.log.is_empty(), |d| {
                d.child(label("Connection events will appear here."))
            })
            .children(self.log.iter().rev().take(400).rev().map(|(t, l, s)| {
                let c = match l {
                    Lvl::Info => C::TEXT,
                    Lvl::Good => C::GREEN,
                    Lvl::Warn => C::AMBER,
                    Lvl::Bad => C::RED,
                };
                div()
                    .flex()
                    .gap_2()
                    .child(
                        div()
                            .w(px(64.))
                            .flex_none()
                            .text_color(rgb(C::MUTED))
                            .child(format!(
                                "{:.3}",
                                start
                                    .map(|s| t.duration_since(s).as_secs_f64())
                                    .unwrap_or(0.0)
                            )),
                    )
                    .child(div().flex_1().min_w_0().text_color(rgb(c)).child(s.clone()))
            }))
            .into_any_element()
    }
}

impl Focusable for MqttView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for MqttView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let search = self.search.read(cx).value.trim().to_string();
        if self.rows_dirty || search != self.last_search {
            self.rebuild_rows(&search);
            self.rows_dirty = false;
            self.last_search = search;
        }
        let running = self.running();
        let rate = self.recent.len() as f64 / 5.0;
        let pane_body = match self.pane {
            Pane::Topic => self.topic_pane(),
            Pane::Broker => self.broker_pane(cx),
            Pane::Log => self.log_pane(),
        };
        let tree = if self.rows.is_empty() {
            empty_state(
                if self.connected {
                    "Waiting for messages…"
                } else {
                    "Not connected"
                },
                "Connect, subscribe (default '#'), and topics appear here as a tree.",
            )
            .into_any_element()
        } else {
            uniform_list(
                "mq-tree",
                self.rows.len(),
                cx.processor(|this, range: Range<usize>, _, cx| {
                    range.map(|i| this.render_row(i, cx)).collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.tree_scroll.clone())
            .flex_1()
            .into_any_element()
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Broker"))
                    .child(self.broker.clone())
                    .child(chip(
                        "mq-tls",
                        "TLS",
                        self.tls,
                        act(&view, |t: &mut Self, _, _| t.tls = !t.tls),
                    ))
                    .when(self.tls, |d| {
                        d.child(chip(
                            "mq-insecure",
                            "Accept invalid cert",
                            self.insecure,
                            act(&view, |t: &mut Self, _, _| t.insecure = !t.insecure),
                        ))
                    })
                    .child(chip(
                        "mq-v5",
                        "MQTT 5",
                        self.v5,
                        act(&view, |t: &mut Self, _, _| t.v5 = !t.v5),
                    ))
                    .child(chip(
                        "mq-clean",
                        "Clean session",
                        self.clean,
                        act(&view, |t: &mut Self, _, _| t.clean = !t.clean),
                    ))
                    .child(label("Client ID"))
                    .child(self.client_id.clone())
                    .child(self.user.clone())
                    .child(self.pass.clone())
                    .child(label("Keepalive"))
                    .child(self.keepalive.clone())
                    .child(if running {
                        button(
                            "mq-go",
                            if self.connected {
                                "■ Disconnect"
                            } else {
                                "Cancel"
                            },
                            C::RED,
                            C::RED_HOVER,
                            act(&view, |t: &mut Self, _, _| t.disconnect()),
                        )
                    } else {
                        button_primary(
                            "mq-go",
                            "▶ Connect",
                            act(&view, |t: &mut Self, _, cx| t.connect(cx)),
                        )
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
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .px_5()
                    .py_2()
                    .child(tile("Messages", self.total_msgs.to_string(), C::TEXT))
                    .child(tile("Rate (5 s)", format!("{rate:.1}/s"), C::CYAN))
                    .child(tile(
                        "Topics",
                        format!(
                            "{}{}",
                            self.topics.len(),
                            if self.dropped_topics > 0 { "+" } else { "" }
                        ),
                        C::TEXT,
                    ))
                    .child(tile(
                        "Data",
                        crate::widgets::mbit(self.total_bytes as f64 * 8.0)
                            .replace("/s", "")
                            .replace("bit", "b"),
                        C::TEXT,
                    ))
                    .child(tile(
                        "Ping RTT",
                        self.rtt
                            .map(|r| format!("{r:.0} ms"))
                            .unwrap_or_else(|| "-".into()),
                        C::GREEN,
                    ))
                    .child(tile(
                        "Packets in / out",
                        format!("{} / {}", self.pkts_in, self.pkts_out),
                        C::MUTED,
                    ))
                    .child(tile(
                        "Wire bytes in / out",
                        format!("{} / {}", self.wire_in, self.wire_out),
                        C::MUTED,
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .border_t_1()
                    .border_color(rgb(C::BORDER))
                    // Tree
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .border_r_1()
                            .border_color(rgb(C::BORDER))
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap_2()
                                    .px_3()
                                    .py_2()
                                    .child(label("Subscribe"))
                                    .child(self.sub_filter.clone())
                                    .children((0..3u8).map(|q| {
                                        chip(
                                            ("mq-sq", q as usize),
                                            format!("QoS {q}"),
                                            self.sub_qos == q,
                                            act(&view, move |t: &mut Self, _, _| t.sub_qos = q),
                                        )
                                    }))
                                    .child(button2(
                                        "mq-sub",
                                        "Subscribe",
                                        act(&view, |t: &mut Self, _, cx| t.subscribe(cx)),
                                    )),
                            )
                            .when(!self.subs.is_empty(), |d| {
                                d.child(div().flex().flex_wrap().gap_2().px_3().pb_2().children(
                                    self.subs.iter().enumerate().map(|(i, (f, q))| {
                                        chip(
                                            ("mq-unsub", i),
                                            format!("{f}  (QoS {q})  ✕"),
                                            true,
                                            act(&view, move |t: &mut Self, _, _| t.unsubscribe(i)),
                                        )
                                    }),
                                ))
                            })
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .px_3()
                                    .pb_2()
                                    .child(self.search.clone())
                                    .child(chip(
                                        "mq-collapse",
                                        "Collapse all",
                                        false,
                                        act(&view, |t: &mut Self, _, _| {
                                            t.expanded.clear();
                                            t.rows_dirty = true;
                                        }),
                                    ))
                                    .child(chip(
                                        "mq-clear",
                                        "Clear",
                                        false,
                                        act(&view, |t: &mut Self, _, _| t.clear()),
                                    )),
                            )
                            .child(table_header(&[
                                ("TOPIC", 0.),
                                ("MSGS", 70.),
                                ("RATE", 70.),
                                ("LAST", 60.),
                                ("QOS", 44.),
                            ]))
                            .child(tree),
                    )
                    // Detail
                    .child(
                        div()
                            .w(px(520.))
                            .flex_none()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .px_3()
                                    .py_2()
                                    .border_b_1()
                                    .border_color(rgb(C::BORDER))
                                    .children(
                                        [
                                            (Pane::Topic, "Topic"),
                                            (Pane::Broker, "Broker ($SYS)"),
                                            (Pane::Log, "Connection log"),
                                        ]
                                        .into_iter()
                                        .enumerate()
                                        .map(
                                            |(i, (p, n))| {
                                                chip(
                                                    ("mq-pane", i),
                                                    n,
                                                    self.pane == p,
                                                    act(&view, move |t: &mut Self, _, _| {
                                                        t.pane = p
                                                    }),
                                                )
                                            },
                                        ),
                                    ),
                            )
                            .child(
                                div()
                                    .id("mq-pane-body")
                                    .flex_1()
                                    .min_h_0()
                                    .p_3()
                                    .overflow_y_scroll()
                                    .child(pane_body),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .p_3()
                                    .border_t_1()
                                    .border_color(rgb(C::BORDER))
                                    .bg(rgb(C::PANEL))
                                    .child(section_title("Publish"))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(self.pub_topic.clone())
                                            .children((0..3u8).map(|q| {
                                                chip(
                                                    ("mq-pq", q as usize),
                                                    format!("QoS {q}"),
                                                    self.pub_qos == q,
                                                    act(&view, move |t: &mut Self, _, _| {
                                                        t.pub_qos = q
                                                    }),
                                                )
                                            }))
                                            .child(chip(
                                                "mq-retain",
                                                "Retain",
                                                self.pub_retain,
                                                act(&view, |t: &mut Self, _, _| {
                                                    t.pub_retain = !t.pub_retain
                                                }),
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(self.pub_payload.clone())
                                            .child(if self.connected {
                                                button_primary(
                                                    "mq-pub",
                                                    "Publish",
                                                    act(&view, |t: &mut Self, _, cx| t.publish(cx)),
                                                )
                                            } else {
                                                button(
                                                    "mq-pub",
                                                    "Publish",
                                                    C::PANEL2,
                                                    C::PANEL2,
                                                    |_, _, _| {},
                                                )
                                            }),
                                    ),
                            ),
                    ),
            )
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .when_some(self.connected_at.filter(|_| self.connected), |d, t| {
                        d.child(format!("connected for {}", ago(t)))
                    }),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_kinds() {
        assert_eq!(payload_text(b"21.5", 100), ("21.5".into(), "text"));
        let (j, k) = payload_text(br#"{"a":1}"#, 100);
        assert_eq!(k, "JSON");
        assert!(j.contains("\"a\": 1"));
        let (h, k) = payload_text(&[0, 1, 0xff], 100);
        assert_eq!(k, "binary");
        assert!(h.starts_with("0000  00 01 ff"));
        assert_eq!(payload_text(b"", 10).1, "empty");
    }
}
