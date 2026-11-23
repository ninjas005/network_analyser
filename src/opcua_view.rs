//! OPC UA tool: endpoint discovery with a security review, then an
//! anonymous or user-name session (SecurityPolicy None) to browse the
//! address space, read node attributes and watch values.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, UniformListScrollHandle,
    Window, div, prelude::*, px, rgb, uniform_list,
};

use crate::gateway::Level;
use crate::mqtt_view::SecretInput;
use crate::opcua::{
    self, Auth, Cmd, DataValue, Discovery, Event, Handle, NodeId, Reference, SessionInfo, Value,
};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, button2, cell, chip, empty_state,
    findings_cards, findings_text, input, kv_row, label, level_color, mono, section_title,
    status_bar, table_header, tile, toolbar,
};

type AttrResult = Result<Vec<(u32, DataValue)>, String>;

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Browse,
    Endpoints,
    Log,
}

#[derive(Clone)]
struct TreeRow {
    node: NodeId,
    name: String,
    class: u32,
    depth: usize,
}

pub struct OpcUaView {
    focus: FocusHandle,
    url: Entity<TextInput>,
    user: Entity<TextInput>,
    pass: Entity<SecretInput>,
    goto: Entity<TextInput>,
    use_user: bool,

    handle: Option<Handle>,
    rx: Option<Receiver<Event>>,
    discovering: bool,
    discovery: Option<Discovery>,
    session: Option<SessionInfo>,
    server_time: Option<String>,
    tab: Tab,

    children: HashMap<NodeId, Vec<Reference>>,
    browse_errors: HashMap<NodeId, String>,
    expanded: HashSet<NodeId>,
    loading: HashSet<NodeId>,
    rows: Vec<TreeRow>,
    rows_dirty: bool,
    selected: Option<NodeId>,
    names: HashMap<NodeId, String>,
    attrs: Option<(NodeId, AttrResult)>,
    watch: Vec<NodeId>,
    watch_vals: HashMap<NodeId, (DataValue, Instant)>,
    tree_scroll: UniformListScrollHandle,

    log: Vec<(Level, String)>,
    status: SharedString,
    error: Option<String>,
    _poll: Option<Task<()>>,
}

fn value_rank(v: &Value) -> String {
    match v {
        Value::Int(-3, _) => "scalar or one dimension".into(),
        Value::Int(-2, _) => "any".into(),
        Value::Int(-1, _) => "scalar".into(),
        Value::Int(0, _) => "one or more dimensions".into(),
        Value::Int(n, _) => format!("array, {n} dimension(s)"),
        v => v.display(),
    }
}

fn attr_value(attr: u32, d: &DataValue) -> String {
    if !opcua::is_good(d.status) {
        return opcua::status_name(d.status);
    }
    match (attr, &d.value) {
        (2, Value::Int(c, _)) => opcua::node_class_name(*c as u32).into(),
        (14, Value::NodeId(n)) => opcua::data_type_name(n),
        (15, v) => value_rank(v),
        (17 | 18, Value::UInt(a, _)) => opcua::access_level_text(*a),
        (12, Value::UInt(e, _)) => {
            if *e & 1 != 0 {
                "subscribes to events".into()
            } else {
                "none".into()
            }
        }
        (_, v) => v.display(),
    }
}

fn class_tag(c: u32) -> (&'static str, u32) {
    match c {
        1 => ("O", C::ACCENT),
        2 => ("V", C::GREEN),
        4 => ("M", C::AMBER),
        8 | 16 | 32 | 64 => ("T", C::PURPLE),
        128 => ("W", C::CYAN),
        _ => ("?", C::MUTED),
    }
}

impl OpcUaView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let pass = cx.new(|cx| SecretInput::new(cx, "password", 120.));
        Self {
            focus: cx.focus_handle(),
            url: input(
                window,
                cx,
                "",
                "opc.tcp://host:4840[/path]",
                Accept::Any,
                |t| t.width(340.).max_len(512),
                |t: &mut Self, _, cx| t.start(Auth::DiscoverOnly, cx),
            ),
            user: input(
                window,
                cx,
                "",
                "user",
                Accept::Any,
                |t| t.width(120.),
                |_: &mut Self, _, _| {},
            ),
            pass,
            goto: input(
                window,
                cx,
                "",
                "go to NodeId, e.g. ns=2;s=Demo.Static.Scalar.Double",
                Accept::Any,
                |t| t.max_len(512),
                |t: &mut Self, _, cx| t.goto_node(cx),
            ),
            use_user: false,
            handle: None,
            rx: None,
            discovering: false,
            discovery: None,
            session: None,
            server_time: None,
            tab: Tab::Endpoints,
            children: HashMap::new(),
            browse_errors: HashMap::new(),
            expanded: HashSet::new(),
            loading: HashSet::new(),
            rows: Vec::new(),
            rows_dirty: false,
            selected: None,
            names: HashMap::new(),
            attrs: None,
            watch: Vec::new(),
            watch_vals: HashMap::new(),
            tree_scroll: UniformListScrollHandle::new(),
            log: Vec::new(),
            status: "Discover lists endpoints and security; Connect opens a session (SecurityPolicy None)."
                .into(),
            error: None,
            _poll: None,
        }
    }

    fn running(&self) -> bool {
        self.handle.is_some()
    }

    fn start(&mut self, auth: Auth, cx: &mut Context<Self>) {
        if self.running() {
            return;
        }
        let raw = self.url.read(cx).value.trim().to_string();
        if raw.is_empty() {
            self.error = Some("Enter a server address".into());
            return;
        }
        let url = opcua::normalize_url(&raw);
        if let Err(e) = opcua::parse_url(&url) {
            self.error = Some(e);
            return;
        }
        if url != raw {
            self.url.update(cx, |t, cx| t.set(url.clone(), cx));
        }
        let auth = match auth {
            Auth::DiscoverOnly => Auth::DiscoverOnly,
            _ if self.use_user => {
                let u = self.user.read(cx).value.trim().to_string();
                if u.is_empty() {
                    self.error = Some("Enter a user name (or choose Anonymous)".into());
                    return;
                }
                Auth::User(u, self.pass.read(cx).value.clone())
            }
            _ => Auth::Anonymous,
        };
        self.error = None;
        self.discovering = matches!(auth, Auth::DiscoverOnly);
        self.session = None;
        self.server_time = None;
        self.children.clear();
        self.browse_errors.clear();
        self.expanded.clear();
        self.loading.clear();
        self.rows.clear();
        self.selected = None;
        self.attrs = None;
        self.watch_vals.clear();
        self.log.clear();
        let objects = NodeId::num(0, opcua::OBJECTS);
        self.expanded.insert(objects.clone());
        self.loading.insert(objects.clone());
        self.names.insert(objects, "Objects".into());
        let (h, rx) = opcua::start(url.clone(), auth, Duration::from_secs(10));
        if !self.watch.is_empty() && !self.discovering {
            h.send(Cmd::SetWatch(self.watch.clone()));
        }
        self.handle = Some(h);
        self.rx = Some(rx);
        self.status = format!("Connecting to {url}…").into();
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

    fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.send(Cmd::Disconnect);
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
        }
        for e in events {
            match e {
                Event::Log(l, s) => self.log.push((l, s)),
                Event::Discovery(d) => {
                    let bad = d
                        .findings
                        .iter()
                        .filter(|f| matches!(f.level, Level::Bad))
                        .count();
                    self.status = format!(
                        "{} endpoint(s), {bad} security problem(s)",
                        d.endpoints.len()
                    )
                    .into();
                    self.discovery = Some(*d);
                    if self.discovering {
                        self.tab = Tab::Endpoints;
                    }
                }
                Event::Session(s) => {
                    self.status = format!(
                        "Session open — {} {} ({})",
                        s.product, s.version, s.identity
                    )
                    .into();
                    self.session = Some(s);
                    self.tab = Tab::Browse;
                }
                Event::Browsed(n, r) => {
                    self.loading.remove(&n);
                    match r {
                        Ok(refs) => {
                            for r in &refs {
                                self.names.insert(r.node.clone(), r.display.clone());
                            }
                            self.browse_errors.remove(&n);
                            self.children.insert(n, refs);
                        }
                        Err(e) => {
                            self.log.push((Level::Warn, format!("Browse {n}: {e}")));
                            self.browse_errors.insert(n.clone(), e);
                            self.children.insert(n, Vec::new());
                        }
                    }
                    self.rows_dirty = true;
                }
                Event::Attrs(n, r) => self.attrs = Some((n, r)),
                Event::Watch(vals) => {
                    for (n, d) in vals {
                        let changed = self
                            .watch_vals
                            .get(&n)
                            .is_none_or(|(old, _)| old.value != d.value || old.status != d.status);
                        let at = if changed {
                            Instant::now()
                        } else {
                            self.watch_vals[&n].1
                        };
                        self.watch_vals.insert(n, (d, at));
                    }
                }
                Event::ServerTime(t) => self.server_time = Some(t),
                Event::Closed(s) => {
                    self.log.push((Level::Info, s.clone()));
                    if !self.discovering {
                        self.status = s.into();
                    }
                    ended = true;
                }
                Event::Error(e) => {
                    self.log.push((Level::Bad, e.clone()));
                    self.status = "Failed — see the message above".into();
                    self.error = Some(e);
                    if self.session.is_none() && self.discovery.is_none() {
                        self.tab = Tab::Log;
                    }
                    ended = true;
                }
            }
        }
        if ended {
            self.rx = None;
            self.handle = None;
            self.discovering = false;
            self.loading.clear();
        }
    }

    fn rebuild_rows(&mut self) {
        let mut rows = Vec::new();
        let root = NodeId::num(0, opcua::OBJECTS);
        rows.push(TreeRow {
            node: root.clone(),
            name: "Objects".into(),
            class: 1,
            depth: 0,
        });
        let mut path = vec![root.clone()];
        self.walk(&root, 1, &mut path, &mut rows);
        self.rows = rows;
    }

    fn walk(&self, n: &NodeId, depth: usize, path: &mut Vec<NodeId>, rows: &mut Vec<TreeRow>) {
        if !self.expanded.contains(n) || depth > 32 {
            return;
        }
        let Some(kids) = self.children.get(n) else {
            return;
        };
        for r in kids.iter().filter(|r| r.forward) {
            rows.push(TreeRow {
                node: r.node.clone(),
                name: if r.display.is_empty() {
                    r.browse_name.1.clone()
                } else {
                    r.display.clone()
                },
                class: r.class,
                depth,
            });
            if !path.contains(&r.node) {
                path.push(r.node.clone());
                self.walk(&r.node, depth + 1, path, rows);
                path.pop();
            }
        }
    }

    fn click_node(&mut self, n: NodeId) {
        let Some(h) = &self.handle else {
            self.selected = Some(n);
            return;
        };
        if self.selected.as_ref() == Some(&n) || n.id == opcua::Ident::Num(opcua::OBJECTS) {
            // Second click (or the root) toggles.
            if !self.expanded.remove(&n) {
                self.expanded.insert(n.clone());
                if !self.children.contains_key(&n) && self.loading.insert(n.clone()) {
                    h.send(Cmd::Browse(n.clone()));
                }
            }
            self.rows_dirty = true;
        } else {
            if !self.children.contains_key(&n) && !self.expanded.contains(&n) {
                // First click on an unbrowsed node: select and expand.
                self.expanded.insert(n.clone());
                if self.loading.insert(n.clone()) {
                    h.send(Cmd::Browse(n.clone()));
                }
                self.rows_dirty = true;
            }
            h.send(Cmd::Read(n.clone()));
        }
        self.selected = Some(n);
    }

    fn goto_node(&mut self, cx: &mut Context<Self>) {
        let s = self.goto.read(cx).value.clone();
        match NodeId::parse(&s) {
            Ok(n) => {
                self.error = None;
                self.selected = Some(n.clone());
                if let Some(h) = &self.handle {
                    h.send(Cmd::Read(n));
                } else {
                    self.error = Some("Connect a session first".into());
                }
            }
            Err(e) => self.error = Some(format!("NodeId: {e}")),
        }
    }

    fn toggle_watch(&mut self, n: NodeId) {
        if let Some(i) = self.watch.iter().position(|w| *w == n) {
            self.watch.remove(i);
            self.watch_vals.remove(&n);
        } else {
            self.watch.push(n);
        }
        if let Some(h) = &self.handle {
            h.send(Cmd::SetWatch(self.watch.clone()));
        }
    }

    // ------------------------------------------------ rendering

    fn render_row(&self, i: usize, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(r) = self.rows.get(i) else {
            return div().into_any_element();
        };
        let view = cx.entity().downgrade();
        let sel = self.selected.as_ref() == Some(&r.node);
        let (tag, tag_color) = class_tag(r.class);
        let arrow = if self.loading.contains(&r.node) {
            "…"
        } else if self.expanded.contains(&r.node) {
            match self.children.get(&r.node) {
                Some(k) if k.iter().all(|r| !r.forward) => " ",
                _ => "▾",
            }
        } else if r.class == 4 {
            " "
        } else {
            "▸"
        };
        let node = r.node.clone();
        div()
            .id(("ua-row", i))
            .flex()
            .items_center()
            .h(px(26.))
            .px_3()
            .text_sm()
            .cursor_pointer()
            .bg(rgb(if sel { C::SELECT } else { C::BG }))
            .hover(|s| s.bg(rgb(C::PANEL2)))
            .on_click(act(&view, move |t: &mut Self, _, _| {
                t.click_node(node.clone())
            }))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .items_center()
                    .gap_1()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .pl(px(r.depth as f32 * 16.))
                    .child(
                        div()
                            .w(px(14.))
                            .flex_none()
                            .text_color(rgb(C::MUTED))
                            .child(arrow),
                    )
                    .child(
                        div()
                            .w(px(18.))
                            .flex_none()
                            .text_xs()
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(rgb(tag_color))
                            .child(tag),
                    )
                    .child(r.name.clone())
                    .when(self.watch.contains(&r.node), |d| {
                        d.child(div().text_xs().text_color(rgb(C::CYAN)).child("●"))
                    }),
            )
            .into_any_element()
    }

    fn endpoints_tab(&self) -> gpui::AnyElement {
        let Some(d) = &self.discovery else {
            return empty_state(
                if self.running() {
                    "Connecting…"
                } else {
                    "No server yet"
                },
                "Enter opc.tcp://host:4840 and press Discover. Public demo: opc.tcp://opcuaserver.com:48010",
            )
            .into_any_element();
        };
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(tile("Endpoints", d.endpoints.len().to_string(), C::TEXT))
                    .child(tile(
                        "Address",
                        d.addr.map(|a| a.to_string()).unwrap_or_default(),
                        C::TEXT,
                    ))
                    .child(tile("Connect", format!("{:.0} ms", d.connect_ms), C::TEXT)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(C::BORDER))
                    .overflow_hidden()
                    .child(table_header(&[
                        ("MODE", 130.),
                        ("POLICY", 190.),
                        ("LOGIN", 230.),
                        ("LEVEL", 60.),
                        ("ENDPOINT URL", 0.),
                    ]))
                    .children(d.endpoints.iter().enumerate().map(|(i, e)| {
                        let (mc, pc) = (
                            match e.mode {
                                1 => C::RED,
                                2 => C::AMBER,
                                _ => C::GREEN,
                            },
                            match opcua::policy_short(&e.policy).as_str() {
                                "None" => C::RED,
                                "Basic128Rsa15" | "Basic256" => C::AMBER,
                                _ => C::GREEN,
                            },
                        );
                        div()
                            .flex()
                            .items_center()
                            .h(px(30.))
                            .px_3()
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(cell(130., opcua::mode_name(e.mode)).text_color(rgb(mc)))
                            .child(cell(190., opcua::policy_short(&e.policy)).text_color(rgb(pc)))
                            .child(cell(
                                230.,
                                e.tokens
                                    .iter()
                                    .map(|t| opcua::token_type_name(t.token_type))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ))
                            .child(cell(60., e.level.to_string()))
                            .child(cell(0., e.url.clone()).text_color(rgb(C::MUTED)))
                    })),
            )
            .child(findings_cards(&d.findings))
            .when(!d.servers.is_empty(), |el| {
                el.child(section_title("Servers known to this discovery endpoint"))
                    .children(d.servers.iter().map(|s| {
                        div().text_sm().child(format!(
                            "{} — {} [{}] {}",
                            s.name,
                            s.uri,
                            opcua::app_type_name(s.app_type),
                            s.discovery_urls.join("  ")
                        ))
                    }))
            })
            .into_any_element()
    }

    fn detail(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let view = cx.entity().downgrade();
        let Some(sel) = self.selected.clone() else {
            return empty_state(
                "Select a node",
                "Click a node to read its attributes; click again to expand or collapse.",
            )
            .into_any_element();
        };
        let watching = self.watch.contains(&sel);
        let name = self.names.get(&sel).cloned().unwrap_or_default();
        let head = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(if name.is_empty() {
                                sel.to_string()
                            } else {
                                name
                            }),
                    )
                    .child(
                        div()
                            .text_xs()
                            .font_family(mono())
                            .text_color(rgb(C::MUTED))
                            .child(sel.to_string()),
                    ),
            )
            .child(chip("ua-copy-id", "Copy NodeId", false, {
                let s = sel.to_string();
                move |_, _, cx| cx.write_to_clipboard(gpui::ClipboardItem::new_string(s.clone()))
            }))
            .child(button2(
                "ua-watch",
                if watching { "Unwatch" } else { "Watch" },
                act(&view, {
                    let sel = sel.clone();
                    move |t: &mut Self, _, _| t.toggle_watch(sel.clone())
                }),
            ))
            .child(button2(
                "ua-refresh",
                "Read again",
                act(&view, {
                    let sel = sel.clone();
                    move |t: &mut Self, _, _| {
                        if let Some(h) = &t.handle {
                            h.send(Cmd::Read(sel.clone()));
                        }
                    }
                }),
            ));
        let body =
            match &self.attrs {
                Some((n, Ok(attrs))) if *n == sel => {
                    let value = attrs.iter().find(|(a, _)| *a == 13).map(|(_, d)| d);
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .text_sm()
                        .when_some(value, |d, v| {
                            d.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .p_3()
                                    .mb_2()
                                    .rounded_md()
                                    .bg(rgb(C::PANEL))
                                    .border_1()
                                    .border_color(rgb(C::BORDER))
                                    .child(label("VALUE"))
                                    .child(
                                        div()
                                            .text_lg()
                                            .font_family(mono())
                                            .text_color(rgb(if opcua::is_good(v.status) {
                                                C::TEXT
                                            } else {
                                                C::RED
                                            }))
                                            .child(if opcua::is_good(v.status) {
                                                v.value.display()
                                            } else {
                                                opcua::status_name(v.status)
                                            }),
                                    )
                                    .child(label(format!(
                                        "{} · {} · source {} · server {}",
                                        v.value.type_name(),
                                        opcua::status_name(v.status),
                                        v.source_ts
                                            .map(opcua::datetime_string)
                                            .unwrap_or_else(|| "-".into()),
                                        v.server_ts
                                            .map(opcua::datetime_string)
                                            .unwrap_or_else(|| "-".into())
                                    ))),
                            )
                        })
                        .children(attrs.iter().filter(|(a, _)| *a != 13).map(|(a, d)| {
                            kv_row(opcua::attribute_name(*a), attr_value(*a, d), 190.)
                        }))
                        .into_any_element()
                }
                Some((n, Err(e))) if *n == sel => div()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .child(e.clone())
                    .into_any_element(),
                _ => label("Reading…").into_any_element(),
            };
        let refs = self.children.get(&sel).filter(|r| !r.is_empty());
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(head)
            .child(body)
            .when_some(self.browse_errors.get(&sel), |d, e| {
                d.child(
                    div()
                        .text_sm()
                        .text_color(rgb(C::AMBER))
                        .child(format!("Browse: {e}")),
                )
            })
            .when_some(refs, |d, refs| {
                d.child(section_title(&format!("References ({})", refs.len())))
                    .children(refs.iter().take(200).map(|r| {
                        div()
                            .flex()
                            .gap_2()
                            .text_xs()
                            .child(
                                div()
                                    .w(px(90.))
                                    .flex_none()
                                    .text_color(rgb(C::MUTED))
                                    .child(opcua::node_class_name(r.class)),
                            )
                            .child(
                                div()
                                    .w(px(150.))
                                    .flex_none()
                                    .text_color(rgb(C::MUTED))
                                    .child(opcua::ref_type_name(&r.ref_type)),
                            )
                            .child(div().w(px(200.)).flex_none().child(r.display.clone()))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .font_family(mono())
                                    .text_color(rgb(C::MUTED))
                                    .child(if r.type_def.is_null() {
                                        r.node.to_string()
                                    } else {
                                        format!(
                                            "{}  ({})",
                                            r.node,
                                            self.names
                                                .get(&r.type_def)
                                                .cloned()
                                                .unwrap_or_else(|| r.type_def.to_string())
                                        )
                                    }),
                            )
                    }))
            })
            .into_any_element()
    }

    fn watch_table(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let view = cx.entity().downgrade();
        if self.watch.is_empty() {
            return div().into_any_element();
        }
        div()
            .id("ua-watch-list")
            .flex_none()
            .max_h(px(240.))
            .overflow_y_scroll()
            .border_t_1()
            .border_color(rgb(C::BORDER))
            .child(table_header(&[
                ("WATCH (1 s)", 220.),
                ("VALUE", 0.),
                ("TYPE", 110.),
                ("STATUS", 150.),
                ("SOURCE TIME", 230.),
                ("", 40.),
            ]))
            .children(self.watch.iter().enumerate().map(|(i, n)| {
                let v = self.watch_vals.get(n);
                let fresh = v.is_some_and(|(_, at)| at.elapsed() < Duration::from_millis(1500));
                let name = self.names.get(n).cloned().unwrap_or_else(|| n.to_string());
                let n2 = n.clone();
                div()
                    .flex()
                    .items_center()
                    .h(px(28.))
                    .px_3()
                    .text_sm()
                    .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                    .child(cell(220., name))
                    .child(
                        cell(
                            0.,
                            v.map(|(d, _)| d.value.display())
                                .unwrap_or_else(|| "…".into()),
                        )
                        .font_family(mono())
                        .text_color(rgb(if fresh {
                            C::CYAN
                        } else {
                            C::TEXT
                        })),
                    )
                    .child(
                        cell(
                            110.,
                            v.map(|(d, _)| d.value.type_name()).unwrap_or_default(),
                        )
                        .text_color(rgb(C::MUTED)),
                    )
                    .child(
                        cell(
                            150.,
                            v.map(|(d, _)| opcua::status_name(d.status))
                                .unwrap_or_default(),
                        )
                        .text_color(rgb(match v {
                            Some((d, _)) if !opcua::is_good(d.status) => C::RED,
                            _ => C::MUTED,
                        })),
                    )
                    .child(
                        cell(
                            230.,
                            v.and_then(|(d, _)| d.source_ts.or(d.server_ts))
                                .map(opcua::datetime_string)
                                .unwrap_or_default(),
                        )
                        .text_color(rgb(C::MUTED)),
                    )
                    .child(div().w(px(40.)).flex_none().child(chip(
                        ("ua-unwatch", i),
                        "✕",
                        false,
                        act(&view, move |t: &mut Self, _, _| t.toggle_watch(n2.clone())),
                    )))
            }))
            .into_any_element()
    }

    fn browse_tab(&mut self, cx: &mut Context<Self>) -> gpui::AnyElement {
        if self.session.is_none() {
            return empty_state(
                if self.running() && !self.discovering {
                    "Opening session…"
                } else {
                    "No session"
                },
                "Press Connect to open an anonymous or user-name session and browse the address space.",
            )
            .into_any_element();
        }
        if self.rows_dirty || self.rows.is_empty() {
            self.rebuild_rows();
            self.rows_dirty = false;
        }
        let s = self.session.clone().unwrap_or_default();
        let detail = self.detail(cx);
        let watch = self.watch_table(cx);
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_4()
                    .px_4()
                    .py_2()
                    .border_b_1()
                    .border_color(rgb(C::BORDER))
                    .text_sm()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(format!("{} {}", s.product, s.version)),
                    )
                    .when(!s.state.is_empty(), |d| {
                        d.child(
                            div()
                                .text_color(rgb(if s.state == "Running" {
                                    C::GREEN
                                } else {
                                    C::AMBER
                                }))
                                .child(s.state.clone()),
                        )
                    })
                    .child(label(format!(
                        "login: {} · session timeout {:.0} s",
                        s.identity,
                        s.timeout_ms / 1000.0
                    )))
                    .when(!s.started.is_empty(), |d| {
                        d.child(label(format!("started {}", s.started)))
                    })
                    .when_some(self.server_time.clone(), |d, t| {
                        d.child(label(format!("server time {t}")))
                    })
                    .child(label(format!("session {}", s.session_id))),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .w(px(420.))
                            .flex_none()
                            .flex()
                            .flex_col()
                            .border_r_1()
                            .border_color(rgb(C::BORDER))
                            .child(div().px_3().py_2().child(self.goto.clone()))
                            .child(
                                uniform_list(
                                    "ua-tree",
                                    self.rows.len(),
                                    cx.processor(|this, range: Range<usize>, _, cx| {
                                        range.map(|i| this.render_row(i, cx)).collect::<Vec<_>>()
                                    }),
                                )
                                .track_scroll(self.tree_scroll.clone())
                                .flex_1(),
                            ),
                    )
                    .child(
                        div()
                            .id("ua-detail")
                            .flex_1()
                            .min_w_0()
                            .p_4()
                            .overflow_y_scroll()
                            .child(detail),
                    ),
            )
            .child(watch)
            .into_any_element()
    }

    fn log_tab(&self) -> gpui::AnyElement {
        div()
            .flex()
            .flex_col()
            .gap_1()
            .text_sm()
            .when(self.log.is_empty(), |d| d.child(label("Nothing yet.")))
            .children(self.log.iter().map(|(l, s)| {
                div()
                    .flex()
                    .gap_2()
                    .child(div().pt(px(6.)).child(crate::widgets::dot(level_color(*l))))
                    .child(div().flex_1().min_w_0().child(s.clone()))
            }))
            .into_any_element()
    }
}

impl Focusable for OpcUaView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for OpcUaView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.running();
        let copy = self
            .discovery
            .as_ref()
            .map(|d| {
                let eps: Vec<String> = d
                    .endpoints
                    .iter()
                    .map(|e| {
                        format!(
                            "{} {} [{}] {}",
                            opcua::mode_name(e.mode),
                            opcua::policy_short(&e.policy),
                            e.tokens
                                .iter()
                                .map(|t| opcua::token_type_name(t.token_type))
                                .collect::<Vec<_>>()
                                .join(", "),
                            e.url
                        )
                    })
                    .collect();
                format!(
                    "{}\n{}\n{}",
                    d.url,
                    eps.join("\n"),
                    findings_text(&d.findings)
                )
            })
            .unwrap_or_default();
        let body = match self.tab {
            Tab::Browse => self.browse_tab(cx),
            Tab::Endpoints => div()
                .id("ua-ep")
                .size_full()
                .p_5()
                .overflow_y_scroll()
                .child(self.endpoints_tab())
                .into_any_element(),
            Tab::Log => div()
                .id("ua-log")
                .size_full()
                .p_5()
                .overflow_y_scroll()
                .child(self.log_tab())
                .into_any_element(),
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Server"))
                    .child(self.url.clone())
                    .child(chip(
                        "ua-anon",
                        "Anonymous",
                        !self.use_user,
                        act(&view, |t: &mut Self, _, _| t.use_user = false),
                    ))
                    .child(chip(
                        "ua-userauth",
                        "User name",
                        self.use_user,
                        act(&view, |t: &mut Self, _, _| t.use_user = true),
                    ))
                    .when(self.use_user, |d| {
                        d.child(self.user.clone()).child(self.pass.clone())
                    })
                    .when(!running, |d| {
                        d.child(button2(
                            "ua-discover",
                            "Discover",
                            act(&view, |t: &mut Self, _, cx| t.start(Auth::DiscoverOnly, cx)),
                        ))
                        .child(button_primary(
                            "ua-connect",
                            "▶ Connect",
                            act(&view, |t: &mut Self, _, cx| t.start(Auth::Anonymous, cx)),
                        ))
                    })
                    .when(running, |d| {
                        d.child(button(
                            "ua-stop",
                            if self.session.is_some() {
                                "■ Disconnect"
                            } else {
                                "Cancel"
                            },
                            C::RED,
                            C::RED_HOVER,
                            act(&view, |t: &mut Self, _, _| t.stop()),
                        ))
                    })
                    .when(!copy.is_empty(), |d| {
                        d.child(crate::widgets::copy_button("ua-copy", copy))
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
            .when(self.use_user, |d| {
                d.child(
                    div()
                        .px_5()
                        .py_1()
                        .text_xs()
                        .text_color(rgb(C::AMBER))
                        .bg(alpha(C::AMBER, 0.06))
                        .child("User-name login runs over SecurityPolicy None: the password is sent unencrypted. Use only on a trusted network or a test account."),
                )
            })
            .child(
                div()
                    .flex()
                    .gap_2()
                    .px_5()
                    .py_2()
                    .border_b_1()
                    .border_color(rgb(C::BORDER))
                    .children(
                        [
                            (Tab::Browse, "Browse"),
                            (Tab::Endpoints, "Endpoints & security"),
                            (Tab::Log, "Log"),
                        ]
                        .into_iter()
                        .enumerate()
                        .map(|(i, (t, n))| {
                            chip(
                                ("ua-tab", i),
                                n,
                                self.tab == t,
                                act(&view, move |v: &mut Self, _, _| v.tab = t),
                            )
                        }),
                    ),
            )
            .child(div().flex().flex_col().flex_1().min_h_0().child(body))
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
