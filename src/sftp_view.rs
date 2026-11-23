//! SFTP / SSH tester: server analysis without credentials, then an SFTP
//! browser with download, upload and a write test after logging in.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use gpui::{
    App, ClipboardItem, Context, Entity, EventEmitter, FocusHandle, Focusable, KeyDownEvent,
    SharedString, Task, Window, div, prelude::*, px, rgb,
};

use crate::gateway::Finding;
use crate::sftp::{self, Auth, Cmd, ConnectCfg, Entry, Ev, Handshake, Worker};
use crate::widgets::{
    Accept, C, Submit, TextInput, act, alpha, button, button_primary, button2, cell, chip,
    copy_button, empty_state, findings_cards, findings_text, input, label, mono, status_bar,
    table_header, toolbar,
};

// ---------------------------------------------------------------- masked input

/// Single-line input that shows bullets instead of its text.
pub struct SecretInput {
    focus: FocusHandle,
    value: String,
    placeholder: SharedString,
    width: f32,
}

impl EventEmitter<Submit> for SecretInput {}

impl SecretInput {
    fn on_key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let ks = &ev.keystroke;
        let cmd = ks.modifiers.control || ks.modifiers.platform;
        match ks.key.as_str() {
            "backspace" if cmd => self.value.clear(),
            "backspace" => {
                self.value.pop();
            }
            "enter" => {
                cx.emit(Submit);
                cx.stop_propagation();
                return;
            }
            "u" if cmd => self.value.clear(),
            "v" if cmd => {
                if let Some(t) = cx.read_from_clipboard().and_then(|c| c.text()) {
                    self.value.push_str(t.lines().next().unwrap_or(""));
                }
            }
            _ => {
                if ks.modifiers.control || ks.modifiers.alt || ks.modifiers.platform {
                    return;
                }
                match ks.key_char.as_deref() {
                    Some(c) if !c.chars().any(char::is_control) && self.value.len() < 1024 => {
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
        let n = self.value.chars().count();
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
            .when(n == 0 && !focused, |d| {
                d.text_color(rgb(C::MUTED)).child(self.placeholder.clone())
            })
            .when(n > 0, |d| {
                d.text_color(rgb(C::TEXT)).child("•".repeat(n.min(40)))
            })
            .when(focused, |d| {
                d.child(div().w(px(1.5)).h(px(16.)).ml(px(1.)).bg(rgb(C::ACCENT)))
            })
    }
}

fn secret<V: 'static>(
    window: &Window,
    cx: &mut Context<V>,
    placeholder: &str,
    width: f32,
    on_submit: impl Fn(&mut V, &mut Window, &mut Context<V>) + 'static,
) -> Entity<SecretInput> {
    let placeholder: SharedString = placeholder.to_string().into();
    let e = cx.new(|cx| SecretInput {
        focus: cx.focus_handle(),
        value: String::new(),
        placeholder,
        width,
    });
    cx.subscribe_in(&e, window, move |this, _, _: &Submit, window, cx| {
        on_submit(this, window, cx);
        cx.notify();
    })
    .detach();
    e
}

// ---------------------------------------------------------------- view

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Analysis,
    Files,
}

#[derive(Clone, Copy, PartialEq)]
enum AuthKind {
    Password,
    Key,
}

pub struct SftpView {
    focus: FocusHandle,
    tab: Tab,
    target: Entity<TextInput>,
    user: Entity<TextInput>,
    password: Entity<SecretInput>,
    key_path: Entity<TextInput>,
    passphrase: Entity<SecretInput>,
    upload_path: Entity<TextInput>,
    auth: AuthKind,
    accept_changed: bool,
    write_test: bool,
    tx: Sender<Ev>,
    rx: Receiver<Ev>,
    worker: Option<Worker>,
    busy: bool,
    connected: bool,
    analysis: Vec<Finding>,
    handshake: Option<Handshake>,
    cwd: String,
    entries: Vec<Entry>,
    selected: Option<usize>,
    log: Vec<(u32, String)>,
    status: SharedString,
    error: Option<String>,
    _poll: Task<()>,
}

impl SftpView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (tx, rx) = channel();
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        let key_default = crate::platform::home_dir()
            .map(|h| {
                ["id_ed25519", "id_ecdsa", "id_rsa"]
                    .iter()
                    .map(|k| h.join(".ssh").join(k))
                    .find(|p| p.exists())
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let poll = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                if this.update(cx, |t, cx| t.drain(cx)).is_err() {
                    break;
                }
            }
        });
        Self {
            focus: cx.focus_handle(),
            tab: Tab::Analysis,
            target: input(
                window,
                cx,
                "",
                "host, host:port or user@host",
                Accept::Any,
                |t| t.width(240.),
                |t: &mut Self, _, cx| t.analyse(cx),
            ),
            user: input(
                window,
                cx,
                &user,
                "user",
                Accept::Any,
                |t| t.width(120.),
                |_, _, _| {},
            ),
            password: secret(window, cx, "password", 150., |t: &mut Self, _, cx| {
                t.connect(cx)
            }),
            key_path: input(
                window,
                cx,
                &key_default,
                "~/.ssh/id_ed25519",
                Accept::Any,
                |t| t.width(220.),
                |_, _, _| {},
            ),
            passphrase: secret(window, cx, "key passphrase", 130., |t: &mut Self, _, cx| {
                t.connect(cx)
            }),
            upload_path: input(
                window,
                cx,
                "",
                "local file to upload",
                Accept::Any,
                |t| t.width(260.),
                |t: &mut Self, _, cx| {
                    let v = t.upload_path.read(cx).value.clone();
                    t.upload_from(v)
                },
            ),
            auth: AuthKind::Password,
            accept_changed: false,
            write_test: false,
            tx,
            rx,
            worker: None,
            busy: false,
            connected: false,
            analysis: Vec::new(),
            handshake: None,
            cwd: String::new(),
            entries: Vec::new(),
            selected: None,
            log: Vec::new(),
            status: "Analyse needs no credentials. Connect logs in and opens SFTP.".into(),
            error: None,
            _poll: poll,
        }
    }

    fn drain(&mut self, cx: &mut Context<Self>) {
        let mut changed = false;
        while let Ok(ev) = self.rx.try_recv() {
            changed = true;
            match ev {
                Ev::Analysis(f) => self.analysis = f,
                Ev::Handshake(h) => self.handshake = Some(*h),
                Ev::Connected { home } => {
                    self.connected = true;
                    self.busy = false;
                    self.tab = Tab::Files;
                    self.cwd = home;
                    self.status = "Connected".into();
                }
                Ev::Listing { path, entries } => {
                    self.status = format!("{path}: {} entries", entries.len()).into();
                    self.cwd = path;
                    self.entries = entries;
                    self.selected = None;
                }
                Ev::Progress(p) => self.status = p.into(),
                Ev::Transfer(t) => {
                    self.status = t.clone().into();
                    self.log.push((C::GREEN, t));
                }
                Ev::Error(e) => {
                    self.log.push((C::RED, e.clone()));
                    self.error = Some(e);
                }
                Ev::Closed(msg) => {
                    self.busy = false;
                    self.connected = false;
                    self.worker = None;
                    if !msg.is_empty() {
                        self.status = msg.into();
                    }
                }
            }
        }
        if changed {
            cx.notify();
        }
    }

    fn cfg(&self, cx: &App, with_auth: bool) -> Result<ConnectCfg, String> {
        let (u, host, port) = sftp::parse_target(&self.target.read(cx).value)?;
        let user = u.unwrap_or_else(|| self.user.read(cx).value.trim().to_string());
        let auth = if !with_auth {
            Auth::None
        } else {
            match self.auth {
                AuthKind::Password => Auth::Password(self.password.read(cx).value.clone()),
                AuthKind::Key => Auth::Key {
                    path: self.key_path.read(cx).value.trim().to_string(),
                    passphrase: self.passphrase.read(cx).value.clone(),
                },
            }
        };
        Ok(ConnectCfg {
            host,
            port,
            user,
            auth,
            accept_changed_key: self.accept_changed,
            timeout: Duration::from_secs(10),
        })
    }

    fn analyse(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let cfg = match self.cfg(cx, false) {
            Ok(c) => c,
            Err(e) => return self.error = Some(e),
        };
        self.error = None;
        self.analysis.clear();
        self.handshake = None;
        self.busy = true;
        self.tab = Tab::Analysis;
        self.status = format!("Analysing {}:{}…", cfg.host, cfg.port).into();
        sftp::analyse(cfg, self.tx.clone());
    }

    fn connect(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        if self.connected {
            self.disconnect();
            return;
        }
        let cfg = match self.cfg(cx, true) {
            Ok(c) => c,
            Err(e) => return self.error = Some(e),
        };
        if cfg.user.is_empty() {
            self.error = Some("enter a user name".into());
            return;
        }
        self.error = None;
        self.busy = true;
        self.entries.clear();
        self.status = format!("Connecting to {}@{}:{}…", cfg.user, cfg.host, cfg.port).into();
        self.log.push((
            C::MUTED,
            format!("connect {}@{}:{}", cfg.user, cfg.host, cfg.port),
        ));
        self.worker = Some(sftp::open(cfg, self.write_test, self.tx.clone()));
    }

    fn disconnect(&mut self) {
        if let Some(w) = &self.worker {
            w.send(Cmd::Close);
        }
    }

    fn send(&mut self, c: Cmd) {
        self.error = None;
        if let Some(w) = &self.worker {
            w.send(c);
        }
    }

    fn open_entry(&mut self, i: usize) {
        let Some(e) = self.entries.get(i) else { return };
        if e.is_dir || e.is_link {
            let p = sftp::join_path(&self.cwd, &e.name);
            self.send(Cmd::List(p));
        } else {
            self.selected = Some(i);
        }
    }

    fn download(&mut self) {
        let Some(e) = self.selected.and_then(|i| self.entries.get(i)).cloned() else {
            self.error = Some("select a file first".into());
            return;
        };
        let local = sftp::download_dir().join(&e.name);
        let remote = sftp::join_path(&self.cwd, &e.name);
        self.status = format!("Downloading {remote}…").into();
        self.send(Cmd::Download { remote, local });
    }

    fn upload_from(&mut self, path: String) {
        let path = path.trim().to_string();
        if path.is_empty() {
            self.error = Some("enter a local file path".into());
            return;
        }
        let p = std::path::PathBuf::from(&path);
        if !p.is_file() {
            self.error = Some(format!("{path}: not a file"));
            return;
        }
        let dir = self.cwd.clone();
        self.status = format!("Uploading {path}…").into();
        self.send(Cmd::Upload {
            local: p,
            remote_dir: dir,
        });
    }

    fn all_findings(&self) -> Vec<Finding> {
        let mut f = self.analysis.clone();
        if let Some(h) = &self.handshake {
            f.extend(sftp::handshake_findings(h));
        }
        f
    }

    fn files_body(&self, view: &gpui::WeakEntity<Self>, cx: &App) -> gpui::AnyElement {
        if !self.connected {
            return empty_state(
                if self.busy {
                    "Connecting…"
                } else {
                    "Not connected"
                },
                "Enter credentials and press Connect to browse files over SFTP.",
            )
            .into_any_element();
        }
        let upload_val = self.upload_path.read(cx).value.clone();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .child(
                toolbar()
                    .child(button2(
                        "sftp-up",
                        "↑ Up",
                        act(view, |t: &mut Self, _, _| {
                            let p = sftp::parent_path(&t.cwd);
                            t.send(Cmd::List(p))
                        }),
                    ))
                    .child(button2(
                        "sftp-refresh",
                        "Refresh",
                        act(view, |t: &mut Self, _, _| {
                            let p = t.cwd.clone();
                            t.send(Cmd::List(p))
                        }),
                    ))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(160.))
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_sm()
                            .font_family(mono())
                            .child(self.cwd.clone()),
                    )
                    .child(button2(
                        "sftp-dl",
                        "⬇ Download",
                        act(view, |t: &mut Self, _, _| t.download()),
                    ))
                    .child(self.upload_path.clone())
                    .child(button2(
                        "sftp-ul",
                        "⬆ Upload here",
                        act(view, move |t: &mut Self, _, _| {
                            t.upload_from(upload_val.clone())
                        }),
                    ))
                    .child(button2(
                        "sftp-wt",
                        "Write test",
                        act(view, |t: &mut Self, _, _| {
                            let d = t.cwd.clone();
                            t.send(Cmd::WriteTest(d))
                        }),
                    )),
            )
            .child(table_header(&[
                ("NAME", 0.),
                ("SIZE", 110.),
                ("PERMISSIONS", 120.),
                ("OWNER", 110.),
                ("MODIFIED (UTC)", 150.),
            ]))
            .child(
                div()
                    .id("sftp-list")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(self.entries.iter().enumerate().map(|(i, e)| {
                        let sel = self.selected == Some(i);
                        div()
                            .id(("sftp-row", i))
                            .flex()
                            .items_center()
                            .px_3()
                            .h(px(28.))
                            .text_sm()
                            .cursor_pointer()
                            .bg(rgb(if sel {
                                C::SELECT
                            } else if i % 2 == 1 {
                                C::ROW_ALT
                            } else {
                                C::BG
                            }))
                            .hover(|s| s.bg(rgb(C::PANEL2)))
                            .on_click(act(view, move |t: &mut Self, _, _| {
                                if t.selected == Some(i) {
                                    t.open_entry(i)
                                } else {
                                    t.selected = Some(i);
                                    if t.entries.get(i).is_some_and(|e| e.is_dir) {
                                        t.open_entry(i)
                                    }
                                }
                            }))
                            .child(
                                cell(
                                    0.,
                                    format!(
                                        "{} {}",
                                        if e.is_dir {
                                            "▸"
                                        } else if e.is_link {
                                            "↪"
                                        } else {
                                            " "
                                        },
                                        e.name
                                    ),
                                )
                                .text_color(rgb(if e.is_dir {
                                    C::ACCENT
                                } else {
                                    C::TEXT
                                })),
                            )
                            .child(cell(
                                110.,
                                if e.is_dir {
                                    String::new()
                                } else {
                                    size(e.size)
                                },
                            ))
                            .child(cell(120., e.perms.clone()).font_family(mono()))
                            .child(cell(110., e.owner.clone()))
                            .child(cell(150., e.mtime.map(sftp::fmt_time).unwrap_or_default()))
                    })),
            )
            .child(
                div()
                    .id("sftp-log")
                    .h(px(110.))
                    .flex_none()
                    .overflow_y_scroll()
                    .px_5()
                    .py_2()
                    .border_t_1()
                    .border_color(rgb(C::BORDER))
                    .bg(rgb(C::PANEL))
                    .text_xs()
                    .font_family(mono())
                    .children(
                        self.log
                            .iter()
                            .rev()
                            .take(40)
                            .map(|(c, l)| div().text_color(rgb(*c)).child(l.clone())),
                    ),
            )
            .into_any_element()
    }
}

fn size(n: u64) -> String {
    let f = n as f64;
    if f >= 1e9 {
        format!("{:.2} GB", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.1} MB", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.1} kB", f / 1e3)
    } else {
        format!("{n} B")
    }
}

impl Focusable for SftpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Drop for SftpView {
    fn drop(&mut self) {
        self.disconnect();
    }
}

impl Render for SftpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let findings = self.all_findings();
        let copy = match self.tab {
            Tab::Analysis => findings_text(&findings),
            Tab::Files => self
                .entries
                .iter()
                .map(|e| format!("{}\t{}\t{}\t{}", e.perms, e.size, e.owner, e.name))
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let body = match self.tab {
            Tab::Analysis if findings.is_empty() => empty_state(
                if self.busy {
                    "Analysing…"
                } else {
                    "No analysis yet"
                },
                "Reads the banner and the server's algorithm lists, completes the key \
                 exchange for the host key, and asks which login methods are offered. \
                 No password is sent.",
            )
            .into_any_element(),
            Tab::Analysis => div()
                .id("sftp-findings")
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .p_5()
                .child(findings_cards(&findings))
                .into_any_element(),
            Tab::Files => self.files_body(&view, cx),
        };
        let fp = self
            .handshake
            .as_ref()
            .and_then(|h| h.key.as_ref())
            .map(|k| format!("{} {}", k.algorithm, k.fingerprint));
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(chip(
                        "sftp-t-a",
                        "Server analysis",
                        self.tab == Tab::Analysis,
                        act(&view, |t: &mut Self, _, _| t.tab = Tab::Analysis),
                    ))
                    .child(chip(
                        "sftp-t-f",
                        "SFTP files",
                        self.tab == Tab::Files,
                        act(&view, |t: &mut Self, _, _| t.tab = Tab::Files),
                    ))
                    .child(div().w(px(10.)))
                    .child(label("Server"))
                    .child(self.target.clone())
                    .child(if self.busy && !self.connected && self.worker.is_none() {
                        button("sftp-an", "Analysing…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary(
                            "sftp-an",
                            "▶ Analyse",
                            act(&view, |t: &mut Self, _, cx| t.analyse(cx)),
                        )
                    })
                    .child(copy_button("sftp-copy", copy)),
            )
            .child(
                toolbar()
                    .child(label("User"))
                    .child(self.user.clone())
                    .child(chip(
                        "sftp-pw",
                        "Password",
                        self.auth == AuthKind::Password,
                        act(&view, |t: &mut Self, _, _| t.auth = AuthKind::Password),
                    ))
                    .child(chip(
                        "sftp-key",
                        "Key file",
                        self.auth == AuthKind::Key,
                        act(&view, |t: &mut Self, _, _| t.auth = AuthKind::Key),
                    ))
                    .when(self.auth == AuthKind::Password, |d| {
                        d.child(self.password.clone())
                    })
                    .when(self.auth == AuthKind::Key, |d| {
                        d.child(self.key_path.clone())
                            .child(self.passphrase.clone())
                    })
                    .child(chip(
                        "sftp-wtc",
                        "Write test on connect",
                        self.write_test,
                        act(&view, |t: &mut Self, _, _| t.write_test = !t.write_test),
                    ))
                    .child(chip(
                        "sftp-acc",
                        "Accept changed host key",
                        self.accept_changed,
                        act(&view, |t: &mut Self, _, _| {
                            t.accept_changed = !t.accept_changed
                        }),
                    ))
                    .child(if self.connected {
                        button(
                            "sftp-conn",
                            "Disconnect",
                            C::RED,
                            C::RED_HOVER,
                            act(&view, |t: &mut Self, _, _| t.disconnect()),
                        )
                    } else if self.busy && self.worker.is_some() {
                        button(
                            "sftp-conn",
                            "Connecting…",
                            C::PANEL2,
                            C::PANEL2,
                            |_, _, _| {},
                        )
                    } else {
                        button_primary(
                            "sftp-conn",
                            "Connect",
                            act(&view, |t: &mut Self, _, cx| t.connect(cx)),
                        )
                    }),
            )
            .when(self.accept_changed, |d| {
                d.child(
                    div()
                        .px_5()
                        .py_2()
                        .text_sm()
                        .text_color(rgb(C::AMBER))
                        .bg(alpha(C::AMBER, 0.08))
                        .child(
                            "A changed host key will be accepted and remembered. Only do this \
                             after confirming the new fingerprint with the server's owner.",
                        ),
                )
            })
            .children(self.error.clone().map(|e| {
                div()
                    .px_5()
                    .py_2()
                    .text_sm()
                    .text_color(rgb(C::RED))
                    .bg(alpha(C::RED, 0.08))
                    .child(e)
            }))
            .child(div().flex().flex_col().flex_1().min_h_0().child(body))
            .child(
                status_bar()
                    .child(div().text_color(rgb(C::TEXT)).child(self.status.clone()))
                    .children(fp.map(|f| {
                        div()
                            .id("sftp-fp")
                            .cursor_pointer()
                            .font_family(mono())
                            .child(f.clone())
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(f.clone()))
                            })
                    })),
            )
    }
}
