//! TLS certificate scanner tool.

use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::tls::{CertInfo, Report};
use crate::widgets::{
    Accept, C, TextInput, act, alpha, button, button_primary, cell, copy_button, empty_state,
    input, kv_row, label, section_title, status_bar, table_header, toolbar,
};

/// Letter grade and the reasons behind it.
pub fn grade(r: &Report) -> (char, Vec<String>) {
    let mut why = Vec::new();
    let leaf = r.chain.first();
    let days = leaf.map(|c| c.days_left).unwrap_or(-1);
    let legacy = r
        .versions
        .iter()
        .any(|(v, s)| (*v == "TLS 1.0" || *v == "TLS 1.1") && *s == Some(true));
    let tls13 = r
        .versions
        .iter()
        .any(|(v, s)| *v == "TLS 1.3" && *s == Some(true));
    if let Err(e) = &r.trust {
        why.push(e.clone());
    }
    if days < 0 {
        why.push("certificate expired".into());
    }
    if !r.name_ok && r.trust.is_ok() {
        why.push("host name not in the certificate".into());
    }
    if !why.is_empty() {
        return ('F', why);
    }
    let mut g = 'A';
    let mut worse = |to: char, w: String, why: &mut Vec<String>| {
        if to > g {
            g = to;
        }
        why.push(w);
    };
    if legacy {
        worse('C', "legacy TLS 1.0 / 1.1 enabled".into(), &mut why);
    }
    if days < 14 {
        worse('C', format!("expires in {days} days"), &mut why);
    } else if days < 30 {
        worse('B', format!("expires in {days} days"), &mut why);
    }
    if let Some(c) = leaf {
        if c.key == "RSA" && c.key_bits < 2048 {
            worse('C', format!("weak RSA key ({} bits)", c.key_bits), &mut why);
        }
        if c.sig_alg.contains("SHA-1") || c.sig_alg.contains("MD5") {
            worse('C', format!("weak signature ({})", c.sig_alg), &mut why);
        }
    }
    if !tls13 {
        worse('B', "TLS 1.3 not supported".into(), &mut why);
    }
    (g, why)
}

fn grade_color(g: char) -> u32 {
    match g {
        'A' => C::GREEN,
        'B' => C::CYAN,
        'C' => C::AMBER,
        _ => C::RED,
    }
}

pub struct TlsView {
    focus: FocusHandle,
    targets: Entity<TextInput>,
    rx: Option<Receiver<(String, Result<Report, String>)>>,
    results: Vec<(String, Result<Report, String>)>,
    pending: usize,
    selected: Option<usize>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl TlsView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self {
            focus: cx.focus_handle(),
            targets: input(
                window,
                cx,
                "",
                "example.com, mail.example.com:587, 10.0.0.5:8443",
                Accept::Any,
                |t| t.width(440.).max_len(4000),
                |t: &mut Self, _, cx| t.run(cx),
            ),
            rx: None,
            results: Vec::new(),
            pending: 0,
            selected: None,
            status: "Ports 25/587/143/110/21 use STARTTLS automatically.".into(),
            _poll: None,
        }
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.pending > 0 {
            return;
        }
        let targets: Vec<String> = self
            .targets
            .read(cx)
            .value
            .split([',', ' ', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if targets.is_empty() {
            return;
        }
        let (tx, rx) = channel();
        self.pending = targets.len();
        for t in targets {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let r = crate::tls::scan(&t, Duration::from_secs(10));
                let _ = tx.send((t, r));
            });
        }
        self.results.clear();
        self.selected = None;
        self.rx = Some(rx);
        self.status = format!("Scanning {} target(s)…", self.pending).into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                let alive = this.update(cx, |t, cx| {
                    if let Some(rx) = &t.rx {
                        while let Ok(r) = rx.try_recv() {
                            t.results.push(r);
                            t.pending -= 1;
                        }
                    }
                    if t.selected.is_none() && !t.results.is_empty() {
                        t.selected = Some(0);
                    }
                    if t.pending == 0 {
                        t.rx = None;
                        let bad = t
                            .results
                            .iter()
                            .filter(|(_, r)| r.as_ref().map(|r| grade(r).0 >= 'C').unwrap_or(true))
                            .count();
                        t.status =
                            format!("{} scanned, {bad} need attention", t.results.len()).into();
                    }
                    cx.notify();
                    t.pending > 0
                });
                if !matches!(alive, Ok(true)) {
                    break;
                }
            }
        }));
    }

    fn cert_card(i: usize, c: &CertInfo) -> impl IntoElement {
        let role = if i == 0 {
            "Server certificate"
        } else if c.self_signed {
            "Root"
        } else {
            "Intermediate"
        };
        let days_color = if c.days_left < 0 {
            C::RED
        } else if c.days_left < 30 {
            C::AMBER
        } else {
            C::GREEN
        };
        div()
            .flex()
            .flex_col()
            .gap_1()
            .p_3()
            .rounded_md()
            .bg(rgb(C::BG))
            .border_1()
            .border_color(rgb(C::BORDER))
            .text_sm()
            .child(section_title(&format!("[{i}] {role}")))
            .child(kv_row("Subject", c.subject.clone(), 120.))
            .child(kv_row("Issuer", c.issuer.clone(), 120.))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        div()
                            .w(px(120.))
                            .flex_none()
                            .text_color(rgb(C::MUTED))
                            .child("Valid"),
                    )
                    .child(format!("{} → {}", c.not_before, c.not_after))
                    .child(div().text_color(rgb(days_color)).child(if c.days_left < 0 {
                        format!("expired {} days ago", -c.days_left)
                    } else {
                        format!("{} days left", c.days_left)
                    })),
            )
            .child(kv_row(
                "Key",
                format!("{} {} bits", c.key, c.key_bits),
                120.,
            ))
            .child(kv_row("Signature", c.sig_alg.clone(), 120.))
            .when(!c.sans.is_empty(), |d| {
                let more = if c.sans.len() > 12 {
                    format!(" … +{}", c.sans.len() - 12)
                } else {
                    String::new()
                };
                d.child(kv_row(
                    "Names (SAN)",
                    format!(
                        "{}{more}",
                        c.sans
                            .iter()
                            .take(12)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    120.,
                ))
            })
            .child(kv_row("Serial", c.serial.clone(), 120.))
            .child(kv_row("SHA-256", c.sha256.clone(), 120.))
            .when(c.is_ca, |d| d.child(label("CA certificate")))
    }
}

impl Focusable for TlsView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for TlsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let text = self
            .results
            .iter()
            .map(|(t, r)| match r {
                Ok(r) => {
                    let (g, why) = grade(r);
                    format!(
                        "{t}: grade {g} — {} {} — {}",
                        r.version,
                        r.chain
                            .first()
                            .map(|c| format!("{} days left", c.days_left))
                            .unwrap_or_default(),
                        why.join("; ")
                    )
                }
                Err(e) => format!("{t}: {e}"),
            })
            .collect::<Vec<_>>()
            .join("\n");
        let detail = self
            .selected
            .and_then(|i| self.results.get(i))
            .map(|(t, r)| match r {
                Err(e) => div()
                    .p_5()
                    .text_color(rgb(C::RED))
                    .child(format!("{t}: {e}"))
                    .into_any_element(),
                Ok(r) => {
                    let (g, why) = grade(r);
                    div()
                        .id("tls-detail")
                        .flex_1()
                        .min_w_0()
                        .p_5()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .overflow_y_scroll()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_4()
                                .child(
                                    div()
                                        .size(px(56.))
                                        .flex_none()
                                        .rounded_md()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_2xl()
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .bg(alpha(grade_color(g), 0.18))
                                        .text_color(rgb(grade_color(g)))
                                        .child(g.to_string()),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .child(
                                            div()
                                                .text_lg()
                                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                                .child(format!(
                                                    "{} {}",
                                                    r.host,
                                                    r.addr
                                                        .map(|a| format!("({a})"))
                                                        .unwrap_or_default()
                                                )),
                                        )
                                        .child(div().text_sm().text_color(rgb(C::MUTED)).child(
                                            format!(
                                                "{} · {} · ALPN {} · handshake {:.0} ms",
                                                r.version,
                                                r.cipher,
                                                r.alpn.clone().unwrap_or_else(|| "-".into()),
                                                r.handshake_ms
                                            ),
                                        )),
                                ),
                        )
                        .child(match &r.trust {
                            Ok(()) => div().text_sm().text_color(rgb(C::GREEN)).child(
                                "✓ Trusted by this system's CA store and valid for the host name",
                            ),
                            Err(e) => div()
                                .text_sm()
                                .text_color(rgb(C::RED))
                                .child(format!("✗ {e}")),
                        })
                        .children(why.iter().map(|w| {
                            div()
                                .text_sm()
                                .text_color(rgb(C::AMBER))
                                .child(format!("• {w}"))
                        }))
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .children(r.versions.iter().map(|(v, s)| {
                                    let legacy = v.contains("1.0") || v.contains("1.1");
                                    let (txt, col) = match s {
                                        Some(true) if legacy => ("enabled ⚠", C::AMBER),
                                        Some(true) => ("supported", C::GREEN),
                                        Some(false) if legacy => ("disabled", C::GREEN),
                                        Some(false) => ("not supported", C::MUTED),
                                        None => ("inconclusive", C::MUTED),
                                    };
                                    div()
                                        .flex()
                                        .flex_col()
                                        .px_3()
                                        .py_2()
                                        .rounded_md()
                                        .bg(rgb(C::PANEL))
                                        .border_1()
                                        .border_color(rgb(C::BORDER))
                                        .child(label(v.to_string()))
                                        .child(div().text_sm().text_color(rgb(col)).child(txt))
                                })),
                        )
                        .children(
                            r.chain
                                .iter()
                                .enumerate()
                                .map(|(i, c)| Self::cert_card(i, c)),
                        )
                        .into_any_element()
                }
            });
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Hosts"))
                    .child(self.targets.clone())
                    .child(if self.pending > 0 {
                        button("tls-go", "Scanning…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary(
                            "tls-go",
                            "▶ Scan",
                            act(&view, |t: &mut Self, _, cx| t.run(cx)),
                        )
                    })
                    .child(copy_button("tls-copy", text)),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .id("tls-list")
                            .w(px(380.))
                            .flex_none()
                            .h_full()
                            .overflow_y_scroll()
                            .border_r_1()
                            .border_color(rgb(C::BORDER))
                            .child(table_header(&[("", 34.), ("HOST", 0.), ("EXPIRES", 90.)]))
                            .children(self.results.iter().enumerate().map(|(i, (t, r))| {
                                let (g, days) = match r {
                                    Ok(r) => (
                                        grade(r).0,
                                        r.chain
                                            .first()
                                            .map(|c| format!("{} d", c.days_left))
                                            .unwrap_or_default(),
                                    ),
                                    Err(_) => ('?', "error".into()),
                                };
                                div()
                                    .id(("tls-row", i))
                                    .flex()
                                    .items_center()
                                    .px_3()
                                    .h(px(32.))
                                    .text_sm()
                                    .cursor_pointer()
                                    .bg(rgb(if self.selected == Some(i) {
                                        C::SELECT
                                    } else {
                                        C::BG
                                    }))
                                    .hover(|s| s.bg(rgb(C::PANEL2)))
                                    .on_click(act(&view, move |v: &mut Self, _, _| {
                                        v.selected = Some(i)
                                    }))
                                    .child(
                                        cell(34., g.to_string())
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_color(rgb(grade_color(g))),
                                    )
                                    .child(cell(0., t.clone()))
                                    .child(cell(90., days).text_color(rgb(C::MUTED)))
                            })),
                    )
                    .child(detail.unwrap_or_else(|| {
                        empty_state(
                            if self.pending > 0 {
                                "Scanning…"
                            } else {
                                "No scan yet"
                            },
                            "Enter one or more hosts (host or host:port) and press Scan.",
                        )
                        .into_any_element()
                    })),
            )
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
