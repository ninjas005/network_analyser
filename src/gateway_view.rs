//! Gateway Discovery tool.

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use gpui::{
    App, Context, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px, rgb,
};

use crate::gateway::{Finding, GwEvent, Level};
use crate::widgets::{
    C, act, button, button_primary, copy_button, dot, empty_state, section_title, status_bar,
    toolbar,
};

pub struct GatewayView {
    focus: FocusHandle,
    findings: Vec<Finding>,
    rx: Option<Receiver<GwEvent>>,
    status: SharedString,
    started: Option<Instant>,
    _poll: Option<Task<()>>,
}

impl GatewayView {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut v = Self {
            focus: cx.focus_handle(),
            findings: Vec::new(),
            rx: None,
            status: "".into(),
            started: None,
            _poll: None,
        };
        v.run(cx);
        v
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        self.findings.clear();
        self.rx = Some(crate::gateway::start());
        self.started = Some(Instant::now());
        self.status = "Discovering…".into();
        self._poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                match this.update(cx, |this, cx| this.drain(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    fn drain(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(rx) = &self.rx else { return false };
        let mut done = false;
        while let Ok(ev) = rx.try_recv() {
            match ev {
                GwEvent::Finding(f) => self.findings.push(f),
                GwEvent::Status(s) => self.status = s.into(),
                GwEvent::Done => done = true,
            }
        }
        if done {
            self.rx = None;
            let warn = self
                .findings
                .iter()
                .filter(|f| matches!(f.level, Level::Warn | Level::Bad))
                .count();
            self.status = format!(
                "Done in {:.1}s — {} finding{}, {warn} to look at",
                self.started
                    .map(|s| s.elapsed().as_secs_f32())
                    .unwrap_or(0.0),
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" }
            )
            .into();
        }
        cx.notify();
        !done
    }

    fn as_text(&self) -> String {
        let mut out = String::new();
        let mut sec = "";
        for f in &self.findings {
            if f.section != sec {
                out.push_str(&format!("\n[{}]\n", f.section));
                sec = &f.section;
            }
            out.push_str(&format!("{:<24} {}\n", f.key, f.value));
        }
        out
    }
}

impl Focusable for GatewayView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for GatewayView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let running = self.rx.is_some();
        let mut sections: Vec<(String, Vec<&Finding>)> = Vec::new();
        for f in &self.findings {
            match sections.iter_mut().find(|(s, _)| *s == f.section) {
                Some((_, v)) => v.push(f),
                None => sections.push((f.section.clone(), vec![f])),
            }
        }
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(div().text_sm().text_color(rgb(C::MUTED)).child(
                        "Default routes, gateway reachability and services, NAT / double-NAT (UPnP, NAT-PMP) and DNS server health.",
                    ))
                    .child(div().flex_1())
                    .child(copy_button("gw-copy", self.as_text()))
                    .child(if running {
                        button("gw-run", "Running…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary("gw-run", "⟲ Run again", act(&view, |t: &mut Self, _, cx| t.run(cx)))
                    }),
            )
            .child(if sections.is_empty() {
                empty_state("Discovering gateways…", "Reading routes and probing the default router.").into_any_element()
            } else {
                div()
                    .id("gw-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_5()
                    .flex()
                    .flex_wrap()
.content_start()
                    .gap_4()
                    .items_start()
                    .children(sections.into_iter().map(|(title, items)| {
                        div()
                            .w(px(560.))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .p_4()
                            .rounded_md()
                            .bg(rgb(C::PANEL))
                            .border_1()
                            .border_color(rgb(C::BORDER))
                            .text_sm()
                            .child(section_title(&title))
                            .children(items.into_iter().map(|f| {
                                let color = match f.level {
                                    Level::Good => C::GREEN,
                                    Level::Warn => C::AMBER,
                                    Level::Bad => C::RED,
                                    Level::Info => 0x3a4252,
                                };
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(dot(color))
                                    .child(div().w(px(170.)).flex_none().text_color(rgb(C::MUTED)).child(f.key.clone()))
                                    .child(div().flex_1().min_w_0().child(f.value.clone()))
                            }))
                    }))
                    .into_any_element()
            })
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}
