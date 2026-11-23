//! Root view: title + tab bar, the active tool, and the quit dialog.

use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use gpui::{
    AnyView, App, Context, Entity, FocusHandle, Focusable, Hsla, MouseButton, Rgba, Task, Window,
    actions, div, prelude::*, px, rgb,
};

use crate::capture_view::CaptureView;
use crate::modbus_view::ModbusView;
use crate::portscan_view::PortScanView;
use crate::serial_view::SerialView;
use crate::ui::ScannerView;
use crate::updater::{self, InstallKind, Progress, Release};
use crate::widgets::{C, button, chip, progress, tip};

actions!(
    network_analyser,
    [
        Quit,
        RequestQuit,
        CancelDialog,
        ToggleFullscreen,
        Tab1,
        Tab2,
        Tab3,
        Tab4,
        Tab5
    ]
);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Lan,
    Ports,
    Capture,
    Serial,
    Modbus,
}

impl Tab {
    pub const ALL: [Tab; 5] = [Tab::Lan, Tab::Ports, Tab::Capture, Tab::Serial, Tab::Modbus];
    fn label(self) -> &'static str {
        match self {
            Tab::Lan => "LAN Scan",
            Tab::Ports => "Port Scan",
            Tab::Capture => "Packet Capture",
            Tab::Serial => "Serial",
            Tab::Modbus => "Modbus",
        }
    }
    pub fn parse(s: &str) -> Option<Tab> {
        match s {
            "lan" | "scan" => Some(Tab::Lan),
            "ports" | "portscan" => Some(Tab::Ports),
            "capture" => Some(Tab::Capture),
            "serial" => Some(Tab::Serial),
            "modbus" => Some(Tab::Modbus),
            _ => None,
        }
    }
}

/// "Check for updates" state shown in the header.
enum Update {
    Idle,
    Checking {
        rx: Receiver<Result<Option<Release>, String>>,
        manual: bool,
    },
    UpToDate,
    CheckFailed(String),
    Available(Release),
    Installing {
        rel: Release,
        rx: Receiver<Progress>,
        status: String,
        frac: Option<f32>,
    },
    InstallFailed {
        rel: Release,
        error: String,
    },
}

pub struct Shell {
    update: Update,
    update_dialog: bool,
    install_kind: InstallKind,
    _update_poll: Option<Task<()>>,
    focus: FocusHandle,
    kiosk: bool,
    tab: Tab,
    confirm_quit: bool,
    lan: Entity<ScannerView>,
    ports: Option<Entity<PortScanView>>,
    capture: Option<Entity<CaptureView>>,
    serial: Option<Entity<SerialView>>,
    modbus: Option<Entity<ModbusView>>,
}

impl Shell {
    pub fn new(
        kiosk: bool,
        lan: Entity<ScannerView>,
        auto_update_check: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        updater::cleanup_previous_update();
        if auto_update_check {
            cx.spawn(async move |this, cx| {
                cx.background_executor().timer(Duration::from_secs(3)).await;
                this.update(cx, |this, cx| this.check_updates(false, cx))
                    .ok();
            })
            .detach();
        }
        Self {
            update: Update::Idle,
            update_dialog: false,
            install_kind: updater::install_kind(),
            _update_poll: None,
            focus: cx.focus_handle(),
            kiosk,
            tab: Tab::Lan,
            confirm_quit: false,
            lan,
            ports: None,
            capture: None,
            serial: None,
            modbus: None,
        }
    }

    /// Switch tab, creating the tool on first use, and focus it.
    pub fn select(&mut self, tab: Tab, window: &mut Window, cx: &mut Context<Self>) {
        self.tab = tab;
        let focus = match tab {
            Tab::Lan => self.lan.focus_handle(cx),
            Tab::Ports => self
                .ports
                .get_or_insert_with(|| cx.new(|cx| PortScanView::new(window, cx)))
                .focus_handle(cx),
            Tab::Capture => self
                .capture
                .get_or_insert_with(|| cx.new(|cx| CaptureView::new(window, cx)))
                .focus_handle(cx),
            Tab::Serial => self
                .serial
                .get_or_insert_with(|| cx.new(|cx| SerialView::new(window, cx)))
                .focus_handle(cx),
            Tab::Modbus => self
                .modbus
                .get_or_insert_with(|| cx.new(|cx| ModbusView::new(window, cx)))
                .focus_handle(cx),
        };
        window.focus(&focus);
        cx.notify();
    }

    fn active_view(&self) -> AnyView {
        let lan = AnyView::from(self.lan.clone());
        match self.tab {
            Tab::Lan => Some(lan.clone()),
            Tab::Ports => self.ports.clone().map(AnyView::from),
            Tab::Capture => self.capture.clone().map(AnyView::from),
            Tab::Serial => self.serial.clone().map(AnyView::from),
            Tab::Modbus => self.modbus.clone().map(AnyView::from),
        }
        .unwrap_or(lan)
    }

    fn toggle_fullscreen(
        &mut self,
        _: &ToggleFullscreen,
        window: &mut Window,
        _: &mut Context<Self>,
    ) {
        // In kiosk mode the window must stay fullscreen.
        if !self.kiosk {
            window.toggle_fullscreen();
        }
    }

    fn request_quit(&mut self, _: &RequestQuit, window: &mut Window, cx: &mut Context<Self>) {
        self.confirm_quit = !self.confirm_quit;
        // Take focus so Enter / Esc reach the dialog, not an input.
        window.focus(&self.focus);
        cx.notify();
    }

    fn cancel_dialog(&mut self, _: &CancelDialog, window: &mut Window, cx: &mut Context<Self>) {
        self.confirm_quit = false;
        self.select(self.tab, window, cx);
    }

    fn quit(&mut self, _: &Quit, _: &mut Window, cx: &mut Context<Self>) {
        self.lan.read(cx).cancel();
        cx.quit();
    }

    fn render_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_1()
            .pl_5()
            .pr_3()
            .h(px(46.))
            .flex_none()
            .bg(rgb(C::BG))
            .border_b_1()
            .border_color(rgb(C::BORDER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .mr_5()
                    .child(div().size(px(12.)).rounded_full().bg(rgb(C::GREEN)))
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::BOLD)
                            .whitespace_nowrap()
                            .child("Network Analyser"),
                    ),
            )
            .children(Tab::ALL.iter().enumerate().map(|(i, &t)| {
                let active = self.tab == t;
                let view = view.clone();
                div()
                    .id(("tab", i))
                    .h_full()
                    .px_4()
                    .flex()
                    .items_center()
                    .border_b_2()
                    .border_color(if active {
                        rgb(C::ACCENT).into()
                    } else {
                        Hsla::transparent_black()
                    })
                    .text_sm()
                    .whitespace_nowrap()
                    .font_weight(if active {
                        gpui::FontWeight::SEMIBOLD
                    } else {
                        gpui::FontWeight::NORMAL
                    })
                    .text_color(rgb(if active { C::TEXT } else { C::MUTED }))
                    .hover(|s| s.text_color(rgb(C::TEXT)))
                    .cursor_pointer()
                    .child(t.label())
                    .tooltip(crate::widgets::tip(format!(
                        "{} ({}+{})",
                        t.label(),
                        if cfg!(target_os = "macos") {
                            "⌘"
                        } else {
                            "Alt"
                        },
                        i + 1
                    )))
                    .on_click(move |_, window, cx| {
                        view.update(cx, |this, cx| this.select(t, window, cx)).ok();
                    })
            }))
            .child(div().flex_1())
            .child(self.render_update_button(cx))
            .child(div().w(px(8.)))
            .child(button("quit", "✕ Quit", C::RED, C::RED_HOVER, {
                let view = view.clone();
                move |_, window, cx| {
                    view.update(cx, |this, cx| this.request_quit(&RequestQuit, window, cx))
                        .ok();
                }
            }))
    }

    // ------------------------------------------------------------ updates

    fn check_updates(&mut self, manual: bool, cx: &mut Context<Self>) {
        if matches!(
            self.update,
            Update::Checking { .. } | Update::Installing { .. }
        ) {
            return;
        }
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(updater::check());
        });
        self.update = Update::Checking { rx, manual };
        self.poll_updates(cx);
        cx.notify();
    }

    fn install_update(&mut self, cx: &mut Context<Self>) {
        let rel = match &self.update {
            Update::Available(r) | Update::InstallFailed { rel: r, .. } => r.clone(),
            _ => return,
        };
        self.update = Update::Installing {
            rx: updater::start_update(rel.clone()),
            rel,
            status: "Starting…".into(),
            frac: None,
        };
        self.poll_updates(cx);
        cx.notify();
    }

    fn poll_updates(&mut self, cx: &mut Context<Self>) {
        self._update_poll = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                match this.update(cx, |this, cx| this.drain_updates(cx)) {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }));
    }

    /// Returns true while there is something to wait for.
    fn drain_updates(&mut self, cx: &mut Context<Self>) -> bool {
        let mut next = None;
        let mut relaunch = None;
        match &mut self.update {
            Update::Checking { rx, manual } => match rx.try_recv() {
                Ok(Ok(Some(rel))) => {
                    // Automatic checks only show the header button; a manual
                    // check opens the dialog straight away.
                    self.update_dialog |= *manual;
                    next = Some(Update::Available(rel));
                }
                Ok(Ok(None)) => next = Some(Update::UpToDate),
                Ok(Err(e)) => {
                    next = Some(if *manual {
                        Update::CheckFailed(e)
                    } else {
                        Update::Idle
                    })
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return true,
                Err(_) => next = Some(Update::Idle),
            },
            Update::Installing {
                rel,
                rx,
                status,
                frac,
            } => loop {
                match rx.try_recv() {
                    Ok(Progress::Status(s)) => {
                        *status = s;
                        *frac = None;
                    }
                    Ok(Progress::Downloading { done, total }) => {
                        *status = format!(
                            "Downloading… {:.1} / {:.1} MB",
                            done as f64 / 1e6,
                            total as f64 / 1e6
                        );
                        *frac = (total > 0).then(|| done as f32 / total as f32);
                    }
                    Ok(Progress::Restart(r)) => {
                        relaunch = Some(r);
                        break;
                    }
                    Ok(Progress::Failed(error)) => {
                        next = Some(Update::InstallFailed {
                            rel: rel.clone(),
                            error,
                        });
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(_) => {
                        next = Some(Update::InstallFailed {
                            rel: rel.clone(),
                            error: "updater stopped unexpectedly".into(),
                        });
                        break;
                    }
                }
            },
            _ => return false,
        }
        cx.notify();
        if let Some(r) = relaunch {
            self.lan.read(cx).cancel();
            r.spawn();
            cx.quit();
            return false;
        }
        match next {
            Some(n) => {
                self.update = n;
                false
            }
            None => true,
        }
    }

    fn render_update_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let open = {
            let view = view.clone();
            move |_: &gpui::ClickEvent, _: &mut Window, cx: &mut App| {
                view.update(cx, |this, cx| {
                    this.update_dialog = true;
                    cx.notify();
                })
                .ok();
            }
        };
        let check = move |_: &gpui::ClickEvent, _: &mut Window, cx: &mut App| {
            view.update(cx, |this, cx| this.check_updates(true, cx))
                .ok();
        };
        match &self.update {
            Update::Idle => chip(
                "upd",
                format!("v{} · Check for updates", updater::CURRENT),
                false,
                check,
            )
            .into_any_element(),
            Update::Checking { .. } => {
                chip("upd", "Checking for updates…", false, |_, _, _| {}).into_any_element()
            }
            Update::UpToDate => chip(
                "upd",
                format!("v{} · Up to date ✓", updater::CURRENT),
                false,
                check,
            )
            .tooltip(tip("Click to check again"))
            .into_any_element(),
            Update::CheckFailed(e) => chip("upd", "Update check failed", false, check)
                .text_color(rgb(C::AMBER))
                .tooltip(tip(format!("{e}. Click to retry.")))
                .into_any_element(),
            Update::Available(r) => button(
                "upd",
                format!("⬆ Update to {}", r.version),
                C::GREEN,
                0x55dd90,
                open,
            )
            .text_color(rgb(C::BG))
            .into_any_element(),
            Update::Installing { status, .. } => {
                chip("upd", status.clone(), true, open).into_any_element()
            }
            Update::InstallFailed { .. } => chip("upd", "Update failed — details", false, open)
                .text_color(rgb(C::RED))
                .into_any_element(),
        }
    }

    fn render_update_dialog(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let rel = match &self.update {
            Update::Available(r)
            | Update::Installing { rel: r, .. }
            | Update::InstallFailed { rel: r, .. } => Some(r.clone()),
            _ => None,
        };
        let installing = matches!(self.update, Update::Installing { .. });
        let close = {
            let view = view.clone();
            move |_: &gpui::ClickEvent, _: &mut Window, cx: &mut App| {
                view.update(cx, |this, cx| {
                    this.update_dialog = false;
                    cx.notify();
                })
                .ok();
            }
        };
        let page = rel
            .as_ref()
            .map(|r| r.page.clone())
            .unwrap_or_else(updater::releases_page);
        let notes: Vec<String> = rel
            .as_ref()
            .map(|r| r.notes.lines().take(60).map(|l| l.to_string()).collect())
            .unwrap_or_default();
        let kind = self.install_kind;
        div()
            .id("update-overlay")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .bg(Hsla::from(Rgba {
                r: 0.,
                g: 0.,
                b: 0.,
                a: 0.6,
            }))
            .occlude()
            .child(
                div()
                    .id("update-dialog")
                    .w(px(620.))
                    .max_h(px(620.))
                    .p_6()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .rounded_lg()
                    .bg(rgb(C::PANEL))
                    .border_1()
                    .border_color(rgb(C::BORDER))
                    .shadow_lg()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child(match &rel {
                                Some(r) => format!("Network Analyser {} is available", r.version),
                                None => "No update available".to_string(),
                            }),
                    )
                    .child(div().text_sm().text_color(rgb(C::MUTED)).child(format!(
                        "You have {}. {}.",
                        updater::CURRENT,
                        kind.describe()
                    )))
                    .when(!notes.is_empty(), |d| {
                        d.child(
                            div()
                                .id("update-notes")
                                .flex_1()
                                .min_h(px(80.))
                                .max_h(px(320.))
                                .overflow_y_scroll()
                                .p_3()
                                .rounded_md()
                                .bg(rgb(C::BG))
                                .text_xs()
                                .children(notes.into_iter().map(|l| div().min_h(px(14.)).child(l))),
                        )
                    })
                    .when_some(
                        match &self.update {
                            Update::Installing { status, frac, .. } => {
                                Some((status.clone(), *frac))
                            }
                            _ => None,
                        },
                        |d, (status, frac)| {
                            d.child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_3()
                                    .text_sm()
                                    .when_some(frac, |d, f| d.child(progress(f, 220.)))
                                    .child(status),
                            )
                        },
                    )
                    .when_some(
                        match &self.update {
                            Update::InstallFailed { error, .. } => Some(error.clone()),
                            _ => None,
                        },
                        |d, e| d.child(div().text_sm().text_color(rgb(C::RED)).child(e)),
                    )
                    .child(
                        div()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .child(button(
                                "upd-page",
                                "Release page",
                                C::PANEL2,
                                C::BORDER,
                                move |_, _, cx| cx.open_url(&page),
                            ))
                            .when(!installing, |d| {
                                d.child(button("upd-later", "Later", C::PANEL2, C::BORDER, close))
                            })
                            .when(!installing && rel.is_some() && kind.can_install(), |d| {
                                d.child(button(
                                    "upd-now",
                                    if matches!(self.update, Update::InstallFailed { .. }) {
                                        "Retry"
                                    } else {
                                        "Update now"
                                    },
                                    C::ACCENT,
                                    C::ACCENT_HOVER,
                                    move |_, _, cx| {
                                        view.update(cx, |this, cx| this.install_update(cx)).ok();
                                    },
                                ))
                            }),
                    ),
            )
    }

    fn render_quit_dialog(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let view2 = view.clone();
        div()
            .id("quit-overlay")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .bg(Hsla::from(Rgba { r: 0., g: 0., b: 0., a: 0.6 }))
            .occlude()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| this.cancel_dialog(&CancelDialog, window, cx)),
            )
            .child(
                div()
                    .id("quit-dialog")
                    .w(px(400.))
                    .p_6()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .rounded_lg()
                    .bg(rgb(C::PANEL))
                    .border_1()
                    .border_color(rgb(C::BORDER))
                    .shadow_lg()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child("Quit Network Analyser?"),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(C::MUTED))
                            .child("Running scans, captures and connections will be stopped. Results not exported will be lost."),
                    )
                    .child(
                        div()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .child(button("quit-cancel", "Cancel (Esc)", C::PANEL2, C::BORDER, move |_, window, cx| {
                                view.update(cx, |this, cx| this.cancel_dialog(&CancelDialog, window, cx)).ok();
                            }))
                            .child(button("quit-confirm", "Quit (Enter)", C::RED, C::RED_HOVER, move |_, window, cx| {
                                view2.update(cx, |this, cx| this.quit(&Quit, window, cx)).ok();
                            })),
                    ),
            )
    }
}

impl Focusable for Shell {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for Shell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tab =
            |t: Tab| cx.listener(move |this: &mut Self, _: &Tab1, w, cx| this.select(t, w, cx));
        div()
            .key_context(if self.confirm_quit {
                "QuitDialog"
            } else {
                "Shell"
            })
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::toggle_fullscreen))
            .on_action(cx.listener(Self::request_quit))
            .on_action(cx.listener(Self::cancel_dialog))
            .on_action(cx.listener(Self::quit))
            .on_action(tab(Tab::Lan))
            .on_action(cx.listener(|this, _: &Tab2, w, cx| this.select(Tab::Ports, w, cx)))
            .on_action(cx.listener(|this, _: &Tab3, w, cx| this.select(Tab::Capture, w, cx)))
            .on_action(cx.listener(|this, _: &Tab4, w, cx| this.select(Tab::Serial, w, cx)))
            .on_action(cx.listener(|this, _: &Tab5, w, cx| this.select(Tab::Modbus, w, cx)))
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(C::BG))
            .text_color(rgb(C::TEXT))
            .child(self.render_header(cx))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .child(self.active_view()),
            )
            .when(self.update_dialog, |d| {
                d.child(self.render_update_dialog(cx))
            })
            .when(self.confirm_quit, |d| d.child(self.render_quit_dialog(cx)))
    }
}
