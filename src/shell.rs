//! Root view: header, segment sidebar, the active tool, update and quit dialogs.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use gpui::{
    AnyView, App, Context, Entity, FocusHandle, Focusable, Hsla, MouseButton, Rgba, ScrollHandle,
    Task, Window, actions, div, prelude::*, px, rgb,
};

use crate::tools::{Segment, Tool};
use crate::ui::ScannerView;
use crate::updater::{self, InstallKind, Progress, Release};
use crate::widgets::{Accept, C, Submit, TextInput, button, chip, progress, tip};

actions!(
    network_analyser,
    [
        Quit,
        RequestQuit,
        CancelDialog,
        ToggleFullscreen,
        PrevTool,
        NextTool,
        ToggleSidebar
    ]
);

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
    tool: Tool,
    sidebar: bool,
    sidebar_scroll: ScrollHandle,
    /// Segments whose tools are shown.
    expanded: HashSet<Segment>,
    /// Sidebar tool filter.
    filter: Entity<TextInput>,
    confirm_quit: bool,
    lan: Entity<ScannerView>,
    views: HashMap<Tool, (AnyView, FocusHandle)>,
}

impl Shell {
    pub fn new(
        kiosk: bool,
        lan: Entity<ScannerView>,
        auto_update_check: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let filter = cx.new(|cx| TextInput::new(cx, "", "Filter tools…", Accept::Any).max_len(40));
        // Re-render the list while typing; Enter opens the first match.
        cx.observe(&filter, |_, _, cx| cx.notify()).detach();
        cx.subscribe_in(&filter, window, |this, _, _: &Submit, window, cx| {
            if let Some(t) = this.visible_tools(cx).first().copied() {
                this.filter.update(cx, |f, cx| f.set("", cx));
                this.select(t, window, cx);
            }
        })
        .detach();
        let expanded = match crate::settings::get().sidebar_expanded {
            Some(list) => Segment::ALL
                .into_iter()
                .filter(|s| list.iter().any(|l| l == s.label()))
                .collect(),
            // First run: only the group of the opening tool (added by select).
            None => HashSet::new(),
        };
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
            tool: Tool::LanScan,
            sidebar: true,
            sidebar_scroll: ScrollHandle::new(),
            expanded,
            filter,
            confirm_quit: false,
            lan,
            views: HashMap::new(),
        }
    }

    /// Switch tool, creating its view on first use, and focus it.
    pub fn select(&mut self, tool: Tool, window: &mut Window, cx: &mut Context<Self>) {
        self.tool = tool;
        if self.expanded.insert(tool.segment()) {
            self.save_expanded();
        }
        // Keep the selected entry visible (startup with --tool, Alt+↑/↓).
        // On the very first frame the container's bounds are not known yet,
        // so repeat the request on the next frame.
        let row = self
            .sidebar_rows(cx)
            .iter()
            .position(|r| matches!(r, Row::Tool(t) if *t == tool))
            .unwrap_or(0);
        let handle = self.sidebar_scroll.clone();
        handle.scroll_to_item(row);
        window.on_next_frame(move |window, _| {
            handle.scroll_to_item(row);
            window.refresh();
        });
        if !self.views.contains_key(&tool) {
            let v = crate::tools::create(tool, &self.lan, window, cx);
            self.views.insert(tool, v);
        }
        if let Some((_, focus)) = self.views.get(&tool) {
            window.focus(focus);
        }
        cx.notify();
    }

    fn step_tool(&mut self, delta: isize, window: &mut Window, cx: &mut Context<Self>) {
        let all = Tool::ALL;
        let i = all.iter().position(|t| *t == self.tool).unwrap_or(0) as isize;
        let n = all.len() as isize;
        self.select(all[((i + delta) % n + n) as usize % n as usize], window, cx);
    }

    fn active_view(&self) -> AnyView {
        self.views
            .get(&self.tool)
            .map(|(v, _)| v.clone())
            .unwrap_or_else(|| self.lan.clone().into())
    }

    fn save_expanded(&self) {
        let list: Vec<String> = Segment::ALL
            .into_iter()
            .filter(|s| self.expanded.contains(s))
            .map(|s| s.label().to_string())
            .collect();
        let _ = crate::settings::update(|s| s.sidebar_expanded = Some(list));
    }

    fn set_all_expanded(&mut self, open: bool) {
        self.expanded = if open {
            Segment::ALL.into_iter().collect()
        } else {
            // Keep the current tool's group open so the selection stays visible.
            [self.tool.segment()].into_iter().collect()
        };
        self.save_expanded();
    }

    fn toggle_segment(&mut self, seg: Segment) {
        if !self.expanded.remove(&seg) {
            self.expanded.insert(seg);
        }
        self.save_expanded();
    }

    fn filter_text(&self, cx: &App) -> String {
        self.filter.read(cx).value.trim().to_lowercase()
    }

    /// Tools matching the filter (all tools when it is empty).
    fn visible_tools(&self, cx: &App) -> Vec<Tool> {
        let q = self.filter_text(cx);
        Tool::ALL
            .into_iter()
            .filter(|t| {
                q.is_empty()
                    || t.label().to_lowercase().contains(&q)
                    || t.slug().contains(&q)
                    || t.describe().to_lowercase().contains(&q)
                    || t.segment().label().to_lowercase().contains(&q)
            })
            .collect()
    }

    /// The sidebar list: a header per segment, then its tools when the
    /// segment is expanded (or always while filtering).
    fn sidebar_rows(&self, cx: &App) -> Vec<Row> {
        let filtering = !self.filter_text(cx).is_empty();
        sidebar_rows(&self.visible_tools(cx), &self.expanded, filtering)
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let filtering = !self.filter_text(cx).is_empty();
        let rows = self.sidebar_rows(cx);
        let all_open = Segment::ALL.iter().all(|s| self.expanded.contains(s));
        let mut items: Vec<gpui::AnyElement> = Vec::new();
        for (i, row) in rows.iter().enumerate() {
            match *row {
                Row::Header { seg, count, open } => {
                    let active_inside = self.tool.segment() == seg;
                    let view = view.clone();
                    items.push(
                        div()
                            .id(seg.label())
                            .mx_2()
                            .when(i > 0, |d| d.mt_1())
                            .px_2()
                            .py(px(6.))
                            .rounded_md()
                            .flex()
                            .items_center()
                            .gap_2()
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(C::PANEL2)))
                            .child(
                                div()
                                    .w(px(10.))
                                    .flex_none()
                                    .text_xs()
                                    .text_color(rgb(C::MUTED))
                                    .child(if open { "▾" } else { "▸" }),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .text_xs()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(rgb(if active_inside && !open {
                                        C::ACCENT
                                    } else if open {
                                        C::TEXT
                                    } else {
                                        0xb7c0cf
                                    }))
                                    .child(seg.label()),
                            )
                            .child(
                                div()
                                    .flex_none()
                                    .px(px(6.))
                                    .rounded_full()
                                    .bg(rgb(C::BG))
                                    .text_xs()
                                    .text_color(rgb(C::MUTED))
                                    .child(count.to_string()),
                            )
                            .when(!filtering, |d| {
                                d.on_click(move |_, _, cx| {
                                    view.update(cx, |this, cx| {
                                        this.toggle_segment(seg);
                                        cx.notify();
                                    })
                                    .ok();
                                })
                            })
                            .into_any_element(),
                    );
                }
                Row::Tool(t) => {
                    let active = self.tool == t;
                    let view = view.clone();
                    items.push(
                        div()
                            .id(t.slug())
                            .ml(px(19.))
                            .mr_2()
                            .pl_3()
                            .pr_2()
                            .py(px(5.))
                            .border_l_2()
                            .border_color(rgb(if active { C::ACCENT } else { C::BORDER }))
                            .rounded_r_md()
                            .text_sm()
                            .whitespace_nowrap()
                            .overflow_hidden()
                            .cursor_pointer()
                            .bg(if active {
                                rgb(C::SELECT).into()
                            } else {
                                Hsla::transparent_black()
                            })
                            .text_color(rgb(if active { C::TEXT } else { 0xb7c0cf }))
                            .when(active, |d| d.font_weight(gpui::FontWeight::SEMIBOLD))
                            .hover(|s| s.bg(rgb(C::PANEL2)).text_color(rgb(C::TEXT)))
                            .child(t.label())
                            .tooltip(tip(t.describe()))
                            .on_click(move |_, window, cx| {
                                view.update(cx, |this, cx| this.select(t, window, cx)).ok();
                            })
                            .into_any_element(),
                    );
                }
            }
        }
        if rows.is_empty() {
            items.push(
                div()
                    .px_4()
                    .py_2()
                    .text_xs()
                    .text_color(rgb(C::MUTED))
                    .child("No tool matches")
                    .into_any_element(),
            );
        }
        let v2 = view.clone();
        div()
            .w(px(224.))
            .flex_none()
            .h_full()
            .flex()
            .flex_col()
            .bg(rgb(C::PANEL))
            .border_r_1()
            .border_color(rgb(C::BORDER))
            .child(
                div()
                    .flex_none()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .px_3()
                    .pt_3()
                    .pb_2()
                    .border_b_1()
                    .border_color(rgb(C::BORDER))
                    .child(self.filter.clone())
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .text_xs()
                            .text_color(rgb(C::MUTED))
                            .child(format!("{} tools", Tool::ALL.len()))
                            .child(
                                div()
                                    .id("sidebar-all")
                                    .cursor_pointer()
                                    .px_2()
                                    .rounded_sm()
                                    .hover(|s| s.bg(rgb(C::PANEL2)).text_color(rgb(C::TEXT)))
                                    .child(if all_open {
                                        "Collapse all"
                                    } else {
                                        "Expand all"
                                    })
                                    .on_click(move |_, _, cx| {
                                        v2.update(cx, |this, cx| {
                                            this.set_all_expanded(!all_open);
                                            cx.notify();
                                        })
                                        .ok();
                                    }),
                            ),
                    ),
            )
            .child(
                div()
                    .id("sidebar")
                    .flex_1()
                    .min_h_0()
                    .py_2()
                    .flex()
                    .flex_col()
                    .overflow_y_scroll()
                    .track_scroll(&self.sidebar_scroll)
                    .children(items),
            )
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
        self.select(self.tool, window, cx);
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
            .child(
                div()
                    .id("toggle-sidebar")
                    .px_2()
                    .py_1()
                    .mr_2()
                    .rounded_md()
                    .cursor_pointer()
                    .text_color(rgb(C::MUTED))
                    .hover(|s| s.bg(rgb(C::PANEL2)).text_color(rgb(C::TEXT)))
                    .child("☰")
                    .tooltip(tip(if cfg!(target_os = "macos") {
                        "Show / hide tools (⌘B)"
                    } else {
                        "Show / hide tools (Ctrl+B)"
                    }))
                    .on_click({
                        let view = view.clone();
                        move |_, _, cx| {
                            view.update(cx, |this, cx| {
                                this.sidebar = !this.sidebar;
                                cx.notify();
                            })
                            .ok();
                        }
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_sm()
                    .whitespace_nowrap()
                    .child(
                        div()
                            .text_color(rgb(C::MUTED))
                            .child(self.tool.segment().label()),
                    )
                    .child(div().text_color(rgb(C::MUTED)).child("›"))
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(self.tool.label()),
                    ),
            )
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
            .on_action(cx.listener(|this, _: &PrevTool, w, cx| this.step_tool(-1, w, cx)))
            .on_action(cx.listener(|this, _: &NextTool, w, cx| this.step_tool(1, w, cx)))
            .on_action(cx.listener(|this, _: &ToggleSidebar, _, cx| {
                this.sidebar = !this.sidebar;
                cx.notify();
            }))
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
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .when(self.sidebar, |d| d.child(self.render_sidebar(cx)))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .child(self.active_view()),
                    ),
            )
            .when(self.update_dialog, |d| {
                d.child(self.render_update_dialog(cx))
            })
            .when(self.confirm_quit, |d| d.child(self.render_quit_dialog(cx)))
    }
}

/// One sidebar line.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Row {
    Header {
        seg: Segment,
        count: usize,
        open: bool,
    },
    Tool(Tool),
}

/// Headers for segments with visible tools; tools under open segments
/// (every segment is open while filtering).
fn sidebar_rows(visible: &[Tool], expanded: &HashSet<Segment>, filtering: bool) -> Vec<Row> {
    let mut rows = Vec::new();
    for seg in Segment::ALL {
        let tools: Vec<Tool> = visible
            .iter()
            .copied()
            .filter(|t| t.segment() == seg)
            .collect();
        if tools.is_empty() {
            continue;
        }
        let open = filtering || expanded.contains(&seg);
        rows.push(Row::Header {
            seg,
            count: tools.len(),
            open,
        });
        if open {
            rows.extend(tools.into_iter().map(Row::Tool));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapsed_segments_hide_their_tools() {
        let all = Tool::ALL.to_vec();
        let none = HashSet::new();
        let rows = sidebar_rows(&all, &none, false);
        // Every segment collapsed: headers only.
        assert!(
            rows.iter()
                .all(|r| matches!(r, Row::Header { open: false, .. }))
        );
        let n_segs = rows.len();
        let open: HashSet<Segment> = [Segment::Iot].into_iter().collect();
        let rows = sidebar_rows(&all, &open, false);
        assert_eq!(rows.len(), n_segs + 2);
        assert!(rows.contains(&Row::Tool(Tool::Mqtt)));
        assert!(!rows.contains(&Row::Tool(Tool::Snmp)));
        // Filtering shows matching tools under open headers only.
        let rows = sidebar_rows(&[Tool::Mqtt, Tool::Ntp], &none, true);
        assert_eq!(rows.len(), 4);
        assert!(rows.contains(&Row::Tool(Tool::Ntp)));
    }
}
