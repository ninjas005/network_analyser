//! Shared look and small widgets used by every tab: palette, buttons, chips,
//! table cells, a single-line text input and a tooltip.

use gpui::{
    App, ClickEvent, ClipboardItem, Context, Entity, EventEmitter, FocusHandle, Hsla, KeyDownEvent,
    SharedString, Window, div, prelude::*, px, rgb,
};

// ---------------------------------------------------------------- palette

pub struct C;
#[allow(dead_code)]
impl C {
    pub const BG: u32 = 0x0f1218;
    pub const PANEL: u32 = 0x161b24;
    pub const PANEL2: u32 = 0x1c2230;
    pub const ROW_ALT: u32 = 0x131821;
    pub const BORDER: u32 = 0x262e3d;
    pub const TEXT: u32 = 0xe4e8ef;
    pub const MUTED: u32 = 0x8a94a6;
    pub const ACCENT: u32 = 0x4c8dff;
    pub const ACCENT_HOVER: u32 = 0x6aa1ff;
    pub const GREEN: u32 = 0x3ccf7e;
    pub const AMBER: u32 = 0xf2b84b;
    pub const RED: u32 = 0xef5a5a;
    pub const RED_HOVER: u32 = 0xff7070;
    pub const SELECT: u32 = 0x23324f;
    pub const PURPLE: u32 = 0xb48cf2;
    pub const CYAN: u32 = 0x4fc8d8;
}

/// Platform monospace font for hex dumps and logs.
pub fn mono() -> &'static str {
    if cfg!(target_os = "macos") {
        "Menlo"
    } else if cfg!(windows) {
        "Consolas"
    } else {
        "DejaVu Sans Mono"
    }
}

// ---------------------------------------------------------------- buttons

pub fn button(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
    bg: u32,
    hover: u32,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .px_4()
        .py(px(7.))
        .rounded_md()
        .bg(rgb(bg))
        .hover(move |s| s.bg(rgb(hover)))
        .cursor_pointer()
        .text_sm()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(rgb(C::TEXT))
        .whitespace_nowrap()
        .child(label.into())
        .on_click(on_click)
}

/// Neutral secondary button.
pub fn button2(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> gpui::Stateful<gpui::Div> {
    button(id, label, C::PANEL2, C::BORDER, on_click)
}

/// Primary (accent) button, or a disabled-looking one.
pub fn button_primary(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> gpui::Stateful<gpui::Div> {
    button(id, label, C::ACCENT, C::ACCENT_HOVER, on_click)
}

/// A small toggleable chip (segmented-control item / checkbox).
pub fn chip(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
    active: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .px_2()
        .py(px(4.))
        .rounded_md()
        .border_1()
        .border_color(rgb(if active { C::ACCENT } else { C::BORDER }))
        .bg(rgb(if active { C::SELECT } else { C::BG }))
        .hover(|s| s.bg(rgb(C::PANEL2)))
        .cursor_pointer()
        .text_xs()
        .whitespace_nowrap()
        .text_color(rgb(if active { C::TEXT } else { C::MUTED }))
        .child(label.into())
        .on_click(on_click)
}

/// Run `f` on the view behind a weak handle from a plain click callback.
pub fn act<V: 'static>(
    view: &gpui::WeakEntity<V>,
    f: impl Fn(&mut V, &mut Window, &mut Context<V>) + 'static,
) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
    let view = view.clone();
    move |_, window, cx| {
        view.update(cx, |this, cx| {
            f(this, window, cx);
            cx.notify();
        })
        .ok();
    }
}

// ---------------------------------------------------------------- layout bits

pub fn section_title(t: &str) -> impl IntoElement {
    div()
        .text_xs()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(rgb(C::ACCENT))
        .pb_1()
        .child(t.to_uppercase())
}

pub fn label(t: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_xs()
        .text_color(rgb(C::MUTED))
        .whitespace_nowrap()
        .child(t.into())
}

pub fn toolbar() -> gpui::Div {
    div()
        .flex()
        .flex_row()
        .flex_wrap()
        .items_center()
        .gap_3()
        .px_5()
        .py_3()
        .min_h(px(60.))
        .bg(rgb(C::PANEL))
        .border_b_1()
        .border_color(rgb(C::BORDER))
}

pub fn status_bar() -> gpui::Div {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_4()
        .px_5()
        .h(px(36.))
        .flex_none()
        .bg(rgb(C::PANEL))
        .border_t_1()
        .border_color(rgb(C::BORDER))
        .text_xs()
        .text_color(rgb(C::MUTED))
        .overflow_hidden()
        .whitespace_nowrap()
}

pub fn progress(frac: f32, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .h(px(6.))
        .flex_none()
        .rounded_full()
        .bg(rgb(C::PANEL2))
        .child(
            div()
                .h_full()
                .rounded_full()
                .bg(rgb(C::ACCENT))
                .w(px(w * frac.clamp(0., 1.))),
        )
}

/// Table header row from (title, width) pairs; width 0 = flexible.
pub fn table_header(cols: &[(&str, f32)]) -> gpui::Div {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(30.))
        .flex_none()
        .px_3()
        .bg(rgb(C::PANEL2))
        .border_b_1()
        .border_color(rgb(C::BORDER))
        .text_xs()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(rgb(C::MUTED))
        .children(cols.iter().map(|(n, w)| cell(*w, n.to_string())))
}

pub fn empty_state(title: &str, hint: &str) -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_2()
        .p_5()
        .text_color(rgb(C::MUTED))
        .child(div().text_xl().child(title.to_string()))
        .child(div().text_sm().child(hint.to_string()))
}

/// A fixed-width table cell whose text is cut with an ellipsis.
/// (gpui 0.2's own `text_ellipsis` caches the unconstrained measurement in
/// flex rows, so the cut is done here from an average glyph width.)
pub fn cell(w: f32, text: impl Into<SharedString>) -> gpui::Div {
    let text: SharedString = text.into();
    let d = div().pr_3().overflow_hidden().whitespace_nowrap();
    if w == 0.0 {
        return d.flex_1().min_w(px(120.)).child(text);
    }
    let max = ((w - 14.) / 7.4).max(3.) as usize;
    let text: SharedString = if text.chars().count() > max {
        format!(
            "{}…",
            text.chars().take(max - 1).collect::<String>().trim_end()
        )
        .into()
    } else {
        text
    };
    d.w(px(w)).flex_none().child(text)
}

/// Key/value rows for detail panes.
pub fn kv_row(k: impl Into<SharedString>, v: impl Into<SharedString>, kw: f32) -> impl IntoElement {
    div()
        .flex()
        .gap_2()
        .child(
            div()
                .w(px(kw))
                .flex_none()
                .text_color(rgb(C::MUTED))
                .child(k.into()),
        )
        .child(div().flex_1().min_w_0().child(v.into()))
}

pub fn alpha(c: u32, a: f32) -> Hsla {
    let mut h: Hsla = rgb(c).into();
    h.a = a;
    h
}

// ---------------------------------------------------------------- tooltip

pub struct Tip(pub SharedString);

impl Render for Tip {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .max_w(px(420.))
            .p_2()
            .rounded_md()
            .bg(rgb(C::PANEL2))
            .border_1()
            .border_color(rgb(C::BORDER))
            .text_xs()
            .text_color(rgb(C::TEXT))
            .child(self.0.clone())
    }
}

pub fn tip(text: impl Into<SharedString>) -> impl Fn(&mut Window, &mut App) -> gpui::AnyView {
    let text = text.into();
    move |_, cx| cx.new(|_| Tip(text.clone())).into()
}

// ---------------------------------------------------------------- text input

/// Emitted when Enter is pressed in a [`TextInput`].
pub struct Submit;

/// Which characters an input accepts.
#[derive(Clone, Copy, PartialEq)]
pub enum Accept {
    Any,
    Digits,
    /// Digits, '.', '/', '-', ' ' (IP ranges)
    Range,
    /// Ports: digits, ',', '-', ' ' and letters (for "top").
    Ports,
}

impl Accept {
    fn ok(self, c: char) -> bool {
        match self {
            Accept::Any => !c.is_control(),
            Accept::Digits => c.is_ascii_digit(),
            Accept::Range => c.is_ascii_digit() || "./- ".contains(c),
            Accept::Ports => c.is_ascii_alphanumeric() || ",- ".contains(c),
        }
    }
}

/// Single-line input with the cursor fixed at the end (like the range box).
/// Supports Backspace, Ctrl+U (clear), Ctrl+V (paste), Enter (emits Submit).
pub struct TextInput {
    pub focus: FocusHandle,
    pub value: String,
    placeholder: SharedString,
    accept: Accept,
    max_len: usize,
    width: Option<f32>,
    pub error: bool,
    monospace: bool,
}

impl EventEmitter<Submit> for TextInput {}

impl TextInput {
    pub fn new(
        cx: &mut Context<Self>,
        value: impl Into<String>,
        placeholder: impl Into<SharedString>,
        accept: Accept,
    ) -> Self {
        Self {
            focus: cx.focus_handle(),
            value: value.into(),
            placeholder: placeholder.into(),
            accept,
            max_len: 256,
            width: None,
            error: false,
            monospace: false,
        }
    }

    pub fn width(mut self, w: f32) -> Self {
        self.width = Some(w);
        self
    }

    pub fn max_len(mut self, n: usize) -> Self {
        self.max_len = n;
        self
    }

    pub fn mono(mut self) -> Self {
        self.monospace = true;
        self
    }

    pub fn set(&mut self, v: impl Into<String>, cx: &mut Context<Self>) {
        self.value = v.into();
        self.error = false;
        cx.notify();
    }

    fn insert(&mut self, s: &str) {
        for c in s.chars() {
            if self.value.chars().count() >= self.max_len {
                break;
            }
            if self.accept.ok(c) {
                self.value.push(c);
            }
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
            "enter" => {
                cx.emit(Submit);
                cx.stop_propagation();
                return;
            }
            "u" if cmd => self.value.clear(),
            "v" if cmd => {
                if let Some(text) = cx.read_from_clipboard().and_then(|c| c.text()) {
                    self.insert(text.lines().next().unwrap_or(""));
                }
            }
            "c" if cmd => {
                cx.write_to_clipboard(ClipboardItem::new_string(self.value.clone()));
            }
            _ => {
                if ks.modifiers.control || ks.modifiers.alt || ks.modifiers.platform {
                    return;
                }
                match ks.key_char.as_deref() {
                    Some(c) => self.insert(c),
                    None => return,
                }
            }
        }
        self.error = false;
        cx.stop_propagation();
        cx.notify();
    }
}

impl Render for TextInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus.is_focused(window);
        let empty = self.value.is_empty();
        div()
            .id("text-input")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::on_key))
            .on_click(cx.listener(|this, _, window, _| window.focus(&this.focus)))
            .map(|d| match self.width {
                Some(w) => d.w(px(w)).flex_none(),
                None => d.flex_1().min_w(px(120.)),
            })
            .h(px(32.))
            .px_2()
            .flex()
            .items_center()
            .overflow_hidden()
            .whitespace_nowrap()
            .rounded_md()
            .bg(rgb(C::BG))
            .border_1()
            .border_color(rgb(if self.error {
                C::RED
            } else if focused {
                C::ACCENT
            } else {
                C::BORDER
            }))
            .cursor_text()
            .text_sm()
            .when(self.monospace, |d| d.font_family(mono()))
            .when(empty && !focused, |d| {
                d.text_color(rgb(C::MUTED)).child(self.placeholder.clone())
            })
            .when(!empty, |d| {
                d.text_color(rgb(C::TEXT)).child(self.value.clone())
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

/// Create an input entity; `on_submit` runs on Enter.
pub fn input<V: 'static>(
    window: &Window,
    cx: &mut Context<V>,
    value: &str,
    placeholder: &str,
    accept: Accept,
    configure: impl FnOnce(TextInput) -> TextInput,
    on_submit: impl Fn(&mut V, &mut Window, &mut Context<V>) + 'static,
) -> Entity<TextInput> {
    let (value, placeholder) = (value.to_string(), placeholder.to_string());
    let e = cx.new(|cx| configure(TextInput::new(cx, value, placeholder, accept)));
    cx.subscribe_in(&e, window, move |this, _, _: &Submit, window, cx| {
        on_submit(this, window, cx);
        cx.notify();
    })
    .detach();
    e
}

// ---------------------------------------------------------------- text area

/// Emitted whenever a [`TextArea`]'s text changes.
pub struct Changed;

/// Multi-line plain-text editor with the cursor at the end: typing,
/// Enter (newline), Backspace, Ctrl+V paste, Ctrl+C copy all, Ctrl+U clear.
pub struct TextArea {
    pub focus: FocusHandle,
    pub value: String,
    placeholder: SharedString,
    height: f32,
    max_len: usize,
}

impl EventEmitter<Changed> for TextArea {}

impl TextArea {
    pub fn new(cx: &mut Context<Self>, placeholder: impl Into<SharedString>, height: f32) -> Self {
        Self {
            focus: cx.focus_handle(),
            value: String::new(),
            placeholder: placeholder.into(),
            height,
            max_len: 1 << 20,
        }
    }

    pub fn set(&mut self, v: impl Into<String>, cx: &mut Context<Self>) {
        self.value = v.into();
        cx.emit(Changed);
        cx.notify();
    }

    fn on_key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let ks = &ev.keystroke;
        let cmd = ks.modifiers.control || ks.modifiers.platform;
        match ks.key.as_str() {
            "backspace" if cmd => self.value.clear(),
            "backspace" => {
                self.value.pop();
            }
            "enter" => self.value.push('\n'),
            "tab" => self.value.push('\t'),
            "u" if cmd => self.value.clear(),
            "v" if cmd => {
                if let Some(t) = cx.read_from_clipboard().and_then(|c| c.text()) {
                    let room = self.max_len.saturating_sub(self.value.len());
                    self.value
                        .extend(t.replace("\r\n", "\n").chars().take(room));
                }
            }
            "c" if cmd => {
                cx.write_to_clipboard(ClipboardItem::new_string(self.value.clone()));
                cx.stop_propagation();
                return;
            }
            _ => {
                if ks.modifiers.control || ks.modifiers.alt || ks.modifiers.platform {
                    return;
                }
                match ks.key_char.as_deref() {
                    Some(c)
                        if self.value.len() < self.max_len
                            && !c.chars().any(|ch| ch.is_control()) =>
                    {
                        self.value.push_str(c)
                    }
                    _ => return,
                }
            }
        }
        cx.emit(Changed);
        cx.stop_propagation();
        cx.notify();
    }
}

impl Render for TextArea {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus.is_focused(window);
        let empty = self.value.is_empty();
        // Very long inputs: render only the tail to keep layout cheap.
        let shown: String = if self.value.len() > 64 * 1024 {
            format!(
                "… ({} bytes)\n{}",
                self.value.len(),
                &self.value[self.value.floor_char_boundary(self.value.len() - 32 * 1024)..]
            )
        } else {
            self.value.clone()
        };
        let lines: Vec<String> = shown.split('\n').map(String::from).collect();
        let last = lines.len().saturating_sub(1);
        div()
            .id("text-area")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::on_key))
            .on_click(cx.listener(|this, _, window, _| window.focus(&this.focus)))
            .h(px(self.height))
            .w_full()
            .p_2()
            .overflow_y_scroll()
            .rounded_md()
            .bg(rgb(C::BG))
            .border_1()
            .border_color(rgb(if focused { C::ACCENT } else { C::BORDER }))
            .cursor_text()
            .text_sm()
            .font_family(mono())
            .when(empty && !focused, |d| {
                d.text_color(rgb(C::MUTED)).child(self.placeholder.clone())
            })
            .when(!empty || focused, |d| {
                d.text_color(rgb(C::TEXT))
                    .children(lines.into_iter().enumerate().map(|(i, l)| {
                        div()
                            .flex()
                            .flex_wrap()
                            .min_h(px(18.))
                            .child(div().child(l))
                            .when(focused && i == last, |d| {
                                d.child(div().w(px(1.5)).h(px(16.)).ml(px(1.)).bg(rgb(C::ACCENT)))
                            })
                    }))
            })
    }
}

/// A read-only value with a Copy button (for results).
pub fn copy_button(id: impl Into<gpui::ElementId>, text: String) -> gpui::Stateful<gpui::Div> {
    chip(id, "Copy", false, move |_, _, cx| {
        cx.write_to_clipboard(ClipboardItem::new_string(text.clone()))
    })
}

/// Green / amber / red / muted dot.
pub fn dot(color: u32) -> impl IntoElement {
    div().size(px(8.)).flex_none().rounded_full().bg(rgb(color))
}

// ---------------------------------------------------------------- charts & reports

/// Vertical bar chart of a time series; `None` = lost sample (red stub).
/// `max` <= 0 scales to the data.
pub fn bar_chart(
    values: &[Option<f32>],
    width: f32,
    height: f32,
    max: f32,
    color: u32,
) -> gpui::Div {
    bar_chart_slots(values, values.len(), width, height, max, color)
}

/// Like [`bar_chart`] with a fixed number of slots: bars are right-aligned so
/// a growing series fills the chart like a strip chart.
pub fn bar_chart_slots(
    values: &[Option<f32>],
    slots: usize,
    width: f32,
    height: f32,
    max: f32,
    color: u32,
) -> gpui::Div {
    let n = slots.max(values.len()).max(1);
    let top = if max > 0.0 {
        max
    } else {
        values.iter().flatten().copied().fold(0.0001f32, f32::max)
    };
    let bar_w = (width / n as f32).max(1.0);
    div()
        .w(px(width))
        .h(px(height))
        .flex_none()
        .flex()
        .flex_row()
        .items_end()
        .justify_end()
        .overflow_hidden()
        .rounded_sm()
        .bg(rgb(C::BG))
        .children(values.iter().map(|v| {
            let (h, c) = match v {
                Some(x) => ((x / top).clamp(0.02, 1.0) * height, color),
                None => (height * 0.15, C::RED),
            };
            div()
                .w(px(bar_w))
                .h(px(h))
                .flex_none()
                .bg(rgb(c))
                .border_r_1()
                .border_color(rgb(C::BG))
        }))
}

/// A small statistic tile.
pub fn tile(
    label_text: impl Into<SharedString>,
    value: impl Into<SharedString>,
    color: u32,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .px_4()
        .py_2()
        .min_w(px(110.))
        .rounded_md()
        .bg(rgb(C::PANEL))
        .border_1()
        .border_color(rgb(C::BORDER))
        .child(label(label_text))
        .child(
            div()
                .text_xl()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .text_color(rgb(color))
                .child(value.into()),
        )
}

pub fn level_color(l: crate::gateway::Level) -> u32 {
    match l {
        crate::gateway::Level::Good => C::GREEN,
        crate::gateway::Level::Warn => C::AMBER,
        crate::gateway::Level::Bad => C::RED,
        crate::gateway::Level::Info => 0x3a4252,
    }
}

/// Findings grouped into section cards (Gateway Discovery, DNS security…).
pub fn findings_cards(findings: &[crate::gateway::Finding]) -> gpui::Div {
    let mut sections: Vec<(String, Vec<&crate::gateway::Finding>)> = Vec::new();
    for f in findings {
        match sections.iter_mut().find(|(s, _)| *s == f.section) {
            Some((_, v)) => v.push(f),
            None => sections.push((f.section.clone(), vec![f])),
        }
    }
    div()
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
                    div()
                        .flex()
                        .items_start()
                        .gap_2()
                        .child(div().pt(px(6.)).child(dot(level_color(f.level))))
                        .child(
                            div()
                                .w(px(170.))
                                .flex_none()
                                .text_color(rgb(C::MUTED))
                                .child(f.key.clone()),
                        )
                        .child(div().flex_1().min_w_0().child(f.value.clone()))
                }))
        }))
}

/// Findings as plain text (Copy buttons).
pub fn findings_text(findings: &[crate::gateway::Finding]) -> String {
    let mut out = String::new();
    let mut sec = "";
    for f in findings {
        if f.section != sec {
            out.push_str(&format!("\n[{}]\n", f.section));
            sec = &f.section;
        }
        out.push_str(&format!("{:<24} {}\n", f.key, f.value));
    }
    out
}

pub fn mbit(bits_per_sec: f64) -> String {
    if bits_per_sec >= 1e9 {
        format!("{:.2} Gbit/s", bits_per_sec / 1e9)
    } else if bits_per_sec >= 1e6 {
        format!("{:.1} Mbit/s", bits_per_sec / 1e6)
    } else if bits_per_sec >= 1e3 {
        format!("{:.0} kbit/s", bits_per_sec / 1e3)
    } else {
        format!("{bits_per_sec:.0} bit/s")
    }
}
