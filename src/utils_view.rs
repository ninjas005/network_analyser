//! Network utilities: Public IP, IP Geolocation, Base64.

use std::net::IpAddr;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Task, Window, div, prelude::*, px,
    rgb,
};

use crate::settings;
use crate::widgets::{
    Accept, C, Changed, TextArea, TextInput, act, alpha, button, button_primary, button2, cell,
    chip, copy_button, input, label, mono, section_title, status_bar, toolbar,
};

fn provider_host(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .unwrap_or(url)
        .to_string()
}

fn privacy_note(urls: &[&str]) -> impl IntoElement {
    let hosts: Vec<String> = urls.iter().map(|u| provider_host(u)).collect();
    div()
        .px_5()
        .py_2()
        .text_xs()
        .text_color(rgb(C::MUTED))
        .bg(alpha(C::ACCENT, 0.06))
        .child(format!(
            "Online lookup: pressing the button sends a request to {} — your public IP is visible to that service. Nothing is sent automatically.",
            hosts.join(" and ")
        ))
}

/// Poll a one-shot background result.
fn spawn_poll<V: 'static>(cx: &mut Context<V>, f: fn(&mut V, &mut Context<V>) -> bool) -> Task<()> {
    cx.spawn(async move |this, cx| {
        loop {
            cx.background_executor()
                .timer(Duration::from_millis(100))
                .await;
            match this.update(cx, f) {
                Ok(true) => {}
                _ => break,
            }
        }
    })
}

// ---------------------------------------------------------------- public IP

type IpResult = (Result<IpAddr, String>, Result<IpAddr, String>);
type GeoResult = Result<(IpAddr, Vec<(String, String)>), String>;

pub struct PublicIpView {
    focus: FocusHandle,
    v4_url: Entity<TextInput>,
    v6_url: Entity<TextInput>,
    rx: Option<Receiver<IpResult>>,
    result: Option<IpResult>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl PublicIpView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let s = settings::get();
        let go = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.check(cx);
        Self {
            focus: cx.focus_handle(),
            v4_url: input(
                window,
                cx,
                &s.public_ip_v4_url,
                settings::DEFAULT_PUBLIC_IP_V4,
                Accept::Any,
                |t| t.width(420.).max_len(500),
                go,
            ),
            v6_url: input(
                window,
                cx,
                &s.public_ip_v6_url,
                settings::DEFAULT_PUBLIC_IP_V6,
                Accept::Any,
                |t| t.width(420.).max_len(500),
                go,
            ),
            rx: None,
            result: None,
            status: "Press Check to look up your public address.".into(),
            _poll: None,
        }
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let (v4, v6) = (
            self.v4_url.read(cx).value.trim().to_string(),
            self.v6_url.read(cx).value.trim().to_string(),
        );
        self.status = match settings::update(|s| {
            s.public_ip_v4_url = v4;
            s.public_ip_v6_url = v6;
        }) {
            Ok(()) => "Provider URLs saved".into(),
            Err(e) => format!("Could not save: {e}").into(),
        };
    }

    fn reset(&mut self, cx: &mut Context<Self>) {
        self.v4_url
            .update(cx, |t, cx| t.set(settings::DEFAULT_PUBLIC_IP_V4, cx));
        self.v6_url
            .update(cx, |t, cx| t.set(settings::DEFAULT_PUBLIC_IP_V6, cx));
        self.save(cx);
    }

    fn check(&mut self, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let (v4, v6) = (
            self.v4_url.read(cx).value.trim().to_string(),
            self.v6_url.read(cx).value.trim().to_string(),
        );
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let a = std::thread::spawn(move || crate::webapi::public_ip(&v4));
            let b = crate::webapi::public_ip(&v6);
            let a = a.join().unwrap_or_else(|_| Err("lookup failed".into()));
            let _ = tx.send((a, b));
        });
        self.rx = Some(rx);
        self.status = "Asking the providers…".into();
        self._poll = Some(spawn_poll(cx, |t: &mut Self, cx| {
            let Some(rx) = &t.rx else { return false };
            match rx.try_recv() {
                Ok(r) => {
                    t.result = Some(r);
                    t.rx = None;
                    t.status = "Done".into();
                    cx.notify();
                    false
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => true,
                Err(_) => {
                    t.rx = None;
                    false
                }
            }
        }));
    }

    fn render_result(&self, family: &str, r: &Result<IpAddr, String>) -> impl IntoElement {
        let local: Vec<IpAddr> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.ip())
            .collect();
        let (value, detail, color) = match r {
            Ok(ip) => {
                let class = crate::webapi::classify(*ip);
                let nat = if local.contains(ip) {
                    "this machine holds the address directly (no NAT)".to_string()
                } else if ip.is_ipv4() {
                    let mine = crate::netinfo::local_interfaces()
                        .first()
                        .map(|i| i.ip.to_string())
                        .unwrap_or_default();
                    format!("behind NAT — this machine is {mine}")
                } else {
                    "address not on a local interface (NAT66 or a proxy)".to_string()
                };
                (ip.to_string(), format!("{class} · {nat}"), C::GREEN)
            }
            Err(e) => (
                "not available".to_string(),
                if family == "IPv6"
                    && (e.contains("resolve") || e.contains("connect") || e.contains("Could not"))
                {
                    format!("no IPv6 internet connectivity ({e})")
                } else {
                    e.clone()
                },
                C::MUTED,
            ),
        };
        div()
            .flex()
            .flex_col()
            .gap_1()
            .p_5()
            .w(px(520.))
            .rounded_md()
            .bg(rgb(C::PANEL))
            .border_1()
            .border_color(rgb(C::BORDER))
            .child(section_title(family))
            .child(
                div()
                    .text_2xl()
                    .font_family(mono())
                    .text_color(rgb(color))
                    .child(value.clone()),
            )
            .child(div().text_sm().text_color(rgb(C::MUTED)).child(detail))
            .when(r.is_ok(), |d| {
                d.child(div().pt_1().child(copy_button(
                    SharedString::from(format!("copy-{family}")),
                    value,
                )))
            })
    }
}

impl Focusable for PublicIpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for PublicIpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let (u4, u6) = (
            self.v4_url.read(cx).value.clone(),
            self.v6_url.read(cx).value.clone(),
        );
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("IPv4 provider"))
                    .child(self.v4_url.clone())
                    .child(label("IPv6 provider"))
                    .child(self.v6_url.clone())
                    .child(button2("pip-save", "Save", act(&view, |t: &mut Self, _, cx| t.save(cx))))
                    .child(button2("pip-reset", "Defaults", act(&view, |t: &mut Self, _, cx| t.reset(cx))))
                    .child(if self.rx.is_some() {
                        button("pip-go", "Checking…", C::PANEL2, C::PANEL2, |_, _, _| {})
                    } else {
                        button_primary("pip-go", "▶ Check", act(&view, |t: &mut Self, _, cx| t.check(cx)))
                    }),
            )
            .child(privacy_note(&[&u4, &u6]))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .p_5()
                    .flex()
                    .flex_wrap()
.content_start()
                    .gap_4()
                    .items_start()
                    .when_some(self.result.as_ref(), |d, (a, b)| {
                        d.child(self.render_result("IPv4", a)).child(self.render_result("IPv6", b))
                    })
                    .when(self.result.is_none(), |d| {
                        d.child(div().text_sm().text_color(rgb(C::MUTED)).child(
                            "Providers must return the address as plain text or JSON with an \"ip\" field (ipify, icanhazip.com, ifconfig.co/json, ipinfo.io/json…).",
                        ))
                    }),
            )
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}

// ---------------------------------------------------------------- geolocation

const HIGHLIGHT: &[&str] = &[
    "ip",
    "city",
    "region",
    "country_name",
    "country",
    "postal",
    "latitude",
    "longitude",
    "lat",
    "lon",
    "loc",
    "timezone",
    "org",
    "asn",
    "isp",
    "as",
];

pub struct GeoIpView {
    focus: FocusHandle,
    target: Entity<TextInput>,
    template: Entity<TextInput>,
    rx: Option<Receiver<GeoResult>>,
    result: Option<GeoResult>,
    status: SharedString,
    _poll: Option<Task<()>>,
}

impl GeoIpView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let s = settings::get();
        let go = |t: &mut Self, _: &mut Window, cx: &mut Context<Self>| t.lookup(false, cx);
        Self {
            focus: cx.focus_handle(),
            target: input(
                window,
                cx,
                "",
                "IP address or hostname",
                Accept::Any,
                |t| t.width(260.),
                go,
            ),
            template: input(
                window,
                cx,
                &s.geo_url,
                settings::DEFAULT_GEO,
                Accept::Any,
                |t| t.width(360.).max_len(500),
                go,
            ),
            rx: None,
            result: None,
            status: "Enter an address, or press My public IP.".into(),
            _poll: None,
        }
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let t = self.template.read(cx).value.trim().to_string();
        self.status = match settings::update(|s| s.geo_url = t) {
            Ok(()) => "Provider URL saved".into(),
            Err(e) => format!("Could not save: {e}").into(),
        };
    }

    fn lookup(&mut self, mine: bool, cx: &mut Context<Self>) {
        if self.rx.is_some() {
            return;
        }
        let target = self.target.read(cx).value.trim().to_string();
        if target.is_empty() && !mine {
            self.status = "Enter an IP address or hostname".into();
            return;
        }
        let template = self.template.read(cx).value.trim().to_string();
        let v4_url = settings::get().public_ip_v4_url;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let ip = if mine {
                crate::webapi::public_ip(&v4_url)
            } else {
                crate::traceroute::resolve(&target, false)
            };
            let r =
                ip.and_then(|ip| crate::webapi::geolocate(&template, ip).map(|rows| (ip, rows)));
            let _ = tx.send(r);
        });
        self.rx = Some(rx);
        self.status = format!("Asking {}…", provider_host(&self.template.read(cx).value)).into();
        self._poll = Some(spawn_poll(cx, |t: &mut Self, cx| {
            let Some(rx) = &t.rx else { return false };
            match rx.try_recv() {
                Ok(r) => {
                    if let Ok((ip, _)) = &r {
                        let ip = ip.to_string();
                        t.target.update(cx, |x, cx| x.set(ip, cx));
                    }
                    t.status = match &r {
                        Ok((ip, rows)) => format!("{ip}: {} fields", rows.len()).into(),
                        Err(e) => format!("Lookup failed: {e}").into(),
                    };
                    t.result = Some(r);
                    t.rx = None;
                    cx.notify();
                    false
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => true,
                Err(_) => {
                    t.rx = None;
                    false
                }
            }
        }));
    }

    fn map_url(rows: &[(String, String)]) -> Option<String> {
        let get = |k: &str| rows.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
        let (lat, lon) = match (
            get("latitude").or(get("lat")),
            get("longitude").or(get("lon")),
        ) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                let loc = get("loc")?;
                let (a, b) = loc.split_once(',')?;
                (a.to_string(), b.to_string())
            }
        };
        let (lat, lon): (f64, f64) = (lat.trim().parse().ok()?, lon.trim().parse().ok()?);
        Some(format!(
            "https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=10/{lat}/{lon}"
        ))
    }
}

impl Focusable for GeoIpView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for GeoIpView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let tpl = self.template.read(cx).value.clone();
        let body = match &self.result {
            None => div().p_5().text_sm().text_color(rgb(C::MUTED)).child(
                "The provider URL must contain {ip}. Examples: https://ipapi.co/{ip}/json/ · https://ipinfo.io/{ip}/json?token=… · http://ip-api.com/json/{ip}",
            ),
            Some(Err(e)) => div().p_5().text_color(rgb(C::RED)).child(e.clone()),
            Some(Ok((ip, rows))) => {
                let mut rows = rows.clone();
                rows.sort_by_key(|(k, _)| HIGHLIGHT.iter().position(|h| h == k).unwrap_or(usize::MAX));
                let map = Self::map_url(&rows);
                div()
                    .flex()
                    .flex_col()
                    .p_5()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().text_xl().font_family(mono()).child(ip.to_string()))
                            .child(div().text_sm().text_color(rgb(C::MUTED)).child(crate::webapi::classify(*ip)))
                            .when_some(map, |d, url| {
                                d.child(button2("geo-map", "Open map", move |_, _, cx| cx.open_url(&url)))
                            }),
                    )
                    .children(rows.into_iter().enumerate().map(|(i, (k, v))| {
                        let hl = HIGHLIGHT.contains(&k.as_str());
                        div()
                            .flex()
                            .px_3()
                            .py_1()
                            .text_sm()
                            .bg(rgb(if i % 2 == 1 { C::ROW_ALT } else { C::BG }))
                            .child(cell(240., k).text_color(rgb(if hl { C::ACCENT } else { C::MUTED })))
                            .child(div().flex_1().min_w_0().child(v))
                    }))
            }
        };
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(label("Address"))
                    .child(self.target.clone())
                    .child(button_primary(
                        "geo-go",
                        "▶ Look up",
                        act(&view, |t: &mut Self, _, cx| t.lookup(false, cx)),
                    ))
                    .child(button2(
                        "geo-mine",
                        "My public IP",
                        act(&view, |t: &mut Self, _, cx| t.lookup(true, cx)),
                    ))
                    .child(label("Provider"))
                    .child(self.template.clone())
                    .child(button2(
                        "geo-save",
                        "Save",
                        act(&view, |t: &mut Self, _, cx| t.save(cx)),
                    ))
                    .child(button2(
                        "geo-def",
                        "Default",
                        act(&view, |t: &mut Self, _, cx| {
                            t.template
                                .update(cx, |x, cx| x.set(settings::DEFAULT_GEO, cx));
                            t.save(cx);
                        }),
                    )),
            )
            .child(privacy_note(&[&tpl]))
            .child(
                div()
                    .id("geo-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(body),
            )
            .child(status_bar().child(div().text_color(rgb(C::TEXT)).child(self.status.clone())))
    }
}

// ---------------------------------------------------------------- base64

pub struct Base64View {
    focus: FocusHandle,
    input: Entity<TextArea>,
    decode: bool,
    url_safe: bool,
    padding: bool,
    wrap76: bool,
    output: Result<String, String>,
    binary: Option<usize>,
}

fn engine(url_safe: bool, padding: bool) -> GeneralPurpose {
    let cfg = GeneralPurposeConfig::new()
        .with_encode_padding(padding)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let alphabet = if url_safe {
        &base64::alphabet::URL_SAFE
    } else {
        &base64::alphabet::STANDARD
    };
    GeneralPurpose::new(alphabet, cfg)
}

/// (output text, Some(n) if the decoded data was binary).
pub fn convert(
    text: &str,
    decode: bool,
    url_safe: bool,
    padding: bool,
    wrap76: bool,
) -> (Result<String, String>, Option<usize>) {
    let e = engine(url_safe, padding);
    if decode {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        // Accept either alphabet when decoding.
        let cleaned = if url_safe {
            cleaned.replace('+', "-").replace('/', "_")
        } else {
            cleaned.replace('-', "+").replace('_', "/")
        };
        match e.decode(cleaned.as_bytes()) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => (Ok(s), None),
                Err(err) => {
                    let b = err.into_bytes();
                    (Ok(crate::dissect::hexdump(&b).join("\n")), Some(b.len()))
                }
            },
            Err(err) => (Err(format!("not valid Base64: {err}")), None),
        }
    } else {
        let mut out = e.encode(text.as_bytes());
        if wrap76 {
            out = out
                .as_bytes()
                .chunks(76)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join("\n");
        }
        (Ok(out), None)
    }
}

impl Base64View {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input = cx.new(|cx| TextArea::new(cx, "Type or paste text here (Ctrl+V)…", 220.));
        cx.subscribe(&input, |this: &mut Self, _, _: &Changed, cx| {
            this.recompute(cx);
            cx.notify();
        })
        .detach();
        Self {
            focus: cx.focus_handle(),
            input,
            decode: false,
            url_safe: false,
            padding: true,
            wrap76: false,
            output: Ok(String::new()),
            binary: None,
        }
    }

    fn recompute(&mut self, cx: &App) {
        let (out, bin) = convert(
            &self.input.read(cx).value,
            self.decode,
            self.url_safe,
            self.padding,
            self.wrap76,
        );
        self.output = out;
        self.binary = bin;
    }
}

impl Focusable for Base64View {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for Base64View {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        let toggle = |f: fn(&mut Self)| {
            act(&view, move |t: &mut Self, _, cx| {
                f(t);
                t.recompute(cx);
            })
        };
        let in_len = self.input.read(cx).value.len();
        let out_text = self.output.clone().unwrap_or_default();
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(chip(
                        "b64-enc",
                        "Encode",
                        !self.decode,
                        toggle(|t| t.decode = false),
                    ))
                    .child(chip(
                        "b64-dec",
                        "Decode",
                        self.decode,
                        toggle(|t| t.decode = true),
                    ))
                    .child(div().w(px(12.)))
                    .child(chip(
                        "b64-std",
                        "Standard (+/)",
                        !self.url_safe,
                        toggle(|t| t.url_safe = false),
                    ))
                    .child(chip(
                        "b64-url",
                        "URL-safe (-_)",
                        self.url_safe,
                        toggle(|t| t.url_safe = true),
                    ))
                    .when(!self.decode, |d| {
                        d.child(chip(
                            "b64-pad",
                            "Padding =",
                            self.padding,
                            toggle(|t| t.padding = !t.padding),
                        ))
                        .child(chip(
                            "b64-wrap",
                            "Wrap at 76 (MIME)",
                            self.wrap76,
                            toggle(|t| t.wrap76 = !t.wrap76),
                        ))
                    })
                    .child(div().flex_1())
                    .child(button2(
                        "b64-swap",
                        "⇅ Use output as input",
                        act(&view, |t: &mut Self, _, cx| {
                            if t.binary.is_none()
                                && let Ok(out) = t.output.clone()
                            {
                                t.decode = !t.decode;
                                t.input.update(cx, |i, cx| i.set(out, cx));
                            }
                        }),
                    ))
                    .child(button2(
                        "b64-clear",
                        "Clear",
                        act(&view, |t: &mut Self, _, cx| {
                            t.input.update(cx, |i, cx| i.set("", cx))
                        }),
                    )),
            )
            .child(
                div()
                    .id("b64-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_5()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(section_title(if self.decode {
                        "Base64 input"
                    } else {
                        "Text input"
                    }))
                    .child(self.input.clone())
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(section_title(if self.decode {
                                "Decoded"
                            } else {
                                "Base64 output"
                            }))
                            .when_some(self.binary, |d, n| {
                                d.child(label(format!(
                                    "binary data, {n} bytes — shown as hex dump"
                                )))
                            })
                            .child(div().flex_1())
                            .child(copy_button("b64-copy", out_text.clone())),
                    )
                    .child(match &self.output {
                        Err(e) => div()
                            .p_3()
                            .text_sm()
                            .text_color(rgb(C::RED))
                            .child(e.clone()),
                        Ok(s) => div()
                            .p_3()
                            .min_h(px(120.))
                            .rounded_md()
                            .bg(rgb(C::PANEL))
                            .border_1()
                            .border_color(rgb(C::BORDER))
                            .text_sm()
                            .font_family(mono())
                            .children(
                                s.split('\n')
                                    .take(2000)
                                    .map(|l| div().min_h(px(18.)).child(l.to_string())),
                            ),
                    }),
            )
            .child(
                status_bar()
                    .child(format!("input {in_len} bytes"))
                    .child(format!("output {} bytes", out_text.len())),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_modes() {
        assert_eq!(
            convert("hello?>", false, false, true, false).0.unwrap(),
            "aGVsbG8/Pg=="
        );
        assert_eq!(
            convert("hello?>", false, true, false, false).0.unwrap(),
            "aGVsbG8_Pg"
        );
        assert_eq!(
            convert("aGVsbG8/Pg", true, false, true, false).0.unwrap(),
            "hello?>"
        );
        // URL-safe input decodes in standard mode too, whitespace ignored.
        assert_eq!(
            convert("aGVs bG8_\nPg==", true, false, true, false)
                .0
                .unwrap(),
            "hello?>"
        );
        let (out, bin) = convert("/w==", true, false, true, false);
        assert_eq!(bin, Some(1));
        assert!(out.unwrap().contains("ff"));
        assert!(convert("!!!", true, false, true, false).0.is_err());
        let long = "x".repeat(100);
        assert!(
            convert(&long, false, false, true, true)
                .0
                .unwrap()
                .contains('\n')
        );
    }
}
