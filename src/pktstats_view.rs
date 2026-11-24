//! Packet Statistics: totals, traffic over time, protocol distribution and
//! hierarchy, sizes, talkers, ports and conversations.

use gpui::{App, Context, Entity, FocusHandle, Focusable, Window, div, prelude::*, px, rgb};

use crate::capture_view::{
    SourceBar, error_line, human_bits, human_bytes, proto_color, session_status,
};
use crate::pktstats::{SIZES, endpoint};
use crate::session::Session;
use crate::widgets::{
    C, act, bar_chart_slots, cell, chip, copy_button, empty_state, label, section_title, tile,
    toolbar,
};

pub struct PacketStatsView {
    focus: FocusHandle,
    session: Entity<Session>,
    bar: Entity<SourceBar>,
    /// Chart bytes instead of packets.
    bytes: bool,
}

impl PacketStatsView {
    pub fn new(_: &mut Window, cx: &mut Context<Self>) -> Self {
        let session = Session::shared(cx);
        cx.observe(&session, |_, _, cx| cx.notify()).detach();
        Self {
            focus: cx.focus_handle(),
            session,
            bar: cx.new(SourceBar::new),
            bytes: true,
        }
    }
}

fn panel(title: String) -> gpui::Div {
    div()
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
}

fn row(cols: Vec<(f32, String, u32)>) -> gpui::Div {
    div().flex().flex_row().items_center().h(px(24.)).children(
        cols.into_iter()
            .map(|(w, t, c)| cell(w, t).text_color(rgb(c))),
    )
}

/// Horizontal share bar with its percentage.
fn share(frac: f64, color: u32) -> gpui::Div {
    div()
        .flex_1()
        .flex()
        .items_center()
        .gap_2()
        .child(
            div()
                .h(px(8.))
                .w(px((110. * frac as f32).max(1.)))
                .rounded_sm()
                .bg(rgb(color)),
        )
        .child(label(format!("{:.1}%", frac * 100.)))
}

impl PacketStatsView {
    fn render_body(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let view = cx.entity().downgrade();
        let s = &self.session.read(cx).a.stats;
        if s.packets == 0 {
            return empty_state(
                "No packets",
                "Start a capture or open a capture file to see statistics.",
            )
            .into_any_element();
        }
        let dur = s.duration();
        let total = s.packets as f64;
        let rate = |n: f64| if dur > 0.0 { n / dur } else { 0.0 };
        let (peak_p, peak_b) = s.peak();
        let protos = s.distribution();
        let hier = s.hierarchy();
        let mut talkers: Vec<_> = s.talkers.iter().collect();
        talkers.sort_by_key(|(ip, t)| (std::cmp::Reverse(t.tx_bytes + t.rx_bytes), **ip));
        let mut convs: Vec<_> = s.convs.iter().collect();
        convs.sort_by_key(|a| (std::cmp::Reverse(a.1.bytes), *a.0));
        let mut ports: Vec<_> = s.ports.iter().collect();
        ports.sort_by_key(|a| (std::cmp::Reverse(a.1.1), *a.0));
        let values: Vec<Option<f32>> = s
            .series
            .buckets
            .iter()
            .map(|b| {
                Some(if self.bytes {
                    b.bytes as f32
                } else {
                    b.packets as f32
                })
            })
            .collect();
        let bytes = self.bytes;

        div()
            .id("pkt-stats")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(tile("Packets", s.packets.to_string(), C::TEXT))
                    .child(tile("Data", human_bytes(s.bytes), C::TEXT))
                    .child(tile("Duration", format!("{dur:.2} s"), C::TEXT))
                    .child(tile(
                        "Average rate",
                        format!("{:.0} pkt/s", rate(total)),
                        C::TEXT,
                    ))
                    .child(tile(
                        "Average throughput",
                        format!("{}/s", human_bits(rate(s.bytes as f64 * 8.0))),
                        C::TEXT,
                    ))
                    .child(tile(
                        "Peak",
                        format!("{peak_p:.0} pkt/s · {}/s", human_bits(peak_b)),
                        C::ACCENT,
                    ))
                    .child(tile(
                        "Packet size",
                        format!("{} – {} B", s.min_size, s.max_size),
                        C::TEXT,
                    ))
                    .child(tile("Hosts", s.talkers.len().to_string(), C::TEXT))
                    .child(tile("Conversations", s.convs.len().to_string(), C::TEXT)),
            )
            .child(
                panel("Traffic over time".into())
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .pb_1()
                            .child(chip(
                                "ch-bytes",
                                "Throughput",
                                bytes,
                                act(&view, |t: &mut Self, _, _| t.bytes = true),
                            ))
                            .child(chip(
                                "ch-pkts",
                                "Packets",
                                !bytes,
                                act(&view, |t: &mut Self, _, _| t.bytes = false),
                            ))
                            .child(label(format!(
                                "One bar = {:.1} s · highest {}",
                                s.series.width,
                                if bytes {
                                    format!("{}/s", human_bits(peak_b))
                                } else {
                                    format!("{peak_p:.0} pkt/s")
                                }
                            ))),
                    )
                    .child(bar_chart_slots(
                        &values,
                        values.len().max(60),
                        960.,
                        110.,
                        0.,
                        C::ACCENT,
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_wrap()
                    .gap_4()
                    .items_start()
                    .child(
                        panel(format!("Protocol distribution ({})", protos.len()))
                            .w(px(510.))
                            .child(row(vec![
                                (130., "PROTOCOL".into(), C::MUTED),
                                (80., "PACKETS".into(), C::MUTED),
                                (90., "BYTES".into(), C::MUTED),
                                (0., "SHARE".into(), C::MUTED),
                            ]))
                            .children(protos.iter().take(40).map(|(name, n, b)| {
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .h(px(24.))
                                    .child(
                                        cell(130., name.to_string())
                                            .text_color(rgb(proto_color(name))),
                                    )
                                    .child(cell(80., n.to_string()))
                                    .child(cell(90., human_bytes(*b)))
                                    .child(share(*n as f64 / total, proto_color(name)))
                            })),
                    )
                    .child(
                        panel("Protocol hierarchy".into())
                            .w(px(580.))
                            .child(row(vec![
                                (200., "PROTOCOL".into(), C::MUTED),
                                (80., "PACKETS".into(), C::MUTED),
                                (90., "BYTES".into(), C::MUTED),
                                (0., "SHARE".into(), C::MUTED),
                            ]))
                            .children(hier.iter().take(80).map(|r| {
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .h(px(22.))
                                    .child(
                                        div()
                                            .w(px(200.))
                                            .flex_none()
                                            .pl(px(14. * r.depth as f32))
                                            .overflow_hidden()
                                            .whitespace_nowrap()
                                            .text_color(rgb(proto_color(r.name)))
                                            .child(r.name),
                                    )
                                    .child(cell(80., r.packets.to_string()))
                                    .child(cell(90., human_bytes(r.bytes)))
                                    .child(share(r.packets as f64 / total, proto_color(r.name)))
                            })),
                    )
                    .child(
                        panel("Packet sizes".into())
                            .w(px(400.))
                            .children(SIZES.iter().zip(s.sizes).map(|((name, _), n)| {
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .h(px(24.))
                                    .child(cell(100., name.to_string()).text_color(rgb(C::MUTED)))
                                    .child(cell(80., n.to_string()))
                                    .child(share(n as f64 / total, C::CYAN))
                            }))
                            .child(div().h(px(6.)))
                            .child(section_title("Delivery and TCP flags"))
                            .children(
                                [
                                    ("Unicast", s.unicast),
                                    ("Multicast", s.multicast),
                                    ("Broadcast", s.broadcast),
                                    ("TCP SYN", s.flags[0]),
                                    ("TCP SYN/ACK", s.flags[1]),
                                    ("TCP FIN", s.flags[2]),
                                    ("TCP RST", s.flags[3]),
                                ]
                                .map(|(k, n)| {
                                    row(vec![
                                        (100., k.into(), C::MUTED),
                                        (80., n.to_string(), C::TEXT),
                                    ])
                                }),
                            ),
                    )
                    .child(
                        panel(format!("Top talkers ({})", talkers.len()))
                            .w(px(640.))
                            .child(row(vec![
                                (250., "ADDRESS".into(), C::MUTED),
                                (140., "SENT".into(), C::MUTED),
                                (140., "RECEIVED".into(), C::MUTED),
                                (90., "TOTAL".into(), C::MUTED),
                            ]))
                            .children(talkers.iter().take(25).map(|(ip, t)| {
                                row(vec![
                                    (250., ip.to_string(), C::TEXT),
                                    (
                                        140.,
                                        format!("{} · {}", t.tx_packets, human_bytes(t.tx_bytes)),
                                        C::MUTED,
                                    ),
                                    (
                                        140.,
                                        format!("{} · {}", t.rx_packets, human_bytes(t.rx_bytes)),
                                        C::MUTED,
                                    ),
                                    (90., human_bytes(t.tx_bytes + t.rx_bytes), C::TEXT),
                                ])
                            })),
                    )
                    .child(
                        panel(format!("Service ports ({})", ports.len()))
                            .w(px(440.))
                            .child(row(vec![
                                (180., "PORT".into(), C::MUTED),
                                (100., "PACKETS".into(), C::MUTED),
                                (100., "BYTES".into(), C::MUTED),
                            ]))
                            .children(ports.iter().take(25).map(|((t, p), (n, b))| {
                                let svc = crate::netinfo::service_name(*p);
                                row(vec![
                                    (180., format!("{}/{p} {svc}", t.to_lowercase()), C::TEXT),
                                    (100., n.to_string(), C::MUTED),
                                    (100., human_bytes(*b), C::MUTED),
                                ])
                            })),
                    ),
            )
            .child(
                panel(format!("Conversations ({})", convs.len()))
                    .child(row(vec![
                        (70., "PROTO".into(), C::MUTED),
                        (300., "ENDPOINT A".into(), C::MUTED),
                        (300., "ENDPOINT B".into(), C::MUTED),
                        (90., "PACKETS".into(), C::MUTED),
                        (100., "BYTES".into(), C::MUTED),
                        (0., "DURATION".into(), C::MUTED),
                    ]))
                    .children(convs.iter().take(60).map(|((a, b, proto), c)| {
                        row(vec![
                            (70., proto.to_string(), C::CYAN),
                            (300., endpoint(*a), C::TEXT),
                            (300., endpoint(*b), C::TEXT),
                            (90., c.packets.to_string(), C::MUTED),
                            (100., human_bytes(c.bytes), C::MUTED),
                            (0., format!("{:.2} s", (c.last - c.first).max(0.)), C::MUTED),
                        ])
                    })),
            )
            .into_any_element()
    }
}

impl Focusable for PacketStatsView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for PacketStatsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let body = self.render_body(cx);
        let s = self.session.read(cx);
        let report = s.a.stats.report();
        div()
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .child(
                toolbar()
                    .child(self.bar.clone())
                    .child(div().flex_1())
                    .child(copy_button("copy-stats", report)),
            )
            .children(error_line(&s.error))
            .child(body)
            .child(session_status(s))
    }
}
