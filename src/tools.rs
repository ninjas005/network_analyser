//! Tool registry: segments, tools, names, and view construction.

use gpui::{AnyView, App, AppContext, Entity, FocusHandle, Focusable, Window};

use crate::ui::ScannerView;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Segment {
    Discovery,
    PortsServices,
    PacketAnalysis,
    Industrial,
    Serial,
    Security,
    Performance,
    Utilities,
}

impl Segment {
    pub const ALL: [Segment; 8] = [
        Segment::Discovery,
        Segment::PortsServices,
        Segment::PacketAnalysis,
        Segment::Industrial,
        Segment::Serial,
        Segment::Security,
        Segment::Performance,
        Segment::Utilities,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Segment::Discovery => "Network Discovery",
            Segment::PortsServices => "Ports & Services",
            Segment::PacketAnalysis => "Packet Analysis",
            Segment::Industrial => "Industrial Protocols",
            Segment::Serial => "Serial Communication",
            Segment::Security => "Security & Audit",
            Segment::Performance => "Performance",
            Segment::Utilities => "Network Utilities",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Tool {
    LanScan,
    Gateway,
    Traceroute,
    DnsLookup,
    ReverseDns,
    Dhcp,
    WakeOnLan,
    PortScan,
    Capture,
    Modbus,
    Serial,
    NetConfig,
    PublicIp,
    GeoIp,
    Base64,
}

impl Tool {
    /// Sidebar order (grouped by segment).
    pub const ALL: [Tool; 15] = [
        Tool::LanScan,
        Tool::Gateway,
        Tool::Traceroute,
        Tool::DnsLookup,
        Tool::ReverseDns,
        Tool::Dhcp,
        Tool::WakeOnLan,
        Tool::PortScan,
        Tool::Capture,
        Tool::Modbus,
        Tool::Serial,
        Tool::NetConfig,
        Tool::PublicIp,
        Tool::GeoIp,
        Tool::Base64,
    ];

    pub fn segment(self) -> Segment {
        match self {
            Tool::LanScan
            | Tool::Gateway
            | Tool::Traceroute
            | Tool::DnsLookup
            | Tool::ReverseDns
            | Tool::Dhcp
            | Tool::WakeOnLan => Segment::Discovery,
            Tool::PortScan => Segment::PortsServices,
            Tool::Capture => Segment::PacketAnalysis,
            Tool::Modbus => Segment::Industrial,
            Tool::Serial => Segment::Serial,
            Tool::NetConfig | Tool::PublicIp | Tool::GeoIp | Tool::Base64 => Segment::Utilities,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tool::LanScan => "LAN Scan",
            Tool::Gateway => "Gateway Discovery",
            Tool::Traceroute => "Traceroute",
            Tool::DnsLookup => "DNS Lookup",
            Tool::ReverseDns => "Reverse DNS",
            Tool::Dhcp => "DHCP Analyser",
            Tool::WakeOnLan => "Wake-on-LAN",
            Tool::PortScan => "Port Scan",
            Tool::Capture => "Packet Capture",
            Tool::Modbus => "Modbus RTU / TCP",
            Tool::Serial => "Serial Monitor",
            Tool::NetConfig => "Network Configuration",
            Tool::PublicIp => "Public IP",
            Tool::GeoIp => "IP Geolocation",
            Tool::Base64 => "Base64",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Tool::LanScan => {
                "Find live devices on a subnet: names, MACs, vendors, ports, OS guesses"
            }
            Tool::Gateway => {
                "Default routers, NAT / double-NAT, UPnP and NAT-PMP, DNS server health"
            }
            Tool::Traceroute => "Path to a host with per-hop latency and loss",
            Tool::DnsLookup => "Query any record type on any DNS server; compare resolvers",
            Tool::ReverseDns => "PTR names for addresses and ranges, with forward confirmation",
            Tool::Dhcp => "Watch DHCP traffic and find every DHCP server on the segment",
            Tool::WakeOnLan => "Send magic packets and confirm the device woke up",
            Tool::PortScan => "TCP scan of domains, addresses and ranges with banners",
            Tool::Capture => "Capture or open .pcap files, decode and analyse traffic",
            Tool::Modbus => "Modbus TCP / RTU master: read, poll, write, discover",
            Tool::Serial => "Serial port monitor, sender, Modbus RTU decoder, baud detection",
            Tool::NetConfig => "Interfaces, addresses, routes, DNS servers and neighbours",
            Tool::PublicIp => "Your public IPv4 / IPv6 address and NAT status (online lookup)",
            Tool::GeoIp => "Location and network owner of an IP address (online lookup)",
            Tool::Base64 => "Encode and decode Base64 (standard or URL-safe)",
        }
    }

    /// Command-line name (`--tool SLUG`).
    pub fn slug(self) -> &'static str {
        match self {
            Tool::LanScan => "lan",
            Tool::Gateway => "gateway",
            Tool::Traceroute => "traceroute",
            Tool::DnsLookup => "dns",
            Tool::ReverseDns => "rdns",
            Tool::Dhcp => "dhcp",
            Tool::WakeOnLan => "wol",
            Tool::PortScan => "ports",
            Tool::Capture => "capture",
            Tool::Modbus => "modbus",
            Tool::Serial => "serial",
            Tool::NetConfig => "netconfig",
            Tool::PublicIp => "publicip",
            Tool::GeoIp => "geoip",
            Tool::Base64 => "base64",
        }
    }

    pub fn parse(s: &str) -> Option<Tool> {
        let s = s.to_ascii_lowercase();
        Tool::ALL
            .into_iter()
            .find(|t| t.slug() == s)
            .or(match s.as_str() {
                "scan" => Some(Tool::LanScan),
                "portscan" => Some(Tool::PortScan),
                "trace" | "tracert" => Some(Tool::Traceroute),
                "reverse-dns" | "ptr" => Some(Tool::ReverseDns),
                "geo" | "geolocation" => Some(Tool::GeoIp),
                _ => None,
            })
    }
}

fn make<V: Focusable + gpui::Render>(
    cx: &mut App,
    f: impl FnOnce(&mut gpui::Context<V>) -> V,
) -> (AnyView, FocusHandle) {
    let e: Entity<V> = cx.new(f);
    let focus = e.focus_handle(cx);
    (e.into(), focus)
}

/// Build a tool's view (LAN Scan is created by the shell).
pub fn create(
    tool: Tool,
    lan: &Entity<ScannerView>,
    window: &mut Window,
    cx: &mut App,
) -> (AnyView, FocusHandle) {
    use crate::*;
    match tool {
        Tool::LanScan => (lan.clone().into(), lan.focus_handle(cx)),
        Tool::Gateway => make(cx, |cx| gateway_view::GatewayView::new(window, cx)),
        Tool::Traceroute => make(cx, |cx| trace_view::TraceView::new(window, cx)),
        Tool::DnsLookup => make(cx, |cx| dns_view::DnsView::new(window, cx)),
        Tool::ReverseDns => make(cx, |cx| dns_view::ReverseDnsView::new(window, cx)),
        Tool::Dhcp => make(cx, |cx| dhcp_view::DhcpView::new(window, cx)),
        Tool::WakeOnLan => {
            let lan = lan.clone();
            make(cx, |cx| wol_view::WolView::new(lan, window, cx))
        }
        Tool::PortScan => make(cx, |cx| portscan_view::PortScanView::new(window, cx)),
        Tool::Capture => make(cx, |cx| capture_view::CaptureView::new(window, cx)),
        Tool::Modbus => make(cx, |cx| modbus_view::ModbusView::new(window, cx)),
        Tool::Serial => make(cx, |cx| serial_view::SerialView::new(window, cx)),
        Tool::NetConfig => make(cx, |cx| netconfig_view::NetConfigView::new(window, cx)),
        Tool::PublicIp => make(cx, |cx| utils_view::PublicIpView::new(window, cx)),
        Tool::GeoIp => make(cx, |cx| utils_view::GeoIpView::new(window, cx)),
        Tool::Base64 => make(cx, |cx| utils_view::Base64View::new(window, cx)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_roundtrip_and_cover_segments() {
        for t in Tool::ALL {
            assert_eq!(Tool::parse(t.slug()), Some(t));
        }
        assert_eq!(Tool::parse("ports"), Some(Tool::PortScan));
        assert_eq!(Tool::parse("scan"), Some(Tool::LanScan));
        // Sidebar order keeps each segment contiguous.
        let segs: Vec<Segment> = Tool::ALL.iter().map(|t| t.segment()).collect();
        let mut seen = Vec::new();
        for s in segs {
            if seen.last() != Some(&s) {
                assert!(!seen.contains(&s), "segment {s:?} split in Tool::ALL");
                seen.push(s);
            }
        }
    }
}
