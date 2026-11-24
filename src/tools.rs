//! Tool registry: segments, tools, names, and view construction.

use gpui::{AnyView, App, AppContext, Entity, FocusHandle, Focusable, Window};

use crate::ui::ScannerView;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Segment {
    Discovery,
    PortsServices,
    PacketAnalysis,
    Industrial,
    Iot,
    Serial,
    Security,
    Performance,
    Utilities,
}

impl Segment {
    pub const ALL: [Segment; 9] = [
        Segment::Discovery,
        Segment::PortsServices,
        Segment::PacketAnalysis,
        Segment::Industrial,
        Segment::Iot,
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
            Segment::Iot => "IoT Protocols",
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
    ServiceVersions,
    TlsScan,
    Snmp,
    Ntp,
    Sftp,
    DhcpClient,
    DnsClient,
    Capture,
    PcapViewer,
    ProtoDecode,
    TcpStreams,
    HttpStreams,
    Handshake,
    DnsMonitor,
    PacketStats,
    Modbus,
    CanBus,
    Profinet,
    Bacnet,
    OpcUa,
    Mqtt,
    WebSocket,
    Serial,
    PortAudit,
    Firewall,
    RogueDhcp,
    ArpSpoof,
    DnsSecurity,
    Anomaly,
    Bandwidth,
    Throughput,
    Latency,
    Jitter,
    PacketLoss,
    Wifi,
    Uptime,
    NetConfig,
    PublicIp,
    GeoIp,
    Base64,
}

impl Tool {
    /// Sidebar order (grouped by segment).
    pub const ALL: [Tool; 48] = [
        Tool::LanScan,
        Tool::Gateway,
        Tool::Traceroute,
        Tool::DnsLookup,
        Tool::ReverseDns,
        Tool::Dhcp,
        Tool::WakeOnLan,
        Tool::PortScan,
        Tool::ServiceVersions,
        Tool::TlsScan,
        Tool::Snmp,
        Tool::Ntp,
        Tool::Sftp,
        Tool::DhcpClient,
        Tool::DnsClient,
        Tool::Capture,
        Tool::PcapViewer,
        Tool::ProtoDecode,
        Tool::TcpStreams,
        Tool::HttpStreams,
        Tool::Handshake,
        Tool::DnsMonitor,
        Tool::PacketStats,
        Tool::Modbus,
        Tool::CanBus,
        Tool::Profinet,
        Tool::Bacnet,
        Tool::OpcUa,
        Tool::Mqtt,
        Tool::WebSocket,
        Tool::Serial,
        Tool::PortAudit,
        Tool::Firewall,
        Tool::RogueDhcp,
        Tool::ArpSpoof,
        Tool::DnsSecurity,
        Tool::Anomaly,
        Tool::Bandwidth,
        Tool::Throughput,
        Tool::Latency,
        Tool::Jitter,
        Tool::PacketLoss,
        Tool::Wifi,
        Tool::Uptime,
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
            Tool::PortScan
            | Tool::ServiceVersions
            | Tool::TlsScan
            | Tool::Snmp
            | Tool::Ntp
            | Tool::Sftp
            | Tool::DhcpClient
            | Tool::DnsClient => Segment::PortsServices,
            Tool::PortAudit
            | Tool::Firewall
            | Tool::RogueDhcp
            | Tool::ArpSpoof
            | Tool::DnsSecurity
            | Tool::Anomaly => Segment::Security,
            Tool::Bandwidth
            | Tool::Throughput
            | Tool::Latency
            | Tool::Jitter
            | Tool::PacketLoss
            | Tool::Wifi
            | Tool::Uptime => Segment::Performance,
            Tool::Capture
            | Tool::PcapViewer
            | Tool::ProtoDecode
            | Tool::TcpStreams
            | Tool::HttpStreams
            | Tool::Handshake
            | Tool::DnsMonitor
            | Tool::PacketStats => Segment::PacketAnalysis,
            Tool::Modbus | Tool::CanBus | Tool::Profinet | Tool::Bacnet | Tool::OpcUa => {
                Segment::Industrial
            }
            Tool::Mqtt | Tool::WebSocket => Segment::Iot,
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
            Tool::ServiceVersions => "Service Versions",
            Tool::TlsScan => "TLS Certificates",
            Tool::Snmp => "SNMP",
            Tool::Ntp => "NTP Analyser",
            Tool::Sftp => "SFTP / SSH Tester",
            Tool::DhcpClient => "DHCP Client Tester",
            Tool::DnsClient => "DNS Client Tester",
            Tool::CanBus => "CAN Bus Analyser",
            Tool::Profinet => "PROFINET",
            Tool::Bacnet => "BACnet",
            Tool::OpcUa => "OPC UA",
            Tool::Mqtt => "MQTT",
            Tool::WebSocket => "WebSocket",
            Tool::PortAudit => "Open Port Audit",
            Tool::Firewall => "Firewall Tester",
            Tool::RogueDhcp => "Rogue DHCP Tester",
            Tool::ArpSpoof => "ARP Spoof Detector",
            Tool::DnsSecurity => "DNS Security",
            Tool::Anomaly => "Anomaly Detector",
            Tool::Bandwidth => "Bandwidth Monitor",
            Tool::Throughput => "Throughput Tester",
            Tool::Latency => "Latency Monitor",
            Tool::Jitter => "Jitter Tester",
            Tool::PacketLoss => "Packet Loss Tester",
            Tool::Wifi => "Wi-Fi Analyser",
            Tool::Uptime => "Uptime Monitor",
            Tool::Capture => "Live Packet Capture",
            Tool::PcapViewer => "PCAP / PCAPNG Viewer",
            Tool::ProtoDecode => "Protocol Decoder",
            Tool::TcpStreams => "TCP Streams",
            Tool::HttpStreams => "HTTP Reconstruction",
            Tool::Handshake => "TCP Handshakes",
            Tool::DnsMonitor => "DNS Monitor",
            Tool::PacketStats => "Packet Statistics",
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
            Tool::ServiceVersions => "Identify products and versions behind open ports",
            Tool::TlsScan => "Certificate chain, expiry, trust, TLS versions (incl. STARTTLS)",
            Tool::Snmp => "SNMP v1/v2c get, walk and device summary; v3 engine discovery",
            Tool::Ntp => "Query NTP servers: offset, delay, stratum, and compare sources",
            Tool::Sftp => "SSH server algorithms and host key, login test, SFTP browse / transfer",
            Tool::DhcpClient => "Run a full DHCP exchange and time each step of the lease",
            Tool::DnsClient => "Benchmark and validate DNS servers: speed, failures, hijacking",
            Tool::CanBus => "CAN / CAN FD via SocketCAN or slcan: monitor, send, statistics",
            Tool::Profinet => "PROFINET DCP: discover devices, names, addresses, set name / IP",
            Tool::Bacnet => "BACnet/IP: discover devices, browse objects, read properties",
            Tool::OpcUa => "OPC UA: endpoints and security, browse the address space, read",
            Tool::Mqtt => "MQTT client: publish, subscribe, topic tree and message rates",
            Tool::WebSocket => "WebSocket client: handshake details, send, frame log",
            Tool::PortAudit => "Risk-rate open ports against a policy and a saved baseline",
            Tool::Firewall => "Outbound policy test, and open / closed / filtered on a target",
            Tool::RogueDhcp => "Find DHCP servers that are not on your authorised list",
            Tool::ArpSpoof => "Detect MAC changes, gateway impersonation and ARP floods",
            Tool::DnsSecurity => "DNSSEC, SPF, DMARC, DKIM, CAA, zone transfer, resolver checks",
            Tool::Anomaly => "Scans, floods, storms, DNS tunnelling, new devices, clear text",
            Tool::Bandwidth => "Live per-interface throughput",
            Tool::Throughput => "Measure TCP throughput between two machines, or an HTTP download",
            Tool::Latency => "Continuous latency to several targets with charts",
            Tool::Jitter => "Jitter, latency spread and a VoIP quality estimate",
            Tool::PacketLoss => "Loss rate and loss bursts over a long probe series",
            Tool::Wifi => "Nearby networks, signal, channel congestion and recommendations",
            Tool::Uptime => "Watch hosts and services; outage log and availability",
            Tool::Capture => "Capture packets live with filters, limits and decoding",
            Tool::PcapViewer => "Open .pcap / .pcapng files (also gzip): packets and file details",
            Tool::ProtoDecode => "Identify protocols by content or port; decode pasted hex",
            Tool::TcpStreams => "Reassemble TCP streams and follow conversations",
            Tool::HttpStreams => "Rebuild HTTP requests and responses with decoded bodies",
            Tool::Handshake => "TCP handshake results, round trips, options and health",
            Tool::DnsMonitor => "DNS queries with answers, times, failures and totals",
            Tool::PacketStats => "Protocol distribution, traffic over time, sizes, talkers",
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
            Tool::ServiceVersions => "versions",
            Tool::TlsScan => "tls",
            Tool::Snmp => "snmp",
            Tool::Ntp => "ntp",
            Tool::Sftp => "sftp",
            Tool::DhcpClient => "dhcp-client",
            Tool::DnsClient => "dns-client",
            Tool::CanBus => "can",
            Tool::Profinet => "profinet",
            Tool::Bacnet => "bacnet",
            Tool::OpcUa => "opcua",
            Tool::Mqtt => "mqtt",
            Tool::WebSocket => "websocket",
            Tool::PortAudit => "audit",
            Tool::Firewall => "firewall",
            Tool::RogueDhcp => "rogue-dhcp",
            Tool::ArpSpoof => "arp",
            Tool::DnsSecurity => "dnssec",
            Tool::Anomaly => "anomaly",
            Tool::Bandwidth => "bandwidth",
            Tool::Throughput => "throughput",
            Tool::Latency => "latency",
            Tool::Jitter => "jitter",
            Tool::PacketLoss => "loss",
            Tool::Wifi => "wifi",
            Tool::Uptime => "uptime",
            Tool::Capture => "capture",
            Tool::PcapViewer => "pcap",
            Tool::ProtoDecode => "decode",
            Tool::TcpStreams => "streams",
            Tool::HttpStreams => "http",
            Tool::Handshake => "handshake",
            Tool::DnsMonitor => "dns-monitor",
            Tool::PacketStats => "packet-stats",
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
                "ssh" => Some(Tool::Sftp),
                "ws" => Some(Tool::WebSocket),
                "canbus" => Some(Tool::CanBus),
                "pcapng" => Some(Tool::PcapViewer),
                "opc-ua" => Some(Tool::OpcUa),
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
        Tool::ServiceVersions => make(cx, |cx| audit_view::ServiceView::new(window, cx)),
        Tool::TlsScan => make(cx, |cx| tls_view::TlsView::new(window, cx)),
        Tool::Snmp => make(cx, |cx| snmp_view::SnmpView::new(window, cx)),
        Tool::Ntp => make(cx, |cx| ntp_view::NtpView::new(window, cx)),
        Tool::Sftp => make(cx, |cx| sftp_view::SftpView::new(window, cx)),
        Tool::DhcpClient => make(cx, |cx| dhcp_client_view::DhcpClientView::new(window, cx)),
        Tool::DnsClient => make(cx, |cx| dns_client_view::DnsClientView::new(window, cx)),
        Tool::CanBus => make(cx, |cx| can_view::CanView::new(window, cx)),
        Tool::Profinet => make(cx, |cx| profinet_view::ProfinetView::new(window, cx)),
        Tool::Bacnet => make(cx, |cx| bacnet_view::BacnetView::new(window, cx)),
        Tool::OpcUa => make(cx, |cx| opcua_view::OpcUaView::new(window, cx)),
        Tool::Mqtt => make(cx, |cx| mqtt_view::MqttView::new(window, cx)),
        Tool::WebSocket => make(cx, |cx| ws_view::WsView::new(window, cx)),
        Tool::PortAudit => make(cx, |cx| audit_view::AuditView::new(window, cx)),
        Tool::Firewall => make(cx, |cx| firewall_view::FirewallView::new(window, cx)),
        Tool::RogueDhcp => make(cx, |cx| firewall_view::RogueDhcpView::new(window, cx)),
        Tool::ArpSpoof => make(cx, |cx| watch_view::ArpView::new(window, cx)),
        Tool::DnsSecurity => make(cx, |cx| watch_view::DnsSecView::new(window, cx)),
        Tool::Anomaly => make(cx, |cx| watch_view::AnomalyView::new(window, cx)),
        Tool::Bandwidth => make(cx, |cx| perf_view::BandwidthView::new(window, cx)),
        Tool::Throughput => make(cx, |cx| perf_view::ThroughputView::new(window, cx)),
        Tool::Latency => make(cx, |cx| {
            monitor_view::MonitorView::new(monitor_view::Purpose::Latency, window, cx)
        }),
        Tool::Jitter => make(cx, |cx| {
            monitor_view::MonitorView::new(monitor_view::Purpose::Jitter, window, cx)
        }),
        Tool::PacketLoss => make(cx, |cx| {
            monitor_view::MonitorView::new(monitor_view::Purpose::Loss, window, cx)
        }),
        Tool::Wifi => make(cx, |cx| perf_view::WifiView::new(window, cx)),
        Tool::Uptime => make(cx, |cx| {
            monitor_view::MonitorView::new(monitor_view::Purpose::Uptime, window, cx)
        }),
        Tool::Capture => make(cx, |cx| {
            capture_view::CaptureView::new(capture_view::Kind::Live, window, cx)
        }),
        Tool::PcapViewer => make(cx, |cx| {
            capture_view::CaptureView::new(capture_view::Kind::File, window, cx)
        }),
        Tool::ProtoDecode => make(cx, |cx| {
            capture_view::CaptureView::new(capture_view::Kind::Decode, window, cx)
        }),
        Tool::TcpStreams => make(cx, |cx| flows_view::StreamsView::new(window, cx)),
        Tool::HttpStreams => make(cx, |cx| flows_view::HttpView::new(window, cx)),
        Tool::Handshake => make(cx, |cx| flows_view::HandshakeView::new(window, cx)),
        Tool::DnsMonitor => make(cx, |cx| dnsmon_view::DnsMonView::new(window, cx)),
        Tool::PacketStats => make(cx, |cx| pktstats_view::PacketStatsView::new(window, cx)),
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
