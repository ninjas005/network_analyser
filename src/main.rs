// Windows: GUI app without a console window (see attach_parent_console).
#![cfg_attr(windows, windows_subsystem = "windows")]

mod anomaly;
mod arpwatch;
mod audit;
mod audit_view;
mod bacnet;
mod bacnet_view;
mod bandwidth;
mod can;
mod can_view;
mod capture;
mod capture_view;
mod cli_tools;
mod dhcp;
mod dhcp_client;
mod dhcp_client_view;
mod dhcp_view;
mod dissect;
mod dns;
mod dns_client;
mod dns_client_view;
mod dns_view;
mod dnscheck;
mod firewall;
mod firewall_view;
mod gateway;
mod gateway_view;
mod modbus;
mod modbus_view;
mod monitor;
mod monitor_view;
mod mqtt;
mod mqtt_view;
mod netconfig;
mod netconfig_view;
mod netinfo;
mod ntp;
mod ntp_view;
mod opcua;
mod opcua_crypto;
mod opcua_view;
mod perf_view;
mod platform;
mod portscan;
mod portscan_view;
mod probes;
mod profinet;
mod profinet_view;
mod scanner;
mod serial;
mod serial_view;
mod settings;
mod sftp;
mod sftp_view;
mod shell;
mod snmp;
mod snmp_view;
mod svcdetect;
mod throughput;
mod tls;
mod tls_view;
mod tools;
mod trace_view;
mod traceroute;
mod ui;
mod updater;
mod utils_view;
mod watch_view;
mod webapi;
mod websocket;
mod widgets;
mod wifi;
mod wol;
mod wol_view;
mod ws_view;

use std::time::Duration;

use gpui::{
    App, AppContext, Application, Bounds, KeyBinding, TitlebarOptions, WindowBounds,
    WindowDecorations, WindowKind, WindowOptions, point, px, size,
};

use shell::{
    CancelDialog, NextTool, PrevTool, Quit, RequestQuit, Shell, ToggleFullscreen, ToggleSidebar,
};
use tools::Tool;
use ui::{ClearSearch, Export, FocusSearch, ScannerView, StartStop, ToggleFilter};

const USAGE: &str = "\
network_analyser - LAN scanner, port scanner, packet capture, serial and Modbus tool

USAGE:
    network_analyser [--kiosk | --windowed] [--scan] [--tool TOOL]
    network_analyser --cli [RANGE]
    network_analyser --portscan TARGETS [PORTS]

OPTIONS:
    (default)     Open fullscreen; F11 toggles fullscreen
    --kiosk       Locked fullscreen, no window decorations; quit via
                  the Quit button, Esc (with confirmation) or Ctrl+Q
    --windowed    Open in a normal window (development)
    --scan        Start scanning the local subnet immediately
    --tool TOOL   Open a tool: lan, gateway, traceroute, dns, rdns, dhcp,
                  wol, ports, capture, modbus, serial, netconfig,
                  publicip, geoip, base64 (--tab is an alias)
    --no-update-check
                  Don't look for a new release on start (also:
                  NETWORK_ANALYSER_NO_UPDATE_CHECK=1)
    --x11         Linux: force X11 (XWayland under a Wayland session)
    --wayland     Linux: force native Wayland
    --cli RANGE   Headless scan, print results to stdout
                  RANGE: 192.168.1.0/24 | 10.0.0.5-40 | 10.0.0.5-10.0.1.9
    --portscan TARGETS [PORTS]
                  Headless TCP port scan of domains / IPs / ranges, e.g.
                  --portscan example.com,10.0.0.0/30 top,8000-8100
    --check-update
                  Print whether a newer release is available
    --dns NAME [TYPE] [@SERVER]
                  DNS query, e.g. --dns example.com MX @1.1.1.1
    --trace HOST  Traceroute
    --gateway     Gateway discovery report
    --dnscheck DOMAIN
                  DNS / mail security checks (DNSSEC, SPF, DMARC, AXFR…)
    --svc HOST [PORTS]
                  Service and version detection
    --wifi        Wi-Fi networks and channel recommendation
    --tls HOST[:PORT]
                  TLS certificate and protocol scan (STARTTLS on 25/587/143/110/21)
    --netconfig   Interfaces, routes and DNS servers
    --wol MAC [BROADCAST]
                  Send a Wake-on-LAN magic packet
    --snmp HOST[:PORT] [summary | get OID… | walk OID | v3 | check [COMMUNITIES]]
                  [-c COMMUNITY] [-1]
                  SNMP device summary (default), get / walk, SNMPv3 engine
                  discovery, or community check (-1 = SNMP v1)
    --ssh [USER@]HOST[:PORT]
                  SSH server audit: banner, algorithms (weak / Terrapin), host key
                  fingerprint and offered login methods (no login attempted)
    --ntp [SERVER…] [-n SAMPLES] [--all]
                  Query NTP servers: offset, delay, stratum, local clock verdict
    --dhcp-client [IFACE] [--mac MAC] [--request IP] [--inform] [--no-release] [--no-arp] [--repeat N]
                  Full DHCP exchange from a test MAC with timing (needs capture rights)
    --dnsbench [RESOLVER…] [-n ROUNDS] [--no-tcp] [--no-dot] [--quick]
                  Benchmark and check DNS resolvers (UDP / TCP / DNS-over-TLS)
    --can list    List SocketCAN interfaces and serial ports usable as slcan
    --can IFACE|slcan:PORT [--bitrate N] [--listen] [--count N] [send ID#DATA ...]
                  CAN monitor (candump-style), or send frames in cansend syntax
    --profinet IFACE [--wait S]
                  PROFINET DCP Identify All (needs capture rights)
    --bacnet [TARGET] [--range LOW-HIGH] [--wait S] [--objects]
                  BACnet/IP Who-Is discovery, device properties, optional object list
    --opcua opc.tcp://HOST[:4840][/PATH] [browse]
            [--policy NAME --mode sign|encrypt] [--user U --password P]
            [--user-cert FILE --user-key FILE] [--cert FILE --key FILE] [--trust]
                  OPC UA endpoints and security review; 'browse' or --policy opens a
                  session (--trust saves the server certificate; --cert/--key = own
                  client certificate, else a built-in one is created)
    --mqtt BROKER [TOPIC-FILTER] [SECONDS] [--user U --password P]
           [--ca CA.pem] [--cert CLIENT.pem --key CLIENT.key] [--insecure]
                  Subscribe and print messages (mqtt://, mqtts://, host[:port]);
                  --cert/--key = mutual TLS
    --ws URL [MESSAGE]
                  WebSocket handshake, send a message and a ping, print frames
    --list-ifaces List packet-capture interfaces
    --list-serial List serial ports
    --update-oui  Download the latest IEEE MAC-vendor list (needs curl)
";

#[derive(PartialEq)]
enum Mode {
    Fullscreen,
    Kiosk,
    Windowed,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        // So --cli/--help/errors print when started from cmd/PowerShell.
        attach_parent_console();
    }
    let mut mode = Mode::Fullscreen;
    let mut autoscan = false;
    let mut tab = Tool::LanScan;
    let mut update_check = std::env::var_os("NETWORK_ANALYSER_NO_UPDATE_CHECK").is_none();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kiosk" => mode = Mode::Kiosk,
            "--windowed" => mode = Mode::Windowed,
            "--scan" => autoscan = true,
            // gpui picks Wayland when WAYLAND_DISPLAY is set, X11 otherwise.
            "--x11" => unsafe { std::env::remove_var("WAYLAND_DISPLAY") },
            "--wayland" => {
                if std::env::var_os("WAYLAND_DISPLAY").is_none() {
                    eprintln!("--wayland: WAYLAND_DISPLAY is not set (not a Wayland session)");
                    std::process::exit(2);
                }
            }
            "--tab" | "--tool" => {
                i += 1;
                tab = args.get(i).and_then(|t| Tool::parse(t)).unwrap_or_else(|| {
                    let names: Vec<&str> = Tool::ALL.iter().map(|t| t.slug()).collect();
                    eprintln!("--tool: expected one of {}", names.join(", "));
                    std::process::exit(2)
                });
            }
            "--no-update-check" => update_check = false,
            "--check-update" => return run_check_update(),
            "--cli" => return run_cli(args.get(i + 1).cloned()),
            "--portscan" => {
                let Some(targets) = args.get(i + 1).cloned() else {
                    eprintln!("--portscan: missing TARGETS\n\n{USAGE}");
                    std::process::exit(2)
                };
                return run_portscan(targets, args.get(i + 2).cloned());
            }
            "--dns" => return cli_tools::dns(&args[i + 1..]),
            "--trace" => return cli_tools::trace(&args[i + 1..]),
            "--gateway" => return cli_tools::gateway(),
            "--tls" => return cli_tools::tls(&args[i + 1..]),
            "--dnscheck" => return cli_tools::dnscheck(&args[i + 1..]),
            "--wifi" => return cli_tools::wifi(),
            "--svc" => return cli_tools::svc(&args[i + 1..]),
            "--netconfig" => return cli_tools::netconfig(),
            "--wol" => return cli_tools::wol(&args[i + 1..]),
            "--snmp" => return snmp::cli(&args[i + 1..]),
            "--ntp" => return ntp::cli(&args[i + 1..]),
            "--ssh" => return sftp::cli(&args[i + 1..]),
            "--dhcp-client" => return dhcp_client::cli(&args[i + 1..]),
            "--dnsbench" => return dns_client::cli(&args[i + 1..]),
            "--can" => return can::cli(&args[i + 1..]),
            "--profinet" => return profinet::cli(&args[i + 1..]),
            "--bacnet" => return bacnet::cli(&args[i + 1..]),
            "--opcua" => return opcua::cli(&args[i + 1..]),
            "--mqtt" => return mqtt::cli(&args[i + 1..]),
            "--ws" => return websocket::cli(&args[i + 1..]),
            "--list-ifaces" => {
                match capture::interfaces() {
                    Ok(list) => {
                        for i in list {
                            println!(
                                "{:<20} {:<5} {:<40} {}",
                                i.name,
                                if i.up { "up" } else { "down" },
                                i.addrs.join(", "),
                                i.desc
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1)
                    }
                }
                return;
            }
            "--list-serial" => {
                match serial::list_ports() {
                    Ok(list) if list.is_empty() => eprintln!("no serial ports found"),
                    Ok(list) => {
                        for p in list {
                            println!("{:<24} {:<9} {}", p.name, p.kind, p.detail);
                        }
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1)
                    }
                }
                return;
            }
            "--update-oui" => {
                return match netinfo::update_oui_db() {
                    Ok(p) => println!("MAC vendor database saved to {}", p.display()),
                    Err(e) => {
                        eprintln!("update failed: {e}");
                        std::process::exit(1)
                    }
                };
            }
            "-h" | "--help" => return print!("{USAGE}"),
            other => {
                eprintln!("unknown argument '{other}'\n\n{USAGE}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    run_gui(mode, autoscan, tab, update_check);
}

fn run_check_update() {
    println!("current version: {}", updater::CURRENT);
    println!("install type:    {:?}", updater::install_kind());
    match updater::check() {
        Ok(Some(r)) => {
            println!("update available: {} ({})", r.version, r.page);
            for a in &r.assets {
                println!("  {} ({} bytes)", a.name, a.size);
            }
        }
        Ok(None) => println!("up to date"),
        Err(e) => {
            eprintln!("update check failed: {e}");
            std::process::exit(1)
        }
    }
}

fn run_gui(mode: Mode, autoscan: bool, tab: Tool, update_check: bool) {
    let kiosk = mode == Mode::Kiosk;
    Application::new().run(move |cx: &mut App| {
        cx.bind_keys([
            KeyBinding::new("secondary-q", Quit, None),
            KeyBinding::new("f5", StartStop, Some("Scanner")),
            KeyBinding::new("secondary-r", StartStop, Some("Scanner")),
            KeyBinding::new("f6", ToggleFilter, Some("Scanner")),
            KeyBinding::new("secondary-e", Export, Some("Scanner")),
            KeyBinding::new("f11", ToggleFullscreen, Some("Shell")),
            KeyBinding::new("escape", RequestQuit, Some("Shell")),
            KeyBinding::new("alt-up", PrevTool, Some("Shell")),
            KeyBinding::new("alt-down", NextTool, Some("Shell")),
            KeyBinding::new("secondary-b", ToggleSidebar, Some("Shell")),
            KeyBinding::new("escape", CancelDialog, Some("QuitDialog")),
            KeyBinding::new("enter", Quit, Some("QuitDialog")),
            KeyBinding::new("secondary-f", FocusSearch, Some("Scanner")),
            KeyBinding::new("escape", ClearSearch, Some("SearchBox")),
        ]);
        // Fallback so Ctrl+Q works even if nothing in the window has focus.
        cx.on_action(|_: &Quit, cx| cx.quit());
        // Closing the window (WM close button, Alt+F4) ends the app.
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        let display_bounds = cx
            .primary_display()
            .map(|d| d.bounds())
            .unwrap_or_else(|| Bounds::new(point(px(0.), px(0.)), size(px(1920.), px(1080.))));
        let window_bounds = match mode {
            Mode::Windowed => {
                WindowBounds::Windowed(Bounds::centered(None, size(px(1400.), px(860.)), cx))
            }
            _ => WindowBounds::Maximized(display_bounds),
        };

        let window = cx
            .open_window(
                WindowOptions {
                    window_bounds: Some(window_bounds),
                    titlebar: Some(TitlebarOptions {
                        title: Some("Network Analyser".into()),
                        ..Default::default()
                    }),
                    focus: true,
                    show: true,
                    kind: WindowKind::Normal,
                    is_movable: !kiosk,
                    is_resizable: !kiosk,
                    is_minimizable: !kiosk,
                    app_id: Some("network-analyser".into()),
                    window_min_size: Some(size(px(900.), px(500.))),
                    window_decorations: kiosk.then_some(WindowDecorations::Client),
                    ..Default::default()
                },
                |window, cx| {
                    let lan = cx.new(|cx| {
                        let mut v = ScannerView::new(kiosk, cx);
                        if autoscan {
                            v.start_scan(cx);
                        }
                        v
                    });
                    cx.new(|cx| {
                        let mut shell = Shell::new(kiosk, lan, update_check, window, cx);
                        shell.select(tab, window, cx);
                        shell
                    })
                },
            )
            .expect("failed to open window");

        if mode != Mode::Windowed {
            // Linux backends ignore an initial Fullscreen bound, so request it
            // once the window has been mapped by the compositor/WM.
            cx.spawn(async move |cx| {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                window
                    .update(cx, |_, window, _| {
                        if !window.is_fullscreen() {
                            window.toggle_fullscreen();
                        }
                    })
                    .ok();
            })
            .detach();
        }
        cx.activate(true);
    });
}

fn run_cli(range: Option<String>) {
    let iface = netinfo::local_interfaces().into_iter().next();
    let range = range
        .or_else(|| iface.as_ref().map(|i| i.cidr()))
        .unwrap_or_else(|| {
            eprintln!("no interface found; pass a range");
            std::process::exit(2)
        });
    let targets = netinfo::parse_range(&range).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    eprintln!("Scanning {range} ({} addresses)…", targets.len());
    let handle = scanner::start(scanner::ScanConfig {
        targets: targets.clone(),
        ports: netinfo::DEFAULT_PORTS.to_vec(),
        host_concurrency: 64,
        connect_timeout: Duration::from_millis(700),
        local: iface,
    });
    let mut hosts: Vec<Option<scanner::HostInfo>> = vec![None; targets.len()];
    while let Ok(ev) = handle.events.recv() {
        match ev {
            scanner::ScanEvent::Host(i, h) => hosts[i] = Some(*h),
            scanner::ScanEvent::Intercepted(p) => {
                eprintln!("warning: ports {p:?} are intercepted by a local proxy; excluded")
            }
            scanner::ScanEvent::Finished { elapsed, .. } => {
                let alive: Vec<_> = hosts.iter().flatten().filter(|h| h.is_alive()).collect();
                for h in &alive {
                    println!(
                        "{:<16} {:>8} ttl={:<4} {:<28} {:<18} {:<28} {:<24} {:<30} [{}]",
                        h.ip.to_string(),
                        h.rtt_ms.map(|r| format!("{r:.1}ms")).unwrap_or("-".into()),
                        h.ttl.map(|t| t.to_string()).unwrap_or("-".into()),
                        h.hostname().unwrap_or("-".into()),
                        h.mac.clone().unwrap_or("-".into()),
                        h.vendor
                            .clone()
                            .unwrap_or("-".into())
                            .chars()
                            .take(28)
                            .collect::<String>(),
                        h.device_type.clone().unwrap_or("-".into()),
                        h.os_guess.clone().unwrap_or("-".into()),
                        h.ports_summary(),
                    );
                    for p in &h.ports {
                        if let Some(b) = &p.banner {
                            println!("{:<16}   {}/{}: {}", "", p.port, p.service, b);
                        }
                    }
                    if let Some(t) = &h.http_title {
                        println!("{:<16}   http title: {t}", "");
                    }
                    if let Some(u) = &h.upnp {
                        println!(
                            "{:<16}   upnp: {:?} {:?} {:?} {:?}",
                            "", u.friendly_name, u.manufacturer, u.model, u.server
                        );
                    }
                }
                eprintln!(
                    "{} live hosts in {:.1}s",
                    alive.len(),
                    elapsed.as_secs_f32()
                );
                break;
            }
        }
    }
}

fn run_portscan(targets: String, ports: Option<String>) {
    let ports = portscan::parse_ports(ports.as_deref().unwrap_or("top")).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    eprintln!("Scanning {} ports on {targets}…", ports.len());
    let handle = portscan::start(portscan::PortScanConfig {
        targets,
        ports,
        timeout: Duration::from_millis(1500),
        concurrency: 400,
        banners: true,
    });
    let mut names = Vec::new();
    let mut open: Vec<portscan::OpenPort> = Vec::new();
    while let Ok(ev) = handle.events.recv() {
        match ev {
            portscan::PortScanEvent::Resolved(t) => {
                for x in &t {
                    eprintln!("  {} -> {}", x.name, x.ip);
                }
                names = t;
            }
            portscan::PortScanEvent::Open(p) => open.push(p),
            portscan::PortScanEvent::Banner {
                target,
                port,
                banner,
            } => {
                if let Some(p) = open
                    .iter_mut()
                    .find(|p| p.target == target && p.port == port)
                {
                    p.banner = banner.text;
                    p.http_title = banner.http_title;
                }
            }
            portscan::PortScanEvent::Progress { .. } => {}
            portscan::PortScanEvent::Error(e) => {
                eprintln!("error: {e}");
                std::process::exit(1)
            }
            portscan::PortScanEvent::Finished { elapsed, .. } => {
                open.sort_by_key(|p| (p.target, p.port));
                for p in &open {
                    let t = &names[p.target];
                    println!(
                        "{:<40} {:>5}/tcp {:<12} {:>7.1}ms  {}{}",
                        format!("{} ({})", t.name, t.ip),
                        p.port,
                        p.service,
                        p.connect_ms,
                        p.banner.clone().unwrap_or_default(),
                        p.http_title
                            .as_ref()
                            .map(|t| format!("  [{t}]"))
                            .unwrap_or_default()
                    );
                }
                eprintln!("{} open ports in {:.1}s", open.len(), elapsed.as_secs_f32());
                break;
            }
        }
    }
}

/// The Windows build uses the GUI subsystem (no console window), so CLI
/// output has to attach to the console of the shell that started us.
#[cfg(windows)]
fn attach_parent_console() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_parent_console() {}
