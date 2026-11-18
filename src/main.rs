mod netinfo;
mod probes;
mod scanner;
mod ui;

use std::time::Duration;

use gpui::{
    App, AppContext, Application, Bounds, KeyBinding, TitlebarOptions, WindowBounds,
    WindowDecorations, WindowKind, WindowOptions, point, px, size,
};

use ui::{CancelDialog, ClearSearch, Export, FocusSearch, Quit, RequestQuit, ScannerView, StartStop, ToggleFilter, ToggleFullscreen};

const USAGE: &str = "\
network_analyser - lightweight LAN scanner

USAGE:
    network_analyser [--kiosk | --windowed] [--scan]
    network_analyser --cli [RANGE]

OPTIONS:
    (default)     Open fullscreen; F11 toggles fullscreen
    --kiosk       Locked fullscreen, no window decorations; quit via
                  the Quit button, Esc (with confirmation) or Ctrl+Q
    --windowed    Open in a normal window (development)
    --scan        Start scanning the local subnet immediately
    --cli RANGE   Headless scan, print results to stdout
    --update-oui  Download the latest IEEE MAC-vendor list (needs curl)
                  RANGE: 192.168.1.0/24 | 10.0.0.5-40 | 10.0.0.5-10.0.1.9
";

#[derive(PartialEq)]
enum Mode {
    Fullscreen,
    Kiosk,
    Windowed,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = Mode::Fullscreen;
    let mut autoscan = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kiosk" => mode = Mode::Kiosk,
            "--windowed" => mode = Mode::Windowed,
            "--scan" => autoscan = true,
            "--cli" => return run_cli(args.get(i + 1).cloned()),
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
    run_gui(mode, autoscan);
}

fn run_gui(mode: Mode, autoscan: bool) {
    let kiosk = mode == Mode::Kiosk;
    Application::new().run(move |cx: &mut App| {
        cx.bind_keys([
            KeyBinding::new("ctrl-q", Quit, None),
            KeyBinding::new("f5", StartStop, Some("Scanner")),
            KeyBinding::new("ctrl-r", StartStop, Some("Scanner")),
            KeyBinding::new("f6", ToggleFilter, Some("Scanner")),
            KeyBinding::new("ctrl-e", Export, Some("Scanner")),
            KeyBinding::new("f11", ToggleFullscreen, Some("Scanner")),
            KeyBinding::new("escape", RequestQuit, Some("Scanner")),
            KeyBinding::new("escape", CancelDialog, Some("QuitDialog")),
            KeyBinding::new("enter", Quit, Some("QuitDialog")),
            KeyBinding::new("ctrl-f", FocusSearch, Some("Scanner")),
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
            Mode::Windowed => WindowBounds::Windowed(Bounds::centered(None, size(px(1400.), px(860.)), cx)),
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
                    let view = cx.new(|cx| {
                        let mut v = ScannerView::new(kiosk, cx);
                        if autoscan {
                            v.start_scan(cx);
                        }
                        v
                    });
                    window.focus(&view.read(cx).focus_handle_ref().clone());
                    view
                },
            )
            .expect("failed to open window");

        if mode != Mode::Windowed {
            // Linux backends ignore an initial Fullscreen bound, so request it
            // once the window has been mapped by the compositor/WM.
            cx.spawn(async move |cx| {
                cx.background_executor().timer(Duration::from_millis(250)).await;
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
    let range = range.or_else(|| iface.as_ref().map(|i| i.cidr())).unwrap_or_else(|| {
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
            scanner::ScanEvent::Intercepted(p) => eprintln!("warning: ports {p:?} are intercepted by a local proxy; excluded"),
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
                        h.vendor.clone().unwrap_or("-".into()).chars().take(28).collect::<String>(),
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
                        println!("{:<16}   upnp: {:?} {:?} {:?} {:?}", "", u.friendly_name, u.manufacturer, u.model, u.server);
                    }
                }
                eprintln!("{} live hosts in {:.1}s", alive.len(), elapsed.as_secs_f32());
                break;
            }
        }
    }
}
