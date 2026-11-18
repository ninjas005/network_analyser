# Network Analyser

A lightweight LAN scanner with a GPUI interface. It finds the live devices
on a network and collects whatever it can about each one. No root needed.

## What it collects per host

| Info | Source |
|---|---|
| Alive / ping RTT / TTL | ICMP via system `ping`, TCP connect/RST, kernel ARP table |
| Hostname | Reverse DNS, unicast mDNS (`.local`), NetBIOS (UDP 137), UPnP friendly name |
| MAC + vendor | `/proc/net/arp` (or NetBIOS) + IEEE OUI registry |
| Open ports | TCP connect scan of ~60 common ports (`netinfo::DEFAULT_PORTS`) |
| Banners | First line of each service (SSH version, FTP, SMTP…), HTTP status / `Server` / `<title>` |
| UPnP / SSDP | Server string, friendly name, manufacturer, model, device type |
| NetBIOS | Machine name, workgroup, logged-in user |
| OS & device type | Heuristics from TTL, ports, banners, vendor, mDNS, UPnP |

**Proxy interception detection:** before each scan the app connects to the reserved
TEST-NET addresses (RFC 5737). If ports "open" there, a transparent proxy or security
agent is answering for every address. Those ports are excluded and a warning appears in
the status bar.

## Build

```sh
sudo apt install libxkbcommon-x11-dev libxcb1-dev libfontconfig-dev libvulkan-dev   # Debian/Ubuntu
cargo build --release
```

## Run

```sh
network_analyser                # fullscreen (F11 toggles)
network_analyser --kiosk        # locked fullscreen, no decorations, F11 disabled
network_analyser --windowed     # normal window
network_analyser --kiosk --scan # start scanning the local subnet on launch
network_analyser --cli [RANGE]  # headless, prints a table
network_analyser --update-oui   # refresh MAC-vendor DB (curl) -> ~/.local/share/network_analyser/oui.txt
```

Ranges: `192.168.1.0/24` (/16–/32), `10.0.0.5-40`, `10.0.0.5-10.0.1.9`, or a single IP.

## Keys

| Key | Action |
|---|---|
| F5 / Ctrl+R / Enter in range box | Start / stop scan |
| Ctrl+F | Focus search (Esc clears it, Esc again leaves the box) |
| F6 | Toggle live-only / all addresses |
| Ctrl+E | Export CSV to `~/network-scan-<timestamp>.csv` |
| F11 | Toggle fullscreen (not in kiosk) |
| Esc | Quit dialog (Enter = quit, Esc = cancel) |
| Ctrl+Q | Quit immediately |
| ✕ Quit button | Quit dialog |

Click a row to open the details panel. Click a column header to sort (ascending →
descending → back to IP order; empty values always last).

Search matches IP, any hostname, MAC, vendor, device, OS, HTTP title/server, UPnP
info, port numbers, service names and banners. Every space-separated term must
match, so `raspberry 22` finds Raspberry Pis with SSH open.

## Layout

- `src/main.rs` – CLI flags, window/kiosk setup, key bindings, headless mode
- `src/ui.rs` – GPUI view (toolbar, table, details, status bar, quit dialog)
- `src/scanner.rs` – scan engine (own thread + tokio), fingerprinting
- `src/probes.rs` – ping, TCP, banners/HTTP, mDNS, NetBIOS, SSDP/UPnP, rDNS
- `src/netinfo.rs` – interfaces, gateway, ARP, OUI vendors, ranges, port names

`libc` is pinned to 0.2.186 (and tokio to 1.52) in `Cargo.lock`. Newer `libc` removed
`ENOATTR`, which breaks `xattr 0.2.3`, a dependency gpui 0.2.2 pulls in. Keep the
lockfile when updating.
