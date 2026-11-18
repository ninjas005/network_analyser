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

## Install

Download from [Releases](../../releases):

| Platform | Package |
|---|---|
| Debian / Ubuntu | `network-analyser_<ver>_amd64.deb` → `sudo apt install ./network-analyser_*.deb` |
| Fedora / RHEL / openSUSE | `network-analyser-<ver>-1.x86_64.rpm` → `sudo dnf install ./network-analyser-*.rpm` |
| Other Linux (glibc 2.35+) | `network-analyser-<ver>-linux-x86_64.tar.gz` |
| macOS 11+ (Apple Silicon + Intel) | `network-analyser-<ver>-macos-universal.dmg` |
| Windows 10/11 x64 | `network-analyser-<ver>-windows-x86_64.zip` |

**Linux display servers:** one binary supports both **Wayland** and **X11**. It uses
Wayland when `WAYLAND_DISPLAY` is set and X11 otherwise. `--x11` forces X11 (XWayland
under a Wayland session) and `--wayland` forces native Wayland. A Vulkan driver is
required (Mesa's `mesa-vulkan-drivers` covers Intel/AMD and software rendering).

**macOS:** the app is ad-hoc signed but not notarized. On first launch, right-click → Open
(or `xattr -dr com.apple.quarantine "/Applications/Network Analyser.app"`), then allow
*Local Network* access.

**Windows:** unsigned, so SmartScreen may warn: click *More info → Run anyway*.
`--cli` output appears in the console it was started from.

## Build from source

```sh
# Debian/Ubuntu build dependencies (same list CI uses)
./.github/linux-deps.sh
cargo build --release
```

macOS needs Xcode command-line tools; Windows needs the MSVC toolchain.

## Releasing

CI (`.github/workflows/ci.yml`) runs fmt, clippy and tests on Linux, macOS and Windows
for every push and PR. To publish a release:

```sh
# bump `version` in Cargo.toml first, commit, then:
git tag v0.1.0 && git push origin v0.1.0
```

`.github/workflows/release.yml` fetches the IEEE MAC-vendor list, builds the
`.deb`/`.rpm`/`.tar.gz`, a universal macOS `.dmg` and a Windows `.zip`, and publishes them
with `SHA256SUMS.txt` as a GitHub Release. The tag must match the Cargo.toml version.

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
| Ctrl+Q (⌘Q on macOS) | Quit immediately |
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
- `src/netinfo.rs` – interfaces, OUI vendors, ranges, port names
- `src/platform.rs` – per-OS gateway / ARP / MAC / directories (Linux `/proc`, macOS & Windows `route`/`arp`/`ifconfig`/`ipconfig`)
- `build.rs` – embeds the icon into the Windows `.exe`
- `assets/` – icon (PNG/ICO), `.desktop` file

`libc` is pinned to 0.2.186 (and tokio to 1.52) in `Cargo.lock`. Newer `libc` removed
`ENOATTR`, which breaks `xattr 0.2.3`, a dependency gpui 0.2.2 pulls in. Keep the
lockfile when updating (CI builds with `--locked`).

## License

MIT, see [LICENSE](LICENSE).
