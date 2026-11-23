## Downloads

| Platform | File | Install |
|---|---|---|
| Debian / Ubuntu / Mint / Pop!_OS | `network-analyser_*_amd64.deb` | `sudo apt install ./network-analyser_*_amd64.deb` |
| Fedora / RHEL / openSUSE | `network-analyser-*.x86_64.rpm` | `sudo dnf install ./network-analyser-*.rpm` (or `zypper install`) |
| Any Linux (glibc 2.35+) | `network-analyser-*-linux-x86_64.tar.gz` | extract, then `./install.sh` (per-user) or `sudo ./install.sh` (system-wide). `--uninstall` removes it |
| macOS 11+ (Apple Silicon & Intel) | `network-analyser-*-macos-universal.dmg` | drag to Applications — see note below |
| **Windows 10/11 x64 (installer)** | `network-analyser-*-windows-x86_64-setup.exe` | run it. Adds Start-menu shortcuts (normal, kiosk, windowed), an optional desktop icon, and an uninstaller in *Apps & features* |
| Windows 10/11 x64 (portable) | `network-analyser-*-windows-x86_64.zip` | extract, run `network_analyser.exe` |

`SHA256SUMS.txt` has checksums for every file.

**Linux:** one binary supports both **Wayland and X11**. It uses Wayland when `WAYLAND_DISPLAY` is set and X11 otherwise. Force a backend with `--x11` or `--wayland`. A Vulkan driver is required (`mesa-vulkan-drivers` on Debian/Ubuntu, `mesa-vulkan-drivers` on Fedora).

**macOS:** the app is not notarized. On first launch, right-click → **Open**, or run
`xattr -dr com.apple.quarantine "/Applications/Network Analyser.app"`. Allow **Local Network** access when prompted.

**Windows:** the installer and exe are unsigned, so SmartScreen may warn. Click **More info → Run anyway**. Users without admin rights can choose *Install for me only*.

**Packet capture** needs raw-socket rights. Linux: `sudo setcap cap_net_raw,cap_net_admin=eip $(command -v network_analyser)`. macOS: access to `/dev/bpf*` (Wireshark's ChmodBPF) or `sudo`. Windows: install [Npcap](https://npcap.com/#download); everything else works without it. Serial ports on Linux need the `dialout` group.

## Usage

```
network_analyser                # fullscreen (F11 toggles)
network_analyser --kiosk        # locked fullscreen, no window decorations
network_analyser --windowed     # normal window
network_analyser --scan         # start scanning the local subnet on launch
network_analyser --cli [RANGE]  # headless scan to stdout
network_analyser --tool dns     # open a tool directly
network_analyser --portscan example.com top   # headless port scan
```

Tools are grouped in the sidebar: **Network Discovery** (LAN Scan, Gateway Discovery, Traceroute, DNS Lookup, Reverse DNS, DHCP Analyser, Wake-on-LAN), **Ports & Services** (Port Scan), **Packet Analysis** (Packet Capture), **Industrial Protocols** (Modbus RTU/TCP), **Serial Communication** (Serial Monitor) and **Network Utilities** (Network Configuration, Public IP, IP Geolocation, Base64). Alt+↑/↓ moves between tools. The app checks for updates on start and can update itself.

Quit: **✕ Quit** button, **Esc** (confirm with Enter), or **Ctrl+Q** (**⌘Q** on macOS).
