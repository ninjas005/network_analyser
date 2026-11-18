## Downloads

| Platform | File | Install |
|---|---|---|
| Debian / Ubuntu / Mint / Pop!_OS | `network-analyser_*_amd64.deb` | `sudo apt install ./network-analyser_*_amd64.deb` |
| Fedora / RHEL / openSUSE | `network-analyser-*.x86_64.rpm` | `sudo dnf install ./network-analyser-*.rpm` (or `zypper install`) |
| Any Linux (glibc 2.35+) | `network-analyser-*-linux-x86_64.tar.gz` | extract, run `bin/network_analyser` |
| macOS 11+ (Apple Silicon & Intel) | `network-analyser-*-macos-universal.dmg` | drag to Applications — see note below |
| Windows 10/11 x64 | `network-analyser-*-windows-x86_64.zip` | extract, run `network_analyser.exe` |

`SHA256SUMS.txt` has checksums for every file.

**Linux:** one binary supports both **Wayland and X11**. It uses Wayland when `WAYLAND_DISPLAY` is set and X11 otherwise. Force a backend with `--x11` or `--wayland`. A Vulkan driver is required (`mesa-vulkan-drivers` on Debian/Ubuntu, `mesa-vulkan-drivers` on Fedora).

**macOS:** the app is not notarized. On first launch, right-click → **Open**, or run
`xattr -dr com.apple.quarantine "/Applications/Network Analyser.app"`. Allow **Local Network** access when prompted.

**Windows:** SmartScreen may warn about an unsigned app. Click **More info → Run anyway**.

## Usage

```
network_analyser                # fullscreen (F11 toggles)
network_analyser --kiosk        # locked fullscreen, no window decorations
network_analyser --windowed     # normal window
network_analyser --scan         # start scanning the local subnet on launch
network_analyser --cli [RANGE]  # headless scan to stdout
```

Quit: **✕ Quit** button, **Esc** (confirm with Enter), or **Ctrl+Q** (**⌘Q** on macOS).
