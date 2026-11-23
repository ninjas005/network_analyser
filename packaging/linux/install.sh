#!/usr/bin/env sh
# Installer for the Network Analyser Linux tarball (any distro).
#
#   ./install.sh              install for the current user (~/.local)
#   sudo ./install.sh         install system-wide (/usr/local)
#   ./install.sh --uninstall  remove (use sudo for a system-wide install)
#
# Debian/Ubuntu and Fedora/openSUSE users can use the .deb / .rpm instead.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" -eq 0 ]; then prefix=${PREFIX:-/usr/local}; else prefix=${PREFIX:-$HOME/.local}; fi

bin="$prefix/bin/network_analyser"
share="$prefix/share/network-analyser"
desktop="$prefix/share/applications/network-analyser.desktop"
icon="$prefix/share/icons/hicolor/512x512/apps/network-analyser.png"

refresh() {
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$prefix/share/applications" || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t "$prefix/share/icons/hicolor" || true
}

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$bin" "$desktop" "$icon"
  rm -rf "$share"
  refresh
  echo "Network Analyser removed from $prefix"
  exit 0
fi

install -Dm755 "$here/bin/network_analyser" "$bin"
install -Dm644 "$here/share/network-analyser/oui.txt" "$share/oui.txt"
install -Dm644 "$here/share/icons/hicolor/512x512/apps/network-analyser.png" "$icon"
# Point the menu entry at the installed binary (works even if ~/.local/bin isn't on PATH).
sed "s|^Exec=network_analyser|Exec=$bin|" "$here/share/applications/network-analyser.desktop" > "$here/.desktop.tmp"
install -Dm644 "$here/.desktop.tmp" "$desktop" && rm -f "$here/.desktop.tmp"
refresh

echo "Installed Network Analyser to $prefix"
echo "  binary: $bin"
echo "  menu:   Network Analyser (normal, kiosk and windowed entries)"
command -v ping >/dev/null 2>&1 || echo "note: install 'iputils-ping' (or your distro's ping) for ICMP results"
echo "packet capture needs libpcap and raw-socket rights:"
echo "  sudo setcap cap_net_raw,cap_net_admin=eip $bin"
echo "serial / Modbus RTU needs access to /dev/tty*: sudo usermod -aG dialout \$USER (then log in again)"
case ":$PATH:" in *":$prefix/bin:"*) ;; *) echo "note: $prefix/bin is not on your PATH" ;; esac
