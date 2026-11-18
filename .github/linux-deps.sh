#!/usr/bin/env bash
# Build dependencies for gpui on Debian/Ubuntu (X11 + Wayland backends).
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  pkg-config clang \
  libxkbcommon-dev libxkbcommon-x11-dev \
  libxcb1-dev libx11-xcb-dev libx11-dev \
  libwayland-dev wayland-protocols \
  libvulkan-dev \
  libfontconfig-dev libfreetype-dev \
  libzstd-dev libssl-dev
