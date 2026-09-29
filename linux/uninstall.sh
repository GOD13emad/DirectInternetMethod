#!/usr/bin/env bash
set -euo pipefail
APP="$HOME/.local/share/DirectInternetMethod"
BIN="$HOME/.local/bin"
DESKTOP="$HOME/.local/share/applications/direct-internet-method.desktop"
ICON="$HOME/.local/share/icons/hicolor/scalable/apps/direct-internet-method.svg"
if [ -f "$APP/directmethod/state.json" ]; then
  pkexec /bin/bash "$APP/direct_method_helper.sh" stop "$APP" "$(id -u)" "$(id -g)"
  [ ! -f "$APP/directmethod/state.json" ] || { echo "Recovery could not be verified; uninstall stopped." >&2; exit 20; }
fi
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
rm -f "$BIN/direct-internet-method" "$BIN/direct-internet-method-uninstall" "$DESKTOP" "$ICON"
if [ -n "$DESKTOP_DIR" ]; then rm -f "$DESKTOP_DIR/Direct Internet Method.desktop"; fi
rm -rf "$APP"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
echo "Direct Internet Method removed."
