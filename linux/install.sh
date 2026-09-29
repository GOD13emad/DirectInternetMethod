#!/usr/bin/env bash
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/.local/share/DirectInternetMethod"
BIN="$HOME/.local/bin"
DESKTOP="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"
BACKUP="$HOME/.local/share/DirectInternetMethod-backup-$(date +%Y%m%d_%H%M%S)"
for c in python3 sha256sum pkexec nft busctl ip curl getent; do command -v "$c" >/dev/null 2>&1 || { echo "Missing required command: $c" >&2; exit 3; }; done
python3 - <<'PY'
import gi
gi.require_version("Gtk","4.0");gi.require_version("Adw","1")
from gi.repository import Gtk,Adw
PY
if [ -d "$APP" ]; then cp -a "$APP" "$BACKUP"; fi
mkdir -p "$APP/runtime/usr/bin" "$APP/directmethod" "$BIN" "$DESKTOP" "$ICONS"
chmod 0700 "$APP" "$APP/directmethod"
install -m 0755 "$HERE/app/direct_internet_method.py" "$APP/direct_internet_method.py"
install -m 0755 "$HERE/app/direct_method_helper.sh" "$APP/direct_method_helper.sh"
install -m 0600 "$HERE/app/hosts.txt" "$APP/direct_hosts.txt"
install -m 0644 "$HERE/app/direct-internet-method.svg" "$APP/direct-internet-method.svg"
install -m 0755 "$HERE/runtime/ctrld" "$APP/runtime/usr/bin/ctrld"
install -m 0755 "$HERE/runtime/nfqws" "$APP/runtime/usr/bin/nfqws"
install -m 0755 "$HERE/uninstall.sh" "$APP/uninstall.sh"
echo "ca64579a2bc866cf72f3e46663e551162afeff0d448e899a01817a095e45b071  $APP/runtime/usr/bin/ctrld" | sha256sum -c -
echo "f34615964d7321650197cd69d3f7cbfdaabe8118b5a0d57c6e41dccdff658999  $APP/runtime/usr/bin/nfqws" | sha256sum -c -
cat > "$BIN/direct-internet-method" <<'EOF'
#!/usr/bin/env bash
exec python3 "$HOME/.local/share/DirectInternetMethod/direct_internet_method.py"
EOF
cat > "$BIN/direct-internet-method-uninstall" <<'EOF'
#!/usr/bin/env bash
exec "$HOME/.local/share/DirectInternetMethod/uninstall.sh"
EOF
chmod 0755 "$BIN/direct-internet-method" "$BIN/direct-internet-method-uninstall"
install -m 0644 "$HERE/app/direct-internet-method.svg" "$ICONS/direct-internet-method.svg"
cat > "$DESKTOP/direct-internet-method.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Direct Internet Method
Comment=Direct DNS + DPI bypass without VPN or proxy
Exec=$BIN/direct-internet-method
Icon=direct-internet-method
Terminal=false
Categories=Network;Utility;
StartupNotify=true
StartupWMClass=io.github.god13emad.DirectInternetMethod
EOF
chmod 0644 "$DESKTOP/direct-internet-method.desktop"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
if [ -n "$DESKTOP_DIR" ] && [ -d "$DESKTOP_DIR" ]; then
  cp "$DESKTOP/direct-internet-method.desktop" "$DESKTOP_DIR/Direct Internet Method.desktop"
  chmod 0755 "$DESKTOP_DIR/Direct Internet Method.desktop"
  command -v gio >/dev/null 2>&1 && gio set "$DESKTOP_DIR/Direct Internet Method.desktop" metadata::trusted true >/dev/null 2>&1 || true
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DESKTOP" >/dev/null 2>&1 || true
command -v gtk4-update-icon-cache >/dev/null 2>&1 && gtk4-update-icon-cache -f "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
python3 - "$APP/INSTALL.json" <<'PY'
import json,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(json.dumps({"schema":1,"product":"Direct Internet Method","version":"1.0.0","platform":"linux-x86_64","installedUtc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"networkMutationOnInstall":False},indent=2)+"\n")
PY
echo "Installed Direct Internet Method 1.0.0."
echo "No network method was started."
