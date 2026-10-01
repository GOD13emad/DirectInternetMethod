#!/usr/bin/env bash
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/.local/share/DirectInternetMethod"
BIN="$HOME/.local/bin"
DESKTOP="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"
BACKUP="$HOME/.local/share/DirectInternetMethod-backup-$(date +%Y%m%d_%H%M%S)"

for c in python3 sha256sum pkexec systemctl nft busctl ip curl getent; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing required command: $c" >&2; exit 3; }
done
python3 - <<'PY'
import gi
gi.require_version("Gtk","4.0")
gi.require_version("Adw","1")
PY

if [ -f "$APP/directmethod/state.json" ]; then
  echo "Direct Internet Method is active or has owned state. Stop/Recovery it before installing or upgrading." >&2
  exit 21
fi

backend_matches_current() {
  local uid
  uid="$(id -u)"
  [ -r /var/lib/directinternetmethod/install.json ] || return 1
  python3 - /var/lib/directinternetmethod/install.json "$uid" <<'PY' >/dev/null 2>&1 || return 1
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
raise SystemExit(0 if d.get("version")=="1.2.1" and str(d.get("uid"))==sys.argv[2] else 1)
PY
  [ "$(cat /etc/directinternetmethod.uid 2>/dev/null || true)" = "$uid" ] || return 1
  for action in start stop recovery; do
    [ -f "/etc/systemd/system/directinternetmethod-$action.service" ] || return 1
  done
  while IFS='|' read -r src dst; do
    [ -f "$src" ] && [ -f "$dst" ] || return 1
    [ "$(sha256sum "$src" | awk '{print $1}')" = "$(sha256sum "$dst" | awk '{print $1}')" ] || return 1
  done <<EOF
$HERE/app/direct_method_helper.sh|/usr/lib/directinternetmethod/direct_method_helper.sh
$HERE/system/control.sh|/usr/lib/directinternetmethod/control.sh
$HERE/system/uninstall_system.sh|/usr/lib/directinternetmethod/uninstall_system.sh
$HERE/app/hosts.txt|/usr/lib/directinternetmethod/direct_hosts.txt
$HERE/runtime/ctrld|/usr/lib/directinternetmethod/runtime/usr/bin/ctrld
$HERE/runtime/nfqws|/usr/lib/directinternetmethod/runtime/usr/bin/nfqws
$HERE/licenses/LICENSE-ctrld.txt|/usr/lib/directinternetmethod/licenses/LICENSE-ctrld.txt
$HERE/licenses/LICENSE-zapret.txt|/usr/lib/directinternetmethod/licenses/LICENSE-zapret.txt
EOF
}

# Administrative authorization is required only when the protected backend is absent or differs.
if backend_matches_current; then
  echo "Protected backend 1.2.1 already matches current package; skipping admin authorization."
else
  pkexec /bin/bash "$HERE/system/install_system.sh" "$HERE" "$(id -u)"
fi
backend_matches_current || { echo "Protected backend verification failed." >&2; exit 22; }
if [ -d "$APP" ]; then
  mkdir -p "$BACKUP"
  for f in direct_internet_method.py router_gateway.py direct-internet-method.svg uninstall.sh INSTALL.json; do
    [ -f "$APP/$f" ] && cp -a "$APP/$f" "$BACKUP/$f"
  done
fi
mkdir -p "$APP/directmethod" "$APP/router_gateway" "$BIN" "$DESKTOP" "$ICONS"
chmod 0700 "$APP" "$APP/directmethod"
install -m 0755 "$HERE/app/direct_internet_method.py" "$APP/direct_internet_method.py"
install -m 0755 "$HERE/app/router_gateway.py" "$APP/router_gateway.py"
ROUTER_DATA="$HERE/app/router_gateway/providers.json"
[ -f "$ROUTER_DATA" ] || ROUTER_DATA="$HERE/../router_gateway/providers.json"
[ -f "$ROUTER_DATA" ] || { echo "Missing Router Gateway provider data." >&2; exit 23; }
install -m 0644 "$ROUTER_DATA" "$APP/router_gateway/providers.json"
install -m 0644 "$HERE/app/direct-internet-method.svg" "$APP/direct-internet-method.svg"
install -m 0755 "$HERE/uninstall.sh" "$APP/uninstall.sh"

cat > "$BIN/direct-internet-method" <<'EOF'
#!/usr/bin/env bash
export G_APPLICATION_NAME="Direct Internet Method"
exec -a DirectInternetMethod python3 "$HOME/.local/share/DirectInternetMethod/direct_internet_method.py"
EOF
cat > "$BIN/direct-internet-method-uninstall" <<'EOF'
#!/usr/bin/env bash
exec "$HOME/.local/share/DirectInternetMethod/uninstall.sh"
EOF
chmod 0755 "$BIN/direct-internet-method" "$BIN/direct-internet-method-uninstall"

install -m 0644 "$HERE/app/direct-internet-method.svg" "$ICONS/direct-internet-method.svg"
DESKTOP_FILE="$DESKTOP/io.github.god13emad.DirectInternetMethod.desktop"
rm -f "$DESKTOP/direct-internet-method.desktop"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Direct Internet Method
Comment=Direct DNS + DPI bypass without VPN or proxy
Exec=$BIN/direct-internet-method
Icon=direct-internet-method
Terminal=false
Categories=Network;Utility;
StartupNotify=true
StartupWMClass=DirectInternetMethod
EOF
chmod 0644 "$DESKTOP_FILE"

DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
if [ -n "$DESKTOP_DIR" ] && [ -d "$DESKTOP_DIR" ]; then
  cp "$DESKTOP_FILE" "$DESKTOP_DIR/Direct Internet Method.desktop"
  chmod 0755 "$DESKTOP_DIR/Direct Internet Method.desktop"
  command -v gio >/dev/null 2>&1 && gio set "$DESKTOP_DIR/Direct Internet Method.desktop" metadata::trusted true >/dev/null 2>&1 || true
fi

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DESKTOP" >/dev/null 2>&1 || true
command -v gtk4-update-icon-cache >/dev/null 2>&1 && gtk4-update-icon-cache -f "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

python3 - "$APP/INSTALL.json" <<'PY'
import json,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(json.dumps({
  "schema":2,
  "product":"Direct Internet Method",
  "version":"1.3.1",
  "platform":"linux-x86_64",
  "installedUtc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
  "networkMutationOnInstall":False,
  "normalRunRequiresAdmin":False,
  "systemBackend":"/usr/lib/directinternetmethod",
  "onlineUpdate":"GitHub latest release + SHA256SUMS verification"
},indent=2)+"\n")
PY

echo "Installed Direct Internet Method 1.3.1."
echo "Normal Start / Stop / Recovery do not require an admin password."
echo "Install/update/uninstall of the protected backend may authenticate once."
