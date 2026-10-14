#!/usr/bin/env bash
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/.local/share/DirectInternetMethod"
BIN="$HOME/.local/bin"
DESKTOP="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"
USER_TRANSACTION="$HERE/app/user_update_transaction.py"
TRANSACTION_ACTIVE=0
ROOT_UPGRADE_STAGED=0
ROOT_TRANSACTION="$HERE/system/protected_upgrade_transaction.py"
rollback_failed_install() {
  local code="$1"
  trap - ERR HUP INT TERM
  if [ "$TRANSACTION_ACTIVE" -eq 1 ]; then
    if ! python3 "$USER_TRANSACTION" --rollback; then
      echo "DEGRADED: code rollback requires review; user settings have not been deleted." >&2
      echo "Inspect $HOME/.local/state/DirectInternetMethod/update-pending" >&2
    fi
  fi
  if [ "$ROOT_UPGRADE_STAGED" -eq 1 ] && [ -f /var/lib/directinternetmethod/upgrade-pending/manifest.json ]; then
    if ! pkexec /usr/bin/python3 "$ROOT_TRANSACTION" rollback; then
      echo 'DEGRADED: protected backend rollback failed; preserve exact root slot for review.' >&2
    fi
  fi
  exit "$code"
}

for c in python3 sha256sum pkexec systemctl nft busctl ip curl getent; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing required command: $c" >&2; exit 3; }
done
python3 - <<'PY'
import gi
gi.require_version("Gtk","4.0")
gi.require_version("Adw","1")
PY

if [ -e /run/directinternetmethod-selective/session.json ]; then
  echo "Protected selected-sites DNS is active. Stop/Recovery before updating." >&2
  exit 21
fi
if [ -f "$APP/directmethod/state.json" ]; then
  echo "Direct Internet Method is active or has owned state. Stop/Recovery it before installing or upgrading." >&2
  exit 21
fi
[ -f "$USER_TRANSACTION" ] || { echo "Transaction helper missing." >&2; exit 23; }
# Fixed launchers are user-visible files; never overwrite unknown custom ones.
# A symlink or nonregular node is an ownership conflict, not a cleanup target.
for entry in "$BIN/direct-internet-method" \
             "$BIN/direct-internet-method-uninstall" \
             "$DESKTOP/io.github.god13emad.DirectInternetMethod.desktop" \
             "$ICONS/direct-internet-method.svg"; do
  if [ -L "$entry" ] || { [ -e "$entry" ] && [ ! -f "$entry" ]; }; then
    echo "Existing launcher or icon has unsafe type; preserve and refuse update: $entry" >&2
    exit 24
  fi
done
# Snapshot ONLY managed code; unknown user configuration never enters this backup.
python3 "$USER_TRANSACTION" --source "$HERE" --stage
TRANSACTION_ACTIVE=1
trap 'rollback_failed_install "$?"' ERR
trap 'rollback_failed_install 130' INT
trap 'rollback_failed_install 143' TERM
trap 'rollback_failed_install 129' HUP

backend_matches_current() {
  local uid
  uid="$(id -u)"
  [ -r /var/lib/directinternetmethod/install.json ] || return 1
  python3 - /var/lib/directinternetmethod/install.json "$uid" <<'PY' >/dev/null 2>&1 || return 1
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
raise SystemExit(0 if d.get("version")=="1.5.5-rc1" and str(d.get("uid"))==sys.argv[2] else 1)
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
$HERE/system/selective_dns.py|/usr/lib/directinternetmethod/selective_dns.py
$HERE/system/encrypted_selective_dns.py|/usr/lib/directinternetmethod/encrypted_selective_dns.py
$HERE/system/encrypted_selective_policy.py|/usr/lib/directinternetmethod/encrypted_selective_policy.py
$HERE/system/control.sh|/usr/lib/directinternetmethod/control.sh
$HERE/system/uninstall_system.sh|/usr/lib/directinternetmethod/uninstall_system.sh
$HERE/app/hosts.txt|/usr/lib/directinternetmethod/direct_hosts.txt
$HERE/app/adult_hosts_fallback.txt|/usr/lib/directinternetmethod/adult_hosts_fallback.txt
$HERE/app/strong_override_hosts.txt|/usr/lib/directinternetmethod/strong_override_hosts.txt
$HERE/runtime/ctrld|/usr/lib/directinternetmethod/runtime/usr/bin/ctrld
$HERE/runtime/nfqws|/usr/lib/directinternetmethod/runtime/usr/bin/nfqws
$HERE/licenses/LICENSE-ctrld.txt|/usr/lib/directinternetmethod/licenses/LICENSE-ctrld.txt
$HERE/licenses/LICENSE-zapret.txt|/usr/lib/directinternetmethod/licenses/LICENSE-zapret.txt
EOF
}

# Administrative authorization is required only when the protected backend is absent or differs.
if backend_matches_current; then
  echo "Protected backend already matches current package; keeping root-owned code unchanged."
else
  if [ -f /var/lib/directinternetmethod/install.json ] &&
     [ -d /usr/lib/directinternetmethod ]; then
    ROOT_UPGRADE_STAGED=1
    pkexec /bin/bash "$HERE/system/upgrade_system.sh" "$HERE" "$(id -u)"
  elif [ ! -e /var/lib/directinternetmethod/install.json ] &&
       [ ! -e /usr/lib/directinternetmethod ]; then
    pkexec /bin/bash "$HERE/system/install_system.sh" "$HERE" "$(id -u)"
  else
    echo 'Foreign/partial root backend; no mutation authorized.' >&2
    rollback_failed_install 25
  fi
fi
backend_matches_current || { echo "Protected backend verification failed." >&2; rollback_failed_install 22; }
# Atomically replace version-managed code in the ONE installed app directory.
# The transaction preserves and verifies settings, custom hosts, scope, strategy,
# adult coverage and user-modified Router Gateway provider data.
python3 "$USER_TRANSACTION" --source "$HERE" --apply
mkdir -p "$APP/directmethod" "$APP/router_gateway" "$BIN" "$DESKTOP" "$ICONS"
chmod 0700 "$APP" "$APP/directmethod"

if [ ! -e "$BIN/direct-internet-method" ]; then
  cat > "$BIN/direct-internet-method" <<'EOF'
#!/usr/bin/env bash
export G_APPLICATION_NAME="Direct Internet Method"
exec -a DirectInternetMethod python3 "$HOME/.local/share/DirectInternetMethod/direct_internet_method.py"
EOF
  chmod 0755 "$BIN/direct-internet-method"
fi
if [ ! -e "$BIN/direct-internet-method-uninstall" ]; then
  cat > "$BIN/direct-internet-method-uninstall" <<'EOF'
#!/usr/bin/env bash
exec "$HOME/.local/share/DirectInternetMethod/uninstall.sh"
EOF
  chmod 0755 "$BIN/direct-internet-method-uninstall"
fi
if [ ! -e "$ICONS/direct-internet-method.svg" ]; then
  install -m 0644 "$HERE/app/direct-internet-method.svg" "$ICONS/direct-internet-method.svg"
fi
DESKTOP_FILE="$DESKTOP/io.github.god13emad.DirectInternetMethod.desktop"
# Never delete or overwrite the old/renamed desktop shortcut without ownership proof.
if [ ! -e "$DESKTOP_FILE" ]; then
  cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Direct Internet Method
Comment=Encrypted DNS + HTTP/TLS/QUIC DPI bypass without VPN or proxy
Exec=$BIN/direct-internet-method
Icon=direct-internet-method
Terminal=false
Categories=Network;Utility;
StartupNotify=true
StartupWMClass=DirectInternetMethod
EOF
  chmod 0644 "$DESKTOP_FILE"
fi

DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
if [ -n "$DESKTOP_DIR" ] && [ -d "$DESKTOP_DIR" ]; then
  if [ -L "$DESKTOP_DIR/Direct Internet Method.desktop" ]; then
    echo "Desktop shortcut is a symlink; refusing to overwrite it." >&2
    rollback_failed_install 24
  fi
  if [ ! -e "$DESKTOP_DIR/Direct Internet Method.desktop" ]; then
    cp "$DESKTOP_FILE" "$DESKTOP_DIR/Direct Internet Method.desktop"
    chmod 0755 "$DESKTOP_DIR/Direct Internet Method.desktop"
    command -v gio >/dev/null 2>&1 && gio set "$DESKTOP_DIR/Direct Internet Method.desktop" metadata::trusted true >/dev/null 2>&1 || true
  fi
fi

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DESKTOP" >/dev/null 2>&1 || true
command -v gtk4-update-icon-cache >/dev/null 2>&1 && gtk4-update-icon-cache -f "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

python3 - "$APP/INSTALL.json" "$USER_TRANSACTION" <<'PY'
import json,pathlib,sys,time,hashlib,importlib.util
home=pathlib.Path.home()
# Only exact program-generated launchers are owned by the uninstaller.
# A user-modified launcher/shortcut is preserved and never claimed as owned.
expected_launchers={
    ".local/bin/direct-internet-method": (
        '#!/usr/bin/env bash\n'
        'export G_APPLICATION_NAME="Direct Internet Method"\n'
        'exec -a DirectInternetMethod python3 "$HOME/.local/share/DirectInternetMethod/direct_internet_method.py"\n'
    ).encode(),
    ".local/bin/direct-internet-method-uninstall": (
        '#!/usr/bin/env bash\n'
        'exec "$HOME/.local/share/DirectInternetMethod/uninstall.sh"\n'
    ).encode(),
    ".local/share/applications/io.github.god13emad.DirectInternetMethod.desktop": (
        '[Desktop Entry]\n'
        'Type=Application\n'
        'Name=Direct Internet Method\n'
        'Comment=Encrypted DNS + HTTP/TLS/QUIC DPI bypass without VPN or proxy\n'
        f'Exec={home}/.local/bin/direct-internet-method\n'
        'Icon=direct-internet-method\n'
        'Terminal=false\n'
        'Categories=Network;Utility;\n'
        'StartupNotify=true\n'
        'StartupWMClass=DirectInternetMethod\n'
    ).encode(),
    ".local/share/icons/hicolor/scalable/apps/direct-internet-method.svg":
        (home/".local/share/DirectInternetMethod/direct-internet-method.svg").read_bytes(),
}
launchers={}
for name, expected in expected_launchers.items():
    p=home/name
    if p.is_file() and not p.is_symlink() and p.read_bytes()==expected:
        launchers[name]=hashlib.sha256(expected).hexdigest()
transaction=json.loads((pathlib.Path.home()/".local/state/DirectInternetMethod/update-pending/manifest.json").read_text(encoding="utf8"))
protected=json.loads(pathlib.Path("/var/lib/directinternetmethod/install.json").read_text(encoding="utf-8"))
assert protected.get("version") == "1.5.5-rc1"
metadata=json.dumps({
  "schema":2,
  "product":"Direct Internet Method",
  "version":"1.5.5-rc1",
  "platform":"linux-x86_64",
  "installedUtc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
  "networkMutationOnInstall":False,
  "normalRunRequiresAdmin":False,
  "systemBackend":"/usr/lib/directinternetmethod",
  "protectedBackendVersion":protected["version"],
  "protectedBackendByteCompatible":True,
  "onlineUpdate":"GitHub latest release + SHA256SUMS verification",
  "managedProviderSha256":transaction["providerSha"],
  "preservedCustomProviderData":not transaction["providerManaged"],
  "managedCodeSha256":{k:v["sha"] for k,v in transaction["managed"].items() if k!="router_gateway/providers.json"},
  "managedLaunchersSha256":launchers,
  "updateMode":"IN_PLACE_SINGLE_INSTALL_DATA_PRESERVED"
},indent=2)+"\n"
# Reuse the already-tested, fail-closed transaction writer instead of
# truncating INSTALL.json in place. A killed process preserves the old bytes;
# any orphaned stage is deliberately retained for ownership-checked recovery.
spec=importlib.util.spec_from_file_location("dim_user_update_transaction",sys.argv[2])
if spec is None or spec.loader is None:
    raise RuntimeError("TRANSACTION_HELPER_NOT_IMPORTABLE")
transaction_helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(transaction_helper)
transaction_helper.atomic_bytes(pathlib.Path(sys.argv[1]),metadata.encode("utf-8"),0o600)
PY

# Unreleased candidate: protected Root must complete REAL native acceptance.
# Retain one bounded user/root rollback slot, not a permanent duplicate install.
if [ "$ROOT_UPGRADE_STAGED" -eq 1 ]; then
  python3 "$USER_TRANSACTION" --status
  TRANSACTION_ACTIVE=0
  trap - ERR HUP INT TERM
  echo 'R519_CANDIDATE_PENDING_NATIVE_ROOT_USER_COMMIT: in-place files updated; not Released.'
else
  python3 "$USER_TRANSACTION" --commit
  TRANSACTION_ACTIVE=0
  trap - ERR HUP INT TERM
  echo 'R519_CANDIDATE_FRESH_USER_CODE_COMMITTED: native release acceptance OPEN.'
fi
echo "Normal Start / Stop / Recovery do not require an admin password."
echo "Install/update/uninstall of the protected backend may authenticate once."
