#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-}"
REQ_UID="${2:-}"
[ "$(id -u)" -eq 0 ] || { echo "root required" >&2; exit 77; }
[ -d "$SRC" ] || exit 64
case "$REQ_UID" in ''|*[!0-9]*) exit 64;; esac
PASSWD="$(getent passwd "$REQ_UID" || true)"
[ -n "$PASSWD" ] || { echo "uid not found" >&2; exit 65; }
IFS=: read -r USER_NAME _ USER_UID USER_GID _ HOME_DIR _ <<<"$PASSWD"
[ "$USER_UID" = "$REQ_UID" ] || exit 65
[[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || { echo "unsafe username" >&2; exit 65; }
[ -d "$HOME_DIR" ] || { echo "home missing" >&2; exit 65; }
[[ "$HOME_DIR" =~ ^/[A-Za-z0-9._@/+:-]+$ ]] || { echo "unsafe home path" >&2; exit 65; }

ROOT=/usr/lib/directinternetmethod
install -d -m 0755 "$ROOT" "$ROOT/runtime" "$ROOT/runtime/usr" "$ROOT/runtime/usr/bin" "$ROOT/licenses"
install -m 0755 "$SRC/app/direct_method_helper.sh" "$ROOT/direct_method_helper.sh"
install -m 0755 "$SRC/system/control.sh" "$ROOT/control.sh"
install -m 0755 "$SRC/system/uninstall_system.sh" "$ROOT/uninstall_system.sh"
install -m 0644 "$SRC/app/hosts.txt" "$ROOT/direct_hosts.txt"
install -m 0644 "$SRC/app/adult_hosts_fallback.txt" "$ROOT/adult_hosts_fallback.txt"
install -m 0644 "$SRC/app/strong_override_hosts.txt" "$ROOT/strong_override_hosts.txt"
install -m 0755 "$SRC/runtime/ctrld" "$ROOT/runtime/usr/bin/ctrld"
install -m 0755 "$SRC/runtime/nfqws" "$ROOT/runtime/usr/bin/nfqws"
install -m 0644 "$SRC/licenses/LICENSE-ctrld.txt" "$ROOT/licenses/LICENSE-ctrld.txt"
install -m 0644 "$SRC/licenses/LICENSE-zapret.txt" "$ROOT/licenses/LICENSE-zapret.txt"

printf '%s\n' "$USER_UID" > /etc/directinternetmethod.uid
chmod 0644 /etc/directinternetmethod.uid
chown root:root /etc/directinternetmethod.uid

for action in start stop recovery; do
  cat > "/etc/systemd/system/directinternetmethod-$action.service" <<EOF
[Unit]
Description=Direct Internet Method $action action
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$ROOT/control.sh $action
TimeoutStartSec=120
User=root
Group=root
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
UMask=0077
ReadWritePaths=$HOME_DIR/.local/share/DirectInternetMethod /run
EOF
  chmod 0644 "/etc/systemd/system/directinternetmethod-$action.service"
done

cat > /etc/polkit-1/rules.d/49-directinternetmethod.rules <<EOF
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.local && subject.active && subject.user == "$USER_NAME") {
        var unit = action.lookup("unit");
        var verb = action.lookup("verb");
        var allowed = [
            "directinternetmethod-start.service",
            "directinternetmethod-stop.service",
            "directinternetmethod-recovery.service"
        ];
        if (verb == "start" && allowed.indexOf(unit) >= 0) {
            return polkit.Result.YES;
        }
    }
    return polkit.Result.NOT_HANDLED;
});
EOF
chmod 0644 /etc/polkit-1/rules.d/49-directinternetmethod.rules
chown root:root /etc/polkit-1/rules.d/49-directinternetmethod.rules

systemctl daemon-reload
test -x "$ROOT/control.sh"
test -x "$ROOT/direct_method_helper.sh"
for action in start stop recovery; do test -f "/etc/systemd/system/directinternetmethod-$action.service"; done
test -f /etc/polkit-1/rules.d/49-directinternetmethod.rules
test "$(cat /etc/directinternetmethod.uid)" = "$USER_UID"
install -d -m 0755 /var/lib/directinternetmethod
cat > /var/lib/directinternetmethod/install.json <<EOF
{"schema":1,"version":"1.5.2","user":"$USER_NAME","uid":$USER_UID,"home":"$HOME_DIR"}
EOF
chmod 0644 /var/lib/directinternetmethod/install.json
echo '{"ok":true,"systemBackend":"installed","version":"1.5.2"}'
