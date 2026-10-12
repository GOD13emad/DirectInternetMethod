#!/usr/bin/env bash
set -euo pipefail
umask 077

APP="$HOME/.local/share/DirectInternetMethod"
HELPER="$APP/user_uninstall_preserve.py"

# Refuse unsafe uninstall while a version-managed user transaction is pending.
[ ! -e "$HOME/.local/state/DirectInternetMethod/update-pending" ] || {
  echo "An interrupted update needs code rollback/acceptance before uninstall." >&2
  exit 87
}
[ -f "$HELPER" ] && [ ! -L "$HELPER" ] || {
  echo "The exact owned-file uninstall manifest helper is missing. User data preserved." >&2
  exit 85
}

# First establish that every program file, icon and launcher selected for removal
# still has the exact SHA recorded by the installed version. Unknowns stay intact.
python3 "$HELPER" --verify

if [ -e /run/directinternetmethod-selective/session.json ]; then
  systemctl start directinternetmethod-recovery.service
  [ ! -e /run/directinternetmethod-selective/session.json ] || {
    echo "Selective DNS remains active. Uninstall cancelled." >&2
    exit 88
  }
fi
if [ -f "$APP/directmethod/state.json" ]; then
  systemctl start directinternetmethod-recovery.service
  [ ! -f "$APP/directmethod/state.json" ] || {
    echo "Recovery could not be verified; uninstall cancelled." >&2
    exit 20
  }
fi

# Delete root-owned backend FIRST. A declined PolicyKit prompt or failed
# protected cleanup must never remove the working user app.
if [ -x /usr/lib/directinternetmethod/uninstall_system.sh ]; then
  pkexec /bin/bash /usr/lib/directinternetmethod/uninstall_system.sh
fi

# Only exact SHA-owned managed executable files are removed. Keep settings,
# strategy, scope, custom hosts, adult coverage, router providers and logs.
python3 "$HELPER" --remove-after-backend

DESKTOP="$HOME/.local/share/applications"
command -v update-desktop-database >/dev/null 2>&1 &&
  update-desktop-database "$DESKTOP" >/dev/null 2>&1 || true
echo "Direct Internet Method uninstalled. User configuration preserved in $APP."
echo "No user data was deleted; reinstall can reuse the same settings."
