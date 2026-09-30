#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || exit 77
for action in start stop recovery; do
  rm -f "/etc/systemd/system/directinternetmethod-$action.service"
done
rm -f /etc/polkit-1/rules.d/49-directinternetmethod.rules /etc/directinternetmethod.uid /etc/directinternetmethod.conf
rm -rf /usr/lib/directinternetmethod /var/lib/directinternetmethod
systemctl daemon-reload
echo '{"ok":true,"systemBackend":"removed"}'
