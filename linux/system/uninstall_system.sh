#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || exit 77
if [ -e /run/directinternetmethod-selective/session.json ]; then
  [ -x /usr/lib/directinternetmethod/selective_dns.py ] || exit 88
  /usr/bin/python3 /usr/lib/directinternetmethod/selective_dns.py restore || exit 88
  [ ! -e /run/directinternetmethod-selective/session.json ] || exit 88
fi
for action in start stop recovery; do
  rm -f "/etc/systemd/system/directinternetmethod-$action.service"
done
rm -f /etc/polkit-1/rules.d/49-directinternetmethod.rules /etc/directinternetmethod.uid /etc/directinternetmethod.conf
rm -rf /usr/lib/directinternetmethod /var/lib/directinternetmethod
systemctl daemon-reload
echo '{"ok":true,"systemBackend":"removed"}'
