#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || exit 77
if [ -e /run/directinternetmethod-selective/session.json ]; then
  [ -x /usr/lib/directinternetmethod/selective_dns.py ] || exit 88
  /usr/bin/python3 /usr/lib/directinternetmethod/selective_dns.py restore || exit 88
  [ ! -e /run/directinternetmethod-selective/session.json ] || exit 88
fi
# Fail closed on encrypted-DNS ownership ambiguity before uninstalling binaries.
if [ -e /run/directinternetmethod-encrypted/session.json ]; then
  [ -x /usr/lib/directinternetmethod/encrypted_selective_dns.py ] || exit 88
  /usr/bin/python3 /usr/lib/directinternetmethod/encrypted_selective_dns.py restore || exit 88
fi
for owned in /run/directinternetmethod-encrypted /run/directinternetmethod-encrypted-ctrld.toml /sys/class/net/dimesd0; do
  [ ! -e "$owned" ] && [ ! -L "$owned" ] || {
    echo "Encrypted DNS resource remains; do not remove protected backend." >&2
    exit 88
  }
done
for action in start stop recovery; do
  rm -f "/etc/systemd/system/directinternetmethod-$action.service"
done
rm -f /etc/polkit-1/rules.d/49-directinternetmethod.rules /etc/directinternetmethod.uid /etc/directinternetmethod.conf
rm -rf /usr/lib/directinternetmethod /var/lib/directinternetmethod
systemctl daemon-reload
echo '{"ok":true,"systemBackend":"removed"}'
