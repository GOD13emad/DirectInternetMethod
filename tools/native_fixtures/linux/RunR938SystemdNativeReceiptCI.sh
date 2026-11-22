#!/usr/bin/env bash
# R938 root-owned ephemeral systemd + native AF_UNIX fixture, not a product install.
# Execute ONLY on an ephemeral trusted GitHub feature-PUSH runner. No PR sudo.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${GITHUB_EVENT_NAME:-}" != push ||
      "${GITHUB_REF:-}" != refs/heads/feature/universal-install-engine ||
      "${CI:-}" != true || -z "${RUNNER_TEMP:-}" ]]; then
  echo R938_EPHEMERAL_TRUSTED_FEATURE_PUSH_ONLY >&2
  exit 83
fi
command -v sudo >/dev/null
sudo -n true
R940_POLKIT_NATIVE="${R940_POLKIT_NATIVE:-0}"
[[ "$R940_POLKIT_NATIVE" == 0 || "$R940_POLKIT_NATIVE" == 1 ]] || { echo R940_INVALID_MODE; exit 82; }
ACTION='org.god13emad.directinternetmethod.r940fixture'
POLICY='/usr/share/polkit-1/actions/org.god13emad.directinternetmethod.r940fixture.policy'
RULE='/etc/polkit-1/rules.d/49-dim-r940-isolated-scope.rules'
[[ $(id -u) -ne 0 ]] || { echo R938_CLIENT_MUST_BE_NONROOT; exit 84; }
ROOT='/run/dim-r938-synthetic-systemd-broker'
UNIT='dim-r938-synthetic-broker.service'
SCRIPT='tools/native_fixtures/linux/RunR938SystemdReceiptFixture.py'
[[ -f "$SCRIPT" && ! -e "$ROOT" && ! -L "$ROOT" ]] || {
  echo R938_SOURCE_OR_ROOT_PRECONDITION_FAILED
  exit 85
}
tmp=$(mktemp -d "$RUNNER_TEMP/dim-r938-systemd-XXXXXXXX")
input="$tmp/input"
output="$tmp/output"
mkdir -m 0700 "$output"
created=0
policy_installed=0
rule_installed=0
cleanup() {
  if [[ "$rule_installed" == 1 ]]; then
    sudo -n rm -f -- "$RULE" || true
  fi
  if [[ "$policy_installed" == 1 ]]; then
    sudo -n rm -f -- "$POLICY" || true
  fi
  if [[ "$created" == 1 ]]; then
    sudo -n systemctl stop "$UNIT" >/dev/null 2>&1 || true
    sudo -n systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
    for file in "$ROOT/public/broker.sock" \
                "$ROOT/public/R938Client.py" \
                "$ROOT/public/foreign/broker-request.json" \
                "$ROOT/state/broker-replay.json" \
                "$ROOT/state/native-completed-receipt.json" \
                "$ROOT/RunR938SystemdReceiptFixture.py" \
                "$ROOT/installer_engine/__init__.py" \
                "$ROOT/installer_engine/engine.py" \
                "$ROOT/installer_engine/linux_peer_credential.py" \
                "$ROOT/installer_engine/linux_polkit_authorization.py" \
                "$ROOT/inputs/broker-request.json" \
                "$ROOT/inputs/broker-policy.json" \
                "$ROOT/inputs/native-intent.json" \
                "$ROOT/inputs/contract.json"; do
      sudo -n rm -f -- "$file" || true
    done
    if [[ "$R940_POLKIT_NATIVE" == 1 ]]; then
      sudo -n rmdir -- "$ROOT/installer_engine" || true
    fi
    sudo -n rmdir -- "$ROOT/public/foreign" "$ROOT/public" "$ROOT/state" "$ROOT/inputs" "$ROOT" || true
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.
if [[ "$R940_POLKIT_NATIVE" == 1 ]]; then
  [[ "$(id -un)" == runner ]] || { echo R940_EXPECTED_CI_RUNNER_PRINCIPAL; exit 80; }
  # Only a disposable hosted runner; no pre-existing foreign OS policy is replaced.
  if [[ -e "$POLICY" || -L "$POLICY" || -e "$RULE" || -L "$RULE" ]]; then
    echo R940_FOREIGN_OS_POLKIT_ACTION_OR_RULE; exit 80
  fi
  if [[ ! -x /usr/bin/pkcheck || ! -x /usr/bin/pkaction ]]; then
    sudo -n apt-get update -qq
    sudo -n apt-get install -y -qq --no-install-recommends polkitd
  fi
  [[ -x /usr/bin/pkcheck && -x /usr/bin/pkaction ]] || {
    echo R940_VENDOR_POLKIT_TOOLS_MISSING; exit 80;
  }
  cat > "$tmp/test-action.policy" <<'POLICY_XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Isolated DIM CI fixture, not product authority</vendor>
  <action id="org.god13emad.directinternetmethod.r940fixture">
    <description>Authorize isolated synthetic root broker test</description>
    <message>Test-only isolated root broker</message>
    <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>no</allow_active></defaults>
  </action>
</policyconfig>
POLICY_XML
  sudo -n install -o root -g root -m 0644 "$tmp/test-action.policy" "$POLICY"
  policy_installed=1
  python "$SCRIPT" prepare --input "$input" --polkit-action "$ACTION"
else
  python "$SCRIPT" prepare --input "$input"
fi
sudo -n install -d -m 0711 -o root -g root "$ROOT"
created=1
sudo -n install -d -m 0700 -o root -g root "$ROOT/state" "$ROOT/inputs"
sudo -n install -d -m 0711 -o root -g root "$ROOT/public"
sudo -n install -o root -g root -m 0500 "$SCRIPT" "$ROOT/RunR938SystemdReceiptFixture.py"
if [[ "$R940_POLKIT_NATIVE" == 1 ]]; then
  sudo -n install -d -o root -g root -m 0700 "$ROOT/installer_engine"
  for f in __init__.py engine.py linux_peer_credential.py linux_polkit_authorization.py; do
    sudo -n install -o root -g root -m 0400 "installer_engine/$f" "$ROOT/installer_engine/$f"
    cmp -s "installer_engine/$f" <(sudo -n cat "$ROOT/installer_engine/$f") || {
      echo "R940_ROOT_OWNED_ADAPTER_SHA_CHANGED_$f"; exit 81;
    }
  done
fi
sudo -n install -d -o root -g root -m 0755 "$ROOT/public/foreign"
sudo -n install -o root -g root -m 0555 "$SCRIPT" "$ROOT/public/R938Client.py"
sudo -n install -o root -g root -m 0644 "$input/broker-request.json" "$ROOT/public/foreign/broker-request.json"
for name in broker-request.json broker-policy.json native-intent.json contract.json; do
  sudo -n install -o root -g root -m 0400 "$input/$name" "$ROOT/inputs/$name"
done
[[ "$(sudo -n stat -c '%u:%a' "$ROOT/state")" == 0:700 ]] || {
  echo R938_ROOT_LEDGER_MODE_WRONG; exit 86;
}
start_unit() {
  sudo -n systemd-run --system --unit=dim-r938-synthetic-broker \
    --property=Type=exec \
    --property=Restart=no \
    --property=NoNewPrivileges=yes \
    --property=PrivateTmp=yes \
    --property=ProtectSystem=strict \
    --property="ReadWritePaths=$ROOT" \
    --property=ProtectHome=yes \
    --property=RuntimeMaxSec=90s \
    /usr/bin/python3 "$ROOT/RunR938SystemdReceiptFixture.py" serve --root "$ROOT"
}
start_unit
wait_socket() {
  for i in $(seq 1 80); do
    # Socket pathname may survive systemctl restart while nobody listens.
    # Kernel AF_UNIX connect_ex (not -S alone) must prove a LIVE listener.
    if [[ -S "$ROOT/public/broker.sock" ]] &&
       /usr/bin/python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(0.2); sys.exit(s.connect_ex(sys.argv[1]) != 0)' "$ROOT/public/broker.sock"; then
      return 0
    fi
    if [[ "$(systemctl is-failed "$UNIT" 2>/dev/null || true)" == failed ]]; then
      sudo -n journalctl --no-pager -n 20 -u "$UNIT" || true
      return 1
    fi
    sleep 0.15
  done
  sudo -n journalctl --no-pager -n 20 -u "$UNIT" || true
  return 1
}
wait_socket
if [[ "$R940_POLKIT_NATIVE" == 1 ]]; then
  python "$SCRIPT" client --input "$input" --root "$ROOT" --mode polkit-denied |
    tee "$output/polkit-denied.json"
  [[ ! -e "$ROOT/state/native-completed-receipt.json" ]] || {
    echo R940_POLKIT_DENIAL_MUTATED_RECEIPT; exit 81
  }
  cat > "$tmp/only-runner.rules" <<'POLKIT_RULE'
polkit.addRule(function(action, subject) {
  if (action.id === "org.god13emad.directinternetmethod.r940fixture" &&
      subject.user === "runner") {
    return polkit.Result.YES;
  }
});
POLKIT_RULE
  sudo -n install -o root -g root -m 0644 "$tmp/only-runner.rules" "$RULE"
  rule_installed=1
  if systemctl list-unit-files polkit.service --no-legend | grep -q polkit.service; then
    sudo -n systemctl restart polkit.service
  fi
  /usr/bin/pkaction --action-id "$ACTION" --verbose | grep -F "$ACTION"
fi
first_pid=$(systemctl show -p MainPID --value "$UNIT")
[[ "$first_pid" =~ ^[1-9][0-9]*$ ]] || { echo R938_SERVICE_PID_INVALID; exit 87; }
python "$SCRIPT" client --input "$input" --root "$ROOT" --mode good | tee "$output/good.json"
python "$SCRIPT" client --input "$input" --root "$ROOT" --mode tampered | tee "$output/tampered.json"
sudo -n -u nobody /usr/bin/python3 "$ROOT/public/R938Client.py" client --input "$ROOT/public/foreign" --root "$ROOT" --mode wrong-uid | tee "$output/wrong-uid.json"
python "$SCRIPT" client --input "$input" --root "$ROOT" --mode replay | tee "$output/replay.json"
if test -r "$ROOT/state/broker-replay.json"; then
  echo R938_NONROOT_CAN_READ_PROTECTED_ROOT; exit 88
fi
# Native systemd restarts the actual root broker; ledger/receipt bytes survive.
sudo -n systemctl restart "$UNIT"
wait_socket
second_pid=$(systemctl show -p MainPID --value "$UNIT")
[[ "$first_pid" != "$second_pid" && "$second_pid" =~ ^[1-9][0-9]*$ ]] || {
  echo R938_SYSTEMD_RESTART_PID_UNCHANGED
  exit 89
}
python "$SCRIPT" client --input "$input" --root "$ROOT" --mode replay | tee "$output/replay-postrestart.json"
for name in broker-replay.json native-completed-receipt.json; do
  sudo -n install -o root -g root -m 0644 "$ROOT/state/$name" "$output/$name"
done
python "$SCRIPT" verify --input "$input" --output "$output"
if [[ "$R940_POLKIT_NATIVE" == 1 ]]; then
  echo 'R940_REAL_OS_POLKIT_DENY_THEN_ALLOW_ROOT_REPLAY_PASS_FIXTURE_ONLY'
fi
echo "R938_REAL_SYSTEMD_PID_CHANGED_$first_pid""_TO_""$second_pid"
echo 'R938_REAL_ROOT_OS_FIXTURE_ONLY_NOT_PRODUCT_INSTALL'
