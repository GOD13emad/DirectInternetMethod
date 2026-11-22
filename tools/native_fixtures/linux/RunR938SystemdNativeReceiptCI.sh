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
cleanup() {
  if [[ "$created" == 1 ]]; then
    sudo -n systemctl stop "$UNIT" >/dev/null 2>&1 || true
    sudo -n systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
    for file in "$ROOT/public/broker.sock" \
                "$ROOT/public/R938Client.py" \
                "$ROOT/public/foreign/broker-request.json" \
                "$ROOT/state/broker-replay.json" \
                "$ROOT/state/native-completed-receipt.json" \
                "$ROOT/RunR938SystemdReceiptFixture.py" \
                "$ROOT/inputs/broker-request.json" \
                "$ROOT/inputs/broker-policy.json" \
                "$ROOT/inputs/native-intent.json" \
                "$ROOT/inputs/contract.json"; do
      sudo -n rm -f -- "$file" || true
    done
    sudo -n rmdir -- "$ROOT/public/foreign" "$ROOT/public" "$ROOT/state" "$ROOT/inputs" "$ROOT" || true
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.
python "$SCRIPT" prepare --input "$input"
sudo -n install -d -m 0711 -o root -g root "$ROOT"
created=1
sudo -n install -d -m 0700 -o root -g root "$ROOT/state" "$ROOT/inputs"
sudo -n install -d -m 0711 -o root -g root "$ROOT/public"
sudo -n install -o root -g root -m 0500 "$SCRIPT" "$ROOT/RunR938SystemdReceiptFixture.py"
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
    [[ -S "$ROOT/public/broker.sock" ]] && return 0
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
echo "R938_REAL_SYSTEMD_PID_CHANGED_$first_pid""_TO_""$second_pid"
echo 'R938_REAL_ROOT_OS_FIXTURE_ONLY_NOT_PRODUCT_INSTALL'
