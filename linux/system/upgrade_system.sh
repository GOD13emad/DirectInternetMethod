#!/usr/bin/env bash
# R519 unreleased candidate; single privileged entrypoint for protected upgrade.
# Only after user transaction has verified and staged the exact extracted package.
# Never auto-commit root; native acceptance and owner review are separate.
set -Eeuo pipefail
umask 077
SRC="${1:-}"
REQ_UID="${2:-}"
TX_SHA="4CE00525AF4773FE25CB7E3E5EDFD661B6A30C6B677964E12F24BCA6650F328D"
[ "$(id -u)" = 0 ] || { echo 'ROOT_REQUIRED' >&2; exit 77; }
case "$REQ_UID" in ''|*[!0-9]*) echo 'UID_INVALID' >&2; exit 77;; esac
[ "$REQ_UID" -gt 0 ] && [ "$REQ_UID" -lt 2147483648 ] || exit 77
[ -d "$SRC" ] && [ ! -L "$SRC" ] && [ -f "$SRC/system/protected_upgrade_transaction.py" ] || {
    echo "UPGRADE_SOURCE_MISSING_OR_SYMLINK" >&2; exit 77;
}
[ "$(basename "$SRC")" = "DirectInternetMethod_1.5.5-rc1_Linux_x86_64" ] || {
    echo "WRONG_PACKAGE_LAYOUT" >&2; exit 77;
}
owner_uid="$(stat -c %u -- "$SRC")"
[ "$owner_uid" = "$REQ_UID" ] || { echo 'PACKAGE_OWNER_MISMATCH' >&2; exit 77; }
[ "$(sha256sum "$SRC/system/protected_upgrade_transaction.py" | cut -d' ' -f1)" = \
  "$(printf '%s' "$TX_SHA" | tr '[:upper:]' '[:lower:]')" ] || {
    echo "UPGRADER_SOURCE_SHA_CHANGED" >&2; exit 77;
}
[ "$(cat /etc/directinternetmethod.uid 2>/dev/null)" = "$REQ_UID" ] || {
    echo "PROTECTED_ACCOUNT_ID_CHANGED" >&2; exit 77;
}
python3 - "$REQ_UID" <<'PY'
from pathlib import Path
import json,sys,stat
expected=int(sys.argv[1])
p=Path('/var/lib/directinternetmethod/install.json')
assert p.is_file() and not p.is_symlink()
s=p.stat()
assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o644
m=json.loads(p.read_text('utf8'))
assert m['schema']==1 and m['version']=='1.5.2' and m['uid']==expected
assert m['home'].startswith('/home/')
PY
# Transactional stage + apply obtain native action lock; one rollback slot.
python3 "$SRC/system/protected_upgrade_transaction.py" stage --source "$SRC"
python3 "$SRC/system/protected_upgrade_transaction.py" apply
python3 "$SRC/system/protected_upgrade_transaction.py" status |
  python3 -c 'import json,sys;j=json.load(sys.stdin);assert j["status"]=="APPLIED" and j["version"]=="1.5.5-rc1"'
echo '{"status":"ROOT_R519_APPLIED_UNCOMMITTED","needsRealNativeAcceptance":true}'
