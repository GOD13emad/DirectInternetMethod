#!/usr/bin/env bash
# R519 unreleased candidate; single privileged entrypoint for protected upgrade.
# Only after user transaction has verified and staged the exact extracted package.
# Never auto-commit root; native acceptance and owner review are separate.
set -Eeuo pipefail
umask 077
SRC="${1:-}"
REQ_UID="${2:-}"
TX_SHA="EB107164CCEDE891C8BF41C06FF422F1B53B59D2D2DDF0B3DD23EBFE5DE9601B"
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
# Arm the separately root-owned boot-persistent R553 guard BEFORE any
# protected Root Stage/Apply. Source identity is a frozen independent SHA;
# a signed-in OS administrator still authenticates through the installer.
GUARD_SHA="3E579455ACDB711F3D84F4F5869228DF8DDEE24BF7CBED952C9465C43A8FAC09"
[ -f "$SRC/system/upgrade_guard.py" ] && [ ! -L "$SRC/system/upgrade_guard.py" ] || {
    echo "R553_GUARD_SOURCE_MISSING_OR_SYMLINK" >&2; exit 87;
}
[ "$(sha256sum "$SRC/system/upgrade_guard.py" | cut -d' ' -f1)" = \
  "$(printf '%s' "$GUARD_SHA" | tr '[:upper:]' '[:lower:]')" ] || {
    echo "R553_GUARD_SOURCE_SHA_CHANGED" >&2; exit 87;
}
python3 "$SRC/system/upgrade_guard.py" arm --source "$SRC" --uid "$REQ_UID"
# R553: Do not touch root-owned binaries/metadata without a separately
# activated, root-owned two-sided timed rollback guard. A user-scoped backup
# from install.sh is reversible; it is NOT a protected autonomous watchdog.
python3 - "$REQ_UID" "$TX_SHA" <<'PY'
import hashlib,json,os,pathlib,stat,subprocess,sys
uid=int(sys.argv[1]); root_sha=sys.argv[2].upper()
unit="directinternetmethod-upgrade-rollback"
guard=pathlib.Path("/var/lib/directinternetmethod/upgrade-guard")
root=pathlib.Path("/var/lib/directinternetmethod/install.json")
try:
    assert guard.is_dir() and not guard.is_symlink()
    gs=guard.stat()
    assert gs.st_uid==0 and stat.S_IMODE(gs.st_mode)==0o711
    paths={"baseline.json":0o600,"worker.py":0o500,"root_tx.py":0o500,"user_tx.py":0o644}
    for name,mode in paths.items():
        p=guard/name
        assert p.is_file() and not p.is_symlink()
        st=p.stat()
        assert st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode
    def sha(path):
        h=hashlib.sha256()
        with path.open("rb") as inp:
            for b in iter(lambda:inp.read(1048576),b""):h.update(b)
        return h.hexdigest().upper()
    metadata=json.loads(root.read_text("utf8"))
    home=pathlib.Path(metadata["home"])
    data=json.loads((guard/"baseline.json").read_text("utf8"))
    assert data["schema"]==1 and data["revision"]=="R552"
    assert data["uid"]==uid and metadata["uid"]==uid and data["home"]==str(home)
    assert data["versionFromRoot"]=="1.5.2" and data["versionFromUser"]=="1.5.4"
    assert data["versionTo"]=="1.5.5-rc1"
    assert data["oldRootMetaSha"]==sha(root)
    assert data["oldUserMetaSha"]==sha(home/".local/share/DirectInternetMethod/INSTALL.json")
    assert data["rootTransactionSha"]==root_sha
    assert sha(guard/"root_tx.py")==root_sha
    assert sha(guard/"user_tx.py")=="EAC84CB951F520F0E6A05D1452EF355A1CC89D7C68DEB73F91BA14C8E1C4BD66"
    assert data["userTransactionSha"]==sha(guard/"user_tx.py")
    assert data["workerSha"]==sha(guard/"worker.py")
    pending=home/".local/state/DirectInternetMethod/update-pending"
    assert pending.is_dir() and not pending.is_symlink() and pending.stat().st_uid==uid
    pm=pending/"manifest.json"
    assert pm.is_file() and not pm.is_symlink() and pm.stat().st_uid==uid
    stage=json.loads(pm.read_text("utf8"))
    assert stage["schema"]==1 and stage["version"]=="1.5.5-rc1"
    assert stage["previousVersion"]=="1.5.4"
    old=stage["old"]["INSTALL.json"]
    assert old["exists"] is True and str(old["sha"]).upper()==data["oldUserMetaSha"]
    for ext in (".service",".timer"):
        p=pathlib.Path("/etc/systemd/system")/(unit+ext)
        assert p.is_file() and not p.is_symlink()
        st=p.stat()
        assert st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o644
    res=subprocess.run(["/usr/bin/systemctl","show",unit+".timer",
           "--property=ActiveState,LoadState,UnitFileState,Triggers","--no-pager"],
           text=True,capture_output=True,timeout=6,check=False)
    assert res.returncode==0 and all(s in res.stdout for s in
         ("ActiveState=active","LoadState=loaded","UnitFileState=enabled",
          unit+".service"))
except Exception as ex:
    print("R553_ROOT_GUARD_NOT_ARMED_FAIL_CLOSED "+type(ex).__name__,file=sys.stderr)
    sys.exit(87)
print("R553_ROOT_GUARD_ACTIVE_PRESTAGE_VERIFIED")
PY
# Transactional stage + apply obtain native action lock; one rollback slot.
python3 "$SRC/system/protected_upgrade_transaction.py" stage --source "$SRC"
python3 "$SRC/system/protected_upgrade_transaction.py" apply
python3 "$SRC/system/protected_upgrade_transaction.py" status |
  python3 -c 'import json,sys;j=json.load(sys.stdin);assert j["status"]=="APPLIED" and j["version"]=="1.5.5-rc1"'
echo '{"status":"ROOT_R519_APPLIED_UNCOMMITTED","needsRealNativeAcceptance":true}'
