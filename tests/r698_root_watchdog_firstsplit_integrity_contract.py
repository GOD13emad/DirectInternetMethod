#!/usr/bin/env python3
"""R698 first-segment profile and independent Root/Watchdog integrity chain.

Runs source inspection and an optional native unprivileged nfqws --dry-run.
No OS installation, admin/root privileges, packet filters, DNS or VPN mutation.
"""
from __future__ import annotations
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
def src(relative: str)->str:
    return (ROOT/relative).read_text(encoding="utf-8-sig")
def sha(relative: str)->str:
    return hashlib.sha256((ROOT/relative).read_bytes()).hexdigest().upper()
def need(ok,reason):
    if not ok: raise AssertionError("R698_"+reason)

helper=src("linux/app/direct_method_helper.sh")
split_head=helper.split('    NFQWS_ARGS=(--qnum="$QNUM")',1)
need(len(split_head)==2,"MISSING_NFQWS_PROFILE_START")
strategies=split_head[1].split('      compatibility)',1)
need(len(strategies)==2,"MISSING_COMPAT")
compat=strategies[1].split('      strong)',1)
need(len(compat)==2,"MISSING_STRONG")
profile=compat[0]
first=re.search(
    r'NFQWS_ARGS\+=\(\s*--new\s+--filter-tcp=443\s+'
    r'--hostlist-domains=youtube[.]com,youtu[.]be,googlevideo[.]com\s+'
    r'--dpi-desync=multisplit\s+--dpi-desync-split-pos=1\s*\)',
    profile,re.S)
need(first is not None,"YOUTUBE_FIRST_BYTE_PROFILE_MISSING")
generic='--new --filter-tcp=443 "${HOST_ARGS[@]}" --dpi-desync=multisplit --dpi-desync-split-pos=1,sniext+1,host+1,midsld,endhost-1'
need(generic in profile,"EXISTING_GENERAL_HTTPS_PROFILE_MISSING")
need(profile.index('--filter-tcp=80')<first.start()<profile.index(generic),"TARGETED_RULE_WRONG_ORDER")
need('--new --filter-udp=443 --filter-l7=quic "${HOST_ARGS[@]}"' in profile,"GENERAL_QUIC_PROFILE_REMOVED")
need(' --hostlist="$STRONG_OVERRIDE"' in profile,"OPTIONAL_ADULT_PROTECTED_HOSTS_REMOVED")
need('--hostlist-domains=youtube.com,youtu.be,googlevideo.com' not in compat[1],"COMPAT_EXCEPTION_ESCAPES_STRONG")
need('--dpi-desync-split-pos=1,sniext+1,host+1,midsld,endhost-1' in helper,"GENERAL_SPLIT_ALGORITHM_MODIFIED")
need('meta mark & 0xff0000 == 0x80000 return' in helper,"TAILSCALE_CONTROL_MARK_BYPASS_REMOVED")
need('[ "$SCOPE" = "targeted" ] && HOST_ARGS=(--hostlist="$RUN_HOSTS")' in helper,"TARGETED_SCOPE_NOT_PRESERVED")

# Exact source hashes are authority in the existing protected scripts,
# not constants invented by this new test. Verify every dependency.
helper_sha=sha("linux/app/direct_method_helper.sh")
tx=src("linux/system/protected_upgrade_transaction.py")
ui=src("linux/app/direct_internet_method.py")
need('"'+helper_sha+'"' in tx,"ROOT_PAYLOAD_HELPER_DIGEST_STALE")
need('COEXIST_HELPER_SHA256="'+helper_sha.lower()+'"' in ui,"GUI_BACKEND_DIGEST_STALE")
tx_sha=sha("linux/system/protected_upgrade_transaction.py")
guard=src("linux/system/upgrade_guard.py")
wrapper=src("linux/system/upgrade_system.sh")
need('PIN_ROOT="'+tx_sha+'"' in guard,"WATCHDOG_ROOT_DIGEST_STALE")
need('TX_SHA="'+tx_sha+'"' in wrapper,"PRIVILEGED_WRAPPER_ROOT_DIGEST_STALE")
need('PIN_ROOT = "'+tx_sha.lower()+'"' in src("tests/r532_root_watchdog_worker.py"),"INDEPENDENT_CI_WATCHDOG_ROOT_STALE")
need('ROOT_SHA = "'+tx_sha.lower()+'"' in src("tests/r532_ephemeral_root_watchdog_contract.py"),"EPHEMERAL_SYSTEMD_ROOT_STALE")
guard_sha=sha("linux/system/upgrade_guard.py")
need('GUARD_SHA="'+guard_sha+'"' in wrapper,"PRIVILEGED_WRAPPER_GUARD_DIGEST_STALE")
for t in ("tests/r552_native_upgrade_guard_contract.py",
          "tests/r554_native_guard_ephemeral_contract.py",
          "tests/r566_native_systemd_persistent_catchup.py"):
    need(guard_sha in src(t),"INDEPENDENT_WATCHDOG_CONTRACT_PIN_STALE_"+pathlib.Path(t).stem)
need('R553_ROOT_GUARD_ACTIVE_PRESTAGE_VERIFIED' in wrapper,"INDEPENDENT_GUARD_REMOVED")
need(wrapper.index('R553_ROOT_GUARD_ACTIVE_PRESTAGE_VERIFIED')<
     wrapper.index('python3 "$SRC/system/protected_upgrade_transaction.py" stage'),
     "ROOT_MUTATES_BEFORE_GUARD_ARMED")
need('"$NFQWS" --dry-run "${NFQWS_ARGS[@]}"' in helper,"ENGINE_PARSER_VERIFICATION_REMOVED")

if sys.platform.startswith("linux"):
    binary=ROOT/"linux/runtime/nfqws"
    need(binary.is_file(),"NATIVE_NFQWS_BINARY_MISSING")
    args=[str(binary),"--dry-run","--qnum=200",
        "--filter-tcp=80","--hostlist-domains=youtube.com",
        "--dpi-desync=multisplit","--dpi-desync-split-pos=method+2",
        "--new","--filter-tcp=443",
        "--hostlist-domains=youtube.com,youtu.be,googlevideo.com",
        "--dpi-desync=multisplit","--dpi-desync-split-pos=1",
        "--new","--filter-tcp=443","--hostlist-domains=youtube.com",
        "--dpi-desync=multisplit","--dpi-desync-split-pos=1,sniext+1,host+1,midsld,endhost-1"]
    p=subprocess.run(args,capture_output=True,text=True,timeout=12,check=False)
    need(p.returncode==0 and "command line parameters verified" in p.stdout,
         "ORIGINAL_NFQWS1_NATIVE_PARSER_FAILED")
    print("R698_NATIVE_ORIGINAL_NFQWS1_3_PROFILE_DRYRUN_PASS")
print("R698_SOURCE_SCOPE_AND_ROOT_GUARD_SHA_CHAIN_PASS")
