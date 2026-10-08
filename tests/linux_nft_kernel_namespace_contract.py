#!/usr/bin/env python3
"""Real-kernel nftables contract in a disposable network namespace.

Run --source-only without root. Run --kernel as root on a disposable test
machine or CI runner. The caller namespace is NEVER mutated; no real network
interface, route, host process, DNS or Tailscale resource is changed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "linux/app/direct_method_helper.sh"
REQUIRED = (
    "state_value", "nft_table_presence", "nft_table_owned",
    "nft_table_transient_owned", "cleanup_state_owned",
    "cleanup_transient", "verify_clean", "rollback_on_exit",
)


def fragment(source: str, name: str) -> str:
    occurrences = re.findall(
        r"^" + re.escape(name) + r"\(\)\{\n.*?^\}\n",
        source, re.M | re.S,
    )
    assert len(occurrences) == 1, f"FUNCTION_NOT_UNIQUE:{name}"
    return occurrences[0]


def extract_functions() -> str:
    source = HELPER.read_text(encoding="utf-8")
    assert "nft delete table inet \"$TABLE\"" in source
    return "\n".join(fragment(source, name) for name in REQUIRED)


def namespace() -> str:
    return os.readlink("/proc/self/ns/net")


def execute(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True,
                          check=False, timeout=25, **kwargs)


def ensure_isolated(parent_ns: str) -> None:
    assert os.geteuid() == 0, "ROOT_REQUIRED"
    assert namespace() != parent_ns, "HOST_NETWORK_NAMESPACE_REFUSED"
    cap_effective = int(
        next(x.split(":", 1)[1].strip() for x in
             Path("/proc/self/status").read_text().splitlines()
             if x.startswith("CapEff:")), 16
    )
    assert cap_effective & (1 << 12), "CAP_NET_ADMIN_REQUIRED"
    result = execute(["ip", "-o", "link", "show"])
    assert result.returncode == 0, result.stderr
    interfaces = [
        re.split(r":\s+", ln, maxsplit=1)[1].split(":", 1)[0].split("@")[0]
        for ln in result.stdout.splitlines()
    ]
    assert interfaces == ["lo"], "NETWORK_NS_NOT_ISOLATED:"+repr(interfaces)
    tables = execute(["nft", "-j", "list", "tables"])
    assert tables.returncode == 0, tables.stderr
    data = json.loads(tables.stdout)
    assert isinstance(data.get("nftables"), list)
    assert not any(isinstance(x, dict) and "table" in x
                   for x in data["nftables"]), "NAMESPACE_TABLES_NOT_EMPTY"


def kernel_script() -> str:
    functions = extract_functions()
    cases = r'''
set -euo pipefail
umask 077
TMP="$(mktemp -d -t dim-kernel-contract-XXXXXX)"
trap 'rm -rf -- "$TMP"' EXIT
TABLE=directinternetmethod
PHY=enp1s0
DNS_IF=dimdns0
QNUM=200
TAILSCALE_COEXIST=1
CREATED_TABLE=1
CREATED_LINK=0
RUN_HOSTS="$TMP/hosts.txt"
STATE="$TMP/state.json"
NPID=0
CPID=0
CTRLD="$TMP/not-ctrld"
NFQWS="$TMP/not-nfqws"
pid_owned(){ return 1; }
remove_dns_link(){ echo "UNEXPECTED_DNS_LINK" >&2; return 99; }

put_state(){
  printf '%s\n' '{"dnsMode":"system-preserved","physicalInterface":"enp1s0","ctrldPid":0,"nfqwsPid":0}' > "$STATE"
  printf 'example.org\n' > "$RUN_HOSTS"
}
new_table(){
  nft add table inet "$TABLE"
}
new_chain(){
  nft "add chain inet $TABLE output { type filter hook output priority mangle; policy accept; }"
}
mark(){
  nft "add rule inet $TABLE output meta mark & 0xff0000 == 0x80000 return"
}
queues(){
  nft add rule inet "$TABLE" output oifname enp1s0 tcp dport 80 ct original packets 1-6 queue num 200 bypass
  nft add rule inet "$TABLE" output oifname enp1s0 tcp dport 443 ct original packets 1-6 queue num 200 bypass
  nft add rule inet "$TABLE" output oifname enp1s0 udp dport 443 ct original packets 1-6 queue num 200 bypass
}
expect_absent(){
  if nft_table_presence; then
    echo "OWNED_TABLE_STILL_PRESENT" >&2
    exit 88
  else
    rc=$?
    test "$rc" -eq 1 || { echo "ABSENCE_NOT_VERIFIED" >&2; exit 89; }
  fi
}
# Positive complete table: production ownership checker and cleanup.
put_state
new_table; new_chain; mark; queues
nft_table_presence
nft_table_owned "$PHY"
cleanup_state_owned
verify_clean
expect_absent
echo "PASS_KERNEL_COMPLETE_OWNED_CLEANUP"
# Prefix-safe rollback: table only, chain+mark, complete table.
for mode in empty partial full; do
  put_state; new_table
  if [ "$mode" != "empty" ]; then new_chain; mark; fi
  if [ "$mode" = "full" ]; then queues; fi
  if cleanup_transient; then rc=0; else rc=$?; fi
  test "$rc" -eq 0
  expect_absent
  echo "PASS_KERNEL_TRANSIENT_$mode"
done
# Foreign rule after Start: state must be preserved with explicit diagnostic.
put_state
new_table; new_chain; mark; queues
nft add rule inet "$TABLE" output ip daddr 203.0.113.7 drop
if nft_table_transient_owned "$PHY" "$TAILSCALE_COEXIST"; then
  echo "FALSE_FOREIGN_OWNERSHIP" >&2; exit 90
fi
if cleanup_transient; then rc=0; else rc=$?; fi
test "$rc" -eq 83
nft list table inet "$TABLE" >/dev/null
test -f "$STATE"
nft delete table inet "$TABLE"
expect_absent
echo "PASS_KERNEL_FOREIGN_ROLLBACK_PRESERVATION"
# Foreign rule after Start completion: stop must fail before killing process.
put_state
new_table; new_chain; mark; queues
nft add rule inet "$TABLE" output ip daddr 203.0.113.7 drop
if cleanup_state_owned; then rc=0; else rc=$?; fi
test "$rc" -eq 81
test -f "$STATE"
nft list table inet "$TABLE" >/dev/null
nft delete table inet "$TABLE"
expect_absent
echo "PASS_KERNEL_FOREIGN_STATE_CLEANUP_PRESERVATION"
# A real foreign table must cause the production EXIT trap to fail.
put_state
new_table; new_chain; mark; queues
nft add rule inet "$TABLE" output ip daddr 203.0.113.7 drop
export TABLE PHY TAILSCALE_COEXIST CREATED_TABLE CREATED_LINK RUN_HOSTS NPID CPID CTRLD NFQWS
export -f rollback_on_exit cleanup_transient nft_table_presence nft_table_transient_owned pid_owned remove_dns_link
if trap_output="$(bash -c 'set -euo pipefail; ACTION=start; START_COMMITTED=0; trap rollback_on_exit EXIT; exit 0' 2>&1)";then
  trap_rc=0
else
  trap_rc=$?
fi
if [ "$trap_rc" -ne 83 ] || ! grep -q START_ROLLBACK_FAILED <<<"$trap_output";then
  echo "FALSE_GREEN_KERNEL_ROLLBACK_TRAP_RC=$trap_rc $trap_output" >&2
  exit 93
fi
nft list table inet "$TABLE" >/dev/null
test -f "$STATE"
nft delete table inet "$TABLE"
expect_absent
echo "PASS_KERNEL_FAILED_ROLLBACK_EXIT_NONZERO"
echo "PASS_KERNEL_NAMESPACE_NFT_CONTRACT_7_OF_7"
'''
    return functions + "\n" + cases


def main() -> int:
    cli = argparse.ArgumentParser()
    mode = cli.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source-only", action="store_true")
    mode.add_argument("--kernel", action="store_true")
    mode.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    cli.add_argument("--parent-ns", default=None, help=argparse.SUPPRESS)
    opts = cli.parse_args()
    extract_functions()
    if opts.source_only:
        print("PASS_SOURCE_ONLY_NFT_KERNEL_CONTRACT_SYNTAX")
        return 0
    for prog in ("nft", "ip", "bash", "unshare"):
        assert shutil.which(prog), f"REQUIRED_TOOL_MISSING:{prog}"
    assert os.geteuid() == 0, "AUTHORIZED_ROOT_REQUIRED"
    if opts.kernel:
        old_ns = namespace()
        child = execute([
            "unshare", "--net", "--",
            sys.executable, str(Path(__file__).resolve()),
            "--inside", "--parent-ns", old_ns,
        ])
        sys.stdout.write(child.stdout)
        sys.stderr.write(child.stderr)
        assert child.returncode == 0, "ISOLATED_KERNEL_CHECK_FAIL"
        return 0
    assert opts.inside and opts.parent_ns, "DIRECT_HOST_KERNEL_EXECUTION_REFUSED"
    ensure_isolated(opts.parent_ns)
    tests = execute(["bash", "-c", kernel_script()])
    sys.stdout.write(tests.stdout)
    sys.stderr.write(tests.stderr)
    assert tests.returncode == 0, "REAL_KERNEL_CONTRACT_FAILED"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
