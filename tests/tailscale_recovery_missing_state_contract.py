#!/usr/bin/env python3
"""Fail-closed rootless regression for the real recovery case when ownership state is absent.

Only selected Bash case text is run; nft/ip are private temp mocks, no real root actions.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
found = re.findall(r"^  recovery\)\n.*?^    ;;\n", source, flags=re.M | re.S)
assert len(found) == 1, "EXACT_RECOVERY_CASE_REQUIRED"
recovery_case = found[0]

CASES = [
    ("foreign_table_no_state", "1", "0", "0", "0", 81, False),
    ("foreign_dns_link_no_state", "0", "1", "0", "0", 81, False),
    ("foreign_both_no_state", "1", "1", "0", "0", 81, False),
    ("late_foreign_dns_no_state", "0", "0", "0", "1", 80, True),
    ("late_foreign_nft_no_state", "0", "0", "1", "0", 80, True),
    ("no_resources_no_state", "0", "0", "0", "0", 0, True),
]
with tempfile.TemporaryDirectory(prefix="dim_r211_stateless_") as work:
    tmp = Path(work)
    mock_nft = tmp / "nft"
    mock_nft.write_text(r"""#!/usr/bin/env bash
case "$*" in
  "list table inet directinternetmethod")
    test "$MOCK_HAS_NFT" = 1 || { test "$MOCK_LATE_NFT" = 1 && test -f "$MOCK_KILLS"; } ;;
  "-j list tables")
    if [ "$MOCK_HAS_NFT" = 1 ] || { [ "$MOCK_LATE_NFT" = 1 ] && [ -f "$MOCK_KILLS" ]; }; then
      echo '{"nftables":[{"table":{"family":"inet","name":"directinternetmethod"}}]}'
    else
      echo '{"nftables":[]}'
    fi ;;
  "delete table inet directinternetmethod") touch "$MOCK_DELETED"; exit 0 ;;
  *) echo "MOCK_NFT_UNEXPECTED" >&2; exit 90 ;;
esac
""", encoding="utf-8")
    mock_nft.chmod(0o755)
    mock_ip = tmp / "ip"
    mock_ip.write_text(r"""#!/usr/bin/env bash
case "$*" in
  "link show dimdns0")
    test "$MOCK_HAS_DNS" = 1 || { test "$MOCK_LATE_DNS" = 1 && test -f "$MOCK_KILLS"; } ;;
  *) echo "MOCK_IP_UNEXPECTED" >&2; exit 90 ;;
esac
""", encoding="utf-8")
    mock_ip.chmod(0o755)
    import textwrap
    presence = re.search(r"^nft_table_presence\(\)\{\n.*?^\}\n", source, re.S | re.M)
    verify = re.search(r"^verify_clean\(\)\{\n.*?^\}\n", source, re.S | re.M)
    assert presence and verify, "PRESENCE_AND_CLEAN_VERIFICATION_REQUIRED"
    for name, has_nft, has_dns, late_nft, late_dns, expected_rc, expected_orphan_kills in CASES:
        actions = tmp / "orphan-kill-attempts"
        deleted = tmp / "resource-delete-attempt"
        state = tmp / "missing-state.json"
        hosts = tmp / "mock-runtime-hosts.txt"
        for f in (actions, deleted, state):
            f.unlink(missing_ok=True)
        hosts.write_text("example.org\n", encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "PATH": str(tmp) + os.pathsep + env["PATH"],
            "MOCK_HAS_NFT": has_nft,
            "MOCK_HAS_DNS": has_dns,
            "MOCK_LATE_NFT": late_nft,
            "MOCK_LATE_DNS": late_dns,
            "MOCK_KILLS": str(actions),
            "MOCK_DELETED": str(deleted),
        })
        cmd = ("""
set -uo pipefail
ACTION=recovery
TABLE=directinternetmethod
DNS_IF=dimdns0
NFQWS=/tmp/isolated/mock-nfqws
CTRLD=/tmp/isolated/mock-ctrld
STATE=""" + "'" + str(state) + "'" + "\nRUN_HOSTS='" + str(hosts) + "'" + r"""
require_root(){ :; }
kill_all_owned_by_exe(){ printf '%s\n' "$1" >>"$MOCK_KILLS"; }
cleanup_state_owned(){ echo UNEXPECTED_CLEANUP_STATE; return 90; }
nft_table_owned(){ return 1; }
dns_link_owned(){ return 1; }
remove_dns_link(){ touch "$MOCK_DELETED"; }
sleep(){ :; }
""" + presence.group() + "\n" + verify.group() + """
case "$ACTION" in
""" + recovery_case + """
esac
""")
        result = subprocess.run(
            ["bash", "-c", cmd], env=env, text=True,
            capture_output=True, timeout=8,
        )
        assert result.returncode == expected_rc, (
            name, "EXIT", result.returncode, expected_rc, result.stdout, result.stderr
        )
        assert actions.exists() == expected_orphan_kills, (
            name, "ORPHAN_KILL_OCCURRED_BEFORE_FOREIGN_OWNERSHIP_PROOF",
            actions.read_text() if actions.exists() else "",
        )
        assert not deleted.exists(), (name, "FOREIGN_RESOURCE_DELETED")
        assert hosts.exists() == (not expected_orphan_kills), (name, "UNOWNED_HOSTS_MUTATED")
        assert "UNEXPECTED" not in result.stdout + result.stderr, (name, result.stderr)
        print("PASS", name, "no foreign resource mutation")
print(f"PASS {len(CASES)}/{len(CASES)} stateless recovery mocks; no real nft/ip/process mutations")
