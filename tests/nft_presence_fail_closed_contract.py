#!/usr/bin/env python3
"""Negative-first fail-closed tests for nft error != verified table absence.

No system netfilter access: a private temp PATH provides mock nft/ip, and
only selected production Bash functions/case fragments are executed.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import subprocess
import tempfile

BASE=Path(__file__).resolve().parents[1]
source=(BASE/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
def function(name, required=True):
    matches=re.findall(r"^"+re.escape(name)+r"\(\)\{\n.*?^\}\n",source,re.S|re.M)
    if required: assert len(matches)==1,("FUNCTION_NOT_UNIQUE",name)
    return matches[0] if matches else ""
def action_case(name):
    matches=re.findall(r"^  "+re.escape(name)+r"\)\n.*?^    ;;\n",source,re.S|re.M)
    assert len(matches)==1,("CASE_NOT_UNIQUE",name)
    return matches[0]
fragments="\n".join(function(n,required=n!="nft_table_presence") for n in
    ("nft_table_presence","nft_table_owned","state_value",
     "cleanup_state_owned","verify_clean"))
actions={n:action_case(n) for n in ("stop","recovery")}
cases=[
    ("stateless_recovery_permission_denied","recovery","denied",False,84,False),
    ("stateless_stop_permission_denied","stop","denied",False,84,False),
    ("stateless_recovery_bad_json","recovery","malformed",False,84,False),
    ("stateless_recovery_absent","recovery","absent",False,0,True),
    ("stateless_recovery_foreign_table","recovery","exists",False,81,False),
    ("stateful_stop_permission_denied","stop","denied",True,84,False),
]
with tempfile.TemporaryDirectory(prefix="dim_r212_nft_unknown_") as td:
    d=Path(td)
    nft=d/"nft"
    nft.write_text(r'''#!/usr/bin/env bash
case "$*" in
  "list table inet directinternetmethod")
    case "$MOCK_NFT" in exists) exit 0;; *) exit 4;; esac ;;
  "-j list tables")
    case "$MOCK_NFT" in
      denied) echo "Permission denied" >&2; exit 4;;
      malformed) echo '{bad'; exit 0;;
      absent) echo '{"nftables":[{"metainfo":{"json_schema_version":1}}]}'; exit 0;;
      exists) echo '{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"directinternetmethod"}}]}'; exit 0;;
    esac ;;
  *) echo "MOCK_UNEXPECTED_NFT_COMMAND:$*" >&2; exit 90;;
esac
''',encoding="utf-8")
    nft.chmod(0o755)
    ip=d/"ip"
    ip.write_text(r'''#!/usr/bin/env bash
[ "$*" = "link show dimdns0" ] && exit 1
echo "MOCK_UNEXPECTED_IP_COMMAND:$*" >&2
exit 90
''',encoding="utf-8")
    ip.chmod(0o755)
    for name,act,mode,has_state,expected,allowed_orphan in cases:
        state=d/"state.json"
        kills=d/"kill_attempts"
        hosts=d/"hosts-runtime.txt"
        for x in (state,kills):
            x.unlink(missing_ok=True)
        hosts.write_text("example.net\n",encoding="utf-8")
        if has_state:
            state.write_text('{"nfqwsPid":123,"ctrldPid":456,"physicalInterface":"enp1s0","dnsMode":"system-preserved"}')
        env=os.environ.copy()
        env.update({"PATH":str(d)+os.pathsep+env["PATH"],
                    "MOCK_NFT":mode,"MOCK_KILLS":str(kills)})
        prelude=f'''set -euo pipefail
ACTION={act}
TABLE=directinternetmethod
DNS_IF=dimdns0
STATE="{state}"
RUN_HOSTS="{hosts}"
NFQWS=/exact/mock/nfqws
CTRLD=/exact/mock/ctrld
require_root(){{ :; }}
acquire_action_lock(){{ :; }}
pid_owned(){{ return 0; }}
kill(){{ touch "$MOCK_KILLS"; }}
kill_all_owned_by_exe(){{ touch "$MOCK_KILLS"; }}
sleep(){{ :; }}
dns_link_owned(){{ return 1; }}
remove_dns_link(){{ echo UNEXPECTED_REMOVE_DNS; return 90; }}
'''
        program=prelude+fragments+f'\ncase "$ACTION" in\n{actions[act]}\nesac\n'
        done=subprocess.run(["bash","-c",program],env=env,text=True,
                            capture_output=True,timeout=8)
        assert done.returncode==expected,(name,"unexpected exit",done.returncode,expected,done.stdout,done.stderr)
        assert kills.exists()==allowed_orphan,(name,"unsafe kill",kills.exists(),done.stdout)
        assert state.exists()==has_state,(name,"state unexpectedly erased")
        assert hosts.exists()==(not allowed_orphan),(name,"hosts cleanup before evidence")
        assert "UNEXPECTED" not in done.stdout+done.stderr,(name,"unexpected mutation")
        print("PASS",name)
print(f"PASS {len(cases)}/{len(cases)} nft query fail-closed mock cases; no real netfilter")
