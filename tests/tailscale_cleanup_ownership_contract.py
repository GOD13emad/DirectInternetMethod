#!/usr/bin/env python3
"""Rootless, isolated cleanup/recovery ownership tests with mocked nft/ip.

This script NEVER invokes live nft, ip or systemctl; helper functions are
extracted without executing the real helper entry point.
"""
from pathlib import Path
import json
import os
import re
import subprocess
import tempfile

R=Path(__file__).resolve().parents[1]
text=(R/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
def f(name):
 m=re.search(r"^"+re.escape(name)+r"\(\)\{\n.*?^\}\n",text,re.M|re.S)
 assert m is not None,name
 return m.group(0)
functions="\n".join(f(n) for n in (
 "nft_table_presence","nft_table_owned","state_value","cleanup_state_owned","verify_clean"
))
nft_output='''table inet directinternetmethod {
    chain output {
        type filter hook output priority mangle; policy accept;
        %%MARK%%
        oifname "enp1s0" tcp dport 80 ct original packets 1-6 queue flags bypass to 200
        oifname "enp1s0" tcp dport 443 ct original packets 1-6 queue flags bypass to 200
        oifname "enp1s0" udp dport 443 ct original packets 1-6 queue flags bypass to 200
    }
}'''
mark="meta mark & 0x00ff0000 == 0x00080000 return"
cases=[
 ("split_coexistence_owns_marked_table", "system-preserved",mark,True,0,True),
 ("split_coexistence_rejects_missing_mark", "system-preserved","",True,81,False),
 ("split_coexistence_rejects_wrong_mark", "system-preserved",
  "meta mark & 0xff0000 == 0x00010000 return",True,81,False),
 ("split_coexistence_rejects_wrong_mask", "system-preserved",
  "meta mark & 0x007f0000 == 0x00080000 return",True,81,False),
 ("split_coexistence_rejects_late_mark", "system-preserved",mark,True,81,False),
 ("standalone_owns_unmarked_table","direct-doh","",True,0,True),
 ("split_coexistence_no_table","system-preserved","",False,0,True),
 ("split_coexistence_foreign_extra_rule", "system-preserved",mark,True,81,False),
]
with tempfile.TemporaryDirectory(prefix="dim_tailscale_cleanup_") as td:
 d=Path(td)
 nft=d/"nft"
 nft.write_text(r'''#!/usr/bin/env bash
set -euo pipefail
if [ "$*" = "list table inet directinternetmethod" ]; then
  test ! -f "$MOCK_DELETED" || exit 1
  test "$MOCK_NFT_EXISTS" = "1" || exit 1
  cat "$MOCK_NFT_FIXTURE"
elif [ "$*" = "-j list tables" ]; then
  if [ "$MOCK_NFT_EXISTS" = "1" ] && [ ! -f "$MOCK_DELETED" ]; then
    echo '{"nftables":[{"table":{"family":"inet","name":"directinternetmethod"}}]}'
  else
    echo '{"nftables":[]}'
  fi
elif [ "$*" = "delete table inet directinternetmethod" ]; then
  test "$MOCK_NFT_EXISTS" = "1" || exit 70
  touch "$MOCK_DELETED"
else
  echo "UNEXPECTED_NFT:$*" >&2
  exit 80
fi
''',encoding="utf-8")
 nft.chmod(0o755)
 ip=d/"ip"
 ip.write_text(r'''#!/usr/bin/env bash
case "$*" in
  "link show dimdns0") exit 1 ;;
  *) echo "UNEXPECTED_IP:$*" >&2; exit 80 ;;
esac
''',encoding="utf-8")
 ip.chmod(0o755)
 for name,mode,bypass,present,rc_expected,owned in cases:
  state=d/"state.json"
  state.write_text(json.dumps({"dnsMode":mode,"physicalInterface":"enp1s0",
                               "ctrldPid":0,"nfqwsPid":0}),encoding="utf-8")
  fixture=d/"nft.out"
  value=nft_output.replace("%%MARK%%",bypass)
  if name=="split_coexistence_rejects_late_mark":
   value=nft_output.replace("%%MARK%%","")
   first='oifname "enp1s0" tcp dport 80 ct original packets 1-6 queue flags bypass to 200'
   assert first in value
   value=value.replace(first,first+"\n        "+mark,1)
  if name=="split_coexistence_foreign_extra_rule":
   value=value.replace('        oifname "enp1s0" udp dport 443', '        ip daddr 203.0.113.7 drop\n        oifname "enp1s0" udp dport 443',1)
  fixture.write_text(value,encoding="utf-8")
  deleted=d/"deleted"
  deleted.unlink(missing_ok=True)
  runhost=d/"run_hosts"
  runhost.write_text("example.com\n",encoding="utf-8")
  env=os.environ.copy()
  env["PATH"]=str(d)+os.pathsep+env["PATH"]
  env["MOCK_NFT_FIXTURE"]=str(fixture)
  env["MOCK_NFT_EXISTS"]="1" if present else "0"
  env["MOCK_DELETED"]=str(deleted)
  kills=d/"attempted-kills"
  kills.unlink(missing_ok=True)
  env["MOCK_KILLS"]=str(kills)
  shell=('set -uo pipefail\n'
       f'TABLE=directinternetmethod\nSTATE="{state}"\n'
       f'RUN_HOSTS="{runhost}"\nDNS_IF=dimdns0\nCTRLD=/nonexistent/ctrld\n'
       f'NFQWS=/nonexistent/nfqws\n' +
       ('pid_owned(){ return 0; }\nkill(){ touch "$MOCK_KILLS"; }\n' if name=="split_coexistence_foreign_extra_rule" else 'pid_owned(){ return 1; }\n') +
       'remove_dns_link(){ echo UNEXPECTED_DNS_LINK_REMOVAL >&2; return 89; }\n'
       +functions+
       '\ncleanup_state_owned\n'
       'rc=$?\n'
       'if [ "$rc" -eq 0 ];then verify_clean; verify_rc=$?; else verify_rc=99;fi\n'
       'printf "RC=%s VERIFY=%s\\n" "$rc" "$verify_rc"\n')
  cp=subprocess.run(["bash","-c",shell],env=env,text=True,
                    capture_output=True,timeout=9)
  success=rc_expected==0
  assert cp.returncode==0,(name,cp.returncode,cp.stderr)
  assert f"RC={rc_expected}" in cp.stdout,(name,cp.stdout,cp.stderr)
  assert deleted.exists()==(present and success),(name,"deleted state",deleted.exists())
  assert state.exists()==(not success),(name,"state file retained",state.exists())
  if success:
   assert "VERIFY=0" in cp.stdout,(name,cp.stdout,cp.stderr)
   assert not runhost.exists(),(name,"run hosts residue")
  else:
   assert runhost.exists(),(name,"foreign hostlist removed without state")
  if name=="split_coexistence_foreign_extra_rule":
   assert not kills.exists(),(name,"KILL_BEFORE_FOREIGN_OWNERSHIP_CHECK")
  assert "UNEXPECTED" not in cp.stderr,(name,cp.stderr)
  print("PASS",name,"cleanup success" if success else "foreign table preserved")
print(f"PASS {len(cases)}/{len(cases)} mock cleanup/recovery gates; no real network mutations")
