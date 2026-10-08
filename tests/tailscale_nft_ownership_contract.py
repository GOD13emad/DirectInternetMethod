#!/usr/bin/env python3
"""Offline nft ownership regression for Tailscale coexistence; no netfilter mutation."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

R=Path(__file__).resolve().parents[1]
src=(R/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
def function(name):
 m=re.search(r"^"+re.escape(name)+r"\(\)\{\n.*?^\}\n",src,re.S|re.M)
 assert m is not None, "MISSING_FUNCTION:"+name
 return m.group()
fragment="\n".join(function(x) for x in ("nft_table_owned","state_value"))
table_template='''table inet directinternetmethod {
        chain output {
                type filter hook output priority mangle; policy accept;
                %%MARK%%
                oifname "enp1s0" tcp dport 80 ct original packets 1-6 queue flags bypass to 200
                oifname "enp1s0" tcp dport 443 ct original packets 1-6 queue flags bypass to 200
                oifname "enp1s0" udp dport 443 ct original packets 1-6 queue flags bypass to 200
        }
}
'''
MARK='meta mark & 0x00ff0000 == 0x00080000 return'
CASES=[
 ("coexist_mark_and_interface", "system-preserved", MARK, "enp1s0", True),
 ("coexist_missing_bypass_mark", "system-preserved", "", "enp1s0", False),
 ("coexist_wrong_interface", "system-preserved", MARK, "enp9s0", False),
 ("coexist_mark_on_wrong_value", "system-preserved", "meta mark & 0xff0000 == 0x00010000 return", "enp1s0", False),
 ("standalone_no_tailscale_mark", "direct-doh", "", "enp1s0", True),
 ("standalone_wrong_interface", "direct-doh", "", "enp9s0", False),
]
with tempfile.TemporaryDirectory(prefix="dim_tail_nft_mock_") as d:
 p=Path(d)
 nft=p/"nft"
 nft.write_text('#!/usr/bin/env bash\n'
    'if [ "$*" != "list table inet directinternetmethod" ];then exit 81;fi\n'
    'cat "$MOCK_NFT_TABLE"\n',encoding="utf-8")
 nft.chmod(0o755)
 state=p/"state.json"
 table=p/"table.txt"
 env=os.environ.copy()
 env["PATH"]=str(p)+os.pathsep+env.get("PATH","")
 env["MOCK_NFT_TABLE"]=str(table)
 for name,mode,mark,iface,expected in CASES:
  table.write_text(table_template.replace("%%MARK%%",mark),encoding="utf-8")
  state.write_text(json.dumps({"dnsMode":mode}),encoding="utf-8")
  script='TABLE="directinternetmethod"\nSTATE="'+str(state)+'"\n'+fragment+(
    '\nif nft_table_owned "'+iface+'";then echo OWNED;else echo FOREIGN;fi\n')
  run=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True,timeout=10)
  actual=run.stdout.strip()=="OWNED"
  assert run.returncode==0 and actual==expected,(
    name,run.returncode,run.stdout,run.stderr,expected)
  print("PASS",name,"OWNED" if actual else "FOREIGN")
print(f"PASS {len(CASES)}/{len(CASES)} nft ownership mock checks; no system NFT commands invoked")
