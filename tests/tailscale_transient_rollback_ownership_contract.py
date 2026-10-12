#!/usr/bin/env python3
"""Offline negative-first rollback contract. All nft/IP/process operations are mocks."""
from __future__ import annotations
import os, pathlib, re, subprocess, tempfile

R=pathlib.Path(__file__).resolve().parents[1]
helper=(R/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
def fragment(name,optional=False):
    matches=re.findall(r"^"+re.escape(name)+r"\(\)\{\n.*?^\}\n",helper,re.M|re.S)
    if optional and not matches: return ""
    assert len(matches)==1,(name,len(matches))
    return matches[0]
real_fragment="\n".join(fragment(x,optional=x=="nft_table_transient_owned") for x in
    ("nft_table_presence","nft_table_transient_owned","cleanup_transient"))
fixture='''table inet directinternetmethod {
    chain output {
        type filter hook output priority mangle; policy accept;
        %%RULES%%
    }
}
'''
mark='meta mark & 0x00ff0000 == 0x00080000 return'
queue=[
'oifname "enp1s0" tcp dport 80 ct original packets 1-6 queue flags bypass to 200',
'oifname "enp1s0" tcp dport 443 ct original packets 1-6 queue flags bypass to 200',
'oifname "enp1s0" udp dport 443 ct original packets 1-6 queue flags bypass to 200',
]
valid=[mark]+queue
cases=[
 ("coexist_empty_table","table inet directinternetmethod {\n}\n","1",True),
 ("coexist_empty_chain",fixture.replace("%%RULES%%",""),"1",True),
 ("coexist_mark_only",fixture.replace("%%RULES%%",mark),"1",True),
 ("coexist_partial_rules",fixture.replace("%%RULES%%","\n".join(valid[:2])),"1",True),
 ("coexist_all_rules",fixture.replace("%%RULES%%","\n".join(valid)),"1",True),
 ("coexist_foreign_added",fixture.replace("%%RULES%%","\n".join(valid+["ip daddr 203.0.113.7 drop"])),"1",False),
 ("coexist_wrong_iface",fixture.replace("%%RULES%%","\n".join([mark,queue[0].replace("enp1s0","enp9s0")])),"1",False),
 ("coexist_wrong_order",fixture.replace("%%RULES%%","\n".join([queue[0],mark])),"1",False),
 ("standalone_foreign_mark",fixture.replace("%%RULES%%","\n".join(valid)),"0",False),
 ("coexist_foreign_chain",fixture.replace("%%RULES%%","\n".join(valid)).replace("\n}\n","\n    chain input { type filter hook input priority filter; policy accept; }\n}\n"),"1",False),
]
with tempfile.TemporaryDirectory(prefix="dim_transient_rollback_") as td:
 d=pathlib.Path(td)
 nft=d/"nft"
 nft.write_text(r'''#!/usr/bin/env bash
case "$*" in
  "list table inet directinternetmethod")
    cat "$MOCK_TABLE" ;;
  "-j list tables")
    printf '%s\n' '{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"directinternetmethod"}}]}' ;;
  "delete table inet directinternetmethod")
    touch "$MOCK_DELETED"; exit 0 ;;
  *) echo "UNEXPECTED_NFT $*" >&2; exit 90 ;;
esac
''',encoding="utf-8")
 nft.chmod(0o755)
 for name,table,coexist,should_delete in cases:
    table_file=d/"table.txt"
    table_file.write_text(table,encoding="utf-8")
    deleted=d/"deleted.txt";deleted.unlink(missing_ok=True)
    hosts=d/"hosts.txt";hosts.write_text("example.com\n")
    env=os.environ.copy()
    env.update({
      "PATH":str(d)+os.pathsep+env["PATH"],
      "MOCK_TABLE":str(table_file),"MOCK_DELETED":str(deleted)
    })
    script=f'''set -uo pipefail
TABLE=directinternetmethod
PHY=enp1s0
TAILSCALE_COEXIST={coexist}
CREATED_TABLE=1
CREATED_LINK=0
CREATED_STATE=0
QNUM=200
RUN_HOSTS="{hosts}"
NFQWS=/nonexistent/nfqws
CTRLD=/nonexistent/ctrld
NPID=0
CPID=0
pid_owned(){{ return 1; }}
remove_dns_link(){{ echo "UNEXPECTED_REMOVE_DNS" >&2;return 90; }}
'''+real_fragment+'''
cleanup_transient
rc=$?
printf 'ROLLBACK_RC=%s\\n' "$rc"
'''
    p=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True,timeout=9)
    assert p.returncode==0,(name,"script exit",p.returncode,p.stdout,p.stderr)
    expected_rc=0 if should_delete else 83
    assert f"ROLLBACK_RC={expected_rc}" in p.stdout,(name,"rollback code",expected_rc,p.stdout,p.stderr)
    assert deleted.exists()==should_delete,(name,"WRONG_NFT_DELETE",deleted.exists(),should_delete,p.stderr)
    assert "UNEXPECTED" not in p.stderr,(name,"UNEXPECTED MUTATION")
    print("PASS",name,"rollback-owned" if should_delete else "foreign-preserved")
print(f"PASS {len(cases)}/{len(cases)} transient rollback ownership tests; no live nft or processes")
