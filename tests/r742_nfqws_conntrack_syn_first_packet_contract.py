#!/usr/bin/env python3
"""R742 negative-first nfqws packet-0 conntrack and fail-closed nft ownership.

Rootless: fakes nft output and validates exact production Bash ownership
function. Never touches real nftables/network, DNS, services or Tailscale.
"""
from __future__ import annotations
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
OWNED_NAME="nft_table_owned"
TRANSIENT_NAME="nft_table_transient_owned"
SYN_FASTPATH='tcp flags & (syn | ack) == syn return'
MARK='meta mark & 0x40000000 == 0x40000000 return'
TS='meta mark & 0xff0000 == 0x80000 return'
QUEUE='tcp dport 443 ct original packets 1-6 queue num "$QNUM" bypass'
OWNED='nft_table_owned(){'
TRANSIENT='nft_table_transient_owned(){'

def fragment(name):
    matches=re.findall(r'^'+re.escape(name)+r'\(\)\{\n.*?^\}\n',
                      SOURCE,flags=re.M|re.S)
    if len(matches)!=1:
        raise AssertionError("R742_EXPECTED_UNIQUE_PRODUCTION_FUNCTION_"+name)
    return matches[0]

class ConntrackGuard(unittest.TestCase):
    def test_01_no_pure_syn_exclusion_prior_to_nfqueue(self):
        self.assertNotIn(SYN_FASTPATH,SOURCE,
                         "R742_SOURCE_BYPASSES_SYN_NFQWS_NEVER_CREATES_INTERNAL_CONNECTION")
        self.assertIn('nft add rule inet "$TABLE" output oifname "$PHY" '+QUEUE,
                      SOURCE)
        self.assertLess(SOURCE.index('meta mark & 0x40000000 == 0x40000000 return'),
                        SOURCE.index(QUEUE))
        self.assertLess(SOURCE.index('meta mark & 0xff0000 == 0x80000 return'),
                        SOURCE.index(QUEUE))

    def test_02_stable_owned_full_nft_requires_same_exact_mark_order_and_counts(self):
        own=fragment(OWNED_NAME)
        self.assertIn('expected_count = 10 if coexist else 9',own)
        self.assertNotIn('syn_rule',own)
        self.assertNotIn('tcp flags',own)
        self.assertIn('lines[offset + index]',own)
        self.assertIn('len(lines) != expected_count',own)

    def test_03_transient_exact_owner_rejects_foreign_early_syn_rule(self):
        fn=fragment(TRANSIENT_NAME)
        self.assertNotIn('patterns.append(dev+r" tcp dport 443 tcp flags',fn)
        self.assertIn('for proto,port in',fn)
        self.assertIn('len(rules)>len(patterns)',fn)

    def test_04_output_has_no_unconditional_slowdown_or_tailscale_mutation(self):
        self.assertIn('ct original packets 1-6 queue num "$QNUM" bypass',SOURCE)
        self.assertIn('meta mark & 0xff0000 == 0x80000 return',SOURCE)
        self.assertIn('meta mark & 0x40000000 == 0x40000000 return',SOURCE)
        self.assertNotIn('ip route replace default',SOURCE)
        self.assertIn('nft_table_owned "$phy"',SOURCE)

    def test_05_original_profile_and_user_whitelist_remain_targeted(self):
        self.assertIn('--hostlist-domains=youtube.com,youtu.be,googlevideo.com',SOURCE)
        self.assertIn('--dpi-desync=multisplit --dpi-desync-split-pos=1',SOURCE)
        self.assertIn('TAILSCALE_ALL_SITES_UNSUPPORTED',SOURCE)

    def test_06_production_owner_semantics_actual_fake_full_and_bad_tables(self):
        extract="\n".join(fragment(name) for name in
                          ('state_value','nft_table_owned','nft_table_transient_owned'))
        full='''table inet directinternetmethod {
chain output {
type filter hook output priority mangle; policy accept;
meta mark & 0x40000000 == 0x40000000 return
meta mark & 0x00ff0000 == 0x00080000 return
oifname "enp1s0" tcp dport 80 ct original packets 1-6 queue flags bypass to 200
oifname "enp1s0" tcp dport 443 ct original packets 1-6 queue flags bypass to 200
oifname "enp1s0" udp dport 443 ct original packets 1-6 queue flags bypass to 200
}
}
'''
        tests=[
           ('owned',full,True,True),
           ('old_fastpath_foreign',full.replace(
                'oifname "enp1s0" tcp dport 80',
                'oifname "enp1s0" tcp dport 443 '+SYN_FASTPATH+'\n'
                'oifname "enp1s0" tcp dport 80',1),False,False),
           ('foreign_missing_injection_guard',full.replace(
               'meta mark & 0x40000000 == 0x40000000 return\n',''),False,False),
           ('foreign_wrong_interface',full.replace(
               'oifname "enp1s0" tcp dport 443 ct',
               'oifname "wrong0" tcp dport 443 ct',1),False,False),
           ('foreign_added_drop',full.replace('oifname "enp1s0" udp dport',
             'ip daddr 203.0.113.1 drop\n'
             'oifname "enp1s0" udp dport',1),False,False),
        ]
        with tempfile.TemporaryDirectory(prefix="r742-nfqws-owner-no-net-") as td:
            base=pathlib.Path(td)
            nft=base/"nft"
            nft.write_text('#!/bin/sh\n[ "$*" = "list table inet directinternetmethod" ] || exit 12\n'
                           'cat "$R742_MOCK_TABLE"\n',encoding="utf8")
            nft.chmod(0o700)
            table=base/"table"
            state=base/"state.json"
            state.write_text(json.dumps({"dnsMode":"system-preserved"}),encoding="utf8")
            env=dict(os.environ,PATH=str(base)+os.pathsep+os.environ.get('PATH',''),
                     R742_MOCK_TABLE=str(table))
            for name,contents,owned,transient in tests:
                table.write_text(contents,encoding="utf8")
                code='set -u\nTABLE=directinternetmethod\nSTATE='+str(state)+'\n'+extract+'''
if nft_table_owned enp1s0;then echo OWNED=1;else echo OWNED=0;fi
if nft_table_transient_owned enp1s0 1;then echo TRANSIENT=1;else echo TRANSIENT=0;fi
'''
                p=subprocess.run(['bash','-c',code],env=env,
                                 text=True,capture_output=True,timeout=12)
                self.assertEqual(p.returncode,0,(name,p.stdout,p.stderr))
                self.assertIn("OWNED="+str(int(owned)),p.stdout,(name,p.stdout))
                self.assertIn("TRANSIENT="+str(int(transient)),p.stdout,(name,p.stdout))

if __name__=="__main__":
    unittest.main(verbosity=1)
    print("R742_SYN_EARLY_NFQUEUE_AND_ROOTLESS_FAILCLOSED_OWNERSHIP_PASS")
