#!/usr/bin/env python3
"""R711 TCP443 original SYN packets bypass NFQUEUE before L7 nfqws queues.

Negative-first source contract, no root, real netfilter, network or user state.
Ensures the SYN optimization is narrowly limited to original WAN TCP443 and
the independent owner-only Stop/Recovery paths recognize only exact rules.
"""
from pathlib import Path
import re

BASE=Path(__file__).resolve().parents[1]
h=(BASE/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
SYN='tcp flags & (syn | ack) == syn return'
def verify(yes, name):
    if not yes:raise AssertionError("R711_"+name)
def fragment(name):
    match=re.findall(r'^'+re.escape(name)+r'\(\)\{\n.*?^\}\n',
                     h,flags=re.S|re.M)
    verify(len(match)==1,"SHELL_FRAGMENT_NOT_EXACT_"+name)
    return match[0]

start=fragment("start_engine") if "start_engine(){" in h else h
print("R711_SOURCE_CURRENT_HEALTH_TARGET_PATH")
rule='nft "add rule inet $TABLE output oifname \\"$PHY\\" tcp dport 443 '+SYN+'"'
verify(h.count(rule)==1,"SYNSKIP_RULE_NOT_UNIQUE")
a=h.index('nft "add rule inet $TABLE output meta mark & 0x40000000 == 0x40000000 return"')
b=h.index('nft "add rule inet $TABLE output meta mark & 0xff0000 == 0x80000 return"')
c=h.index(rule)
queue=h.index('nft add rule inet "$TABLE" output oifname "$PHY" tcp dport 443 ct original packets 1-6 queue num "$QNUM" bypass')
verify(a<b<c<queue,"SYN_BEFORE_QUEUE_AFTER_BYPASS_MARKS")
verify(h.count(SYN)==1,"SYN_MATCH_EXACT_NARROWED")
own=fragment("nft_table_owned")
trans=fragment("nft_table_transient_owned")
verify('expected_count = 11 if coexist else 10' in own,"COMPLETE_OWNED_ROW_COUNT")
verify('tcp flags & \\(syn \\| ack\\) == syn return' in own,"COMPLETE_OWNED_SYN_EXACT_MATCH")
verify('tcp flags & \\(syn \\| ack\\) == syn return' in trans,"TRANSIENT_OWNED_SYN_EXACT_MATCH")
verify('patterns.append(' in trans and
       trans.index('tcp flags & \\(syn \\| ack\\)')<
       trans.index('for proto,port in'),"TRANSIENT_SEQUENCE")
verify('meta mark & 0x0*40000000' in own and 'meta mark & 0x0*ff0000' in own,"PRESERVE_MARKS")
verify('ROLLBACK_FOREIGN_NFT_PRESERVED' in h,"FAIL_CLOSED_TRANSIENT")
verify('NFT_TABLE_OWNERSHIP_MISMATCH' in h,"FAIL_CLOSED_STEADY")
verify('tcp dport 80 ct original packets 1-6 queue' in h and
       'udp dport 443 ct original packets 1-6 queue' in h,"PRESERVE_OTHER_PROTOCOLS")
print("R711_EXACT_OWNED_TCP443_SYN_FASTPATH_SOURCE_PASS")
