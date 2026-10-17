#!/usr/bin/env python3
"""R711 -> R742: original SYN must reach bounded NFQUEUE to seed nfqws conntrack.

The old R711 optimization bypassed SYN, which upstream nfqws documents as
required for tracking TCP direction/sequence. Regression is source-only;
independent physical queue validation remains a separate release gate.
"""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
h=(ROOT/"linux/app/direct_method_helper.sh").read_text(encoding="utf8")
def verify(value,name):
    if not value:raise AssertionError("R742_"+name)
def fragment(name):
    results=re.findall(r'^'+re.escape(name)+r'\(\)\{\n.*?^\}\n',
                       h,flags=re.S|re.M)
    verify(len(results)==1,"MISSING_UNIQUE_"+name)
    return results[0]
syn='tcp flags & (syn | ack) == syn return'
verify(syn not in h,"ORIGINAL_TCP443_SYN_BYPASS_MUST_NOT_EXIST")
queue='nft add rule inet "$TABLE" output oifname "$PHY" tcp dport 443 ct original packets 1-6 queue num "$QNUM" bypass'
mark='nft "add rule inet $TABLE output meta mark & 0x40000000 == 0x40000000 return"'
tailscale='nft "add rule inet $TABLE output meta mark & 0xff0000 == 0x80000 return"'
verify(h.count(queue)==1 and h.count(mark)==1 and h.count(tailscale)==1,
       "ONE_INJECTED_MARK_ONE_TAILSCALE_MARK_ONE_QUEUE")
verify(h.index(mark)<h.index(tailscale)<h.index(queue),
       "BYPASS_MARKS_MUST_APPEAR_BEFORE_QUEUE")
verify('R742: nfqws internal conntrack needs the original SYN' in h,
       "ROOT_SOURCE_BOUND_TO_PACKET_ZERO_DESIGN")
own=fragment("nft_table_owned")
trans=fragment("nft_table_transient_owned")
verify('expected_count = 10 if coexist else 9' in own,
       "COMPLETE_TABLE_NEW_PACKET_ZERO_EXACT_ROW_COUNT")
verify('syn_rule' not in own and 'tcp flags' not in own,
       "OWNERSHIP_MUST_NOT_REQUIRE_FOREIGN_SYN_EXEMPTION")
verify('tcp flags' not in trans,"TRANSIENT_CLEANUP_MUST_NOT_REQUIRE_OLD_BYPASS")
verify('patterns.append(r"meta mark & 0x0*ff0000' in trans,
       "TAILSCALE_MARK_STILL_STRICT")
verify('len(rules)>len(patterns)' in trans and
       'not all(re.fullmatch(pattern,actual)' in trans,
       "TRANSIENT_FOREIGN_RULE_FAIL_CLOSED")
verify('ROLLBACK_FOREIGN_NFT_PRESERVED' in h and
       'NFT_TABLE_OWNERSHIP_MISMATCH' in h,"SAFETY_REFUSES_FOREIGN_NFT")
for protocol in ('tcp dport 80','tcp dport 443','udp dport 443'):
    verify(protocol+' ct original packets 1-6 queue num "$QNUM" bypass' in h,
           "BOUND_AND_FAILOPEN_"+protocol)
print("R742_SYNS_SENT_IN_BOUNDED_NFQUEUE_STRICT_MARKED_TABLE_SOURCE_PASS")
