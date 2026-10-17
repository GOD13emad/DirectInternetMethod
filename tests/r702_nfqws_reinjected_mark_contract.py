#!/usr/bin/env python3
"""R702 reject queued nfqws reinjected traffic: source+owned-table policy.

Negative-first source fixture; no privileged commands, netfilter state,
network connections, DNS, VPN, or user settings are modified.
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
helper=(ROOT/"linux/app/direct_method_helper.sh").read_text("utf-8-sig")
mark='meta mark & 0x40000000 == 0x40000000 return'
tailscale='meta mark & 0xff0000 == 0x80000 return'
chain='nft "add chain inet $TABLE output { type filter hook output priority mangle; policy accept; }"'
owned='nft_table_owned(){'
transient='nft_table_transient_owned(){'
queue='nft add rule inet "$TABLE" output oifname "$PHY" tcp dport 80 ct original packets 1-6 queue num "$QNUM" bypass'
expected='nft "add rule inet $TABLE output '+mark+'"'
assert helper.count(expected)==1,"MISSING_UNIQUE_NFQWS_REINJECTED_MARK_EXCLUSION"
assert helper.count('nft "add rule inet $TABLE output '+tailscale+'"')==1,"TAILSCALE_MARK_RULE_DRIFT"
assert helper.index(chain)<helper.index(expected)<helper.index('nft "add rule inet $TABLE output '+tailscale+'"')<helper.index(queue),"RULE_ORDER_NOT_PRE_QUEUE"
assert helper.count(owned)==1 and helper.count(transient)==1
live=helper.split(owned,1)[1].split('\n}\n',1)[0]
rollback=helper.split(transient,1)[1].split('\n}\n',1)[0]
assert 'expected_count = 10 if coexist else 9' in live
assert 'offset = 4' in live
assert 'lines[3]' in live and 'lines[4]' in live
assert 'offset = 5' in live
assert 'r"meta mark & 0x0*40000000 == 0x0*40000000 return"' in live
assert 'r"meta mark & 0x0*40000000 == 0x0*40000000 return"' in rollback
assert rollback.index('patterns=[r"meta mark & 0x0*40000000')<rollback.index('patterns.append(r"meta mark & 0x0*ff0000')
assert '"$NFQWS" --dry-run "${NFQWS_ARGS[@]}"' in helper
assert 'meta mark & 0xff0000 == 0x80000 return' in helper
assert not re.search(r'(?m)^\s*(?:ip|nmcli)\s+route\s+(?:del|replace)\s+default',helper)
print("R702_SOURCE_INJECTED_MARK_PREQUEUE_AND_STRICT_OWNERSHIP_PASS")
