#!/usr/bin/env python3
"""R247 negative-first selective-DNS lifecycle contract; no kernel/network mutations."""
from pathlib import Path
import ast, json, hashlib
R=Path(__file__).resolve().parents[1]
module=R/"linux/system/selective_dns.py"
helper=(R/"linux/app/direct_method_helper.sh").read_text()
ui=(R/"linux/app/direct_internet_method.py").read_text()
sysinst=(R/"linux/system/install_system.sh").read_text()
pkg=(R/"build_linux_package.py").read_text()
assert module.is_file(), "MISSING_ROOT_OWNED_SELECTIVE_DNS_CONTROLLER"
txt=module.read_text()
ast.parse(txt)
for operation in ("activate","commit","rollback","monitor","status"):
    assert "def "+operation+"(" in txt, operation
assert "194.225.152.10" in txt, "TESTED_UNENCRYPTED_UPSTREAM_NOT_PINNED"
assert "I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1" in txt, "EXPLICIT_USER_CONSENT_MISSING"
assert "127.0.0.1" in txt and "10535" in txt, "LOCALHOST_ONLY_FORWARDING_MISSING"
assert "systemd-run" in txt, "LIFECYCLE_OWNERSHIP_UNPROVEN"
assert "resolvectl" in txt and "tailscale0" in txt, "MAGICDNS_PRESERVATION_MISSING"
assert 'SELECTIVE_DNS_OPT_IN' in helper, "BACKEND_CONSENT_GUARD_MISSING"
assert 'selective_dns.py' in helper, "BACKEND_START_STOP_RECOVERY_NOT_COUPLED"
assert "I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1" in ui, "GUI_PRIVACY_DISCLOSURE_MISSING"
assert "selective_dns.py" in sysinst and "selective_dns.py" in pkg, "NOT_PACKAGED_OR_PRIVILEGED"
assert "restore" in txt and "monitor" in txt and "rollback" in txt, "RECOVERY_MONITOR_MISSING"
print("PASS R247 SELECTIVE_DNS_SOURCE_CONTRACT")
