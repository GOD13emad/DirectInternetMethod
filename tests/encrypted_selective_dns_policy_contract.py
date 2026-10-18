#!/usr/bin/env python3
"""R516 negative-first proof of the pure encrypted selective-DNS policy.

Do not change system DNS, Tailscale, ctrld processes or product files.
"""
from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / "linux/system/encrypted_selective_policy.py"
spec = importlib.util.spec_from_file_location("dim_r516_secure_doh", POLICY)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
passed = 0


def check(label: str, condition: bool) -> None:
    global passed
    assert condition, label
    passed += 1
    print("PASS_R516", label)


invalid_dns = [
    None, 123, "", " ", "192.168.8.1 ", " 192.168.8.1",
    "192.168.8.1\n[listener.9]", "192.168.8.256", "fe80::1",
    "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0",
    "8.8.8.8", "76.76.10.11", "100.100.100.100",
    "255.255.255.255", "192.0.2.1",
]
for value in invalid_dns:
    try:
        module.build_secure_targeted_dns_config(value, 53534)
    except (ValueError, TypeError):
        check("reject_invalid_physical_dns_" + repr(value), True)
    else:
        raise AssertionError("UNSAFE_DNS_ACCEPTED " + repr(value))

for port in (None, False, True, "53534", 0, 53, 1023, -1, 65536, 99999, 3.14):
    try:
        module.build_secure_targeted_dns_config("192.168.8.1", port)
    except (ValueError, TypeError):
        check("reject_invalid_listener_port_" + repr(port), True)
    else:
        raise AssertionError("UNSAFE_PORT_ACCEPTED " + repr(port))

body = module.build_secure_targeted_dns_config("192.168.8.1", 53534)
j = tomllib.loads(body.decode("ascii"))
check("exact_validated_R516_runtime_config_SHA", hashlib.sha256(body).hexdigest().lower() ==
      "46f63805fe53b5cedc6b7d4df242bbf13a6ca8229bb9072058be8de304697954")
check("exact_second_independent_Emad_config_SHA", hashlib.sha256(
      module.build_secure_targeted_dns_config("192.168.20.1", 53535)).hexdigest().lower() ==
      "3cc90962571ac80220b1a947c901709c64cd0da0bd63ee5beb6d1ec8781615dc")
check("doh_tls_pinned_endpoint", j["upstream"]["0"]["endpoint"] ==
      "https://76.76.10.11/p0" and j["upstream"]["0"]["type"] == "doh")
check("bootstrap_ip_and_ipv4_only", j["upstream"]["0"]["bootstrap_ip"] == "76.76.10.11"
      and j["upstream"]["0"]["ip_stack"] == "v4")
check("physical_fallback_only_router", j["upstream"]["1"]["endpoint"] ==
      "192.168.8.1" and j["upstream"]["1"]["type"] == "legacy")
check("listener_loopback_only", j["listener"]["0"]["ip"] == "127.0.0.1" and
      j["listener"]["0"]["port"] == 53534)
check("listener_no_wan", j["listener"]["0"]["allow_wan_clients"] is False)
check("no_discovery_listeners", all(j["service"][name] is False for name in
      ("discover_mdns", "discover_arp", "discover_dhcp", "discover_ptr", "discover_hosts")))
check("no_leak_on_upstream_failure", j["service"]["leak_on_upstream_failure"] is False)
rules = j["listener"]["0"]["policy"]["rules"]
check("exact_target_domain_rules", len(rules) == 2 * len(module.TARGET_DOMAINS)
      and all(list(item.values()) == [["upstream.0"]] for item in rules))
check("target_names_and_subdomains", [list(item.keys())[0] for item in rules] ==
      [z for name in module.TARGET_DOMAINS for z in (name, "*." + name)])
check("default_fallback_unchanged_physical_dns", j["listener"]["0"]["policy"]["networks"] ==
      [{"network.0": ["upstream.1"]}])
check("no_unencrypted_third_party_upstream", b"194.225.152.10" not in body)
check("no_global_wildcard_catchall_rules", not any("*" == list(item)[0] for item in rules))
check("valid_other_private_router", b'endpoint = "10.0.0.1"' in
      module.build_secure_targeted_dns_config("10.0.0.1"))
check("valid_other_private_router_172", b'endpoint = "172.16.1.1"' in
      module.build_secure_targeted_dns_config("172.16.1.1"))
source = POLICY.read_text("utf-8")
check("pure_module_no_root_or_network_actions",
      not any(token in source for token in
              ('import subprocess', 'import os', 'systemctl start', 'resolvectl dns',
               'nft add', 'ip route add', 'socket.connect')))
print(f"R516_NEGATIVE_FIRST_OFFLINE_PASS_{passed}_OF_{passed}_NO_HOST_MUTATIONS")
