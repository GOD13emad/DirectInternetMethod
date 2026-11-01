#!/usr/bin/env python3
"""Pure v1.5.7 ctrld targeted DoH policy generator (R516 candidate, NOT deployed).

Produces a loopback-only listener; exact targeted names use pinned HTTPS DoH,
all other names retain the pre-existing RFC1918 physical DNS as legacy upstream.
No network operations, files, service changes, install or global resolver edits.
Any future runtime controller MUST add native ownership/rollback and V&V first.
"""
from __future__ import annotations

import ipaddress

TARGET_DOMAINS = ("youtube.com", "googlevideo.com", "ytimg.com", "youtu.be")
TLS_DOH_ENDPOINT = "https://76.76.10.11/p0"
TLS_DOH_IP = "76.76.10.11"


def _physical_dns(address: str) -> str:
    if type(address) is not str or not address or address.strip() != address:
        raise ValueError("PHYSICAL_DNS_INVALID_TYPE_OR_SPACE")
    try:
        addr = ipaddress.IPv4Address(address)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError("PHYSICAL_DNS_NOT_LITERAL_IPV4") from exc
    # Accept only RFC1918 LAN resolvers: never silently configure public,
    # reserved, loopback or link-local fallback as part of targeted mode.
    lan = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(addr in network for network in lan):
        raise ValueError("PHYSICAL_DNS_NOT_RFC1918_LAN")
    return str(addr)


def build_secure_targeted_dns_config(physical_dns: str, listener_port: int = 10535) -> bytes:
    """Return deterministic ctrld v1.5.7 TOML with documented rule precedence.

    This pure function does not authorize use as system DNS.
    """
    router = _physical_dns(physical_dns)
    if type(listener_port) is not int or not 1024 <= listener_port <= 65535:
        raise ValueError("PORT_UNSAFE_OR_PRIVILEGED")
    # Validated on independent MMZ network as 127.0.0.1:53534.  Config is
    # rendered byte-for-byte in that form for the validated router/port pair.
    return f"""[service]
log_level = "error"
cache_enable = false
leak_on_upstream_failure = false
discover_mdns = false
discover_arp = false
discover_dhcp = false
discover_ptr = false
discover_hosts = false

[network.0]
cidrs = ["127.0.0.1/32"]
name = "LoopbackOnly"

[upstream.0]
bootstrap_ip = "76.76.10.11"
endpoint = "https://76.76.10.11/p0"
name = "EncryptedPinnedControlD"
timeout = 5000
type = "doh"
ip_stack = "v4"

[upstream.1]
endpoint = "{router}"
name = "ExistingPhysicalDNS"
timeout = 3000
type = "legacy"
ip_stack = "v4"

[listener.0]
ip = "127.0.0.1"
port = {listener_port}
restricted = false
allow_wan_clients = false

[listener.0.policy]
name = "EncryptedTargetedDoH_OriginalFallback"
rules = [
    {{"youtube.com" = ["upstream.0"]}},
    {{"*.youtube.com" = ["upstream.0"]}},
    {{"googlevideo.com" = ["upstream.0"]}},
    {{"*.googlevideo.com" = ["upstream.0"]}},
    {{"ytimg.com" = ["upstream.0"]}},
    {{"*.ytimg.com" = ["upstream.0"]}},
    {{"youtu.be" = ["upstream.0"]}},
    {{"*.youtu.be" = ["upstream.0"]}},
]
networks = [
    {{"network.0" = ["upstream.1"]}},
]
""".encode("ascii")


# Protected native per-link mode. The exact kernel link and IP are controller-owned.
# Never accept user-supplied arbitrary bind addresses or subnets.
OWNED_DNS_INTERFACE = "dimesd0"
OWNED_DNS_IPV4 = "172.31.254.59"
OWNED_DNS_PORT = 53534


def build_owned_interface_policy(physical_dns: str) -> bytes:
    """Render the tested targeted DoH policy for one owned /32 dummy interface.

    It is not a runtime migration or permission to alter a resolver. A native
    controller must prove ownership and arm an independent rollback first.
    """
    raw = build_secure_targeted_dns_config(physical_dns, OWNED_DNS_PORT)
    old_network = b'cidrs = ["127.0.0.1/32"]'
    old_listener = b'ip = "127.0.0.1"'
    if raw.count(old_network) != 1 or raw.count(old_listener) != 1:
        raise ValueError("SOURCE_POLICY_SHAPE_CHANGED")
    result = raw.replace(
        old_network, b'cidrs = ["172.31.254.59/32"]'
    ).replace(
        old_listener, b'ip = "172.31.254.59"'
    )
    if b'0.0.0.0' in result or b'192.168.8.1' in result and physical_dns != "192.168.8.1":
        raise ValueError("POLICY_BINDING_OR_ROUTER_DRIFT")
    return result
