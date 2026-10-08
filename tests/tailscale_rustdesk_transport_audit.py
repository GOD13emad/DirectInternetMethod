#!/usr/bin/env python3
"""Read-only RustDesk/Tailscale coexistence baseline; no auth material or peer IDs.

--selftest: offline deterministic checks, usable in public CI.
--live: query local Tailscale route, RustDesk listener/config (no traffic sent).
--live --probe: additionally send up to three Tailscale discovery pings and
one TCP handshake to peer port 21118; never reconfigure either application.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys

RUSTDESK_DIRECT_DEFAULT_PORT = 21118


def run(cmd: list[str], limit: float = 6.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=limit, check=False)


def interface_from_route(output: str) -> str:
    words = output.split()
    return words[words.index("dev") + 1] if "dev" in words and words.index("dev") + 1 < len(words) else ""


def ping_path_counts(text: str) -> dict[str, int]:
    lines = [x for x in text.splitlines() if x.startswith("pong from ")]
    return {
        "pongs": len(lines),
        "derp": sum(" via DERP(" in line for line in lines),
        "peerRelay": sum(" via peer-relay(" in line for line in lines),
        "direct": sum(bool(re.search(r" via [0-9.]+:[0-9]+", line)) for line in lines),
    }


def rustdesk_direct_setting() -> tuple[str, int]:
    enabled = "UNKNOWN"
    port = RUSTDESK_DIRECT_DEFAULT_PORT
    root = pathlib.Path.home() / ".config" / "rustdesk"
    if not root.is_dir():
        return enabled, port
    for f in sorted(root.glob("*.toml")):
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        flag = re.search(r"(?m)^\s*direct-server\s*=\s*['\"]?(Y|N|true|false)", txt, re.I)
        num = re.search(r"(?m)^\s*direct-access-port\s*=\s*['\"]?([0-9]{1,5})", txt)
        if flag:
            enabled = "YES" if flag.group(1).lower() in ("y", "true") else "NO"
        if num and 1 <= int(num.group(1)) <= 65535:
            port = int(num.group(1))
    return enabled, port


def local_port_listening(port: int) -> bool | None:
    try:
        p = run(["ss", "-H", "-ltn"], 3)
        if p.returncode:
            return None
        return any(
            addr.rsplit(":", 1)[-1] == str(port)
            for line in p.stdout.splitlines() for addr in line.split()[3:4]
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def selftest() -> None:
    assert interface_from_route("100.64.0.2 dev tailscale0 src 100.64.0.1") == "tailscale0"
    assert interface_from_route("1.1.1.1 via 192.168.20.1 dev enp1s0 src 192.168.20.6") == "enp1s0"
    assert interface_from_route("unreachable") == ""
    text = ("pong from peer (100.101.1.2) via DERP(waw) in 180ms\n"
            "pong from peer (100.101.1.2) via peer-relay(192.0.2.1:9999:vni:1) in 180ms\n"
            "pong from peer (100.101.1.2) via 192.0.2.5:41641 in 50ms\n"
            "direct connection not established")
    counts = ping_path_counts(text)
    assert counts == {"pongs": 3, "derp": 1, "peerRelay": 1, "direct": 1}, counts
    isolated = ping_path_counts("pong from peer via DERP(waw) in 45ms\n"
                                "pong from peer via DERP(fra) in 50ms\n"
                                "direct connection not established\n")
    assert isolated == {"pongs": 2, "derp": 2, "peerRelay": 0, "direct": 0}, isolated
    data_pongs = ping_path_counts("pong from peer via TSMP in 150ms\n")
    assert data_pongs["pongs"] == 1
    assert data_pongs["derp"] == 0 and data_pongs["direct"] == 0
    serialized = json.dumps({"status": "DERP_REACHABLE", "counts": isolated})
    assert not re.search(r"\b100\.\d+\.\d+\.\d+\b", serialized)
    print("PASS 7/7 RustDesk/Tailscale transport parsing and redaction fixtures")


def live(probe: bool) -> None:
    if not shutil.which("tailscale"):
        raise RuntimeError("TAILSCALE_CLI_NOT_INSTALLED")
    status = run(["tailscale", "status", "--json"], 7)
    if status.returncode:
        raise RuntimeError("TAILSCALE_STATUS_UNAVAILABLE")
    d = json.loads(status.stdout)
    peer_list = [
        peer for peer in d.get("Peer", {}).values()
        if peer.get("Online") and peer.get("TailscaleIPs")
    ]
    peer = peer_list[0].get("TailscaleIPs", [""])[0] if peer_list else None
    result: dict[str, object] = {
        "schema": 1,
        "status": "READ_ONLY",
        "tailscaleState": str(d.get("BackendState")),
        "exitNodeActive": bool(d.get("ExitNodeStatus")),
        "peerOnlineCount": len(peer_list),
        "tailnetDnsConfigured": bool(d.get("CurrentTailnet", {}).get("MagicDNSSuffix")),
        "rustdeskInstalled": bool(shutil.which("rustdesk")),
        "networkMutation": False,
        "secretsReadOrEmitted": False,
    }
    direct_flag, port = rustdesk_direct_setting()
    result["rustdeskDirectAccessFlag"] = direct_flag
    result["rustdeskDirectAccessPort"] = port
    result["localDirectPortListening"] = local_port_listening(port)
    if peer:
        r = run(["ip", "-4", "route", "get", peer], 3)
        if r.returncode:
            result["peerRouteInterface"] = "UNKNOWN"
        else:
            result["peerRouteInterface"] = interface_from_route(r.stdout)
        internet = run(["ip", "-4", "route", "get", "1.1.1.1"], 3)
        result["publicRouteInterface"] = interface_from_route(internet.stdout) if internet.returncode == 0 else "UNKNOWN"
        if probe:
            try:
                p = run(["tailscale", "ping", "--c=3", "--timeout=2s", peer], 13)
                counts = ping_path_counts(p.stdout)
                result["peerPing"] = counts
                # Tailscale CLI can exit 1 for a reachable DERP-only peer:
                # a successful direct UDP route is its default success criterion.
                result["tailnetDiscoveryReachable"] = counts["pongs"] > 0
                result["tailnetDirectEstablished"] = counts["direct"] > 0
                # A DISCO pong proves discovery, not WireGuard data plane.
                # TSMP tests the encrypted data path, including DERP fallback.
                dataplane = run(["tailscale", "ping", "--tsmp", "--c=2",
                                 "--until-direct=false", "--timeout=2s", peer], 9)
                tsmp = ping_path_counts(dataplane.stdout)
                result["tailnetDataPlaneReachable"] = (dataplane.returncode == 0 and
                                                      tsmp["pongs"] > 0)
            except (OSError, subprocess.TimeoutExpired):
                result["tailnetDiscoveryReachable"] = None
                result["tailnetDirectEstablished"] = None
                result["tailnetDataPlaneReachable"] = None
            try:
                with socket.create_connection((peer, port), timeout=2):
                    result["rustdeskRemoteDirectPort"] = "OPEN"
            except (OSError, TimeoutError):
                result["rustdeskRemoteDirectPort"] = "NOT_OPEN"
    else:
        result["peerRouteInterface"] = "NO_ONLINE_PEER"
    print(json.dumps(result, indent=2, sort_keys=True))
    # Diagnostics do not fail merely because the RustDesk port is not enabled.
    if result["tailscaleState"] != "Running" or result["exitNodeActive"]:
        raise SystemExit(10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--selftest", action="store_true")
    modes.add_argument("--live", action="store_true")
    parser.add_argument("--probe", action="store_true", help="Limited peer ping and TCP port handshake")
    a = parser.parse_args()
    if a.selftest:
        if a.probe:
            parser.error("--probe requires --live")
        selftest()
    else:
        live(a.probe)
