# Tailscale split-network coexistence (Linux candidate)

**Status:** Source/contract candidate only until exact-SHA CI, privileged backend
deployment, and real route/DNS/peer-availability lifecycle acceptance complete.

This is not an exit-node bypass or a promise to reach every website. The
Windows v1.5.2 installer remains gated on legitimate code signing and
Smart App Control-on clean installation. Existing Windows/Tailscale DNS
coexistence is not yet independently accepted.

## Automatically eligible configuration

- `tailscale0` is up, Tailscale reports `BackendState=Running`.
- **No exit node** is selected (`ExitNodeStatus` is empty); Tailscale
  table 52 contains neither default nor split /1 IPv4 or IPv6 routes.
- The top default IPv4 route uses the ordinary physical interface.
- No other active tun/tap/wg/warp/zt interface exists, even if it is
  invisible to NetworkManager.
- Direct Method owns no previous dirty network state or foreign NFT/DNS
  resources. The existing Start/Recovery ownership guards still apply.
- Only `targeted` host mode is allowed in coexistence. `all-sites`
  remains intentionally blocked to avoid touching unmarked control traffic.

## Ownership and traffic rules

On eligible Tailscale split mode, Direct Method uses its existing
`nfqws`/nftables DPI engine **only** for outbound 80/443 TCP and
443 UDP routed through the physical interface. The nftables rule
matching Tailscale's reserved Linux bypass mark
`0x80000/0xff0000` is placed before all DPI queue rules so
marked tailscaled control/DERP traffic is not rewritten.

Coexistence intentionally does **not** add a DNS dummy interface,
start the bundled DNS daemon, modify systemd-resolved route domains,
change physical-adapter DNS, change Tailscale `--accept-dns`,
disconnect peers, change routes, or terminate tailscaled.
The host's existing resolver, including MagicDNS and split-DNS, is
preserved; **Direct DoH is not active in this coexistence mode**.
The GUI and persisted state must accurately show
`dnsMode=system-preserved` and `tailscaleCoexistence=true`,
with no invented `ctrldAlive`.

Standalone mode without Tailscale retains existing DoH + multiprotocol
DPI behavior. Exit nodes or unsupported VPNs are fail-closed, and no
global `all-sites` strategy is activated for split coexistence.

## Evidence and acceptance limits

- Pure Bash preflight matrix: safe split, no Tailscale, exit node JSON,
  exit /1 routes for IPv4/IPv6, tunnel-default route, stopped daemon,
  extra NetworkManager WireGuard, extra non-NetworkManager tunnel,
  and NetworkManager-invisible Tailscale.
- Pure Python GUI state fixtures: OFF, ACTIVE/DNS preserved, CONFLICT,
  STALE, and standard DoH ACTIVE.
- Emad Ubuntu physical default `enp1s0`, Tailscale peer-only route
  table 52, actual preflight `PASS` without changing route/DNS.
- Still required: a real authorized protected backend install (new helper
  bytes require legitimate polkit authorization), root-owned nft grammar
  execution, start/stop/recovery with actual peer/DERP connectivity and
  DNS/route baseline equality, Tailscale reconnect/exit-node transition,
  and safe system stop rollback tests.
- Saeid Linux Remote Commander became available again. Both Linux hosts
  have been audited with the read-only Tailscale/RustDesk probe. Actual
  protected Direct Method coexistence still has NOT been installed there.

## Technical references

- Tailscale packet marks:
  https://github.com/tailscale/tailscale/blob/main/tsconst/linuxfw.go
- Tailscale Linux DNS:
  https://tailscale.com/docs/reference/linux-dns
- Tailscale MagicDNS:
  https://tailscale.com/docs/features/magicdns
- systemd-resolved routing-domain precedence:
  https://man7.org/linux/man-pages/man8/systemd-resolved.8.html

Do not change Windows Smart App Control or Tailscale configuration to
circumvent policy restrictions. Versioned release and installed
acceptance remain separately blocked until independent proof exists.


## RustDesk compatibility and private peer baseline — 2026-10-08

Tailscale and RustDesk are installed on both Linux hosts. Each Tailscale
device sees one online peer. All three of the limited peer pings on each
host received DERP replies; no direct UDP path was established. This is
**usable encrypted Tailscale relay connectivity**, not evidence of a
direct P2P tunnel, and the CLI can exit nonzero when it was unable to
upgrade from DERP to direct UDP.

Route checks show the peer's private address uses `tailscale0`, while
normal public internet uses the host's physical NIC. These separate
paths are central to preserving RustDesk remote-access transport.

RustDesk's direct-IP listener on port 21118 was NOT accepting
connections on the two hosts in this audit. Saeid's user config had
`direct-server=Y`, while Emad's user config lacked an explicit
direct-server flag. The mere presence of RustDesk and Tailscale is not
proof that live RustDesk desktop sessions use Tailscale direct IP;
RustDesk may instead use its ordinary rendezvous/relay service.
Do not turn on an unrestricted remote desktop listener, change a
RustDesk password or firewall, or claim session success without an
authorized end-to-end session test.

Repeatable unprivileged diagnostics:
`python3 tests/tailscale_rustdesk_transport_audit.py --selftest`
for offline CI and
`python3 tests/tailscale_rustdesk_transport_audit.py --live --probe`
for limited read-only host evidence. Reports exclude peer addresses,
passwords, tokens and device identifiers.

Current source evidence:
`evidence/DIM_TAILSCALE_RUSTDESK_BASELINE_20261008.json`.
New Direct Method protected backend is NOT INSTALLED yet, so relay
preservation under live Direct DPI remains UNPROVEN.

### WireGuard data plane and NAT clarification

The follow-up test used Tailscale's TSMP ping (encrypted data path) in
both directions, not only DERP discovery. Both succeeded, confirming
the private tailnet data plane is reachable through a relay. This does
not prove that RustDesk accepts a desktop session over direct-IP mode:
the port 21118 listener remains unavailable on both machines.

A read-only Tailscale netcheck on both hosts reported outbound UDP
available. On Emad Linux MappingVariesByDestIP was FALSE; on Saeid Linux
it was TRUE, with no available router port-mapping protocol detected.
That pattern is consistent with a hard-NAT side and a DERP-only link,
but the precise network cause is not independently proven. Do not
change router UPnP/port forwards or remote desktop security defaults
without a separate safety assessment.

The optional transport diagnostic distinguishes discovery/DERP from
TSMP/WireGuard data-plane reachability. This baseline is captured in
`evidence/DIM_TAILSCALE_RUSTDESK_TSMP_NETCHECK_20261008.json`.
