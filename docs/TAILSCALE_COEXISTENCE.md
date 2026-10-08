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


## Read-only nftables ownership and stop/recovery simulation

The reserved Tailscale bypass mark `0x80000/0xff0000` has been
checked against Tailscale's upstream `tsconst/linuxfw.go`. The
coexistence-mode output NFT table is expected to include a marked
packet RETURN before the ordinary physical-NIC TCP/UDP web queue rules.

Two rootless automated test suites extract helper ownership and
cleanup functions without executing the actual helper entry point:

- `tests/tailscale_nft_ownership_contract.py`: six positive/negative
  nftables table match cases including missing/wrong bypass mark,
  foreign physical interface, and standalone behavior.
- `tests/tailscale_cleanup_ownership_contract.py`: five stop/recovery
  cases with mock `nft` and `ip` commands. Only a table that matches
  the current Direct Method state is deleted; on ownership mismatch
  the table AND recorded state remain untouched for safe diagnosis.

The tests do **not** prove kernel nft syntax or service operation,
because CAP_NET_ADMIN and a genuine authorized root install are
needed for that. Do not treat them as a substitute for an actual
Tailscale/RustDesk before-during-after live regression.

Confirmed host prestate: both Linux hosts' Tailscale peers reachable
over DERP discovery and encrypted TSMP data plane; Direct Method OFF,
the physical internet routes remain independent of tailscale0, and
there is no valid non-interactive sudo elevation available in the
connected command sessions. An operating system administrator
authorization is necessary before deploying changed root-owned
backend bytes. Do not bypass the OS privilege boundary.

## Safety regression closeout: NFT mark and renamed VPN — 2026-10-08

Two Tailscale nftables ownership errors were reproduced with isolated mock
fixtures before correction: an incorrect mask with the expected bypass
mark value could be counted as owned, and a bypass-mark rule placed after
an NFQUEUE rule could likewise be considered owned and removed during
Recovery. The repaired ownership guard requires the exact Tailscale mark
mask 0x00ff0000, bypass value 0x00080000 and the bypass rule before all
queue rules. Negative/positive nft ownership fixtures 8/8 PASS, mock
cleanup and Recovery fixtures 7/7 PASS on Linux; no kernel firewall table
was changed.

A third fail-closed bug was reproduced: NetworkManager could report an
active WireGuard profile as wireguard:private-office, whose device name
is not prefixed by wg. Earlier source treated that as safe coexistence.
The guard now checks VPN/TUN/WireGuard connection TYPE as well as device
name in both the privileged helper and GUI. Bash Tailscale split-mode
preflight fixtures 11/11 PASS, including renamed WireGuard; GUI state and
renamed-network negative regression PASS; actual Emad Linux read-only
preflight continues to permit the legitimate Tailscale-only split setup.

Current unreleased candidate Linux 1.5.2 ZIP SHA256:
294F0BD037F688828130B2B26C20807503BFDD57981A9224EC5AD510DA10664B
(size 8,195,241 bytes). Previous unreleased SHA 313FFD... is
SUPERSEDED and must not be installed. This document does not claim a
live nftables rule, Tailscale peer, RustDesk or Stop/Recovery PASS while
Direct Method is running. Windows signing and policy-on Sandbox remain
independent external release blockers.

## 2026-10-08 R210 strict nft ownership / pre-stop safety (candidate, NOT deployed)

Negative-first regression on the exact e40f94f predecessor demonstrated a destructive false positive:
a table retaining all three Direct Method queues but also containing a foreign `ip daddr ... drop`
rule was classified `OWNED`. A second negative-first test showed that an attempted process
kill occurred before foreign-table ownership was rejected. These are source-proven failure
modes; there was no mutation of either host's live nftables.

The successor candidate requires **exactly one** owned `inet directinternetmethod` output
chain, approved filter-hook priority/policy, exactly three fixed queue rules all bound to
the saved physical interface and, in Tailscale coexistence only, the exact earlier
`0x80000/0xff0000` return mark. It rejects unknown rules/chains, mixed interfaces,
extra queues, unrecognized DNS modes and missing state/physical context. Stop/Recovery
preflights table **and** DNS-link ownership before stopping the Direct engine, with a
second ownership check immediately before table deletion. Foreign material remains
untouched and the operation fails closed.

Proof: isolated Emad Linux QA `tests/tailscale_nft_ownership_contract.py` 12/12,
`tests/tailscale_cleanup_ownership_contract.py` 8/8; full Linux source-contract
suite PASS; independent Linux artifact reproduction from Windows and Emad Linux
exactly **8,196,074 bytes**, SHA256
`7BEE8DC4D8C63F4DAED82CB74A6636D7A989A472FC373E8613B5E60FE802D6F8`.
The previous unpublished e40f94f archive SHA `294F0BD0...DA10664B` is
**SUPERSEDED—DO NOT INSTALL**. Public v1.5.1 and all current installed runtimes unchanged.

Limitation: nft kernel grammar, true service lifecycle, concurrent table replacement,
Tailscale TSMP/MagicDNS/RustDesk while DPI runs, and actual OS-authorized backend
installation are still UNPROVEN. Strict table ownership deliberately fails closed
when the real nft output differs from the accepted schema; manual review is safer
than deleting an unrecognized table. Windows signing / Smart App Control remains
a separate mandatory release gate. This section does not authorize merge/release.
