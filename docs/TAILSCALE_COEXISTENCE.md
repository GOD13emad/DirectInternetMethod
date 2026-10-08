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

## 2026-10-08 R211: Stateless recovery cannot assume ownership

**Negative-first security regression:** in the prior R210 code, the `recovery` action
without a saved owner-state file invoked exact-executable orphan cleanup *before*
checking whether a named nft table or DNS dummy link was foreign or stale.
The original scenario attempted two terminations, then rejected the foreign table.
A second test simulated a DNS link appearing after initial preflight and found
the legacy no-state branch could still enter unknown-link cleanup.

**R211 guard:** if no owner-state file exists, the helper checks nft and DNS-link
presence first and exits with `FOREIGN_OR_STALE_RESOURCE_WITHOUT_STATE`
without touching any process if either resource is present. With no such resources,
it may clean up exact-path orphaned Direct processes, but the no-state branch has
no nft or DNS-link deletion path at all. A final verify fails closed on late
resource appearance. This is a narrow change to Recovery, not a new release.

Tests: `tests/tailscale_recovery_missing_state_contract.py` 6/6 isolated
negative and control cases PASS, existing 12/12 table ownership and 8/8
owned-state cleanup regressions PASS. New Linux source archive:
8,196,051 bytes, SHA256
`6D517949DC044122C5E19B5F7C82608C9E798BD56741E6424EB5CD81D23155C3`;
prior R210 candidate ZIP SHA `7BEE8DC4...D6F8` is
**SUPERSEDED—DO NOT INSTALL**. No user network state, Tailscale,
RustDesk, installed backend or public v1.5.1 release changed.

Runtime caveat: No test of privileged production Start/Stop/Recovery,
real nft rule syntax, MagicDNS, TSMP and active RustDesk session has
been accepted. Windows Authenticode and Smart App Control-on installation
remain release-blocking. Never merge/release merely from mock QA PASS.

## 2026-10-08 R212 — nftables query-error tri-state safety guard

A negative-first isolated mock confirmed a false-green Recovery: `nft list table`
returned an access/read failure, but the old guard treated that as absence,
ran orphan cleanup and returned `{"ok":true,"state":"RECOVERED"}`.
The same confusion existed in Stop/Start preflight, cleanup and verify_clean.

The source candidate now separates **PRESENT** (0), **VERIFIED ABSENT**
(1; only after `nft -j list tables` succeeds and parses structurally)
and **UNKNOWN/UNREADABLE** (2). The third case fails with
`NFT_PRESENCE_UNVERIFIED` (exit 84) before mutation; cleanup/post-check
cannot treat it as success. A confirmed foreign table is never treated as
an owned table. `nft -j` is based on nftables documented JSON output,
but the root kernel behavior still requires an independently recoverable
authorized machine test.

Regression: 6/6 query-error negative/normal fixtures, 12/12 existing
nft ownership, 8/8 state-owned cleanup, 6/6 stateless Recovery, full
read-only Linux QA PASS. New unpublished Linux 19-member archive
8,198,183 bytes, SHA256
`F916D5ACAA0BF884C67D0B552FBE973DEFD13E305C945BD1154C70DB37678975`,
independently reproduced on Windows and Emad Linux. Supersedes unpublished
R211 SHA `6D517949...3155C3` (**DO NOT INSTALL**), preserved at
`C:\Users\Aa.Emad\source\repos\DIM_R212_GATE\BASELINE_34C4114.zip`.

This does NOT close root-privileged Start/Stop/Recovery, installed
Tailscale/RustDesk live reachability, trusted Windows signing/SAC Sandbox
or publication. Maintain PR #26 Draft and public v1.5.1 unchanged.

## 2026-10-08 R213 — failed-Start transient rollback preserves foreign nft state

**Negative-first verified on actual Kernel in an isolated namespace.**
The predecessor `fe501aa4` used `CREATED_TABLE=1` followed by unconditional
`nft delete table` from `cleanup_transient`. A foreign `ip daddr ... drop`
rule inserted after the app created its table was deleted along with the
whole table. No real user network or service was involved in this test.

**R213 one-objective guard:** `nft_table_transient_owned` checks that the
table is exactly a prefix of the program's own sequence (empty table,
empty output chain, optional Tailscale mark before queue, then three
physical-interface TCP/UDP queue rules). Added rules/chains, mixed physical
interfaces, wrong order, malformed tables or ambiguous query results
are foreign. The rollback checks table ownership twice, just before
deletion, and **preserves unknown/foreign state with an explicit error**.
Partially built app-owned tables are still cleaned, preventing unrelated
rollback degradation. Concurrent privileged modifications between final
check and deletion remain a residual TOCTOU risk, not a proven impossibility.

Offline tests: `tests/tailscale_transient_rollback_ownership_contract.py`
10/10 negative/control cases PASS. Isolated **real WSL2 Kernel** (6.18.33.2,
nftables v1.0.9, independent Network Namespace) proved valid empty, partial
and full rollback deletion and preservation of foreign rule; 4/4 PASS.
Existing Linux static/regression suite PASS on Emad Linux. No installed
backend, Windows service, Tailscale, RustDesk or physical route mutation.

New **unpublished source candidate Linux ZIP:** 8,200,436 bytes, 19 members,
SHA256 `58E9F55C8B65BB51C9274298CB67D4682AD3B15E4789D04D137E9FB020D5AF5C`.
Previous R212 SHA `F916D5AC...678975` is
**SUPERSEDED—DO NOT INSTALL**, preserved at
`C:\Users\Aa.Emad\source\repos\DIM_R213_GATE\BASELINE_FE501AA.zip`.
Windows v1.5.2 trusted Authenticode and SAC Sandbox, Linux actual
protected root Start/Stop/Recovery with TSMP/MagicDNS/RustDesk remain
separate **OPEN** acceptance gates. Do not promote PR26 or PR24.

## 2026-10-08 R214 — CI-enforced isolated real-kernel nft regression

**Single revision goal:** make the previously observed WSL2 Kernel nft
acceptance reproducible and mandatory in hosted Linux CI, without changing
the protected helper/runtime. New `tests/linux_nft_kernel_namespace_contract.py`
extracts actual `nft_table_presence`, `nft_table_owned`,
`nft_table_transient_owned`, `cleanup_state_owned`,
`cleanup_transient`, and `verify_clean` from the current helper.

Its privileged path creates an independent `unshare --net` namespace,
requires effective `CAP_NET_ADMIN`, proves that only isolated `lo`
exists and there are initially no nft tables, and only then exercises
the real Kernel. Direct execution in a host namespace or from a regular
Linux account fails closed. It never configures Tailscale, modifies
physical routes or queries user credentials.

Local WSL2 root child namespace (Kernel 6.18.33.2, nftables 1.0.9):
**6/6 PASS** — exact real owned table cleanup, empty/partial/full
transient rollback, foreign table preservation during rollback and
stateful cleanup. The unknown/foreign cases log the expected diagnostics
but do not delete the foreign table.

Linux-source CI adds an explicit mandatory isolated-kernel step using
`sudo -n` plus a source-only check. A runner without authorization,
namespace support or nftables cannot silently pass. This is evidence
for kernel rule grammar and ownership/rollback under a fresh namespace,
**not** active installed Linux/Tailscale/RustDesk Start/Stop/Recovery.
The package SHA, protected helper bytes and public v1.5.1 stable
remain unchanged from R213. PR #26 and dependent #24 remain Draft
until all installed/live/signing gates have proper acceptance.

## 2026-10-08 R215 — exclusive mutating-action lock

The Linux backend uses a shared system-wide `inet directinternetmethod`
nft table, runtime hostlist and per-user `state.json`. A source audit found
that root Start, Stop and Recovery could execute concurrently without an
exclusive action lock. This was a **confirmed guard absence**; a real
network/session collision was not claimed.

**One narrow repair:** before any mutating action's state/network logic,
require a single nonblocking OS `flock` on the root-only
`/run/directinternetmethod-action.lock` (0600). If held by another action,
return `ACTION_ALREADY_RUNNING` (86). If `flock` is absent or the lock
path is unsafe/unavailable, return `ACTION_LOCK_UNAVAILABLE` (85).
The kernel releases the lock when the action process exits, including
failures. Read-only status remains nonblocking.

New `tests/linux_mutation_action_lock_contract.py` proved mandatory
lock placement for all three mutating actions, rejected concurrent
execution, automatic unlock and rejection of a pre-existing malicious
symlink — **4/4 PASS**. The rest of the Linux source/mocked regression
suite also PASS. These tests are in the source/QA environment only:
actual root-installed Start/Stop/Recovery alongside live Tailscale and
RustDesk remain UNPROVEN, and flock does not serialize unrelated
privileged third-party modifications to nftables.

The new unpublished Linux 19-member candidate archive is 8,201,431
bytes, SHA256
`CA1664923662F2FCBC2A73BEB021D96A33809305A6E92A073F55632CE15938C2`.
Previous R214 unpublished archive SHA `58E9F55C...D5AF5C` is
**SUPERSEDED—DO NOT INSTALL**, preserved at
`C:\Users\Aa.Emad\source\repos\DIM_R215_GATE\BASELINE_D5C5364.zip`.
Public release v1.5.1 remains unchanged and Windows publication
still requires a trusted signer/SAC clean-Sandbox acceptance.
