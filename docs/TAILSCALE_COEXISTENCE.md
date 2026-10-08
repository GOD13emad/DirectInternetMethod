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
- Saeid Linux Remote Commander connectivity is temporarily unavailable;
  no claim of deployed coexistence there.

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
