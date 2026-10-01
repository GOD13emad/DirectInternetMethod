# Direct Internet Method v1.4.0

## Direct multi-protocol engine

- Hardens the existing direct-IP DoH path by disabling ctrld's desktop OS-resolver fallback on upstream failure.
- Adds bounded HTTP/80 host split/desync.
- Keeps and formalizes TLS/SNI-oriented TCP/443 desync.
- Replaces Linux's previous UDP/443 reject/fallback with bounded QUIC UDP/443 desync.
- Uses zapret multi-strategy profiles so each traffic family has its own filter and method.
- Remains scoped to the existing host list.

## Non-goals / safety invariants

- No VPN or default-route tunnel.
- No HTTP/SOCKS/WinHTTP proxy.
- No physical adapter DNS mutation.
- No broad /1 route creation.
- No global all-domain packet manipulation.
- Stop/Recovery retain owned-resource and rollback checks.

## Method selection rationale

Official zapret documentation supports separate HTTP/TLS/QUIC strategies, hostlist scoping and multi-profile `--new` configuration, and recommends intercepting the minimum traffic required. The same documentation warns that IP fragmentation is unreliable on modern networks and that server-window tricks can slow sites, so those methods are not enabled by default. ctrld officially supports DoH, DoH3, DoQ and DoT, but live isolated tests on the current Linux network passed only the established direct-IP DoH path; DoH3, DoQ and DoT did not resolve successfully. They are therefore not activated merely for feature count. v1.4.0 does explicitly disable ctrld's desktop OS-resolver fallback so encrypted-DNS failure does not silently leak back to the physical resolver.

## Validation boundary

An authenticated Router Gateway tunnel remains router-model/firmware-dependent. QUIC configuration and runtime ownership are validated, but curl on the current Windows/Linux hosts does not expose HTTP/3, so a curl-based HTTP/3 end-to-end claim is not made.
