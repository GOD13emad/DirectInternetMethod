# Direct Internet Method v1.5.0

## Site coverage and live diagnostics

- Keeps the accepted v1.4.0 bounded direct engine: leak-closed direct-IP DoH, HTTP/80 host split, TLS/SNI TCP/443 desync and QUIC UDP/443 desync.
- Adds explicit host-scoped coverage for the Gemini web application and the requested adult-site/CDN target instead of enabling global all-domain DPI manipulation.
- Adds Gemini to the in-app live checks.
- Adds an **Adult site** live check with a per-user on/off switch. It defaults OFF and the adult brand/domain is not displayed in the application UI.
- Live checks now distinguish PASS (2xx/3xx), REACHABLE (HTTP transport succeeded but the server returned a non-success application status such as 403), and FAIL (transport failure).
- Gemini/adult diagnostics are non-gating: they never roll back a successful core Direct Method Start. Core lifecycle acceptance still uses owned-resource health plus the established YouTube/OpenAI/GitHub checks.
- Linux updater integrity now requires exact-one expected assets and three-way SHA-256 agreement: GitHub API digest == SHA256SUMS.txt == downloaded ZIP.
- Router Gateway endpoint tests no longer imply protocol authentication: PPTP reports TCP/1723 control reachability with GRE/authentication unverified; L2TP/IPsec generic fallback explicitly states UDP 500/4500/authentication are not verified.

## Evidence-first scope

The v1.4.0 host list contained only YouTube-related domains. Linux baseline testing therefore showed Gemini was already network-reachable but returned HTTP 403, while the requested adult site timed out before a useful HTTP response. Explicit hostlist targeting is the minimum-sufficient next step because zapret applies desync only to listed hosts; auto-hostlist/global interception is intentionally not enabled unless explicit targeting proves insufficient in live validation.

The Direct Method does not change public egress IP. It can mitigate DNS/DPI interference, but it cannot guarantee access when a remote service itself rejects an IP range, account, age/region policy, or product availability.

## Preserved invariants

- No VPN or default-route tunnel.
- No HTTP/SOCKS/WinHTTP application proxy.
- No physical-adapter DNS mutation.
- No broad /1 route creation.
- Hostlist-scoped DPI handling only.
- Stop/Recovery retain owned-resource and rollback checks.

## Validation boundaries

An authenticated Router Gateway tunnel remains router-model/firmware-dependent. HTTP/3 application-level E2E remains separately unproven where the installed curl lacks HTTP/3. The Windows installer is not Authenticode-signed.
