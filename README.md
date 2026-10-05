# Direct Internet Method

**زن زندگی آزادی**

Standalone direct-connect application for Windows and Linux. It is independent of FreeNetHub and does not require ChatGPT for normal use.

## Direct Method — v1.5.0

v1.5.0 keeps the bounded v1.4 direct engine and expands explicit host-scoped coverage and diagnostics without creating a VPN, HTTP/SOCKS proxy, or default-route tunnel.

Built-in target coverage now includes the existing YouTube family plus Gemini, the requested adult-site/CDN target, OpenAI/ChatGPT, and GitHub. The application UI never exposes the adult brand name: it shows **Adult site**, and its live check is **off by default** and can be enabled or disabled by the user.

For sites not covered by the built-in catalog, **Custom Sites** accepts normalized domains/URLs (up to 256 entries). The **Strategy** panel provides Balanced, Compatibility, and Strong profiles. Scope defaults to **Targeted**; an opt-in **All Sites (experimental)** mode is available for unknown blocked domains when targeted coverage is insufficient. All Sites is not the default because broad DPI manipulation can reduce compatibility or speed.

Live-check results distinguish **PASS** (successful 2xx/3xx), **REACHABLE** (HTTP transport succeeded but the site returned an application response such as 403), and **FAIL** (transport did not complete). This matters because the Direct Method can address DNS/DPI interference but does not change public egress IP, account state, or server-side country/product policy.

Linux online update hardening in v1.5.0 requires three-way agreement between the GitHub API asset digest, the exact SHA256SUMS.txt entry, and the downloaded ZIP hash, with exact-one expected asset selection. Router Gateway health diagnostics also state their protocol boundary explicitly: PPTP TCP/1723 checks do not verify GRE/authentication, and L2TP/IPsec generic endpoint fallback does not claim UDP 500/4500 or authenticated tunnel success.

The engine is bounded by default to built-in + Custom Sites host lists and uses four direct method families:

- **Encrypted DNS (DoH):** ctrld uses the proven direct-IP Control D DoH path and explicitly disables OS-resolver leakage if the encrypted upstream fails.
- **HTTP/80 Host split:** hostlist-scoped TCP/80 DPI desynchronization using fake + multisplit around the HTTP method.
- **TLS/SNI desync:** hostlist-scoped TCP/443 fake + multidisorder with SNI-oriented split markers.
- **QUIC desync:** hostlist-scoped UDP/443 QUIC fake packets instead of globally blocking UDP/443.

The app still does **not** change the physical adapter DNS, create broad /1 or default routes, or configure a WinHTTP proxy. Start/Stop/Recovery own only the resources created by Direct Internet Method and retain exact rollback guards.

Deliberately not enabled by default: broad IP fragmentation, permanent small TCP-window tricks, automatic hostlist learning, All Sites scope, or a second DPI-bypass runtime. The accepted runtime exposes All Sites only as an explicit user choice; automatic hostlist learning is not enabled because upstream documentation requires broader inbound/outbound interception and extra false-positive controls.

A newer zapret2 Windows archive was evaluated separately but was **not shipped** after Microsoft Defender classified it as a Severe/Concrete Trojan. No exclusion or restore is used. The project instead reimplemented useful ideas (Custom Sites, strategy profiles, optional All Sites) on the already accepted runtime and added a CI hash gate for rejected components.

Secure-DNS resilience was also re-tested. The current direct-IP Control D endpoint `76.76.10.11/p0` produced real DNS answers. Alternate Control D, Google, Quad9 and Cloudflare fallback attempts timed out or reset on the validation network, so they were not promoted merely to increase option count; OS-resolver leakage remains disabled.

## Router Gateway

Router Gateway remains a separate non-privileged configuration panel for compatible modems/routers.

- L2TP/IPsec profiles are preferred.
- PPTP is available only as a legacy compatibility fallback.
- Copy-ready Server/IP, Username, Password and IPsec PSK fields.
- Bundled offline snapshot and best-effort online refresh.
- Numeric VPN Gate IPs where available.
- Endpoint tests do not change routes or VPN state.
- Private/loopback/link-local DNS results are rejected as possible interception.
- Guides for Generic VPN Client, TP-Link, ASUS and MikroTik.
- Provider catalog revision 2: 9 ready profiles from VPN Gate, VPNBook and Pilovali.
- Router support and authenticated tunnel success remain model/firmware-dependent.

## Windows 1.5.0

- Native WPF application; preferred startup geometry remains 1289 × 632 DIP with responsive footer.
- Fixed-command privileged Windows service; normal Start/Stop/Recovery do not prompt for administrator rights after install.
- Bundled protected PowerShell 7.6.6.
- Owned ctrld service + leak-closed direct-IP DoH + loopback ULA + NRPT.
- zapret/winws + WinDivert for bounded TCP/80, TCP/443 and UDP/443 direct DPI handling.
- Service-mediated in-app update with GitHub release digest + SHA256SUMS + downloaded-file SHA-256 verification.
- Installer is not Authenticode-signed.

## Linux 1.5.0

- Dedicated temporary DNS link + leak-closed ctrld DoH + systemd-resolved.
- Owned nftables table queues only host traffic classes needed by nfqws: TCP/80, TCP/443 and UDP/443.
- zapret/nfqws multi-profile direct engine for HTTP, TLS/SNI and QUIC.
- Protected backend is versioned 1.5.0 because the protected hostlist/version contract changed.
- GTK/Adwaita UI with Router Gateway integrated.
- After the one-time protected-backend upgrade, normal Start/Stop/Recovery remain non-interactive.

## Release artifacts

- `DirectInternetMethod_1.5.0_Windows_Setup.exe`
- `DirectInternetMethod_1.5.0_Linux_x86_64.zip`
- `SHA256SUMS.txt`

Acceptance and provenance evidence are stored under `evidence/`.
