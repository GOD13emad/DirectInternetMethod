# Direct Internet Method

**زن زندگی آزادی**

Standalone connectivity application for Windows and Linux. It is independent of FreeNetHub and does not require ChatGPT for normal use.

## Direct Method
The original Direct Method remains a direct DNS + DPI-bypass path. It does **not** create a VPN, HTTP/SOCKS proxy, or default-route tunnel.

## Router Gateway — v1.3.2
v1.3.2 retains the non-privileged Router Gateway panel and provider-catalog revision 2, and fixes the Windows table visibility defect from v1.3.0/v1.3.1.

- L2TP/IPsec profiles are preferred.
- PPTP is available only as a legacy compatibility fallback.
- Copy-ready Server/IP, Username, Password and IPsec PSK fields.
- Bundled offline snapshot so the panel still works when provider websites are blocked.
- Refresh from the project manifest, plus best-effort refresh of rotating credentials.
- Numeric VPN Gate IPs are supplied where available to reduce DDNS-filtering dependency.
- Endpoint health tests do not change routes or VPN state.
- Public endpoints resolving to private/loopback/link-local addresses are rejected as possible DNS interception.
- Router guides included for Generic VPN Client, TP-Link, ASUS and MikroTik.
- Provider catalog revision 2 includes 9 ready profiles from 3 independent providers: VPN Gate, VPNBook and Pilovali.
- Unselected Router Gateway rows use explicit dark backgrounds, dark headers and readable foreground text; all loaded profiles remain visible.
- Additional independently researched providers (HideSSH, VPN Jantit, TCPVPN) require per-user account generation and are intentionally not represented as fake ready credentials.
- The app does not blindly log into or reconfigure the router; exact VPN Client support depends on router model and firmware.

## Windows 1.3.2
- Native WPF application + fixed-command privileged Windows service.
- Bundled protected PowerShell 7.6.6; no external PowerShell dependency.
- Normal Start / Stop / Recovery and Router Gateway use without administrator prompt after installation.
- Owned demand-start ctrld service + DoH + Loopback ULA + NRPT.
- zapret/winws + WinDivert for hostlist-scoped TCP/443 DPI handling.
- Direct in-app update through the installed privileged service with release digest + SHA256SUMS + downloaded-file SHA-256 verification.
- Installer is not Authenticode-signed.

## Linux 1.3.2
- Dedicated temporary DNS link + ctrld/DoH + systemd-resolved + nftables/NFQUEUE + zapret nfqws.
- GTK/Adwaita application with Router Gateway integrated into the same UI.
- Existing protected 1.2.1-compatible backend is reused because Router Gateway is user-space only; upgrading this feature does not require needless backend replacement.
- Start / Stop / Refresh / Recovery and Router Gateway do not require admin during normal use.

## Release artifacts
- `DirectInternetMethod_1.3.2_Windows_Setup.exe`
- `DirectInternetMethod_1.3.2_Linux_x86_64.zip`
- `SHA256SUMS.txt`

Acceptance and provenance evidence are stored under `evidence/`.
