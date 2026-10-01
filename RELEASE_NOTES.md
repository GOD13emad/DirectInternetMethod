# Direct Internet Method v1.3.0

Router Gateway release. The accepted Direct DNS/DPI architecture remains intact; the new path supplies modem/router configuration data without automatically mutating router firmware or the host default route.

## Router Gateway
- Added L2TP/IPsec profiles with copy-ready server/IP, username, password and IPsec PSK.
- Added PPTP only as an explicitly labeled legacy fallback.
- Added offline-first bundled provider data and cached refresh.
- Added current VPN Gate L2TP/IPsec data and rotating VPNBook PPTP snapshot/refresh path.
- Added Generic, TP-Link, ASUS and MikroTik setup guidance.
- Added non-mutating endpoint health testing.
- Added a fail-closed private/reserved-address guard after live testing exposed DNS interception of a public PPTP hostname.

## Windows
- Router Gateway integrated into the native WPF UI.
- Service/network runtime remains unchanged from the previously accepted direct path.
- Full self-contained payload build, service self-test and Windows regression contract are required before packaging.
- Installer remains unsigned by Authenticode.

## Linux
- Router Gateway integrated into the GTK/Adwaita UI.
- Router Gateway is user-space only; the existing protected backend remains 1.2.1-compatible to avoid unnecessary privilege prompts.
- Python compile, legacy Linux contract, Router Gateway contract and runtime smoke are required.

## Validation boundaries
- Endpoint health is a reachability heuristic, not a complete L2TP/IPsec or PPTP authentication handshake.
- Exact VPN Client support varies by router model/firmware.
- PPTP should not be used when L2TP/IPsec or OpenVPN is available.

## Release integrity
Release artifacts are generated only after the source/contract/runtime gates pass. Publication is promoted to FINAL only after public re-download and independent SHA-256 verification.
