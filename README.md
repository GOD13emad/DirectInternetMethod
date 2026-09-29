# Direct Internet Method

Standalone Windows and Linux application for direct DNS + DPI access. Normal use does not depend on FreeNetHub or ChatGPT.

## Branding
The application uses the freedom-dove logo and the Persian slogan **زن زندگی آزادی**.

## Windows
- Dedicated installer, Start Menu entry, Desktop shortcut, icon, Control Panel and uninstaller.
- Start / Stop / Refresh / Recovery.
- Architecture: Loopback ULA + ctrld 1.5.7/DoH + Windows NRPT + zapret/winws/WinDivert.
- No VPN, HTTP/SOCKS proxy, or default-route tunnel.
- Requires PowerShell 7.
- Installer is currently not Authenticode-signed.

## Linux x86_64
- Dedicated installer script, Applications launcher, Desktop shortcut, icon and uninstaller.
- Movable/resizable standard libadwaita window with HeaderBar window controls.
- Start / Stop / Refresh / Recovery.
- Architecture: dedicated temporary DNS link + ctrld 1.5.7/DoH + systemd-resolved route-only DNS + nftables/NFQUEUE + zapret nfqws 72.13.
- No VPN, HTTP/SOCKS proxy, or default-route tunnel.

## Release files
- `DirectInternetMethod_1.0.0_Windows_Setup.exe`
- `DirectInternetMethod_1.0.0_Linux_x86_64.zip`

## SHA-256
- Windows: `1D32D0619EDC85C5B11405218087154D53907C06D650843F7375092B2FC7C602`
- Linux: `5940CC754108189A67627C4DACAF10BEBF0A4613E0B203D6004548CC279A3826`

Acceptance evidence is stored in `evidence/`.
