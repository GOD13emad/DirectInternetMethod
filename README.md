# Direct Internet Method

**زن زندگی آزادی**

Standalone direct-connect application for Windows and Linux. It is independent of FreeNetHub and does not require ChatGPT for normal use.

## Windows
- Loopback ULA + ctrld 1.5.7/DoH + Windows NRPT + zapret/winws/WinDivert
- Dedicated Control Panel, icon, Desktop shortcut, Start Menu shortcut and uninstaller
- Start / Stop / Status / Recovery
- No VPN, HTTP/SOCKS proxy or default-route tunnel
- PowerShell 7 required
- Installer is currently not Authenticode-signed

## Linux
- Dedicated temporary DNS link + ctrld 1.5.7/DoH + systemd-resolved + nftables/NFQUEUE + zapret nfqws 72.13
- Dedicated GTK/Adwaita application with dove icon and «زن زندگی آزادی»
- Explicit Minimize / Maximize-Restore / Close controls and draggable standard header bar
- Applications-menu launcher, Desktop shortcut, icon and uninstaller
- Start / Stop / Refresh / Recovery
- No VPN, HTTP/SOCKS proxy or default-route tunnel

## Release artifacts
- `DirectInternetMethod_1.0.0_Windows_Setup.exe`
- `DirectInternetMethod_1.0.0_Linux_x86_64.zip`

Acceptance evidence is stored under `evidence/`.
