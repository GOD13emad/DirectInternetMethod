# Direct Internet Method

**زن زندگی آزادی**

Standalone direct-connect application for Windows and Linux. It is independent of FreeNetHub and does not require ChatGPT for normal use.

## Windows 1.2.1
- Native WPF application + fixed-command privileged Windows service
- Bundled protected PowerShell 7.6.6; no external PowerShell dependency
- Normal Start / Stop / Recovery without administrator prompt after installation
- Owned demand-start ctrld 1.5.7 service + DoH + Loopback ULA + NRPT
- zapret/winws + WinDivert for hostlist-scoped TCP/443 DPI handling
- Dedicated icon, Desktop shortcut, Start Menu shortcut and uninstaller
- No VPN, HTTP/SOCKS proxy or default-route tunnel
- Direct in-app Windows update through the installed privileged service; GitHub asset digest, SHA256SUMS.txt and downloaded-file SHA-256 must all match
- Normal Windows updates after v1.2.1 require no UAC; the one-time transition from v1.1.0 may require UAC
- Installer is not Authenticode-signed

## Linux 1.2.1
- Dedicated temporary DNS link + ctrld 1.5.7/DoH + systemd-resolved + nftables/NFQUEUE + zapret nfqws 72.13
- Dedicated GTK/Adwaita application with dove icon and «زن زندگی آزادی»
- Applications-menu launcher, Desktop shortcut, icon and uninstaller
- Start / Stop / Refresh / Recovery without admin prompt during normal use
- No VPN, HTTP/SOCKS proxy or default-route tunnel

## Release artifacts
- `DirectInternetMethod_1.2.1_Windows_Setup.exe`
- `DirectInternetMethod_1.2.1_Linux_x86_64.zip`
- `SHA256SUMS.txt`

Acceptance evidence is stored under `evidence/`.
