# Direct Internet Method

Standalone direct-connect application for Windows and Linux.

It is independent of FreeNetHub and does not require ChatGPT for normal use.

## Windows
Architecture: Loopback ULA + ctrld 1.5.7/DoH + Windows NRPT + zapret/winws/WinDivert.

The installer creates a dedicated Start Menu entry, Desktop shortcut, icon, Control Panel, Start/Stop/Status/Recovery actions, and uninstaller. It does not create a VPN, HTTP/SOCKS proxy, or default-route tunnel.

## Linux
Architecture: temporary dedicated DNS link + ctrld 1.5.7/DoH + systemd-resolved route-only DNS + nftables/NFQUEUE + zapret nfqws 72.13.

The Linux installer creates an Applications-menu launcher, Desktop shortcut, icon, Start/Stop/Refresh/Recovery UI, and uninstaller. It does not create a VPN, HTTP/SOCKS proxy, or default-route tunnel.

## Release artifacts
- Windows: DirectInternetMethod_1.0.0_Windows_Setup.exe
- Linux: DirectInternetMethod_1.0.0_Linux_x86_64.zip

See the evidence directory for acceptance records and hashes.
