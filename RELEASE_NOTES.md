# Direct Internet Method v1.0.0

Standalone Windows + Linux release.

## Windows
- Dedicated application/control panel with dove icon and «زن زندگی آزادی»
- Desktop + Start Menu shortcuts with the product icon
- Start / Stop / Status / Recovery
- Loopback ULA + ctrld 1.5.7/DoH + NRPT + zapret/winws/WinDivert
- No VPN, HTTP/SOCKS proxy or default-route tunnel
- SHA-256: `1D32D0619EDC85C5B11405218087154D53907C06D650843F7375092B2FC7C602`
- Current limitation: PowerShell 7 required; installer is not Authenticode-signed

## Linux
- Dedicated GTK/Adwaita application with dove icon and «زن زندگی آزادی»
- Draggable standard header + explicit Minimize / Maximize-Restore / Close
- Applications launcher + Desktop shortcut + uninstaller
- Temporary dedicated DNS link + ctrld 1.5.7/DoH + systemd-resolved + nftables/NFQUEUE + nfqws 72.13
- No VPN, HTTP/SOCKS proxy or default-route tunnel
- Exact package install + live DNS/HTTPS + rollback PASS
- SHA-256: `4F6C80D3406055A0A956082E76B211206D1CFFBD2E7398EE84DB62D155F52B98`
