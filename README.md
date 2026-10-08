# Direct Internet Method

**زن زندگی آزادی**

Standalone direct-connect application for Windows and Linux. It does not create a VPN, HTTP/SOCKS proxy, WinHTTP proxy, or default-route tunnel.

## Direct Method — v1.5.2 corrective candidate

v1.5.2 retains the accepted v1.5.1 direct engine and turns the existing opt-in **Adult coverage** control into real bounded domain coverage rather than a single-site diagnostic.

When Adult coverage is enabled, the app fetches and validates a maintained HaGeZi NSFW only-domains catalog at runtime and combines it with a small offline fallback. The feature remains OFF by default. Core traffic stays targeted, and the catalog is not applied unless the user enables it.

Representative controlled testing on the validation Linux network proved that adding the missing host scope changed **XVideos** and **XNXX** from TLS failure to HTTP 200. A separate representative Cloudflare-backed site remains unproven for a usable full page: several accepted-runtime strategies reached HTTP 520 on one edge while another edge still failed TLS. HTTP 4xx/5xx is therefore reported as failure, not success. Broad catalog coverage maximizes targeting but does not truthfully guarantee every remote origin/CDN edge.

Gemini currently returns HTTP 403 on the validated public egress. Direct DNS/DPI manipulation can solve DNS spoofing and DPI interference but does not change the public egress region; 403 is not counted as PASS.

The engine uses:

- leak-closed direct-IP DoH through ctrld;
- host-scoped HTTP/80 splitting;
- host-scoped TLS/SNI TCP/443 desynchronization;
- host-scoped QUIC UDP/443 desynchronization;
- user-managed Custom Sites;
- Balanced / Compatibility / Strong strategy profiles;
- opt-in All Sites scope;
- opt-in maintained Adult coverage.

The validation network exhibits DNS interception when Direct Method is disabled. Direct Method's encrypted DNS resolves affected domains to their real public addresses before DPI handling.

## Router Gateway

Router Gateway remains a separate non-privileged configuration panel for compatible routers/modems. Provider data revision 3 is maintained independently of application artifacts. Endpoint probes do not claim authenticated PPTP/L2TP tunnel success.

## Windows 1.5.2

- Native WPF UI and fixed-command privileged service.
- Bundled PowerShell 7.6.6.
- ctrld + zapret/winws v72.13 + WinDivert.
- Adult coverage catalog is opt-in and cached per user.
- Installer is not Authenticode-signed; SHA-256 remains the artifact identity gate.

## Linux 1.5.2

- Dedicated temporary DNS link + ctrld + systemd-resolved.
- nftables/NFQUEUE + zapret/nfqws v72.13.
- Protected backend version 1.5.2.
- Adult coverage uses the same validated catalog/fallback model as Windows.

## Release artifacts

- `DirectInternetMethod_1.5.2_Windows_Setup.exe`
- `DirectInternetMethod_1.5.2_Linux_x86_64.zip`
- `SHA256SUMS.txt`

Authoritative acceptance/provenance records are stored under `evidence/`.

## Tailscale split-network coexistence — v1.5.2 development candidate

On Linux, Tailscale peer/subnet mode **without an Exit Node** may run alongside Direct Internet Method in `targeted` DPI-only mode. The Direct Method preserves existing DNS/MagicDNS, Tailscale routes and daemon state, and bypasses the Tailscale-reserved packet mark before passing ordinary physical-interface web traffic to NFQUEUE. It does **not** activate its own DoH listener in coexistence mode. Exit nodes, an unknown second tunnel or all-sites DPI fail closed. The original DoH + DPI configuration remains available when Tailscale is not running. See `docs/TAILSCALE_COEXISTENCE.md` for safety preconditions and outstanding real-host acceptance.

This mode is **source candidate only**, not yet installed or tested end-to-end on Tailscale-active hosts; changing the protected Linux helper requires the normal authorized administrative install. The Windows v1.5.2 public release remains HOLD pending trusted signing and policy-on Sandbox installation. Neither always-on global connectivity nor usable Gemini HTTP 403 is guaranteed.
