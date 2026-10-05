# Direct Internet Method v1.5.1

## Main change

- Converts the Adult control from a single-site live diagnostic into real opt-in DPI host coverage.
- Uses a maintained upstream domain catalog with strict size/domain validation and a bounded offline fallback.
- Default remains OFF; core hostlist remains free of Adult domains.
- Windows and Linux use the same coverage semantics.
- Full-page acceptance now requires HTTP 2xx/3xx. HTTP 403/520 and transport failures are not PASS.

## Evidence

- Controlled Linux tests proved XVideos and XNXX move from TLS failure to HTTP 200 when added to the accepted host-scoped DPI path.
- One Cloudflare-backed representative remains unproven: multiple accepted zapret v72.13 HTTPS strategies reached HTTP 520 on one edge while another edge continued to fail TLS. No unstable strategy is promoted globally.
- Official zapret v72.13 release archive was hash-verified before strategy research.
- The validation network shows DNS interception when Direct Method is off; Direct Method's ctrld DoH resolves affected names to real public addresses.
- Gemini remains HTTP 403 on the current egress. Direct-only DNS/DPI methods do not change public egress geolocation.

## Preserved invariants

- No VPN/default-route tunnel.
- No HTTP/SOCKS/WinHTTP proxy.
- No physical-adapter DNS mutation.
- Targeted scope remains the default.
- All Sites and Adult coverage remain explicit opt-ins.
- Rejected third-party binaries remain rejected.

## Known boundaries

- Maintained domain coverage is broad, not a mathematical guarantee that every remote Adult origin/CDN edge is usable.
- Gemini 403 requires an egress-policy solution outside the current direct-only architecture.
- Windows installer remains unsigned with Authenticode.
