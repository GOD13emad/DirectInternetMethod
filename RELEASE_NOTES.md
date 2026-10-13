# v1.5.3 — published Stable (13 October 2026)

Official release: https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v1.5.3

The exact Windows/Linux assets and their native installation, update and rollback evidence are published with `SHA256SUMS.txt` and `ACCEPTANCE_V153.json`. The public tag is `581a063836a20ca3c0adb941bfc77146e33d693a`.

Source-only .NET 10 maintenance was accepted in PR #55; it has not silently replaced the public v1.5.3 installer. Active customer-host deployment and new-version maintenance are separate from the accepted v1.5.3 publication milestone.

## Historical build notes — superseded publication labels

The original entries below are retained for provenance. Their earlier CANDIDATE/UNPUBLISHED labels describe the build stage and are not the current public release state.

---

# v1.5.3 — UNPUBLISHED VERSIONED CANDIDATE

- Includes PR45 source-only legacy v1.5.1 updater-stage cleanup, now rebuilt as a versioned candidate.
- Preserve one Windows AppId, user settings/custom Router Gateway provider and no duplicate installed version; all require genuine new-asset Windows/Linux installed QA.
- Linux may keep a byte-identical protected 1.5.2 backend, fresh install uses 1.5.3. Native backup/rollback still mandatory for any privileged change.
- Public v1.5.2 assets are immutable; the publisher does not require code signing or weakening Windows security settings.
- No publication before exact SHA and upgrade/rollback acceptance.

---

# v1.5.2 — Stable (published 2026-10-12)

- Fix Linux fresh install under umask 077. Explicitly set root-owned nonsecret parent directories to mode 0755 so user-level backend verification can traverse them; files stay root-owned.
- Add negative/positive regression and keep Windows/Linux release and updater versions aligned.
- No new DNS/DPI features; preserve opt-in Adult coverage, original direct-only design, rollback and historical v1.5.1.
- Gemini real-browser HTTP 403 remains FAIL and cannot be marked usable by transport-only tests.
- Published from source 14a3eec378eb75856f6691b7b3edc970507ee61f; exact public release asset hashes and hosted installation/rollback acceptance verified. Some websites remain inaccessible on particular networks; public release does not guarantee authenticated site access.

---

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
