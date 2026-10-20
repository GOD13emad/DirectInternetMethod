# Direct Internet Method v1.5.6 — Linux release-preparation candidate (NOT PUBLISHED)

This package is a **private validation candidate**, not a second public product
line. The current public Stable remains v1.5.4 until a separate authorized
GitHub release establishes exact asset identities and accepted test receipts.

## Supported single-install upgrade paths

- Public Linux User 1.5.4 with protected Root backend 1.5.2.
- Previously owner-accepted private Linux User 1.5.5-rc1 with protected Root
  backend 1.5.5-rc1.
- No mixed, unknown, modified, symlinked, or partially installed Root/User pair
  is silently upgraded. Existing custom Router Gateway data, settings,
  Tailscale, DNS/physical route, and one original installation must survive.
- Windows private installations have FileVersion 1.5.5.0. Public v1.5.5 is
  **not** a forward numeric upgrade for their existing updater; v1.5.6 is the
  first normal three-component version that can update them directly.

## Security and recovery

Privileged protected-file reads accept only literal approved filenames with
descriptor-based no-symlink traversal, pinned SHA-256 payloads, regular-file
identity, and verified original ownership. A per-transaction random acceptance
nonce prevents replay of previous Root acceptance receipts. The new
version-specific trusted privileged bootstrap must be installed only through
normal native administrator authorization after verifying its reviewed digest.

The Root+User maintenance transaction has one private rollback slot; a separate
Root-owned watchdog is armed before protected mutation and must be settled with
real Start, Stop, Recovery, original DNS/Tailscale checks and user settings
hashes before release. A preliminary staged/apply or hosted CI PASS alone does
not authorize physical deployment or publication. Do not disable host security
policies, reboot, modify default routes, reset DNS, or automatically install
a VPN or global tunnel.

## Known acceptance limits

Some physical networks reset YouTube TLS depending on SNI even when
public Google IPs are reachable. Site acceptance must be verified on the
intended network; no universal-connectivity claim is made. The current
physical network is not a verified universal connectivity target. Historical
plain `curl` HTTP403 and isolated headless browser timeout do **not** prove
ChatGPT account sign-in. Optional encrypted selective-DNS needs explicit,
separate user consent, and its controller remains restricted to safe native
rollback and Tailscale coexistence.

Current exact source starting point: primary PR #63 commit
`b38aa94b67fb102dd24359184abaa324cd29a3ad`, plus separately scoped
R803 forward-upgrade migration work. The new candidate's final Git SHA,
package digest, hosted Linux/Windows acceptance and release decision remain
UNVERIFIED until recorded on the exact generated artifacts.

Public v1.5.4 release and protected `main` remain unchanged. This document is
a package-level statement of intended behavior, not a claim of publication.
