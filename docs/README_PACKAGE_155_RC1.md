# Direct Internet Method 1.5.5-rc1 — Linux candidate (NOT RELEASED)

This archive is a versioned development candidate for upgrading the existing
single-install Linux app from public **v1.5.4**. It is not a public Stable
release and must not be offered as an automatic update.

## Scope
- Existing v1.5.4 settings, custom hosts, Router Gateway provider and
  Tailscale split mode must remain intact.
- Explicit NEW consent is required for encrypted selective DNS. Previous
  unencrypted third-party UDP opt-in does **not** count as consent.
- Pinned ctrld v1.5.7 DoH upstream routes only documented target domains
  through an owned per-link resolver. Non-target DNS stays with the user's
  physical DNS server, which may still time out or be intercepted.
- The root backend upgrade from installed protected v1.5.2 is a single-slot
  accepted-SHA transaction with an independent Rollback; it is **not**
  authorized for promotion until installed-native QA and hosted CI.
- Running a new root backend without an accepted user/backend pair is
  forbidden. The candidate's installer must fail closed if either side is
  foreign, active, or has an uncommitted conflicting transaction.

## Known limitations / open acceptance gates
The R516 targeted DNS pilot succeeded on two different LANs, and the R517
controller passed source-only and simulated rollback tests; these do not
demonstrate a successful upgrade, protection after reboot, a working
per-link resolver under live root, or access to every website.
YouTube HTTPS on the MMZ mobile ISP reset TLS even after native balanced
DPI, with a separate Strong test's root-only receipts unavailable. Seman
L2TP combined with Tailscale is not an accepted mode. Some services may
still return a region/account-specific HTTP 403.

Do not delete backups, auto-promote, disable Tailscale/Seman, reset system
DNS, reboot or shutdown as part of installation.
A native acceptance record must prove exact SHA, data preservation, service
Start/Stop/Recovery, rollback, Tailscale and physical DNS invariants before
release.

Source authority: GOD13emad/DirectInternetMethod, main commit
26ef644117ea474b487186ce5e6e61e92cd02dd4, versioned R519 branch.
Public release authority remains v1.5.4 (tag
51009372e3c2d069d7016b97773f35ee5e1e0631).
