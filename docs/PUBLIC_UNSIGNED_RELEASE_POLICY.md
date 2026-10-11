# Direct Internet Method — Public Unsigned Release Policy

**Owner-authorized policy, 2026-10-11.** This policy is applicable to Direct Internet Method as distributed by the owner, including future versions. It supersedes historical guidance suggesting that a publicly trusted code-signing certificate is mandatory to publish this product.

## One public product; no certificate prerequisite

- There is **one public distribution line**, not separate internal/external, signed/unsigned, or country-based products. Private GitHub Drafts may be used as temporary test transport; they are not end-user release channels.
- The publicly available **v1.5.1 is Stable and unsigned**. Its status is established by the actual GitHub release, not by possession of a signing certificate.
- Version 1.5.2 and later versions **may also be published as unsigned Stable releases**. Lack of Authenticode is **not** itself a build failure, release blocker, or basis to withhold a Stable label.
- Every public release must identify its exact source commit, downloadable file names, sizes, SHA-256 digests, version, and real acceptance results. `NotSigned` must be stated truthfully for unsigned Windows executables.
- **Never disable, bypass, weaken or modify** Smart App Control, Defender, App Control policy, certificate trust stores or other operating-system protections to make an unsigned installer run. Individual systems may refuse installation; that limitation must be communicated to users. Users decide whether to install on systems that permit it by their existing policies.
- No universal direct-Internet connectivity guarantee: authenticated ChatGPT browser access, HTTP 403 challenges, regional egress restrictions and YouTube DNS/TLS interference are independent measurable service gates.

## Quality gates independent of signing

The public Stable decision is based on evidence for source identity, reproducible builds, checksum-verified assets, legitimate clean Windows installation and uninstall, verified Windows 1.5.1→1.5.2 upgrade and restoration where applicable, protected Linux operation and rollback, safe Tailscale/RustDesk coexistence, supported update behavior, and truthful user-facing limitations. Do not equate source CI, compile success, user interface startup or public file upload with complete functional acceptance.

Current Windows hosted evidence: run 38167341910 (real clean install/uninstall) and run 38168392209 (exact public v1.5.1→1.5.2 and restore with zero errors). They test ephemeral Windows 2025 under its default OS policy; they do not constitute crash/power-loss restoration or prove compatibility with every configured Windows computer.

## Publication and rights

Owner permission to publish binaries does not by itself establish third-party license compliance. Keep project copyright permissions, Cygwin/WinDivert LGPL/GPL corresponding-source conditions, included notices, and verifiable provenance visible as separate gates. Do not infer a project source-code license without the rights holder's decision.

## Known historical controls to review

The legacy `windows-release-contract` for `v*` tags and `tests/release_metadata_audit.py` currently include **mandatory Authenticode/SAC signer requirements** inherited from an earlier release plan. Those requirements are **SUPERSEDED FOR THE OWNER'S UNSIGNED CHANNEL** and must be migrated to checks for unsigned artifact identity and actual installed lifecycle acceptance before treating a new tag's whole CI as accepted. Never silently suppress a failed security test or claim an obsolete red job is a valid release PASS; record the version-specific policy and corrected CI before promotion.

At this checkpoint: v1.5.1 is the latest prior Stable, `unsigned-1.5.2-preview.3` is publicly available as a prerelease, exact Windows install/upgrade/restore has passed on disposable hosted Windows. The next stable release is a product-owner publication decision with outstanding site/rights and release pipeline acceptance called out explicitly.
