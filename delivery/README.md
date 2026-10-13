# v1.5.4 BUILD CANDIDATE (NOT YET PUBLIC)
Future Windows and Linux packages: DirectInternetMethod_1.5.4_Windows_Setup.exe and DirectInternetMethod_1.5.4_Linux_x86_64.zip. Official public Stable remains v1.5.3 until publication.

# v1.5.3 BUILD CANDIDATE (UNRELEASED)

Artifacts built from this branch are QA-only until separately versioned and SHA-attested hosted Windows/Linux installed acceptance. Current public Stable remains v1.5.2; official public checksums belong to that Release, never to local candidates.

# Delivery authority: Direct Internet Method

Current application release: `v1.5.2` — public Stable, published 2026-10-12.

**Authoritative public installers are the six immutable assets of** [GitHub v1.5.2 Stable](https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v1.5.2), including Release-attached `SHA256SUMS.txt`: Windows `F94A81CC819E465D6B1000FFDB0B20A7212E39B6F6282ED8A720774148DFC78D`; Linux `53C9FCADDBE96CEC9F63505AB20992479C422F3AB9A9E2379898F5A80BF76692`.

The root and `delivery/` source-controlled checksum files, and the pinned artifact hashes in root `RELEASE.json`, intentionally describe an **earlier Preview 3 build** used by historical source contract tests. These are NOT the Stable download hashes; consult `docs/PUBLISHED_V152_ASSET_AUTHORITY.md`. Do not overwrite historical acceptance digests or mistake a source CI run for a new binary Release.

Public `v1.5.1` remains the previous Stable release (unsigned); `unsigned-1.5.2-preview.3` is a historical preview. One public product line; signing certificate acquisition is not required.

## Historical pinned Preview 3 assets (source commit 3ead2491)
- Windows: `DirectInternetMethod_1.5.2_Windows_Setup.exe`, 157124929 bytes, SHA256 `2F054752E3B1B4715D68958CA49639AEA6FE43E0E4CBC6611DDEEBABAE2C7EB5`.
- Linux: `DirectInternetMethod_1.5.2_Linux_x86_64.zip`, 8234805 bytes, SHA256 `0218BEBD0DC8F88670374FF0E12A61D45229A03092C606678C5C00FD81DC2C9E`.
- Checksums: `SHA256SUMS.txt`, LF-serialized SHA `B0A89D10D8AF5E39E0CF2AA17FB96178AB44ED82D0346450FA3C94285C3B82DD`.
- Hosted Windows clean installation/uninstall and 1.5.1 → 1.5.2 → exact 1.5.1 rollback: PASS (GitHub runs 38167341910 attempt 2 and 38168392209 zero warnings).
- GitHub source CI: Windows and Linux PASS 38152706915.

**Build identity boundary:** these hashes describe the historical public PREVIEW from source 3ead2491. The published Stable v1.5.2 is a different, separately SHA-verified artifact set, with actual hosted R450 Windows and R451 Linux install/rollback evidence. A later source hotfix in PR #45 is merged into `main` but **not** in the immutable Stable v1.5.2 binaries. Never equate source-HEAD checksums or historical Preview evidence with a published new binary.

Known open acceptance: crash/reboot-interrupted upgrade rollback; authenticated user ChatGPT/YouTube website availability on all restricted networks; first-party and upstream source-license obligations. The installer is unsigned and some Windows policies may reject it; NEVER disable SAC, Defender or OS security to install it.
