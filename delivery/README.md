# Delivery authority: Direct Internet Method

Current application release: `v1.5.2` (public unsigned PREVIEW3, NOT YET STABLE).

Public `v1.5.1` is the preceding Stable release (unsigned).
Public `unsigned-1.5.2-preview.3` is the tested v1.5.2 unsigned PREVIEW (not yet Stable).
One public product release line; signing certificate acquisition is not required.

## Pinned last-accepted Preview 3 assets (source commit 3ead2491)
- Windows: `DirectInternetMethod_1.5.2_Windows_Setup.exe`, 157124929 bytes, SHA256 `2F054752E3B1B4715D68958CA49639AEA6FE43E0E4CBC6611DDEEBABAE2C7EB5`.
- Linux: `DirectInternetMethod_1.5.2_Linux_x86_64.zip`, 8234805 bytes, SHA256 `0218BEBD0DC8F88670374FF0E12A61D45229A03092C606678C5C00FD81DC2C9E`.
- Checksums: `SHA256SUMS.txt`, LF-serialized SHA `B0A89D10D8AF5E39E0CF2AA17FB96178AB44ED82D0346450FA3C94285C3B82DD`.
- Hosted Windows clean installation/uninstall and 1.5.1 → 1.5.2 → exact 1.5.1 rollback: PASS (GitHub runs 38167341910 attempt 2 and 38168392209 zero warnings).
- GitHub source CI: Windows and Linux PASS 38152706915.

**Build identity boundary:** these hashes describe the already-tested public PREVIEW from source 3ead2491; source commits subsequently changing metadata, tests, or release policy MUST rebuild and reverify new binaries before stable tag publication. Never mistake historical QA digest for newly built HEAD.

Known open acceptance: crash/reboot-interrupted upgrade rollback; authenticated user ChatGPT/YouTube website availability on all restricted networks; first-party and upstream source-license obligations. The installer is unsigned and some Windows policies may reject it; NEVER disable SAC, Defender or OS security to install it.
