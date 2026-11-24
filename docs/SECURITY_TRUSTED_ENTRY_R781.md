# Administrator-local bootstrap — reviewed v1.5.7 QA candidate (R965)

**Status: private QA only; not approved for production provisioning.** The current candidate uses the existing administrator-local path, not a Debian-managed file. Debian Policy section 9.1.2 reserves /usr/local for the local administrator: https://www.debian.org/doc/debian-policy/ch-opersys.html . A future Debian package must use a package-owned path and a newly reviewed installer/manifest; do not relocate the frozen v1.5.7 helper or change historical hashes.

The exact private CI delivery comprises the frozen Linux ZIP, the separately reviewed bootstrap source, SHA256SUMS.txt and SOURCE_COMMIT.txt. Verify these against independently approved source and digests, not merely a checksum included with an untrusted download:

- ZIP SHA256: 298C4D3B9AE5C8B0709EDFFCAE665FB66A84A47BBDB2564E4E92356903738FCD
- Bootstrap SHA256: 452D7BF28865A376B25EA7B87BDDCD73BA66A406BE1C90B6A45B7AD09F5ACBA4
- Manifest SHA256 pinned inside bootstrap: B43D98BEA4403094969BC47A5C4C1A60CA5E27981101F55BC442F9F23BF736C7

For a fresh administrator-approved host, the native provisioning recipe is: independently verify the exact reviewed source; confirm all destination ancestors are real root:root directories without group/world write access and the final entry does not exist (including dangling links); create a new dedicated root-owned directory and private 0700 staging directory on the same filesystem; use GNU install -o root -g root -m 0500 to copy into staging; verify staged bytes against the independent pin; fsync; publish with GNU ln -T without -f, which refuses an occupied destination; remove only the owned staging link; verify final root:root, regular type, 0500, one link and exact digest. Never execute a downloaded user-writable provisioning script as root. Existing or drifted anchors require separately approved migration, not overwrite. The subsequent product install remains the existing owner install.sh and legitimate native Polkit approval. No credential or authorization policy change. The R965 VM test exercises these native tools and the existing fresh lifecycle; its simulated PKEXEC_UID does not prove actual interactive Polkit consent.

GNU references: https://www.gnu.org/software/coreutils/manual/html_node/install-invocation.html and https://www.gnu.org/software/coreutils/manual/html_node/ln-invocation.html .

---

## Historical R781 record (original candidate, not current instructions)

# R781 — trusted Linux Root entrypoint (unreleased, review-only)

## Purpose and authority

The existing `pkexec /bin/bash "$HERE/system/upgrade_system.sh"` launched shell code directly from the owner's extracted package. Native Polkit confirmation authenticates the invoking user but does not attest this script. R781 replaces that initial privileged entry with a fixed administrator-provisioned program:

`/usr/local/libexec/directinternetmethod/privileged_entry.py`

This directory is deliberately **outside** the primary `/usr/lib/directinternetmethod` backend, so pre-provisioning does not accidentally make a truly fresh installation look like a partial backend. It is one trusted component of the same product, **not** a second full installation, a privileged wildcard broker, or permission to disable authentication.

The source of this bootstrap is `tools/security/privileged_entry.py` in the exact reviewed commit. Its SHA-256 in the R781 test candidate is:

`C8AE0759FDF3A5EE514B5457D05AF1BFEF0BB266E03244C7EF2F3F6EDB8994D1`

It freezes only the **single accepted** `v1.5.5-rc1` package, using a compiled-in manifest SHA-256:

`E3D6186F8BC775FA7861DD506AA1EB978F6296BDC98D686CD3731C79680FEB42`

The built Linux ZIP is **UNRELEASED**: SHA-256 `0C4D22F98C7C4ECEA2CDE1C0232B3C3928C022779BA8A644CD3DC46FF13CE934` (8,424,218 bytes, 28 payload members).

## Exact sequence and guardrails

1. Independently review the exact source commit, its GitHub history and privilege boundary; obtain the trusted bootstrap from that immutable reviewed source. This is **not yet approved for installation**.
2. A legitimate interactive OS administrator, not this unprivileged installer, approves provisioning a new **Root-owned** file. Verify the source's SHA-256 independently; refuse existing foreign/symlink target. Create the dedicated root-owned ancestor with group/world nonwritable permissions, copy as root mode `0500`, then recompute and compare the installed file's SHA-256 before running any upgrade. Do not execute the package as Root to provision it.
3. User-side `linux/install.sh` verifies the trusted path's owner/group/mode/type/link count. If missing, fail closed, roll back its staged **user** transaction, and clearly request the separate OS-admin action. Never fall back to user-owned Bash.
4. Polkit authorizes `/usr/bin/python3 -I` on the fixed root-owned script with explicit `--action upgrade|install`, `--source`. The script demands actual `PKEXEC_UID`, verifies itself and all pathname ancestors as root-owned, and rejects non-root/caller identity mismatch.
5. Before ANY contained script runs under Root, the bootstrap verifies a fixed manifest hash, exactly 28 canonical allowlisted payloads, checks file types, sizes, symlinks/hardlinks, reads source bytes using a single pinned descriptor with no symlink traversal, and validates each member SHA. It freezes the entire accepted tree under a temporary `/run` directory owned by Root, mode `0700`.
6. Run only the copied, SHA-attested package script under a minimal sanitized environment. The existing independent, root-owned watchdog still protects protected `stage/apply`. The bootstrap removes only its isolated ephemeral copy. Any failure must leave user-owned configuration intact and must not hide an incomplete privileged transaction.

## Security boundaries / remaining checks

This SHA-pinned release-specific approach intentionally requires **another explicit administrator review and trusted-anchor update** for a future package with a different manifest. The project does not require arbitrary publisher digital signatures or silently trust an unverified GitHub release.

R781 rootless tests only exercise preflight, source freezing, rejection and code provenance. They do **not** prove protected install, timer/rollback, UAC/Polkit consent, live TLS routing or product-wide security. Native ephemeral hosted Root tests, independent review of PR #62/#63, expert adjudication of all CodeQL High findings and owner-authorized physical acceptance are still separate gates. The current new digest of the trusted entry has NOT been installed on either physical Linux host. Read-only native SHA checks on 2026-10-19 found previous root-owned 0500 entry SHA256 `DD878D594830A3C1A85283E3399BF96B42B9FBC02AF68D993DE5507D605577D8` on both; replacing it requires fresh administrator consent after reviewed security acceptance.

## Revocation and recovery

The installed file remains an explicit OS-admin-owned asset; no self-updater may overwrite it. If its installed checksum/ownership drifts or the corresponding package manifest changes, reject the privileged attempt. An administrator may disable/revoke this isolated entrypoint only after checking for active upgrade/rollback guard state and preserving the accepted installed backend and user settings. Do not remove any persistent watchdog or pending rollback evidence as part of bootstrap cache cleanup.

## Provenance

Original review-only source parent: `c31783167ce22be2c30e379d2a99650056601f5a` (PR #63). New test: `tests/r781_privileged_entry_contract.py`. Scope: source/prototype until native hosted and physical, approved privileged acceptance is demonstrated.
