# R781 — trusted Linux Root entrypoint (unreleased, review-only)

## Purpose and authority

The existing `pkexec /bin/bash "$HERE/system/upgrade_system.sh"` launched shell code directly from the owner's extracted package. Native Polkit confirmation authenticates the invoking user but does not attest this script. R781 replaces that initial privileged entry with a fixed administrator-provisioned program:

`/usr/local/libexec/directinternetmethod/privileged_entry.py`

This directory is deliberately **outside** the primary `/usr/lib/directinternetmethod` backend, so pre-provisioning does not accidentally make a truly fresh installation look like a partial backend. It is one trusted component of the same product, **not** a second full installation, a privileged wildcard broker, or permission to disable authentication.

The source of this bootstrap is `tools/security/privileged_entry.py` in the exact reviewed commit. Its SHA-256 in the R781 test candidate is:

`C81E9D6F1B517CCE19ADD72CBA6E442D18A0E88B435AAAAD3433158E48964E80`

It freezes only the **single accepted** `v1.5.5-rc1` package, using a compiled-in manifest SHA-256:

`5754B16D7C4916749691EC71012AAE2BAAFA28638293B10BA225962702381BF4`

The built Linux ZIP is **UNRELEASED**: SHA-256 `F60AB5672A91EA5A16F9264831C5CFB9D7A397535BD71CD1704EA7AC8C83566E` (8,422,093 bytes, 28 payload members).

## Exact sequence and guardrails

1. Independently review the exact source commit, its GitHub history and privilege boundary; obtain the trusted bootstrap from that immutable reviewed source. This is **not yet approved for installation**.
2. A legitimate interactive OS administrator, not this unprivileged installer, approves provisioning a new **Root-owned** file. Verify the source's SHA-256 independently; refuse existing foreign/symlink target. Create the dedicated root-owned ancestor with group/world nonwritable permissions, copy as root mode `0500`, then recompute and compare the installed file's SHA-256 before running any upgrade. Do not execute the package as Root to provision it.
3. User-side `linux/install.sh` verifies the trusted path's owner/group/mode/type/link count. If missing, fail closed, roll back its staged **user** transaction, and clearly request the separate OS-admin action. Never fall back to user-owned Bash.
4. Polkit authorizes `/usr/bin/python3 -I` on the fixed root-owned script with explicit `--action upgrade|install`, `--source`. The script demands actual `PKEXEC_UID`, verifies itself and all pathname ancestors as root-owned, and rejects non-root/caller identity mismatch.
5. Before ANY contained script runs under Root, the bootstrap verifies a fixed manifest hash, exactly 28 canonical allowlisted payloads, checks file types, sizes, symlinks/hardlinks, reads source bytes using a single pinned descriptor with no symlink traversal, and validates each member SHA. It freezes the entire accepted tree under a temporary `/run` directory owned by Root, mode `0700`.
6. Run only the copied, SHA-attested package script under a minimal sanitized environment. The existing independent, root-owned watchdog still protects protected `stage/apply`. The bootstrap removes only its isolated ephemeral copy. Any failure must leave user-owned configuration intact and must not hide an incomplete privileged transaction.

## Security boundaries / remaining checks

This SHA-pinned release-specific approach intentionally requires **another explicit administrator review and trusted-anchor update** for a future package with a different manifest. The project does not require arbitrary publisher digital signatures or silently trust an unverified GitHub release.

R781 rootless tests only exercise preflight, source freezing, rejection and code provenance. They do **not** prove protected install, timer/rollback, UAC/Polkit consent, live TLS routing or product-wide security. Native ephemeral hosted Root tests, independent review of PR #62/#63, expert adjudication of all CodeQL High findings and owner-authorized physical acceptance are still separate gates. No trusted entry has been installed on either physical Linux host.

## Revocation and recovery

The installed file remains an explicit OS-admin-owned asset; no self-updater may overwrite it. If its installed checksum/ownership drifts or the corresponding package manifest changes, reject the privileged attempt. An administrator may disable/revoke this isolated entrypoint only after checking for active upgrade/rollback guard state and preserving the accepted installed backend and user settings. Do not remove any persistent watchdog or pending rollback evidence as part of bootstrap cache cleanup.

## Provenance

Original review-only source parent: `c31783167ce22be2c30e379d2a99650056601f5a` (PR #63). New test: `tests/r781_privileged_entry_contract.py`. Scope: source/prototype until native hosted and physical, approved privileged acceptance is demonstrated.
