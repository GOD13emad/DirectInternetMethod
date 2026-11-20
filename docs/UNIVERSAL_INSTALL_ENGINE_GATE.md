# Universal Installer Engine — accepted project pivot (2026-11-20)

**Primary objective:** build and prove a reusable, OS-independent installation transaction engine for Direct Internet Method. Per-host workarounds are no longer the main execution strategy.

## Definition of Done

One shared version/manifest/security contract and transition machine for install, in-place upgrade, recovery, rollback and safe uninstall; one active installation on each host; no silent loss of user settings, no orphaned versions or foreign file deletion; native Windows (Inno/SCM) and Linux (systemd/polkit/root-owned bootstrap) adapters; independently pinned packages; no dependency on a specific owner's paths or SID. Run the same accepted test matrix on native Windows and Linux targets before production canaries and release.

## Current scoped evidence — NOT production acceptance

The shared engine is now tracked on feature/universal-install-engine rather than only an external ZIP. Kernel version-one commit eb68422faf7ef999e0895fe820590e71458b4ca6; workflow YAML repair commit 98334987dcc200f956b936558a77552788ed0011 (both derived from original PR #66 base without modifying it). Shared state-machine scope: independently pinned manifest and file SHA-256, one managed current slot, staged previous slot, locked and durable update journal, strict version monotonicity, intentional rollback/commit and crash replay. It never operates on native Service/Registry/DNS and never reads/removes private data stored separately from code.

**Confirmed GitHub CI:** 44758531902, four successful jobs across ubuntu-latest/windows-latest and Python 3.11/3.14. This first CI snapshot ran 16 contract tests per environment, with the Windows symlink creation fixture allowed to SKIP if unprivileged OS policy disallows it. Additionally native Windows 3.14.7 ran 15 PASS + 1 SKIP; Linux 3.13 ran 16 PASS.

**New scoped core improvement (not yet hosted-accepted at this section's timestamp):** a two-phase safe-uninstall protocol (prepare_uninstall, abort_uninstall, finish_uninstall) with a durable uninstall journal. It parks only owned code, demands native adapter's explicit unregistration proof, and deletes only hash-verified owned code, never owner data. Local synthetic Linux 3.13: 23/23 PASS; native Windows 3.14.7: 22 PASS, 1 SKIP. Native Windows Inno/SCM and Linux root/systemd/polkit integration is still NOT implemented; boolean adapter callbacks are assertions, not authentic proof.

**Release scope:** All current tests mutate temporary fixtures only. There is no real clean install/migration of DIM application binaries through this engine, no full native installer rollback, no signed release authentication and no production acceptance. Public stable v1.5.4 and private v1.5.7 stay unchanged.
## Ordered implementation gates

1. **CORE FILES TRACKED:** One canonical Python implementation and test suite on the development branch; preserve full original ZIP provenance and hashes, with no parallel production implementation.
2. **CORE MATRIX VERIFIED:** Linux/Windows GitHub runner CI across Python 3.11/3.14 (first 16-case suite); rerun expanded uninstall suite after commit, retain per-run evidence and any skipped tests. Add native filesystem/reparse negative tests.
3. Build native adapters: integrate Windows Inno AppId, signed/pinned asset, SCM/UAC and one registered uninstaller; Linux trusted root-owned bootstrap, systemd/polkit and one user installation. Do not let privileged execution ingest user-writable unverified package code.
4. Validate real DIM package manifests, byte-level installer/update/uninstall/rollback, security, profile-data preservation, locked binaries and crash/reboot recovery across multiple clean native VMs. Use one acceptance matrix; preserve exact provenance.
5. Obtain independent human security/release approval, run consented physical canaries, then prepare public release. **Until then: RELEASE HOLD**.

Reference: existing `PROJECT_BRAIN.md` contains the accepted pivot under `DIM-UE-CROSS-PLATFORM-ENGINE-20261120`. Existing `v1.5.4` remains public stable; `v1.5.7` remains private.
