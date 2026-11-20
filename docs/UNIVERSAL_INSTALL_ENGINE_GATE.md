# Universal Installer Engine — accepted project pivot (2026-11-20)

**Primary objective:** build and prove a reusable, OS-independent installation transaction engine for Direct Internet Method. Per-host workarounds are no longer the main execution strategy.

## Definition of Done

One shared version/manifest/security contract and transition machine for install, in-place upgrade, recovery, rollback and safe uninstall; one active installation on each host; no silent loss of user settings, no orphaned versions or foreign file deletion; native Windows (Inno/SCM) and Linux (systemd/polkit/root-owned bootstrap) adapters; independently pinned packages; no dependency on a specific owner's paths or SID. Run the same accepted test matrix on native Windows and Linux targets before production canaries and release.

## Current scoped evidence — NOT production acceptance

A portable standard-library Python engine **candidate** has been generated in the originating ChatGPT task as a separate downloadable ZIP. SHA-256 of that ZIP: `C7B3098EF3BB2BFAC19B75332669D5F290482689F76379848A08C204216DAC2E`. It has not been committed to this Git branch. Its portable kernel implements one active code slot, verified pending transaction, file ownership guards, rollback after interrupted directory moves, and adapter-required quiescence and acceptance hooks. Synthetic Linux 3.13 tests: **13/13 PASS**, plus CLI fixture path EMPTY -> STAGE -> ACTIVATE -> COMMIT -> VERIFY **PASS**. Windows owner host: **native Python primitive-only** rename/replace/msvcrt mutex fixture **PASS**; full engine code on Windows **NOT TESTED**. No physical DIM installations, services, DNS, adapters or release artifacts modified.

This evidence does not constitute successful clean install/migration of the real DIM payload or Windows/Linux native service integration. Neither a manifest digest from the package itself nor the CLI booleans authenticates a release or proves native service health.

## Ordered implementation gates

1. Import the exact engine source and tests from candidate ZIP into this branch as reviewed text files; compare every SHA-256 to its evidence manifest. No duplicate active implementation in the canonical project.
2. Run **unchanged source** in native Windows and Linux CI with negative tests: unsafe path/links, tampered payload, downgrade, foreign file preservation, lock contention, hard termination between renames, rollback, commit replay and untouched mutable data.
3. Build native adapters: integrate Windows Inno AppId, signed/pinned asset, SCM/UAC and one registered uninstaller; Linux trusted root-owned bootstrap, systemd/polkit and one user installation. Do not let privileged execution ingest user-writable unverified package code.
4. Validate real DIM package manifests, byte-level installer/update/uninstall/rollback, security, profile-data preservation, locked binaries and crash/reboot recovery across multiple clean native VMs. Use one acceptance matrix; preserve exact provenance.
5. Obtain independent human security/release approval, run consented physical canaries, then prepare public release. **Until then: RELEASE HOLD**.

Reference: existing `PROJECT_BRAIN.md` contains the accepted pivot under `DIM-UE-CROSS-PLATFORM-ENGINE-20261120`. Existing `v1.5.4` remains public stable; `v1.5.7` remains private.
