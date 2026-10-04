# Local reconciliation archive

This directory is the local, non-release archive created by the 2026-10-01 deep machine audit.

It is **not release authority**. Current project truth remains protected `main`, immutable release tags, public release artifacts, reproducible tests, and tracked evidence under `evidence/`.

Local categories:

- `predecessor/DirectDnsDpiHarness/` — preserved copy of the pre-Git standalone proof/handoff project from 2026-09-29.
- `machine-snapshots/windows-appdata-legacy/` — old audit/pre-install snapshots moved out of AppData.
- `machine-snapshots/temp-public-verification/` — old public-download verification caches moved out of Temp.
- `machine-snapshots/crashdumps/DirectInternetMethod.exe.67464.dmp` — preserved copy of the discovered 2026-09-29 Windows crash dump; the original remains external.
- `worktree-history/DirectInternetMethod_all_refs_precleanup_20261001.bundle` — Git bundle created before worktree cleanup attempts; `git bundle list-heads` enumerated all locally-known heads/tags/remotes/stash/worktree refs.
- `release-artifacts/` — exact historical checksum assets used to disambiguate immutable releases.
- `superseded-artifacts/` — local/intermediate binaries that are not immutable public-release authority.
- `validation-tools/` — non-product validation/bootstrap packages removed from canonical delivery.

Large archive content is intentionally kept out of Git. Tracked audit manifests under `audit/20261001_deep_machine_reconciliation/` describe provenance and classifications.

Six clean historical linked worktrees remain outside this root because ACL/permission denied prevented safe removal. Their release artifacts are consolidated here and their refs are preserved in the pre-cleanup bundle; they are **EXTERNAL / REDUNDANT-HISTORICAL**, not current authority.

The Remote Commander backup store remains external by design. The audit indexed 920 project-related backup files (799 unique contents; about 672 MB unique) instead of duplicating that safety store into this repository.
