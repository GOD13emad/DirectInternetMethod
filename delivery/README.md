# Delivery directory authority

Release authority is the immutable Git tag/release plus root `RELEASE.json`, the exact public checksum asset, and reproducible acceptance evidence. A filename in this directory alone is never sufficient authority.

Public tagged versions in project history:
`v1.0.0`, `v1.1.0`, `v1.2.0`, `v1.2.1`, `v1.3.0`, `v1.3.1`, `v1.3.2`, `v1.4.0`.

The 2026-10-01 machine audit copied missing authoritative historical release binaries from clean historical worktrees into this canonical delivery directory and verified source/destination SHA-256 values. See:
`audit/20261001_deep_machine_reconciliation/ARTIFACT_CONSOLIDATION_MANIFEST.json`.

Non-release material was removed from canonical delivery:
- untagged/local `1.0.1` artifacts → `archive/superseded-artifacts/v1.0.1-local/`
- `DIM_120_HOST_BOOTSTRAP_RUNNER.zip` → `archive/validation-tools/`
- known intermediate same-version artifacts remain under `archive/superseded-artifacts/`

`delivery/SHA256SUMS.txt` is the **exact 223-byte v1.4.0 public checksum asset** with SHA-256:
`7F80836A153EF0FFEF1A79D797502B773D8776DB99BBE21E1D81227A2D9EA609`.

Current v1.4.0 authority:
- Windows: `69F0EF63E3A658EC616362FC7D7ADAB95337EC3A034D3981DF44C685DB9FCB93`
- Linux: `4CF521FD3821F9204999C0F17B217A60DC7117AC68421E5634FDF8D15D3C485E`

Do not choose artifacts by newest-file or directory-location heuristics.
