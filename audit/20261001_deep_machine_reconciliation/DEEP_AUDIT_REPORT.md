# Direct Internet Method — Deep Project & Machine Audit

Date: 2026-10-01
Audit status: **FINAL — deep machine/project reconciliation complete; v1.4.0 release authority preserved; only documented non-blocking future work remains**

## 1. Authority and audit scope

Canonical project root is `C:\Users\Aa.Emad\source\repos\DirectInternetMethod`.

At audit start the directory was clean but checked out on an old audit branch. Read-only comparison proved that branch had no commits ahead of current protected `origin/main`; the root was therefore safely returned to `main` and fast-forwarded to `8da94b821bfabf01ef993e730def170f7f5ddbb5`.

Current public release authority remains immutable tag `v1.4.0`, release commit `910e22d06209e244f8caf809c9821e3fb16c7cc1`, tree `db7f8e02ca706ca0c74a54901368a6a61a4733cd`. The later main commit `8da94b8` contains final publication/installed-host evidence and no release binary mutation.

This audit examined:
- canonical source, Git refs/tags/stash/worktrees and historical release artifacts;
- installed Windows user/privileged/runtime/update locations;
- Downloads and Downloads/My Project with project-specific name signatures;
- AppData legacy backups, Temp public-download verification caches and crash evidence;
- the historical predecessor `DirectDnsDpiHarness`;
- GitHub repository protection, tag rules, releases, CI, open work and secret-scanning settings;
- Windows/Linux update, ownership, rollback, packaging and metadata-control code.

Project truth precedence for this report is: live/raw state and immutable release data → reproducible tests/CI → tracked evidence → Project Brain → inference.

## 2. What the project actually is, and where it started

The project did **not** begin as the current GitHub repository. The predecessor found on disk is:

`C:\Users\Aa.Emad\source\repos\DirectDnsDpiHarness`

Its own Brain states the original objective explicitly: prove a standalone Windows direct-access method for later FreeNetHub handoff, using encrypted DNS + DPI desynchronization, with **no VPN, no HTTP/SOCKS proxy, no default-route tunnel, and exact rollback**. Its final two-cycle acceptance and visible-browser gate passed on 2026-09-29.

That predecessor has now been copied into the canonical root at:

`archive/predecessor/DirectDnsDpiHarness`

The source and archived copy each contain 106 entries at the verified listing depth; the copied predecessor `PROJECT_BRAIN.md` SHA-256 exactly matches the source:
`4F2A7E550C8D3D4EB91F3E6801BBC512899FE02B84C6C07BF9738756EC3D0079`.

The predecessor is important because it preserves the experimental history that the later polished repository no longer exposes directly: listener trials, ULA/NRPT decisions, browser diagnostics, repeated acceptance-harness fixes, packaging/root-cause evidence, and the original FreeNetHub handoff contract.

### Repository evolution reconstructed from Git

The canonical Git history begins with `4b9111f` on 2026-09-29 (“Direct Internet Method 1.0.0 Windows standalone”), then evolves through:

- **v1.0.0** — standalone Windows + Linux product, GitHub publication and dedicated UI/branding.
- **v1.1.0** — packaged/runtime stabilization and cross-platform release finalization.
- **v1.2.0** — service-mediated direct Windows online update.
- **v1.2.1** — Linux CRLF/package defect correction, deterministic cross-host archive, protected CI/GitHub governance.
- **v1.3.0** — Router Gateway introduced as a separate non-mutating router configuration panel.
- **v1.3.1** — Windows startup geometry/footer fix plus provider-catalog expansion.
- **v1.3.2** — Router Gateway grid visibility/contrast fix; all 9 profiles became visibly readable.
- **v1.4.0** — bounded multi-protocol direct engine: encrypted DNS, HTTP/80, TLS/SNI TCP/443 and QUIC UDP/443 DPI handling, still without VPN/proxy/default-route tunneling.

Current main then records final v1.4.0 installed-host/publication acceptance in `8da94b8`.

### Important architecture-history nuance

The predecessor records more than one DNS architecture experiment. Early evidence describes Windows-native DoH/NRPT as a simpler accepted direction after local port-53 lifecycle trouble; later accepted product generations use an owned ctrld listener/service with loopback ULA + NRPT. These are **sequential design decisions**, not one timeless architecture. The current v1.4.0 architecture is authoritative; predecessor decisions remain historical evidence explaining why lifecycle/ownership controls became strict.

## 3. Machine-wide reconciliation and cleanup

### Downloads / My Project

Targeted searches in `C:\Users\Aa.Emad\Downloads` and `Downloads\My Project` for the strong project signatures `DirectInternetMethod`, `Direct Internet Method`, `DirectDnsDpiHarness` and `DIM_140` found **no Direct Internet Method project files** in the searched depth. Matches for the generic phrase `direct_method` belonged to an unrelated scientific RETURN_R013A project and were deliberately not moved.

This is high-confidence targeted negative evidence, not a claim that every byte under Downloads was content-indexed: one broad content-oriented search timed out. No unrelated Downloads/My Project material was moved.

### C: drive footprint

A direct `C:\` project-name search timed out after returning 37 hits, but it captured the important current footprint:
- installed privileged runtime under `C:\Program Files\DirectInternetMethod`;
- service/update state under `C:\ProgramData\DirectInternetMethod`;
- current user/cache locations under AppData;
- canonical Git root;
- six historical linked Git worktrees.

The separate predecessor search found `C:\Users\Aa.Emad\source\repos\DirectDnsDpiHarness`.

### Material physically consolidated into the canonical root

Moved out of AppData into `archive/machine-snapshots/windows-appdata-legacy/`:
- `DirectInternetMethod_AuditBackup_110`
- `DirectInternetMethod_BrokenInstall_Audit_20260930`
- `DirectInternetMethod_Pre110_Backup_20260930`
- `DirectInternetMethod_PreBundled110_Backup_20260930`
- `DirectInternetMethod_UIAudit_Prestate_20260929`

Post-check at the AppData top level found zero remaining `DirectInternetMethod_*` legacy backup directories.

Moved out of Temp into `archive/machine-snapshots/temp-public-verification/`:
- `dim131-public-verify`
- `dim132-public-final`
- `dim140-public-verify`

Copied into the root archive:
- the complete predecessor `DirectDnsDpiHarness`.

Consolidated into canonical `delivery/` with source hash + destination hash verification:
- authoritative v1.2.1 Windows/Linux artifacts;
- authoritative v1.3.1 Windows/Linux artifacts;
- authoritative v1.3.2 Windows/Linux artifacts;
- authoritative v1.4.0 Windows/Linux artifacts;
- current root checksum authority copied to `delivery/SHA256SUMS.txt`.

The copy manifest is `ARTIFACT_CONSOLIDATION_MANIFEST.json` and records 9 verified consolidation actions.

### What correctly remains outside the source root

These paths are deliberately **not moved**, because moving them would break or distort the installed product:
- `C:\Program Files\DirectInternetMethod\Privileged` — installed privileged runtime.
- `%LOCALAPPDATA%\Programs\DirectInternetMethod` — installed user GUI/docs/uninstaller.
- `C:\ProgramData\DirectInternetMethod` — action state, service log, updater cache and install logs.
- `%LOCALAPPDATA%\DirectInternetMethod` — current Router Gateway cache.

The Remote Commander safety-backup store contains at least 200 matching historical paths and the search result was truncated. It is an external recoverability store, not project authority; bulk deletion would add risk without improving the released product.

A crash dump `DirectInternetMethod.exe.67464.dmp` was discovered under AppData CrashDumps and copied non-destructively into `archive/machine-snapshots/crashdumps/DirectInternetMethod.exe.67464.dmp`. The archived copy is 6,219,229 bytes with SHA-256 `0714E2BC3407266ACDE55C7C9DB0F215DD634662ABDB0E2D0A49EFFAA7AE4162`; the original remains external and was not deleted.

### Remaining historical Git worktree directories

Six clean historical worktrees still exist outside the canonical root. Before any attempted cleanup, the audit created:

`archive/worktree-history/DirectInternetMethod_all_refs_precleanup_20261001.bundle`

The bundle was created successfully and `git bundle list-heads` successfully enumerated all locally-known heads, tags, origin refs, the stash, and all six linked worktree HEAD refs. This preserves Git history before directory cleanup.

The environment blocked the destructive `git worktree remove` operation. Therefore these directories are classified **EXTERNAL / REDUNDANT-HISTORICAL / CLEAN**, not falsely reported as removed. Their release artifacts have already been consolidated, and their Git refs are preserved in the bundle.

## 4. Current product capabilities — evidence-backed

### Direct path

v1.4.0 has four bounded direct, non-VPN/non-proxy method families:

1. **Encrypted DNS / direct-IP DoH** through ctrld, with `leak_on_upstream_failure=false`.
2. **HTTP/80 host split/desync** using hostlist-scoped fake + multisplit.
3. **TLS/SNI TCP/443 desync** using hostlist-scoped fake + multidisorder.
4. **QUIC UDP/443 desync** using hostlist-scoped fake handling rather than globally disabling UDP/443.

System invariants are explicit: no physical-adapter DNS rewrite, no broad `0.0.0.0/1` or `128.0.0.0/1` tunneling routes, no WinHTTP proxy, no VPN default-route takeover, and no all-domain packet interception.

### Windows product

- Native WPF app.
- Preferred startup size 1289×632 DIP; installed-host UI automation verified exact 1289×632 at 96 DPI with all six actions visible and zero overlap.
- Fixed-command privileged service; normal actions are service-mediated.
- Bundled PowerShell 7.6.6; normal product operation does not require ChatGPT.
- Owned ctrld service, loopback ULA/NRPT lifecycle and owned zapret/WinDivert resources.
- Service-mediated online update.
- Windows updater verifies GitHub release asset digest, published SHA256SUMS entry, and the downloaded installer SHA-256 before launching the installer.
- Installed v1.3.2→v1.4.0 public update passed without UAC.
- Real-host v1.4.0 Start→ACTIVE→Stop→Recovery passed with exact rollback and a clean final OFF state.

### Linux product

- GTK/Adwaita UI.
- Protected backend under `/usr/lib/directinternetmethod`.
- Dedicated temporary DNS link + ctrld DoH + systemd-resolved.
- Owned nftables table/NFQUEUE path for only TCP/80, TCP/443 and UDP/443 classes required by nfqws.
- Strict path/UID/home checks in the protected controller.
- Narrow polkit rule grants the local active user only the fixed Start/Stop/Recovery systemd actions.
- Installer skips repeat administrative authorization when the installed protected backend hashes already match the package.
- Public-package installed identity and Start→ACTIVE→Stop→Recovery clean lifecycle have passed.

### Router Gateway

Router Gateway is a separate, non-privileged configuration/data feature, not part of the direct packet engine:
- L2TP/IPsec preferred.
- PPTP retained only as legacy compatibility fallback.
- 9 ready profiles from VPN Gate, VPNBook and Pilovali.
- copy-ready server/user/password/PSK data;
- offline snapshot plus online refresh;
- endpoint health tests that do not mutate host routing/DNS;
- private/loopback/link-local DNS answers fail closed;
- model/vendor configuration guidance.

Authenticated router tunnel success is intentionally not claimed as universal; it remains router-model/firmware dependent.

## 5. Verification status

The current v1.4.0 release itself remains **FINAL / PUBLISHED / INSTALLED VERIFIED**.

Key release authority:
- tag `v1.4.0`
- commit `910e22d06209e244f8caf809c9821e3fb16c7cc1`
- source tree `db7f8e02ca706ca0c74a54901368a6a61a4733cd`
- Windows public artifact SHA-256 `69F0EF63E3A658EC616362FC7D7ADAB95337EC3A034D3981DF44C685DB9FCB93`
- Linux public artifact SHA-256 `4CF521FD3821F9204999C0F17B217A60DC7117AC68421E5634FDF8D15D3C485E`

The later main evidence commit `8da94b821bfabf01ef993e730def170f7f5ddbb5` has GitHub Actions run `36841799782`: `linux-source` PASS and `windows-source` PASS.

A fresh local Windows contract audit during this machine audit also returned **PASS** across the full contract set, including direct-method boundaries, ownership, rollback controls, updater controls, installer controls, UI layout guards, runtime pins and bundled-PowerShell checks.

A tracked-secret signature scan over Git-controlled text found no RSA/EC/OpenSSH private key header, GitHub PAT pattern, OpenAI-style secret pattern, AWS access-key pattern or Bearer-token literal.

Git object integrity audit exited successfully; reported dangling objects are consistent with prior rebases/worktrees and are not repository corruption.


## 6. Deep-audit findings, root causes and controls

### F1 — release checksum serialization drift: CLOSED

**Finding (CONFIRMED):** the canonical delivery directory initially still carried an older v1.3.0 `delivery/SHA256SUMS.txt`, while root release metadata for v1.4.0 declared the v1.4.0 public checksum asset.

**Root cause:** historical build worktrees carried exact release assets, while the canonical root retained an ignored delivery checksum from an earlier release. The root `SHA256SUMS.txt` had current v1.4.0 content but LF serialization; the public release checksum asset is the CRLF 223-byte file.

**Prevention/control:** canonical delivery now contains the exact public v1.4.0 checksum asset:
- bytes: 223
- SHA-256: `7F80836A153EF0FFEF1A79D797502B773D8776DB99BBE21E1D81227A2D9EA609`

The consolidation script now pins that exact source/hash instead of relying on newest-file or line-ending assumptions. The hardened metadata audit verifies the checksum artifact's raw SHA-256 against `RELEASE.json`.

### F2 — platform publication metadata guard regression: CLOSED

**Finding (CONFIRMED):** `windows/RELEASE.json` remained release-ready with `publication=PENDING` after v1.4.0 had already passed publication and installed-host acceptance.

**Root cause:** `release_metadata_audit.py` used a brittle substring gate requiring literal `PUBLISHED_VERIFIED`. Current root status is `PASS_FINAL_PUBLISHED_INSTALLED_VERIFIED_V1_4_0`; publication verification therefore existed semantically but the old guard did not enter its platform-publication consistency checks.

**Fix:** post-release source control metadata now records v1.4.0 publication/installed acceptance, and root `RELEASE.json` carries explicit publication metadata. The immutable v1.4.0 tag/assets and installed binaries were not changed.

**Guard:** `release_metadata_audit.py` now:
- recognizes published+verified states structurally rather than by the brittle contiguous substring;
- requires root and Windows publication metadata;
- compares tag, tag commit, release URL and publication timestamp;
- verifies the declared checksum artifact exists and its raw SHA-256 equals the release metadata.

**Regression:** the hardened metadata audit returns PASS.

### F3 — text-evidence raw hashes were worktree-serialization-specific: CLASSIFIED / CONTROLLED

The Project Brain recorded raw SHA-256 values for three final v1.4 evidence JSON files. Those values exactly match the historical finalization worktree, but the canonical checkout has different raw worktree-byte hashes while Git reports **zero content diff** between the two refs.

Git blob identities for stable tracked-content authority are:
- `evidence/WINDOWS_140_HOST_FINAL_ACCEPTANCE_20261001.json` → blob `0f5864f28edd504cd910b65a1741f302cac432a8`
- `evidence/LINUX_140_PUBLIC_INSTALLED_FINAL_ACCEPTANCE_20261001.json` → blob `e5b01fa734e33a94dc11472b3ee9a57ecd0d6ea6`
- `evidence/DIM_140_PUBLICATION_INSTALLED_FINAL_20261001.json` → blob `f81ee8cdbd7f331d7f8fa3aa38ef31e4a07debb3`

This is **not content corruption**. For Git-tracked text, the durable identity is the Git blob/commit plus canonical repository content; raw worktree SHA should only be treated as a byte-serialization hash when EOL policy is fixed.

### F4 — historical machine duplication: CONTROLLED

The Remote Commander safety-backup store contains:
- 920 project-related files
- 799 unique contents
- 741,236,438 total bytes
- 672,381,380 unique bytes

Those backups remain outside the project root by design. Copying them into the repository would add hundreds of MB of duplicate safety material without increasing project truth. Their inventory is recorded in `REMOTE_COMMANDER_PROJECT_BACKUPS.json` and its summary.

Six historical linked worktrees are clean and redundant. Safe `git worktree remove` was attempted but failed with Windows permission denied. They remain **EXTERNAL / REDUNDANT-HISTORICAL / CLEAN**. Their release assets are consolidated and their refs are preserved by the 45,355,308-byte pre-cleanup bundle, SHA-256 `5308BF413E17241CB4421137C7F4E5077E4F9734518FB132D90DD83282D0F415`.

### F5 — canonical delivery mixed product and non-product artifacts: CLOSED

Untagged/local v1.0.1 binaries and the v1.2 bootstrap runner were removed from canonical `delivery/` and categorized under the local archive. Known intermediate v1.3.0/v1.3.1 artifacts were separately preserved under `archive/superseded-artifacts/`. Canonical delivery now contains tagged public-version product artifacts only, plus README and the exact current checksum asset.

## 7. Strict code/design findings that do not invalidate v1.4.0

These are future-maintenance findings, not retroactive release failures:

- **Linux updater integrity asymmetry — PROBABLE / future hardening.** Linux verifies the downloaded ZIP against `SHA256SUMS.txt`, but unlike Windows it does not additionally require GitHub API asset `digest` to equal that checksum. HTTPS + SHA-256 verification is present and v1.4.0 public identity was independently verified; a future release should add digest/checksum/download three-way agreement and exact-one-asset selection.
- **Router Gateway L2TP health heuristic — CONFIRMED limitation.** After ICMP failure, both Windows and Linux currently use TCP/443 as a generic reachability fallback for L2TP/IPsec profiles. The UI correctly labels this a health heuristic rather than a full authenticated tunnel handshake, but TCP/443 is not a protocol-aware L2TP/IPsec probe. Future work should either label it purely generic endpoint reachability or add bounded UDP 500/4500 diagnostics where meaningful.
- **Windows installer signing — OPEN / non-blocking for v1.4.0.** Authenticode remains absent.
- **Repository license — OWNER/LEGAL DECISION OPEN.** No license is selected automatically.
- **Physical-router authenticated tunnel E2E — MODEL/FIRMWARE DEPENDENT.** Universal compatibility remains unproven by design.
- **HTTP/3 application-level QUIC — UNPROVEN on current validation host.** UDP/443 QUIC desync configuration/runtime is verified; application HTTP/3 was not independently exercised because the available curl lacked HTTP/3.

No additional fragmentation/window-size/global interception/DPI-bypass runtime was promoted merely to increase feature count; existing evidence still favors the smaller bounded v1.4.0 design.

## 8. GitHub/public authority re-verification

Live GitHub read-back during this audit confirms:
- repository is public and default branch is `main`;
- `main` is protected and points to `8da94b821bfabf01ef993e730def170f7f5ddbb5`;
- required checks are `linux-source` and `windows-source`;
- active tag ruleset: `Protect release tags`;
- latest release is non-draft/non-prerelease `v1.4.0`, published 2026-10-01T08:37:55Z;
- the three public asset sizes/digests exactly match project authority;
- current main CI run `36841799782` concluded success;
- no open pull requests were present at the time of the audit.

The connector cannot read the full branch-protection administration endpoint (HTTP 403 for that endpoint), so claims beyond the branch object's exposed protection/check data remain based on the earlier recorded governance audits.

## 9. Roadmap reconstruction and grounded state

**Completed / evidence-backed:** predecessor proof and browser/lifecycle validation → standalone v1.0.0 Windows/Linux → v1.1.0 runtime stabilization → v1.2.0 direct updater → v1.2.1 deterministic Linux/governance hardening → v1.3.0 Router Gateway → v1.3.1 UI/provider update → v1.3.2 grid visibility fix → v1.4.0 bounded multiprotocol direct engine → protected publication → public hash verification → installed Windows/Linux acceptance → this deep machine/root reconciliation.

**Current:** v1.4.0 maintenance authority. No release-critical gate is open.

**Deferred future release work:** Linux updater digest symmetry; protocol-aware Router Gateway diagnostics; optional code/installer signing infrastructure; owner legal license decision; router-model-specific authenticated E2E; HTTP/3-capable application validation if needed.

No fabricated progress percentage is used. The v1.4.0 DoD is complete by acceptance evidence; future items are a separate maintenance roadmap.

## 10. Final audit disposition

**PASS_FINAL_DEEP_MACHINE_PROJECT_AUDIT_WITH_DOCUMENTED_NONBLOCKING_BOUNDARIES**

Canonical root is now the project-control center for:
- current source and release authority;
- cumulative Project Brain/evidence;
- historical tagged delivery artifacts;
- exact current public checksum authority;
- archived predecessor and machine snapshots;
- superseded/intermediate classification;
- external-store/worktree indexes and limitations.

The audit does not claim that every inaccessible/system-protected byte on C: was content-indexed. It does establish project provenance and current authority through multiple independent paths: Git history/refs, installed state, release artifacts/hashes, live GitHub read-back, local contracts/builds, predecessor evidence, machine footprint searches, and explicit classification of external stores.

**Exact next action:** merge only the audit/control-metadata changes through the protected branch workflow; keep immutable `v1.4.0` tag/assets untouched. Runtime feature changes belong to a future release branch.
