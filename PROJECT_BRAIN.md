# PROJECT BRAIN — Direct Internet Method

Status: INCOMPLETE_FOR_CROSS_PLATFORM_1.1.0
Final Objective: standalone Windows + Linux direct-connect application with independent install, icon, shortcuts, UI controls, rollback, online update, and GitHub release; normal Start/Stop/Recovery must not require administrator authorization.
DoD: PASS_FINAL_RELEASE on both platforms + live install/runtime/rollback validation + hash-pinned deterministic artifacts + GitHub main/release published.

## Authoritative current state
- Git/source authority: the Windows project working tree for `DirectInternetMethod`; host-specific absolute paths are intentionally omitted from the portable Brain.
- Latest fully promoted cross-platform release remains `v1.0.0`.
- Linux 1.1.0: **PASS_FINAL_LINUX_1_1_0**.
  - Installed user app and protected backend 1.1.0.
  - Normal Start/Stop/Recovery live-proven without admin prompt.
  - Direct baseline with VPN off: YouTube timed out; OpenAI=401; GitHub=200.
  - With Direct Internet Method active: UI `load_state()=ACTIVE`, `verify_live()=true`, YouTube=204, OpenAI=401, GitHub=200.
  - ctrld and nfqws are independent systemd transient services and were observed `active/running`.
  - Stop PASS, Recovery/no-state PASS, state and `dimdns0` clean after stop.
  - Existing Linux VPN `OIG-VPN-LIVE` was temporarily disconnected only for the direct test and restored successfully.
- Linux deterministic artifact:
  - `delivery/DirectInternetMethod_1.1.0_Linux_x86_64.zip`
  - bytes: 8,139,344
  - SHA-256: `621AD8512FDF4E53DFF283DDFBEB620DDD80631C2DB4785536F8523EAA0AC861`
  - independently reproduced with identical hash on Windows and Linux; 14/14 package input hashes identical.
- Windows 1.1.0:
  - contract audit PASS.
  - privileged service observed installed/running.
  - installer exists and hash verified:
    `EE24A8682D663715901CE7CF48A04B7E0F6E328C381D4204DE2202C49A0DD255`, 157,083,679 bytes.
  - normal-run no-UAC/service/update contracts PASS.
  - **live Windows 1.1.0 network Start/Stop acceptance is MISSING**.
  - Windows network was intentionally kept read-only per locked project decision while owner is actively using that machine.
- Therefore cross-platform v1.1.0 promotion/publication is NOT yet authorized by evidence.

## Roadmap
Completed: v1.0.0 Windows/Linux final release and GitHub publication.
Completed: Windows 1.1.0 native WPF + privileged service + bundled PowerShell 7.6.6 architecture and contract audit.
Completed: Linux 1.1.0 protected backend, no-admin normal actions, online update hash gate, ownership and rollback guards.
Completed: Linux install and lifecycle root-cause fixes.
Completed: Linux 1.1.0 live Start/UI/DNS/HTTPS/process-service/Stop/Recovery acceptance.
Completed: cross-host deterministic Linux 1.1.0 build.
← CURRENT: preserve/version 1.1.0 candidate without promoting cross-platform release.
Open critical gate: dedicated Windows 1.1.0 live network validation window.
After that: final cross-platform evidence → root RELEASE.json 1.1.0 → SHA256SUMS.txt → main/tag v1.1.0 → GitHub release assets → online-update verification.
Deferred: trusted Authenticode signing for Windows.

## Failure → Root Cause → Prevention → Regression
1. Linux privileged installer assigned Bash readonly `UID`.
   - Fix: `USER_UID/USER_GID`.
   - Regression: `install_avoids_readonly_uid_variable`.
2. User installer probed protected polkit directory directly and false-failed after successful backend install.
   - Fix: protected postconditions verified root-side; user retry verifies accessible backend hashes/state.
   - Regressions: `install_no_unprivileged_polkit_probe`, `install_idempotent_backend_hash_gate`.
3. User installer backed up whole app tree and hit root-owned transient runtime files.
   - Fix: backup only persistent user files; exclude `directmethod/` runtime state/logs/config.
   - Regression: `install_backup_excludes_runtime_state`.
4. ctrld/nfqws were children of a oneshot action unit and systemd killed them after action completion.
   - Fix: independent transient systemd services via `systemd-run --collect --service-type=exec`.
   - Regression: `daemon_lifecycle_transient_services`.
5. Recovery nft ownership guard expected creation syntax `queue num 200 bypass`, but `nft list` canonicalized it to `queue flags bypass to 200`.
   - Fix: ownership guard accepts both semantically equivalent forms.
   - Regression: `nft_queue_canonical_guard`.
6. UI attempted `/proc/<root-pid>/exe` ownership verification under Ubuntu Yama `ptrace_scope=1`, causing false STALE.
   - Fix: unprivileged UI verifies fixed systemd unit name + MainPID + ActiveState; root backend retains exact executable ownership for destructive cleanup.
   - Regression: `ui_systemd_unit_ownership`.
7. Cross-platform ZIP compression produced different bytes despite identical inputs.
   - Fix: fixed ZipInfo metadata + ZIP_STORED.
   - Gate: independently built Windows/Linux archive hashes must match.

## Evidence / Knowledge
- `evidence/LINUX_110_FINAL_ACCEPTANCE_20260930.json`
  - SHA-256 `de4560b6f1ac168ef58453e62a9a809f683560c421e529ae12ba61cda28668e6`
- `evidence/DIM_110_GATE_STATUS_20260930.json`
  - SHA-256 `c54669c83fcb196777f583083be409d7b172f1c043435ee958e4fff0d68f1a78`
- `evidence/LINUX_110_LIVE_LIFECYCLE_FAILURE_20260930.json`
  - preserved failure/root-cause record.
- `evidence/DIM_110_RECONCILE_20260930.json`
  - preserved reconcile history.
- Windows installer build evidence: `evidence/WINDOWS_110_INSTALLER_BUILD_20260930.json`.
- Contract audits: Windows PASS; Linux PASS on both authoritative Windows tree and Linux host.
- Do not call cross-platform 1.1.0 Final until Windows live network acceptance exists.

## Exact Next Action
During an explicitly available Windows network-test window, capture Windows prestate; live Start through the installed 1.1.0 service; verify product process ownership, DNS/HTTPS and absence of unintended default-route/adapter-DNS/WinHTTP/ICS changes; Stop; verify exact rollback; Recovery/no-state. If PASS, promote 1.1.0: update RELEASE.json/RELEASE_NOTES, generate SHA256SUMS.txt, merge candidate branch to main, tag v1.1.0, create GitHub release with Windows/Linux assets + sums, and verify online updater against the published release.

## HISTORY
- 2026-09-29: v1.0.0 Windows and Linux PASS_FINAL_RELEASE; GitHub v1.0.0 published and verified.
- 2026-09-30: Windows 1.1.0 native UI/service/bundled-runtime candidate built; contract audit PASS.
- 2026-09-30: Linux installer readonly-UID failure found and fixed.
- 2026-09-30: Windows/Linux source drift reconciled; Linux contract audits PASS on both hosts.
- 2026-09-30: Linux protected backend installed; false polkit postcheck and backup-scope failures found and fixed.
- 2026-09-30: Linux live Start exposed oneshot child-lifecycle failure; systemd transient-service fix implemented.
- 2026-09-30: nft canonical ownership mismatch found from live recovery and fixed.
- 2026-09-30: UI root-process ownership false-negative under Yama found and replaced by systemd unit/MainPID ownership verification.
- 2026-09-30: Linux 1.1.0 live UI/network/rollback PASS; original VPN restored.
- 2026-09-30: final Linux package reproduced identically on Windows and Linux with SHA-256 `621AD8512FDF4E53DFF283DDFBEB620DDD80631C2DB4785536F8523EAA0AC861`.
