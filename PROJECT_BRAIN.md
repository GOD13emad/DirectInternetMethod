# PROJECT BRAIN — Direct Internet Method

Status: FINAL_PUBLISHED_VERIFIED_1_1_0
Final Objective: standalone Windows + Linux direct-connect application with independent install/UI/rollback/online update and GitHub release; normal Start/Stop/Recovery must not require administrator authorization.
DoD: PASS_FINAL_RELEASE on both platforms + live install/runtime/rollback validation + hash-pinned artifacts + GitHub main/tag/release published + online-update verification.

## Authoritative current state
- Source authority: working tree on branch `release/v1.1.0-candidate`; pre-promotion HEAD was `8ffe1627e45045e083a3d86e4e3dfd0902262725`.
- Cross-platform 1.1.0 product acceptance is **PASS_FINAL_RELEASE** and GitHub publication/update verification is **PUBLISHED_VERIFIED**.
- Windows final artifact:
  - `delivery/DirectInternetMethod_1.1.0_Windows_Setup.exe`
  - bytes: 157,078,634
  - SHA-256: `E59B61C4E17F30AFBA3F2E0234B42759435A114B7F4264BCA7C1D253A950C9B0`
  - service SHA-256: `F1BF7D8FC5A7F1DEF093CC635A4B5204882418A755ADFBF6774685DC58037F68`
  - manifest SHA-256: `F60D21EC678B9CB5F44D2CEA70DDFC1C3F4C80D4799A37131BAC18DC5536AD42`
  - Authenticode: NotSigned (deferred, not a release blocker).
- Windows final artifact was installed on the real host and live-tested:
  - normal-user Start control PASS, action `done/0`;
  - ACTIVE: YouTube=204, OpenAI=401, GitHub=200;
  - ctrld SCM service owns UDP/TCP ULA:53; winws + protected WinDivert active;
  - physical adapter DNS unchanged; no broad /1 routes; WinHTTP unchanged; pre-existing ICS Running/PID preserved;
  - Stop PASS with exact rollback; Recovery/no-state PASS;
  - final clean state: no state file, owned NRPT, ULA, ctrld process, winws process, or owned WinDivert residue.
- Windows Sandbox lifecycle also PASS with restricted Basic User controls.
- Linux 1.1.0 is **PASS_FINAL_LINUX_1_1_0**:
  - `delivery/DirectInternetMethod_1.1.0_Linux_x86_64.zip`
  - bytes: 8,139,344
  - SHA-256: `621AD8512FDF4E53DFF283DDFBEB620DDD80631C2DB4785536F8523EAA0AC861`
  - live ACTIVE YouTube=204, OpenAI=401, GitHub=200;
  - Stop/Recovery/no-admin normal actions PASS;
  - independently reproduced deterministic archive hash on Windows and Linux.
- Windows and Linux contract audits: PASS.
- `SHA256SUMS.txt` contains the exact final Windows/Linux artifact hashes.

## Roadmap
Completed: v1.0.0 Windows/Linux final release and publication.
Completed: Windows 1.1.0 native WPF + privilege-separated service + bundled PowerShell 7.6.6.
Completed: Windows owned demand-start ctrld SCM lifecycle, collision guard, completion/timeout regression.
Completed: Windows fresh Sandbox normal-user Start/Stop/Recovery acceptance.
Completed: Windows real-host final-artifact install/ACTIVE/Stop/exact rollback/Recovery acceptance.
Completed: Linux protected backend, no-admin actions, live network, rollback/recovery, deterministic build.
Completed: release docs/metadata reconciled to 1.1.0 and final Windows installer rebuilt/tested.
Completed: cross-platform final acceptance + SHA256SUMS.
Completed: main/tag `v1.1.0` + GitHub release assets + latest endpoint + full downloaded SHA-256 update verification.
← CURRENT: no release blocker remains; maintenance/compatibility monitoring only.
Deferred: trusted Authenticode signing.

## Failure → Root Cause → Prevention → Regression
1. Linux installer used Bash readonly `UID` → `USER_UID/USER_GID`; regression PASS.
2. Linux unprivileged polkit postcheck false-failed → protected root-side verification; regression PASS.
3. Linux backup included root-owned transient runtime → persistent-file-only backup; regression PASS.
4. Linux ctrld/nfqws died with oneshot parent → independent transient systemd services; live regression PASS.
5. nft queue canonicalization broke ownership guard → accept canonical/creation forms; regression PASS.
6. Linux UI /proc ownership false-negative under Yama → systemd unit/MainPID UI verification; regression PASS.
7. Cross-host ZIP bytes differed → fixed ZIP metadata + ZIP_STORED; deterministic cross-host hash PASS.
8. Windows assumed loopback InterfaceIndex=1 → dynamic owner of `::1/128`; Sandbox/host regression PASS.
9. Windows ctrld child-process model incompatible with ctrld Windows lifecycle → owned demand-start SCM service; UDP/TCP :53 + DNS regression PASS.
10. Windows backend completion stayed running after ACTIVE → deterministic process completion handling; Start/Stop/Recovery `done/0` regression PASS.
11. Host validator could not read SYSTEM `Process.Path` as normal user → validate ctrld service ImagePath/PID/listeners + privileged runtime evidence; harness regression PASS.
12. Host validator boolean-array aggregation produced false-negative → named boolean map; all active checks PASS.
13. Rollback validator compared different default-route schemas → normalize route fields; exact rollback PASS.
All three validator failures were harness defects; product runtime remained healthy and their failing evidence is preserved.

## Evidence / Knowledge
- Cross-platform final: `evidence/DIM_110_FINAL_ACCEPTANCE_20260930.json` — SHA-256 `5610C74C0265D9F614A8619A4E6C6E008DEC7CCEC0774EF0720B8616E1A89D2C`.
- Gate status: `evidence/DIM_110_GATE_STATUS_20260930.json` — SHA-256 `DC7E7E0544D671BE3D21876159E7629101B59586FBE401AE71019B46FE44AB5A`.
- Windows final artifact acceptance: `evidence/WINDOWS_110_HOST_FINAL_ARTIFACT_ACCEPTANCE_20260930.json` — SHA-256 `0E37A969EE9C91DF4BD4FCBDAF330A3D4122DCA8DEB7FF1D577D1B2FAC0A3FA9`.
- Windows final install: `evidence/WINDOWS_110_HOST_FINAL_INSTALL_RESULT_20260930.json` — SHA-256 `846993CCF9F5C381633A61FF0E3689FCE5BC207CC4012D1D8600F9B2BC45CAC8`.
- Windows active: `evidence/WINDOWS_110_HOST_ACTIVE_ACCEPTANCE_20260930.json` — SHA-256 `52BEEA2E4272E640BBC2D52BB8E25B1F847FA5FC81BD890EACEE6B9C1AA4DAE7`.
- Windows exact rollback: `evidence/WINDOWS_110_HOST_ROLLBACK_ACCEPTANCE_20260930.json` — SHA-256 `C779172D6DA4F270B06DEF1EE1658973D855414F678552CBCB1980234E93064B`.
- Windows recovery: `evidence/WINDOWS_110_HOST_RECOVERY_ACCEPTANCE_20260930.json` — SHA-256 `CF5BC74B02353954CF73D908ED50E19719024122D4BA1D0D8EFAFED23DC2F3AD`.
- Windows Sandbox: `evidence/WINDOWS_110_SANDBOX_FINAL_ACCEPTANCE_20260930.json` — SHA-256 `EECB896189B88CADA49DD0C8D8D4D48B4D13A11196135C65C2DE757A7DD795BE`.
- Linux final: `evidence/LINUX_110_FINAL_ACCEPTANCE_20260930.json` — SHA-256 `DE4560B6F1AC168EF58453E62A9A809F683560C421E529AE12BA61CDA28668E6`.
- ctrld root cause: `evidence/WINDOWS_110_CTRLD_SERVICE_ROOT_CAUSE_20260930.json`.
- action completion root cause: `evidence/WINDOWS_110_ACTION_COMPLETION_ROOT_CAUSE_20260930.json`.
- Publication final: `evidence/DIM_110_PUBLICATION_FINAL_20261001.json` — SHA-256 `8CAE7F56239575001B665BD4F4240CE999F084D408597F041E13F4327915857D`.
- Published update-flow verification: `evidence/DIM_110_GITHUB_PUBLICATION_VERIFY_20261001.json` — SHA-256 `461A4CD7C270F18F1E4B732A6AF308BD6B23FFDA2D2AA003AED2C89ADC8CE130`.
- Additional host exact-rollback revalidation: `evidence/WINDOWS_110_HOST_LIVE_POSTROLLBACK_20261001.json` — SHA-256 `DFB518795599780DBF960791B4ED3F435F77CD2C5C0816B5006210ABAB74B566`.
- Post-final transient custom Start observation: `evidence/WINDOWS_110_POSTFINAL_REACTIVATION_20261001.json` — SHA-256 `84AF92E5DA8DF1FEA549D57B9687950C3BAFC1E12DDFA4A7FE72AB16D55BF142`; source attribution UNPROVEN, not classified as product auto-start defect.
- Final clean-state stabilization: `evidence/DIM_110_FINAL_CLEAN_STATE_20261001.json` — SHA-256 `7751A356EF1FFB00BEC0C20E594A12534068D8EA9980964D094A7E90E1584788`; Stop/Recovery done/0, state absent, ctrld stopped, winws/ULA/owned NRPT zero.
- Candidate-cycle evidence was copied to immutable `WINDOWS_110_HOST_CANDIDATE_*` records before final-artifact retest.
- Earlier stale parallel hashes `D6AF…/A011…/5AEF…` are superseded and must not be used as release authority.

## Exact Next Action
No release-critical action remains. Keep v1.1.0 immutable; future changes require a new version. Optional deferred work: Authenticode signing when trusted signing credentials are available.

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

- 2026-09-30: Windows Sandbox no-admin service-control path proven with Basic User restricted token; Start failure reproduced and rolled back cleanly; ctrld v1.5.7 SCM lifecycle incompatibility isolated and confirmed against upstream v1.5.7 source and a successful SCM-service experiment.

- 2026-09-30: Windows ctrld converted to owned demand-start SCM service; fresh Sandbox Start reached ACTIVE and restored YouTube while preserving DNS/routes/WinHTTP/ICS.
- 2026-09-30: service output-pipe inheritance deadlock fixed; fresh final Sandbox Start/Stop/Recovery all reached `done/0`, with clean rollback/recovery. Final Windows candidate installer SHA-256 `D6AFABEF9A951CB8D94F6730325CC791CDFFAA78906FF54036861379BEE2688B`.
- 2026-09-30: Linux contract audit rechecked on `aliemad-Labtop`; PASS; Linux artifact hash remained `621AD8512FDF4E53DFF283DDFBEB620DDD80631C2DB4785536F8523EAA0AC861`.

- 2026-09-30: Windows 1.1.0 fresh Sandbox acceptance PASS after SCM lifecycle + deterministic service completion fixes; restricted Basic User Start/Stop/Recovery PASS and exact rollback clean. Host Windows live-network gate intentionally remains open.
- 2026-09-30: host Windows 1.1.0 candidate installed and live-tested; normal-user Start/Stop/Recovery PASS, ACTIVE YouTube=204/OpenAI=401/GitHub=200, exact rollback PASS.
- 2026-09-30: host validation false-negatives isolated to test harness permissions/aggregation/schema normalization; failing evidence preserved; named-check and normalized-route validators PASS.
- 2026-09-30: release docs/metadata corrected from stale 1.0/CANDIDATE descriptions; final installer rebuilt as SHA-256 `E59B61C4E17F30AFBA3F2E0234B42759435A114B7F4264BCA7C1D253A950C9B0`.
- 2026-09-30: exact final Windows artifact installed and retested on real host; Start/ACTIVE/Stop/rollback/Recovery PASS. Cross-platform 1.1.0 acceptance is PASS; publication remains.

- 2026-10-01: GitHub v1.1.0 publication verified end-to-end. `/releases/latest` returned v1.1.0; Windows and Linux release assets were downloaded and matched published `SHA256SUMS.txt` exactly. Release state promoted to FINAL/PUBLISHED_VERIFIED.

- 2026-10-01: one unattributed custom Start control appeared after release verification; it completed normally. Stop/Recovery restored clean OFF state and no recurrence was observed during the final stabilization window. No product auto-start defect was proven.
