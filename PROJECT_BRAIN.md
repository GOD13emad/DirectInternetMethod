# PROJECT BRAIN — Direct Internet Method

Status: FINAL_V1_4_0_DIRECT_MULTIPROTOCOL_PUBLISHED_INSTALLED_VERIFIED
Final Objective: standalone Windows + Linux direct-connect application with independent install/UI/rollback/online update and GitHub release; normal Start/Stop/Recovery must not require administrator authorization.
DoD: PASS_FINAL_RELEASE on both platforms + live install/runtime/rollback validation + hash-pinned artifacts + GitHub main/tag/release published + online-update verification.


## CURRENT maintenance audit — 2026-10-01 deep machine/project reconciliation
- **Status:** `PASS_FINAL_DEEP_MACHINE_PROJECT_AUDIT_WITH_DOCUMENTED_NONBLOCKING_BOUNDARIES`. Immutable v1.4.0 release authority is unchanged; this change set is audit/control-metadata only.
- **Canonical Root:** `C:\Users\Aa.Emad\source\repos\DirectInternetMethod`. Project origin was reconstructed from the pre-Git predecessor `DirectDnsDpiHarness` through v1.0.0→v1.4.0.
- **Machine Reconciliation:** predecessor, old AppData audit/install snapshots, old Temp public-download verification caches and the discovered Windows crash dump are categorized under local `archive/`. Downloads and Downloads/My Project strong-signature searches found no Direct Internet Method material; generic `direct_method` matches belonged to an unrelated scientific project and were not moved.
- **Delivery Hygiene:** canonical `delivery/` now contains tagged public-version product artifacts only, plus `README.md` and exact public v1.4.0 `SHA256SUMS.txt` (223 bytes / `7F80836A153EF0FFEF1A79D797502B773D8776DB99BBE21E1D81227A2D9EA609`). Untagged v1.0.1 artifacts and the v1.2 bootstrap runner were moved to classified local archive categories; known intermediate v1.3.x variants are preserved as superseded, not release authority.
- **External Stores:** Remote Commander safety store indexed at 920 files / 799 unique contents / 672,381,380 unique bytes; intentionally remains external. Six historical linked Git worktrees are clean and redundant; ACL denied safe removal, but all refs are preserved in `archive/worktree-history/DirectInternetMethod_all_refs_precleanup_20261001.bundle` (45,355,308 bytes / `5308BF413E17241CB4421137C7F4E5077E4F9734518FB132D90DD83282D0F415`).
- **Failure→Prevention #1:** stale delivery checksum serialization was closed by pinning the exact v1.4.0 public checksum asset and adding raw checksum-artifact SHA verification to release metadata audit.
- **Failure→Prevention #2:** `windows/RELEASE.json` remained publication=PENDING because the metadata guard required the brittle literal substring `PUBLISHED_VERIFIED`. Root/platform publication metadata is now explicit; the guard structurally requires published+verified status, validates publication fields, and regression PASSes.
- **Tracked Text Identity:** prior Brain SHA-256 values for three v1.4 final evidence JSONs are retained as historical raw hashes of the finalization worktree, not portable tracked-text identities. Canonical stable Git blobs are Windows final `0f5864f28edd504cd910b65a1741f302cac432a8`, Linux final `e5b01fa734e33a94dc11472b3ee9a57ecd0d6ea6`, publication final `f81ee8cdbd7f331d7f8fa3aa38ef31e4a07debb3`; Git content diff to finalization ref is zero.
- **Fresh V&V:** Windows contract PASS; Linux contract PASS; Router Gateway contract PASS; hardened release-metadata audit PASS; tracked syntax/build audit PASS (47 PowerShell, 11 Python, 0 parse/compile errors; service + GUI builds 0 warnings/0 errors); Git fsck shows dangling historical objects only, no corruption.
- **GitHub Read-back:** protected `main` at `8da94b821bfabf01ef993e730def170f7f5ddbb5`, required `linux-source` + `windows-source`, active `Protect release tags` ruleset, v1.4.0 exact public asset digests, main CI `36841799782` success, tag CI `36837069912` success, no open PR at audit read-back. Full protection-admin endpoint is unavailable to the integration, so earlier governance evidence remains authority for settings not exposed by the branch object.
- **Deferred / Non-blocking:** Linux updater API-digest/checksum symmetry; protocol-aware L2TP/IPsec health diagnostics instead of generic TCP/443 fallback; optional Windows signing infrastructure; owner/legal repository license decision; model-specific authenticated router E2E; HTTP/3 application E2E if needed.
- **Knowledge/Evidence Record:** `evidence/DIM_DEEP_MACHINE_RECONCILIATION_20261001.json` (initial audit record SHA-256 `0B341B8B990A126B1AB5CF937F336EFE0F5828C78A6F6D6E550320B9C924FBA2`), detailed report `audit/20261001_deep_machine_reconciliation/DEEP_AUDIT_REPORT.md`.
- **Open Gates / Critical Path:** no v1.4.0 release blocker. Only protected merge of audit/control-metadata reconciliation remains in this maintenance change set; immutable tag/assets must not change.
- **Brain Status:** CURRENT / FINAL release + CURRENT maintenance-audit record.

## CURRENT v1.4.0 Direct multi-protocol engine
- **Current Accepted Authority:** FINAL/PUBLISHED/INSTALLED_VERIFIED at immutable tag `v1.4.0` and protected-main release commit `910e22d06209e244f8caf809c9821e3fb16c7cc1`; source tree `db7f8e02ca706ca0c74a54901368a6a61a4733cd`.
- **Direct Methods:** leak-closed direct-IP DoH; hostlist-scoped HTTP/80 fake+multisplit; hostlist-scoped TLS/SNI TCP/443 fake+multidisorder; hostlist-scoped QUIC UDP/443 fake desync. No VPN, HTTP/SOCKS/WinHTTP proxy, default-route tunnel, physical-adapter DNS mutation, broad /1 route, or global all-domain interception.
- **Evidence-first exclusions:** DoH3/DoQ/DoT are supported by ctrld but isolated current-network tests did not return DNS answers, so they are not enabled. ECH remains browser/server negotiated rather than an OS direct-method toggle. IP fragmentation, wssize/window shrinking, automatic hostlist growth and a second DPI-bypass runtime remain deferred because their evidence/risk trade-off does not justify default complexity.
- **Public Artifacts:** Windows setup 157,103,781 bytes / SHA-256 `69F0EF63E3A658EC616362FC7D7ADAB95337EC3A034D3981DF44C685DB9FCB93`; Linux ZIP 8,159,881 bytes / `4CF521FD3821F9204999C0F17B217A60DC7117AC68421E5634FDF8D15D3C485E`; checksum file `7F80836A153EF0FFEF1A79D797502B773D8776DB99BBE21E1D81227A2D9EA609`. Public re-download and GitHub digests match exactly.
- **Protected CI:** PASS on protected `main` run `36836911098` and immutable tag run `36837069912`.
- **Windows Public Update / Identity:** installed v1.3.2 updated directly to v1.4.0 through service control 131 without UAC; completion `done/0`; repeat check = `Already up to date`. Installed GUI `BF1E18CE…B354C`, service `770D5D1C…AF130`, manifest `7FFD3C00…716DF` match release authority.
- **Windows UI / Router Gateway:** installed GUI opens exactly 1289×632 at 96 DPI; all six actions visible, zero overlap; Refresh mouse/keyboard PASS; Router Gateway physical open PASS with 9 visible DataItems, 7 columns and VPN Gate/VPNBook/Pilovali present.
- **Windows Real-host Live Lifecycle:** PASS. Start reached `PASS_ACTIVE` with all four direct methods. Live probes: HTTP/80 YouTube=301, YouTube HTTPS=204, OpenAI=401, GitHub=200. Physical DNS `192.168.20.1`, default route via `192.168.20.1`, WinHTTP direct and ICS Running remained unchanged. Stop removed only owned NRPT/winws/WinDivert/ctrld/ULA and exact rollback PASS; Recovery `done/0`; final state is clean OFF with zero owned residue.
- **Linux Public Installed / Live:** public ZIP hash verified; installed user-space authoritative files and protected backend files match the public package exactly; protected backend=1.4.0; updater reports up-to-date. Pre-public live acceptance source tree is byte-identical to public tag tree and Start→ACTIVE→Stop→Recovery clean lifecycle PASS. Final state: no state file, dimdns0, nft table, ctrld/nfqws processes or transient units; physical default route and DNS preserved.
- **Linux Hygiene:** stale unreferenced user-space helper/host/runtime copies from older architecture were backed up at `~/.cache/DirectInternetMethod/legacy-residue-v140-20261001` and removed; current authoritative paths remain exact and clean.
- **Validation Boundary:** Windows installer remains unsigned. Physical-router authenticated L2TP/IPsec/PPTP success is model/firmware-dependent. HTTP/3 application-level QUIC is not separately claimed because current curl builds lack HTTP/3; UDP/443 QUIC desync configuration/runtime and both platform lifecycles are verified.
- **Knowledge/Evidence:** method selection + secure-DNS + Linux live evidence retained. The previously recorded SHA-256 values `4453FAE…47CB`, `7D987E…0AE2`, `09137E…BACA` are historical finalization-worktree raw-byte hashes. Stable tracked-content authority is Git blob `0f5864f2…32a8` (Windows final), `e5b01fa7…6ea6` (Linux final), `f81ee8cd…1e4a` (publication final), plus the immutable commit/ref; content diff to the finalization ref is zero.
- **Open Gates / Critical Path:** none for v1.4.0.
- **Brain Status:** CURRENT / FINAL.

## CURRENT v1.3.2 Router Gateway visibility hotfix
- **Previous Accepted Release:** v1.3.1 is the immutable published baseline at tag `v1.3.1` / commit `3b9fa6e7953e7d18068b8a0b574e0282411584ab`.
- **Current Authority:** branch `hotfix/router-grid-v1.3.2` created directly from protected `origin/main` at the v1.3.1 release baseline. v1.3.1 startup-layout fixes and provider catalog revision 2 are preserved.
- **User-visible Failure:** Router Gateway with `Protocol=All` appeared to contain only one populated row.
- **Root Cause:** all 9 RouterProfile objects were loaded, but unselected WPF DataGrid rows/cells inherited a white default background while the grid foreground was white. The selected blue row alone had readable contrast.
- **Fix / Prevention:** explicit dark RowBackground `#0E1D2D`, alternating row `#10263A`, readable DataGridRow/DataGridCell foreground `#F7FAFC`, dark headers `#1A3248`, and a permanent `windows_grid_readable_dark_rows` contract.
- **Runtime V&V:** exact v1.3.2 GUI runtime UIA reports 9 rows, 7 columns and 9 DataItems; VPN Gate, VPNBook and Pilovali are present. v1.3.1 inherited startup geometry still PASSes exactly 1289×632 at 96 DPI with six visible actions and zero overlap.
- **Windows release-ready artifact:** `delivery/DirectInternetMethod_1.3.2_Windows_Setup.exe`, 157,107,271 bytes, SHA-256 `B5141A93BDF2C261F54F4C0483128D973A54DEFBCD45C6C701535037B31E6E58`; GUI `F9FDE9A0…C5BBD`; service `CF2D1FBF…06D5D`; 678-file manifest `36A310F4…D7A8`.
- **Linux release-ready artifact:** `delivery/DirectInternetMethod_1.3.2_Linux_x86_64.zip`, 8,158,337 bytes, SHA-256 `8D4AB63AC64CF1837C47341D2438617BDF821919AE170BA75B301AA2B661172D`; Windows/Linux byte-identical reproduction PASS; Linux contract/runtime smoke PASS with 9 profiles.
- **Network Scope:** no Direct DNS/DPI privileged network logic changed from v1.3.1. Router Gateway remains non-mutating to routes/DNS.
- **Validation Boundary:** physical-router authenticated L2TP/IPsec/PPTP success remains model/firmware-dependent; not claimed universally.
- **Critical Path / Open Gates:** none for v1.3.2. Optional future validation only: model-specific physical-router authenticated tunnel E2E.
- **Publication / Installed Hosts:** PASS. v1.3.2 public release is hash-verified; Windows installed GUI/manifest match release payload, 9 profiles + Desktop/Start shortcuts present, clean OFF state; Linux installed files match the public ZIP exactly, 9 profiles + Desktop/Applications shortcuts present, clean OFF state.
- **Brain Status:** CURRENT / FINAL for v1.3.2.

## CURRENT v1.3.1 UI hotfix / provider-catalog integration
- **v1.3.1 Historical State:** FINAL/PUBLISHED baseline for v1.3.2 at immutable tag `v1.3.1` (`3b9fa6e`). The lines below preserve its pre-publication acceptance history.
- **Current Authority:** branch `hotfix/v1.3.1-ui-layout` rebased onto protected `main` commit `8d5fb149992ee1bdac3e73940b23ad6f0e873a4e`. Concurrent main work was preserved: GitHub supply-chain hardening plus Router Gateway provider catalog revision 2 / Linux source-install hardening.
- **UI Root Cause:** v1.3.0 opened at 980×620 while six minimum-width actions were forced into a non-wrapping horizontal StackPanel beside Auto-sized footer text; constrained width caused crowding/overlap.
- **UI Prevention:** preferred startup size 1289×632 DIP; current Windows host is 96 DPI so verified physical size is exactly 1289×632. Footer actions use WrapPanel; explanatory text is bounded to 360 DIP and wraps; layout rounding/pixel snapping enabled.
- **Dynamic Windows V&V:** self-contained 1.3.1 GUI post-rebase opens at exactly 1289×632; all six actions visible; zero button/button and button/footer overlap; Refresh mouse + keyboard PASS; Router Gateway physical mouse open PASS. Reduced 1000×632 regression also PASSed with wrapping and zero overlap.
- **Router Gateway concurrent delta preserved:** catalog revision 2 now contains 9 ready profiles from 3 providers (VPN Gate, VPNBook, Pilovali). Router contract PASS including official Pilovali profile; auto-router mutation remains false.
- **Windows post-rebase candidate:** `delivery/DirectInternetMethod_1.3.1_Windows_Setup.exe`, 157,096,702 bytes, SHA-256 `4F70C372E6B8CE7152D9501E5C4A70F4B2F650638CFDD3014B18EB6E3C123093`; GUI `8F3A410C…110E`; service `1A8A235A…29E6`; manifest `B0A1B328…1207`; Authenticode NotSigned.
- **Linux post-rebase candidate:** `delivery/DirectInternetMethod_1.3.1_Linux_x86_64.zip`, 8,158,158 bytes, SHA-256 `B21BD0D5C8B40643F4CF5F07DC13F220B07E71A674F862DFB792D63FD9823A34`. aliemad-Labtop fresh clone of pushed commit `b0b34aa` reproduced the exact SHA; Linux contract, Router Gateway contract/runtime smoke (9 profiles), LF guard and six-file `bash -n` all PASS.
- **Superseded candidate hashes:** pre-rebase Windows `E805F7F1…CAA0`; pre-rebase Linux `4AB0D082…BED5C`; intermediate post-rebase Linux `A2B74521…F3D6`. They are preserved as history but are not release authority.
- **Regression:** Windows full contract PASS; Linux contract PASS; Router contract PASS; release metadata to be rerun after final metadata; Windows GUI/service source was unchanged by concurrent main, so binary hashes remained identical while manifest/installer were rebuilt for the new provider data.
- **Validation Boundary:** Direct DNS/DPI, route/DNS rollback and Windows service action logic were not modified by this UI hotfix. Physical-router authenticated tunnel success remains model/firmware-dependent.
- **Critical Path / Open Gates:** required PR #7 `linux-source`/`windows-source` checks → protected merge → v1.3.1 tag/release/public hash verification → installed Windows public-update + final installed UI 1289×632 verification.
- **Brain Status:** CURRENT / CANDIDATE. Do not promote v1.3.1 to FINAL until all gates above close.


## CURRENT v1.3.0 Router Gateway delta
- **Previous Accepted State:** v1.2.1 remains FINAL/PUBLISHED_VERIFIED at tag `v1.2.1` (`ffc8119`); publication/governance lineage is finalized through `ad5f019`.
- **Current Delta:** Router Gateway is integrated into the existing Windows WPF and Linux GTK/Adwaita apps. L2TP/IPsec is preferred; PPTP is explicitly legacy fallback. The module supplies copy-ready router/modem configuration, offline snapshot/cache/refresh, vendor guidance and non-mutating endpoint health tests.
- **Authority:** canonical Git root `C:\Users\Aa.Emad\source\repos\DirectInternetMethod`; branch `feature/router-gateway-v1.3.0` rebased on the fully published/governed v1.2.1 main lineage through `ad5f019` after concurrent main movement was detected.
- **Windows release-ready artifact:** `delivery/DirectInternetMethod_1.3.0_Windows_Setup.exe`, 157,098,906 bytes, SHA-256 `04EBFD968146A7122A0695DB36A01DBACB5F91B69104D6D1DEA6D1964BB99263`; Authenticode NotSigned.
- **Windows payload:** GUI `83594B60BBA67F84175F1287EB12E6921A14C883E83BF2CCF566A8A4A698728B`; service `034CA29CF4CB3968AAB37CEABDB8D78C84F0B7355659F312D119A19E61C163D4`; 678-file manifest `15D6A96AB4ECA44B70F9C4A6855BAEEC2F03411E8F54233003940B1027BFEFAE`.
- **Linux release-ready artifact:** `delivery/DirectInternetMethod_1.3.0_Linux_x86_64.zip`, 8,156,742 bytes, SHA-256 `14CE381D589482FB8DBF437C12B351B5F232653F2C6512F871139FB5F3809824`; byte-identical Windows/Linux reproduction PASS.
- **Checksums:** `delivery/SHA256SUMS.txt`, SHA-256 `A56DB90964085A0D8452691D70DCEFF74D888DB65B634B370926A3BB38596ABE`.
- **V&V:** Router Gateway contract PASS; Windows compile 0 warnings/0 errors; service self-test + full regression contract PASS; final release WPF UI automation PASS; 8-profile Test All completed; DNS interception `10.10.34.35` rejected fail-closed; Linux contract/runtime smoke PASS; deterministic cross-host ZIP PASS.
- **Failure prevention:** adding `providers.json` exposed a deterministic-build gap because JSON EOL was not normalized; `.json` is now normalized and cross-host hash is identical.
- **Validation boundary:** full authenticated tunnel success on an arbitrary physical router remains **UNPROVEN / model-dependent**. The release does not claim universal router compatibility.
- **Open Gate / Critical Path:** none for v1.3.0 publication. Optional future gate only: physical-router model-specific authenticated tunnel E2E when a concrete model is available.
- **Windows public-update host verification:** PASS. Installed v1.3.0 hashes match release payload; update action reports done/exit 0; no pending update or residual winws/ULA/NRPT/broad DNS state remains; physical DNS state is clean.
- **Linux public fresh-clone acceptance:** PASS. Public v1.3.0 tag + public ZIP were revalidated on aliemad-Labtop; Bash syntax/LF guard, Linux contract, Router Gateway contract/runtime smoke and deterministic archive SHA all PASS.
- **Installed Windows Router Gateway UI refresh:** PASS. Installed app shows 8 profiles, refreshes to cache, and state/broad/DNS remain unchanged.
- **Validator root cause:** CLOSED / harness-only. Initial post-install validator looked in `{app}\router_gateway`; installer and WPF correctly use `{app}\app\router_gateway`. Validator now derives path from executable directory contract.
- **Final GitHub governance audit:** PASS. Public repo, strict main protection, required Linux/Windows checks, secret scanning/push protection, immutable release-tag ruleset, exact release assets and feature/main/tag CI all verify. The v1.3.0 tag is correctly an ancestor of post-release evidence commits on main.
- **Post-hygiene GitHub final audit:** PASS. Root `SHA256SUMS.txt` exactly matches the public v1.3.0 release checksum asset; release-metadata CI guard is enforced; Private Vulnerability Reporting and secret scanning/push protection are enabled; required CI is SHA-pinned and the full Windows contract now runs pre-merge. A current `feature/router-providers-v1.3.1` branch/worktree exists as active post-release development and is explicitly outside immutable v1.3.0 release authority.
- **License:** `OWNER_LEGAL_DECISION_OPEN`; not a technical release blocker. No software license was selected on the owner's behalf.
- **Provider catalog revision 2 (post-release data update):** 9 ready profiles from 3 independent ready providers after adding official Pilovali L2TP/IPsec. HideSSH, VPN Jantit and TCPVPN are confirmed candidate sources but require per-user account generation; they are not exposed as fake ready profiles.
- **Installation/shortcut correction:** Windows v1.3.0 was installed and Start Menu shortcut existed; missing per-user Desktop shortcut was repaired and target/icon verified. Linux was still user-space v1.1.0; it was safely stopped, upgraded from the verified v1.3.0 ZIP, and now has v1.3.0 + Desktop shortcut + Applications entry with network state clean OFF.
- **Linux source-install failure prevention:** direct source-tree install initially failed because provider data path assumed package layout. Installer now uses packaged path first and canonical source-tree fallback; Linux temp-path regression PASS.
- **Brain Status:** CURRENT / FINAL for v1.3.0. GitHub tag/release, public asset hashes, Windows public-update host verification, installed UI refresh, Linux public fresh-clone acceptance and final governance audit are verified.

- **GitHub line-by-line final audit:** `evidence/GITHUB_130_LINE_BY_LINE_FINAL_AUDIT_20261001.json` — SHA-256 `5F14FE447285028DDA7DB5581978E69A6AAF9051F6A00D1A9B6890661869C385`; PASS_FINAL_GITHUB_LINE_BY_LINE_AUDIT_V1_3_0.
- **Metadata/CI drift closure:** `evidence/GITHUB_130_METADATA_CI_DRIFT_FIX_20261001.json` — platform publication metadata synchronized; full Windows contract moved into protected pre-merge `windows-source`; PR #4 + main CI PASS.
- **Actions supply-chain closure:** `evidence/GITHUB_130_ACTION_SUPPLY_CHAIN_HARDENING_20261001.json` — all official actions pinned to immutable 40-hex commits; weekly GitHub-Actions Dependabot active; PR #5 + main CI PASS.

## Authoritative current state
- **CURRENT release authority:** v1.4.0 is FINAL/PUBLISHED/INSTALLED_VERIFIED at immutable tag `v1.4.0`, release/main commit `910e22d06209e244f8caf809c9821e3fb16c7cc1`, source tree `db7f8e02ca706ca0c74a54901368a6a61a4733cd`.
- Windows v1.4.0 public artifact: `DirectInternetMethod_1.4.0_Windows_Setup.exe`, 157,103,781 bytes, SHA-256 `69F0EF63E3A658EC616362FC7D7ADAB95337EC3A034D3981DF44C685DB9FCB93`; installed GUI/service/manifest identity, public update and real-host lifecycle PASS.
- Linux v1.4.0 public artifact: `DirectInternetMethod_1.4.0_Linux_x86_64.zip`, 8,159,881 bytes, SHA-256 `4CF521FD3821F9204999C0F17B217A60DC7117AC68421E5634FDF8D15D3C485E`; deterministic reproduction, public installed identity and live lifecycle PASS.
- GitHub `Source and Release Contracts`: protected-main run `36836911098` PASS and immutable-tag run `36837069912` PASS. Release assets and public re-download SHA-256 values match.
- GitHub protection/security controls from earlier governance audits remain part of project authority unless a later audit supersedes them: protected main, protected immutable `v*` tags, secret scanning/push protection and SHA-pinned actions.
- Repository LICENSE remains MISSING by explicit owner/legal choice; no license was selected automatically.
- Historical v1.0–v1.3.x release facts/evidence below remain append-only history and are superseded as current release authority by v1.4.0.

## Roadmap
Completed: v1.0.0 and v1.1.0 Windows/Linux final releases and publication.
Completed: v1.1.0 Windows/Linux live lifecycle, rollback/recovery, deterministic Linux build and published updater verification.
Completed: v1.2.0 Windows service-mediated direct updater implementation: SCM control 131, clean-OFF gate, GitHub latest release, triple SHA-256 agreement, atomic download, registered-install-path preservation, silent installer handoff, installer completion marker.
Completed: Windows v1.2.0 Sandbox E2E direct-update acceptance from restricted user; exact candidate install and installed payload hash verification PASS.
Completed: Linux v1.2.0 compatibility/version package; contract audits PASS on Windows/Linux and deterministic cross-host ZIP reproduction PASS.
Completed: exact Windows v1.2.0 host bootstrap; installed GUI/service/manifest hashes match candidate; control 131 host regression PASS.
Completed: Windows v1.2.0 host Start/ACTIVE/Stop/exact rollback/Recovery regression PASS.
Completed: immutable v1.3.0 release/publication gates remain closed as previous accepted authority.
Completed: v1.3.2 FINAL/PUBLISHED/INSTALLED_VERIFIED.
Completed: v1.4.0 direct multi-protocol engine, deterministic builds, Windows/Linux live lifecycle, protected CI, immutable publication, public hash verification and installed-host updates.
← CURRENT: v1.4.0 FINAL/PUBLISHED/INSTALLED_VERIFIED; maintenance only.
Open v1.4.0 release gates: none.
Deferred: trusted Authenticode signing; model-specific physical-router authenticated tunnel E2E; HTTP/3 application-level QUIC claim; optional encrypted-DNS transports only if independently proven.

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
14. Windows update control 131 constant/client mapping initially existed without a service Handler case → add explicit `case CTRL_UPDATE` and regression requiring `Task.Run(RunUpdateAsync)`; Sandbox regression PASS.
15. LocalSystem updater could otherwise install user payload into SYSTEM profile → resolve all-users Inno Setup `InstallLocation` from HKLM, require expected app/manifest, and pass explicit `/DIR`; Sandbox path-preservation PASS.
16. Update completion originally depended on target service startup → installer now writes `action-status=done/0` and deletes pending marker at post-install; fresh Sandbox seeded-pending regression PASS.
17. Linux v1.2 deterministic package initially mismatched due stale non-Git Linux workspace inputs → reconcile package inputs from Git-controlled authority; Windows/Linux ZIP hash now identical.
18. Host bootstrap Runner helper name `H` collided with PowerShell alias `h/Get-History` before elevation → rename to `Get-Sha256`, pin runner/script hashes, and require final host bootstrap evidence; fixed Runner PASS.
19. Public Linux v1.2.0 ZIP shipped CRLF shell scripts → no Git EOL policy + package builder copied checkout bytes verbatim; confirmed public asset failure on Linux. Prevention: *.sh LF policy + package-byte LF normalization + CI source/archive bash gates; v1.2.1 regression PASS.
20. Initial v1.2.1 Linux ZIP remained cross-host non-deterministic after shell-only normalization → README/license/hosts text EOL differed across hosts; normalize all package text payloads (.sh/.py/.md/.txt/.svg) before hashing/packing; Windows/Linux v1.2.1 ZIP hash now identical.
21. Concurrent writer switched original checkout to Router Gateway branch during GitHub audit → hotfix commit briefly landed on local Router branch. Prevention: recovered hotfix ref and isolated all subsequent work to dedicated Git worktree; Router Gateway tracked/untracked work preserved.
22. Windows platform release metadata remained `release-ready/publication=PENDING` after public v1.3.0 publication → release metadata audit did not compare platform publication state to root authority. Prevention: synchronize `windows/RELEASE.json`, enforce root/platform publication fields and root/delivery checksum equality in CI; PR #4/main CI PASS.
29. Required protected Windows CI ran full contract only after immutable tag creation → pinned PowerShell runtime was restored only in tag job. Prevention: restore pinned runtime and run full Windows + Router Gateway contract in required pre-merge `windows-source`; PR #4/main CI PASS.
30. GitHub Actions used floating major tags (`checkout@v7`, `setup-dotnet@v6`) → mutable supply-chain refs. Prevention: pin official actions to verified full commit SHAs and maintain them with weekly GitHub-Actions Dependabot; PR #5/main CI PASS.

All earlier harness failures remain preserved; no product runtime failure is hidden.
28. Initial v1.3 post-install validator checked `{app}\\router_gateway` and falsely reported missing Router Gateway data → installer/UI contract actually uses `{app}\\app\\router_gateway`; corrected validator derives the path from executable directory; installed hash and UI refresh regression PASS.

23. Router Gateway provider websites were unreliable/blocked during development → offline-first bundled manifest + cache + non-fatal refresh; regression PASS.
24. PPTP hostname resolved to private `10.10.34.35` and was initially falsely reachable → fail closed on non-global DNS results on both platforms; final UI regression PASS.
25. Concurrent `origin/main` advanced to v1.2.1 during Router Gateway work → checkpoint, fetch/audit, rebase on authoritative v1.2.1, discard pre-rebase artifact hashes and rebuild all release artifacts; PASS.
26. v1.3 Linux ZIP differed cross-host after adding `providers.json` → root cause was JSON EOL omitted from deterministic text normalization; add `.json` normalization; Windows/Linux ZIP SHA now identical.
27. One post-rebase UI probe returned no endpoint results after a fixed 9-second wait → harness window was shorter than sequential 8-endpoint worst-case; completion-based bounded polling replaced fixed delay; final release UI smoke PASS with process stable.

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
- Windows 1.2 host bootstrap gate: `evidence/WINDOWS_120_HOST_BOOTSTRAP_GATE_20261001.json` — SHA-256 `75A6C10B3C4DC9A4DFAC0D15DD44EDC3BFFB0268F417D363FDA8285CDDA5B89F`; one-time UAC owner gate; pre/post host remains clean v1.1.0.
- Windows 1.2 direct-update Sandbox E2E: `evidence/WINDOWS_120_DIRECT_UPDATE_SANDBOX_E2E_20261001.json` — SHA-256 `8A79264D3FA588F9B5F6896110B3DBDD90207433093CC09E92DF8DE0819026CB`; restricted-user control 131, dual SHA-256 verification, exact v1.2 installer, done/0, exact installed payload identity, preserved user install path, and zero DIM network residue.
- Final clean-state stabilization: `evidence/DIM_110_FINAL_CLEAN_STATE_20261001.json` — SHA-256 `7751A356EF1FFB00BEC0C20E594A12534068D8EA9980964D094A7E90E1584788`; Stop/Recovery done/0, state absent, ctrld stopped, winws/ULA/owned NRPT zero.
- Windows v1.2 direct-update Sandbox acceptance: `evidence/WINDOWS_120_DIRECT_UPDATE_ACCEPTANCE_20261001.json` — SHA-256 `F2DDB33F715EFDB98FD96F6E2F6C69C6E254241847C417A9680407F5238041FC`.
- Linux v1.2 compatibility/deterministic acceptance: `evidence/LINUX_120_COMPAT_ACCEPTANCE_20261001.json` — SHA-256 `298E36F0A88529BD17C74E99C75893F485C3D10B788D4FD02E32AB0CEB5D293A`.
- Windows v1.2 host lifecycle prestate: `evidence/WINDOWS_120_HOST_LIFECYCLE_PRESTATE_20261001.json` — SHA-256 `579D8164F632AEF6BC865DBC2E68BD3AB3E3BB932463A79238E965217FDF1008`.
- Windows v1.2 host bootstrap result: `evidence/WINDOWS_120_HOST_BOOTSTRAP_RESULT_20261001.json` — SHA-256 `87E527185370F4156CC60D04A0A352CA79A1FD14C481B57195FBEBB76699D302`.
- Windows v1.2 host ACTIVE acceptance: `evidence/WINDOWS_120_HOST_ACTIVE_ACCEPTANCE_20261001.json` — SHA-256 `F65CD416A117178A7CF2FA4AC11230E8FA2D9FA6724797D78F78C09869EC8833`; YouTube=204/OpenAI=401/GitHub=200, physical DNS/routes/WinHTTP/ICS preserved.
- Windows v1.2 exact rollback: `evidence/WINDOWS_120_HOST_ROLLBACK_ACCEPTANCE_20261001.json` — SHA-256 `52A8235BC1CE59155D35A52CA1254C98617463D2389265B798E392EA38D7A3A4`.
- Windows v1.2 recovery/no-state: `evidence/WINDOWS_120_HOST_RECOVERY_ACCEPTANCE_20261001.json` — SHA-256 `F86DE943DCBF27FDDF6D2C18DAA6BAD0889A75F2194F274CD6A0CA14C7FF8743`.
- Windows v1.2 host final acceptance: `evidence/WINDOWS_120_HOST_FINAL_ACCEPTANCE_20261001.json` — SHA-256 `9BE7D268491860622C355C45A28D3DEC45261EF6F71EECB7A45C0E58BC32C06A`; PASS_FINAL_WINDOWS_1_2_0.
- Windows v1.2 bootstrap Runner fix: `evidence/WINDOWS_120_HOST_BOOTSTRAP_RUNNER_FIX_20261001.json` — SHA-256 `89AF020D5DDCC47CD6403CF40FC2FEE80222B3AB6F1A540C7CC58E7E2D423C42`; final local Runner ZIP SHA-256 `DB13BD5F72DFFD244B657442C3411C65ADD962F8D6D675C71C444B65AE842071`, script SHA-256 `1CD853F5ED1F255B2DDEAF82508E65C6523B042B6E1687848E266D7A9E724C42`.
- v1.2 public release verification: `evidence/DIM_120_GITHUB_PUBLICATION_VERIFY_20261001.json` — SHA-256 `95BBEC5DFD8231BC95D5FFBF81F4CF05CD7E5DEE1903BAD5CF1082ABB1CF4D24`; latest=v1.2.0; all three public asset hashes/digests match.
- v1.2 Windows public updater verification: `evidence/WINDOWS_120_HOST_PUBLIC_UPDATER_VERIFY_20261001.json` — SHA-256 `A478EA78232A7BC5564752DC9DC20F64CEADD892B587E37E333E57A058944DE9`; control 131 done/0, Already up to date, no state/pending.
- v1.2 final clean state: `evidence/DIM_120_FINAL_CLEAN_STATE_20261001.json` — SHA-256 `2E8766F75C6AF16AA9F3B1CB6B0DB7E68C340DAD020EEB8DBCA31AAE8ADDEE27`; exact installed hashes, state/pending absent, ctrld stopped, winws/ULA/NRPT/broad-route zero.
- v1.2 publication final: `evidence/DIM_120_PUBLICATION_FINAL_20261001.json` — SHA-256 `00635FD814E151D94D5B512DA3F750E6E6BD880A7EDAD6C1C03554A6BA0B14B7`; PASS_FINAL_PUBLISHED_VERIFIED_V1_2_0.
- Cross-platform v1.2 final acceptance: `evidence/DIM_120_FINAL_ACCEPTANCE_20261001.json` — SHA-256 `399053A0806A3D2EA9A71DEC6D0027444CAD08EFF2910020A1268354EDB1B1AC`; release gate = publication only.
- Windows v1.2 candidate: `delivery/DirectInternetMethod_1.2.0_Windows_Setup.exe`, 157,093,296 bytes, SHA-256 `E1D774B29BEE29B15632ADBED9B6137738E4D297DAF1A3B216D5B27DE9559FC1`; GUI `FAB82346…`, service `43274024…`, manifest `FA254338…`.
- Linux v1.2 candidate: `delivery/DirectInternetMethod_1.2.0_Linux_x86_64.zip`, 8,140,827 bytes, SHA-256 `BBCDAD529D242987EAC74DC4EC4EA02435FAB9755D6736ECABE84133FC3DABDC`; identical on Windows and Linux.
- Candidate-cycle evidence was copied to immutable `WINDOWS_110_HOST_CANDIDATE_*` records before final-artifact retest.
- Earlier stale parallel hashes `D6AF…/A011…/5AEF…` are superseded and must not be used as release authority.

- GitHub v1.2.0 Linux public-release failure: `evidence/GITHUB_V120_LINUX_EOL_RELEASE_FAILURE_20261001.json`.
- Linux v1.2.1 LF/deterministic acceptance: `evidence/LINUX_121_EOL_DETERMINISTIC_ACCEPTANCE_20261001.json` — SHA-256 `ECBEB4CD6DE6EC3C20AE74CB8E46E3A894900845F6014A1002FD0921626ED2E5`.
- Windows v1.2.1 exact Sandbox identity: `evidence/WINDOWS_121_SANDBOX_IDENTITY_ACCEPTANCE_20261001.json` — SHA-256 `9D6F8161FAA8197BD8F7D48E5AC4B764F248C6EA009F76285D32AA5256B7EC40`.
- GitHub Actions hotfix acceptance: `evidence/GITHUB_ACTIONS_121_HOTFIX_ACCEPTANCE_20261001.json` — SHA-256 `3EC713DD9259245A4DEAAD8E3B0415494F473960F6EFF4FA008678A1017C36B8`.
- Concurrent-writer isolation: `evidence/GITHUB_AUDIT_CONCURRENT_WRITER_ISOLATION_20261001.json` — SHA-256 `92F6A20D4338BB02FAFDD6CEF84EFC13F75EADE52D1A67B7DE602E90A7EA7996`.
- v1.2.1 release-ready aggregate: `evidence/DIM_121_RELEASE_READY_ACCEPTANCE_20261001.json` — SHA-256 `B70FF0F478E98B44A6F47EEE826E79F30C7E9726DDEC120EA9E15C3A91FCC89F`.

- GitHub v1.2.1 final audit: `evidence/GITHUB_121_FINAL_AUDIT_20261001.json` — SHA-256 `9E314C8A5ABE3E33996296B7E6EF9039C90B254BD3A3D331D90F572B92B5CB2F`; PASS_FINAL_GITHUB_AUDIT_V1_2_1.

- v1.3 GitHub final governance audit: `evidence/GITHUB_130_FINAL_AUDIT_20261001.json` — PASS_FINAL_GITHUB_AUDIT_V1_3_0.
- v1.3 post-hygiene GitHub final audit: `evidence/GITHUB_130_POST_HYGIENE_FINAL_AUDIT_20261001.json` — SHA-256 `57D22DDF65DE3F63795076CFC3827725B4A7744F4684078FBCF1554FDE449E18`; root/public checksum equality, PR #2 + post-merge main CI PASS, PVR enabled, only remote branch `main`.
- v1.3 Windows public update: `evidence/WINDOWS_130_HOST_PUBLIC_UPDATE_VERIFY_20261001.json` — PASS, exact installed hashes, CLEAN_OFF.
- v1.3 installed Router Gateway UI/refresh: `evidence/WINDOWS_130_INSTALLED_ROUTER_GATEWAY_UI_VERIFY_20261001.json` — PASS, 8 profiles, refreshed-cache, no DNS/route/state mutation.
- v1.3 Linux public fresh-clone/archive: `evidence/LINUX_130_PUBLIC_RELEASE_ACCEPTANCE_20261001.json` — PASS, public SHA, `bash -n`, zero CR, runtime/contract/deterministic rebuild.
- v1.3 validator false-negative root cause: `evidence/WINDOWS_130_ROUTER_DATA_VALIDATOR_ROOT_CAUSE_20261001.json` — harness-only; product path/hash verified.

## Exact Next Action
Maintenance only. Keep tag `v1.4.0` and its three release assets immutable. Any future release must start from protected `main` and repeat platform contracts, deterministic artifact gates, live Start/Stop/Recovery, public re-download/hash verification and installed-host update verification.

## HISTORY
- 2026-10-01: v1.4.0 finalized end-to-end. Protected main/tag CI PASS; public Windows/Linux/SHA256SUMS assets re-downloaded with exact hashes. Windows updated 1.3.2→1.4.0 through control 131 without UAC, installed hashes/UI/9-profile Router Gateway verified, and real-host Start→PASS_ACTIVE→Stop exact rollback→Recovery PASS with DNS/default-route/WinHTTP/ICS preserved. Linux public-package identity and clean OFF state verified; obsolete unreferenced legacy user-space runtime residue backed up and removed. v1.4.0 promoted to FINAL/PUBLISHED/INSTALLED_VERIFIED.
- 2026-10-01: v1.4.0 fresh-clone Linux acceptance PASS at commit `015b58a`: exact ZIP SHA reproduced, backend upgraded to 1.4.0, Start→ACTIVE live probes PASS, nft queues exactly TCP80/TCP443/UDP443 bounded to first packets, Stop exact-clean rollback and Recovery no-state PASS. Earlier ad-hoc DNS-transport ctrld residue was removed and final no-residue regression passed.
- 2026-10-01: v1.4 method audit expanded beyond VPN/proxy: bounded HTTP/80, TLS/SNI TCP/443 and QUIC UDP/443 zapret profiles added; direct-IP DoH retained and hardened with `leak_on_upstream_failure=false`. DoH3/DoQ/DoT were isolated-tested but failed to resolve on the current Linux network, so they were not promoted. ECH classified as browser/server negotiated rather than an app-level method toggle.
- 2026-10-01: v1.4.0 direct multi-protocol candidate created from final v1.3.2. Added bounded encrypted DNS + HTTP/80 + TLS/SNI TCP/443 + QUIC UDP/443 methods; removed Linux UDP/443 blanket reject; preserved no-VPN/no-proxy/no-default-route/physical-DNS invariants. Local source/build/UI gates PASS; Linux live protected-backend gate remains open.
- 2026-10-01: aliemad-Labtop fresh clone of pushed post-rebase commit `b0b34aa` reproduced Linux v1.3.1 ZIP SHA `B21BD0D5…23A34` exactly; Linux/Router contracts, Router runtime smoke with 9 profiles, LF guard and six-file Bash syntax PASS. Post-rebase cross-host gate CLOSED.
- 2026-10-01: user-reported Windows crowding traced to 980×620 startup geometry + non-wrapping six-action footer. v1.3.1 sets 1289×632 preferred startup geometry and responsive footer; dynamic 1289×632 and 1000×632 zero-overlap regressions PASS.
- 2026-10-01: protected main advanced during v1.3.1 work with provider catalog revision 2 and GitHub hardening. Hotfix branch rebased onto `8d5fb14`; concurrent 9-profile/3-provider catalog and Linux installer hardening preserved. Pre-rebase artifacts superseded; Windows manifest/installer and Linux archive rebuilt from new authority.
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

- 2026-10-01: v1.2 Windows service-mediated direct updater implemented and Sandbox E2E accepted. Restricted user control 131 rc=0; verified public release download/install path exercised; fresh v1.2 installer wrote completion done/0 and preserved registered user install location.
- 2026-10-01: Linux v1.2 compatibility package rebuilt from Git-controlled source; stale Linux workspace drift reconciled; Windows/Linux deterministic ZIP hash matched at BBCDAD529D242987EAC74DC4EC4EA02435FAB9755D6736ECABE84133FC3DABDC.

- 2026-10-01: Windows v1.2 direct updater reached Sandbox E2E PASS. A restricted user triggered control 131; exact v1.2.0 installer was verified and installed silently by the privileged service; completion returned done/0; exact GUI/service/manifest hashes matched; network state remained clean. Production v1.2 service then returned Already up to date/done0 from the same restricted control against real GitHub latest.

- 2026-10-01: host v1.2 bootstrap attempted from clean v1.1.0. Windows UAC consent appeared, but Commander secure-desktop control was unavailable; no install occurred and host remained clean v1.1.0. Classified as owner UAC gate, not product failure.

- 2026-10-01: exact Windows v1.2.0 candidate installed on EMAD-PC-ULTIMAT. Payload hashes matched; control 131 host regression done/0. Live Start restored YouTube=204 while OpenAI=401/GitHub=200; adapter DNS, default route, WinHTTP and ICS were preserved. Stop exact rollback and Recovery/no-state PASS; host left clean OFF. Windows v1.2 host gate closed.

- 2026-10-01: v1.2.0 published on GitHub from tag/main release commit `6c30dbf`. Windows/Linux/SHA256SUMS assets redownloaded publicly and matched exact hashes/GitHub digests. Installed Windows v1.2 updater queried public latest v1.2.0 and returned Already up to date/done0 without UAC or network-state mutation. Final host clean-state audit PASS; release promoted to FINAL/PUBLISHED_VERIFIED.

- 2026-10-01: deep GitHub audit found public Linux v1.2.0 release defect: all six packaged shell scripts retained CRLF and failed bash -n. v1.2.0 tag/assets left immutable; patch v1.2.1 created with LF Git policy, package-byte normalization, GitHub Actions, and cross-host deterministic ZIP. Windows network logic unchanged. Concurrent Router Gateway writer was isolated via dedicated worktree. v1.2.1 Windows exact Sandbox identity and Linux source/archive syntax gates PASS; release is READY, not yet published.

- 2026-10-01: v1.2.1 published. Public Linux ZIP SHA-256 CAF93659… passed LF-only + bash -n on aliemad-Labtop. Windows host updated 1.2.0→1.2.1 via public GitHub latest/control 131 without UAC; installed hashes matched release authority; state/pending remained absent. Public redownload of Windows/Linux/SHA256SUMS matched exact hashes. Main protection remains the sole open GitHub gate.

- 2026-10-01: deep GitHub finalization completed. v1.2.1 latest/public assets verified; Linux public ZIP passed LF-only + bash -n; Windows host updated 1.2.0→1.2.1 through public control 131 without UAC. main now requires strict linux-source/windows-source checks, linear history, admin enforcement, no force-push/delete, conversation resolution. Active tag ruleset protects v* tags from update/delete with no bypass. Historical v1.2.0 release was annotated as Linux-superseded without changing tag/assets. Root LICENSE remains an explicit owner/legal choice.

- 2026-10-01: v1.3.0 Router Gateway release-ready delta finalized on top of authoritative v1.2.1 after concurrent-main audit/rebase. Windows/Linux local gates PASS.
- 2026-10-01: live endpoint testing found DNS interception to private 10.10.34.35; reachability logic now fails closed on non-global addresses; final WPF UI regression PASS.
- 2026-10-01: deterministic Linux builder extended EOL normalization to JSON after cross-host providers.json mismatch; final ZIP is byte-identical across Windows/Linux.
- 2026-10-01: v1.3.0 tag `1fc9a04` published as GitHub release. Feature/main/tag Source and Release Contracts PASS. All public assets re-downloaded from direct GitHub release URLs and SHA-256 matched; v1.3.0 promoted to FINAL/PUBLISHED_VERIFIED.
- 2026-10-01: Windows host public-update verification PASS for v1.3.0; installed GUI/service/manifest/router hashes match and no residual network state remains.
- 2026-10-01: Linux public v1.3.0 tag/archive fresh-clone acceptance PASS; rebuilt ZIP matches published SHA exactly.
- 2026-10-01: Installed Windows Router Gateway UI refresh PASS with 8 profiles and unchanged network/DNS state.
- 2026-10-01: Post-install router-data validator false negative traced to harness path error ({app}\router_gateway vs actual {app}\app\router_gateway); product path/hash were correct and validator prevention added.
- 2026-10-01: Corrected GitHub final audit PASS. Release tag ancestry, branch protection, tag rules, exact asset digests and CI verified; repository license remains an explicit owner legal decision, not a technical release gate.

- 2026-10-01: final GitHub hygiene remediation merged through protected PR #2. Root checksum authority synchronized to public v1.3.0 release, release-metadata CI guard added, Private Vulnerability Reporting and merged-branch auto-delete enabled, SECURITY.md added, stale merged remote branches removed. Post-merge main run 36812693607 passed linux-source/windows-source. Final post-hygiene audit PASS.
- 2026-10-01: Pilovali L2TP/IPsec ready profile added after official-source verification and live public-IP/ping check; ready catalog is now 9 profiles / 3 independent ready providers.
- 2026-10-01: Linux user-space install corrected from v1.1.0 to v1.3.0 with Desktop/Application shortcuts verified and clean OFF state; Windows missing per-user Desktop shortcut repaired.
- 2026-10-01: Source-tree Linux installer path defect for Router Gateway data closed with package/source fallback; contract + Linux temp-path regression PASS.

- 2026-10-01: GitHub line-by-line audit closed for immutable v1.3.0. PR #4 fixed platform release-metadata drift and moved full Windows contract into protected pre-merge CI; PR #5 pinned all GitHub Actions to immutable SHAs and enabled GitHub-Actions-only Dependabot. Main protection, no-bypass v* tag ruleset, secret scanning/push protection, PVR, public release digests and checksum authority reverified. Active v1.3.1 provider/UI worktrees remain separate unreleased development.
- 2026-10-01: v1.3.2 Router Gateway visibility hotfix release-ready. Screenshot-reported “one profile” traced to WPF white-on-white unselected rows; runtime proved 9 loaded rows. Dark row/cell/header styling + permanent regression added.
- 2026-10-01: v1.3.2 Windows/Linux artifacts built; Windows full contract and inherited 1289×632 startup layout PASS; Linux ZIP reproduced byte-identically across Windows/Linux.
- 2026-10-01: v1.3.2 public release and both installed hosts verified. Public asset SHA-256 PASS; Windows installed GUI/manifest match release payload with 9 visible-profile runtime regression and both shortcuts; Linux installed user-space files match public ZIP exactly with both shortcuts and clean OFF state.
