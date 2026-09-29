# PROJECT BRAIN — Direct Internet Method

Status: CURRENT
Final Objective: standalone Windows + Linux direct-connect application with independent install, icon, shortcuts, UI controls, rollback, and GitHub release.
DoD: PASS_FINAL_RELEASE on both platforms + hash-pinned artifacts + GitHub main/release published.

## Authoritative current state
- Windows: PASS_FINAL_RELEASE. Installer hash 1D32D0619EDC85C5B11405218087154D53907C06D650843F7375092B2FC7C602.
- Linux: PASS_FINAL_RELEASE. ZIP hash 4F6C80D3406055A0A956082E76B211206D1CFFBD2E7398EE84DB62D155F52B98.
- Both are standalone and do not require FreeNetHub or ChatGPT for normal use.
- Brand/UI: free-dove icon + «زن زندگی آزادی».
- Linux window: standard draggable header plus explicit Minimize / Maximize-Restore / Close.
- Windows limitation: PowerShell 7 required; installer is not Authenticode-signed.

## Roadmap
Completed: Windows standalone acceptance; Linux standalone live/rollback acceptance; icon/shortcut/UI correction; deterministic evidence and artifact hashing.
← CURRENT: publish updated source and both final artifacts to GitHub v1.0.0.
Open gate: GitHub commit/push/release only.
Deferred: trusted Authenticode signing for Windows.

## Failure prevention
- Never promote an installer merely because an output file exists; require completed build evidence/hash.
- Linux DNS uses owned temporary link, not physical adapter DNS mutation.
- Cleanup/rollback remains product-owned and exact.

## Exact Next Action
Commit/push current final state, create/update GitHub tag/release v1.0.0, attach both hash-pinned artifacts, then verify release assets remotely.

## HISTORY
- 2026-09-29: Windows standalone PASS_FINAL_RELEASE.
- 2026-09-29: Linux standalone PASS_FINAL_RELEASE after live DNS/HTTPS + rollback.
- 2026-09-29: Brand/UI corrected to dove + slogan; Linux window controls and drag behavior explicitly implemented.
