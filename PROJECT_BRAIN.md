# PROJECT BRAIN — Direct Internet Method

Status: CURRENT / PASS_LOCAL_FINAL / GitHub release pending publication in this change set.

Final Objective: standalone Windows + Linux product with its own branding, installer/package, shortcuts, icon, GUI controls, Start/Stop/Refresh/Recovery, exact rollback, and public GitHub release.

Authoritative Windows state:
- Network acceptance: PASS_FINAL_RELEASE.
- Final installer SHA-256: 1D32D0619EDC85C5B11405218087154D53907C06D650843F7375092B2FC7C602.
- Installed manifest parity and shortcuts/icon: PASS.
- Branding: freedom dove + «زن زندگی آزادی».

Authoritative Linux state:
- Live network acceptance: PASS_LOCAL_FINAL.
- YouTube 204, OpenAI 401/reachable, GitHub 200.
- Physical DNS/default route unchanged during Direct Method.
- Stop rollback removed owned state/process/link.
- Final ZIP SHA-256: 5940CC754108189A67627C4DACAF10BEBF0A4613E0B203D6004548CC279A3826.
- Exact release ZIP install verification: PASS.
- GUI uses Adw.ToolbarView + Adw.HeaderBar; standard movable/resizable window controls.
- Branding: freedom dove + «زن زندگی آزادی».

Critical limitations:
- Windows installer is not Authenticode-signed.
- Linux package currently targets x86_64 Ubuntu/Mint-class systems with GTK4/libadwaita, polkit, systemd-resolved and nftables.

HISTORY:
- 2026-09-29: Windows standalone network lifecycle accepted.
- 2026-09-29: Linux standalone architecture accepted after root-cause fixes.
- 2026-09-29: Added independent Windows/Linux installers, shortcuts and GUI.
- 2026-09-29: Replaced product branding with freedom-dove logo and «زن زندگی آزادی».
- 2026-09-29: Linux window chrome migrated to libadwaita ToolbarView/HeaderBar and exact release package reverified.
