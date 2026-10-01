# Direct Internet Method v1.2.1

Patch release for GitHub/Linux packaging correctness and repository hardening.

## Fixes
- Linux release shell scripts are now guaranteed LF-only in Git and in the ZIP builder.
- The Linux package manifest hashes the exact normalized bytes written into the archive.
- GitHub Actions validates Linux shell syntax, packaged-archive shell syntax, Python syntax, Windows PowerShell syntax, .NET builds, and the full Windows release contract on version tags.
- Windows and Linux version/channel stay synchronized so the shared GitHub `/releases/latest` updater remains complete on both platforms.

## Windows
- Network/DNS/DPI runtime logic is unchanged from accepted v1.2.0.
- Direct in-app updater remains service-mediated, SHA-256 verified, and no-UAC after the v1.2 bootstrap.
- Installer remains unsigned by Authenticode.

## Linux
- Network architecture is unchanged from the accepted v1.2.0/v1.1.0 behavior.
- Primary patch: repair the CRLF shell packaging defect discovered by public-asset audit of v1.2.0.

## Release integrity
- Release contains Windows installer, Linux x86_64 ZIP, and `SHA256SUMS.txt`.
- Public assets are re-downloaded after publication and independently hashed before promotion to FINAL.
