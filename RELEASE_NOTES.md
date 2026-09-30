# Direct Internet Method v1.1.0

Cross-platform final release for Windows and Linux.

## Windows
- Native WPF UI with privilege-separated `DirectInternetMethodSvc`.
- Normal Start/Stop/Recovery works without UAC after installation.
- Bundled protected PowerShell 7.6.6; no external PowerShell dependency.
- ctrld v1.5.7 runs as an owned demand-start Windows service.
- Loopback ULA + DoH + NRPT + zapret/winws/WinDivert.
- Online update checks GitHub latest release and requires `SHA256SUMS.txt` verification.
- Fresh Sandbox acceptance PASS.
- Real Windows host acceptance PASS: baseline YouTube timeout → ACTIVE YouTube 204; OpenAI 401; GitHub 200.
- Adapter DNS/default route/WinHTTP/ICS preservation PASS.
- Exact Stop rollback and Recovery/no-state PASS.

## Linux
- Protected backend with no-admin normal actions.
- ctrld + nfqws independent transient systemd services.
- Direct live acceptance PASS: YouTube 204; OpenAI 401; GitHub 200.
- Stop and Recovery rollback PASS.
- Deterministic Linux package reproduced with identical SHA-256 on Windows and Linux.

## Limitations
- Windows installer is not Authenticode-signed.
- Filtering effectiveness can vary if network filtering behavior changes.
