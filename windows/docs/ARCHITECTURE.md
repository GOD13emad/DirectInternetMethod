# Architecture and Integration Contract

Status: PASS_FINAL_RELEASE_1_1_0_2026-09-30

## Windows architecture
- Native WPF UI runs as the normal user.
- Fixed-command privileged service: `DirectInternetMethodSvc`.
- Normal Start/Stop/Recovery use custom service controls; no admin prompt is required after installation.
- Bundled protected PowerShell 7.6.6 executes lifecycle scripts; no external PowerShell dependency.
- Owned demand-start SCM DNS helper: `ctrld` v1.5.7.
- Loopback ULA: `fd53:4444:48::53/128`, SkipAsSource=true.
- Upstream DoH: `https://76.76.10.11/p0`.
- Owned NRPT catch-all points Windows DNS Client to the ULA only while ACTIVE.
- zapret `winws` + WinDivert performs hostlist-scoped TCP/443 DPI desync.

## Prohibited mutations
- No adapter DNS mutation.
- No VPN connection creation.
- No HTTP/SOCKS proxy.
- No `0.0.0.0/1` or `128.0.0.0/1` routes.
- No unintended WinHTTP or ICS mutation.

## Ownership and rollback
- ctrld service ownership requires the exact protected binary and runtime config path.
- NRPT uses the owned DirectDnsDpiHarness display/comment signature.
- ULA is removed only with package ownership evidence.
- winws/WinDivert cleanup is package-root scoped.
- Start fails closed and rolls back on a failed gate.
- Stop verifies DNS/NRPT/routes/WinHTTP/ICS preservation and owned residue removal.

## Final acceptance
Windows Sandbox: PASS.
Windows host `EMAD-PC-ULTIMAT`: PASS.
Normal-user Start/Stop/Recovery: PASS.
ACTIVE: YouTube=204, OpenAI=401, GitHub=200.
Exact rollback: PASS.
Recovery/no-state: PASS.

Authority:
- `evidence/WINDOWS_110_SANDBOX_FINAL_ACCEPTANCE_20260930.json`
- `evidence/WINDOWS_110_HOST_ACTIVE_ACCEPTANCE_20260930.json`
- `evidence/WINDOWS_110_HOST_ROLLBACK_ACCEPTANCE_20260930.json`
- `evidence/WINDOWS_110_HOST_RECOVERY_ACCEPTANCE_20260930.json`
