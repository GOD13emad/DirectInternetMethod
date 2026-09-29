# Architecture and Integration Contract

Status: FINAL_ACCEPTED_2026-09-29

Architecture:
- Loopback ULA: fd53:4444:48::53/128, ActiveStore, SkipAsSource=true.
- ctrld v1.5.7 foreground hidden process, UDP/TCP 53 bound to the ULA.
- Upstream DoH: https://76.76.10.11/p0, bootstrap 76.76.10.11.
- Owned NRPT catch-all points Windows DNS Client to the ULA only while active.
- zapret winws + WinDivert hostlist-scoped TCP/443 DPI desync.
- Physical default-interface IPv4 is auto-resolved and used for direct HTTPS probes.

Prohibited mutations:
- No adapter DNS mutation.
- No Windows Native DoH mapping mutation.
- No VPN connection creation.
- No HTTP/SOCKS proxy.
- No 0.0.0.0/1 or 128.0.0.0/1 routes.

Ownership:
- NRPT DisplayName: DirectDnsDpiHarness.
- ULA is removed only when state proves this package created it.
- ctrld/winws processes are owned only if their executable paths are under the installed package root.
- WinDivert services are owned only if PathName contains the installed package root.

Accepted precursor evidence:
- LOOPBACK_ULA_LISTENER_TRIAL_20260929.json
- NRPT_ULA_TRIAL_20260929.json
- ULA_DNS_ARCHITECTURE_DECISION_20260929.json

Final gate: PASS.
- Cycle 1: Start → 3 DNS/HTTPS rounds → default-mode Chrome YouTube → Stop → exact rollback.
- Cycle 2: Start → 2 DNS/HTTPS rounds → default-mode Chrome YouTube → Stop → exact rollback.
- Authority: `evidence/FINAL_ACCEPTANCE_20260929.json`.


Final acceptance:
- evidence/FINAL_ACCEPTANCE_20260929.json => PASS_FINAL.
- Cycle 1: 3 DNS/HTTPS stability rounds PASS; Chrome default-mode YouTube PASS; exact rollback PASS.
- Cycle 2: 2 DNS/HTTPS stability rounds PASS; Chrome default-mode YouTube PASS; exact rollback PASS.
- Final baseline: adapter DNS restored, preexisting NRPT preserved, ICS same PID, no ULA, no ctrld/winws/WinDivert residue, no /1 routes, WinHTTP direct.

- Final post-patch acceptance additionally proved no `ctrld_control.sock` residue after either rollback.
