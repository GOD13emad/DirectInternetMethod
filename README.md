# Direct Internet Method

<p align="center">
  <img src="https://raw.githubusercontent.com/TandemVector-Labs/.github/main/brand/social/DirectInternetMethod.png" alt="Direct Internet Method visual project card" width="720">
</p>

## Current public release: v1.5.4 Stable (.NET 10 LTS)

Published 13 October 2026, official release: https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v1.5.4 .

Windows: `DirectInternetMethod_1.5.4_Windows_Setup.exe`, SHA256 FFB9A2AE19C2E89338EE12EE8DA133F5A16DBF4DCF961678C33D77D0C3843133.
Linux: `DirectInternetMethod_1.5.4_Linux_x86_64.zip`, SHA256 4784FCD44ED3D1B40103BCA140B2C0066784F794D07C3AE1F525334766A553C7.
Published SHA256SUMS.txt SHA 68E70329E8B9DAC6B738CE9B90D99A0010030980CD9C17CDE45A5199A60692D8, with exact ACCEPTANCE_V154.json and third-party corresponding sources.

This is a public Stable, NOT a private draft. Windows WPF and Service use .NET 10 LTS. Publisher signing is not mandatory; users must not disable OS protections.
Active remote Tailscale/Direct Method host upgrades remain gated by safe managed OFF and verified rollback. Regional HTTP403 cannot universally be fixed by direct DNS/DPI.
The source-level RELEASE.json historical candidate label is build-time provenance and is NOT current publication authority.
See docs/PUBLISHED_V154_ASSET_AUTHORITY.md and the official Release for exact checksums and native accepted tests.

---

## Previous public release: v1.5.3 Stable (historical)

**v1.5.3 was published on 13 October 2026.** It is a public stable release, not an unpublished draft.

[Download the official Windows or Linux installer](https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v1.5.3)

| Platform | One installation package | SHA-256 |
|---|---|---|
| Windows x64 | `DirectInternetMethod_1.5.3_Windows_Setup.exe` | B517EA79C8949E960897CE814591F7C1518FDEA45E4419A891B64469E879B6FF |
| Linux x86_64 | `DirectInternetMethod_1.5.3_Linux_x86_64.zip` | 680343F86ABEC2D7B69CE807F4EC5B344789B2D6335C51C068BC49F4650DFC05 |

The Release-attached `SHA256SUMS.txt` and `ACCEPTANCE_V153.json` are the authority for the published packages. Do not substitute a locally rebuilt or QA-only installer for an official release asset.

### What this application does

Direct Internet Method provides targeted direct DNS/DPI methods on Windows and Linux. It is **not** a VPN, HTTP/SOCKS proxy or default-route tunnel. It includes a Windows WPF interface with a privileged service, a Linux desktop interface with a protected systemd/PolicyKit backend, connection diagnostics, custom host scopes, optional additional domain coverage, and a Router Gateway profile catalog.

Site availability depends on the network. HTTP 401 from an unauthenticated API demonstrates transport reachability, not a logged-in account. HTTP 403, login restrictions and regional egress policy are not reported as usable access. Router Gateway TCP probes do not establish a completed PPTP/L2TP/IPsec authenticated connection.

### Install and update

**Windows:** Run the single official Setup executable. Privileged installation uses the normal Windows UAC prompt. The installer retains the application identity and directory for in-place updates; it must not accumulate parallel installations. Stop the active Direct Method session through its own controls before upgrading. Do not forcibly stop unrelated services or disable Windows security protections.

**Linux:** Extract the official ZIP and run `./install.sh` from the extracted directory. Fresh protected-backend setup uses normal system authorization. A compatible byte-identical protected backend may be retained while user code updates. The installer refuses an active Direct Method session; use the managed Stop/Recovery action first and preserve a safe network recovery path.

Settings, user-managed files and custom Router Gateway provider data are protected by the tested update/rollback paths. Back up configuration before making changes on a live machine.

### Accepted release evidence

- Exact published Windows installer: hosted Windows native install, in-place update and rollback [run 38389324841](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38389324841).
- Direct Windows v1.5.1 to official v1.5.3 update and rollback: [run 38406271349](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38406271349).
- Linux protected root/user fresh lifecycle: [run 38388513538](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38388513538).
- Linux real v1.5.2 to v1.5.3 in-place update: [run 38390031680](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38390031680).
- Public release/tag verification: [run 38396348743](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38396348743).

These are bounded acceptance results, not a guarantee that every ISP, destination, user account or live host has been validated. Active-host maintenance remains a separate deployment task.

### Source development is not a replacement release

The `main` branch contains the .NET 10 maintenance change accepted in PR #55. It was tested with a genuine Windows installation, a visible WPF window, a running service, preserved user data and rollback in [run 38428921577](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38428921577). **The published v1.5.3 Windows installer has not been replaced by this .NET 10 build.** A future versioned distribution requires its own exact-asset acceptance.

The existing v1.5.3 archive contains build-time documentation and metadata. Their historical candidate labels do not override this public Release record. `docs/README_PACKAGE_153.md` preserves the exact originally shipped README solely so that the accepted Linux ZIP can be reproduced without changing any released byte. New releases must intentionally version their package documentation.

`PROJECT_BRAIN.md` below its authority notice is a historical project log, not the current release manifest. Current operational state is recorded in the cumulative versioned private Project Brain and the Release acceptance evidence.

### Tailscale and security limits

Tailscale/MagicDNS coexistence is network-specific. Preserving system DNS may also preserve a network's incorrect DNS answers; a running DPI process alone does not prove correct name resolution. Do not change all system DNS settings or weaken TLS certificate checks merely to make a connectivity indicator green.

Windows code signing is not a publication requirement chosen by the publisher. Systems enforcing unsigned-app restrictions may reject the installer; do not disable operating-system protections. Third-party license notices and the attached corresponding-source archives remain applicable. No new first-party source license is implied by this status clarification.
