# Direct Internet Method — Public v1.5.2 asset authority (R463)

**Fact, verified 2026-10-13:** public Stable release [v1.5.2](https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v1.5.2) is published. Release ID `410941631`; immutable tag/source `14a3eec378eb75856f6691b7b3edc970507ee61f`; release date `2026-10-12T20:25:24Z`.

| Published release asset | Bytes | SHA-256 |
| --- | ---: | --- |
| `DirectInternetMethod_1.5.2_Windows_Setup.exe` | 157118257 | `F94A81CC819E465D6B1000FFDB0B20A7212E39B6F6282ED8A720774148DFC78D` |
| `DirectInternetMethod_1.5.2_Linux_x86_64.zip` | 8273837 | `53C9FCADDBE96CEC9F63505AB20992479C422F3AB9A9E2379898F5A80BF76692` |
| `SHA256SUMS.txt` | 221 | `F5AD1390F3D62E35F4D9695A2B8602A18280EC6CC4B802688774EDA37F18B529` |
| `ACCEPTANCE_V152.json` | 1925 | `AB778E6C995760DDBB31F9A1FFE14D64A4E0A23B3CD9DAB6E7B397F55EE0D880` |
| `cygwin-3.4.10-1-src.tar.xz` | 8964220 | `AC70AF0D4E644732F74946F55F7BAFE010BAB9B9DA39A9327C3F0367F1FA43A2` |
| `WinDivert-v2.2.2-corresponding-source.zip` | 199555 | `65EC79C9E6AFA99F648A3F4D1F6DB794640B40D0B65BD438770EA503EE14ECB7` |

## Which checksums to trust

1. For **public v1.5.2 Stable downloads**, use the `SHA256SUMS.txt` **attached to the GitHub Release**, whose 221 bytes were independently read via GitHub's download endpoint and agree with GitHub's release-asset digest metadata.
2. The root `SHA256SUMS.txt`, `delivery/SHA256SUMS.txt` and the `platforms.*.sha256` values in root `RELEASE.json` are retained historical **Preview 3 / source contract** metadata: Windows `2F054752E3B1B4715D68958CA49639AEA6FE43E0E4CBC6611DDEEBABAE2C7EB5`, Linux `0218BEBD0DC8F88670374FF0E12A61D45229A03092C606678C5C00FD81DC2C9E`. They must not be presented as Stable release asset digests. Changing historical records blindly would invalidate their evidence chain.
3. The published release's source tag is fixed. Current `main` includes additional changes and is **not automatically identical to the shipped installer**.

## V&V and remaining gates

- **PASS — hosted genuine native Windows** v1.5.1 → v1.5.2 in-place → uninstall/rollback, source run [38300242241](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38300242241), raw `REPORT_R435.json` SHA `8448D818AA9F11C5F3BA48B8BB9ED15CCB5AB63818DE0B8903794DA090EEFF9B`.
- **PASS — hosted native Linux** protected/user install and rollback, source run [38300249518](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38300249518), raw `REPORT_R436.log` SHA `34D3930FF19FF09663A8AC6A74982628304A46F4D0E88787AF1CEEFDDB654A86`.
- **PASS — current `main` source CI** exact SHA `5d8fa89edf7def723773ecd3700825a086c43b3a`, [run 38313891717](https://github.com/GOD13emad/DirectInternetMethod/actions/runs/38313891717); it verifies source, not a newer public binary.
- **OPEN — latest source hotfix** PR [#45](https://github.com/GOD13emad/DirectInternetMethod/pull/45) fixes legacy v1.5.1 staged updater finalization in `main` only. The already-published v1.5.2 files do **not** contain this hotfix. A future official native service build requires independent exact-SHA build, installed-host QA and versioned release; no silent asset replacement.
- **OPEN — Windows Emad installed v1.5.1**; its network-active process must not be stopped, switched or updated without protected stop, route/DNS snapshot and rollback readiness. Saeid Windows and both Linux hosts report installed v1.5.2.
- **KNOWN LIMITATION — unsigned Windows installer** can be rejected by Smart App Control. Do not weaken native OS protections. HTTP 403 on restricted ChatGPT/Gemini egress is not a product PASS or universal-access guarantee. First-party source licensing/redistribution authorization remains a separate owner decision.

The historical Preview branches and old `DIM_R395_RELEASE_BUILD` worktree are **SUPERSEDED — DO NOT PROMOTE**. Preserve existing history and user data. This file changes documentation only; no application binary, release asset, user setting or installed service is modified.
