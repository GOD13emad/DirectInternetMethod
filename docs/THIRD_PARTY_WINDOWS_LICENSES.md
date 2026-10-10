# Third-party Windows runtime licenses and source provenance

**Status: technical provenance and license-text inventory — legal redistribution acceptance remains OPEN.**
Project: Direct Internet Method. Candidate: v1.5.2. Baseline source: `08770b3a30e89a0921e74c3c4df50fad574d4c19` prior to this notice revision.

This document records the binary releases and texts bundled with the Windows Installer. It does **not** license Direct Internet Method's own source code or represent a legal opinion. The rights holder must approve a project license; the repository has no root `LICENSE` yet.

## WinDivert 2.2.2 (Basil)

Source and original release: [WinDivert v2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2). Official ZIP: `WinDivert-2.2.2-A.zip` (SHA256 `63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15`).

The Windows Installer redistributes the upstream unmodified x64 `WinDivert.dll` (SHA256 `C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2`) and `WinDivert64.sys` (SHA256 `8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2`). Both match the official release ZIP byte-for-byte.

WinDivert offers a **choice** of LGPL version 3 or GPL version 2. Its **complete unmodified upstream** combined license bundle is installed as `Privileged\bin\zapret\LICENSE.WinDivert.txt`, SHA256 `14A0CB5214D536E4FDAE6AA3F5696F981EEDA106CD026E9794BBA489EE79D628`. Underlying source is publicly available at the versioned repository link above. Additional source-distribution obligations, including corresponding source and relinking terms where applicable, require owner/legal verification.

## Cygwin runtime 3.4.10-1

The Installer redistributes `cygwin1.dll` version 3.4.10, SHA256 `103104A52E5293CE418944725DF19E2BF81AD9269B9A120D71D39028E821499B`. This binary is byte-identical to `usr/bin/cygwin1.dll` inside archived `cygwin-3.4.10-1.tar.xz` (SHA256 `BB81511484DE5E0182B0BAEFAD1BD1ABEE618FA0656A25B283B0A32FF72AC088`).

The corresponding archived source package `cygwin-3.4.10-1-src.tar.xz` has SHA256 `AC70AF0D4E644732F74946F55F7BAFE010BAB9B9DA39A9327C3F0367F1FA43A2` and embeds `newlib-cygwin-3.4.10.tar.bz2` (SHA256 `2F9890A76E76FE9D679EDC3386929571A109F0820754DAE4DD7C6471F880006`). Archived package reference: [Cygwin x64 archived release directory](https://ftp.cvut.cz/mirrors/cygwin.com/x86_64/release/cygwin/). This is an archived mirror, **not** an independently authenticated signed release; extra provenance verification remains a gate.

Bundled **unmodified** texts, byte-exact to version 3.4.10 source:
- `LICENSE.Cygwin.txt`: `CYGWIN_LICENSE`, SHA256 `794433752103CF4BBB4A84A1BDB8FBC150ABB1762704BB35FECC9F7F820BE984`.
- `LGPL3.Cygwin.txt`: `COPYING.LIB`, SHA256 `DA7EABB7BAFDF7D3AE5E9F223AA5BDC1EECE45AC569DC21B3B037520B4464768`.
- `GPL3.Cygwin.txt`: `COPYING`, SHA256 `8CEB4B9EE5ADEDDE47B31E975C1D90C73AD27B6B165A1DCD80C7C545EB65B903`.

These are installed alongside the DLL at `Privileged\bin\zapret`. Cygwin's API library is subject to LGPLv3-or-later and a documented linking exception; [official Cygwin licensing](https://cygwin.com/licensing.html). Making corresponding source available and satisfying any applicable redistribution conditions remain owner/legal acceptance gates, not automatically proved by shipping license texts.

## Other dependencies

`ctrld.exe` v1.5.7 (MIT) notice: `Privileged\bin\ctrld\LICENSE.txt`. `winws.exe` from zapret (MIT) notice: `Privileged\bin\zapret\LICENSE.txt`. The bundled PowerShell 7.6.6 runtime also carries its upstream `LICENSE.txt` and `ThirdPartyNotices.txt`.

## Release fail-closed checklist

Before public publication, verify (1) source owner rights and a legitimately selected OSI-approved license for Direct Internet Method; (2) exact dependency upstream provenance and any required corresponding source distribution/availability; (3) complete NOTICE and source offer terms reviewed by an authorized maintainer/legal advisor; (4) full installer payload and notices hash-checked; (5) publicly trusted publisher signing and real Smart App Control-on install/update acceptance; (6) exact GitHub release/tag and re-download SHA confirmation.

The current v1.5.2 candidate remains **RELEASE HOLD / FINAL UNPROVEN**. Never use a self-signed certificate as a substitute for publisher trust, or present third-party binaries as project-owned.
