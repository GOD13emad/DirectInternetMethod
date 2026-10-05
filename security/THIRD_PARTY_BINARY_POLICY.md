# Third-party binary admission policy

Status: CURRENT — security/release gate

All new or updated third-party binaries, drivers, archives, and executable bundles are treated as **UNAPPROVED** until they pass the same promotion path. Connectivity benefit never overrides a failed malware gate.

## Promotion path

1. **Provenance and identity**
   - authoritative upstream repository/release only;
   - exact version/tag/commit recorded;
   - release digest/checksum matched before inspection;
   - file SHA-256 recorded in Project Evidence.

2. **Static inspection**
   - enumerate archive contents and executable/file types;
   - compare expected files with upstream source/release layout;
   - inspect PE/ELF imports/strings and high-risk source patterns where practical;
   - identify bundled drivers/runtimes separately so an archive-level alert is not misattributed.

3. **Platform malware scan**
   - Windows candidates: Microsoft Defender scan/read-back;
   - other platform scanners may supplement but do not replace the native platform gate;
   - Severe/Concrete malware detection => REJECTED unless an independently reproducible clean source build and subsequent clean platform scan establish a different artifact identity.

4. **Isolated execution**
   - execute only the minimum behavior required for identification/compatibility;
   - use a disposable VM/sandbox or a locked-down non-privileged environment with no secrets and no production project state;
   - no privileged packet interception, persistence, credential access, or unrestricted network execution for a quarantined candidate;
   - record command, isolation boundary, output, and hash.

5. **Project regression**
   - contracts/builds/syntax tests;
   - lifecycle/rollback tests appropriate to the component;
   - no weakening of antivirus, firewall, service ACLs, or updater verification.

6. **Explicit promotion**
   - only evidence-backed candidates are added to runtime manifests/hash pins;
   - rejected hashes are recorded in `security/rejected_components.json`;
   - CI `tests/rejected_component_audit.py` fails if a rejected executable/archive becomes tracked.

## Rejected-file handling

- Do not restore a Severe/Concrete Defender quarantine automatically.
- Do not create Defender exclusions to make a candidate pass.
- Do not execute a rejected Windows binary on the production Windows host.
- Useful algorithms/configuration ideas may be reimplemented using already-accepted runtimes or independently rebuilt clean artifacts.

## Current case

`bol-van/zapret2 v1.0.5.2` release archive matched the official GitHub digest but Microsoft Defender classified the archive as `Trojan:Win32/Suschil!rfn` (Severe/Concrete). The Windows archive/binary remains rejected. The Linux `nfqws2` binary was only version-queried inside a non-privileged, private-network systemd user sandbox; no privileged/networked packet execution occurred. Design ideas were reused with the already-accepted v72.13 runtime instead of shipping the rejected archive.
