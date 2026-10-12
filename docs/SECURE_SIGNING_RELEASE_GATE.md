# Secure Windows release: signed-publication acceptance

**Date:** 2026-10-08
**Stable version:** v1.5.1, unchanged.
**Candidate:** v1.5.2, PR #24 Draft/HOLD.
**Current blocker:** Trusted publisher code-signing identity is not available.

## Confirmed Smart App Control block

The exact unsigned Windows installer SHA256
`BE6B7C1127CC62A4CE706EEFEC778B87CAA7784A9B19D61E282741163E281D85`
was blocked in an offline Windows Sandbox with Smart App Control ON.
CodeIntegrity event 3077 identified `VerifiedAndReputableDesktop`,
policy GUID `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`, with a matching
installer flat SHA. Correlated 3089 had `TotalSignatureCount=0`.
Sanitized evidence: `evidence/DIM_152_SMART_APP_CONTROL_3077_3089_20261008.json`.
Signing is a prerequisite, not a guarantee of acceptance under every
current and future security policy.

## Legitimate identity issuance paths

Microsoft Artifact Signing Public Trust needs an eligible, validated
publisher identity and an Azure billing/account workflow; Private Trust
and test profiles do not provide general public trust. See
https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart and
https://learn.microsoft.com/en-us/azure/artifact-signing/concept-trust-models .

Commercial public code-signing certificates likewise require genuine
identity proof and approved key management. SignPath Foundation's
free OSS service has distinct conditions including an OSI-approved
license, appropriate licensing for components, documented ownership,
a trusted build and approval policy:
https://signpath.org/terms.html .
This repository has **no root LICENSE** at present. Do not invent
ownership consent or assign a license without the legal rights holder's
explicit selection. No suitable valid code-signing private key was
found in the checked Windows certificate stores. Self-signed/test
certificates are not an alternative for public trust.

## Release gate sequence (not yet completed)

1. Confirm clean exact SHA of the candidate, verified dependencies,
   legitimate publisher rights and trusted signing identity.
2. Build project-owned GUI and privileged service binaries. Sign
   required binaries, independently verify certificates and SHA-256.
   Do not claim to sign unrelated third-party binaries as publisher.
3. Rebuild Windows payload manifest from **final** binary bytes;
   then package the Inno Setup installer and sign the final installer
   with trusted timestamp. Recalculate all versioned checksums,
   `RELEASE.json` identities and build evidence after signing.
4. Run `tests/windows_distribution_signature_audit.ps1` on the
   signed artifact. Correct signature is a necessary condition only.
5. Test in a fresh offline Windows Sandbox with Smart App Control
   enforced. Confirm installation exit 0, registration/AppId, running
   privileged service, GUI and all 680 manifest file hashes; preserve
   the actual CodeIntegrity evidence on failure.
6. Test Windows v1.5.1 -> v1.5.2 direct update and
   Start/Stop/Recovery + route/DNS baseline rollback on a safely OFF
   host or isolated VM, never the user's active session.
7. Test the Linux fresh-install `umask 077` fix and independently
   rebuilt archive. Linux update avoids repeat admin only if the
   already-installed protected backend is proven byte-identical.
   Privileged changes may still need genuine OS authorization.
8. Exact-head Windows/Linux CI, final signed asset SHA verification,
   release approval, **new** immutable tag/release and public
   re-download; update Project Brain/HISTORY with accepted evidence.

## Fail-closed metadata control

For v1.5.2 and newer,
`tests/release_metadata_audit.py` refuses claims of
`PUBLISHED` or `PASS_FINAL` if trusted Windows signing,
Smart App Control-on isolated installation and signed-hash/sandbox
proof references are missing. Four deliberately forged-status
negative cases are tested by
`tests/release_publication_negative_regression.py`.
These checks **do not cryptographically authenticate** a claimed
signature or an asserted sandbox receipt: actual signed artifacts and
independent installation evidence remain mandatory.

PR #24 must remain Draft/HOLD, and issues #23/#25 stay open until the
external signing and installed release gates genuinely pass. Never
disable or bypass Smart App Control to obtain a false-green result.

## 2026-10-09 R223 — Windows release signer eligibility guard

The previous `windows_distribution_signature_audit.ps1` validated SHA and
`Get-AuthenticodeSignature.Status == Valid`, but it did not independently
reject a locally trusted self-signed development certificate, an ECC signer
(unsupported by Smart App Control), missing Code Signing EKU, or a private
untrusted CA. This omission is a **confirmed source-level gate weakness**;
no real public signature forgery or unsafe Windows installation was performed.

R223 adds `Assert-EligibleSignerForSmartAppControl` and a Windows-CI
negative/positive contract. Six ephemeral in-memory certificate fixtures
reject unsigned, missing signer, self-signed RSA, ECC leaf, untrusted CA RSA
and missing EKU; a Microsoft Authenticode-signed OS reference passes the
positive branch. No test certificate was imported into machine/user trust
stores. Existing unsigned v1.5.2 Windows setup SHA
`BE6B7C1127CC62A4CE706EEFEC778B87CAA7784A9B19D61E282741163E281D85`
still fails closed with exit 42; no installation or security-policy mutation.

**Do not mistake this source guard for public-trust acceptance.** A
legitimate publisher identity, a genuine trusted RSA code-signing
certificate/signing service and timestamped exact artifact remain required,
then a **clean Smart App Control-ON Sandbox** must independently accept
installation, payload signatures, service/GUI registration and update flow.
A self-signed certificate, disabled SAC, manually injected trust root, or
a merely positive Microsoft-signed reference sample cannot satisfy DoD.

Microsoft-supported external choices (eligibility and identity validation
NOT yet accepted):

- Microsoft Artifact Signing Public Trust, subject to identity validation
  and location eligibility; external publisher controls required.
- CA-issued OV certificate, subject to legal publisher validation.
- SignPath Foundation free signing for qualifying open-source projects;
  independent application and approval required.
- Microsoft Store MSIX re-signing at submission; this product's service,
  WinDivert driver and privileged installer compatibility with MSIX is
  **UNPROVEN** and must be evaluated before choosing that route. The Store
  does **not** re-sign a submitted legacy EXE/MSI installer.

Primary references:
https://learn.microsoft.com/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control
https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart

R223 local signer-fixture tests PASS. Hosted exact-SHA CI must be accepted
after commit. Keep PR #24/#26 Draft and public stable v1.5.1 unchanged.
