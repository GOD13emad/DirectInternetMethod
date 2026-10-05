# Delivery authority

Current application release: `v1.5.0`.

Release authority is the Git tag/GitHub Release plus root `RELEASE.json`, root/delivery `SHA256SUMS.txt`, and acceptance evidence. Versioned installer/archive binaries are intentionally **not tracked in the current source tree**; download authoritative binaries from the corresponding GitHub Release.

## Current v1.5.0 authority

- Windows: `DirectInternetMethod_1.5.0_Windows_Setup.exe`
  - SHA-256: `544FB1D01242F2670C44CA325A171F5CB4B7E962109A68239BCEECFDB83B266C`
- Linux: `DirectInternetMethod_1.5.0_Linux_x86_64.zip`
  - SHA-256: `61A76B06A59BAC55196DD538D1D17C27C86F8045C6564B67AF3091A3AC7CCBD2`
- Checksum asset: `SHA256SUMS.txt`
  - SHA-256: `66B4BCD88E6B2708D51BAA75D66256CC0295AE1D0C274C12B3B51B479E15522C`

The application release remains v1.5.0 while rotating Router Gateway provider data is maintained independently on `main/router_gateway/providers.json`. Current data authority is revision 3.

Historical releases remain available through their Git tags/GitHub Releases; they do not need duplicate binaries in the current branch. Do not choose artifacts by newest-file or directory-location heuristics.
