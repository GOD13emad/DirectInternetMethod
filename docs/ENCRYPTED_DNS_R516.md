# R516 — encrypted selective DNS candidate (NOT RELEASED)

**Project:** Direct Internet Method; source authority is exact GitHub main commit
`26ef644117ea474b487186ce5e6e61e92cd02dd4`. Existing public
Stable remains **v1.5.4**. The last cumulative Project Brain accepted is R514
SHA-256 `DF4D5EFD2F412D344160745491BC5F812DCD03AF8D89B3B21FC5644D9C229300`.

## Reason and evidence

The installed Linux `linux/system/selective_dns.py` has an explicitly
opted-in but **unencrypted** UDP upstream `194.225.152.10` routed via
`dnsmasq`. It does not meet the project's encrypted-DNS requirement
under observed DNS interception.

R511 and R513 used the already bundled `ctrld v1.5.7` with verified TLS
DoH `https://76.76.10.11/p0` on bounded per-link DNS pilots. R516 added
a narrower localhost-only source-policy test (non-root, MMZ Linux on
2026-10-14) on `127.0.0.1:53534` with `systemd-run --user` and a 90-second
`RuntimeMaxSec`; system DNS, Tailscale and the Direct Method app were not
changed. Exact runtime TOML SHA-256:
`46F63805FE53B5CEDC6B7D4DF242BBF13A6CA8229BB9072058BE8DE304697954`.

Observed R516 localhost DNS:
- `www.youtube.com`: public IP addresses `142.251.150.4` through
  `142.251.157.4`, no RFC1918 addresses;
- `www.googlevideo.com`: public `142.251.141.36`;
- `github.com`: public `140.82.121.3`, same as router;
- `example.com`: public Cloudflare IPs;
- direct query against original `192.168.8.1` returned forged/private
  `10.10.34.36` for YouTube.
The temporary user unit exited or was stopped and the listener was absent,
with DNS and default route/Tailscale unchanged.

Independent repeat on Emad Linux (router `192.168.20.1`, `127.0.0.1:53535`)
generated **byte-exact** source TOML SHA-256
`3CC90962571AC80220B1A947C901709C64CD0DA0BD63EE5BEB6D1EC8781615DC`.
The DoH path gave legitimate public YouTube and Googlevideo addresses,
and `github.com` matched the physical router. **`example.com` timed out
because this non-target request intentionally fell back to Emad's unreliable
router DNS.** Thus the targeted model demonstrably protects listed domains;
it does NOT repair arbitrary domains, which require an explicit broader opt-in.
The user-bounded test service stopped, with physical DNS, Tailscale and
Direct Method unchanged. On Emad, the separate Seman L2TP connection remained
user-controlled and was not used to infer safe combined product mode.

Both routers' rendered Policy bytes are pinned in the **46/46 offline
negative-first tests**, and all invalid resolver addresses and unsafe ports
fail closed. MMZ direct router YouTube answers were private during the test;
Emad's physical router responses vary over time, so one public answer from
that router does not establish reliable default DNS.

The pure source policy generator in
`linux/system/encrypted_selective_policy.py` emits **byte-exact** TOML
for the validated MMZ router and temporary listener port. It has negative-first
rootless contracts in `tests/encrypted_selective_dns_policy_contract.py`.
No installer, root helper, UI, upgrade flow or published binary is wired
to this policy in R516.

## Acceptance and open gates

**PASS:** rootless isolated policy, exact runtime sample, encrypted target
DoH with real public A, original router fallback for non-target names and
bounded cleanup without product/system DNS/Tailscale changes.

**OPEN:** supervised integration into one protected updater and GUI;
opt-in token migration from *unencrypted* to *encrypted* (never silently
reinterpret consent); native per-link route-only recovery/backstop with
systemd-resolved; tests on Ubuntu 26 under actual installed user/service;
one-install update/rollback and hosted exact-SHA CI; selected-site HTTPS
access (MMZ YouTube still curl35); Seman concurrent VPN policy and
service/region HTTP403.

The generator must not be silently substituted into v1.5.4's old
`dnsmasq` controller, because the controller's assumptions (runtime
binary, state schema, consent, rollback) differ. **SUPERSEDED—DO NOT RUN**
includes older temporary R510/R512/R513/R514 and independently completed
R515 scripts; preserve previous Brain and historical raw files.

## Next exact action

In a separate transaction, design and negative-test an opt-in encrypted
controller that owns a disposable per-link resolver, enforces route-only
domains and exposes an independent bounded rollback before touching DNS.
Then modify the protected installer and GUI together in a versioned release
candidate; require a clean in-place upgrade path, native V&V, CI and
explicit promotion gates. Do not publish merely because the pure policy
and DNS lookups PASS.

Sources:
- Control D ctrld v1.5.7 configuration reference, policy precedence
  (rules before networks): https://github.com/Control-D-Inc/ctrld/blob/v1.5.7/docs/config.md
- Ubuntu systemd-resolved D-Bus SetLinkDNSEx/SetLinkDomains/RevertLink:
  https://manpages.ubuntu.com/manpages/resolute/man5/org.freedesktop.resolve1.5.html
- Public v1.5.4 release:
  https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v1.5.4
