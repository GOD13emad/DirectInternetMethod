from __future__ import annotations
import hashlib, json, pathlib, re, subprocess


def assert_unsigned_publication_acceptance(meta):
    """Source metadata guards. Real public SHA/download/hosted receipts are checked
    separately by unsigned_public_release_contract.py --public-tag on the tagged
    GitHub-hosted runner. A textual PASS value is never cryptographic evidence."""
    ver = str(meta.get('version', ''))
    if not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', ver):
        raise SystemExit('RELEASE_VERSION_NOT_SEMVER')
    if tuple(map(int, ver.split('.'))) < (1, 5, 2):
        return
    policy = meta.get('publicUnsignedDistribution', {})
    if (not isinstance(policy, dict) or
        policy.get('onePublicLine') is not True or
        policy.get('codeSigningCertificateRequired') is not False or
        policy.get('disableWindowsSecurity') is not False):
        raise SystemExit('OWNER_UNSIGNED_DISTRIBUTION_POLICY_MISSING_OR_UNSAFE')
    status = str(meta.get('status', ''))
    if 'HOLD_APP_CONTROL_SIGNING' in status:
        raise SystemExit('SUPERSEDED_SIGNING_RELEASE_BLOCKER_STILL_ACTIVE')
    acceptance = meta.get('acceptance', {})
    publication = meta.get('publication', {})
    if not isinstance(acceptance, dict) or not isinstance(publication, dict):
        raise SystemExit('RELEASE_ACCEPTANCE_OR_PUBLICATION_NOT_OBJECT')
    published = (status.startswith(('PASS_FINAL', 'FINAL_', 'PUBLISHED_')) or
        str(acceptance.get('publication', '')).startswith(('PASS_PUBLIC', 'PUBLISHED_VERIFIED')) or
        bool(publication.get('publishedAt')))
    if not published:
        return
    if (acceptance.get('windowsFreshInstall') != 'PASS_HOSTED_REAL_INSTALL_UNINSTALL' or
        acceptance.get('windowsUpgradeRollback') != 'PASS_HOSTED_151_TO_152_AND_151_RESTORE_ZERO_ERRORS' or
        acceptance.get('windowsSecurityPolicyUnchanged') is not True):
        raise SystemExit('REAL_UNSIGNED_WINDOWS_INSTALL_AND_ROLLBACK_REQUIRED')
    receipts = meta.get('windowsHostAcceptanceEvidence', {})
    if not isinstance(receipts, dict):
        raise SystemExit('HOSTED_RELEASE_RECEIPT_MISSING')
    hashes = ('installerSha256', 'freshReportSha256', 'upgradeReportSha256')
    if any(not re.fullmatch('[A-Fa-f0-9]{64}', str(receipts.get(k,''))) for k in hashes):
        raise SystemExit('HOSTED_RELEASE_RECEIPT_HASH_MISSING')
    if any(not isinstance(receipts.get(k),int) or receipts[k] <= 10000000000
           for k in ('freshRunId', 'upgradeRunId')):
        raise SystemExit('HOSTED_RELEASE_RECEIPT_RUN_ID_MISSING')
    if receipts.get('installerSha256','').upper() != str(meta.get('platforms',{}).get('windows',{}).get('sha256','')).upper():
        raise SystemExit('HOSTED_RELEASE_INSTALLER_SHA_MISMATCH')
    if (publication.get('tag') != 'v'+ver or
        not re.fullmatch('[a-f0-9]{40}', str(publication.get('tagCommit',''))) or
        not str(publication.get('releaseUrl','')).startswith('https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v') or
        not publication.get('publishedAt')):
        raise SystemExit('PUBLIC_STABLE_RELEASE_AUTHORITY_INCOMPLETE')
    # Source-only checks cannot establish a real GitHub publication.
    # Mandatory hosted tag job must run actual downloads and validate the raw
    # reports independently; metadata labels never substitute for that evidence.


ROOT = pathlib.Path(__file__).resolve().parents[1]
release = json.loads((ROOT / 'RELEASE.json').read_text(encoding='utf-8-sig'))
def require_public_stable_forward_update_from_rc155(version: str) -> None:
    """Public successors must be newer than deployed private Windows 1.5.5-rc1.

    Both already-installed GUI and privileged service carry .NET AssemblyVersion
    1.5.5.0 and compare GitHub's numeric stable tag using System.Version.
    In System.Version, v1.5.5 is (1,5,5,-1), NOT newer than (1,5,5,0).
    Therefore v1.5.5 Stable could strand both physical RC1 canaries indefinitely
    on the private build. The earliest monotonically safe next Stable tag is
    v1.5.6 unless a separately validated and installed promotion client exists.
    This guard does not declare v1.5.6 acceptable for publication by itself.
    """
    if not re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+", version):
        raise SystemExit("RELEASE_VERSION_NOT_SEMVER")
    parts = tuple(int(n) for n in version.split("."))
    if parts > (1, 5, 4) and (*parts, -1) <= (1, 5, 5, 0):
        raise SystemExit("PUBLIC_155_WOULD_NOT_AUTOUPDATE_DEPLOYED_PRIVATE_RC1_USE_156_OR_VERIFIED_PROMOTION")

version = str(release['version'])
require_public_stable_forward_update_from_rc155(version)
platforms = release['platforms']

expected = {}
for key in ('windows', 'linux'):
    p = platforms[key]
    name = pathlib.Path(p['artifact']).name
    sha = str(p['sha256']).upper()
    if not re.fullmatch(r'[0-9A-F]{64}', sha):
        raise SystemExit(f'invalid {key} sha256 in RELEASE.json')
    expected[name] = sha

lines = [x.strip() for x in (ROOT / 'SHA256SUMS.txt').read_text(encoding='ascii').splitlines() if x.strip()]
actual = {}
for line in lines:
    m = re.fullmatch(r'([0-9A-Fa-f]{64})\s+(.+)', line)
    if not m:
        raise SystemExit(f'invalid SHA256SUMS line: {line!r}')
    sha, name = m.group(1).upper(), m.group(2).strip()
    if name in actual:
        raise SystemExit(f'duplicate checksum entry: {name}')
    actual[name] = sha

if actual != expected:
    raise SystemExit(f'SHA256SUMS mismatch: expected={expected!r} actual={actual!r}')

delivery_sums = ROOT / 'delivery' / 'SHA256SUMS.txt'
if delivery_sums.exists():
    delivery_text = delivery_sums.read_text(encoding='ascii').replace('\r\n','\n')
    root_text = (ROOT / 'SHA256SUMS.txt').read_text(encoding='ascii').replace('\r\n','\n')
    if delivery_text != root_text:
        raise SystemExit('root SHA256SUMS.txt differs from delivery/SHA256SUMS.txt')

delivery_readme = (ROOT / 'delivery' / 'README.md').read_text(encoding='utf-8-sig')
if f'Current application release: `v{version}`' not in delivery_readme and f'v{version} BUILD CANDIDATE' not in delivery_readme:
    raise SystemExit(f'delivery/README.md does not declare current application release v{version}')
if (ROOT / '.git').exists():
    tracked_delivery = subprocess.run(
        ['git','ls-files','--','delivery/DirectInternetMethod_*'],
        cwd=ROOT,text=True,capture_output=True,check=True
    ).stdout.splitlines()
    if tracked_delivery:
        raise SystemExit(f'versioned delivery binaries must not be tracked in current source tree: {tracked_delivery!r}')

provider_data = json.loads((ROOT / 'router_gateway' / 'providers.json').read_text(encoding='utf-8-sig'))
release_router = release.get('routerGateway', {})
if int(release_router.get('dataRevision', -1)) != int(provider_data.get('dataRevision', -2)):
    raise SystemExit(
        f"Router Gateway data revision mismatch: RELEASE.json={release_router.get('dataRevision')} "
        f"providers.json={provider_data.get('dataRevision')}"
    )

checksum_meta = release.get('checksums', {})
checksum_rel = str(checksum_meta.get('artifact',''))
checksum_expected = str(checksum_meta.get('sha256','')).upper()
if not checksum_rel or not re.fullmatch(r'[0-9A-F]{64}', checksum_expected):
    raise SystemExit('RELEASE.json checksums metadata is missing or invalid')
checksum_path = ROOT / checksum_rel
if not checksum_path.is_file():
    raise SystemExit(f'checksum artifact missing: {checksum_rel}')
checksum_actual = hashlib.sha256(checksum_path.read_bytes()).hexdigest().upper()
if checksum_actual != checksum_expected:
    raise SystemExit(f'checksum artifact hash mismatch: expected={checksum_expected} actual={checksum_actual}')

readme = (ROOT / 'README.md').read_text(encoding='utf-8-sig')
for name in expected:
    if ('`' + name + '`') not in readme:
        raise SystemExit(f'README missing release artifact {name}')
if ('v' + version) not in readme and (' ' + version) not in readme:
    raise SystemExit(f'README does not mention current version {version}')

win_manifest = json.loads((ROOT / 'windows' / 'manifest.json').read_text(encoding='utf-8-sig'))
win_release = json.loads((ROOT / 'windows' / 'RELEASE.json').read_text(encoding='utf-8-sig'))
win_version = str(win_release.get('version'))
# R535: an UNPUBLISHED, Windows-only private RC1 candidate is developed against
# the publicly accepted v1.5.4 cross-platform base. It cannot silently
# replace root/public release authority or satisfy public publication.
# The exception is branch- and metadata-exact; all original public sha/source
# checks above still run. Every other drift remains a hard failure.
branch = subprocess.run(['git','branch','--show-current'],cwd=ROOT,
                        capture_output=True,text=True,check=True).stdout.strip()
ref = __import__('os').environ.get('GITHUB_REF','')
private_win_rc1 = (
    version == '1.5.4' and win_version == '1.5.5-rc1'
    and win_release.get('status') == 'PRIVATE_WINDOWS_RC1_SOURCE_CANDIDATE_UNPUBLISHED_UNPROVEN'
    and win_release.get('previousAccepted',{}).get('version') == '1.5.4'
    and win_release.get('previousAccepted',{}).get('tag') == 'v1.5.4'
    and win_release.get('publication',{}).get('publishedAt') is None
    and (branch == 'feature/r535-windows-155rc1'
         or ref in ('refs/heads/feature/r535-windows-155rc1',
                    'refs/heads/feature/r520-linux-155rc1-ci'))
)
if win_version != version and not private_win_rc1:
    raise SystemExit('WINDOWS_PRIVATE_RC1_IDENTITY_NOT_AUTHORIZED')
if str(win_manifest.get('version')) != win_version:
    raise SystemExit('WINDOWS_MANIFEST_NOT_MATCHING_PLATFORM_VERSION')

linux_ui = (ROOT / 'linux' / 'app' / 'direct_internet_method.py').read_text(encoding='utf-8-sig')
# The Linux 1.5.5-rc1 source was already present on this private draft branch.
# Its published metadata remains anchored to v1.5.4 until native acceptance.
# Require exact RC1 UI bytes for private candidate and exact stable otherwise.
linux_source_expected = '1.5.5-rc1' if private_win_rc1 else version
if ('VERSION="' + linux_source_expected + '"') not in linux_ui and ('VERSION = "' + linux_source_expected + '"') not in linux_ui:
    raise SystemExit('Linux UI version is inconsistent with authorized source state')

assert_unsigned_publication_acceptance(release)
root_status = str(release.get('status',''))
root_published = ('PUBLISHED' in root_status and 'VERIFIED' in root_status) or str(release.get('acceptance',{}).get('publication','')).startswith('PASS_PUBLIC')
if root_published:
    win_status = str(win_release.get('status',''))
    if not ('PUBLISHED' in win_status and 'VERIFIED' in win_status):
        raise SystemExit(f'windows/RELEASE.json status is stale after publication: {win_status!r}')
    publication_state = str(win_release.get('acceptance',{}).get('publication',''))
    if publication_state not in {'PASS_PUBLIC_REDOWNLOAD_VERIFIED','PUBLISHED_VERIFIED'}:
        raise SystemExit(f'windows/RELEASE.json publication state is stale: {publication_state!r}')
    root_pub = release.get('publication',{})
    win_pub = win_release.get('publication',{})
    required_pub = ('tag','tagCommit','releaseUrl','publishedAt')
    if any(not str(root_pub.get(key,'')) for key in required_pub):
        raise SystemExit('RELEASE.json publication metadata is incomplete')
    if any(not str(win_pub.get(key,'')) for key in required_pub):
        raise SystemExit('windows/RELEASE.json publication metadata is incomplete')
    for key in ('tag','tagCommit','releaseUrl','publishedAt'):
        if str(win_pub.get(key,'')) != str(root_pub.get(key,'')):
            raise SystemExit(f'windows/RELEASE.json publication {key} != RELEASE.json')

print(f'PASS release_metadata_audit v{version}: {len(expected)} artifacts')
