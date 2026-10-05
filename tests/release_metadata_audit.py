from __future__ import annotations
import hashlib, json, pathlib, re, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
release = json.loads((ROOT / 'RELEASE.json').read_text(encoding='utf-8-sig'))
version = str(release['version'])
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
if f'Current application release: `v{version}`' not in delivery_readme:
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
if str(win_manifest.get('version')) != version:
    raise SystemExit(f"windows/manifest.json version {win_manifest.get('version')} != {version}")

linux_ui = (ROOT / 'linux' / 'app' / 'direct_internet_method.py').read_text(encoding='utf-8-sig')
if ('VERSION="' + version + '"') not in linux_ui and ('VERSION = "' + version + '"') not in linux_ui:
    raise SystemExit('Linux UI version is inconsistent with RELEASE.json')

win_release = json.loads((ROOT / 'windows' / 'RELEASE.json').read_text(encoding='utf-8-sig'))
if str(win_release.get('version')) != version:
    raise SystemExit(f"windows/RELEASE.json version {win_release.get('version')} != {version}")

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
