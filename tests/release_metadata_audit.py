from __future__ import annotations
import json, pathlib, re

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
if 'PUBLISHED_VERIFIED' in root_status:
    win_status = str(win_release.get('status',''))
    if 'PUBLISHED_VERIFIED' not in win_status:
        raise SystemExit(f'windows/RELEASE.json status is stale after publication: {win_status!r}')
    publication_state = str(win_release.get('acceptance',{}).get('publication',''))
    if publication_state not in {'PASS_PUBLIC_REDOWNLOAD_VERIFIED','PUBLISHED_VERIFIED'}:
        raise SystemExit(f'windows/RELEASE.json publication state is stale: {publication_state!r}')
    root_pub = release.get('publication',{})
    win_pub = win_release.get('publication',{})
    for key in ('tag','tagCommit','releaseUrl','publishedAt'):
        if str(win_pub.get(key,'')) != str(root_pub.get(key,'')):
            raise SystemExit(f'windows/RELEASE.json publication {key} != RELEASE.json')

print(f'PASS release_metadata_audit v{version}: {len(expected)} artifacts')
