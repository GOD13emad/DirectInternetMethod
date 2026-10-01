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

print(f'PASS release_metadata_audit v{version}: {len(expected)} artifacts')
