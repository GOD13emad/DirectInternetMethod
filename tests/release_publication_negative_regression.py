#!/usr/bin/env python3
from copy import deepcopy
from pathlib import Path
import runpy, json

R = Path(__file__).resolve().parents[1]
namespace = runpy.run_path(str(R / 'tests/release_metadata_audit.py'))
check = namespace['assert_trusted_publication_acceptance']
current = json.loads((R / 'RELEASE.json').read_text(encoding='utf-8-sig'))
assert current['version'] == '1.5.2'
assert str(current['acceptance'].get('windowsDistributionSigning', '')).startswith('FAIL')
assert str(current['acceptance'].get('windowsSandbox', '')).startswith('FAIL')
check(current)  # The blocked, unpublished candidate is correctly not promoted.

for name in ('published_status', 'publication_flag', 'published_timestamp'):
    spoof = deepcopy(current)
    if name == 'published_status':
        spoof['status'] = 'PASS_FINAL_PUBLISHED_INSTALLED_VERIFIED'
    elif name == 'publication_flag':
        spoof['acceptance']['publication'] = 'PASS_PUBLIC_REDOWNLOAD_VERIFIED'
    else:
        spoof['publication']['publishedAt'] = '2026-10-08T00:00:00Z'
    try:
        check(spoof)
    except SystemExit as err:
        assert 'TRUSTED_WINDOWS_SIGNATURE_AND_SANDBOX_REQUIRED' in str(err), (name, err)
    else:
        raise AssertionError('FALSE_PUBLISHED_CLAIM_ACCEPTED:' + name)

# Even metadata PASS labels alone do not bypass the independent proof gate.
proof_spoof = deepcopy(current)
proof_spoof['status'] = 'PASS_FINAL_PUBLISHED_INSTALLED_VERIFIED'
proof_spoof['acceptance']['windowsDistributionSigning'] = 'PASS_TRUSTED_AUTHENTICODE_VERIFIED'
proof_spoof['acceptance']['windowsSandbox'] = 'PASS_ISOLATED_INSTALL_VERIFIED'
try:
    check(proof_spoof)
except SystemExit as err:
    assert 'WINDOWS_PUBLICATION_PROOF_MISSING' in str(err), err
else:
    raise AssertionError('MISSING_SIGNING_PROOF_WAS_ACCEPTED')
print('PASS 4/4 negative release promotion regressions, blocked v1.5.2 candidate remains unpromoted')
