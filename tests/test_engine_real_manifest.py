"""Read-only compatibility check against the real DIM Windows source manifest.

The bundle's executable bytes are *not* included in this source-only probe;
no native setup, service or package installation is performed.
"""
import json
from pathlib import Path
import unittest

from installer_engine.engine import manifest_schema

REPO = Path(__file__).resolve().parents[1]


@unittest.skipUnless((REPO / 'windows/manifest.json').is_file(),
                     'the isolated prototype ZIP does not include the Windows product tree')
class RealWindowsPayloadManifest(unittest.TestCase):
    def test_681_scoped_entries_satisfy_shared_manifest_portability(self):
        source = json.loads((REPO / 'windows/manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(source['product'], 'Direct Internet Method')
        files = [
            {
                'path': item['scope'] + '/' + item['file'].replace('\\', '/'),
                'bytes': item['bytes'],
                'sha256': item['sha256'].lower(),
                'mode': 0o644,
            }
            for item in source['files']
        ]
        self.assertGreaterEqual(len(files), 600)
        self.assertEqual(sum(x['path'].startswith('user/') for x in files), 7)
        self.assertTrue(any('/.signature.p7s' in x['path'] for x in files))
        normalized = {
            'schema': 1, 'product': source['product'],
            'version': source['version'], 'platform': 'windows-x86_64',
            'files': files,
        }
        self.assertIs(manifest_schema(normalized, platform='windows-x86_64'), normalized)


if __name__ == '__main__':
    unittest.main(verbosity=2)
