#!/usr/bin/env python3
"""One-time exact original-repo hosted native private-to-private release bridge."""
from pathlib import Path
import unittest
R=Path(__file__).resolve().parents[1]
WF=(R/".github/workflows/ci.yml").read_text()
SCRIPT=(R/"tests/r848_windows_private156_forward_native.ps1").read_text()
class R848(unittest.TestCase):
 def test_provenance_and_hosted_authority(self):
  for s in ("GOD13emad/DirectInternetMethod","github-hosted","refs/heads/prep/r846-forward-157-native-gates","GITHUB_SHA","GH_TOKEN","12969796101","41038434425","r600-private-tested-v156-41038434425"):
   self.assertIn(s,SCRIPT)
 def test_fixed_private_v156_asset_digests(self):
  for s in ("5BDE9DFFC3B866A7754DABEF9EDC853CFE519A08944163C39D812B2C8E9F3620","0CC4270B507BC9A141B4012378EE28D42C0EE8C5509E03A9ED3FB8C73B9865A3","32AA6E88F57097D669D395999ED23A8AA85C2A330C41C542D1CB44A744C031FB"):
   self.assertIn(s,SCRIPT)
 def test_native_transaction_contract(self):
  for s in ("PASS_HOSTED_NATIVE_156_TO_157_AND_BACK_156","IN_PLACE_USER_DATA_PRESERVED","ONE_UNINSTALLER","NETWORK_BASELINE_EXACT","EXACT_PRIVATE_156_BINARY_HASHES_RESTORED","DIM_R846_NATIVE"):
   self.assertIn(s,SCRIPT)
  self.assertNotIn("1.5.4",SCRIPT)
 def test_strict_one_time_ci_and_token_permissions(self):
  for s in ("windows-private-r848-v156-forward:","r848-hosted-156-to-157-once","actions: read","tests/r848_windows_private156_forward_native.ps1","windows-private-r846-native:"):
   self.assertIn(s,WF)
  self.assertIn("GH_TOKEN: "+chr(36)+"{{ github.token }}",WF)
if __name__=="__main__":
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(R848))
 raise SystemExit(0 if result.wasSuccessful() else 1)
