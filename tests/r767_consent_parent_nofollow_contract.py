#!/usr/bin/env python3
"""Isolated negative-first consent-parent symlink path contract, no root/network."""
from pathlib import Path
import importlib.util
import os
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location("r767_dns_controller",ROOT/"linux/system/encrypted_selective_dns.py")
m=importlib.util.module_from_spec(s)
s.loader.exec_module(m)

class ConsentPath(unittest.TestCase):
 def test_user_home_private_consent_cannot_be_redirected_via_dotlocal_symlink(self):
  with tempfile.TemporaryDirectory(prefix="r767-parent-",dir=str(ROOT)) as temp:
   p=Path(temp);home=p/"fake-home";home.mkdir()
   ext=p/"user-external-local";app=ext/"share/DirectInternetMethod"
   app.mkdir(parents=True)
   (home/".local").symlink_to(ext,target_is_directory=True)
   (app/m.NEW_OPTIN).write_text(m.CONSENT+"\n")
   (app/m.NEW_OPTIN).chmod(0o600)
   (app/"scope.txt").write_text("targeted\n")
   (app/"strategy.txt").write_text("balanced\n")
   self.assertTrue((home/".local").is_symlink())
   self.assertFalse((home/".local/share/DirectInternetMethod"/m.NEW_OPTIN).is_symlink())
   with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_CONSENT_PARENT_COMPONENT"):
    m.require_consent(os.getuid(),str(home))
if __name__=="__main__":
 unittest.main(verbosity=2)
