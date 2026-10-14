#!/usr/bin/env python3
"""R519 negative-first immutable package, source manifest and version contracts.

No installed writes: all mutations are confined to a temporary extracted ZIP
directory and compared to its original exact-SHA baseline.
"""
from __future__ import annotations
import ast,hashlib,importlib.util,json,pathlib,re,tempfile,unittest,zipfile
R=pathlib.Path(__file__).resolve().parents[1]
VERSION="1.5.5-rc1"
PACKAGE=R/"delivery"/f"DirectInternetMethod_{VERSION}_Linux_x86_64.zip"
GUI=R/"linux/app/direct_internet_method.py"
HELPER=R/"linux/app/direct_method_helper.sh"
ROOT_TXN=R/"linux/system/protected_upgrade_transaction.py"
INSTALLER=R/"linux/install.sh"
USER_TXN=R/"linux/app/user_update_transaction.py"
PKG_DOC=R/"docs/README_PACKAGE_155_RC1.md"
EXPECTED={"version":VERSION,"files":26,"sha256":"45A29A65B3E34302AD8E0745324EC2A1C418BB43669F9B95B15963B02CDFCC49"}
def digest(data):return hashlib.sha256(data).hexdigest().upper()
class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert PACKAGE.is_file()
        cls.info=zipfile.ZipFile(PACKAGE)
        cls.n=cls.info.namelist()
        cls.prefix=f"DirectInternetMethod_{VERSION}_Linux_x86_64/"
        cls.rows=json.loads(cls.info.read(cls.prefix+"PACKAGE_MANIFEST.json"))["files"]
    @classmethod
    def tearDownClass(cls):cls.info.close()
    def test_exact_zip_sha(self):
        self.assertEqual(digest(PACKAGE.read_bytes()),EXPECTED["sha256"])
    def test_exact_manifest_version_and_members(self):
        manifest=json.loads(self.info.read(self.prefix+"PACKAGE_MANIFEST.json"))
        self.assertEqual((manifest["schema"],manifest["version"],manifest["platform"]),(1,VERSION,"linux-x86_64"))
        self.assertEqual(len(manifest["files"]),EXPECTED["files"])
        self.assertEqual(len(self.n),EXPECTED["files"]+2)
        self.assertEqual(len(self.n),len(set(self.n)))
        self.assertEqual(set(self.n),{self.prefix+r["file"] for r in self.rows}|{
            self.prefix+"PACKAGE_MANIFEST.json",self.prefix+"SHA256SUMS.txt"})
        self.assertIsNone(self.info.testzip())
    def test_source_members_all_match_manifest(self):
        hashes=set()
        for item in self.rows:
            path=item["file"]
            self.assertFalse(pathlib.PurePosixPath(path).is_absolute())
            self.assertNotIn("..",pathlib.PurePosixPath(path).parts)
            data=self.info.read(self.prefix+path)
            self.assertEqual((len(data),digest(data)),(item["bytes"],item["sha256"]))
            self.assertNotIn(path,hashes)
            hashes.add(path)
        sums="".join(f'{r["sha256"]}  {r["file"]}\n' for r in self.rows)
        self.assertEqual(self.info.read(self.prefix+"SHA256SUMS.txt").decode(),sums)
    def test_versioned_components_present(self):
        included={r["file"] for r in self.rows}
        self.assertTrue({"system/encrypted_selective_dns.py","system/encrypted_selective_policy.py",
           "system/protected_upgrade_transaction.py","system/upgrade_system.sh",
           "app/direct_method_helper.sh","app/user_update_transaction.py"}.issubset(included))
    def test_r519b_uninstaller_accepts_only_new_ownership_version(self):
        rel="app/user_uninstall_preserve.py"
        got=self.info.read(self.prefix+rel)
        declared=next(row for row in self.rows if row["file"]==rel)
        self.assertEqual(digest(got),declared["sha256"])
        self.assertEqual(declared["sha256"],"6691AA7262307F41DDAD1B5EB409E1C7AAC3B2171B5285156045849D969F6B8A")
        self.assertIn('doc.get("version") == "1.5.5-rc1"',got.decode())
        self.assertNotIn('doc.get("version") == "1.5.4"',got.decode())
        self.assertEqual(digest((R/"linux/app/user_uninstall_preserve.py").read_bytes()),declared["sha256"])
    def test_original_unreleased_candidate_preserved_and_only_uninstaller_delta(self):
        old=R/"evidence/R519_ORIGINAL_RC1_SUPERSEDED.zip"
        self.assertTrue(old.is_file())
        self.assertEqual(digest(old.read_bytes()),"47776640A1BB8B5D4490244565DDD47A6A817A999347566917CC73E21F41EC24")
        with zipfile.ZipFile(old) as before:
            self.assertEqual(set(before.namelist()),set(self.n))
            changed={n for n in self.n if before.read(n)!=self.info.read(n)}
            expected={self.prefix+"app/user_uninstall_preserve.py",
                      self.prefix+"PACKAGE_MANIFEST.json",self.prefix+"SHA256SUMS.txt"}
            self.assertEqual(changed,expected)
    def test_original_published_metadata_untouched(self):
        data=json.loads((R/"RELEASE.json").read_text())
        self.assertEqual(data["version"],"1.5.4")
        self.assertFalse(any("1.5.5-rc1" in x["file"] for x in self.rows))
    def test_fresh_root_contract_version(self):
        root=(R/"linux/system/install_system.sh").read_text()
        self.assertIn('{"schema":1,"version":"1.5.5-rc1"',root)
        self.assertIn('encrypted_selective_dns.py',root)
        self.assertIn('encrypted_selective_policy.py',root)
    def test_protected_upgrade_exact_sha(self):
        text=ROOT_TXN.read_text()
        self.assertIn('TARGET_VERSION="1.5.5-rc1"',text)
        self.assertIn('CURRENT_BACKEND_VERSION="1.5.2"',text)
        self.assertIn('data.get("revision")=="R519"',text)
        self.assertIn('receipt.get("revision")=="R519"',text)
        self.assertIn("NATIVE_ACCEPTANCE_NOT_PROVEN",text)
        self.assertIn("one slot",text.lower())
    def test_root_wrapper_pinned_identity(self):
        src=(R/"linux/system/upgrade_system.sh").read_text()
        self.assertIn(digest(ROOT_TXN.read_bytes()),src)
        self.assertIn('DirectInternetMethod_1.5.5-rc1_Linux_x86_64',src)
        self.assertIn('python3 "$SRC/system/protected_upgrade_transaction.py" stage',src)
        self.assertIn('python3 "$SRC/system/protected_upgrade_transaction.py" apply',src)
        self.assertNotIn(' commit',src)
    def test_user_installer_never_pretends_committed(self):
        src=INSTALLER.read_text()
        self.assertIn("ROOT_UPGRADE_STAGED=1",src)
        self.assertIn('R519_CANDIDATE_PENDING_NATIVE_ROOT_USER_COMMIT',src)
        self.assertIn('pkexec /bin/bash "$HERE/system/upgrade_system.sh"',src)
        self.assertIn('python3 "$USER_TRANSACTION" --rollback',src)
    def test_gui_and_user_metadata_pins(self):
        app=GUI.read_text()
        self.assertIn('VERSION="1.5.5-rc1"',app)
        self.assertIn('COEXIST_HELPER_SHA256="'+digest(HELPER.read_bytes()).lower()+'"',app)
        self.assertIn('installed.get("version") == "1.5.5-rc1"',app)
        updater=USER_TXN.read_text()
        self.assertIn('len(package_doc["files"]) == 26',updater)
        self.assertIn('data.get("version") == "1.5.5-rc1"',updater)
        self.assertIn('"encrypted-dns-optin.txt"',updater)
    def test_rc_semver_prevents_implicit_downgrade(self):
        code=ast.parse(GUI.read_text())
        node=next(x for x in code.body if isinstance(x,ast.FunctionDef) and x.name=='_version_tuple')
        ns={"re":re}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(GUI),"exec"),ns)
        v=ns["_version_tuple"]
        self.assertLess(v("1.5.4"),v("1.5.5-rc1"))
        self.assertLess(v("1.5.5-rc1"),v("1.5.5"))
        self.assertLess(v("1.5.5-rc1"),v("1.5.5-rc2"))
    def test_archive_manifest_negative_corrupted_payload(self):
        with tempfile.TemporaryDirectory(prefix="R519_OFFLINE_TEST_") as temp:
            target=pathlib.Path(temp)/f"DirectInternetMethod_{VERSION}_Linux_x86_64"
            self.info.extractall(temp)
            payload=target/"app/direct_internet_method.py"
            payload.write_bytes(payload.read_bytes()+b"\n# tampered\n")
            spec=importlib.util.spec_from_file_location("r519_user_txn",USER_TXN)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            with self.assertRaisesRegex((RuntimeError,AssertionError),".*"):
                module.source_files(target)
    def test_readme_is_explicitly_unreleased(self):
        s=PKG_DOC.read_text()
        self.assertIn("NOT RELEASED",s)
        self.assertIn("1.5.5-rc1",s)
        self.assertIn("v1.5.4",s)
if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    print("R519_COHERENCE_NEGATIVE_FIRST",result.testsRun,"cases", "PASS" if result.wasSuccessful() else "FAIL")
    raise SystemExit(0 if result.wasSuccessful() else 1)
