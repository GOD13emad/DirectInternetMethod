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
EXPECTED={"version":VERSION,"files":28,"sha256":"4B4A76C02873982DE817380A4A23AAF399EC7B3AE9756CA12D39F1499EE86E2C"}
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
           "app/direct_method_helper.sh","app/user_update_transaction.py",
           "system/upgrade_guard.py"}.issubset(included))
    def test_r519b_uninstaller_accepts_only_new_ownership_version(self):
        rel="app/user_uninstall_preserve.py"
        got=self.info.read(self.prefix+rel)
        declared=next(row for row in self.rows if row["file"]==rel)
        self.assertEqual(digest(got),declared["sha256"])
        self.assertEqual(declared["sha256"],"06825BCD25B237625DBC4FF60250763C38A27238A6273E0C97E847EAD385E64F")
        self.assertIn('"socket_fallback.py"', got.decode())
        self.assertIn('doc.get("version") == "1.5.5-rc1"',got.decode())
        self.assertNotIn('doc.get("version") == "1.5.4"',got.decode())
        self.assertEqual(digest((R/"linux/app/user_uninstall_preserve.py").read_bytes()),declared["sha256"])
    def test_original_unreleased_candidate_preserved_and_current_source_delta(self):
        # CI does not commit an 8.3 MB obsolete candidate ZIP. Its original
        # manifest and changed single source member are pinned byte-for-byte
        # as compact historical fixtures (all 26 original file SHA entries).
        fixtures=R/"tests/fixtures/r519_original"
        old_manifest=fixtures/"PACKAGE_MANIFEST.json"
        old_source=fixtures/"user_uninstall_preserve.py"
        # Compare canonical historical LF bytes, not Git-for-Windows CRLF checkout.
        old_manifest_bytes=old_manifest.read_bytes().replace(b"\r\n",b"\n")
        self.assertEqual(digest(old_manifest_bytes),
                         "EA43CD77EAA2979AC970A8B47145881C767519E3D024BF907167A2FE3FD6C05E")
        self.assertEqual(digest(old_source.read_bytes()),
                         "9A4A4C37E3F63F1602E15454100150D209E3CD099DE80504B560F31D42D3C0EF")
        prev=json.loads(old_manifest_bytes)
        self.assertEqual((prev["schema"],prev["version"],prev["platform"]),(1,VERSION,"linux-x86_64"))
        before={row["file"]:row for row in prev["files"]}
        after={row["file"]:row for row in self.rows}
        self.assertEqual(set(after),set(before)|{"system/upgrade_guard.py","app/socket_fallback.py"})
        self.assertEqual(len(before),26)
        changed={name for name in before if before[name]!=after[name]}
        # Preserve the immutable historical manifest and explicitly recognize
        # the new R762 controller hardening in the current unreleased package.
        self.assertEqual(changed,{"app/user_uninstall_preserve.py","app/direct_internet_method.py",
                                 "app/direct_method_helper.sh","app/user_update_transaction.py","system/protected_upgrade_transaction.py",
                                 "system/upgrade_system.sh","install.sh","system/encrypted_selective_dns.py"})
        self.assertEqual(after["system/encrypted_selective_dns.py"]["sha256"],
                         "6E12A906D0B3AD6FD910303B55F89F76EB56C2EF1AABF15549806641285E461F")
        self.assertEqual(after["app/direct_internet_method.py"]["sha256"],
                         "6CF031D2C7F18D7E7E4F1F9A37A1A0EBD3CA589F16F7E26274496F1F53E9317B")
        self.assertIn("encrypted=encrypted_dns_optin_state()",
                      self.info.read(self.prefix+"app/direct_internet_method.py").decode())
        self.assertIn('s.get("selectiveDnsEncrypted")',
                      self.info.read(self.prefix+"app/direct_internet_method.py").decode())
        self.assertIn('PHYSICAL_INTERFACE_ROUTE_DRIFT',
                      self.info.read(self.prefix+"app/direct_method_helper.sh").decode())
        self.assertIn('PHYSICAL_INTERFACE_ROUTE_DRIFT',
                      self.info.read(self.prefix+"app/direct_internet_method.py").decode())
        previous=before["app/user_uninstall_preserve.py"]
        self.assertEqual((previous["bytes"],previous["sha256"]),
                         (len(old_source.read_bytes()),digest(old_source.read_bytes())))
        self.assertNotEqual(previous["sha256"],after["app/user_uninstall_preserve.py"]["sha256"])
        # If the old full binary happens to be available locally, verify the
        # exact historical archive as additional provenance, not a CI prerequisite.
        old=R/"evidence/R519_ORIGINAL_RC1_SUPERSEDED.zip"
        if old.exists():
            self.assertEqual(digest(old.read_bytes()),
                             "47776640A1BB8B5D4490244565DDD47A6A817A999347566917CC73E21F41EC24")
            with zipfile.ZipFile(old) as z:
                self.assertEqual(set(self.n),set(z.namelist())|{self.prefix+"system/upgrade_guard.py",self.prefix+"app/socket_fallback.py"})
                self.assertEqual(z.read(self.prefix+"PACKAGE_MANIFEST.json"),old_manifest_bytes)
                self.assertEqual(z.read(self.prefix+"app/user_uninstall_preserve.py"),old_source.read_bytes())
                self.assertEqual(z.testzip(),None)
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
        self.assertIn("R553_ROOT_GUARD_ACTIVE_PRESTAGE_VERIFIED",src)
        self.assertIn("GUARD_SHA=",src)
        self.assertLess(src.index("R553_ROOT_GUARD_ACTIVE_PRESTAGE_VERIFIED"),
                        src.index('python3 "$SRC/system/protected_upgrade_transaction.py" stage'))
        self.assertIn('python3 "$SRC/system/protected_upgrade_transaction.py" stage',src)
        self.assertIn('python3 "$SRC/system/protected_upgrade_transaction.py" apply',src)
        self.assertNotIn(' commit',src)
    def test_guard_and_hosted_root_zip_inventory_track_live_manifest(self):
        # R748 negative-first: source/unit guards must accept the same exact
        # archive member count as the deterministic current ZIP (no bypass).
        guard=(R/"linux/system/upgrade_guard.py").read_text(encoding="utf8")
        wrapper=(R/"linux/system/upgrade_system.sh").read_text(encoding="utf8")
        native=(R/"tests/r528_ephemeral_native_root_cli_contract.py").read_text(encoding="utf8")
        expected=EXPECTED["files"]
        self.assertIn(f"len(files)=={expected}",guard)
        self.assertIn(f"archive_verify(z,CANDIDATE_PREFIX,{expected+2})",native)
        self.assertIn(f'len(manifest.get("files",[]))=={expected}',native)
        self.assertIn('GUARD_SHA="'+digest(guard.encode("utf8"))+'"',wrapper)
        # The independent guard and system wrapper MUST agree with the
        # installed user transaction, including future managed-file changes.
        user_sha=digest(USER_TXN.read_bytes())
        self.assertIn('PIN_USER="'+user_sha+'"',guard)
        self.assertIn('assert sha(guard/"user_tx.py")=="'+user_sha+'"',wrapper)
        # Immutable original public Stable stays deliberately at 24 ZIP
        # entries; only the unpublished RC1's inventory is extended.
        self.assertIn('archive_verify(z,STABLE_PREFIX,24)',native)

    def test_hosted_root_watchdog_user_sha_matches_current_candidate(self):
        # R748: adding/removing a managed user module changes this source
        # without changing Root. Both sides of the independent watchdog and
        # the hosted guard tests must follow the exact current user hash.
        expected=digest(USER_TXN.read_bytes())
        for filename,variable in (
            ("tests/r532_ephemeral_root_watchdog_contract.py","USER_SHA"),
            ("tests/r532_root_watchdog_worker.py","PIN_USER"),
            ("tests/r554_native_guard_ephemeral_contract.py","PIN_USER"),
        ):
            text=(R/filename).read_text(encoding="utf8")
            matches=re.findall(
                rf'(?m)^\s*{variable}\s*=\s*["\x27]([a-fA-F0-9]{{64}})["\x27]',
                text,
            )
            self.assertEqual(len(matches),1,filename)
            self.assertEqual(matches[0].upper(),expected,filename)

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
        self.assertIn('len(package_doc["files"]) == 28',updater)
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
