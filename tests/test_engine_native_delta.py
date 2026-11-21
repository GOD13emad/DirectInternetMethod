"""R904 read-only portable product-managed-code baseline-to-target delta.

Real 1.5.7 source bytes are used; 1.5.6 prior hashes in these unit tests
are synthetic. Separate read-only host observations prove actual 1.5.6
baseline identities; these tests NEVER modify a host installation.
"""
from __future__ import annotations
import ast
import copy
import hashlib
import json
from pathlib import Path
import unittest

from installer_engine.engine import EngineError
from installer_engine.scoped_layout import compile_scoped_layout
from installer_engine.native_delta import compare_managed_code_delta, STATUS
from tests.test_engine_scoped_layout import _current_source_manifest, ROOT


class NativeCodeDeltaContracts(unittest.TestCase):
    def setUp(self):
        self.layout_path=ROOT/"linux"/"native_layout.json"
        self.source=_current_source_manifest()
        self.raw=self.layout_path.read_bytes()
        self.plan=compile_scoped_layout(
            self.source,self.raw,hashlib.sha256(self.raw).hexdigest())
        self.assertEqual([name for name,_ in self.plan.scopes],
                         ["privileged","user"])
        # Original 1.5.6 managed identities are simulated here: 13 root
        # unchanged, four user changed, four user unchanged.
        rows=[]
        for name,manifest in self.plan.scopes:
            old=[]
            for file in manifest["files"]:
                copy_row=copy.deepcopy(file)
                if name=="user" and file["path"] in (
                    "direct_internet_method.py","socket_fallback.py",
                    "user_uninstall_preserve.py","user_update_transaction.py"):
                    copy_row["sha256"]=hashlib.sha256(
                        ("SYNTHETIC_156_"+file["path"]).encode()).hexdigest()
                old.append(copy_row)
            rows.append({"name":name,"files":old})
        self.before={"schema":1,"product":"Direct Internet Method",
                     "platform":"linux-x86_64","version":"1.5.6",
                     "scopes":rows}
        self.observed=copy.deepcopy(self.before)

    def evaluate(self):
        return compare_managed_code_delta(
            self.plan,self.before,self.observed)

    def test_real_product_21_scope_source_code_has_only_four_replacements(self):
        result=self.evaluate()
        self.assertEqual(result["status"],STATUS)
        self.assertEqual(result["stats"],{
            "unchanged":17,"replace":4,"create":0})
        self.assertEqual(
            {r["path"] for r in result["scopes"]["user"] if
             r["action"]=="replace"},
            {"direct_internet_method.py","socket_fallback.py",
             "user_uninstall_preserve.py","user_update_transaction.py"})
        self.assertEqual(len(result["scopes"]["privileged"]),13)
        self.assertTrue(all(r["action"]=="unchanged"
                            for r in result["scopes"]["privileged"]))
        self.assertEqual(len(result["scopes"]["user"]),8)
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["privileged_broker_implemented"])
        self.assertFalse(result["protected_write_performed"])

    def test_user_scope_drift_refused_without_mutation(self):
        self.observed["scopes"][1]["files"][0]["sha256"]="0"*64
        with self.assertRaisesRegex(EngineError,"DELTA_INSTALLED_MANAGED_CODE_DRIFT"):
            self.evaluate()

    def test_root_scope_drift_refused_without_mutation(self):
        self.observed["scopes"][0]["files"][1]["bytes"]+=1
        with self.assertRaisesRegex(EngineError,"DELTA_INSTALLED_MANAGED_CODE_DRIFT"):
            self.evaluate()

    def test_expected_previous_and_observed_must_match_exact_file_set(self):
        self.observed["scopes"][0]["files"].pop()
        with self.assertRaisesRegex(EngineError,"DELTA_PRIOR_CURRENT_CODE_PATH_DRIFT"):
            self.evaluate()

    def test_previous_unmapped_code_cannot_be_silently_retired(self):
        candidate={"path":"unlisted.bin","sha256":"a"*64,
                   "bytes":1,"mode":0o644}
        self.before["scopes"][1]["files"].append(candidate)
        self.observed["scopes"][1]["files"].append(copy.deepcopy(candidate))
        with self.assertRaisesRegex(
                EngineError,"DELTA_PREVIOUS_MANAGED_CODE_RETIRE_REQUIRES_NATIVE_REVIEW"):
            self.evaluate()

    def test_no_old_code_path_can_be_silently_claimed_as_new(self):
        target=self.plan
        self.before["scopes"][1]["files"].pop()
        self.observed["scopes"][1]["files"].pop()
        result=self.evaluate()
        self.assertEqual(result["stats"]["create"],1)
        self.assertFalse(result["native_installation_accepted"])

    def test_older_release_required(self):
        self.before["version"]=self.plan.version
        self.observed["version"]=self.plan.version
        with self.assertRaisesRegex(EngineError,
                                    "DELTA_BASELINE_RELEASE_MISMATCH_OR_NOT_OLDER"):
            self.evaluate()

    def test_mismatched_declared_baseline_versions_refused(self):
        self.observed["version"]="1.5.5"
        with self.assertRaisesRegex(EngineError,
                                    "DELTA_BASELINE_RELEASE_MISMATCH_OR_NOT_OLDER"):
            self.evaluate()

    def test_inventory_must_match_platform(self):
        self.observed["platform"]="windows-x86_64"
        with self.assertRaisesRegex(EngineError,"DELTA_INVENTORY_SCHEMA_OR_IDENTITY"):
            self.evaluate()

    def test_inventory_scope_names_exact(self):
        self.before["scopes"][0]["name"]="malicious"
        with self.assertRaisesRegex(EngineError,"DELTA_SCOPE_IDENTITY_DRIFT"):
            self.evaluate()

    def test_double_mentioned_path_is_denied_casefolded(self):
        duplicate=copy.deepcopy(self.observed["scopes"][1]["files"][0])
        duplicate["path"]=duplicate["path"].upper()
        self.observed["scopes"][1]["files"].append(duplicate)
        with self.assertRaisesRegex(EngineError,"DELTA_CODE_PATH_DUPLICATE"):
            self.evaluate()

    def test_bool_or_wrong_size_refused(self):
        for bad in (True,-1,1<<31):
            with self.subTest(bad=bad):
                self.observed=copy.deepcopy(self.before)
                self.observed["scopes"][1]["files"][0]["bytes"]=bad
                with self.assertRaisesRegex(EngineError,"DELTA_CODE_BYTES_INVALID"):
                    self.evaluate()

    def test_invalid_managed_mode_refused(self):
        self.observed["scopes"][1]["files"][0]["mode"]=0o777
        with self.assertRaisesRegex(EngineError,"DELTA_CODE_MODE_INVALID"):
            self.evaluate()

    def test_attack_controlled_extra_field_refused(self):
        self.observed["scopes"][1]["files"][0]["command"]="systemctl stop foreign"
        with self.assertRaisesRegex(EngineError,"DELTA_CODE_FILE_SCHEMA"):
            self.evaluate()

    def test_no_user_settings_provider_or_untrusted_root_in_code_plan(self):
        paths={f["path"] for _,manifest in self.plan.scopes
               for f in manifest["files"]}
        self.assertNotIn("router_gateway/providers.json",paths)
        self.assertNotIn("settings.json",paths)
        self.assertNotIn("custom-hosts.txt",paths)
        self.assertNotIn("/usr/lib/directinternetmethod",paths)

    def test_existing_privileged_upgrade_writer_targets_match_real_13_code_plan(self):
        # The existing *real* root upgrade transaction is not replaced by
        # our source-only file-delta proposal. Prove its four potentially
        # mutable code files and nine static identity constraints map
        # EXACTLY to the common code scope with no unaccounted root member.
        path=ROOT/"linux/system/protected_upgrade_transaction.py"
        tree=ast.parse(path.read_text("utf-8"))
        declared={}
        for item in tree.body:
            if (isinstance(item,ast.Assign) and len(item.targets)==1 and
                    isinstance(item.targets[0],ast.Name) and
                    item.targets[0].id in ("FILES","STATIC_ROOT",
                                           "SUPPORTED_BASELINE_VERSIONS")):
                declared[item.targets[0].id]=ast.literal_eval(item.value)
        self.assertIn("1.5.6",declared["SUPPORTED_BASELINE_VERSIONS"])
        root={x["path"]:x for name,m in self.plan.scopes
              if name=="privileged" for x in m["files"]}
        changed={}
        for item in declared["FILES"]:
            name,source,destination,old,new,mode=item
            self.assertTrue(destination.startswith(
                "usr/lib/directinternetmethod/"))
            relative=destination.removeprefix(
                "usr/lib/directinternetmethod/")
            self.assertIn(relative,root)
            self.assertEqual(root[relative]["mode"],mode)
            self.assertEqual(root[relative]["sha256"].lower(),new.lower())
            # For installed baseline 1.5.6, the old-root pin is the new
            # digest, meaning the current code bytes are not a target drift.
            changed[relative]=new.lower()
        static={}
        for destination,sha in declared["STATIC_ROOT"].items():
            self.assertTrue(destination.startswith(
                "usr/lib/directinternetmethod/"))
            relative=destination.removeprefix(
                "usr/lib/directinternetmethod/")
            self.assertIn(relative,root)
            self.assertEqual(root[relative]["sha256"].lower(),sha.lower())
            static[relative]=sha.lower()
        self.assertEqual(len(changed),4)
        self.assertEqual(len(static),9)
        self.assertEqual(set(changed).intersection(static),set())
        self.assertEqual(set(changed).union(static),set(root))

    def test_existing_root_boot_guard_accepts_exact_156_pair_without_permissive_wildcard(self):
        path=ROOT/"linux/system/upgrade_guard.py"
        tree=ast.parse(path.read_text("utf-8"))
        pairs=None
        for item in tree.body:
            if (isinstance(item,ast.Assign) and len(item.targets)==1 and
                    isinstance(item.targets[0],ast.Name) and
                    item.targets[0].id=="ALLOWED_BASELINE_PAIRS"):
                pairs=ast.literal_eval(item.value)
        self.assertIsNotNone(pairs)
        self.assertIn(("1.5.6","1.5.6"),pairs)
        self.assertNotIn(("1.5.6","1.5.7"),pairs)
        self.assertNotIn(("1.5.7","1.5.6"),pairs)
        self.assertEqual(len(set(pairs)),len(pairs))

    def test_source_plan_accepts_no_native_authority(self):
        from dataclasses import replace
        altered=replace(self.plan,native_adapter_accepted=True)
        with self.assertRaisesRegex(EngineError,"DELTA_NATIVE_PLAN_UNTRUSTED"):
            compare_managed_code_delta(altered,self.before,self.observed)


if __name__=="__main__":
    unittest.main()
