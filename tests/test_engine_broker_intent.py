"""R899 cross-platform exact policy/request/scope binding — NO privilege grant.

This is a fail-closed parser for FUTURE OS-protected native broker requests.
The test policy pin is synthetic, not evidence of real publisher approval.
"""
from __future__ import annotations

import json
import unittest

from installer_engine.broker_intent import (
    BROKER_STATUS, compare_pinned_policy_intent,
    compare_linux_fd_pinned_intent,
)
from installer_engine.engine import EngineError, PRODUCT, hash_bytes
from installer_engine.native_plan import NativePlan, windows_scoped_plan


def canonical(document):
    return (json.dumps(document, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def pin_manifest(manifest):
    return hash_bytes(canonical(manifest))


def fixture_manifest(scope, platform="linux-x86_64", release="1.5.7"):
    file = ("fixture-"+scope+"-"+release).encode()
    return {
        "schema": 1, "product": PRODUCT,
        "platform": platform, "version": release,
        "files": [{"path": "app/"+scope+".bin", "bytes": len(file),
                   "sha256": hash_bytes(file), "mode": 0o644}],
    }


def fixture_plan(platform="linux-x86_64", release="1.5.7"):
    return NativePlan(
        PRODUCT, release, platform,
        "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
        (("code", fixture_manifest("code", platform, release)),
         ("user", fixture_manifest("user", platform, release))),
    )


def fixture_contract(plan=None, action="upgrade"):
    plan = plan or fixture_plan()
    roles = {"code": "protected", "user": "user",
             "privileged": "protected"}
    rows = sorted(
        ({"name": name, "manifest_sha256": pin_manifest(doc)}
         for name, doc in plan.scopes), key=lambda r: r["name"])
    request = {"schema": 1, "product": PRODUCT, "platform": plan.platform,
               "version": plan.version, "operation": action,
               "request_id": "10" * 16, "scopes": rows}
    rb = canonical(request)
    policy = {"schema": 1, "product": PRODUCT, "platform": plan.platform,
              "version": plan.version, "operation": action,
              "request_sha256": hash_bytes(rb),
              "scopes": [dict(row, role=roles[row["name"]]) for row in rows]}
    pb = canonical(policy)
    return plan, policy, request, pb, rb


def evaluate(plan, policy, request):
    pb, rb = canonical(policy), canonical(request)
    return compare_pinned_policy_intent(plan, pb, hash_bytes(pb), rb)


class BrokerIntentNoPrivilegeTests(unittest.TestCase):
    def test_good_exact_scope_contract_cannot_authorize_privilege(self):
        plan, policy, request, pb, rb = fixture_contract()
        result = compare_pinned_policy_intent(
            plan, pb, hash_bytes(pb), rb)
        self.assertEqual(result["status"], BROKER_STATUS)
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["privileged_broker_implemented"])
        self.assertEqual(result["request_id"], "10" * 16)
        self.assertEqual(result["request_sha256"], hash_bytes(rb))

    def test_existing_windows_native_id64_preserved_across_policy_and_request(self):
        plan, policy, request, _, _ = fixture_contract(
            fixture_plan(platform="windows-x86_64"))
        request["request_id"] = "01ab" * 16
        rb = canonical(request)
        policy["request_sha256"] = hash_bytes(rb)
        pb = canonical(policy)
        result = compare_pinned_policy_intent(
            plan, pb, hash_bytes(pb), rb)
        self.assertEqual(result["request_id"], request["request_id"])
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])
        for wrong in ("01ab" * 15 + "01a", ("01ab" * 16).upper(),
                      "01ab" * 17, "01ab" * 8 + "-" + "01ab" * 8):
            request["request_id"] = wrong
            rb = canonical(request)
            policy["request_sha256"] = hash_bytes(rb)
            pb = canonical(policy)
            with self.subTest(wrong=wrong), self.assertRaisesRegex(
                    EngineError, "BROKER_REQUEST_ID_INVALID"):
                compare_pinned_policy_intent(
                    plan, pb, hash_bytes(pb), rb)

    def test_pinned_policy_tamper_is_rejected(self):
        plan, policy, request, pb, rb = fixture_contract()
        wrong = bytearray(pb)
        index = pb.find(b"upgrade")
        self.assertGreater(index, 0)
        wrong[index] = ord("i")
        with self.assertRaisesRegex(EngineError, "BROKER_PROTECTED_POLICY_PIN_MISMATCH"):
            compare_pinned_policy_intent(plan, bytes(wrong), hash_bytes(pb), rb)

    def test_request_byte_change_even_whitespace_is_refused(self):
        plan, policy, request, pb, rb = fixture_contract()
        with self.assertRaisesRegex(EngineError, "BROKER_REQUEST_BYTES_NOT_POLICY_PINNED"):
            compare_pinned_policy_intent(plan, pb, hash_bytes(pb), rb + b" ")

    def test_unsupported_arbitrary_execution_action_is_refused(self):
        plan, policy, request, pb, rb = fixture_contract(action="exec")
        with self.assertRaisesRegex(EngineError, "BROKER_POLICY_IDENTITY_INVALID"):
            compare_pinned_policy_intent(plan, pb, hash_bytes(pb), rb)

    def test_user_selected_root_path_is_refused_in_request(self):
        plan, policy, request, pb, rb = fixture_contract()
        request["root"] = "/tmp/foreign"
        policy["request_sha256"] = hash_bytes(canonical(request))
        with self.assertRaisesRegex(EngineError, "BROKER_REQUEST_SCHEMA"):
            evaluate(plan, policy, request)

    def test_untrusted_requested_command_field_is_refused(self):
        plan, policy, request, pb, rb = fixture_contract()
        request["command"] = "systemctl stop foreign.service"
        policy["request_sha256"] = hash_bytes(canonical(request))
        with self.assertRaisesRegex(EngineError, "BROKER_REQUEST_SCHEMA"):
            evaluate(plan, policy, request)

    def test_user_inserted_native_acceptance_is_refused(self):
        plan, policy, request, pb, rb = fixture_contract()
        request["native_installation_accepted"] = True
        policy["request_sha256"] = hash_bytes(canonical(request))
        with self.assertRaisesRegex(EngineError, "BROKER_REQUEST_SCHEMA"):
            evaluate(plan, policy, request)

    def test_scope_role_must_have_exactly_one_protected_and_one_user(self):
        plan, policy, request, pb, rb = fixture_contract()
        policy["scopes"][0]["role"] = "user"
        with self.assertRaisesRegex(EngineError, "BROKER_EXACT_ONE_PROTECTED_ONE_USER"):
            evaluate(plan, policy, request)

    def test_scope_hash_drift_between_plan_and_request_is_rejected(self):
        plan, policy, request, pb, rb = fixture_contract()
        request["scopes"][0]["manifest_sha256"] = "0" * 64
        policy["request_sha256"] = hash_bytes(canonical(request))
        with self.assertRaisesRegex(EngineError, "BROKER_POLICY_REQUEST_PLAN_SCOPE_PIN_DRIFT"):
            evaluate(plan, policy, request)

    def test_scope_hash_drift_between_plan_and_policy_is_rejected(self):
        plan, policy, request, pb, rb = fixture_contract()
        policy["scopes"][0]["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(EngineError, "BROKER_POLICY_REQUEST_PLAN_SCOPE_PIN_DRIFT"):
            evaluate(plan, policy, request)

    def test_cross_platform_or_version_mismatch_is_rejected(self):
        plan, policy, request, pb, rb = fixture_contract()
        for key, value in (("platform", "windows-x86_64"),
                           ("version", "1.5.6")):
            with self.subTest(key=key):
                updated = dict(request, **{key:value})
                changed = dict(policy, **{key:value},
                               request_sha256=hash_bytes(canonical(updated)))
                with self.assertRaisesRegex(EngineError, "BROKER_PLAN_POLICY_IDENTITY_DRIFT"):
                    evaluate(plan, changed, updated)

    def test_missing_or_out_of_band_policy_pin_rejected(self):
        plan, policy, request, pb, rb = fixture_contract()
        with self.assertRaisesRegex(EngineError, "BROKER_OUT_OF_BAND_POLICY_SHA_REQUIRED"):
            compare_pinned_policy_intent(plan, pb, None, rb)
        with self.assertRaisesRegex(EngineError, "BROKER_PROTECTED_POLICY_PIN_MISMATCH"):
            compare_pinned_policy_intent(plan, pb, "0"*64, rb)

    def test_duplicate_json_keys_refused(self):
        plan, policy, request, pb, rb = fixture_contract()
        wrong = pb.replace(b'"schema":1',b'"schema":1,"schema":1',1)
        with self.assertRaisesRegex(EngineError, "BROKER_DUPLICATE_JSON_KEY"):
            compare_pinned_policy_intent(plan, wrong, hash_bytes(wrong), rb)

    def test_policy_bytes_bounded_before_hash(self):
        plan, policy, request, pb, rb = fixture_contract()
        invalid = b"a" * 65537
        with self.assertRaisesRegex(EngineError, "BROKER_POLICY_BYTES_INVALID"):
            compare_pinned_policy_intent(plan, invalid, hash_bytes(invalid), rb)

    def test_reject_one_scope_distribution_plan(self):
        plan = NativePlan(
            PRODUCT,"1.5.7","linux-x86_64",
            "DISTRIBUTION_SOURCE_NOT_NATIVE_INSTALLED_ROOTS",
            (("distribution", fixture_manifest("dist")),))
        policy = {"schema":1}
        with self.assertRaisesRegex(EngineError,"BROKER_PLAN_UNTRUSTED_SOURCE_KIND"):
            # A well-formed request/policy is necessary to reach _plan_pins,
            # so derive a valid two-scope envelope from a separate fixture.
            good, envelope, req, pb, rb = fixture_contract()
            compare_pinned_policy_intent(plan, pb, hash_bytes(pb), rb)

    def test_reject_unsorted_scope_names(self):
        plan, policy, request, pb, rb = fixture_contract()
        request["scopes"].reverse()
        policy["request_sha256"] = hash_bytes(canonical(request))
        with self.assertRaisesRegex(EngineError,"BROKER_SCOPE_SORT_DUPLICATE_INVALID"):
            evaluate(plan, policy, request)

    def test_linux_fd_bridge_refuses_fake_client_object(self):
        plan, policy, request, pb, rb = fixture_contract()
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_LINUX_ROOT_HANDLE_REQUIRED"):
            compare_linux_fd_pinned_intent(
                plan, object(), "policy.json",
                hash_bytes(pb), len(pb), rb)

    def test_policy_cannot_add_anarbitrary_installed_root_path(self):
        plan, policy, request, pb, rb = fixture_contract()
        policy["root"] = "/tmp/untrusted-root"
        with self.assertRaisesRegex(EngineError, "BROKER_POLICY_SCHEMA"):
            evaluate(plan, policy, request)

    def test_request_cannot_choose_privilege_role(self):
        plan, policy, request, pb, rb = fixture_contract()
        request["scopes"][0]["role"] = "protected"
        policy["request_sha256"] = hash_bytes(canonical(request))
        with self.assertRaisesRegex(EngineError, "BROKER_SCOPE_KEYS_INVALID"):
            evaluate(plan, policy, request)

    def test_plan_cannot_claim_prior_native_authority(self):
        plan, policy, request, pb, rb = fixture_contract()
        from dataclasses import replace
        invalid = replace(plan, native_adapter_accepted=True)
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_PLAN_UNTRUSTED_SOURCE_KIND"):
            evaluate(invalid, policy, request)

    def test_request_size_guard_refuses_oversized_payload(self):
        plan, policy, request, pb, rb = fixture_contract()
        oversize = b" " * 65537
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_REQUEST_BYTES_INVALID"):
            compare_pinned_policy_intent(
                plan,pb,hash_bytes(pb),oversize)

    def test_windows_source_plan_user_then_privileged_can_be_normalized(self):
        user=b"owned-user"
        protected=b"owned-protected"
        source = {"schema":2,"product":PRODUCT,"version":"1.5.7","files":[
            {"scope":"user","file":"app/user.bin","source":"src/user.bin",
             "bytes":len(user),"sha256":hash_bytes(user)},
            {"scope":"privileged","file":"app/protected.bin","source":"src/protected.bin",
             "bytes":len(protected),"sha256":hash_bytes(protected)},
        ]}
        plan = windows_scoped_plan(source)
        self.assertEqual(tuple(name for name,_ in plan.scopes),
                         ("user","privileged"))
        _, policy, request, pb, rb = fixture_contract(plan)
        result = compare_pinned_policy_intent(plan,pb,hash_bytes(pb),rb)
        self.assertEqual(result["status"],BROKER_STATUS)
        self.assertFalse(result["native_installation_accepted"])


    @staticmethod
    def native_for_request(request, *, old="1.5.6", new="1.5.7"):
        return {"schema": 1, "request_id": request["request_id"],
                "platform": request["platform"], "operation": request["operation"],
                "old": old, "new": new,
                "preimage_sha256": hash_bytes(b"synthetic-old-native-registration"),
                "scope_pins": request["scopes"]}

    def test_native_transaction_identity_binds_broker_request_and_digest(self):
        from installer_engine.broker_intent import compare_native_transaction_policy_intent
        from installer_engine.native_receipt import intent_sha256
        plan, policy, request, pb, rb = fixture_contract()
        native = self.native_for_request(request)
        result = compare_native_transaction_policy_intent(
            plan, pb, hash_bytes(pb), rb, native)
        self.assertEqual(result["native_intent_sha256"], intent_sha256(native))
        self.assertFalse(result["native_installation_accepted"])

    def test_same_files_new_request_id_does_not_authorize_stale_native_transaction(self):
        from installer_engine.broker_intent import compare_native_transaction_policy_intent
        plan, policy, request, pb, rb = fixture_contract()
        native = self.native_for_request(request)
        request["request_id"] = "11" * 16
        request_bytes = canonical(request)
        policy["request_sha256"] = hash_bytes(request_bytes)
        policy_bytes = canonical(policy)
        with self.assertRaisesRegex(EngineError, "BROKER_NATIVE_REQUEST_ID_DRIFT"):
            compare_native_transaction_policy_intent(
                plan, policy_bytes, hash_bytes(policy_bytes), request_bytes, native)

    def test_native_scope_pin_and_transition_drift_denied(self):
        from installer_engine.broker_intent import compare_native_transaction_policy_intent
        plan, policy, request, pb, rb = fixture_contract()
        native = self.native_for_request(request)
        changed = dict(native, scope_pins=[
            dict(row) for row in native["scope_pins"]])
        changed["scope_pins"][0]["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(EngineError, "BROKER_NATIVE_SCOPE_PIN_DRIFT"):
            compare_native_transaction_policy_intent(
                plan, pb, hash_bytes(pb), rb, changed)
        wrong_transition = self.native_for_request(request, old=None)
        wrong_transition["operation"] = "install"
        with self.assertRaisesRegex(EngineError, "BROKER_NATIVE_TRANSITION_DRIFT"):
            compare_native_transaction_policy_intent(
                plan, pb, hash_bytes(pb), rb, wrong_transition)

    def test_native_uninstall_requires_matching_old_release_and_request(self):
        from installer_engine.broker_intent import compare_native_transaction_policy_intent
        plan, policy, request, pb, rb = fixture_contract(action="uninstall")
        native = self.native_for_request(request, old="1.5.7", new=None)
        result = compare_native_transaction_policy_intent(
            plan, pb, hash_bytes(pb), rb, native)
        self.assertEqual(result["operation"], "uninstall")
        altered = dict(native, old="1.5.6")
        with self.assertRaisesRegex(EngineError, "BROKER_NATIVE_RELEASE_DRIFT"):
            compare_native_transaction_policy_intent(
                plan, pb, hash_bytes(pb), rb, altered)


class NativeWindowsScmId64SourceParity(unittest.TestCase):
    """No native OS authorization: compare shared broker ID with SCM source."""

    def test_existing_scm_fixture_can_receive_full_inno_id64(self):
        from pathlib import Path
        path = (Path(__file__).resolve().parents[1] /
                "tools/native_fixtures/windows/R937NativeScmReceiptFixture.cs")
        source = path.read_text(encoding="utf-8")
        self.assertIn("private static bool ValidBrokerRequestId(", source)
        self.assertIn("ValidBrokerRequestId(id)", source)
        self.assertIn("ids.All(ValidBrokerRequestId)", source)
        self.assertIn('args[0]=="--validate-id"', source)
        self.assertNotIn("id.Length==32", source)
        self.assertNotIn("ids.All(x=>x.Length==32)", source)

    def test_scm_fixture_source_identity_keeps_exact_256_bit_request(self):
        from tools.native_fixtures.windows.BuildR937ScmReceiptInputs import (
            pinned_native_id64_contract,
        )
        from installer_engine.broker_intent import (
            compare_native_transaction_policy_intent,
        )
        from installer_engine.native_receipt import validate_intent
        from installer_engine.broker_replay import parse_replay_snapshot
        plan, policy, request, pb, rb = pinned_native_id64_contract()
        self.assertEqual(request["request_id"], "0123456789abcdef" * 4)
        self.assertEqual(len(request["request_id"]), 64)
        self.assertEqual(policy["request_sha256"], hash_bytes(rb))
        native = {
            "schema": 1, "request_id": request["request_id"],
            "platform": "windows-x86_64", "operation": "upgrade",
            "old": "1.5.6", "new": "1.5.7",
            "preimage_sha256": hash_bytes(b"R937_SYNTHETIC_PREIMAGE_156"),
            "scope_pins": request["scopes"],
        }
        validate_intent(native)
        matched = compare_native_transaction_policy_intent(
            plan, pb, hash_bytes(pb), rb, native)
        self.assertEqual(matched["request_id"], request["request_id"])
        self.assertFalse(matched["native_installation_accepted"])
        self.assertFalse(matched["publisher_authenticated"])
        ledger = canonical({
            "schema": 1, "platform": "windows-x86_64",
            "used_request_ids": [request["request_id"]],
            "active": None,
        })
        self.assertEqual(parse_replay_snapshot(ledger, "windows-x86_64")
                         ["used_request_ids"], [request["request_id"]])
        for malformed in (
            "0" * 31, "0" * 33, "0" * 63, "0" * 65,
            ("0123456789abcdef" * 4).upper(),
            "0123456789abcdef" * 2 + "-" + "0123456789abcdef" * 2,
        ):
            candidate = dict(request, request_id=malformed)
            request_bytes = canonical(candidate)
            candidate_policy = dict(policy, request_sha256=hash_bytes(request_bytes))
            with self.subTest(malformed=malformed), self.assertRaisesRegex(
                    EngineError, "BROKER_REQUEST_ID_INVALID"):
                compare_pinned_policy_intent(
                    plan, canonical(candidate_policy),
                    hash_bytes(canonical(candidate_policy)), request_bytes)

if __name__ == "__main__":
    unittest.main()
