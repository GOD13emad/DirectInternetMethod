"""R944: bind actual 21-file Linux two-scope package to R899 broker intent.

Read-only policy/intent fixture; NO root/systemd/polkit installation, real
publisher trust, or native completed receipt. Test-generated policy hash is
never an OS trust anchor.
"""
import json
import unittest

from installer_engine.broker_intent import compare_pinned_policy_intent
from installer_engine.engine import EngineError, PRODUCT, hash_bytes
from installer_engine.native_plan import NativePlan
from tests.test_engine_broker_intent import canonical, fixture_contract
from tests import test_engine_real_linux_two_scope as real_linux


class RealLinuxBrokerBinding(unittest.TestCase):
    def setUp(self):
        self.fixture = real_linux.RealLinuxTwoScopeIntegration(
            "test_real_privileged_binary_tamper_denied_before_any_scope_mutation")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_actual_21_file_manifest_pins_match_common_transaction_and_broker(self):
        bundles = self.fixture._build("1.5.7")
        manifests = {
            name: json.loads((directory / "manifest.json").read_text("utf-8"))
            for name, (directory, _) in bundles.items()
        }
        self.assertEqual({name: len(doc["files"]) for name, doc in
                          manifests.items()}, {"privileged": 13, "user": 8})
        plan = NativePlan(PRODUCT, "1.5.7", "linux-x86_64",
                          "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
                          tuple((name, manifests[name]) for name in
                                ("privileged", "user")))
        _, policy, request, pb, rb = fixture_contract(plan)
        accepted = compare_pinned_policy_intent(plan, pb, hash_bytes(pb), rb)
        self.assertFalse(accepted["native_installation_accepted"])
        self.assertFalse(accepted["publisher_authenticated"])
        expected = {name: pin for name, (_, pin) in bundles.items()}
        self.assertEqual({row["name"]: row["manifest_sha256"]
                          for row in request["scopes"]}, expected)

        # Same exact pinned package enters the OS-neutral live journal.
        self.fixture.engine.begin(bundles)
        journal = self.fixture.engine._load()
        self.assertEqual({row["name"]: row["manifest_sha256"]
                          for row in journal["scope_pins"]}, expected)
        self.assertEqual(journal["new"], "1.5.7")

        # A forged request can be self-consistent with a client-recomputed
        # policy hash, but cannot match the actual pinned 21-file plan.
        request["scopes"][0]["manifest_sha256"] = "0" * 64
        policy["scopes"][0]["manifest_sha256"] = "0" * 64
        policy["request_sha256"] = hash_bytes(canonical(request))
        forged_policy, forged_request = canonical(policy), canonical(request)
        with self.assertRaisesRegex(
                EngineError, "BROKER_POLICY_REQUEST_PLAN_SCOPE_PIN_DRIFT"):
            compare_pinned_policy_intent(
                plan, forged_policy, hash_bytes(forged_policy), forged_request)
        self.assertFalse(self.fixture.adapter.receipt.exists())


if __name__ == "__main__":
    unittest.main()
