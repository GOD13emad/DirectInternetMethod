"""R926 OS-independent receipt matching; never a native security signature."""
from __future__ import annotations

import json
import unittest

from installer_engine.engine import EngineError
from installer_engine.native_receipt import (
    intent_sha256, validate_intent, verify_completion_receipt,
    verify_restoration_receipt,
)


class UniversalNativeReceiptContract(unittest.TestCase):
    def setUp(self):
        self.intent = {
            "schema": 1, "request_id": "a" * 32,
            "platform": "linux-x86_64", "operation": "upgrade",
            "old": "1.5.6", "new": "1.5.7",
            "preimage_sha256": "b" * 64,
            "scope_pins": [
                {"name": "protected", "manifest_sha256": "c" * 64},
                {"name": "user", "manifest_sha256": "d" * 64},
            ],
        }

    def receipt(self):
        return json.dumps({
            "schema": 1, "status": "completed",
            "intent_sha256": intent_sha256(self.intent)
        }).encode("utf8")

    def test_exact_receipt_matches_full_identity(self):
        self.assertTrue(verify_completion_receipt(self.intent, self.receipt()))
        self.assertFalse(verify_completion_receipt(self.intent, None))

    def test_stale_or_cross_platform_receipt_refused(self):
        original = self.receipt()
        for name, value in (
            ("request_id", "e" * 32),
            ("platform", "windows-x86_64"),
            ("old", "1.5.5"),
            ("new", "1.5.8"),
            ("preimage_sha256", "f" * 64),
        ):
            with self.subTest(name=name):
                different = dict(self.intent, **{name: value})
                with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
                    verify_completion_receipt(different, original)

    def test_changed_manifest_for_either_scope_refused(self):
        valid = self.receipt()
        for ix in (0, 1):
            changed = json.loads(json.dumps(self.intent))
            changed["scope_pins"][ix]["manifest_sha256"] = "e" * 64
            with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
                verify_completion_receipt(changed, valid)

    def test_uninstall_receipt_cannot_authorize_upgrade(self):
        old = self.receipt()
        uninst = dict(self.intent, operation="uninstall", new=None)
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
            verify_completion_receipt(uninst, old)

    def test_duplicate_json_keys_refused_before_authorization(self):
        bad = (b'{"schema":1,"schema":1,"status":"completed",'
               b'"intent_sha256":"' + b"0" * 64 + b'"}')
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_DUPLICATE_FIELD"):
            verify_completion_receipt(self.intent, bad)

    def test_invalid_json_size_and_schema_refused(self):
        for data, reason in (
            (b"", "SIZE_INVALID"),
            (b"Z" * 2049, "SIZE_INVALID"),
            (b"{", "PARSE_INVALID"),
            (b'{"schema":true,"status":"completed","intent_sha256":"' +
             b"a" * 64 + b'"}', "SCHEMA_INVALID"),
            (b'{"schema":1,"status":"completed","intent_sha256":"' +
             b"a" * 64 + b'","extra":1}', "SCHEMA_INVALID"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_" + reason):
                    verify_completion_receipt(self.intent, data)

    def test_bad_intent_identity_and_scope_order_refused(self):
        for bad in (
            dict(self.intent, request_id="not-a-request-id"),
            dict(self.intent, scope_pins=list(reversed(self.intent["scope_pins"]))),
            dict(self.intent, operation="uninstall"),
            dict(self.intent, platform="other"),
            dict(self.intent, old="1.5.7"),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(EngineError):
                    validate_intent(bad)

    def test_real_windows_native_id64_correlates_ssdone_but_never_authorizes(self):
        from installer_engine.native_receipt import correlate_windows_inno_ssdone
        intent = dict(self.intent, platform="windows-x86_64",
                      request_id="ab" * 32)
        setup_pin = "e7" * 32
        signed_by_inno = ("DIM-INNO-V1|" + intent["request_id"].upper() +
                          "|" + setup_pin.upper()).encode("ascii")
        out = correlate_windows_inno_ssdone(intent, setup_pin, signed_by_inno)
        self.assertEqual(out["request_id"], intent["request_id"])
        self.assertEqual(out["intent_sha256"], intent_sha256(intent))
        self.assertTrue(out["source_receipt_bytes_match"])
        self.assertFalse(out["native_installation_accepted"])
        self.assertFalse(out["publisher_authenticated"])
        self.assertFalse(out["privileged_broker_implemented"])
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_PARSE_INVALID"):
            verify_completion_receipt(intent, signed_by_inno)

    def test_windows_inno_ssdone_must_be_exact_and_no_cross_os_grant(self):
        from installer_engine.native_receipt import correlate_windows_inno_ssdone
        intent = dict(self.intent, platform="windows-x86_64",
                      request_id="12" * 32)
        pin = "cd" * 32
        raw = ("DIM-INNO-V1|" + intent["request_id"].upper() +
               "|" + pin.upper()).encode()
        for modified, given_sha, match in (
            (raw + b"\n", pin, "EXACT_RECEIPT_SIZE_REQUIRED"),
            (raw[:-1], pin, "EXACT_RECEIPT_SIZE_REQUIRED"),
            (raw.replace(b"DIM-INNO-V1|", b"DIM-INNO-V0|"), pin, "RECEIPT_ID_OR_PIN_DRIFT"),
            (raw.lower(), pin, "RECEIPT_ID_OR_PIN_DRIFT"),
            (raw, "ab" * 32, "RECEIPT_ID_OR_PIN_DRIFT"),
            (raw.replace(b"1212", b"1313", 1), pin, "RECEIPT_ID_OR_PIN_DRIFT"),
            (b"x" * len(raw), pin, "RECEIPT_ID_OR_PIN_DRIFT"),
        ):
            with self.subTest(match=match, raw=modified[:15]):
                with self.assertRaisesRegex(EngineError, match):
                    correlate_windows_inno_ssdone(intent, given_sha, modified)
        for changed in (
            dict(intent, platform="linux-x86_64"),
            dict(intent, request_id="12" * 16),
        ):
            with self.assertRaisesRegex(EngineError, "EXACT_WINDOWS_ID64_REQUIRED"):
                correlate_windows_inno_ssdone(changed, pin, raw)
        with self.assertRaisesRegex(EngineError, "INSTALLER_PIN_REQUIRED"):
            correlate_windows_inno_ssdone(intent, "X"*64, raw)
        with self.assertRaisesRegex(EngineError, "NATIVE_INTENT_REQUEST_ID_INVALID"):
            correlate_windows_inno_ssdone(
                dict(intent, request_id="AB" * 32), pin, raw)

    def test_digest_independent_of_input_dict_insertion_order(self):
        original = intent_sha256(self.intent)
        reversed_doc = dict(reversed(list(self.intent.items())))
        self.assertEqual(original, intent_sha256(reversed_doc))



    def test_restoration_receipt_has_independent_status(self):
        normal = self.receipt()
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_SCHEMA_INVALID"):
            verify_restoration_receipt(self.intent, normal)
        restored = json.dumps({
            "schema": 1, "status": "restored",
            "intent_sha256": intent_sha256(self.intent)
        }).encode("utf8")
        self.assertTrue(verify_restoration_receipt(self.intent, restored))
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_SCHEMA_INVALID"):
            verify_completion_receipt(self.intent, restored)
if __name__ == "__main__":
    unittest.main()
