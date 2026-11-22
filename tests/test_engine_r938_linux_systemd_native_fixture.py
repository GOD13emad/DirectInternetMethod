"""R938 common source contract and synthetic Linux root-service acceptance boundaries.

These tests intentionally do not issue root privileges or change systemd.
The separate trusted feature-PUSH CI job proves actual root-owned systemd
service, SO_PEERCRED client identity, durable receipt and restart replay.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from installer_engine.broker_replay import parse_replay_snapshot
from installer_engine.native_receipt import (
    intent_sha256, validate_intent, verify_completion_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/native_fixtures/linux/RunR938SystemdReceiptFixture.py"
HARNESS = ROOT / "tools/native_fixtures/linux/RunR938SystemdNativeReceiptCI.sh"
spec = importlib.util.spec_from_file_location("r938_linux_synthetic", SCRIPT)
fixture = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(fixture)


class R938FixtureContracts(unittest.TestCase):
    def test_cli_is_synthetic_not_a_second_product_installer(self):
        source = SCRIPT.read_text(encoding="utf8")
        self.assertIn("native_product_installation_accepted\": False", source)
        self.assertIn("production_privileged_broker_implemented\": False", source)
        self.assertIn("R938_REQUEST_REPLAY_DENIED", source)
        self.assertIn("socket.SO_PEERCRED", source)
        self.assertIn("os.fsync", source)
        self.assertNotIn("subprocess.run([\"/usr/bin/sh\"", source)
        self.assertIn("subprocess.run([\"/usr/bin/systemctl\"", source)

    def test_native_root_identity_is_literal_not_user_selected(self):
        with self.assertRaisesRegex(ValueError, "NONCANONICAL"):
            fixture.exact_root(Path("/tmp/dim-r938"))
        with self.assertRaisesRegex(ValueError, "NONCANONICAL"):
            fixture.exact_root(Path("/run/another-service"))
        if sys.platform.startswith("linux"):
            fixture.exact_root(Path(fixture.ROOT_NAME))

    def test_bounded_canonical_bytes_independent_of_os(self):
        data = {"schema": 1, "status": "synthetic", "count": 1}
        first = fixture.canonical(data)
        self.assertEqual(first, b'{"count":1,"schema":1,"status":"synthetic"}')
        self.assertEqual(len(fixture.digest(first)), 64)

    def test_nonroot_cannot_write_native_root_receipt(self):
        if sys.platform.startswith("linux") and os.geteuid() == 0:
            self.skipTest("root worker is separately tested in trusted CI")
        with tempfile.TemporaryDirectory(prefix="dim-r938-denied-") as directory:
            if not hasattr(os, "geteuid"):
                self.skipTest("Linux OS root predicate required")
            with self.assertRaisesRegex(PermissionError, "ROOT_REQUIRED"):
                fixture.atomic_root_json(Path(directory) / "receipt.json",
                                         {"status": "completed"})

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux native preparation only")
    def test_prepare_reuses_exact_shared_r899_r926_contract(self):
        with tempfile.TemporaryDirectory(prefix="dim-r938-contract-") as parent:
            inp = Path(parent) / "input"
            fixture.prepare(inp)
            metadata = json.loads((inp / "contract.json").read_bytes())
            native = json.loads((inp / "native-intent.json").read_bytes())
            request = (inp / "broker-request.json").read_bytes()
            self.assertTrue(metadata["fixture_only"])
            self.assertFalse(metadata["production_privileged_broker_implemented"])
            self.assertEqual(metadata["expected_peer_uid"], os.getuid())
            self.assertEqual(metadata["request_sha256"], fixture.digest(request))
            validate_intent(native)
            self.assertEqual(intent_sha256(native), metadata["native_intent_sha256"])
            self.assertEqual([s["name"] for s in native["scope_pins"]],
                             ["code", "user"])
            self.assertEqual(native["operation"], "upgrade")
            # Forged bytes here are only a contract fixture; never OS proof.
            synthetic = fixture.canonical({
                "schema": 1, "status": "completed",
                "intent_sha256": metadata["native_intent_sha256"],
            })
            self.assertTrue(verify_completion_receipt(native, synthetic))

    def test_client_subcommand_and_request_mode_are_distinct(self):
        from unittest.mock import patch
        # Before the fix, argparse used dest=mode for BOTH subcommand and
        # --mode and dispatched a client as verify(), missing --output.
        for kind in ("good", "tampered", "replay", "wrong-uid"):
            with self.subTest(client_mode=kind):
                argv = ["r938", "client", "--input", "/nonexistent",
                        "--root", "/tmp/r938-untrusted", "--mode", kind]
                with patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(
                            ValueError, "R938_NONCANONICAL_OS_FIXTURE_ROOT"):
                        fixture.main()

    def test_ci_native_root_fixture_is_push_only_and_nonproduction(self):
        src = HARNESS.read_text(encoding="utf8")
        self.assertIn("GITHUB_EVENT_NAME", src)
        self.assertIn("refs/heads/feature/universal-install-engine", src)
        self.assertIn("systemd-run --system", src)
        self.assertIn("sudo -n systemctl restart", src)
        self.assertIn("R938_REAL_ROOT_OS_FIXTURE_ONLY_NOT_PRODUCT_INSTALL", src)
        self.assertNotIn("apt install", src)
        self.assertNotIn("rm -rf -- \"$ROOT\"", src)


if __name__ == "__main__":
    unittest.main()
