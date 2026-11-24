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
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only source build")
    def test_r940_installed_action_is_root_metadata_not_client_grant(self):
        with tempfile.TemporaryDirectory(prefix="dim-r940-action-") as tmp:
            action = "org.god13emad.directinternetmethod.r940fixture"
            target = Path(tmp) / "input"
            fixture.prepare(target, polkit_action=action)
            meta = json.loads((target / "contract.json").read_bytes())
            request = json.loads((target / "broker-request.json").read_bytes())
            self.assertEqual(meta["polkit_action"], action)
            self.assertNotIn("polkit_action", request)
            self.assertFalse(meta["native_product_installation_accepted"])
            self.assertFalse(meta["production_privileged_broker_implemented"])
            self.assertFalse(meta["publisher_authenticated"])
            with self.assertRaisesRegex(ValueError, "R940_OS_POLKIT_ACTION_INVALID"):
                fixture.prepare(Path(tmp) / "bad", polkit_action="org.bad;code")

    def test_r940_ci_uses_installed_test_only_vendor_policy_and_unchanged_kernel(self):
        script = SCRIPT.read_text(encoding="utf8")
        shell = HARNESS.read_text(encoding="utf8")
        self.assertIn("observe_linux_polkit_authorization(conn, action)", script)
        self.assertIn('metadata["polkit_action"] = polkit_action', script)
        self.assertIn('"R940_OS_POLKIT_DENIED"', script)
        self.assertIn('denied_exceptions += (EngineError,)', script)
        self.assertIn('except denied_exceptions as error:', script)
        self.assertIn('--setenv=PYTHONDONTWRITEBYTECODE=1', shell)
        self.assertIn('R940_POLKIT_NATIVE', shell)
        self.assertIn('subject.user === "runner"', shell)
        self.assertIn('<allow_any>no</allow_any>', shell)
        self.assertIn("R940_POLKIT_DENIAL_MUTATED_RECEIPT", shell)
        self.assertIn("GITHUB_EVENT_NAME", shell)
        self.assertIn("refs/heads/feature/universal-install-engine", shell)
        self.assertNotIn("rm -rf -- \"$ROOT\"", shell)
        self.assertIn("R975_ROOT_RESERVED_CRASH", shell)
        self.assertIn("R975_REAL_ROOT_SYSTEMD_RESERVED_CRASH_RECOVERED_NO_NATIVE_PASS", shell)
        self.assertIn("retire_root_reserved_before_native", script)
        self.assertIn("from installer_engine.broker_replay import parse_replay_snapshot", script)

    def test_r946_root_policy_plan_binds_native_intent_and_rejects_repin(self):
        from installer_engine.engine import EngineError
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="dim-r946-policy-") as tmp:
            inp = Path(tmp) / "input"
            # Only a source preparation fixture; no Linux privilege on Win.
            with patch.object(fixture.os, "getuid", lambda: 1000, create=True):
                fixture.prepare(
                    inp, polkit_action="org.god13emad.directinternetmethod.r940fixture")
            meta = json.loads((inp / "contract.json").read_bytes())
            result = fixture.verify_pinned_native_contract(inp, meta)
            self.assertFalse(result["native_installation_accepted"])
            self.assertEqual(result["native_intent_sha256"],
                             meta["native_intent_sha256"])
            good_bytes = (inp / "native-intent.json").read_bytes()
            native = json.loads(good_bytes)
            native["request_id"] = "22" * 16
            (inp / "native-intent.json").write_bytes(fixture.canonical(native))
            meta["native_intent_sha256"] = fixture.digest(
                fixture.canonical(native))
            with self.assertRaisesRegex(
                    EngineError, "BROKER_NATIVE_REQUEST_ID_DRIFT"):
                fixture.verify_pinned_native_contract(inp, meta)
            # A separately re-pinned yet different scope plan is also denied.
            (inp / "native-intent.json").write_bytes(good_bytes)
            meta["native_intent_sha256"] = fixture.digest(good_bytes)
            plan = json.loads((inp / "native-plan.json").read_bytes())
            plan["scopes"][0]["manifest"]["files"][0]["sha256"] = "f" * 64
            changed_plan = fixture.canonical(plan)
            (inp / "native-plan.json").write_bytes(changed_plan)
            meta["native_plan_sha256"] = fixture.digest(changed_plan)
            with self.assertRaisesRegex(
                    EngineError, "BROKER_POLICY_REQUEST_PLAN_SCOPE_PIN_DRIFT"):
                fixture.verify_pinned_native_contract(inp, meta)

    def test_r974_existing_systemd_root_broker_uses_exact_id64_policy(self):
        from unittest.mock import patch
        from installer_engine.broker_intent import compare_pinned_policy_intent
        from installer_engine.engine import EngineError, hash_bytes
        with tempfile.TemporaryDirectory(prefix="dim-r974-linux-id64-") as tmp:
            inp = Path(tmp) / "inputs"
            with patch.object(fixture.os, "getuid", lambda: 1000, create=True):
                fixture.prepare(
                    inp, polkit_action="org.god13emad.directinternetmethod.r940fixture")
            req_bytes = (inp / "broker-request.json").read_bytes()
            policy_bytes = (inp / "broker-policy.json").read_bytes()
            request = json.loads(req_bytes)
            policy = json.loads(policy_bytes)
            meta = json.loads((inp / "contract.json").read_bytes())
            native = json.loads((inp / "native-intent.json").read_bytes())
            self.assertEqual(request["request_id"], "0123456789abcdef" * 4)
            self.assertEqual(len(request["request_id"]), 64)
            self.assertEqual(native["request_id"], request["request_id"])
            self.assertEqual(meta["request_id"], request["request_id"])
            self.assertEqual(policy["request_sha256"], hash_bytes(req_bytes))
            self.assertEqual(meta["request_sha256"], hash_bytes(req_bytes))
            result = fixture.verify_pinned_native_contract(inp, meta)
            self.assertEqual(result["request_id"], request["request_id"])
            self.assertFalse(result["native_installation_accepted"])
            self.assertFalse(meta["production_privileged_broker_implemented"])
            self.assertFalse(meta["publisher_authenticated"])
            from tests.test_engine_broker_intent import fixture_plan
            changed = dict(request, request_id=request["request_id"][:-1])
            changed_bytes = (json.dumps(changed, sort_keys=True,
                                        separators=(",", ":")) + "\n").encode()
            from tests.test_engine_broker_intent import canonical
            changed_policy = dict(
                policy, request_sha256=hash_bytes(changed_bytes))
            changed_policy_bytes = canonical(changed_policy)
            with self.assertRaisesRegex(EngineError, "BROKER_REQUEST_ID_INVALID"):
                compare_pinned_policy_intent(
                    fixture_plan("linux-x86_64"), changed_policy_bytes,
                    hash_bytes(changed_policy_bytes), changed_bytes)

    def test_r976_real_systemd_root_cut_is_failure_status_not_tempfail(self):
        # systemd.service documents EX_TEMPFAIL/75 as a successful exit;
        # expecting Result=exit-code with 75 misclassifies our real test.
        source = SCRIPT.read_text(encoding="utf-8")
        shell = HARNESS.read_text(encoding="utf-8")
        self.assertIn("os._exit(78)", source)
        self.assertIn('"$observed_status" == 78', shell)
        self.assertIn('"$observed_result" == exit-code', shell)
        self.assertNotIn("os._exit(75)", source)
        self.assertIn("R976_REAL_ROOT_SYSTEMD_FAILED_PROCESS_STATUS_PASS", shell)
        self.assertIn("R975_ROOT_RESERVED_CRASH", shell)

    def test_r990_exact_product_guard_waits_for_native_timer_not_manual_service_start(self):
        guard = (ROOT / "tests/r554_native_guard_ephemeral_contract.py").read_text("utf8")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text("utf8")
        for marker in ("DIM_R990_TIMER_PARTIAL", "crash_after_first_root_write",
                       "R990_EXACT_GUARD_TIMER_FIRED", "LastTriggerUSecMonotonic",
                       "rootPhaseBefore", "R990_TIMER_ONLY_REQUIRES_STAGED"):
            self.assertIn(marker, guard)
        self.assertIn("linux_guard_partial_candidate_sha:", workflow)
        self.assertIn("inputs.linux_guard_partial_candidate_sha == github.sha", workflow)

    def test_r989_native_watchdog_fault_is_after_real_durable_mutation(self):
        watchdog = (ROOT / "tests/r532_ephemeral_root_watchdog_contract.py").read_text("utf8")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text("utf8")
        for marker in ("R989_ROOT_PARTIAL_CRASH", "def crash_after_first_root_write(",
                       "os.fork()", "os._exit(79)", "os.waitstatus_to_exitcode",
                       "R989_ACTUAL_PARTIAL_ROOT_STATE", "R989_WATCHDOG_STAGED_RECOVERY",
                       "R989_EXPECTED_CRASH_EXIT"):
            self.assertIn(marker, watchdog)
        self.assertIn('R989_ROOT_PARTIAL_CRASH=', workflow)
        self.assertIn("github.event_name == 'push'", workflow)

    def test_r988_automatic_systemd_restart_is_bounded_and_not_manual(self):
        shell = HARNESS.read_text(encoding="utf8")
        workflow = (ROOT / ".github/workflows/universal-install-engine.yml").read_text("utf8")
        for marker in ("R988_AUTO_RESTART", "Restart=on-failure",
                       "RestartSec=20s", "StartLimitBurst=2",
                       "NRestarts", "R988_REAL_OS_AUTOMATIC_RESTART_PASS",
                       "R988_RESTART_PID_OR_COUNT_INVALID"):
            self.assertIn(marker, shell)
        self.assertIn("R988_AUTO_RESTART: '1'", workflow)
        self.assertIn("if [[ \"$R988_AUTO_RESTART\" == 1 ]]; then", shell)

    def test_r975_root_reserved_restart_retires_without_native_and_never_replays(self):
        """Unit contract only; real root+systemd service runs in push-only CI."""
        from unittest.mock import patch
        from installer_engine.broker_replay import parse_replay_snapshot
        with tempfile.TemporaryDirectory(prefix="dim-r975-reserved-") as tmp:
            base = Path(tmp)
            inp = base / "input"
            with patch.object(fixture.os, "getuid", lambda: 1000, create=True):
                fixture.prepare(inp)
            meta = json.loads((inp / "contract.json").read_bytes())
            state = {
                "schema": 1, "platform": "linux-x86_64",
                "used_request_ids": [meta["request_id"]],
                "active": {
                    "request_id": meta["request_id"],
                    "request_sha256": meta["request_sha256"],
                    "policy_sha256": meta["policy_sha256"],
                    "version": "1.5.7", "operation": "upgrade",
                    "phase": "reserved",
                },
            }
            ledger = base / "ledger.json"
            receipt = base / "receipt.json"
            ledger.write_bytes(fixture.canonical(state))
            def fixture_only_atomic(path, doc):
                path.write_bytes(fixture.canonical(doc))
            with patch.object(fixture, "atomic_root_json",
                              side_effect=fixture_only_atomic) as mocked:
                result = fixture.retire_root_reserved_before_native(
                    ledger, receipt, meta)
            self.assertEqual(result, "R975_RESERVED_TOMBSTONED_NO_NATIVE")
            self.assertEqual(mocked.call_count, 1)
            final = parse_replay_snapshot(ledger.read_bytes(), "linux-x86_64")
            self.assertIsNone(final["active"])
            self.assertEqual(final["used_request_ids"], [meta["request_id"]])
            self.assertFalse(receipt.exists())
            # No double-retire or second writer on normal restart.
            with patch.object(fixture, "atomic_root_json",
                              side_effect=AssertionError("REWRITE_FORBIDDEN")):
                self.assertEqual(fixture.retire_root_reserved_before_native(
                    ledger, receipt, meta), "R975_NO_PENDING_RESERVATION")
            for bad in ("wrong-request", "wrong-policy", "receipt-present"):
                with self.subTest(reason=bad):
                    ledger.write_bytes(fixture.canonical(state))
                    wrong = dict(meta)
                    if bad == "wrong-request":
                        wrong["request_sha256"] = "0" * 64
                    elif bad == "wrong-policy":
                        wrong["policy_sha256"] = "0" * 64
                    else:
                        receipt.write_bytes(b"STAGED_FORGERY")
                    unchanged = ledger.read_bytes()
                    with patch.object(fixture, "atomic_root_json",
                                      side_effect=AssertionError("WRITER_CALLED")):
                        with self.assertRaisesRegex(
                            ValueError, "R975_RESERVED_IDENTITY_OR_RECEIPT_DRIFT"):
                            fixture.retire_root_reserved_before_native(
                                ledger, receipt, wrong)
                    self.assertEqual(ledger.read_bytes(), unchanged)
                    receipt.unlink(missing_ok=True)
            # Once native applying might have begun, NEVER auto-abort.
            state["active"]["phase"] = "applying"
            ledger.write_bytes(fixture.canonical(state))
            old = ledger.read_bytes()
            with patch.object(fixture, "atomic_root_json",
                              side_effect=AssertionError("APPLYING_REWRITE_FORBIDDEN")):
                self.assertEqual(fixture.retire_root_reserved_before_native(
                    ledger, receipt, meta),
                    "R975_APPLYING_REQUIRES_NATIVE_RECONCILIATION")
            self.assertEqual(ledger.read_bytes(), old)

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

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux AF_UNIX readiness")
    def test_socket_readiness_requires_live_listener_not_stale_socket_inode(self):
        # Reproduce CI's root cause: -S remains true after a service stops,
        # yet an AF_UNIX connect returns ECONNREFUSED until rebind/listen.
        import socket
        import subprocess
        shell = HARNESS.read_text("utf-8")
        matching = [line for line in shell.splitlines()
                    if "s.connect_ex(sys.argv[1])" in line]
        self.assertEqual(len(matching), 1)
        program = matching[0].split(" -c '", 1)[1].rsplit("'", 1)[0]
        with tempfile.TemporaryDirectory(prefix="dim-r942-socket-") as temp:
            name = str(Path(temp) / "broker.sock")
            def probe():
                return subprocess.run(
                    [sys.executable, "-c", program, name],
                    check=False, capture_output=True, timeout=3).returncode
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(name)
                self.assertNotEqual(probe(), 0,
                                    "BOUND_BUT_NOT_LISTENING_MUST_NOT_BE_READY")
                server.listen(1)
                self.assertEqual(probe(), 0, "LISTENING_SOCKET_MUST_BE_READY")
                with server.accept()[0]:
                    pass
            self.assertTrue(Path(name).exists(),
                            "SOCKET_PATH_MUST_SURVIVE_SERVER_CLOSE")
            self.assertNotEqual(probe(), 0,
                                "STALE_SOCKET_PATH_MUST_NOT_MEAN_READY")

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
