#!/usr/bin/env python3
"""R526: hermetic Linux 1.5.5-rc1 INSTALL.json activation regression gate.

Run the exact inline metadata program from linux/install.sh against a disposable
HOME and a fake protected Root metadata file. No real installer, sudo, systemd,
DNS, routes, nftables, Tailscale, or live user installation is touched.
This verifies implementation contracts, not physical-host acceptance.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
INSTALL = BASE / "linux/install.sh"
USER_TX = BASE / "linux/app/user_update_transaction.py"
BEGIN = """python3 - "$APP/INSTALL.json" "$USER_TRANSACTION" <<'PY'\n"""
END = "\nPY\n"
PROTECTED = 'pathlib.Path("/var/lib/directinternetmethod/install.json")'
VERSION = "1.5.5-rc1"


def exact_inline_program() -> str:
    source = INSTALL.read_text(encoding="utf-8")
    if source.count(BEGIN) != 1:
        raise AssertionError("INLINE_METADATA_ENTRY_NOT_UNIQUE")
    tail = source.split(BEGIN, 1)[1]
    if tail.count(END) != 1 or tail.count(PROTECTED) != 1:
        raise AssertionError("INLINE_METADATA_PROVENANCE_NOT_UNIQUE")
    program = tail.split(END, 1)[0]
    if "transaction_helper.atomic_bytes(" not in program:
        raise AssertionError("METADATA_ATOMIC_WRITER_MISSING")
    return program


class InstallerMetadata(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="DIM_R526_META_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.app = self.home / ".local/share/DirectInternetMethod"
        self.app.mkdir(parents=True)
        self.pending = self.home / ".local/state/DirectInternetMethod/update-pending"
        self.pending.mkdir(parents=True)
        self.protected = self.root / "protected.json"
        self.protected.write_text(json.dumps({"schema": 1, "version": VERSION, "uid": 1000}))
        self.target = self.app / "INSTALL.json"
        self.original = b'{"schema":2,"version":"1.5.4","userNote":"KEEP"}\n'
        self.target.write_bytes(self.original)
        (self.app / "direct-internet-method.svg").write_bytes(b"FIXTURE_ICON")
        self.custom = self.app / "custom-hosts.txt"
        self.custom.write_bytes(b"KEEP_CUSTOM_HOSTS\n")
        self.manifest = {
            "schema": 1,
            "version": VERSION,
            "managed": {
                "direct_internet_method.py": {"sha": "a" * 64, "mode": 0o755},
                "user_update_transaction.py": {"sha": "b" * 64, "mode": 0o755},
            },
            "providerSha": "c" * 64,
            "providerManaged": True,
        }
        (self.pending / "manifest.json").write_text(json.dumps(self.manifest))
        self.program = exact_inline_program()

    def invoke(self) -> subprocess.CompletedProcess[str]:
        if self.program.count(PROTECTED) != 1:
            raise AssertionError("PROTECTED_PATH_PROVENANCE_CHANGED")
        # Override one exact path ONLY inside the disposable child process.
        # Never edit the package, protected host metadata, or user files.
        rendered = self.program.replace(PROTECTED, "pathlib.Path(" + repr(str(self.protected)) + ")")
        env = dict(os.environ)
        env["HOME"] = str(self.home)
        return subprocess.run(
            [sys.executable, "-B", "-", str(self.target), str(USER_TX)],
            input=rendered + "\n",
            text=True,
            capture_output=True,
            env=env,
            timeout=12,
            check=False,
        )

    def unchanged_on_failure(self) -> None:
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(self.custom.read_bytes(), b"KEEP_CUSTOM_HOSTS\n")

    def test_01_entrypoint_and_exact_source_contract(self) -> None:
        self.assertTrue(INSTALL.is_file() and USER_TX.is_file())
        self.assertEqual(len(self.program.splitlines()), 64)
        self.assertEqual(self.program.count(PROTECTED), 1)
        self.assertIn('assert protected.get("version") == "1.5.5-rc1"', self.program)
        self.assertIn('transaction_helper.atomic_bytes(', self.program)

    def test_02_in_place_metadata_and_mutable_preservation(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr[-700:])
        doc = json.loads(self.target.read_text())
        self.assertEqual(doc["schema"], 2)
        self.assertEqual(doc["version"], VERSION)
        self.assertEqual(doc["protectedBackendVersion"], VERSION)
        self.assertEqual(doc["managedProviderSha256"], self.manifest["providerSha"])
        self.assertEqual(
            doc["managedCodeSha256"],
            {key: row["sha"] for key, row in self.manifest["managed"].items()},
        )
        self.assertIsInstance(doc["managedLaunchersSha256"], dict)
        self.assertFalse(doc["networkMutationOnInstall"])
        self.assertFalse(doc["normalRunRequiresAdmin"])
        self.assertEqual(doc["updateMode"], "IN_PLACE_SINGLE_INSTALL_DATA_PRESERVED")
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.custom.read_bytes(), b"KEEP_CUSTOM_HOSTS\n")

    def test_03_old_protected_backend_fails_closed(self) -> None:
        self.protected.write_text('{"version":"1.5.2"}')
        self.unchanged_on_failure()

    def test_04_missing_protected_metadata_fails_closed(self) -> None:
        self.protected.unlink()
        self.unchanged_on_failure()

    def test_05_missing_pending_transaction_fails_closed(self) -> None:
        (self.pending / "manifest.json").unlink()
        self.unchanged_on_failure()

    def test_06_malformed_pending_transaction_fails_closed(self) -> None:
        (self.pending / "manifest.json").write_bytes(b"{INVALID JSON")
        self.unchanged_on_failure()

    def test_07_symlink_metadata_never_overwrites_foreign(self) -> None:
        foreign = self.root / "foreign.txt"
        foreign.write_bytes(b"FOREIGN_DO_NOT_MODIFY")
        self.target.unlink()
        self.target.symlink_to(foreign)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.read_bytes(), b"FOREIGN_DO_NOT_MODIFY")
        self.assertTrue(self.target.is_symlink())

    def test_08_orphan_stage_preserved_without_mutation(self) -> None:
        orphan = self.app / ".INSTALL.json.dim-update-stage"
        orphan.write_bytes(b"UNKNOWN_OWNER_STAGE")
        self.unchanged_on_failure()
        self.assertEqual(orphan.read_bytes(), b"UNKNOWN_OWNER_STAGE")

    def test_09_commit_requires_new_metadata_in_transaction_source(self) -> None:
        transaction = USER_TX.read_text(encoding="utf-8")
        self.assertIn('METADATA = "INSTALL.json"', transaction)
        self.assertIn("def check_metadata(app, data):", transaction)
        self.assertIn("check_metadata(app, data)", transaction)
        self.assertIn("def rollback():", transaction)
        self.assertIn("def recover_metadata_stage(", transaction)

    def test_10_no_network_service_mutation_in_activation_program(self) -> None:
        for disallowed in (
            "systemctl ", "tailscale set", "nft ", "ip route ",
            "subprocess.run(", "os.system(", "/etc/resolv.conf",
        ):
            self.assertNotIn(disallowed, self.program)
        self.assertNotIn("https://", self.program)

    def test_11_source_is_unmodified_by_child_execution(self) -> None:
        before = (hashlib.sha256(INSTALL.read_bytes()).digest(), hashlib.sha256(USER_TX.read_bytes()).digest())
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr[-700:])
        after = (hashlib.sha256(INSTALL.read_bytes()).digest(), hashlib.sha256(USER_TX.read_bytes()).digest())
        self.assertEqual(after, before)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InstallerMetadata)
    report = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"R526_INLINE_METADATA_CI {report.testsRun} tests; failures={len(report.failures)}; errors={len(report.errors)}")
    raise SystemExit(0 if report.wasSuccessful() else 1)
