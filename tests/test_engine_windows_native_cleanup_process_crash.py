"""R923 Windows process-exit fixture for native update completion cleanup.

Runs a compiled fixture linking the *production* C# journal and receipt
validators. Verifies process boundaries, not service SCM/UAC, host reboot,
filesystem power-cut durability or a real Inno rollback.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROJ = ROOT / "tools/native_fixtures/windows/NativeCleanupCrashFixture/NativeCleanupCrashFixture.csproj"
TXN = "0123456789ABCDEF" * 4
RECEIPT = f"completion-{TXN}.receipt"


@unittest.skipUnless(os.name == "nt" and shutil.which("dotnet"),
                     "Windows and dotnet SDK required for native fixture")
class NativeUpdateCleanupProcessCrashTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sdk = subprocess.run(["dotnet", "--list-sdks"], capture_output=True,
                             text=True, timeout=20)
        if sdk.returncode != 0 or not any(
                line.split(".", 1)[0] == "10" for line in sdk.stdout.splitlines()):
            raise unittest.SkipTest("Native .NET 10 SDK not present")
        cls.builddir = tempfile.TemporaryDirectory(prefix="dim-r923-native-build-")
        output = Path(cls.builddir.name) / "out"
        obj = str(Path(cls.builddir.name) / "obj") + os.sep
        result = subprocess.run([
            "dotnet", "build", str(PROJ), "-c", "Release", "-o", str(output),
            "-p:BaseIntermediateOutputPath=" + obj, "--nologo",
        ], capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            cls.builddir.cleanup()
            raise AssertionError("R923 fixture compilation failed: " +
                                 (result.stdout + result.stderr)[-2000:])
        cls.dll = output / "NativeCleanupCrashFixture.dll"
        assert cls.dll.is_file(), "Native R923 fixture DLL not produced"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "builddir"):
            cls.builddir.cleanup()

    def run_fixture(self, root, action, expected):
        result = subprocess.run(["dotnet", str(self.dll), action, str(root)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(expected, result.returncode,
                         f"{action}: {result.stdout} {result.stderr}")
        return result

    def root(self, td):
        folder = Path(td)
        (folder / ".dim-r923-owned").write_text("owned synthetic fixture", encoding="utf8")
        return folder

    def test_committed_pending_recovers_in_new_process(self):
        with tempfile.TemporaryDirectory(prefix="dim-r923-commit-") as td:
            root = self.root(td)
            self.run_fixture(root, "seed", 0)
            self.run_fixture(root, "commit-exit", 79)
            self.assertTrue((root / "pending-update.json").exists())
            self.assertTrue((root / RECEIPT).exists())
            self.assertFalse((root / "stage-fixture.bin").exists())
            self.run_fixture(root, "resume", 0)
            self.run_fixture(root, "verify", 0)

    def test_crash_after_receipt_removal_recovers_without_second_receipt(self):
        with tempfile.TemporaryDirectory(prefix="dim-r923-receipt-") as td:
            root = self.root(td)
            self.run_fixture(root, "seed", 0)
            self.run_fixture(root, "commit-exit", 79)
            self.run_fixture(root, "receipt-exit", 80)
            self.assertTrue((root / "pending-update.json").exists())
            self.assertFalse((root / RECEIPT).exists())
            self.run_fixture(root, "resume", 0)
            self.run_fixture(root, "verify", 0)

    def test_committed_pending_with_reintroduced_stage_rejected(self):
        with tempfile.TemporaryDirectory(prefix="dim-r923-stage-") as td:
            root = self.root(td)
            self.run_fixture(root, "seed", 0)
            self.run_fixture(root, "commit-exit", 79)
            (root / "stage-fixture.bin").write_text("unexpected", encoding="utf8")
            self.run_fixture(root, "resume", 12)
            self.assertTrue((root / "pending-update.json").exists())
            self.assertTrue((root / RECEIPT).exists())
            self.assertIn("preserved-owner-data-r923",
                          (root / "owner-data.txt").read_text(encoding="utf8"))

    def test_forged_receipt_refuses_commit_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory(prefix="dim-r923-mismatch-") as td:
            root = self.root(td)
            self.run_fixture(root, "seed", 0)
            (root / RECEIPT).write_text("forged-receipt", encoding="utf8")
            self.run_fixture(root, "commit-exit", 12)
            self.assertTrue((root / "stage-fixture.bin").exists())
            self.assertTrue((root / "pending-update.json").exists())

    def test_missing_receipt_prepared_phase_refuses_commit(self):
        with tempfile.TemporaryDirectory(prefix="dim-r923-prepared-") as td:
            root = self.root(td)
            self.run_fixture(root, "seed", 0)
            (root / RECEIPT).unlink()
            self.run_fixture(root, "commit-exit", 12)
            self.assertTrue((root / "stage-fixture.bin").exists())
            self.assertTrue((root / "pending-update.json").exists())


if __name__ == "__main__":
    unittest.main()
