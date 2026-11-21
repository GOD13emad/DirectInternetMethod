"""R905 Windows read-only managed-code delta: synthetic manifest and OS-path fixtures.

The probe must never write to a caller's installed roots. Tests create only
disposable synthetic code files, never execute product/service or elevation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools/native_fixtures/windows/ReadOnlyManagedCodeDelta.py"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class WindowsManagedCodeDeltaProbe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.user = self.home / "User"
        self.root = self.home / "Privileged"
        self.user.mkdir()
        self.root.mkdir()
        (self.user / "app").mkdir()
        (self.root / "app").mkdir()
        self.old_user = b"old-synthetic-gui"
        self.old_root = b"unchanged-synthetic-service"
        (self.user / "app/code.exe").write_bytes(self.old_user)
        (self.root / "app/svc.exe").write_bytes(self.old_root)
        self.old = {
            "schema": 2, "product": "Direct Internet Method",
            "version": "1.5.6", "files": [
                {"scope": "user", "file": "app/code.exe",
                 "source": "app/code.exe", "bytes": len(self.old_user),
                 "sha256": sha(self.old_user)},
                {"scope": "privileged", "file": "app/svc.exe",
                 "source": "app/svc.exe", "bytes": len(self.old_root),
                 "sha256": sha(self.old_root)},
            ],
        }
        self.new = json.loads(json.dumps(self.old))
        self.new["version"] = "1.5.7"
        changed = b"new-synthetic-gui"
        self.new["files"][0]["bytes"] = len(changed)
        self.new["files"][0]["sha256"] = sha(changed)
        self.archive = self.home / "old.zip"
        self.target = self.home / "target.json"
        old_raw = json.dumps(self.old, sort_keys=True).encode()
        with zipfile.ZipFile(self.archive, "w") as zf:
            zf.writestr("installer-metadata/manifest.json", old_raw)
        (self.user / "manifest.json").write_bytes(old_raw)
        self.old_sha = sha(old_raw)
        self.target.write_text(json.dumps(self.new, sort_keys=True))
        self.archive_sha = sha(self.archive.read_bytes())
        self.target_sha = sha(self.target.read_bytes())

    def run_probe(self, **changes):
        options = {
            "--archive": str(self.archive),
            "--archive-sha256": self.archive_sha,
            "--old-manifest-sha256": self.old_sha,
            "--target-manifest": str(self.target),
            "--target-sha256": self.target_sha,
            "--user-root": str(self.user),
            "--privileged-root": str(self.root),
        }
        options.update(changes)
        args = [sys.executable, "-B", str(PROBE)]
        for key, value in options.items():
            args.extend([key, value])
        completed = subprocess.run(
            args, cwd=ROOT, capture_output=True, text=True, timeout=20)
        return completed, json.loads(completed.stdout)

    def test_valid_synthetic_delta_is_read_only_and_no_native_acceptance(self):
        before = {p: p.read_bytes() for p in
                  [self.user / "app/code.exe", self.root / "app/svc.exe",
                   self.user / "manifest.json"]}
        proc, result = self.run_probe()
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertEqual(result["stats"],
                         {"unchanged": 1, "replace": 1, "create": 0})
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["os_trusted_handle_readback"])
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_modified_installed_user_code_rejected(self):
        (self.user / "app/code.exe").write_bytes(b"corrupted")
        proc, result = self.run_probe()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("DELTA_INSTALLED_MANAGED_CODE_DRIFT", result["reason"])

    def test_replaced_archive_pin_rejected(self):
        proc, result = self.run_probe(**{"--archive-sha256": "0" * 64})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("ARCHIVE_PIN_MISMATCH", result["reason"])

    def test_target_source_pin_rejected(self):
        proc, result = self.run_probe(**{"--target-sha256": "0" * 64})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("TARGET_MANIFEST_PIN_MISMATCH", result["reason"])

    def test_installed_manifest_drift_rejected(self):
        (self.user / "manifest.json").write_bytes(b"foreign-data")
        proc, result = self.run_probe()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("INSTALLED_MANIFEST_BASELINE_DRIFT", result["reason"])

    def test_symlink_parent_rejected_if_supported(self):
        alternative = self.home / "Elsewhere"
        alternative.mkdir()
        linked = self.home / "Alias"
        try:
            linked.symlink_to(self.user, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("unprivileged symlink creation unavailable")
        proc, result = self.run_probe(**{"--user-root": str(linked)})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("DELTA_REPARSE_OR_LINK_IN_ANCESTRY", result["reason"])

    def test_probe_source_excludes_write_and_service_control(self):
        source = PROBE.read_text(encoding="utf-8")
        for forbidden in ("Start-Process", "pkexec", "sc.exe",
                          "os.remove(", ".unlink(", "shutil.rmtree(",
                          "subprocess.Popen(", "os.chmod("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
