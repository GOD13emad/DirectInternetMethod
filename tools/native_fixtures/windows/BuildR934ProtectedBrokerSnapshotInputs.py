"""Build isolated native Windows Sandbox R934 broker snapshot test.

Reuses the shared existing engine policy/request/replay implementations and
installed PyInstaller; emits a frozen read-only *test* probe and two synthetic
policy/ledger files. Nothing is installed in the host OS. All output goes to
a NEW direct OS-temp root; the guest must independently check and use pins.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from tools.native_fixtures.windows.R934ProtectedBrokerSnapshotProbe import (
    expected_input_bytes,
)

ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "tools/native_fixtures/windows/R934ProtectedBrokerSnapshotProbe.py"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(output: Path) -> dict:
    output = output.absolute()
    os_temp = Path(tempfile.gettempdir()).resolve()
    if (os.name != "nt" or
            output.parent.resolve() != os_temp or
            re.fullmatch(r"dim-r934-broker-[a-z0-9]{8,20}",
                         output.name) is None or
            output.exists() or output.is_symlink()):
        raise ValueError("R934_NEW_HOST_NATIVE_OS_TEMP_FIXTURE_REQUIRED")
    if not PROBE.is_file() or PROBE.is_symlink():
        raise RuntimeError("R934_ORIGINAL_SHARED_PROBE_SOURCE_REQUIRED")
    output.mkdir(mode=0o700)
    inputs = output / "input"
    inputs.mkdir()
    raw = expected_input_bytes()
    for name in ("policy.json", "replay.json"):
        (inputs / name).write_bytes(raw[name])

    executable = inputs/"R934NativeBrokerSnapshotProbe.exe"
    command = [
        sys.executable, "-m", "PyInstaller", "--onefile",
        "--clean", "--noconfirm", "--paths", str(ROOT),
        "--name", executable.stem,
        "--distpath", str(inputs),
        "--workpath", str(output/"build"),
        "--specpath", str(output/"spec"),
        str(PROBE),
    ]
    proc = subprocess.run(command, cwd=str(ROOT), capture_output=True,
                          text=True, timeout=180)
    (output / "pyinstaller.out.txt").write_text(
        proc.stdout + "\nSTDERR\n" + proc.stderr, encoding="utf8",
    )
    if proc.returncode != 0 or not executable.is_file():
        raise RuntimeError("R934_EXISTING_PYINSTALLER_FROZEN_PROBE_FAILED")
    pins = {
        "schema": 1,
        "scope": "R934_WIN_NATIVE_HELD_READONLY",
        "policy_sha256": sha(raw["policy.json"]),
        "ledger_sha256": sha(raw["replay.json"]),
        "policy_bytes": len(raw["policy.json"]),
        "ledger_bytes": len(raw["replay.json"]),
        "request_sha256": sha(raw["request"]),
        "source_sha256": sha(PROBE.read_bytes()),
        "probe_sha256": sha(executable.read_bytes()),
        "probe_bytes": executable.stat().st_size,
        "native_authorization_accepted": False,
        "publisher_authenticated": False,
    }
    # The probe's schema is intentionally narrower than the builder report.
    # Only pinned file identities belong in its input file.
    probe_pins = {k: pins[k] for k in (
        "schema", "scope", "policy_sha256", "ledger_sha256",
        "policy_bytes", "ledger_bytes", "source_sha256",
        "probe_sha256",
    )}
    (inputs/"pins.json").write_text(
        json.dumps(probe_pins, sort_keys=True, indent=2)+"\n", encoding="utf8",
    )
    (output/"build-receipt.json").write_text(
        json.dumps(pins, sort_keys=True, indent=2)+"\n", encoding="utf8",
    )
    return pins


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(build(args.output), sort_keys=True))
