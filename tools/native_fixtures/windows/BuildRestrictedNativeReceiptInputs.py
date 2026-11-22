"""R931: prepare pinned synthetic receipt + restricted-token probe, NO installation.

The only output is a new OS-temp fixture root. Real ACL enforcement
happens only later INSIDE disposable, offline Windows Sandbox.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from installer_engine.native_receipt import (
    intent_sha256, verify_restoration_receipt,
)

ROOT = Path(__file__).resolve().parents[3]
CS = ROOT / "tools/native_fixtures/windows/RestrictedNativeReceiptProbe.cs"
PS = ROOT / "tools/native_fixtures/windows/RunRestrictedNativeReceiptSandboxFixture.ps1"
CSC = Path("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(dest: Path) -> dict:
    dest = Path(dest).absolute()
    if (dest.parent.resolve() != Path(tempfile.gettempdir()).resolve() or
            not re.fullmatch(r"dim-r931-receipt-[A-Za-z0-9_-]{6,22}",
                             dest.name)):
        raise ValueError("R931_NEW_DIRECT_OS_TEMP_FIXTURE_REQUIRED")
    if os.name != "nt" or not CSC.is_file():
        raise RuntimeError("R931_NATIVE_WINDOWS_COMPILER_REQUIRED")
    if dest.exists() or dest.is_symlink():
        raise ValueError("R931_REFUSE_OVERWRITE_OR_REUSE")
    if not CS.is_file() or not PS.is_file():
        raise ValueError("R931_PROBE_SOURCES_MISSING")
    dest.mkdir(mode=0o700)
    exe = dest / "RestrictedNativeReceiptProbe.exe"
    proc = subprocess.run(
        [str(CSC), "/nologo", "/target:exe", "/platform:x64",
         "/out:" + str(exe), str(CS)],
        capture_output=True, text=True, timeout=35,
    )
    if proc.returncode != 0 or not exe.is_file():
        raise RuntimeError("R931_RESTRICTED_PROBE_COMPILER_FAILED:" +
                           (proc.stdout + proc.stderr)[-1300:])
    intent = {
        "schema": 1,
        "request_id": secrets.token_hex(16),
        "platform": "windows-x86_64",
        "operation": "upgrade",
        "old": "1.5.6",
        "new": "1.5.7",
        "preimage_sha256": sha(b"R931_ISOLATED_SYNTHETIC_PREVIOUS_STATE"),
        "scope_pins": [
            {"name": "code", "manifest_sha256":
                sha(b"R931_MANIFEST_SYNTHETIC_CODE_SCOPE")},
            {"name": "user", "manifest_sha256":
                sha(b"R931_MANIFEST_SYNTHETIC_USER_SCOPE")},
        ],
    }
    signature = intent_sha256(intent)
    data = (json.dumps({"schema": 1, "status": "restored",
                        "intent_sha256": signature},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()
    if not verify_restoration_receipt(intent, data):
        raise AssertionError("R931_SYNTHETIC_RESTORATION_RECEIPT_INVALID")
    (dest / "restored.receipt.json").write_bytes(data)
    (dest / "RunRestrictedNativeReceiptSandboxFixture.ps1").write_bytes(
        PS.read_bytes())
    pins = {
        "schema": 1,
        "scope": "R931_OS_SYNTHETIC_RECEIPT_ONLY",
        "receipt_sha256": sha(data),
        "intent_sha256": signature,
        "probe_sha256": sha(exe.read_bytes()),
        "probe_bytes": exe.stat().st_size,
        "script_sha256": sha(PS.read_bytes()),
        "trusted_native_broker_implemented": False,
    }
    (dest / "receipt-pins.json").write_text(
        json.dumps(pins, sort_keys=True) + "\n", encoding="utf8")
    return pins


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output), sort_keys=True))
