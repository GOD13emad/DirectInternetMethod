"""Read-only correlation of REAL Inno ssDone bytes with the ONE common engine.

Only for the existing native disposable Windows VM test while its protected
Inno completion receipt is live. This helper cannot install, authenticate a
publisher, issue an OS grant or turn a readback into native completion.
The baseline service binary SHA is NOT a complete native preimage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from installer_engine.broker_intent import _unique_pairs
from installer_engine.engine import EngineError, hash_bytes, require
from installer_engine.native_plan import windows_scoped_plan
from installer_engine.native_receipt import correlate_windows_inno_ssdone
from installer_engine.windows_handle_bound import read_windows_pinned_small_file


def correlate_existing_vm_receipt(
    manifest: Path, manifest_pin: str, receipt_path: Path,
    native_transaction_id: str, installer_sha256: str,
    observed_baseline_service_sha256: str,
) -> dict:
    require(os.name == "nt", "R972_NATIVE_WINDOWS_OS_REQUIRED")
    for value, label in (
        (native_transaction_id, "TRANSACTION"),
        (installer_sha256, "INSTALLER"),
        (observed_baseline_service_sha256, "BASELINE"),
    ):
        require(type(value) is str and len(value) == 64 and
                all(c in "0123456789ABCDEF" for c in value),
                "R972_" + label + "_UPPER_HEX64_REQUIRED")
    source_bytes = manifest.read_bytes()
    require(hash_bytes(source_bytes) == manifest_pin.lower(),
            "R972_SOURCE_MANIFEST_SHA_DRIFT")
    source = json.loads(source_bytes.decode("utf-8-sig"),
                        object_pairs_hook=_unique_pairs)
    plan = windows_scoped_plan(source)
    require(plan.version == "1.5.7" and
            plan.platform == "windows-x86_64" and
            {name for name, _ in plan.scopes} == {"user", "privileged"},
            "R972_WINDOWS_NATIVE_PLAN_OR_VERSION_DRIFT")
    pins = sorted(
        ({"name": name, "manifest_sha256": hash_bytes(
            (json.dumps(doc, sort_keys=True, separators=(",", ":")) +
             "\n").encode("utf-8"))}
         for name, doc in plan.scopes), key=lambda row: row["name"])
    # Only a correlation SAMPLE. A service file hash is not the native
    # adapter snapshot; never dispatch this sample as broker authorization.
    intent = {
        "schema": 1, "request_id": native_transaction_id.lower(),
        "platform": "windows-x86_64", "operation": "upgrade",
        "old": "1.5.4", "new": "1.5.7",
        "preimage_sha256": observed_baseline_service_sha256.lower(),
        "scope_pins": pins,
    }
    expected = ("DIM-INNO-V1|" + native_transaction_id + "|" +
                installer_sha256).encode("ascii")
    native = read_windows_pinned_small_file(
        receipt_path, len(expected), hashlib.sha256(expected).hexdigest())
    result = correlate_windows_inno_ssdone(
        intent, installer_sha256.lower(), native)
    require(result["source_receipt_bytes_match"] and
            not result["native_installation_accepted"] and
            not result["publisher_authenticated"],
            "R972_NO_NATIVE_AUTHORITY_IN_CORRELATION")
    return result | {
        "source_manifest_sha256": manifest_pin.lower(),
        "source_scopes": len(plan.scopes),
        "native_receipt_exact_handle_read": True,
        "native_preimage_complete": False,
        "os_authorized_common_broker": False,
        "status": "R972_REAL_INNO_RECEIPT_CORRELATION_READONLY_PASS",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("manifest", "manifest-sha", "receipt", "transaction-id",
                 "installer-sha", "baseline-service-sha"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    try:
        out = correlate_existing_vm_receipt(
            Path(a.manifest), a.manifest_sha, Path(a.receipt),
            a.transaction_id, a.installer_sha, a.baseline_service_sha)
        print(json.dumps(out, sort_keys=True))
        return 0
    except (EngineError, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "FAIL_CLOSED", "reason": str(exc)}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
