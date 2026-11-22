"""Runtime self-test of the same universal transaction API on Windows or Linux.

Uses ONLY uniquely created OS-temp directories and a synthetic native
registration. Never installs the product or calls SCM/systemd/polkit/Inno.
Intended for both source and privately built frozen CLI acceptance.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from .engine import Engine, EngineError, require
from .universal_install import UniversalFixtureInstaller
from .native_receipt import intent_sha256


class _NativeFixture:
    def __init__(self):
        self.version = None
        self.receipt = None
        self.suppress_receipt = False

    def snapshot(self) -> bytes:
        return json.dumps({"v": self.version}, sort_keys=True).encode("utf8")

    def observed_version(self) -> str | None:
        return self.version

    def quiesced(self) -> bool:
        return True

    @staticmethod
    def _fixture_receipt(intent: dict) -> bytes:
        return json.dumps({"schema": 1, "status": "completed",
                           "intent_sha256": intent_sha256(intent)},
                          sort_keys=True).encode("utf8")

    def apply(self, target_version: str, intent: dict) -> None:
        self.version = target_version
        self.receipt = None if self.suppress_receipt else self._fixture_receipt(intent)

    def completed(self, intent: dict) -> bytes | None:
        return self.receipt

    def restore(self, snapshot: bytes, intent: dict) -> None:
        v = json.loads(snapshot.decode("utf8"))
        require(type(v) is dict and set(v) == {"v"},
                "SELFTEST_NATIVE_SNAPSHOT_INVALID")
        self.version = v["v"]
        self.receipt = None

    def unregister(self, intent: dict) -> None:
        self.version = None
        self.receipt = None if self.suppress_receipt else self._fixture_receipt(intent)

    def uninstall_completed(self, intent: dict) -> bytes | None:
        return self.receipt


def _bundle(base: Path, platform: str, scope: str, ver: str):
    target = base / ("source-" + scope + "-" + ver.replace(".", "-"))
    payload = target / "payload" / "app" / "code.bin"
    payload.parent.mkdir(parents=True)
    data = ("universal-fixture|" + scope + "|" + ver).encode("ascii")
    payload.write_bytes(data)
    doc = {
        "schema": 1, "product": "Direct Internet Method",
        "version": ver, "platform": platform,
        "files": [{"path": "app/code.bin", "bytes": len(data),
                   "sha256": hashlib.sha256(data).hexdigest(),
                   "mode": 0o644}],
    }
    manifest = target / "manifest.json"
    manifest.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf8")
    return target, hashlib.sha256(manifest.read_bytes()).hexdigest()


def run(platform: str) -> dict:
    actual = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    require(platform == actual, "UNIVERSAL_SELFTEST_HOST_PLATFORM_MISMATCH")
    with tempfile.TemporaryDirectory(prefix="dim-universal-cli-fixture-") as td:
        root = Path(td)
        roots = {"protected": root/"protected",
                 "user": root/"user"}
        backend = _NativeFixture()

        def engine():
            return UniversalFixtureInstaller(root/"journal", platform, roots, backend)

        def sources(v):
            return {k: _bundle(root, platform, k, v) for k in roots}

        def versions():
            return {Engine(p, platform).verify().get("version")
                    for p in roots.values()}

        tx = engine()
        tx.begin(sources("1.5.6"))
        tx.activate()
        require(tx.commit()["version"] == "1.5.6" and
                versions() == {"1.5.6"},
                "UNIVERSAL_SELFTEST_FRESH_INSTALL_FAILED")

        owner = roots["user"]/"data"/"configuration.json"
        owner.parent.mkdir()
        owner.write_bytes(b"OWNER_CONFIG_PRESERVE_ALWAYS")

        tx.begin(sources("1.5.7"))
        tx.activate()
        require(tx.commit()["version"] == "1.5.7" and
                versions() == {"1.5.7"},
                "UNIVERSAL_SELFTEST_UPGRADE_FAILED")

        backend.suppress_receipt = True
        tx.begin(sources("1.5.8"))
        tx.activate()
        require(backend.version == "1.5.8" and
                backend.completed(tx._intent(tx._load())) is None,
                "UNIVERSAL_SELFTEST_NEGATIVE_NOT_REPRODUCED")
        # Crash/restart: new instance checks durable journal; MUST abort rather
        # than assume success merely because native version is already 1.5.8.
        require(engine().recover()["version"] == "1.5.7" and
                backend.version == "1.5.7" and
                versions() == {"1.5.7"},
                "UNIVERSAL_SELFTEST_ROLLBACK_FAILED")

        backend.suppress_receipt = False
        tx.begin_uninstall()
        tx.apply_uninstall()
        require(engine().finish_uninstall()["status"] ==
                "UNIVERSAL_UNINSTALL_COMPLETE_FIXTURE_ONLY" and
                versions() == {None} and backend.version is None,
                "UNIVERSAL_SELFTEST_UNINSTALL_FAILED")
        require(owner.read_bytes() == b"OWNER_CONFIG_PRESERVE_ALWAYS",
                "UNIVERSAL_SELFTEST_OWNER_DATA_MODIFIED")
        require(not engine().journal.exists(),
                "UNIVERSAL_SELFTEST_TRANSACTION_NOT_CLEANED")

        return {
            "status": "PASS_UNIVERSAL_TRANSACTION_FIXTURE",
            "platform": platform,
            "fresh_install": "PASS",
            "in_place_upgrade": "PASS",
            "incomplete_native_update_rollback": "PASS",
            "uninstall_preserves_owner_data": "PASS",
            "native_product_install_accepted": False,
            "native_os_rollback_accepted": False,
            "power_cut_accepted": False,
        }
