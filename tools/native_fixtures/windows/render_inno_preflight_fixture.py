"""Render an offline, synthetic-only Inno Setup test fixture.

This tooling NEVER installs production DIM, never uses the production Inno
AppId, and never starts/stops the Windows Service. It renders a controlled
Inno6 source from the exact R880 preflight pattern. Production Windows
UAC/SCM/physical multi-root recovery remains an independent acceptance gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import tempfile
import uuid

from installer_engine.archive_import import import_pinned_archive
from installer_engine.engine import EngineError, hash_file, require

PRODUCTION_APP_ID = uuid.UUID("B5388E8B-9AF3-41F4-87E2-01C9601A36CB")
TEMPLATE = Path(__file__).with_name("InnoPreflightFixture.iss.in")
AUTO_UNINSTALL = Path(__file__).with_name("InnoAutoCleanupFixture.inc")
REPLACEMENTS = {
    "@VERSION@", "@TAG@", "@SOURCE_ZIP@", "@ARCHIVE_SHA256@",
    "@NORMALIZED_SHA256@", "@ENGINE_BINARY@", "@APPID_DIRECTIVE@",
    "@FIXTURE_INSTALL_ROOT@", "@FIXTURE_OUTPUT_DIR@"
}
EXPECTED_FIXTURE_FILES = {
    "user/app/main.bin": "FAKE_GUI_{}_TEST_ONLY",
    "privileged/bin/service.stub": "NOT_A_SERVICE_{}_TEST_ONLY",
}
SHA_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")


def _windows_literal(value: str) -> str:
    require(isinstance(value, str) and
            not any(ch in value for ch in '"\r\n;{}<>|'),
            "INNO_UNSAFE_LITERAL")
    p = PureWindowsPath(value)
    require(p.is_absolute() and p.drive and
            len(p.parts) >= 3, "INNO_ABSOLUTE_WINDOWS_PATH_REQUIRED")
    return str(p)


def build_fixture(
    source_zip: Path,
    independent_archive_pin: str,
    engine_binary: Path,
    independent_engine_pin: str,
    output_dir: Path,
    tag: str,
    app_id: uuid.UUID,
    install_root: str,
    integrated_uninstall: bool = False,
) -> dict:
    require(isinstance(tag, str) and TAG_RE.fullmatch(tag) is not None,
            "INVALID_FIXTURE_TAG")
    require(type(integrated_uninstall) is bool,
            "INVALID_UNINSTALL_FIXTURE_FLAG")
    require(type(app_id) is uuid.UUID and app_id != PRODUCTION_APP_ID,
            "FIXTURE_MUST_NOT_USE_PRODUCTION_APP_ID")
    require(type(independent_archive_pin) is str and
            SHA_RE.fullmatch(independent_archive_pin) is not None and
            type(independent_engine_pin) is str and
            SHA_RE.fullmatch(independent_engine_pin) is not None,
            "INDEPENDENT_SOURCE_AND_ENGINE_PINS_REQUIRED")
    source_zip = Path(source_zip).absolute()
    engine_binary = Path(engine_binary).absolute()
    output_dir = Path(output_dir).absolute()
    root = _windows_literal(install_root)
    require("DIM_UE_" in root.upper() and
            root.upper() != "C:\\PROGRAM FILES\\DIRECTINTERNETMETHOD",
            "FIXTURE_ROOT_MUST_BE_DISPOSABLE")
    require(source_zip.is_file() and engine_binary.is_file(),
            "INNO_SOURCE_INPUTS_MISSING")
    require(hash_file(source_zip).lower() == independent_archive_pin.lower(),
            "INNO_SOURCE_ZIP_PIN_INVALID")
    require(hash_file(engine_binary).lower() == independent_engine_pin.lower(),
            "INNO_FROZEN_ENGINE_PIN_INVALID")
    require(output_dir.is_dir(), "INNO_OUTPUT_PARENT_MUST_EXIST")
    iss = output_dir / ("DimUEPreflight_" + tag + ".iss")
    receipt = output_dir / ("DimUEPreflight_" + tag + ".json")
    require(not iss.exists() and not receipt.exists(),
            "INNO_FIXTURE_OUTPUT_ALREADY_EXISTS")
    source_string = _windows_literal(str(source_zip))
    binary_string = _windows_literal(str(engine_binary))
    output_string = _windows_literal(str(output_dir / "output"))
    with tempfile.TemporaryDirectory(prefix="dim-inno-source-preflight-",
                                     dir=output_dir) as temp:
        normalized = Path(temp) / "normalized"
        info = import_pinned_archive(
            source_zip, independent_archive_pin, normalized, "windows-managed")
        require(info["files"] == 2 and info["platform"] == "windows-x86_64",
                "INNO_NOT_A_SYNTHETIC_TWO_SCOPE_FIXTURE")
        doc = json.loads((normalized / "manifest.json").read_text("utf-8"))
        require(set(row["path"] for row in doc["files"]) ==
                set(EXPECTED_FIXTURE_FILES), "INNO_REAL_PRODUCT_PAYLOAD_FORBIDDEN")
        for name, text in EXPECTED_FIXTURE_FILES.items():
            require((normalized / "payload" / name).read_bytes() ==
                    text.format(doc["version"]).encode("ascii"),
                    "INNO_NOT_AN_EXPLICIT_SYNTHETIC_TEST_PAYLOAD")
        template = TEMPLATE.read_text("utf-8")
        options = {
            "@VERSION@": doc["version"],
            "@TAG@": tag,
            "@SOURCE_ZIP@": source_string,
            "@ARCHIVE_SHA256@": independent_archive_pin.lower(),
            "@NORMALIZED_SHA256@": info["normalized_manifest_sha256"],
            "@ENGINE_BINARY@": binary_string,
            "@APPID_DIRECTIVE@": "{{" + str(app_id).upper() + "}",
            "@FIXTURE_INSTALL_ROOT@": root,
            "@FIXTURE_OUTPUT_DIR@": output_string
        }
        require(all(template.count(key) == 1 for key in options if key != "@TAG@") and
                template.count("@TAG@") >= 2, "INNO_TEMPLATE_VARIABLES_CHANGED")
        for key, val in options.items():
            template = template.replace(key, val)
        require(not any(key in template for key in REPLACEMENTS),
                "INNO_UNRENDERED_VARIABLE")
        if integrated_uninstall:
            # Native Inno cleanup observed on a synthetic guest only.
            extra = AUTO_UNINSTALL.read_text("utf-8")
            placeholder = "@FIXTURE_UNINSTALL_REGISTRY_PATH@"
            require(extra.count(placeholder) == 2,
                    "INNO_AUTO_UNINSTALL_TEMPLATE_REGISTRY_GUARD_MISSING")
            native_registry = (
                "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
                + "{" + str(app_id).upper() + "}_is1")
            template += "\n" + extra.replace(placeholder, native_registry)
            require("function InitializeUninstall()" in template and
                    "procedure CurUninstallStepChanged(" in template and
                    "usDone" in template and "--native-unregistered" in template,
                    "INNO_NATIVE_FIXTURE_UNINSTALL_NOT_WIRED")
        require("PrivilegesRequired=lowest" in template and
                "function PrepareToInstall" in template and
                "Flags: dontcopy noencryption" in template and
                "DimUEPreflight_" + tag in template and
                "AppName=DIM Universal Engine Isolated Fixture" in template,
                "INNO_FIXTURE_SAFETY_BOUNDARY_CHANGED")
        # This source is only for building offline fixtures, not for native
        # production acceptance. It cannot create a trusted publisher proof.
        iss.write_text(template, encoding="utf-8")
        report = {
            "status": "PASS_RENDERED_SYNTHETIC_NATIVE_INNO_FIXTURE_SOURCE_ONLY",
            "fixture_appid": str(app_id),
            "fixture_script": str(iss),
            "fixture_script_sha256": hash_file(iss),
            "archive_sha256": independent_archive_pin.lower(),
            "engine_sha256": independent_engine_pin.lower(),
            "normalized_manifest_sha256": info["normalized_manifest_sha256"],
            "source_version": doc["version"],
            "native_service_installed": False,
            "native_install_or_rollback_accepted": False,
            "native_uninstall_fixture_automatic": integrated_uninstall,
            "publisher_authenticated": False
        }
        receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
        return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-zip", type=Path, required=True)
    p.add_argument("--archive-sha256", required=True)
    p.add_argument("--engine-exe", type=Path, required=True)
    p.add_argument("--engine-sha256", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--app-id", type=uuid.UUID, required=True)
    p.add_argument("--install-root", required=True)
    p.add_argument("--integrated-uninstall", action="store_true", help="synthetic native Inno cleanup fixture ONLY")
    a = p.parse_args()
    print(json.dumps(build_fixture(
        a.source_zip, a.archive_sha256, a.engine_exe, a.engine_sha256,
        a.out, a.tag, a.app_id, a.install_root,
        a.integrated_uninstall), sort_keys=True))


if __name__ == "__main__":
    main()
