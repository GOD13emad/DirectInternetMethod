"""Generate a fixture-only Qt IFW component that owns NO DIM managed code.

Qt Installer Framework's existing Execute operation calls the existing
cross-platform universal-selftest. The Qt component itself contains ZERO
payload files, and only metadata/lifecycle belongs to Qt. This is not a
production installer and never provisions OS services or privileged brokers.

Reference: https://doc.qt.io/qtinstallerframework/operations.html
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from xml.etree import ElementTree as ET

PLATFORM = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
COMPONENT = "org.dim.bridge.fixture"
PACKAGES = (
    ("packages_initial", "1.0.0-1", False),
    ("packages_upgrade", "1.0.1-1", False),
    ("packages_failure", "1.0.2-1", True),
)


def _guard(root: Path, source: Path, python: Path, platform: str) -> None:
    root = root.absolute()
    expected_parent = Path(tempfile.gettempdir()).resolve()
    if (root.parent.resolve() != expected_parent or
            not re.fullmatch(r"dim-qtifw-bridge-[a-zA-Z0-9_-]{6,24}",
                             root.name) or
            root.exists() or root.is_symlink()):
        raise ValueError("QTIFW_FIXTURE_NEW_DIRECT_OS_TEMP_ROOT_REQUIRED")
    if platform != PLATFORM:
        raise ValueError("QTIFW_FIXTURE_HOST_PLATFORM_MISMATCH")
    if (not source.is_dir() or source.is_symlink() or
            not (source / "installer_engine/universal_selftest.py").is_file() or
            not (source / "installer_engine/universal_install.py").is_file()):
        raise ValueError("QTIFW_FIXTURE_EXISTING_SHARED_ENGINE_REQUIRED")
    if not python.is_file() or python.is_symlink():
        raise ValueError("QTIFW_FIXTURE_EXISTING_PYTHON_EXE_REQUIRED")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def render(root: Path, source: Path, *, platform: str = PLATFORM,
           python: Path = Path(sys.executable)) -> dict:
    """Build only metadata and empty component data folders.

    No tools are installed, no IFW binary is fetched, no operation executed.
    source is the unchanged upstream project that provides universal-selftest.
    """
    root, source = (Path(x).absolute() for x in (root, source))
    python = Path(python).resolve(strict=False)  # Follow ordinary OS interpreter aliases.
    _guard(root, source, python, platform)
    root.mkdir(mode=0o700)
    config = ET.Element("Installer")
    for field, value in (
        ("Name", "R933 Synthetic External Ownership Boundary"),
        ("Version", "1.0.0"),
        ("Title", "R933 TEST-ONLY Qt IFW External Engine Bridge"),
        ("Publisher", "Test fixture only, NOT the DIM publisher"),
        ("TargetDir", str(root / "qt-shell-root")),
        ("RemoveTargetDir", "false"),
    ):
        ET.SubElement(config, field).text = value
    config_file = root / "config/config.xml"
    config_file.parent.mkdir()
    ET.ElementTree(config).write(config_file, encoding="utf-8",
                                 xml_declaration=True)

    reports = {}
    for dirname, version, failed in PACKAGES:
        pkg = root / dirname / COMPONENT
        meta = pkg / "meta"
        data = pkg / "data"
        meta.mkdir(parents=True)
        data.mkdir()
        elem = ET.Element("Package")
        for field, value in (
            ("DisplayName", "R933 test-only Qt shell, no product payload"),
            ("Description", "Calls existing universal test engine, no code files"),
            ("Version", version),
            ("ReleaseDate", "2026-11-22"),
            ("Default", "true"),
            ("Script", "bridge.qs"),
        ):
            ET.SubElement(elem, field).text = value
        ET.ElementTree(elem).write(meta / "package.xml", encoding="utf-8",
                                   xml_declaration=True)
        arguments = [
            str(python), "-m", "installer_engine", "universal-selftest",
            "--platform", platform, "workingdirectory=" + str(source),
        ]
        script = (
            "function Component() {}\n"
            "Component.prototype.createOperations = function() {\n"
            "  component.addOperation(\"Execute\", " +
            ", ".join(json.dumps(a) for a in arguments) + ");\n"
        )
        if failed:
            # A vendor-managed failure AFTER the existing engine selftest.
            # All managed code in a different root must remain unchanged.
            fault_arguments = (
                ["/usr/bin/false"] if os.name != "nt" else
                [str(Path(os.environ["SystemRoot"]) /
                     "System32/cmd.exe"), "/C", "exit 7"]
            )
            script += (
                "  component.addOperation(\"Execute\", " +
                ", ".join(json.dumps(a) for a in fault_arguments) + ");\n"
            )
        script += "};\n"
        (meta / "bridge.qs").write_text(script, encoding="utf-8")
        if list(data.iterdir()):
            raise AssertionError("QTIFW_FIXTURE_DATA_MUST_REMAIN_EMPTY")
        reports[dirname] = {
            "version": version, "deliberate_failure": failed,
            "script_sha256": _sha(script.encode("utf8")),
            "data_files": 0,
        }

    receipt = {
        "schema": 1,
        "status": "R933_QTIFW_EXTERNAL_SHELL_RENDER_ONLY",
        "component": COMPONENT, "platform": platform,
        "engine_entrypoint": "installer_engine universal-selftest",
        "source_root": str(source), "python_executable": str(python),
        "qt_owns_product_code": False,
        "native_os_service_accepted": False,
        "publisher_authenticated": False,
        "powercut_accepted": False,
        "product_installation_accepted": False,
        "packages": reports,
        "config_sha256": _sha(config_file.read_bytes()),
    }
    (root / "fixture-receipt.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n",
        encoding="utf8",
    )
    return receipt


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--platform", choices=("linux-x86_64", "windows-x86_64"),
                   default=PLATFORM)
    a = p.parse_args()
    print(json.dumps(render(a.output, a.source, platform=a.platform),
                     sort_keys=True))
