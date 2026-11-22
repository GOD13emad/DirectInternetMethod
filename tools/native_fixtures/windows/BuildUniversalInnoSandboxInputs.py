"""R929: build three SHA-pinned *synthetic* native Inno executables for Sandbox.

No host installation or privilege changes. Reuses the exact R924 AppId,
synthetic markers and R924 postinstall-failure renderer, with a new healthy
1.5.7 variant. Output must be an unused direct child of OS TEMP.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from tools.native_fixtures.windows.RenderInnoPostFailureFixture import (
    APP_ID, build,
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render(root: Path) -> dict:
    root = Path(root).absolute()
    base = Path(tempfile.gettempdir()).resolve()
    if root.parent.resolve() != base or not re.fullmatch(
            r"dim-r924-r929-[A-Za-z0-9_-]{4,26}", root.name):
        raise ValueError("R929_TEMP_ONLY_SYNTHETIC_ROOT")
    build(root)
    broken = (root / "R924_1_5_7.iss").read_text("utf8")
    if broken.count("[Code]\n") != 1 or broken.count(
            "OutputBaseFilename=R924_Inno_1_5_7") != 1:
        raise ValueError("R929_SOURCE_INNO_SCRIPT_CHANGED")
    healthy = broken.split("[Code]\n", 1)[0].replace(
        "OutputBaseFilename=R924_Inno_1_5_7",
        "OutputBaseFilename=R929_Inno_1_5_7_good")
    (root / "R929_1_5_7_good.iss").write_text(
        healthy, encoding="utf8")
    compiler = Path(os.environ["LOCALAPPDATA"]) / "Programs/Inno Setup 6/ISCC.exe"
    if not compiler.is_file():
        raise RuntimeError("R929_INNO6_COMPILER_MISSING")
    for name in ("R924_1_5_6", "R924_1_5_7", "R929_1_5_7_good"):
        result = subprocess.run(
            [str(compiler), str(root / (name + ".iss"))],
            capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError("R929_COMPILER_" + name +
                               (result.stdout + result.stderr)[-1000:])
    pins = {"schema": 1, "scope": "R929_SYNTHETIC_INNO_THREE_PACKAGES",
            "app_id": APP_ID,
            "old": sha(root / "R924_Inno_1_5_6.exe"),
            "failed": sha(root / "R924_Inno_1_5_7.exe"),
            "good": sha(root / "R929_Inno_1_5_7_good.exe")}
    (root / "inno-pins.json").write_text(
        json.dumps(pins, sort_keys=True) + "\n", encoding="utf8")
    return pins


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(render(args.output), sort_keys=True))
