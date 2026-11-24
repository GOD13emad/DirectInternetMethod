"""R930 build-only SHA-pinned synthetic Inno6 + Windows SCM SERVICE fixture.

Creates native EXEs in one unused direct child of OS TEMP. Never registers,
starts, stops or installs any Windows service or Inno on the build host.
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

from tools.native_fixtures.windows.BuildUniversalInnoSandboxInputs import render

SERVICE = "DIMR887IsolatedFixtureSvc"
SOURCE = Path(__file__).with_name("ScmFixtureService.cs")


def digest(f: Path) -> str:
    return hashlib.sha256(f.read_bytes()).hexdigest()


def build(root: Path) -> dict:
    root = Path(root).absolute()
    if root.parent.resolve() != Path(tempfile.gettempdir()).resolve() or \
            not re.fullmatch(r"dim-r924-r929-r930-[A-Za-z0-9_-]{4,24}", root.name):
        raise ValueError("R930_SYNTHETIC_DIRECT_OS_TEMP_REQUIRED")
    render(root)
    csc = Path(os.environ["SystemRoot"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    lib = csc.with_name("System.ServiceProcess.dll")
    if not csc.is_file() or not lib.is_file() or not SOURCE.is_file():
        raise RuntimeError("R930_NATIVE_CSC_FRAMEWORK_SOURCE_MISSING")
    for version, flag in (("1.5.6", None), ("1.5.7", "VERSION_157")):
        exe = root / ("ScmFixture-" + version + ".exe")
        args = [str(csc), "/nologo", "/target:exe", "/optimize+",
                "/r:" + str(lib), "/out:" + str(exe)]
        if flag:
            args.append("/define:" + flag)
        args.append(str(SOURCE))
        p = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if p.returncode:
            raise RuntimeError("R930_CSC_NATIVE_SERVICE_BUILD_FAILED_"+version+
                               (p.stderr+p.stdout)[-800:])
        observed = subprocess.run([str(exe), "--version"], text=True,
                                  capture_output=True, timeout=15)
        if observed.returncode or observed.stdout.strip() != version:
            raise RuntimeError("R930_NATIVE_SERVICE_VERSION_MISMATCH_"+version)
    pins = {
        "schema": 1, "scope": "R930_SYNTHETIC_SCM_ONLY", "name": SERVICE,
        "old_sha256": digest(root/"ScmFixture-1.5.6.exe"),
        "new_sha256": digest(root/"ScmFixture-1.5.7.exe"),
    }
    (root/"scm-pins.json").write_text(
        json.dumps(pins, sort_keys=True)+"\n", encoding="utf8")
    return pins


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    opts = parser.parse_args()
    print(json.dumps(build(opts.output), sort_keys=True))
