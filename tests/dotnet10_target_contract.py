#!/usr/bin/env python3
"""R482 exact .NET 10 LTS framework, build and same-product-version negative tests.

Existing public v1.5.3 release remains immutable. Source-only upgrade is not a new release.
"""
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
TARGET="net10.0-windows"
PROJECTS=("windows/gui/DirectInternetMethod.csproj","windows/service/DirectInternetMethod.Service.csproj")
CI=ROOT/".github/workflows/ci.yml"

def inspect(raw,project):
    tree=ET.fromstring(raw)
    target=tree.find(".//TargetFramework")
    version=tree.find(".//Version")
    output=tree.find(".//OutputType")
    assert target is not None and target.text==TARGET,(project,"TargetFramework")
    assert version is not None and version.text=="1.5.3",(project,"product_version_guard")
    assert output is not None and output.text=="WinExe",(project,"runtime_subsystem")
    if "/gui/" in project:
        wpf=tree.find(".//UseWPF")
        assert wpf is not None and wpf.text=="true",(project,"WPF_preserved")
    return True

def negative_first():
    for project in PROJECTS:
        data=(ROOT/project).read_bytes()
        inspect(data,project)
        assert data.count(b"net10.0-windows")==1
        assert b"net8.0-windows" not in data
        # In-memory source mutations must be rejected before packaging.
        for wrong in (b"net8.0-windows",b"net9.0-windows",b"net11.0-windows"):
            try:inspect(data.replace(b"net10.0-windows",wrong),project)
            except AssertionError:pass
            else:raise AssertionError(("FAIL_OPEN_VERSION_DRIFT",project,wrong))
        try:inspect(data.replace(b"<Version>1.5.3</Version>",b"<Version>1.5.2</Version>"),project)
        except AssertionError:pass
        else:raise AssertionError(("FAIL_OPEN_PRODUCT_VERSION_DRIFT",project))

def main():
    negative_first()
    ci=CI.read_text("utf-8")
    assert ci.count("dotnet-version: '10.0.x'")==1
    assert "dotnet-version: '8.0.x'" not in ci
    assert ci.count("python -B tests/dotnet10_target_contract.py")==1
    assert ci.count("dotnet build windows/gui/DirectInternetMethod.csproj")==1
    assert ci.count("dotnet build windows/service/DirectInternetMethod.Service.csproj")==1
    print("PASS_R482_NET10_TWO_PROJECTS_SDK_PIN_AND_8_NEGATIVE_FIXTURES")
if __name__=="__main__":main()
