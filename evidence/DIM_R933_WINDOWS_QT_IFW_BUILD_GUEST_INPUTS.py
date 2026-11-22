"""Synthetic-only R933 Windows Sandbox Qt IFW guest package generator.

Vendor Qt binarycreator/repogen are used UNMODIFIED. No product files,
SCM service, owner user directories, root credentials or installer registry
on the Windows host are touched. This only builds files for a disposable
network-disabled Windows Sandbox.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from xml.etree import ElementTree as E

ROOT = Path(tempfile.gettempdir())/"dim-r933-qtifw-win-vendor-20261122"
assert ROOT.parent.resolve() == Path(tempfile.gettempdir()).resolve()
assert ROOT.is_dir() and not ROOT.is_symlink()
ARCHIVE=ROOT/"qt-ifw-win-official.7z"
assert ARCHIVE.is_file()
assert ARCHIVE.stat().st_size == 54044474
def sha(f):
    return hashlib.sha256(f.read_bytes()).hexdigest()
assert sha(ARCHIVE) == "a8d18072fbcc99362e6972c924be aab4f0fb08a24dde27970de5d55f682f9b6f".replace(" ","")
BIN=ROOT/"Tools/QtInstallerFramework/4.7/bin"
assert (BIN/"binarycreator.exe").stat().st_size == 34678784
assert (BIN/"repogen.exe").stat().st_size == 28214272
ENGINE=ROOT/"frozen/dist/dim-universal-engine.exe"
assert ENGINE.is_file()
assert sha(ENGINE)=="0bd3879668b9e91d501c5b494bdc3d5fd7bc5b62e2cabe443b362d81e9bff534"
INPUT=ROOT/"input"
OUT=ROOT/"output"
assert not INPUT.exists() and not OUT.exists()
INPUT.mkdir()
OUT.mkdir()
TARGET="C:/DIMR933/qt-shell"
ENGINE_GUEST="C:/DIMR933/input/dim-universal-engine.exe"
COMP="org.dim.bridge.fixture"
CONF=ROOT/"config"
CONF.mkdir()
conf=E.Element("Installer")
for tag,val in (("Name","R933 Synthetic Vendor Shell Windows"),("Version","1.0.0"),
                ("Title","R933 TEMP ONLY Native Qt Shell Bridge"),
                ("Publisher","R933 Disposable Test Fixture Only"),
                ("TargetDir",TARGET),("RemoveTargetDir","false")):
    E.SubElement(conf,tag).text=val
E.ElementTree(conf).write(CONF/"config.xml",encoding="utf8",xml_declaration=True)
for pkg,version,bad in (("packages-100","1.0.0-1",False),
                         ("packages-101","1.0.1-1",False),
                         ("packages-102","1.0.2-1",True)):
    p=ROOT/pkg/COMP
    meta=p/"meta"
    meta.mkdir(parents=True)
    data=p/"data"
    data.mkdir()
    pack=E.Element("Package")
    for tag,val in (("DisplayName","R933 Synthetic Vendor Qt Metadata Only"),
                    ("Description","No DIM managed app payload; calls existing shared kernel"),
                    ("Version",version),("ReleaseDate","2026-11-22"),
                    ("Default","true"),("Script","bridge.qs")):
        E.SubElement(pack,tag).text=val
    E.ElementTree(pack).write(meta/"package.xml",encoding="utf8",xml_declaration=True)
    text='''function Component() {}
Component.prototype.createOperations = function() {
  component.addOperation("Execute", "C:/DIMR933/input/dim-universal-engine.exe",
                         "universal-selftest", "--platform", "windows-x86_64");
'''
    if bad:
        text+='  component.addOperation("Execute", "C:/Windows/System32/cmd.exe", "/C", "exit 7");\n'
    text+="};\n"
    (meta/"bridge.qs").write_text(text,encoding="utf8")
    assert not list(data.iterdir())
    assert "component.createOperations()" not in text
shutil.copyfile(ENGINE,INPUT/"dim-universal-engine.exe")
def run(label,cmd):
    proc=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
    (ROOT/(label+".out.txt")).write_text(proc.stdout+"\nSTDERR\n"+proc.stderr,encoding="utf8")
    if proc.returncode:
        raise RuntimeError(label+" failed "+str(proc.returncode)+" "+proc.stderr[-1400:])
run("binarycreator", [str(BIN/"binarycreator.exe"),"-c",str(CONF/"config.xml"),
                      "-p",str(ROOT/"packages-100"),str(INPUT/"qt-shell-setup.exe")])
assert (INPUT/"qt-shell-setup.exe").is_file()
for num,p in (("101","packages-101"),("102","packages-102")):
    run("repogen-"+num,[str(BIN/"repogen.exe"),"-p",str(ROOT/p),str(INPUT/("repository-"+num))])
    assert (INPUT/("repository-"+num)/"Updates.xml").is_file()
pins={
    "schema":1,
    "scope":"R933_WINDOWS_SANDBOX_QT_VENDOR_METADATA_ONLY",
    "project_source_head":"308faa0e08b7803a7f96a417128ddd36aef2237f",
    "vendor":"Qt Installer Framework",
    "vendor_version":"4.7.0",
    "vendor_archive_sha256":sha(ARCHIVE),
    "frozen_engine_sha256":sha(INPUT/"dim-universal-engine.exe"),
    "frozen_engine_bytes":(INPUT/"dim-universal-engine.exe").stat().st_size,
    "vendor_qt_setup_sha256":sha(INPUT/"qt-shell-setup.exe"),
    "vendor_qt_setup_bytes":(INPUT/"qt-shell-setup.exe").stat().st_size,
    "synthetic_component":COMP,
    "qt_product_payload_file_count":0,
    "network_enabled":False,
    "product_installed":False,
    "publisher_authenticated":False,
}
(INPUT/"native-pins.json").write_text(json.dumps(pins,sort_keys=True,indent=2)+"\n",encoding="utf8")
print(json.dumps(pins,sort_keys=True))
