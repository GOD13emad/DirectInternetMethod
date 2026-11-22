"""R935 native Windows Sandbox probe inputs from existing shared R899 contract.

Test-only source assembler. No product native broker / publisher trust; the
local 'pins' are synthetic. Must be invoked only for an already built and SHA-
pinned standalone R935 fixture in a fresh direct Windows OS-temp directory.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from installer_engine.broker_intent import compare_pinned_policy_intent
from installer_engine.engine import hash_bytes
from tests.test_engine_broker_intent import fixture_contract, fixture_plan

SOURCE = Path(__file__).resolve().parents[3]
GUEST = SOURCE/"tools/native_fixtures/windows/RunR935NativeBrokerPipeSandboxFixture.ps1"
PROBE_SOURCE = SOURCE/"tools/native_fixtures/windows/R935NativePipeBoundaryFixture.cs"
EXE = "R935NativePipeBoundaryFixture.exe"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(root: Path, expected_binary_sha256: str) -> dict:
    root=root.absolute()
    if (os.name!="nt" or root.parent.resolve()!=Path(tempfile.gettempdir()).resolve()
        or not re.fullmatch(r"dim-r935-native-pipe-[a-z0-9-]{8,48}",root.name)
        or not root.is_dir() or root.is_symlink()):
        raise ValueError("R935_EXACT_EXISTING_OS_TEMP_FIXTURE_REQUIRED")
    binary=root/"input"/EXE
    if (not binary.is_file() or binary.is_symlink()
        or not re.fullmatch("[a-f0-9]{64}",expected_binary_sha256)
        or sha(binary)!=expected_binary_sha256):
        raise ValueError("R935_PREBUILT_DOTNET_PROBE_IDENTITY_MISMATCH")
    inputs=root/"input"
    if any((inputs/k).exists() for k in (
        "broker-request.json", "broker-policy.json",
        "RunR935NativeBrokerPipeSandboxFixture.ps1", "pins.json")):
        raise ValueError("R935_INPUT_OVERWRITE_NOT_ALLOWED")
    plan,policy,request,pb,rb=fixture_contract(fixture_plan("windows-x86_64"))
    result=compare_pinned_policy_intent(plan,pb,hash_bytes(pb),rb)
    if result["native_installation_accepted"] or result["privileged_broker_implemented"]:
        raise AssertionError("R935_PRODUCTION_NATIVE_AUTHORITY_FROM_SYNTHETIC_SOURCE")
    if result["request_sha256"]!=hash_bytes(rb):
        raise AssertionError("R935_SHARED_R899_REQUEST_PIN_UNBOUND")
    assert len(rb)<65536 and len(pb)<65536
    (inputs/"broker-request.json").write_bytes(rb)
    (inputs/"broker-policy.json").write_bytes(pb)
    (inputs/"RunR935NativeBrokerPipeSandboxFixture.ps1").write_bytes(GUEST.read_bytes())
    pins={
        "schema":1,
        "scope":"R935_SYNTHETIC_NATIVE_BROKER_PIPE_ONLY",
        "probe_sha256":expected_binary_sha256,
        "source_cs_sha256":sha(PROBE_SOURCE),
        "guest_runner_sha256":sha(inputs/"RunR935NativeBrokerPipeSandboxFixture.ps1"),
        "request_sha256":sha(inputs/"broker-request.json"),
        "policy_sha256":sha(inputs/"broker-policy.json"),
        "request_bytes":len(rb),
        "policy_bytes":len(pb),
        "trusted_broker_implemented":False,
        "publisher_authenticated":False,
        "native_product_installation_accepted":False,
    }
    (inputs/"pins.json").write_text(
        json.dumps(pins,sort_keys=True,indent=2)+"\n",encoding="utf8")
    if sha(inputs/"broker-request.json") != result["request_sha256"]:
        raise AssertionError("R935_OS_TEMP_REQUEST_PIN_CHANGED")
    return pins


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--expected-binary-sha256",required=True)
    a=p.parse_args()
    print(json.dumps(stage(a.root,a.expected_binary_sha256),sort_keys=True))
