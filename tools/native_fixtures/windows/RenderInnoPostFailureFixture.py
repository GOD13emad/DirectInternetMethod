"""R924 synthetic Inno ssPostInstall failure fixture renderer.

Only creates marker payloads and Inno scripts in a new OS-temp fixture root.
Nothing is installed on the build host. No real DIM AppId, service or source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile

APP_ID = "{BE452737-93D8-4693-930C-C0ABFF932924}"
APP_NAME = "DIM R924 Synthetic Post-Failure Fixture"
INSTALL_FOLDER = "DIM_R924_Synthetic_Inno"
MARKERS = {
    "1.5.6": b"DIM_R924_OLD_SYNTHETIC_CODE\n",
    "1.5.7": b"DIM_R924_NEW_SYNTHETIC_CODE\n",
}


def build(root: Path) -> dict:
    base = Path(tempfile.gettempdir()).resolve()
    root = Path(root).absolute()
    if not re.fullmatch(r"dim-r924-[A-Za-z0-9_-]{4,40}", root.name):
        raise ValueError("FIXTURE_ROOT_NAME_REQUIRED")
    if not root.parent.resolve() == base:
        raise ValueError("FIXTURE_ONLY_DIRECT_CHILD_OF_OS_TEMP")
    if root.exists() or root.is_symlink():
        raise ValueError("REFUSE_OVERWRITE_OR_REPLAY")
    root.mkdir()
    for version, marker in MARKERS.items():
        tag = version.replace(".", "_")
        payload = root / ("code_" + tag + ".txt")
        payload.write_bytes(marker)
        source_sha = hashlib.sha256(marker).hexdigest()
        postfail = (
            """[Code]
var
  R924PostInstallError: Boolean;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    R924PostInstallError := True;
end;

function GetCustomSetupExitCode: Integer;
begin
  if R924PostInstallError then Result := 67
  else Result := 0;
end;
"""
            if version == "1.5.7" else ""
        )
        # Exact hardcoded synthetic AppId, no script-supplied path or command.
        iss = f"""[Setup]
AppId={{{APP_ID}
AppName={APP_NAME}
AppVersion={version}
UninstallDisplayName={APP_NAME}
DefaultDirName={{autopf}}\\{INSTALL_FOLDER}
UsePreviousAppDir=yes
UninstallLogMode=overwrite
Uninstallable=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
DisableDirPage=yes
DisableWelcomePage=yes
DisableReadyPage=yes
DisableFinishedPage=yes
CloseApplications=no
RestartApplications=no
Compression=none
SolidCompression=no
OutputDir={root}
OutputBaseFilename=R924_Inno_{tag}
[Files]
Source: "{payload}"; DestDir: "{{app}}"; DestName: "code.fixture"; Flags: ignoreversion
{postfail}"""
        (root / ("R924_" + tag + ".iss")).write_text(iss, encoding="utf-8")
    info = {
        "schema": 1,
        "scope": "R924_SYNTHETIC_INNO_FAILURE_ONLY",
        "app_id": APP_ID,
        "old_marker_sha256": hashlib.sha256(MARKERS["1.5.6"]).hexdigest(),
        "new_marker_sha256": hashlib.sha256(MARKERS["1.5.7"]).hexdigest(),
        "native_product_rollback_accepted": False,
    }
    (root / "fixture.json").write_text(json.dumps(info, sort_keys=True) + "\n", encoding="utf-8")
    return info


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output), sort_keys=True))


if __name__ == "__main__":
    main()
