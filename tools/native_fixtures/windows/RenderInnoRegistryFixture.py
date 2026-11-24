"""Render isolated, non-product, Inno 6 registration-only fixture (R892).

The AppId is a fixed synthetic GUID unrelated to DirectInternetMethod.
Only one owned marker is installed; no service, DNS or product code is touched.
"""
from __future__ import annotations

import argparse
from pathlib import Path

APP_ID = "{E8039748-26D7-4E64-ACEF-3E24B708B9A2}"
NAME = "DIM R892 Isolated Inno Registry Fixture"


def render(version: str, marker: Path, output_dir: Path, script: Path) -> None:
    if version not in ("1.5.6", "1.5.7"):
        raise ValueError("R892_SYNTHETIC_VERSIONS_ONLY")
    if not marker.is_file() or not output_dir.is_dir():
        raise ValueError("R892_MARKER_OR_OUTPUT_MISSING")
    if script.exists() or script.is_symlink():
        raise ValueError("R892_SCRIPT_DESTINATION_EXISTS")
    # Inno doubles the opening brace of a literal GUID AppId.
    escaped_appid = "{" + APP_ID
    text = f"""[Setup]
AppId={escaped_appid}
AppName={NAME}
AppVersion={version}
UninstallDisplayName={NAME}
DefaultDirName={{autopf}}\\DIM_R892_Isolated_Inno
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
OutputDir={output_dir}
OutputBaseFilename=R892_Inno_{version.replace(".", "_")}
[Files]
Source: "{marker}"; DestDir: "{{app}}"; DestName: "synthetic.marker"; Flags: ignoreversion
"""
    script.write_text(text, encoding="utf-8")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--version", required=True)
    p.add_argument("--marker", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--script", type=Path, required=True)
    args = p.parse_args()
    render(args.version, args.marker, args.output_dir, args.script)


if __name__ == "__main__":
    main()
