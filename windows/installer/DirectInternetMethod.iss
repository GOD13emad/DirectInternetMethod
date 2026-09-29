#define MyAppName "Direct Internet Method"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Local"
#define MyAppExeName "ControlPanel.cmd"

[Setup]
AppId={{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\DirectInternetMethod
DefaultGroupName=Direct Internet Method
DisableProgramGroupPage=yes
OutputDir=..\..\delivery
OutputBaseFilename=DirectInternetMethod_1.0.0_Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\app\DirectInternetMethod.ico
PrivilegesRequired=lowest
Uninstallable=yes
SetupLogging=yes
CloseApplications=yes
RestartApplications=no

[Files]
Source: "..\app\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\bin\ctrld\ctrld.exe"; DestDir: "{app}\bin\ctrld"; Flags: ignoreversion
Source: "..\bin\ctrld\ctrld.toml"; DestDir: "{app}\bin\ctrld"; Flags: ignoreversion
Source: "..\bin\ctrld\LICENSE.txt"; DestDir: "{app}\bin\ctrld"; Flags: ignoreversion
Source: "..\bin\zapret\winws.exe"; DestDir: "{app}\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\WinDivert.dll"; DestDir: "{app}\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\WinDivert64.sys"; DestDir: "{app}\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\cygwin1.dll"; DestDir: "{app}\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\hosts.txt"; DestDir: "{app}\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\LICENSE.txt"; DestDir: "{app}\bin\zapret"; Flags: ignoreversion
Source: "..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\manifest.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\RELEASE.json"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Direct Internet Method"; Filename: "{app}\app\ControlPanel.cmd"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.ico"
Name: "{group}\Start Direct Internet"; Filename: "{app}\app\Start.cmd"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.ico"
Name: "{group}\Stop Direct Internet"; Filename: "{app}\app\Stop.cmd"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.ico"
Name: "{group}\Status"; Filename: "{app}\app\Status.cmd"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.ico"
Name: "{group}\Emergency Recovery"; Filename: "{app}\app\Recovery.cmd"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.ico"
Name: "{autodesktop}\Direct Internet Method"; Filename: "{app}\app\ControlPanel.cmd"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.ico"

[Run]
Filename: "{app}\app\ControlPanel.cmd"; Description: "Open Direct Internet Method"; Flags: nowait postinstall skipifsilent

[Code]
function PowerShell7Available(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{cmd}'), '/C where pwsh.exe >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function InitializeSetup(): Boolean;
begin
  if not PowerShell7Available() then
  begin
    MsgBox('PowerShell 7 (pwsh.exe) is required before installing Direct Internet Method.', mbError, MB_OK);
    Result := False;
    exit;
  end;
  Result := True;
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
  ScriptPath: String;
  Args: String;
begin
  ScriptPath := ExpandConstant('{app}\app\Recovery.ps1');
  if not FileExists(ScriptPath) then
  begin
    Result := True;
    exit;
  end;
  Args := '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '"';
  if Exec('pwsh.exe', Args, ExpandConstant('{app}\app'), SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
  begin
    Result := True;
  end
  else
  begin
    MsgBox('Recovery did not complete. Uninstall was stopped to avoid leaving network state behind.', mbError, MB_OK);
    Result := False;
  end;
end;
