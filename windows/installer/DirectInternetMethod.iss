#define MyAppName "Direct Internet Method"
#define MyAppVersion "1.3.1"
#define MyAppPublisher "Direct Internet Method"
#define MyAppExeName "DirectInternetMethod.exe"

[Setup]
AppId={{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\DirectInternetMethod
UsePreviousAppDir=yes
DefaultGroupName=Direct Internet Method
DisableProgramGroupPage=yes
OutputDir=..\..\delivery
OutputBaseFilename=DirectInternetMethod_1.3.1_Windows_Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\app\DirectInternetMethod.ico
UninstallDisplayIcon={app}\app\DirectInternetMethod.exe
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Uninstallable=yes
SetupLogging=yes
CloseApplications=yes
RestartApplications=no

[Files]
Source: "..\app\DirectInternetMethod.exe"; DestDir: "{app}\app"; Flags: ignoreversion
Source: "..\app\DirectInternetMethod.ico"; DestDir: "{app}\app"; Flags: ignoreversion
Source: "..\app\Status.ps1"; DestDir: "{app}\app"; Flags: ignoreversion
Source: "..\..\router_gateway\providers.json"; DestDir: "{app}\app\router_gateway"; Flags: ignoreversion
Source: "..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\manifest.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\RELEASE.json"; DestDir: "{app}"; Flags: ignoreversion

Source: "..\app\DirectInternetMethod.Service.exe"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\app"; Flags: ignoreversion
Source: "..\vendor\pwsh\*"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\runtime\pwsh"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\app\Start-Direct.ps1"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\app"; Flags: ignoreversion
Source: "..\app\Stop-Direct.ps1"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\app"; Flags: ignoreversion
Source: "..\app\Recovery.ps1"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\app"; Flags: ignoreversion
Source: "..\bin\ctrld\ctrld.exe"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\ctrld"; Flags: ignoreversion
Source: "..\bin\ctrld\ctrld.toml"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\ctrld"; Flags: ignoreversion
Source: "..\bin\ctrld\LICENSE.txt"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\ctrld"; Flags: ignoreversion
Source: "..\bin\zapret\winws.exe"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\WinDivert.dll"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\WinDivert64.sys"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\cygwin1.dll"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\hosts.txt"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\zapret"; Flags: ignoreversion
Source: "..\bin\zapret\LICENSE.txt"; DestDir: "{commonpf}\DirectInternetMethod\Privileged\bin\zapret"; Flags: ignoreversion

[InstallDelete]
Type: files; Name: "{app}\app\ControlPanel.cmd"
Type: files; Name: "{app}\app\ControlPanel.ps1"
Type: files; Name: "{app}\app\Start.cmd"
Type: files; Name: "{app}\app\Stop.cmd"
Type: files; Name: "{app}\app\Status.cmd"
Type: files; Name: "{app}\app\Recovery.cmd"
Type: files; Name: "{app}\app\Toggle.ps1"
Type: files; Name: "{app}\app\Start-Direct.ps1"
Type: files; Name: "{app}\app\Stop-Direct.ps1"
Type: files; Name: "{app}\app\Recovery.ps1"
Type: files; Name: "{app}\app\DirectInternetMethod.Helper.exe"
Type: filesandordirs; Name: "{app}\bin"
Type: files; Name: "{app}\is-*.tmp"
Type: files; Name: "{app}\app\is-*.tmp"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\evidence"
Type: files; Name: "{app}\is-*.tmp"
Type: files; Name: "{app}\app\is-*.tmp"
Type: dirifempty; Name: "{app}\app"
Type: dirifempty; Name: "{app}"
Type: filesandordirs; Name: "{commonpf}\DirectInternetMethod\Privileged"
Type: dirifempty; Name: "{commonpf}\DirectInternetMethod"

[Icons]
Name: "{group}\Direct Internet Method"; Filename: "{app}\app\DirectInternetMethod.exe"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.exe"
Name: "{autodesktop}\Direct Internet Method"; Filename: "{app}\app\DirectInternetMethod.exe"; WorkingDir: "{app}\app"; IconFilename: "{app}\app\DirectInternetMethod.exe"

[Run]
Filename: "{app}\app\DirectInternetMethod.exe"; Description: "Open Direct Internet Method"; Flags: nowait postinstall skipifsilent

[Code]
const
  ServiceName = 'DirectInternetMethodSvc';
  CtrldServiceName = 'ctrld';

function RunSc(Params: String; var ResultCode: Integer): Boolean;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function ServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  Result := RunSc('query "' + ServiceName + '"', ResultCode) and (ResultCode = 0);
end;

function CtrldServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  Result := RunSc('query "' + CtrldServiceName + '"', ResultCode) and (ResultCode = 0);
end;

function CtrldServiceOwned(): Boolean;
var
  ImagePath: String;
  OwnedExe: String;
begin
  Result := False;
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\' + CtrldServiceName, 'ImagePath', ImagePath) then
    exit;
  OwnedExe := ExpandConstant('{commonpf}\DirectInternetMethod\Privileged\bin\ctrld\ctrld.exe');
  Result := Pos(LowerCase(OwnedExe), LowerCase(ImagePath)) > 0;
end;

procedure StopCtrldServiceIfOwned();
var
  ResultCode: Integer;
begin
  if CtrldServiceExists() and CtrldServiceOwned() then
  begin
    RunSc('stop "' + CtrldServiceName + '"', ResultCode);
    Sleep(1200);
  end;
end;

procedure InstallOrUpdateCtrldService();
var
  ResultCode: Integer;
  CtrldExe: String;
  CtrldConfig: String;
  BinPath: String;
  Params: String;
begin
  CtrldExe := ExpandConstant('{commonpf}\DirectInternetMethod\Privileged\bin\ctrld\ctrld.exe');
  CtrldConfig := ExpandConstant('{commonappdata}\DirectDnsDpiHarness\ctrld\ctrld.toml');
  BinPath := '\"' + CtrldExe + '\" run -s -c \"' + CtrldConfig + '\"';

  if CtrldServiceExists() and (not CtrldServiceOwned()) then
    RaiseException('A different Windows service named ctrld already exists. Direct Internet Method will not overwrite it.');

  if not CtrldServiceExists() then
  begin
    Params := 'create "' + CtrldServiceName + '" binPath= "' + BinPath + '" start= demand DisplayName= "Direct Internet Method DNS Helper"';
    if (not RunSc(Params, ResultCode)) or (ResultCode <> 0) then
      RaiseException('Unable to create owned ctrld service. sc.exe exit=' + IntToStr(ResultCode));
  end
  else
  begin
    Params := 'config "' + CtrldServiceName + '" binPath= "' + BinPath + '" start= demand DisplayName= "Direct Internet Method DNS Helper"';
    if (not RunSc(Params, ResultCode)) or (ResultCode <> 0) then
      RaiseException('Unable to update owned ctrld service. sc.exe exit=' + IntToStr(ResultCode));
  end;

  RunSc('description "' + CtrldServiceName + '" "Owned DNS helper for Direct Internet Method; do not start manually"', ResultCode);
  RunSc('failure "' + CtrldServiceName + '" reset= 0 actions= ""', ResultCode);
end;

procedure StopServiceIfPresent();
var
  ResultCode: Integer;
begin
  if ServiceExists() then
  begin
    RunSc('stop "' + ServiceName + '"', ResultCode);
    Sleep(1200);
  end;
end;

procedure InstallOrUpdateService();
var
  ResultCode: Integer;
  ServiceExe: String;
  Params: String;
  Sddl: String;
begin
  ServiceExe := ExpandConstant('{commonpf}\DirectInternetMethod\Privileged\app\DirectInternetMethod.Service.exe');

  if not ServiceExists() then
  begin
    Params := 'create "' + ServiceName + '" binPath= "' + ServiceExe + '" start= auto DisplayName= "Direct Internet Method Service"';
    if (not RunSc(Params, ResultCode)) or (ResultCode <> 0) then
      RaiseException('Unable to create Direct Internet Method service. sc.exe exit=' + IntToStr(ResultCode));
  end
  else
  begin
    Params := 'config "' + ServiceName + '" binPath= "' + ServiceExe + '" start= auto DisplayName= "Direct Internet Method Service"';
    if (not RunSc(Params, ResultCode)) or (ResultCode <> 0) then
      RaiseException('Unable to update Direct Internet Method service. sc.exe exit=' + IntToStr(ResultCode));
  end;

  RunSc('description "' + ServiceName + '" "Privilege-separated backend for Direct Internet Method"', ResultCode);

  Sddl := 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCCR;;;IU)';
  if (not RunSc('sdset "' + ServiceName + '" "' + Sddl + '"', ResultCode)) or (ResultCode <> 0) then
    RaiseException('Unable to set Direct Internet Method service permissions. sc.exe exit=' + IntToStr(ResultCode));

  RunSc('failure "' + ServiceName + '" reset= 86400 actions= restart/5000/restart/10000', ResultCode);
  RunSc('failureflag "' + ServiceName + '" 1', ResultCode);

  if (not RunSc('start "' + ServiceName + '"', ResultCode)) or ((ResultCode <> 0) and (ResultCode <> 1056)) then
    RaiseException('Unable to start Direct Internet Method service. sc.exe exit=' + IntToStr(ResultCode));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  StatePath: String;
begin
  StatePath := ExpandConstant('{commonappdata}\DirectDnsDpiHarness\state.json');
  if FileExists(StatePath) then
  begin
    Result := 'Direct Internet Method is active. Use Stop or Recovery before installing/upgrading.';
    exit;
  end;
  if CtrldServiceExists() and (not CtrldServiceOwned()) then
  begin
    Result := 'A different Windows service named ctrld already exists. Direct Internet Method will not overwrite it.';
    exit;
  end;
  StopCtrldServiceIfOwned();
  StopServiceIfPresent();
  Result := '';
end;

procedure CompletePendingDirectUpdate();
var
  PendingPath: String;
  StatusPath: String;
  TempPath: String;
  Payload: String;
begin
  PendingPath := ExpandConstant('{commonappdata}\DirectInternetMethod\pending-update.json');
  if not FileExists(PendingPath) then
    exit;

  StatusPath := ExpandConstant('{commonappdata}\DirectInternetMethod\action-status.json');
  TempPath := StatusPath + '.tmp';
  Payload := '{"schema":1,"action":"update","phase":"done","exitCode":0,"message":"Updated to v{#MyAppVersion}.","updatedUtc":"installer-postinstall"}';
  if not SaveStringToFile(TempPath, Payload, False) then
    RaiseException('Unable to write direct-update completion status.');
  if FileExists(StatusPath) then
    DeleteFile(StatusPath);
  if not RenameFile(TempPath, StatusPath) then
    RaiseException('Unable to promote direct-update completion status.');
  DeleteFile(PendingPath);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallOrUpdateCtrldService();
    InstallOrUpdateService();
    CompletePendingDirectUpdate();
  end;
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
  ScriptPath: String;
  PwshPath: String;
  StatePath: String;
  Args: String;
begin
  StatePath := ExpandConstant('{commonappdata}\DirectDnsDpiHarness\state.json');
  if FileExists(StatePath) then
  begin
    ScriptPath := ExpandConstant('{commonpf}\DirectInternetMethod\Privileged\app\Recovery.ps1');
    if not FileExists(ScriptPath) then
    begin
      MsgBox('Direct Method is active but the protected Recovery backend is missing. Uninstall was cancelled to avoid leaving network state behind.', mbError, MB_OK);
      Result := False;
      exit;
    end;

    PwshPath := ExpandConstant('{commonpf}\DirectInternetMethod\Privileged\runtime\pwsh\pwsh.exe');
    if not FileExists(PwshPath) then
    begin
      MsgBox('Direct Method is active but the protected bundled PowerShell runtime is missing. Uninstall was cancelled to avoid leaving network state behind.', mbError, MB_OK);
      Result := False;
      exit;
    end;
    Args := '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + ScriptPath + '"';
    if (not Exec(PwshPath, Args, ExtractFileDir(ScriptPath), SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
    begin
      MsgBox('Recovery did not complete. Uninstall was stopped to avoid leaving network state behind.', mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;

  StopCtrldServiceIfOwned();
  StopServiceIfPresent();
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopCtrldServiceIfOwned();
    if CtrldServiceExists() and CtrldServiceOwned() then
      RunSc('delete "' + CtrldServiceName + '"', ResultCode);
    StopServiceIfPresent();
    RunSc('delete "' + ServiceName + '"', ResultCode);
    Sleep(500);
  end;
end;
