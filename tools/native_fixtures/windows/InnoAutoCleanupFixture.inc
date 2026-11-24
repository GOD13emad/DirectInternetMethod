// R882 fixture ONLY, no SCM registration and no production AppId.
// Installed engine copied to Inno temp before [Files] deletion.
var
  DIMUninstallCopy: String;
  DIMUninstallPrepared: Boolean;

function InitializeUninstall(): Boolean;
var
  Code: Integer;
begin
  Result := False;
  DIMUninstallPrepared := False;
  DIMUninstallCopy := ExpandConstant('{tmp}\dim-universal-uninstall.exe');
  if not FileCopy(
      ExpandConstant('{app}\engine\dim-universal-engine.exe'),
      DIMUninstallCopy, False) then
  begin
    Log('R882_REFUSED_ENGINE_COPY');
    Exit;
  end;
  if (not Exec(DIMUninstallCopy, 'uninstall-prepare --root "' +
      ExpandConstant('{app}\managed') +
      '" --platform windows-x86_64 --quiesced', '',
      SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
  begin
    Log('R882_REFUSED_PREPARE');
    Exit;
  end;
  DIMUninstallPrepared := True;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep <> usDone then Exit;
  if not DIMUninstallPrepared then
    RaiseException('R882_NO_VERIFIED_UNINSTALL_PREPARATION');
  // Do not accept an Inno uninstall until native AppId is removed.
  if RegKeyExists(HKCU, '@FIXTURE_UNINSTALL_REGISTRY_PATH@') or
     RegKeyExists(HKLM, '@FIXTURE_UNINSTALL_REGISTRY_PATH@') then
    RaiseException('R882_NATIVE_INNO_REGISTRATION_STILL_EXISTS');
  if (not Exec(DIMUninstallCopy, 'uninstall-commit --root "' +
      ExpandConstant('{app}\managed') +
      '" --platform windows-x86_64 --native-unregistered', '',
      SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
    RaiseException('R882_CODE_ONLY_FINALIZATION_FAILED');
  DIMUninstallPrepared := False;
  Log('R882_NATIVE_UNINSTALL_AUTOCLEAN_PASS');
end;
