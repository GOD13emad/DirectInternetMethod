#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,re,sys
R=Path(__file__).resolve().parents[1]
W=R/"windows"
def txt(rel): return (W/rel).read_text(encoding="utf-8-sig")
start,stop,recovery,status,iss=map(txt,["app/Start-Direct.ps1","app/Stop-Direct.ps1","app/Recovery.ps1","app/Status.ps1","installer/DirectInternetMethod.iss"])
gui=txt("gui/MainWindow.xaml.cs"); xaml=txt("gui/MainWindow.xaml")
svc=txt("service/Program.cs"); client=txt("gui/ServiceClient.cs"); updater=txt("gui/UpdateClient.cs")
manifest=json.loads(txt("manifest.json"))
D={"schema":2,"status":"PASS","checks":{},"hashes":{}}
def check(name,cond):
    D["checks"][name]=bool(cond)
    if not cond:D["status"]="FAIL"
def idx(s,x): return s.find(x)

check("start_refuses_broad_tunnel_before_mutation", idx(start,"REFUSE_BROAD_TUNNEL_ROUTE")>=0 and idx(start,"REFUSE_BROAD_TUNNEL_ROUTE") < idx(start,"New-NetIPAddress"))
check("loopback_index_dynamic", all("DestinationPrefix '::1/128'" in x and "$LoopbackIndex=[int]$LoopbackRoute.InterfaceIndex" in x and "$LoopbackIndex=1" not in x for x in (start,stop,recovery)) and "DestinationPrefix '::1/128'" in status and "InterfaceIndex 1" not in status)
check("no_adapter_dns_set", "Set-DnsClientServerAddress" not in start+stop+recovery)
check("no_default_route_create", not re.search(r'(New-NetRoute|route\.exe\s+add|netsh\s+interface\s+ipv4\s+add\s+route)',start,re.I))
check("start_adapter_dns_regression", "ADAPTER_DNS_CHANGED" in start)
check("start_winhttp_regression", "WINHTTP_PROXY_CHANGED" in start)
check("start_ics_regression", "ICS_CHANGED_LIVE" in start and "ICS_CHANGED_DURING_DNS_STAGE" in start)
check("start_rollback", "Rollback $state" in start and "START_FAIL_" in start)
check("start_exact_process_argument_boundaries", "Start-ExactProcess" in start and "ProcessStartInfo" in start and "$psi.ArgumentList.Add" in start and "Start-Process -FilePath $Ctrld" not in start and "Start-Process -FilePath $Winws" not in start)
check("ctrld_scm_owned_service_architecture", "$CtrldServiceName='ctrld'" in start and "Start-OwnedCtrldService" in start and "CTRLD_SERVICE_PROCESS_OWNERSHIP_MISMATCH" in start and "$cp=Start-ExactProcess $Ctrld" not in start)
check("ctrld_external_service_fail_closed", "REFUSE_EXTERNAL_CTRLD_SERVICE" in start and "REFUSE_EXTERNAL_CTRLD_SERVICE" in stop and "REFUSE_EXTERNAL_CTRLD_SERVICE" in recovery)
check("ctrld_stop_recovery_service_managed", "Stop-OwnedCtrldService" in stop and "Stop-OwnedCtrldService" in recovery)
check("stop_preserves_external_routes", "STOP_MUTATED_EXTERNAL_ROUTES" in stop)
check("stop_preserves_external_nrpt", "STOP_MUTATED_EXTERNAL_NRPT" in stop)
check("stop_preserves_adapter_dns", "STOP_MUTATED_ADAPTER_DNSV4" in stop and "STOP_MUTATED_ADAPTER_DNSV6" in stop)
check("stop_no_state_does_not_remove_ula", "ULA is not removed without state ownership evidence." in stop)
check("recovery_state_root_guard", "STATE_ROOT_OWNERSHIP_MISMATCH" in recovery)
check("recovery_exact_orphan_ula_guard", all(x in recovery for x in ("ULA_OWNERSHIP_AMBIGUOUS","ULA_OWNERSHIP_MISMATCH","$ownedUla","Remove-NetIPAddress","RECOVERY_INCOMPLETE")))
check("status_pid_name_ownership", "Get-PidHealth" in status and "ProcessName" in status)
check("status_external_conflict", all(x in status for x in ("CONFLICT","BLOCKED","VPN/tunnel")))
check("status_fast_primitives", "Win32_SystemDriver" not in status and "Win32_Service" not in status)

check("ui_native_exe_hidden_status_backend", "bundledPwshPath" in gui and '"Privileged", "runtime", "pwsh", "pwsh.exe"' in gui and "CreateNoWindow = true" in gui and "UseShellExecute = false" in gui)
check("ui_no_external_pwsh_dependency", 'ProcessStartInfo("pwsh.exe"' not in gui)
check("ui_no_direct_runas", 'Verb = "runas"' not in gui)
check("ui_uses_service_client", 'ServiceClient.Send(action)' in gui)
check("ui_waits_service_completion", "WaitForActionAsync" in gui and "action-status.json" in gui)
check("ui_blocked_state", '"BLOCKED"' in gui and "Disconnect external VPN/tunnel to Start" in gui)
check("ui_vector_hero", "<Viewbox" in xaml and "زن زندگی آزادی" in xaml)
check("ui_preferred_startup_size_1289x632", 'Width="1289"' in xaml and 'Height="632"' in xaml and 'SizeToContent="Manual"' in xaml)
check("ui_layout_rounding", 'UseLayoutRounding="True"' in xaml and 'SnapsToDevicePixels="True"' in xaml)
check("ui_footer_responsive_no_stack_overflow", '<WrapPanel Orientation="Horizontal">' in xaml and 'TextWrapping="Wrap"' in xaml and '<ColumnDefinition Width="360"/>' in xaml)
check("ui_direct_update_service_handoff", 'ServiceClient.Send("update")' in gui and 'ServiceClient.Send("recovery")' in gui and '"handoff"' in gui and "300000" in gui and "DownloadVerifiedAsync" not in gui and "LaunchInstaller" not in gui)
check("ui_update_advisory_release_digest", "InstallerDigest" in updater and "digest" in updater and "SHA256SUMS.txt" in updater and "DownloadVerifiedAsync" not in updater and "Process.Start" not in updater)

check("service_custom_controls", all(x in svc for x in ("CTRL_START = 128","CTRL_STOP = 129","CTRL_RECOVERY = 130","CTRL_UPDATE = 131")) and "case CTRL_UPDATE:" in svc and "_ = Task.Run(RunUpdateAsync)" in svc)
check("service_direct_update_security", all(x in svc for x in ("LatestReleaseApi","SHA256SUMS.txt","ApiSha256","SHA256.HashDataAsync","CryptographicException","GetLatestUpdateAsync","ParseExpectedSha256")) and "expected.Equals(package.ApiSha256" in svc and "actual.Equals(expected" in svc)
check("service_direct_update_atomic_download", '".part"' in svc and "DownloadWithSystemCurlAsync" in svc and '"-L", "--fail", "--silent", "--show-error"' in svc and '"--max-time", "210"' in svc and "File.Move(partPath, finalPath, true)" in svc)
check("service_direct_update_silent_installer", all(x in svc for x in ('"/VERYSILENT"','"/SUPPRESSMSGBOXES"','"/NORESTART"','"/NORESTARTAPPLICATIONS"','"/CLOSEAPPLICATIONS"','"/SP-"')) and "UseShellExecute = false" in svc and 'Verb = "runas"' not in svc)
check("service_direct_update_requires_clean_off", "NetworkStatePath" in svc and "Direct Method must be OFF before update." in svc)
check("service_direct_update_post_restart_finalize", "PendingUpdatePath" in svc and "FinalizePendingUpdate()" in svc and '"update", "done"' in svc and "targetVersion" in svc)
check("service_direct_update_preserves_registered_user_install", "GetRegisteredInstallDirectory" in svc and "Registry.LocalMachine.OpenSubKey" in svc and "InstallLocation" in svc and '"/DIR=" + installDir' in svc and "DirectInternetMethod.exe" in svc and "manifest.json" in svc)
check("service_action_gate", "SemaphoreSlim ActionGate" in svc and "WaitAsync(0)" in svc)
check("service_action_status", "action-status.json" in svc and "WriteActionStatus" in svc and 'phase = "done"' not in svc)
check("service_fixed_scripts", all(x in svc for x in ('RunActionAsync("Start-Direct.ps1"','RunActionAsync("Stop-Direct.ps1"','RunActionAsync("Recovery.ps1"')))
check("service_hidden_backend", "CreateNoWindow = true" in svc and "WindowStyle = ProcessWindowStyle.Hidden" in svc)
check("service_bundled_pwsh_only", '"runtime", "pwsh", "pwsh.exe"' in svc and 'return File.Exists(p) ? p : "pwsh.exe"' not in svc)
check("service_action_timeout_guard", "WaitForExit(120000)" in svc and "Kill(entireProcessTree: true)" in svc and "exceeded the 120 second safety timeout" in svc)
check("service_action_completion_no_inherited_pipe_deadlock", "RedirectStandardOutput = true" not in svc and "RedirectStandardError = true" not in svc and "ReadToEndAsync" not in svc and 'Log($"action-end:{actionName}:exit={p.ExitCode}")' in svc)
check("ui_wait_timeout_exceeds_service_timeout", "int timeoutMs = 130000" in gui)
check("client_minimum_access", "SERVICE_QUERY_STATUS | SERVICE_USER_DEFINED_CONTROL" in client and "SERVICE_CHANGE_CONFIG" not in client and "SERVICE_START" not in client and "SERVICE_STOP" not in client)
check("installer_service_acl_interactive_users_minimum", "(A;;LCCR;;;IU)" in iss and "sdset" in iss and "(A;;LCCR;;;AU)" not in iss)
check("installer_service_protected_root", "{commonpf}\\DirectInternetMethod\\Privileged" in iss)
check("installer_admin_only_install", "PrivilegesRequired=admin" in iss)
check("installer_service_recovery", 'failure "' in iss and "failureflag" in iss)
check("installer_direct_update_completion_marker", "CompletePendingDirectUpdate" in iss and "pending-update.json" in iss and '"action":"update","phase":"done"' in iss and "DeleteFile(PendingPath)" in iss)
check("installer_ctrld_owned_demand_service", "CtrldServiceName = 'ctrld'" in iss and "InstallOrUpdateCtrldService" in iss and "start= demand" in iss and "CurrentControlSet\\Services\\" in iss)
check("installer_ctrld_collision_fail_closed", "A different Windows service named ctrld already exists" in iss and "CtrldServiceOwned()" in iss)
check("installer_ctrld_owned_uninstall", "StopCtrldServiceIfOwned" in iss and "delete \"" in iss and "CtrldServiceName" in iss)
check("installer_shortcuts_exe", 'DirectInternetMethod.exe' in iss and 'ControlPanel.cmd' not in "\n".join(x for x in iss.splitlines() if x.startswith("Name:")))
check("installer_active_guard", "PrepareToInstall" in iss and "DirectDnsDpiHarness" in iss and "state.json" in iss)
check("installer_bundled_pwsh", '..\\vendor\\pwsh\\*' in iss and 'Privileged\\runtime\\pwsh' in iss and "PowerShell7Available" not in iss)
check("installer_uninstall_recovery_gate", "InitializeUninstall" in iss and "Recovery did not complete" in iss)

files={(x["scope"],x["file"]) for x in manifest["files"]}
check("manifest_version", manifest.get("version")=="1.3.2")
check("manifest_direct_update", manifest.get("directUpdate",{}).get("userUacRequired") is False and "SHA256SUMS.txt" in manifest.get("directUpdate",{}).get("integrity",""))
check("manifest_native_exe", ("user","app/DirectInternetMethod.exe") in files)
check("manifest_router_gateway_data", ("user","app/router_gateway/providers.json") in files)
check("manifest_service", ("privileged","app/DirectInternetMethod.Service.exe") in files)
check("manifest_no_helper", not any(x[1].endswith("Helper.exe") for x in files))
check("manifest_bundled_pwsh", manifest.get("bundledPowerShellVersion")=="7.6.6" and manifest.get("bundledPowerShellArchiveSha256")=="02FE458BE20493FBDF43F61EA20610B811EE6C738AB1676C61B9CFCD1A33C860" and ("privileged","runtime/pwsh/pwsh.exe") in files)
check("manifest_bundled_pwsh_tree", sum(1 for s,f in files if s=="privileged" and f.startswith("runtime/pwsh/")) >= 650)
check("manifest_no_legacy_launchers", not any(scope=="user" and (f.endswith(".cmd") or f in {"app/ControlPanel.ps1","app/Toggle.ps1"}) for scope,f in files))

expected={
"ctrld":"FC966FD7DD5EE850A9709F632789CFB5BBC06C45D903D24B8ECFCE3306B658CD",
"winws":"A14BFF1DF6234EA555D2E0C61B589F0707C0B12D6C9B7EECCDA76012154996E8",
"windivertdll":"C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2",
"windivertsys":"8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2",
"pwsh":"BFB46AF89433268872DDB43D1CA7A3F433452EE91ED356A9786940F90118E285"}
for name,rel in (("ctrld","bin/ctrld/ctrld.exe"),("winws","bin/zapret/winws.exe"),("windivertdll","bin/zapret/WinDivert.dll"),("windivertsys","bin/zapret/WinDivert64.sys"),("pwsh","vendor/pwsh/pwsh.exe")):
    h=hashlib.sha256((W/rel).read_bytes()).hexdigest().upper();D["hashes"][name]=h;check("runtime_"+name+"_pin",h==expected[name])
print(json.dumps(D,indent=2))
sys.exit(0 if D["status"]=="PASS" else 20)
