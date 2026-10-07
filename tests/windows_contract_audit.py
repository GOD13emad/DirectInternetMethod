#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,re,sys,subprocess
R=Path(__file__).resolve().parents[1]
W=R/"windows"
def txt(rel): return (W/rel).read_text(encoding="utf-8-sig")
start,stop,recovery,status,iss=map(txt,["app/Start-Direct.ps1","app/Stop-Direct.ps1","app/Recovery.ps1","app/Status.ps1","installer/DirectInternetMethod.iss"])
gui=txt("gui/MainWindow.xaml.cs"); xaml=txt("gui/MainWindow.xaml")
svc=txt("service/Program.cs"); client=txt("gui/ServiceClient.cs"); updater=txt("gui/UpdateClient.cs")
manifest=json.loads(txt("manifest.json")); ctrldcfg=txt("bin/ctrld/ctrld.toml"); hostlist=txt("bin/zapret/hosts.txt"); adult_fallback=txt("bin/zapret/adult-fallback-hosts.txt"); strong_override=txt("bin/zapret/strong-override-hosts.txt")
payload_builder=(R/"tests"/"build_windows_151_payload.ps1").read_text(encoding="utf-8-sig")
installer_builder=(R/"tests"/"build_windows_151_installer.ps1").read_text(encoding="utf-8-sig")
ci_workflow=(R/".github"/"workflows"/"ci.yml").read_text(encoding="utf-8-sig")
gitattributes=(R/".gitattributes").read_text(encoding="utf-8-sig")
install_registration_guard=(R/"tests"/"windows_install_registration_audit.ps1").read_text(encoding="utf-8-sig")
installed_release_verifier=(R/"tests"/"windows_installed_release_audit.ps1").read_text(encoding="utf-8-sig")
D={"schema":2,"status":"PASS","checks":{},"hashes":{}}
def check(name,cond):
    D["checks"][name]=bool(cond)
    if not cond:D["status"]="FAIL"
def idx(s,x): return s.find(x)

check("start_refuses_broad_tunnel_before_mutation", idx(start,"REFUSE_BROAD_TUNNEL_ROUTE")>=0 and idx(start,"REFUSE_BROAD_TUNNEL_ROUTE") < idx(start,"New-NetIPAddress"))
check("loopback_index_dynamic", all("DestinationPrefix '::1/128'" in x and "$LoopbackIndex=[int]$LoopbackRoute.InterfaceIndex" in x and "$LoopbackIndex=1" not in x for x in (start,stop,recovery)) and "DestinationPrefix '::1/128'" in status and "InterfaceIndex 1" not in status)
check("no_adapter_dns_set", "Set-DnsClientServerAddress" not in start+stop+recovery)
check("no_default_route_create", not re.search(r'(New-NetRoute|route\.exe\s+add|netsh\s+interface\s+ipv4\s+add\s+route)',start,re.I))
check("direct_multiprotocol_engine", all(x in start for x in (
    "$DirectMethods=@('encrypted-dns-doh','http-host-split-tcp80','tls-sni-desync-tcp443','quic-desync-udp443','custom-hostlist','adult-catalog','strategy-profile')",
    "'--wf-tcp=80,443'","'--wf-udp=443'","'--filter-tcp=80'","'--filter-tcp=443'","'--filter-udp=443'","'--filter-l7=quic'",
    "'--dpi-desync-split-pos=method+2'","'--dpi-desync-split-pos=1,midsld'","'--dpi-desync-repeats=6'","'--new'"
)))
check("direct_multiprotocol_scope_controlled", "Add-ScopeHost" in start and "$scope='targeted'" in start and "all-sites" in start and "--hostlist-auto=" not in start)
check("secure_dns_no_os_leak", 'leak_on_upstream_failure = false' in ctrldcfg)
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
check("target_hostlist_scope", "^gemini.google.com" in hostlist.splitlines() and all(x not in hostlist.splitlines() for x in ("pornhub.com","phncdn.com","xvideos.com","xnxx.com","xhamster.com")) and all(x in adult_fallback.splitlines() for x in ("pornhub.com","phncdn.com","xvideos.com","xvideos-cdn.com","xvcdn.com","xnxx.com","xnxx-cdn.com","xhamster.com","xhcdn.com","redtube.com","rdtcdn.com")))
check("critical_global_services_hostlist", all(x in hostlist.splitlines() for x in ("openai.com","chatgpt.com","oaistatic.com","oaiusercontent.com","github.com","githubusercontent.com","githubassets.com","reddit.com","redditstatic.com","redditmedia.com","redd.it")))
check("custom_site_hostlist", all(x in start for x in ("$CustomHosts=Join-Path $UserConfigDir 'custom-hosts.txt'","$RuntimeHostList=Join-Path $env:ProgramData 'DirectInternetMethod\\runtime-hosts.txt'","USER_CONFIG_INVALID","WriteAllLines($RuntimeHostList")) and all(x in gui for x in ("CustomSites_Click","NormalizeCustomSite","customHostsPath","Maximum 256 entries")) and 'Content="Custom Sites"' in xaml and 'DirectInternetMethod\\UserConfig' in iss and 'users-modify' in iss)
check("strategy_profiles", all(x in start for x in ("$StrategyFile=Join-Path $UserConfigDir 'strategy.txt'","balanced","compatibility","strong","fakedsplit","hostfakesplit","sniext+1","STRATEGY_INVALID")) and all(x in gui for x in ("Strategy_Click","strategyPath","Compatibility","Strong")) and 'Content="Strategy"' in xaml)
check("all_sites_scope_optional_default_targeted", all(x in start for x in ("$ScopeFile=Join-Path $UserConfigDir 'scope.txt'","$scope='targeted'","all-sites","SCOPE_INVALID","Add-ScopeHost")) and all(x in gui for x in ("scopePath","Apply DPI strategy to all web sites (experimental)","all-sites","targeted")))
check("ui_gemini_adult_live_checks", all(x in xaml for x in ('Text="Gemini"','Text="Adult coverage"','x:Name="AdultSiteCheckToggle"','x:Name="GeminiText"','x:Name="AdultSiteText"')) and all(x in gui for x in ("https://www.pornhub.com/","https://www.xvideos.com/","https://www.xnxx.com/","https://xhamster.com/","FmtAdult")) and "pornhub" not in xaml.lower())
check("ui_adult_check_default_off_persisted", all(x in gui for x in ("adultSiteLiveCheck","settings.json","AdultSiteCheckToggle_Changed")) and "bool adultCheckEnabled;" in gui)
check("adult_catalog_opt_in", all(x in gui for x in ("adultCoverageEnabled","adult-enabled.txt","adult-hosts.txt","nsfw-onlydomains.txt","EnsureAdultCatalogAsync","Adult catalog is unexpectedly small","xvideos.com","xnxx.com","xhamster.com")) and all(x in start for x in ("$AdultEnabledFile","$AdultHosts","$AdultFallback","adultHostCount","ADULT_CATALOG_INVALID")) and 'adult-fallback-hosts.txt' in iss)
check("startup_https_health_quorum", all(x in start for x in ("Curl-Probe-Retry","HTTPS_HEALTH_QUORUM_FAIL","$httpsProbePassCount -lt 2","httpsHealth=[ordered]@{required=2")) and all(x not in start for x in ("throw 'YOUTUBE_HTTP80_FAIL'","throw 'YOUTUBE_HTTPS_FAIL'","throw 'OPENAI_HTTPS_FAIL'","throw 'GITHUB_HTTPS_FAIL'")))
check("adult_strong_override_profile", all(x in strong_override.splitlines() for x in ("xhamster.com","xhamsterlive.com","xhcdn.com","reddit.com","redditstatic.com","redditmedia.com","redd.it")) and all(x in start for x in ("$StrongOverrideHostList","strong-override-hosts.txt","--hostlist='+$StrongOverrideHostList","--dpi-desync=fake,hostfakesplit","--dpi-desync-repeats=11")) and 'strong-override-hosts.txt' in iss)
check("ui_live_probe_semantics", "FAIL · HTTP" in gui and 'https://gemini.google.com/' in gui and "adultTasks is not null" in gui and "full pages" in gui)
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
check("windows_install_registration_guard", all(x in install_registration_guard for x in ("HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","noSameAppIdPerUserDuplicate","registeredUninstallerPresent","installedReleaseMatches")))
check("installed_release_verifier_delegates_registration_guard", "windows_install_registration_audit.ps1" in installed_release_verifier and "Where-Object DisplayName" not in installed_release_verifier and "pwsh.exe" in installed_release_verifier)
check("windows_build_shared_exclusive_lock", all(x in payload_builder for x in ("windows-151-build.lock","FileShare]::None","WINDOWS_151_BUILD_LOCKED")) and all(x in installer_builder for x in ("windows-151-build.lock","FileShare]::None","WINDOWS_151_BUILD_LOCKED")))
check("windows_installer_output_stability_guard", all(x in installer_builder for x in ("OUTPUT_STILL_LOCKED_AFTER_ISCC_EXIT","@($Sizes | Select-Object -Unique).Count","OUTPUT_SIZE_UNSTABLE_","outputStableSamples")))
tracked_strong=subprocess.run(["git","ls-files","--error-unmatch","windows/bin/zapret/strong-override-hosts.txt"],cwd=R,text=True,capture_output=True).returncode==0
check("windows_strong_override_source_tracked", tracked_strong)
check("windows_hash_pinned_text_eol_policy", all(x in gitattributes for x in ("windows/bin/zapret/hosts.txt text eol=crlf","windows/bin/zapret/adult-fallback-hosts.txt text eol=lf","windows/bin/zapret/strong-override-hosts.txt text eol=crlf")))
check("windows_ci_external_audits_fail_fast", ci_workflow.count("if($LASTEXITCODE -ne 0){ exit $LASTEXITCODE }") >= 7)

files={(x["scope"],x["file"]) for x in manifest["files"]}
check("manifest_version", manifest.get("version")=="1.5.1")
check("manifest_direct_update", manifest.get("directUpdate",{}).get("userUacRequired") is False and "SHA256SUMS.txt" in manifest.get("directUpdate",{}).get("integrity",""))
check("manifest_native_exe", ("user","app/DirectInternetMethod.exe") in files)
check("manifest_router_gateway_data", ("user","app/router_gateway/providers.json") in files)
check("manifest_adult_fallback", ("privileged","bin/zapret/adult-fallback-hosts.txt") in files)
check("manifest_strong_override", ("privileged","bin/zapret/strong-override-hosts.txt") in files)
check("manifest_service", ("privileged","app/DirectInternetMethod.Service.exe") in files)
check("manifest_no_helper", not any(x[1].endswith("Helper.exe") for x in files))
check("manifest_bundled_pwsh", manifest.get("bundledPowerShellVersion")=="7.6.6" and manifest.get("bundledPowerShellArchiveSha256")=="02FE458BE20493FBDF43F61EA20610B811EE6C738AB1676C61B9CFCD1A33C860" and ("privileged","runtime/pwsh/pwsh.exe") in files)
check("manifest_bundled_pwsh_tree", sum(1 for s,f in files if s=="privileged" and f.startswith("runtime/pwsh/")) >= 650)
check("manifest_no_legacy_launchers", not any(scope=="user" and (f.endswith(".cmd") or f in {"app/ControlPanel.ps1","app/Toggle.ps1"}) for scope,f in files))

pin_paths={
"ctrld.exe":"bin/ctrld/ctrld.exe",
"ctrld.toml":"bin/ctrld/ctrld.toml",
"winws.exe":"bin/zapret/winws.exe",
"WinDivert.dll":"bin/zapret/WinDivert.dll",
"WinDivert64.sys":"bin/zapret/WinDivert64.sys",
"cygwin1.dll":"bin/zapret/cygwin1.dll",
"hosts.txt":"bin/zapret/hosts.txt",
"adult-fallback-hosts.txt":"bin/zapret/adult-fallback-hosts.txt",
"strong-override-hosts.txt":"bin/zapret/strong-override-hosts.txt",
}
start_pins=dict(re.findall(r"'([^']+)'='([0-9A-F]{64})'",start))
pin_actual={k:hashlib.sha256((W/v).read_bytes()).hexdigest().upper() for k,v in pin_paths.items()}
D["selfIntegrityPins"]={"declared":{k:start_pins.get(k) for k in pin_paths},"actual":pin_actual}
check("start_self_integrity_pins",all(start_pins.get(k)==v for k,v in pin_actual.items()))

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
