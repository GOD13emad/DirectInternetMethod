[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Root=Split-Path $PSScriptRoot -Parent
$Runtime=Join-Path $env:ProgramData 'DirectDnsDpiHarness'
$StatePath=Join-Path $Runtime 'state.json'
$RuntimeCtrld=Join-Path $Runtime 'ctrld'
$Stop=Join-Path $PSScriptRoot 'Stop-Direct.ps1'
$CtrldDir=Join-Path $Root 'bin\ctrld'
$CtrldSock=Join-Path $CtrldDir 'ctrld_control.sock'
$ZapretDir=Join-Path $Root 'bin\zapret'
$Ula='fd53:4444:48::53'
$LoopbackIndex=1
$NrptDisplay='DirectDnsDpiHarness'
$NrptComment='Owned by DirectDnsDpiHarness; safe to remove only by this harness.'
function IsAdmin{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=[Security.Principal.WindowsPrincipal]::new($id)
 $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if(-not(IsAdmin)){
 $p=Start-Process pwsh.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath) -Wait -PassThru
 exit $p.ExitCode
}
if(Test-Path $StatePath){
 try{& pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $Stop;exit $LASTEXITCODE}catch{}
}
$ownedRules=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay -and $_.Comment -eq $NrptComment})
$ownedCtrld=@(Get-Process ctrld -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($CtrldDir,[StringComparison]::OrdinalIgnoreCase)})
$ownedWinws=@(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)})
$ownedDrivers=@(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^WinDivert' -and $_.PathName -and $_.PathName.Contains($Root,[StringComparison]::OrdinalIgnoreCase)})
$runtimeExists=Test-Path $RuntimeCtrld
$corroborated=($ownedRules.Count -gt 0 -or $ownedCtrld.Count -gt 0 -or $ownedWinws.Count -gt 0 -or $ownedDrivers.Count -gt 0 -or $runtimeExists)
foreach($r in $ownedRules){Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction SilentlyContinue}
Clear-DnsClientCache -ErrorAction SilentlyContinue
$ownedWinws|Stop-Process -Force -ErrorAction SilentlyContinue
$ownedCtrld|Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400
Remove-Item -LiteralPath $CtrldSock -Force -ErrorAction SilentlyContinue
foreach($d in $ownedDrivers){& sc.exe stop $d.Name|Out-Null;Start-Sleep -Milliseconds 150;& sc.exe delete $d.Name|Out-Null}
Start-Sleep -Milliseconds 400
if($corroborated){
 $a=@(Get-NetIPAddress -InterfaceIndex $LoopbackIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $Ula)
 if($a.Count -eq 1 -and [int]$a[0].PrefixLength -eq 128 -and [bool]$a[0].SkipAsSource){
  Remove-NetIPAddress -InterfaceIndex $LoopbackIndex -IPAddress $Ula -AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue
 }
}
Remove-Item -LiteralPath $RuntimeCtrld -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
Clear-DnsClientCache -ErrorAction SilentlyContinue
$leftRules=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay -and $_.Comment -eq $NrptComment})
$leftCtrld=@(Get-Process ctrld -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($CtrldDir,[StringComparison]::OrdinalIgnoreCase)})
$leftWinws=@(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)})
$leftDrivers=@(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^WinDivert' -and $_.PathName -and $_.PathName.Contains($Root,[StringComparison]::OrdinalIgnoreCase)})
$leftUla=@(Get-NetIPAddress -InterfaceIndex $LoopbackIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $Ula)
if($leftRules.Count -or $leftCtrld.Count -or $leftWinws.Count -or $leftDrivers.Count -or ($corroborated -and $leftUla.Count) -or (Test-Path -LiteralPath $CtrldSock)){throw 'RECOVERY_INCOMPLETE'}
Write-Host 'Recovery PASS. Owned Direct Internet resources are clean.'
