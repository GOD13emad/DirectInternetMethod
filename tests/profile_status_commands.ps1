$ErrorActionPreference='SilentlyContinue'
$rows=@()
function T([string]$Name,[scriptblock]$Block){
  $sw=[Diagnostics.Stopwatch]::StartNew()
  & $Block | Out-Null
  $sw.Stop()
  $script:rows += [pscustomobject]@{Name=$Name;Ms=$sw.ElapsedMilliseconds}
}
T 'defaultRoute' {Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'}
T 'broadRoutes' {Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1';Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '128.0.0.0/1'}
T 'adapter' {Get-NetAdapter}
T 'ipv4' {Get-NetIPAddress -AddressFamily IPv4}
T 'nrpt' {Get-DnsClientNrptRule}
T 'loopbackIpv6' {Get-NetIPAddress -InterfaceIndex 1 -AddressFamily IPv6}
T 'winDivertCim' {Get-CimInstance Win32_SystemDriver -Filter "Name LIKE 'WinDivert%'"}
T 'icsCim' {Get-CimInstance Win32_Service -Filter "Name='SharedAccess'"}
T 'dns' {Get-DnsClientServerAddress -AddressFamily IPv4}
T 'winhttp' {netsh winhttp show proxy}
T 'processes' {Get-Process ctrld,winws}
$rows|Sort-Object Ms -Descending|ConvertTo-Json -Depth 3
