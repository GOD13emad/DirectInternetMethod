$x=@()
function T([string]$n,[scriptblock]$b){
  $s=[Diagnostics.Stopwatch]::StartNew()
  & $b | Out-Null
  $s.Stop()
  $script:x += [pscustomobject]@{Name=$n;Ms=$s.ElapsedMilliseconds}
}
T 'route' { Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue }
T 'adapter' { Get-NetAdapter -ErrorAction SilentlyContinue }
T 'ip' { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue }
T 'nrpt' { Get-DnsClientNrptRule -ErrorAction SilentlyContinue }
T 'ula' { Get-NetIPAddress -InterfaceIndex 1 -AddressFamily IPv6 -ErrorAction SilentlyContinue }
T 'driver' { Get-CimInstance Win32_SystemDriver -Filter "Name LIKE 'WinDivert%'" -ErrorAction SilentlyContinue }
T 'ics' { Get-CimInstance Win32_Service -Filter "Name='SharedAccess'" -ErrorAction SilentlyContinue }
T 'dns' { Get-DnsClientServerAddress -InterfaceAlias 'Ethernet 3' -AddressFamily IPv4 -ErrorAction SilentlyContinue }
T 'proxy' { netsh winhttp show proxy | Out-Null }
T 'procs' { Get-Process ctrld,winws -ErrorAction SilentlyContinue }
$x | ConvertTo-Json -Depth 3
