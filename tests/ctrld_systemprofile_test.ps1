$ErrorActionPreference='Stop'
$root=Resolve-Path '.\windows'
$ctrld=Join-Path $root 'bin\ctrld\ctrld.exe'
$tmp=Join-Path $env:TEMP ('dim-ctrld-sysprofile-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp|Out-Null
$cfg=Get-Content (Join-Path $root 'bin\ctrld\ctrld.toml') -Raw
$cfg=$cfg.Replace('port = 53','port = 53536')
[IO.File]::WriteAllText((Join-Path $tmp 'ctrld.toml'),$cfg,[Text.UTF8Encoding]::new($false))
$psi=[Diagnostics.ProcessStartInfo]::new($ctrld,('run --config="'+(Join-Path $tmp 'ctrld.toml')+'" --silent'))
$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$tmp
$psi.Environment['USERPROFILE']='C:\Windows\System32\config\systemprofile'
$psi.Environment['HOME']='C:\Windows\System32\config\systemprofile'
$p=[Diagnostics.Process]::Start($psi)
try{
 Start-Sleep -Seconds 2
 $udp=@(Get-NetUDPEndpoint -LocalPort 53536 -ErrorAction SilentlyContinue|Select-Object LocalAddress,OwningProcess)
 $tcp=@(Get-NetTCPConnection -LocalPort 53536 -State Listen -ErrorAction SilentlyContinue|Select-Object LocalAddress,OwningProcess)
 [pscustomobject]@{Pid=$p.Id;Exited=$p.HasExited;Udp=$udp;Tcp=$tcp}|ConvertTo-Json -Depth 5
}finally{Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue;Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue}
