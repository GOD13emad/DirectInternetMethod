$ErrorActionPreference='Stop'
$root=Resolve-Path '.\windows'
$ctrld=Join-Path $root 'bin\ctrld\ctrld.exe'
$tmp=Join-Path $env:TEMP ('dim-ctrld-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp|Out-Null
$cfg=Get-Content (Join-Path $root 'bin\ctrld\ctrld.toml') -Raw
$cfg=$cfg.Replace('port = 53','port = 53535')
[IO.File]::WriteAllText((Join-Path $tmp 'ctrld.toml'),$cfg,[Text.UTF8Encoding]::new($false))
$p=Start-Process -FilePath $ctrld -ArgumentList @('run',('--config='+(Join-Path $tmp 'ctrld.toml')),'--silent') -WorkingDirectory $tmp -WindowStyle Hidden -PassThru
try{
 Start-Sleep -Seconds 2
 $udp=@(Get-NetUDPEndpoint -LocalPort 53535 -ErrorAction SilentlyContinue|Select-Object LocalAddress,LocalPort,OwningProcess)
 $tcp=@(Get-NetTCPConnection -LocalPort 53535 -State Listen -ErrorAction SilentlyContinue|Select-Object LocalAddress,LocalPort,OwningProcess)
 [pscustomobject]@{Pid=$p.Id;Exited=$p.HasExited;Udp=$udp;Tcp=$tcp}|ConvertTo-Json -Depth 6
}finally{
 Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
 Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
