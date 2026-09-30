$ErrorActionPreference='Stop'
$root=Resolve-Path '.\windows'
$ctrld=Join-Path $root 'bin\ctrld\ctrld.exe'
$tmp=Join-Path $env:TEMP ('dim-ctrld-home-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp,(Join-Path $tmp 'home')|Out-Null
$cfg=Get-Content (Join-Path $root 'bin\ctrld\ctrld.toml') -Raw
$cfg=$cfg.Replace('port = 53','port = 53537')
[IO.File]::WriteAllText((Join-Path $tmp 'ctrld.toml'),$cfg,[Text.UTF8Encoding]::new($false))
$psi=[Diagnostics.ProcessStartInfo]::new($ctrld,('run --config="'+(Join-Path $tmp 'ctrld.toml')+'"'))
$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$tmp
$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
$psi.Environment['USERPROFILE']=(Join-Path $tmp 'home')
$psi.Environment['HOME']=(Join-Path $tmp 'home')
$p=[Diagnostics.Process]::Start($psi)
Start-Sleep -Seconds 2
$udp=@(Get-NetUDPEndpoint -LocalPort 53537 -ErrorAction SilentlyContinue|Select-Object LocalAddress,OwningProcess)
$tcp=@(Get-NetTCPConnection -LocalPort 53537 -State Listen -ErrorAction SilentlyContinue|Select-Object LocalAddress,OwningProcess)
$ex=$p.HasExited
if(-not $ex){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
$o=$p.StandardOutput.ReadToEnd();$e=$p.StandardError.ReadToEnd()
[pscustomobject]@{Pid=$p.Id;Exited=$ex;ExitCode=$(if($ex){$p.ExitCode}else{$null});Udp=$udp;Tcp=$tcp;Out=$o;Err=$e}|ConvertTo-Json -Depth 6
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
