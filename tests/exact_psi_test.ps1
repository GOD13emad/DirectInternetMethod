$ErrorActionPreference='Stop'
$p='C:\Program Files\DirectInternetMethod\Privileged\runtime\pwsh\pwsh.exe'
$wd='C:\Program Files\DirectInternetMethod\Privileged\app'
$args='-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "[Console]::Write(''EXACT_PSI_PASS'')"'
$psi=[Diagnostics.ProcessStartInfo]::new($p,$args)
$psi.UseShellExecute=$false
$psi.CreateNoWindow=$true
$psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
$psi.WorkingDirectory=$wd
$psi.RedirectStandardOutput=$true
$psi.RedirectStandardError=$true
try{
  $x=[Diagnostics.Process]::Start($psi)
  $o=$x.StandardOutput.ReadToEnd()
  $e=$x.StandardError.ReadToEnd()
  $x.WaitForExit()
  [pscustomobject]@{Exit=$x.ExitCode;Out=$o;Err=$e}|ConvertTo-Json
}catch{
  [pscustomobject]@{
    Type=$_.Exception.GetType().FullName
    HResult=$_.Exception.HResult
    Native=$(if($_.Exception -is [ComponentModel.Win32Exception]){$_.Exception.NativeErrorCode}else{$null})
    Message=$_.Exception.Message
  }|ConvertTo-Json
  exit 1
}
