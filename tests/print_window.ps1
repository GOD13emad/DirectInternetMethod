Add-Type -AssemblyName System.Drawing
$src=@'
using System;
using System.Runtime.InteropServices;
public static class PW {
 [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left,Top,Right,Bottom; }
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd,out RECT rect);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd,IntPtr hdcBlt,uint flags);
}
'@
Add-Type $src
$p=Get-Process DirectInternetMethod -ErrorAction Stop|Select-Object -First 1
$r=New-Object PW+RECT
[PW]::GetWindowRect($p.MainWindowHandle,[ref]$r)|Out-Null
$w=$r.Right-$r.Left;$h=$r.Bottom-$r.Top
$bmp=New-Object System.Drawing.Bitmap $w,$h
$g=[System.Drawing.Graphics]::FromImage($bmp)
$hdc=$g.GetHdc()
try{[void][PW]::PrintWindow($p.MainWindowHandle,$hdc,2)}finally{$g.ReleaseHdc($hdc);$g.Dispose()}
$out=Join-Path $env:TEMP 'dim-win-printwindow.png'
$bmp.Save($out,[System.Drawing.Imaging.ImageFormat]::Png);$bmp.Dispose()
[pscustomobject]@{Path=$out;Width=$w;Height=$h}|ConvertTo-Json
