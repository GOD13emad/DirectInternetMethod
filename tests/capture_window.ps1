Add-Type -AssemblyName System.Drawing
$src=@'
using System;
using System.Runtime.InteropServices;
public static class PW {
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);
 public struct RECT { public int Left,Top,Right,Bottom; }
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
[PW]::PrintWindow($p.MainWindowHandle,$hdc,2)|Out-Null
$g.ReleaseHdc($hdc);$g.Dispose()
$path=Join-Path $env:TEMP 'dim-window-audit.png'
$bmp.Save($path,[System.Drawing.Imaging.ImageFormat]::Png);$bmp.Dispose()
Write-Output $path
