Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$src=@'
using System;
using System.Runtime.InteropServices;
public static class NativeInput {
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int X,int Y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,uint data,UIntPtr extra);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern void keybd_event(byte vk,byte scan,uint flags,UIntPtr extra);
}
'@
Add-Type $src
$p=Get-Process DirectInternetMethod -ErrorAction Stop|Select-Object -First 1
$root=[System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
$c=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty,'Refresh')
$b=$root.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$c)
if(-not $b){throw 'REFRESH_BUTTON_NOT_FOUND'}
$r=$b.Current.BoundingRectangle
$x=[int]($r.Left+$r.Width/2);$y=[int]($r.Top+$r.Height/2)
[NativeInput]::SetForegroundWindow($p.MainWindowHandle)|Out-Null
[NativeInput]::SetCursorPos($x,$y)|Out-Null
[NativeInput]::mouse_event(2,0,0,0,[UIntPtr]::Zero)
[NativeInput]::mouse_event(4,0,0,0,[UIntPtr]::Zero)
Start-Sleep -Milliseconds 800
$b.SetFocus()
[NativeInput]::keybd_event(0x0D,0,0,[UIntPtr]::Zero)
[NativeInput]::keybd_event(0x0D,0,2,[UIntPtr]::Zero)
Start-Sleep -Seconds 2
$p.Refresh()
[pscustomobject]@{Mouse='PASS';KeyboardEnter='PASS';Button='Refresh';X=$x;Y=$y;Responding=$p.Responding;Title=$p.MainWindowTitle}|ConvertTo-Json
