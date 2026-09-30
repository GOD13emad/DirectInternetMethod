param([Parameter(Mandatory=$true)][string]$Name)
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$src=@'
using System;
using System.Runtime.InteropServices;
public static class NativeInput {
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int X,int Y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,uint data,UIntPtr extra);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
'@
Add-Type $src
$p=Get-Process DirectInternetMethod -ErrorAction Stop|Select-Object -First 1
$root=[System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
$c=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty,$Name)
$b=$root.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$c)
if(-not $b){throw "BUTTON_NOT_FOUND:$Name"}
$r=$b.Current.BoundingRectangle
$x=[int]($r.Left+$r.Width/2);$y=[int]($r.Top+$r.Height/2)
[NativeInput]::SetForegroundWindow($p.MainWindowHandle)|Out-Null
[NativeInput]::SetCursorPos($x,$y)|Out-Null
Start-Sleep -Milliseconds 150
[NativeInput]::mouse_event(2,0,0,0,[UIntPtr]::Zero)
[NativeInput]::mouse_event(4,0,0,0,[UIntPtr]::Zero)
[pscustomobject]@{Button=$Name;X=$x;Y=$y;Method='physical-mouse'}|ConvertTo-Json
