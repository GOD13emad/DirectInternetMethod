param(
  [int]$ProcessId = 0,
  [double]$ExpectedWidthDip = 1289,
  [double]$ExpectedHeightDip = 632,
  [int]$TolerancePx = 4
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$src=@'
using System;
using System.Runtime.InteropServices;
public static class DimUiWin32 {
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
  [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
}
'@
Add-Type $src
$p = if($ProcessId -gt 0){ Get-Process -Id $ProcessId -ErrorAction Stop } else { Get-Process DirectInternetMethod -ErrorAction Stop | Select-Object -First 1 }
$until=(Get-Date).AddSeconds(12)
while($p.MainWindowHandle -eq 0 -and (Get-Date) -lt $until){ Start-Sleep -Milliseconds 150; $p.Refresh() }
if($p.MainWindowHandle -eq 0){ throw 'MAIN_WINDOW_NOT_READY' }
$wasMinimized=[DimUiWin32]::IsIconic($p.MainWindowHandle)
if($wasMinimized){
  [void][DimUiWin32]::ShowWindowAsync($p.MainWindowHandle,9)
  $restoreUntil=(Get-Date).AddSeconds(5)
  while([DimUiWin32]::IsIconic($p.MainWindowHandle) -and (Get-Date) -lt $restoreUntil){ Start-Sleep -Milliseconds 100; $p.Refresh() }
  if([DimUiWin32]::IsIconic($p.MainWindowHandle)){ throw 'WINDOW_RESTORE_TIMEOUT' }
  Start-Sleep -Milliseconds 250
}
$r=New-Object DimUiWin32+RECT
if(-not [DimUiWin32]::GetWindowRect($p.MainWindowHandle,[ref]$r)){ throw 'GET_WINDOW_RECT_FAILED' }
$dpi=[int][DimUiWin32]::GetDpiForWindow($p.MainWindowHandle)
if($dpi -le 0){$dpi=96}
$w=$r.Right-$r.Left
$h=$r.Bottom-$r.Top
$ew=[int][Math]::Round($ExpectedWidthDip*$dpi/96.0)
$eh=[int][Math]::Round($ExpectedHeightDip*$dpi/96.0)
$root=[System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
$buttonCond=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::Button)
$buttons=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,$buttonCond)
$rows=@()
for($i=0;$i -lt $buttons.Count;$i++){
  $e=$buttons.Item($i)
  $b=$e.Current.BoundingRectangle
  $rows += [pscustomobject]@{Name=$e.Current.Name;Left=[double]$b.Left;Top=[double]$b.Top;Right=[double]$b.Right;Bottom=[double]$b.Bottom;Width=[double]$b.Width;Height=[double]$b.Height;Offscreen=[bool]$e.Current.IsOffscreen;Enabled=[bool]$e.Current.IsEnabled}
}
if($rows.Count -lt 6){ throw "BUTTON_COUNT_$($rows.Count)" }
$footerName='Start / Stop / Recovery / direct updates require no UAC after initial install'
$textCond=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty,$footerName)
$footer=$root.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$textCond)
if(-not $footer){ throw 'FOOTER_TEXT_NOT_FOUND' }
$fr=$footer.Current.BoundingRectangle
$overlaps=@()
for($i=0;$i -lt $rows.Count;$i++){
  $a=$rows[$i]
  if(($a.Left -lt $fr.Right) -and ($a.Right -gt $fr.Left) -and ($a.Top -lt $fr.Bottom) -and ($a.Bottom -gt $fr.Top)){
    $overlaps += "button-footer:$($a.Name)"
  }
  for($j=$i+1;$j -lt $rows.Count;$j++){
    $b=$rows[$j]
    if(($a.Left -lt $b.Right) -and ($a.Right -gt $b.Left) -and ($a.Top -lt $b.Bottom) -and ($a.Bottom -gt $b.Top)){
      $overlaps += "button-button:$($a.Name)|$($b.Name)"
    }
  }
}
$checks=[ordered]@{
  width = ([Math]::Abs($w-$ew) -le $TolerancePx)
  height = ([Math]::Abs($h-$eh) -le $TolerancePx)
  sixOrMoreButtons = ($rows.Count -ge 6)
  allButtonsVisible = (@($rows | Where-Object Offscreen).Count -eq 0)
  noOverlap = ($overlaps.Count -eq 0)
  footerVisible = (-not $footer.Current.IsOffscreen)
}
$status=if(@($checks.Values | Where-Object { -not $_ }).Count -eq 0){'PASS'}else{'FAIL'}
[pscustomobject]@{
  schema=1
  status=$status
  pid=$p.Id
  title=$p.MainWindowTitle
  dpi=$dpi
  restoredFromMinimized=$wasMinimized
  window=[ordered]@{widthPx=$w;heightPx=$h;expectedWidthPx=$ew;expectedHeightPx=$eh}
  checks=$checks
  overlaps=$overlaps
  buttons=$rows
  footer=[ordered]@{left=$fr.Left;top=$fr.Top;right=$fr.Right;bottom=$fr.Bottom;offscreen=$footer.Current.IsOffscreen}
}|ConvertTo-Json -Depth 6
if($wasMinimized){ [void][DimUiWin32]::ShowWindowAsync($p.MainWindowHandle,6) }
if($status -ne 'PASS'){exit 31}
