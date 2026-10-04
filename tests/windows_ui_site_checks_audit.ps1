param([int]$ProcessId)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$desktop=[System.Windows.Automation.AutomationElement]::RootElement
$pc=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$ProcessId)
$win=$desktop.FindFirst([System.Windows.Automation.TreeScope]::Children,$pc)
if(-not $win){throw "window not found"}
$all=$win.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
$names=@()
$toggle=$null
for($i=0;$i -lt $all.Count;$i++){
  $e=$all.Item($i); $n=$e.Current.Name
  if($n){$names += $n}
  if($n -eq 'Live check' -and $e.Current.ControlType.ProgrammaticName -eq 'ControlType.CheckBox'){$toggle=$e}
}
if(-not ($names -contains 'Gemini')){throw 'Gemini live card missing'}
if(-not ($names -contains 'Adult site')){throw 'Adult site live card missing'}
if(-not $toggle){throw 'Adult live-check toggle missing'}
$pat=[System.Windows.Automation.TogglePattern]::Pattern
$tp=$toggle.GetCurrentPattern($pat)
$before=$tp.Current.ToggleState.ToString()
if($before -ne 'Off'){throw "adult toggle default is $before, expected Off"}
$tp.Toggle(); Start-Sleep -Milliseconds 500
$on=$tp.Current.ToggleState.ToString()
$settings=Join-Path $env:LOCALAPPDATA 'DirectInternetMethod\settings.json'
$j=if(Test-Path $settings){Get-Content $settings -Raw|ConvertFrom-Json}else{$null}
$persistOn=($null -ne $j -and $j.adultSiteLiveCheck -eq $true)
$tp.Toggle(); Start-Sleep -Milliseconds 500
$off=$tp.Current.ToggleState.ToString()
$j2=if(Test-Path $settings){Get-Content $settings -Raw|ConvertFrom-Json}else{$null}
$persistOff=($null -ne $j2 -and $j2.adultSiteLiveCheck -eq $false)
[pscustomobject]@{
 schema=1;status=if($on -eq 'On' -and $off -eq 'Off' -and $persistOn -and $persistOff){'PASS'}else{'FAIL'}
 geminiVisible=($names -contains 'Gemini')
 adultLabelVisible=($names -contains 'Adult site')
 adultBrandVisible=(@($names|Where-Object{$_ -match 'pornhub'}).Count -gt 0)
 default=$before;on=$on;off=$off;persistOn=$persistOn;persistOff=$persistOff
}|ConvertTo-Json -Depth 4
if($on -ne 'On' -or $off -ne 'Off' -or -not $persistOn -or -not $persistOff){exit 31}
