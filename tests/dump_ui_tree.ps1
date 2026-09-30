Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$p=Get-Process DirectInternetMethod -ErrorAction Stop|Select-Object -First 1
$root=[System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
$all=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
$out=for($i=0;$i -lt $all.Count;$i++){
 $e=$all.Item($i)
 if($e.Current.Name){[pscustomobject]@{Name=$e.Current.Name;Type=$e.Current.ControlType.ProgrammaticName;Enabled=$e.Current.IsEnabled}}
}
$out|ConvertTo-Json -Depth 3
