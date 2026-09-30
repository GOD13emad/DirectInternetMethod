Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$p=Get-Process DirectInternetMethod -ErrorAction Stop|Select-Object -First 1
$root=[System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
$walker=[System.Windows.Automation.TreeWalker]::ControlViewWalker
$all=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
$o=@()
for($i=0;$i -lt $all.Count;$i++){
 $e=$all.Item($i);$n=$e.Current.Name;$ct=$e.Current.ControlType.ProgrammaticName
 if($n -in @('Start','Stop','Refresh','Recovery','BLOCKED','ACTIVE','OFF','CONFLICT','DEGRADED') -or $ct -match 'Button'){
  $o+=[pscustomobject]@{Name=$n;Type=$ct;Enabled=$e.Current.IsEnabled;Offscreen=$e.Current.IsOffscreen}
 }
}
$o|ConvertTo-Json -Depth 3
