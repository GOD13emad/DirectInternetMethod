[CmdletBinding()]
param([switch]$Smoke)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore

$Root=Split-Path $PSScriptRoot -Parent
$Start=Join-Path $PSScriptRoot 'Start-Direct.ps1'
$Stop=Join-Path $PSScriptRoot 'Stop-Direct.ps1'
$Status=Join-Path $PSScriptRoot 'Status.ps1'
$Recovery=Join-Path $PSScriptRoot 'Recovery.ps1'

function Get-Pwsh{
 $c=Get-Command pwsh.exe -ErrorAction SilentlyContinue
 if(-not $c){throw 'PowerShell 7 (pwsh.exe) is required.'}
 $c.Source
}
function Read-Status{
 $pwsh=Get-Pwsh
 $raw=& $pwsh -NoProfile -ExecutionPolicy Bypass -File $Status -Json 2>$null
 if($LASTEXITCODE -ne 0 -or -not $raw){return $null}
 try{return ($raw -join [Environment]::NewLine)|ConvertFrom-Json}catch{return $null}
}
function Run-Elevated([string]$Script){
 $pwsh=Get-Pwsh
 $p=Start-Process -FilePath $pwsh -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$Script) -Wait -PassThru
 $p.ExitCode
}
function Set-StateUi($s){
 if(-not $s){
  $StatusText.Text='UNKNOWN'
  $Detail.Text='Status could not be read.'
  return
 }
 $StatusText.Text=[string]$s.mode
 $nl=[Environment]::NewLine
 $icsText=if($s.ics){([string]$s.ics.state+' / PID '+[string]$s.ics.pid)}else{'n/a'}
 $Detail.Text=('Interface: '+$s.interface+'   IP: '+$s.localIp+
  $nl+'Adapter DNS: '+(@($s.adapterDns)-join ', ')+
  $nl+'ULA: '+@($s.ula).Count+'   NRPT: '+@($s.nrpt).Count+'   ctrld PID: '+$s.ctrldPid+'   winws PID: '+$s.winwsPid+'   WinDivert: '+$s.winDivertCount+
  $nl+'Broad routes: '+$s.broadRouteCount+'   WinHTTP direct: '+$s.winHttpDirect+
  $nl+'ICS: '+$icsText)
}
function Refresh-State{
 $Window.Cursor=[Windows.Input.Cursors]::Wait
 try{Set-StateUi (Read-Status)}finally{$Window.Cursor=[Windows.Input.Cursors]::Arrow}
}

if($Smoke){
 $x=New-Object Windows.Window
 $x.Title='Direct Internet Method'
 $x.Width=600
 $x.Height=420
 Write-Output 'CONTROL_PANEL_SMOKE_PASS'
 exit 0
}

$Window=New-Object Windows.Window
$Window.Title='Direct Internet Method'
$Window.Width=720
$Window.Height=460
$Window.WindowStartupLocation='CenterScreen'
$Window.ResizeMode='NoResize'
$Window.FontFamily='Segoe UI'
$Window.Background=[Windows.Media.Brushes]::White

$Grid=New-Object Windows.Controls.Grid
$Window.Content=$Grid
foreach($h in @(70,70,150,90,70)){
 $rd=New-Object Windows.Controls.RowDefinition
 $rd.Height=New-Object Windows.GridLength($h)
 $Grid.RowDefinitions.Add($rd)
}

$Hero=New-Object Windows.Controls.StackPanel
$Hero.Orientation='Horizontal'
$Hero.Margin='24,10,24,4'
$Logo=New-Object Windows.Controls.Image
$Logo.Width=54;$Logo.Height=54;$Logo.Margin='0,0,12,0'
$Logo.Source=[Windows.Media.Imaging.BitmapFrame]::Create([Uri](Join-Path $PSScriptRoot 'DirectInternetMethod.ico'))
$HeroText=New-Object Windows.Controls.StackPanel
$Title=New-Object Windows.Controls.TextBlock
$Title.Text='Direct Internet Method'
$Title.FontSize=24
$Title.FontWeight='SemiBold'
$Slogan=New-Object Windows.Controls.TextBlock
$Slogan.Text='زن زندگی آزادی'
$Slogan.FontSize=18
$Slogan.FontWeight='SemiBold'
$Slogan.FlowDirection='RightToLeft'
$HeroText.Children.Add($Title)|Out-Null
$HeroText.Children.Add($Slogan)|Out-Null
$Hero.Children.Add($Logo)|Out-Null
$Hero.Children.Add($HeroText)|Out-Null
[Windows.Controls.Grid]::SetRow($Hero,0)
$Grid.Children.Add($Hero)|Out-Null

$StatusPanel=New-Object Windows.Controls.StackPanel
$StatusPanel.Orientation='Horizontal'
$StatusPanel.Margin='24,12,24,6'
$Label=New-Object Windows.Controls.TextBlock
$Label.Text='Status: '
$Label.FontSize=18
$StatusText=New-Object Windows.Controls.TextBlock
$StatusText.FontSize=18
$StatusText.FontWeight='Bold'
$StatusPanel.Children.Add($Label)|Out-Null
$StatusPanel.Children.Add($StatusText)|Out-Null
[Windows.Controls.Grid]::SetRow($StatusPanel,1)
$Grid.Children.Add($StatusPanel)|Out-Null

$Detail=New-Object Windows.Controls.TextBlock
$Detail.Margin='24,10,24,10'
$Detail.TextWrapping='Wrap'
$Detail.FontSize=14
$Detail.Foreground=[Windows.Media.Brushes]::DimGray
[Windows.Controls.Grid]::SetRow($Detail,2)
$Grid.Children.Add($Detail)|Out-Null

$Buttons=New-Object Windows.Controls.WrapPanel
$Buttons.Margin='24,12,24,12'
$Buttons.HorizontalAlignment='Center'
function Make-Button([string]$Text,[double]$Width){
 $b=New-Object Windows.Controls.Button
 $b.Content=$Text
 $b.Width=$Width
 $b.Height=46
 $b.Margin='7'
 $b.FontSize=15
 $b
}
$StartBtn=Make-Button 'Start' 125
$StopBtn=Make-Button 'Stop' 125
$RefreshBtn=Make-Button 'Refresh' 125
$RecoverBtn=Make-Button 'Recovery' 125
$Buttons.Children.Add($StartBtn)|Out-Null
$Buttons.Children.Add($StopBtn)|Out-Null
$Buttons.Children.Add($RefreshBtn)|Out-Null
$Buttons.Children.Add($RecoverBtn)|Out-Null
[Windows.Controls.Grid]::SetRow($Buttons,3)
$Grid.Children.Add($Buttons)|Out-Null

$Note=New-Object Windows.Controls.TextBlock
$Note.Text='Start/Stop/Recovery use standard Windows UAC. No VPN, proxy, or ChatGPT is required.'
$Note.Margin='24,8,24,10'
$Note.HorizontalAlignment='Center'
$Note.Foreground=[Windows.Media.Brushes]::Gray
[Windows.Controls.Grid]::SetRow($Note,4)
$Grid.Children.Add($Note)|Out-Null

$StartBtn.Add_Click({
 $Window.IsEnabled=$false
 try{
  $code=Run-Elevated $Start
  Refresh-State
  if($code -ne 0){[Windows.MessageBox]::Show('Start did not complete successfully. Use Recovery or check Status.','Direct Internet Method')|Out-Null}
 }catch{[Windows.MessageBox]::Show($_.Exception.Message,'Direct Internet Method')|Out-Null}
 finally{$Window.IsEnabled=$true}
})
$StopBtn.Add_Click({
 $Window.IsEnabled=$false
 try{
  $code=Run-Elevated $Stop
  Refresh-State
  if($code -ne 0){[Windows.MessageBox]::Show('Stop reported a problem. Run Recovery.','Direct Internet Method')|Out-Null}
 }catch{[Windows.MessageBox]::Show($_.Exception.Message,'Direct Internet Method')|Out-Null}
 finally{$Window.IsEnabled=$true}
})
$RefreshBtn.Add_Click({Refresh-State})
$RecoverBtn.Add_Click({
 $r=[Windows.MessageBox]::Show('Recovery removes only resources owned by this package. Continue?','Direct Internet Method',[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Warning)
 if($r -ne [Windows.MessageBoxResult]::Yes){return}
 $Window.IsEnabled=$false
 try{
  $code=Run-Elevated $Recovery
  Refresh-State
  if($code -ne 0){[Windows.MessageBox]::Show('Recovery could not fully clean owned resources.','Direct Internet Method')|Out-Null}
 }catch{[Windows.MessageBox]::Show($_.Exception.Message,'Direct Internet Method')|Out-Null}
 finally{$Window.IsEnabled=$true}
})
$Window.Add_ContentRendered({Refresh-State})
$Window.ShowDialog()|Out-Null
