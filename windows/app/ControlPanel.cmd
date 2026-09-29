@echo off
where pwsh.exe >nul 2>&1 || (echo PowerShell 7 ^(pwsh.exe^) is required.& pause& exit /b 2)
start "" pwsh.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0ControlPanel.ps1"
