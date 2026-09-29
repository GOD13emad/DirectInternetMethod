@echo off
where pwsh.exe >nul 2>&1 || (echo PowerShell 7 ^(pwsh.exe^) is required.& pause& exit /b 2)
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Stop-Direct.ps1"
if errorlevel 1 pause
