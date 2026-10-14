@echo off
setlocal
cd /d "%~dp0"
title WinProof scan
echo.
echo  WinProof - read-only forensic scan
echo  Nothing on this machine is modified by this script.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "probes\browser_prefs.ps1"
if errorlevel 1 goto :fail

powershell -NoProfile -ExecutionPolicy Bypass -File "probes\persistence.ps1"
if errorlevel 1 goto :fail

powershell -NoProfile -ExecutionPolicy Bypass -File "engine.ps1" -Mode scan
if errorlevel 1 goto :fail

powershell -NoProfile -ExecutionPolicy Bypass -File "report.ps1"
if errorlevel 1 goto :fail

echo.
echo  Report ready: %~dp0out\report.html  (opening in your browser)
start "" "%~dp0out\report.html"
timeout /t 3 >nul
exit /b 0

:fail
echo.
echo  FAILED - see the message above.
pause
exit /b 1
