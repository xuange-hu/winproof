@echo off
setlocal
cd /d "%~dp0"
title WinProof baseline
echo.
echo  WinProof - freeze the current state as the reference point
echo.
echo  Only run this when you believe today's state is the one you want.
echo  After this, every scan.bat reports what CHANGED against this moment.
echo  The baseline is never updated automatically: if it were, whatever
echo  re-injected your hijack would simply wait for you to re-capture it
echo  and would then look normal.
echo.
pause

powershell -NoProfile -ExecutionPolicy Bypass -File "probes\browser_prefs.ps1"
if errorlevel 1 goto :fail

powershell -NoProfile -ExecutionPolicy Bypass -File "probes\persistence.ps1"
if errorlevel 1 goto :fail

powershell -NoProfile -ExecutionPolicy Bypass -File "engine.ps1" -Mode baseline
if errorlevel 1 goto :fail

powershell -NoProfile -ExecutionPolicy Bypass -File "report.ps1"
if errorlevel 1 goto :fail

echo.
echo  Baseline stored in store\baseline.json
echo  Next scan.bat will classify every finding as new / changed / gone.
timeout /t 5 >nul
exit /b 0

:fail
echo.
echo  FAILED - see the message above.
pause
exit /b 1
