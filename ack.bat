@echo off
setlocal
cd /d "%~dp0"
title WinProof acknowledge

if "%~1"=="" (
  echo  usage: ack.bat "RULE-ID^|Subject"
  echo.
  echo  Copy the key from the grey line at the bottom of a finding card in
  echo  out\report.html. Acknowledging means "this is mine, stop flagging it"
  echo  - it is how you keep a real hijack visible instead of tuning the
  echo  whole rule down because one match annoyed you.
  echo.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "engine.ps1" -Mode ack -AckKey %1
if errorlevel 1 (
  echo.
  echo  FAILED - quote the key, it contains a pipe character.
  echo    ack.bat "BR-01^|Edge / Profile 1"
  pause
  exit /b 1
)

echo  Rebuild the report to see it demoted to KNOWN: scan.bat
exit /b 0
