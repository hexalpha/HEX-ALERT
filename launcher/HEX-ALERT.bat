@echo off
setlocal
cd /d "%~dp0.."
if exist "%~dp0dist\HEX-ALERT.exe" (
  start "" "%~dp0dist\HEX-ALERT.exe"
) else (
  py -3 "%~dp0launcher.py"
)
