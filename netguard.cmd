@echo off
rem Lance le menu netguard-gaming. ExecutionPolicy Bypass ne vaut QUE pour ce processus PowerShell :
rem la strategie d'execution de Windows n'est pas modifiee. Pas de droits administrateur requis.
title netguard-gaming
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Start-NetGuard.ps1" %*
echo.
pause
