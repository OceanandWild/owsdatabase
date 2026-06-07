@echo off
title Respaldo OWS a GitHub
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "..\..\scripts\backup-to-github.ps1" %*
pause
