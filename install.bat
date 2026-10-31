@echo off
REM Copyright 2026 Alingan Patra
REM SPDX-License-Identifier: Apache-2.0
REM APIEdge one-click installer for Windows. Double-click it, or run:
REM   install.bat [--yes] [--smoke-test] [--uninstall] [--help]
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install.ps1" %*
set "RC=%ERRORLEVEL%"
REM Keep the window open when started by double-click (no arguments).
if "%~1"=="" pause
exit /b %RC%
