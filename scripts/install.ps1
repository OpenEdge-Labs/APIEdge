# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
# APIEdge installer bootstrap for Windows: finds Python 3.10-3.12, then runs scripts/install.py.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

function Test-Python([string[]]$Cmd) {
    try {
        $exe = $Cmd[0]; $pre = @(); if ($Cmd.Length -gt 1) { $pre = $Cmd[1..($Cmd.Length - 1)] }
        $v = & $exe @pre -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $v -in @('3.10', '3.11', '3.12')) { return $true }
    } catch { }
    return $false
}

$candidates = @(@('py', '-3.12'), @('py', '-3.11'), @('py', '-3.10'), @('python'), @('python3'))
$python = $null
foreach ($c in $candidates) { if (Test-Python $c) { $python = $c; break } }

if (-not $python) {
    Write-Host ''
    Write-Host 'APIEdge needs Python 3.10, 3.11 or 3.12, and none was found.' -ForegroundColor Red
    Write-Host 'Install it from https://www.python.org/downloads/windows/'
    Write-Host '  (tick "Add python.exe to PATH" in the installer), or run:'
    Write-Host '  winget install Python.Python.3.12'
    Write-Host 'Then double-click install.bat again.'
    exit 3
}

$exe = $python[0]; $pre = @(); if ($python.Length -gt 1) { $pre = $python[1..($python.Length - 1)] }
& $exe @pre (Join-Path $Root 'scripts\install.py') @args
exit $LASTEXITCODE
