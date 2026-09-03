# Builds installer/dist/MicroDFIRAgentSetup.exe -- must be run on Windows (NSIS's
# compiler produces a real Windows PE executable either way, but this repo's own build
# is only ever exercised here, not on the Linux appliance, which has no way to run this
# script or verify its output at all).
#
# Prerequisites (one-time):
#   winget install --id NSIS.NSIS
# (If that hits a UAC/elevation issue in a non-interactive shell, download NSIS's setup
# .exe directly from https://nsis.sourceforge.io/Download and run it with /S -- it
# doesn't require admin rights when installed to a user-writable directory.)
#
# Usage:
#   powershell -File installer/build.ps1
# Output: installer/dist/MicroDFIRAgentSetup.exe (checked into the repo -- see its own
# comment in agent_installer.nsi for why).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vendorDir = Join-Path $root "vendor"
$pyEmbedDir = Join-Path $vendorDir "python-embed"
$pyZip = Join-Path $vendorDir "python-embed.zip"
$pyVersion = "3.12.7"
$pyUrl = "https://www.python.org/ftp/python/$pyVersion/python-$pyVersion-embed-amd64.zip"

New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null

if (-not (Test-Path (Join-Path $pyEmbedDir "python.exe"))) {
    Write-Host "Downloading Python $pyVersion embeddable distribution..."
    Invoke-WebRequest -Uri $pyUrl -OutFile $pyZip -UseBasicParsing
    New-Item -ItemType Directory -Force -Path $pyEmbedDir | Out-Null
    Expand-Archive -Path $pyZip -DestinationPath $pyEmbedDir -Force
    # Sanity check -- this is what actually matters for the agent, not just "the zip
    # extracted ok". If this ever fails after a python version bump above, the
    # embeddable build for that version dropped a module the agent needs.
    $modules = "urllib.request, json, time, sys, os, subprocess, socket, random, ssl, tempfile, threading, hashlib"
    & (Join-Path $pyEmbedDir "python.exe") -c "import $modules; print('module check OK')"
    if ($LASTEXITCODE -ne 0) { throw "Embeddable Python failed to import a module the agent needs -- see output above." }
} else {
    Write-Host "Embeddable Python already present, skipping download."
}

$makensis = Get-Command makensis.exe -ErrorAction SilentlyContinue
if (-not $makensis) {
    $candidate = "$env:LOCALAPPDATA\NSIS\makensis.exe"
    if (Test-Path $candidate) { $makensis = $candidate } else { throw "makensis.exe not found. Install NSIS first (see this script's own header comment)." }
} else {
    $makensis = $makensis.Source
}

Write-Host "Compiling installer with $makensis ..."
Push-Location $root
try {
    & $makensis "agent_installer.nsi"
    if ($LASTEXITCODE -ne 0) { throw "makensis failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}

Write-Host "Built: $root\dist\MicroDFIRAgentSetup.exe"
