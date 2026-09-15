# Builds installer/dist/MicroDFIRAgent.exe -- a single-file PyInstaller bundle of
# agents/micro_agent_windows.py.
#
# WHY THIS EXISTS, and what it does and does not buy. The agent ships today as a .py next
# to an embeddable Python (installer/build.ps1). That works, but it leaves editable source
# in Program Files and there is nothing for the OS to verify. A bundle is one signable
# artifact instead.
#
# Be clear-eyed about the limits: a onefile bundle extracts to a temp directory at run
# time and its PYZ archive is readable with ordinary tools, so this is not obfuscation and
# should never be described as such. The real security gain is the Authenticode signature
# (see SIGNING below) -- with it, tampering is detectable by Windows and the binary can be
# allowlisted. Without a signing certificate, this mostly buys tidiness.
#
# THE TRADE-OFF YOU ARE MAKING. A bundled agent cannot take the remote "Upgrade Agent"
# action: that pushes Python source, and nothing in a bundled install executes a .py.
# The agent refuses such an upgrade loudly rather than pretending (see upgrade_agent in
# the agent source) and reports X-Agent-Packaging: frozen on every check-in so the console
# can show which endpoints are in this mode. Upgrading a bundled fleet means pushing a new
# installer. Decide that deliberately; do not discover it later.
#
# Prerequisites (one-time):
#   python -m venv installer/.buildvenv
#   installer/.buildvenv/Scripts/python.exe -m pip install pyinstaller
#
# Usage:
#   powershell -File installer/build_agent_exe.ps1
#
# SIGNING (optional, and the part that actually matters). With a code-signing
# certificate installed, set the thumbprint and this script will sign the result:
#   $env:MICRODFIR_SIGN_THUMBPRINT = "<cert thumbprint>"
# Unsigned output is still produced without it, with a warning -- an unsigned binary is
# not worse than the .py it replaces, it just is not better in the way that counts.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $root
$venvPy = Join-Path $root ".buildvenv\Scripts\python.exe"
$agent = Join-Path $repo "agents\micro_agent_windows.py"
$distDir = Join-Path $root "dist"
$workDir = Join-Path $root ".build"

if (-not (Test-Path $venvPy)) {
    throw "Build venv not found at $venvPy. See this script's header for the one-time setup."
}
if (-not (Test-Path $agent)) { throw "Agent source not found at $agent" }

# The version reported on every check-in, read from the agent itself so the built
# artifact and the console can never disagree about what was shipped.
$verLine = Select-String -Path $agent -Pattern 'AGENT_VERSION = "([^"]+)"' | Select-Object -First 1
if (-not $verLine) { throw "Could not read AGENT_VERSION from $agent" }
$agentVersion = $verLine.Matches[0].Groups[1].Value
Write-Host "Building Micro DFIR agent $agentVersion ..."

New-Item -ItemType Directory -Force -Path $distDir | Out-Null

# --onefile so the artifact is one signable file.
# --noconsole would hide the window, but the agent prints diagnostics before it installs
# its own log redirection -- with no console those writes fail. The existing run_hidden.vbs
# already launches it hidden, so a console build stays correct AND stays invisible.
& $venvPy -m PyInstaller `
    --onefile `
    --name MicroDFIRAgent `
    --distpath $distDir `
    --workpath $workDir `
    --specpath $workDir `
    --noconfirm `
    --clean `
    $agent
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)." }

$exe = Join-Path $distDir "MicroDFIRAgent.exe"
if (-not (Test-Path $exe)) { throw "PyInstaller reported success but $exe is missing." }

# Proves the bundle actually starts and knows it is frozen. `--version` is a cheap,
# side-effect-free entry point -- it must NOT be a path that installs anything, since
# this runs on a developer workstation.
$probe = & $exe --version 2>&1 | Out-String
if ($probe -notmatch [regex]::Escape($agentVersion)) {
    throw "Built exe did not report version $agentVersion (got: $probe). Refusing to ship it."
}
if ($probe -notmatch 'packaging=frozen') {
    throw "Built exe does not report itself as frozen -- the upgrade/watchdog paths would misbehave. Refusing to ship it."
}
# The probe also exercises the agent's two lazily-imported modules (winreg, ctypes) and
# exits non-zero if either is missing from the bundle -- the failure mode PyInstaller is
# most likely to produce, and one that would otherwise only surface on a real endpoint.
if ($LASTEXITCODE -ne 0 -or $probe -match 'FAILED') {
    throw "Built exe failed its self-check: $probe"
}
Write-Host "Self-check passed: $($probe.Trim())"

if ($env:MICRODFIR_SIGN_THUMBPRINT) {
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) { throw "MICRODFIR_SIGN_THUMBPRINT is set but signtool.exe is not on PATH (install the Windows SDK)." }
    Write-Host "Signing with certificate $env:MICRODFIR_SIGN_THUMBPRINT ..."
    & $signtool.Source sign /sha1 $env:MICRODFIR_SIGN_THUMBPRINT /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $exe
    if ($LASTEXITCODE -ne 0) { throw "signtool failed (exit $LASTEXITCODE)." }
    Write-Host "Signed."
} else {
    Write-Warning "MICRODFIR_SIGN_THUMBPRINT is not set -- the binary is UNSIGNED. That removes the main security benefit of bundling (tamper detection by the OS, allowlisting). See this script's header."
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Built: $exe ($size MB, agent $agentVersion)"
