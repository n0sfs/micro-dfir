# Canned response-action templates, one script-builder set per agent OS. Each function
# returns a ready-to-run script string; the caller is responsible for
# validating/sanitizing any parameters before formatting. Windows templates are
# PowerShell (written to a temp .ps1 file and run by the agent via `powershell -File`
# — see run_remote_script() in micro_agent_windows.py); Linux templates are bash (run
# by the agent via `subprocess.run(['bash', '-c', script])`, which sidesteps
# shell-quoting entirely since the whole script travels as one argument).
import re

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')
_MD5_RE = re.compile(r'^[0-9a-fA-F]{32}$')
_SHA1_RE = re.compile(r'^[0-9a-fA-F]{40}$')

# ---- Windows (PowerShell) ----

def list_processes():
    return (
        "Get-Process | Select-Object Id,ProcessName,Path,StartTime,"
        "@{N='CPU';E={[math]::Round($_.CPU,1)}} | Sort-Object CPU -Descending | "
        "Select-Object -First 100 | ConvertTo-Json -Compress"
    )

def kill_process(pid):
    pid = int(pid)
    return (
        f"try {{ Stop-Process -Id {pid} -Force -ErrorAction Stop; "
        f"\"Process {pid} terminated.\" }} catch {{ \"Failed to terminate PID {pid}: $_\" }}"
    )

# Unlike kill_process()'s single live PID (something an analyst just saw and picked),
# this targets every process whose name OR executable path CONTAINS the given pattern --
# built for automation (a SOAR playbook can't know a PID ahead of time, but can be
# authored against a known-bad process/file name) and for "kill every instance of X"
# containment on a single host. [regex]::Escape() treats the pattern as a literal
# substring, not a user-supplied regex; -match is case-insensitive by default in
# PowerShell. Deliberately broader-blast-radius than kill_process, so it's gated at
# edr.command.advanced for the direct console action (see AGENT_COMMAND_TIER1_LABELS)
# and always requires_approval as a playbook action.
def kill_process_by_name(pattern):
    esc = pattern.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f"""$pattern = [regex]::Escape("{esc}")
$targets = Get-Process | Where-Object {{ $_.ProcessName -match $pattern -or ($_.Path -and $_.Path -match $pattern) }}
if (-not $targets) {{ '{{"killed":[],"failed":[],"message":"no matching processes"}}'; exit }}
$killed = @(); $failed = @()
foreach ($p in $targets) {{
    try {{ Stop-Process -Id $p.Id -Force -ErrorAction Stop; $killed += @{{pid=$p.Id; name=$p.ProcessName; path=$p.Path}} }}
    catch {{ $failed += @{{pid=$p.Id; name=$p.ProcessName; error="$_"}} }}
}}
@{{killed=$killed; failed=$failed}} | ConvertTo-Json -Compress
"""

def isolate_host(soc_ip):
    if not _IPV4_RE.match(soc_ip):
        raise ValueError(f"Invalid SOC IP address: {soc_ip!r}")
    return f"""Remove-NetFirewallRule -DisplayName "MicroDFIR-Isolation-*" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "MicroDFIR-Isolation-Allow-SOC-Out" -Direction Outbound -RemoteAddress {soc_ip} -Action Allow -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "MicroDFIR-Isolation-Allow-SOC-In" -Direction Inbound -RemoteAddress {soc_ip} -Action Allow -Profile Any | Out-Null
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
"Host isolated. Only traffic to/from {soc_ip} is permitted."
"""

def restore_network():
    return """Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -DefaultOutboundAction Allow
Remove-NetFirewallRule -DisplayName "MicroDFIR-Isolation-*" -ErrorAction SilentlyContinue
"Network isolation removed. Host restored to normal connectivity."
"""

# A lighter-touch containment than isolate_host: adds two DENY rules for one specific
# IP instead of flipping the whole host's default policy to block-everything-except-SOC.
# The host stays otherwise fully usable (an analyst/user can keep working) while the one
# known-bad destination is cut off -- the natural response to "this host is talking to a
# bad IP" when full isolation would be overkill (or would cut off something the user
# still legitimately needs, e.g. mid-investigation on their own machine). Same
# Remove-then-create idempotency isolate_host already uses (a second block on the same
# IP replaces, not duplicates, the existing rule). Both directions share one DisplayName
# on purpose -- unblock_ip() below removes both with a single -DisplayName match.
#
# [Confirmed by actually running this without admin rights] New-NetFirewallRule without
# -ErrorAction Stop lets a permission failure pass silently -- the script would otherwise
# print its hardcoded success message regardless of whether the rule was actually
# created, a false-positive an analyst could act on (believing a host is contained when
# it isn't). Wrapped in try/catch here so a real failure is reported as one, not masked.
def block_ip(target_ip):
    if not _IPV4_RE.match(target_ip):
        raise ValueError(f"Invalid target IP address: {target_ip!r}")
    return f"""$ip = "{target_ip}"
try {{
    Remove-NetFirewallRule -DisplayName "MicroDFIR-Block-$ip" -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "MicroDFIR-Block-$ip" -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -DisplayName "MicroDFIR-Block-$ip" -Direction Inbound -RemoteAddress $ip -Action Block -Profile Any -ErrorAction Stop | Out-Null
    "Blocked all inbound/outbound traffic to/from $ip via Windows Firewall (two new deny rules; the host's own default policy and every other existing rule are untouched)."
}} catch {{
    $errMsg = $_.Exception.Message -replace '"', "'"
    "{{`"error`":`"failed to create firewall block rule for $ip -- $errMsg`"}}"
}}
"""

def unblock_ip(target_ip):
    if not _IPV4_RE.match(target_ip):
        raise ValueError(f"Invalid target IP address: {target_ip!r}")
    return f"""$ip = "{target_ip}"
try {{
    $existing = @(Get-NetFirewallRule -DisplayName "MicroDFIR-Block-$ip" -ErrorAction Stop)
    if ($existing.Count -gt 0) {{ Remove-NetFirewallRule -DisplayName "MicroDFIR-Block-$ip" -ErrorAction Stop }}
    if ($existing.Count -gt 0) {{ "Removed $($existing.Count) MicroDFIR block rule(s) for $ip." }} else {{ "No MicroDFIR block rule found for $ip -- nothing to remove." }}
}} catch {{
    $errMsg = $_.Exception.Message -replace '"', "'"
    "{{`"error`":`"failed to remove firewall block rule for $ip -- $errMsg`"}}"
}}
"""

def collect_triage():
    return r"""$result = @{}
$result.processes = Get-Process | Select-Object Id,ProcessName,Path,@{N='Hash';E={try{(Get-FileHash $_.Path -Algorithm SHA256 -ErrorAction Stop).Hash}catch{$null}}} | Select-Object -First 60
$result.connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess -First 60
$result.autoruns = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
$result.users = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,LastLogon
$result.startup_files = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime
$result | ConvertTo-Json -Depth 4 -Compress
"""

def collect_file(path):
    # 40KB raw, not 4MB -- base64 inflates size by ~4/3, and the server truncates a
    # command's whole stdout (this JSON wrapper included) to 60,000 chars
    # (api_agent_result, app.py) with no decode-aware truncation. A 4MB file's base64
    # blows straight through that limit and gets cut mid-string into invalid JSON --
    # confirmed as a real bug, not a hypothetical. 40KB raw -> ~54KB base64, leaving
    # headroom for the path/size/sha256 fields around it.
    esc = path.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f"""$p = "{esc}"
if (-not (Test-Path $p)) {{ '{{"error":"file not found"}}'; exit }}
$size = (Get-Item $p).Length
if ($size -gt 40KB) {{ "{{`"error`":`"file too large ($size bytes, 40KB limit)`"}}"; exit }}
$bytes = [IO.File]::ReadAllBytes($p)
$b64 = [Convert]::ToBase64String($bytes)
$hash = (Get-FileHash $p -Algorithm SHA256).Hash
@{{ path=$p; size=$size; sha256=$hash; content_b64=$b64 }} | ConvertTo-Json -Compress
"""

# Contain, not just collect -- moves the file out of its original location (so it can no
# longer be executed/loaded from there) into a locked-down folder, rather than only ever
# pulling a copy for offline analysis while the original stays live. icacls grants SYSTEM/
# Administrators full control explicitly (rather than denying Everyone, which would also
# lock out the accounts that need to later restore or delete it) and denies execute to
# Everyone else. A sidecar .manifest.json records the original path/hash/timestamp for
# restoration, matching the FIM baseline's own "state lives next to the agent, survives
# an upgrade" pattern.
def quarantine_file(path):
    esc = path.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f"""$p = "{esc}"
if (-not (Test-Path $p -PathType Leaf)) {{ '{{"error":"file not found"}}'; exit }}
$hash = (Get-FileHash $p -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
$qDir = "C:\\ProgramData\\MicroDFIR\\Quarantine"
if (-not (Test-Path $qDir)) {{ New-Item -ItemType Directory -Path $qDir -Force | Out-Null }}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$shortHash = 'nohash'
if ($hash) {{ $shortHash = $hash.Substring(0, [Math]::Min(16, $hash.Length)) }}
$destName = "${{stamp}}_${{shortHash}}_$(Split-Path $p -Leaf).quarantined"
$dest = Join-Path $qDir $destName
try {{
    Move-Item -Path $p -Destination $dest -Force -ErrorAction Stop
    icacls $dest /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)" /deny "Everyone:(RX)" | Out-Null
    $manifest = @{{ original_path = $p; quarantined_path = $dest; sha256 = $hash; quarantined_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }}
    $manifest | ConvertTo-Json -Compress | Out-File -FilePath "$dest.manifest.json" -Encoding utf8
    $manifest | ConvertTo-Json -Compress
}} catch {{
    $errMsg = $_.Exception.Message -replace '"', "'"
    "{{`"error`":`"failed to quarantine: $errMsg`"}}"
}}
"""

# Triage-scoped volatile-data capture, not full RAM acquisition: dumps ONE process's
# memory (a PID an analyst already has in hand -- same "live PID just seen" precedent as
# kill_process()), not the whole system. Uses comsvcs.dll's built-in MiniDump export
# (rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> <path> full) -- no
# third-party tool to bundle or download, since it's already present on every Windows box.
# This is the exact same OS-native mechanism real-world credential-dumping TTPs use
# against lsass.exe (see _is_suspicious_lsass_process_access() and its own comment
# elsewhere in this codebase) -- pointed at an arbitrary suspicious process instead, for
# legitimate triage. Expect it to be flagged/blocked by the endpoint's own AV/EDR when
# targeting a protected process (lsass.exe, a PPL-protected service) -- that's a correct,
# expected outcome of a defensive product using a known-abusable mechanism, not a bug.
#
# The dump itself (commonly tens to hundreds of MB, sometimes more) is deliberately left
# on the endpoint's own disk, NOT transferred back through the agent command channel --
# collect_file()'s own 40KB cap exists precisely because a single command's result has to
# fit in a bounded JSON stdout blob (see collect_file()'s comment), and a memory dump is
# routinely 1000x that size. What comes back here is metadata only (path, size, hash,
# process identity) so the capture is recorded and hash-verifiable; an analyst retrieves
# the actual .dmp out-of-band (RDP/PsExec/etc.) and can upload it as a case attachment --
# which now hashes on upload and re-verifies on every download (see case_attachments) --
# to cross-check it against the hash recorded here at capture time.
def capture_process_memory(pid):
    pid = int(pid)
    return f"""$targetPid = {pid}
try {{ $proc = Get-Process -Id $targetPid -ErrorAction Stop }}
catch {{ "{{`"error`":`"no process with PID $targetPid`"}}"; exit }}
$dir = "C:\\ProgramData\\MicroDFIR\\MemoryCaptures"
if (-not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$safeName = ($proc.ProcessName -replace '[^a-zA-Z0-9_-]', '_')
$outPath = Join-Path $dir "${{stamp}}_pid${{targetPid}}_${{safeName}}.dmp"
$procImage = $proc.Path
try {{
    Start-Process -FilePath "rundll32.exe" -ArgumentList "C:\\Windows\\System32\\comsvcs.dll, MiniDump $targetPid `"$outPath`" full" -Wait -WindowStyle Hidden -ErrorAction Stop
}} catch {{
    $errMsg = $_.Exception.Message -replace '"', "'"
    "{{`"error`":`"failed to launch dump: $errMsg`"}}"; exit
}}
if (-not (Test-Path $outPath) -or (Get-Item $outPath).Length -eq 0) {{
    "{{`"error`":`"dump produced no output -- the process may be protected (PPL) or blocked by AV/EDR on this endpoint`"}}"; exit
}}
$size = (Get-Item $outPath).Length
$hash = (Get-FileHash $outPath -Algorithm SHA256).Hash
@{{ pid=$targetPid; process_name=$proc.ProcessName; process_image=$procImage; dump_path=$outPath; size_bytes=$size; sha256=$hash; captured_at=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }} | ConvertTo-Json -Compress
"""

# capture_process_memory()'s real limitation: it needs an already-identified PID, which
# an analyst doing FIRST triage on a possibly-compromised host usually doesn't have yet --
# a chicken-and-egg gap. This closes it by doing the picking itself: a simple,
# entirely-local (no server round-trip) suspicion heuristic ranks every running process,
# and the top few get memory-dumped automatically via the same comsvcs.dll MiniDump
# mechanism/output metadata shape as capture_process_memory() above (dump stays on the
# endpoint's disk; only hash/metadata comes back).
#
# The heuristic is deliberately simple and explainable, not a real detection model:
# +1 for a non-standard install path, +1 for an invalid/missing Authenticode signature,
# +2 for an established TCP connection to a non-private IP (weighted highest since an
# active outbound connection to the public internet is the strongest single signal of
# ongoing C2/exfil this script can check without a network round-trip). A handful of
# core OS processes are excluded outright -- not because they can't score high (they
# rarely would), but because dumping one on a host that's actively under investigation
# is a real stability risk for no real triage benefit (their own behavior is already
# implicitly trusted by the OS, and lsass.exe already has its own deliberate, single-PID
# path via capture_process_memory when an analyst genuinely wants it).
#
# [Confirmed by actually running this on a real Windows box, not just eyeballing it --
# see the session that added this comment] Get-AuthenticodeSignature is genuinely slow
# (disk I/O + Authenticode chain validation per call) -- calling it unconditionally for
# every running process took well over 60s against a normal dev-machine process count
# (150-300+), which would risk blowing this agent's own 180s SCRIPT_TIMEOUT_SECONDS on
# a production host. Fixed by only running it as a SECOND pass, on the (typically small)
# subset of processes that already scored from the cheap checks (non-standard path or a
# live external connection) -- both faster and a better heuristic, since signature
# corroborates an already-flagged process rather than blanket-scanning everything. Also
# deduplicated by path (many processes, e.g. several svchost.exe, share one executable)
# so a shared image is never signature-checked more than once.
#
# TOP_N and the per-process size cap both exist to respect this agent's own
# SCRIPT_TIMEOUT_SECONDS (180s, run_remote_script() in micro_agent_windows.py) and the
# 60,000-char stdout cap (api_agent_result, app.py) that bounds this command's whole
# JSON result -- a handful of small dumps' metadata comfortably fits either; a dozen
# multi-GB dumps would not.
_TOP_SUSPICIOUS_MEMORY_N = 3
_TOP_SUSPICIOUS_MEMORY_MAX_WORKING_SET_MB = 500

def capture_top_suspicious_memory():
    protected = "'System','Idle','csrss','wininit','services','smss','winlogon','lsass','Registry','Memory Compression'"
    return r"""$topN = """ + str(_TOP_SUSPICIOUS_MEMORY_N) + r"""
$maxBytes = """ + str(_TOP_SUSPICIOUS_MEMORY_MAX_WORKING_SET_MB) + r"""MB
$protectedNames = @(""" + protected + r""")
$standardDirs = @($env:WINDIR, "$env:WINDIR\System32", "$env:WINDIR\SysWOW64", ${env:ProgramFiles}, ${env:ProgramFiles(x86)}) | Where-Object { $_ }

$connByPid = @{}
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.RemoteAddress -and $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)') {
        $connByPid[$_.OwningProcess] = $true
    }
}

# Pass 1 -- cheap checks only (no disk I/O beyond what Get-Process already did).
$candidates = @()
foreach ($p in (Get-Process | Where-Object { $protectedNames -notcontains $_.ProcessName })) {
    $score = 0
    $reasons = @()
    if ($p.Path) {
        $inStandardDir = $false
        foreach ($d in $standardDirs) { if ($p.Path.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)) { $inStandardDir = $true; break } }
        if (-not $inStandardDir) { $score += 1; $reasons += 'non-standard install path' }
    } else {
        $score += 1; $reasons += 'no accessible executable path'
    }
    if ($connByPid.ContainsKey($p.Id)) { $score += 2; $reasons += 'active connection to a non-private IP' }
    if ($score -gt 0) { $candidates += [PSCustomObject]@{ Process = $p; Score = $score; Reasons = $reasons } }
}

# Pass 2 -- signature check, only for candidates the cheap pass already flagged, and only
# once per unique executable path (see the comment above this function for why).
$sigCache = @{}
foreach ($c in $candidates) {
    $path = $c.Process.Path
    if (-not $path) { continue }
    if (-not $sigCache.ContainsKey($path)) {
        try { $sigCache[$path] = (Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop).Status } catch { $sigCache[$path] = 'Unknown' }
    }
    if ($sigCache[$path] -ne 'Valid') { $c.Score += 1; $c.Reasons += 'unsigned or invalid signature' }
}
$candidates = $candidates | ForEach-Object { [PSCustomObject]@{ Process = $_.Process; Score = $_.Score; Reasons = ($_.Reasons -join '; ') } }

$targets = $candidates | Sort-Object -Property Score -Descending | Select-Object -First $topN
if (-not $targets) { '{"message":"no processes scored as suspicious -- nothing captured","captures":[]}'; exit }

$dir = "C:\ProgramData\MicroDFIR\MemoryCaptures"
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$captures = @()
foreach ($t in $targets) {
    $p = $t.Process
    if ($p.WorkingSet64 -gt $maxBytes) {
        $captures += @{ pid = $p.Id; process_name = $p.ProcessName; score = $t.Score; reasons = $t.Reasons; error = "skipped -- working set ($($p.WorkingSet64) bytes) exceeds the $maxBytes byte cap for an automatic bulk dump" }
        continue
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeName = ($p.ProcessName -replace '[^a-zA-Z0-9_-]', '_')
    $outPath = Join-Path $dir "${stamp}_pid$($p.Id)_${safeName}.dmp"
    try {
        Start-Process -FilePath "rundll32.exe" -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $($p.Id) `"$outPath`" full" -Wait -WindowStyle Hidden -ErrorAction Stop
        if (-not (Test-Path $outPath) -or (Get-Item $outPath).Length -eq 0) {
            $captures += @{ pid = $p.Id; process_name = $p.ProcessName; score = $t.Score; reasons = $t.Reasons; error = "dump produced no output -- the process may be protected (PPL) or blocked by AV/EDR on this endpoint" }
            continue
        }
        $size = (Get-Item $outPath).Length
        $hash = (Get-FileHash $outPath -Algorithm SHA256).Hash
        $captures += @{ pid = $p.Id; process_name = $p.ProcessName; process_image = $p.Path; dump_path = $outPath; size_bytes = $size; sha256 = $hash; score = $t.Score; reasons = $t.Reasons; captured_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
    } catch {
        $errMsg = $_.Exception.Message -replace '"', "'"
        $captures += @{ pid = $p.Id; process_name = $p.ProcessName; score = $t.Score; reasons = $t.Reasons; error = "failed to dump: $errMsg" }
    }
}
@{ captures = $captures } | ConvertTo-Json -Compress -Depth 4
"""

# Start-MpScan -ScanType QuickScan runs synchronously (blocks this whole script until it
# finishes) -- a quick scan is typically a few minutes, comfortably inside this agent's
# own 180s SCRIPT_TIMEOUT_SECONDS, but that's a real host-dependent "typically," not a
# guarantee: a heavily loaded or unusually large QuickScan target set can still exceed
# it. If it does, run_remote_script() (micro_agent_windows.py) reports a clean
# "Command timed out after 180s" result rather than hanging or crashing -- a known,
# accepted, self-explanatory failure mode, not a silent one. For anything that can
# genuinely run long, see defender_full_scan() below, which launches detached instead of
# blocking.
def defender_quick_scan():
    return r"""try {
    Start-MpScan -ScanType QuickScan -ErrorAction Stop
} catch {
    $errMsg = $_.Exception.Message -replace '"', "'"
    "{`"error`":`"failed to run quick scan: $errMsg`"}"; exit
}
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    # Get-MpThreatDetection has no "from this specific scan run" filter -- Defender
    # doesn't expose one -- so this approximates it with a lookback window a little
    # longer than a quick scan's typical runtime. A real detection from just before this
    # scan started could double-count; an honest approximation, not a precise join.
    $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-15) })
    @{ status = 'completed'; scan_type = 'QuickScan'; last_quick_scan_time = $status.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss'); antivirus_signature_age_days = $status.AntivirusSignatureAge; threats_found_recently = $threats.Count; threats = @($threats | Select-Object -First 20 -Property ThreatName,Resources,ActionSuccess) } | ConvertTo-Json -Compress -Depth 4
} catch {
    '{"status":"completed","scan_type":"QuickScan","note":"scan completed but status/threat detail was unavailable"}'
}
"""

# A full scan (every file on every local drive) can take hours on a real disk -- nowhere
# close to fitting inside SCRIPT_TIMEOUT_SECONDS, so unlike defender_quick_scan() this
# launches detached and returns immediately, the same "write a child .ps1, Start-Process
# it independently, self-delete when done" pattern beacon_simulator() below already
# established for exactly this "runs far longer than one command's budget" shape. There
# is deliberately no companion "check full-scan status" action -- same as
# beacon_simulator, this tool doesn't wait for or report back detached work; an admin
# can check Get-MpComputerStatus.FullScanEndTime later via a Custom Command.
def defender_full_scan():
    child_body = r"""try { Start-MpScan -ScanType FullScan -ErrorAction Stop } catch {}
Remove-Item -Path $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"""
    return f"""$dir = "C:\\ProgramData\\MicroDFIR\\DefenderScans"
if (-not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
$childScript = Join-Path $dir "fullscan_$stamp.ps1"
@'
{child_body}
'@ | Set-Content -Path $childScript -Encoding UTF8
Start-Process -FilePath "powershell.exe" -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$childScript`"") -WindowStyle Hidden
@{{ status = 'started'; scan_type = 'FullScan'; note = 'Runs detached in the background and can take hours depending on disk size -- check Get-MpComputerStatus.FullScanEndTime later (e.g. via a Custom Command) to confirm it finished.' }} | ConvertTo-Json -Compress
"""

# Validation tool for UEBA's Beaconing Detection model (see _run_beaconing_model in
# ueba_engine.py) -- generates a real, jittered, periodic TCP connect pattern from this
# host to an admin-chosen target, the same "known controlled beacon" idea as
# activecm/threat-tools' beacon-simulator.py, so a SOC can confirm the detector actually
# catches a real regularity pattern instead of trusting it on faith. Windows-only,
# deliberately: the detector itself only ever reads Sysmon Event ID 3 (Network
# Connection) rows, a Windows-only data source (see _run_beaconing_model's own comment)
# -- a Linux/macOS version would generate connections the detector can never see, so it
# would validate nothing. The run itself must survive well past this agent's own
# SCRIPT_TIMEOUT_SECONDS (180s, see run_remote_script() in micro_agent_windows.py) for
# any realistic beacon interval (the model's own default lookback is 24h), so this
# builder only writes and detaches a background .ps1 (via Start-Process, a real
# independent OS process, not a Start-Job pipe tied to this script's own lifetime) and
# returns immediately -- it does not itself wait for the beacon run to finish.
def beacon_simulator(target_ip, target_port, interval_seconds, jitter_seconds, count):
    if not _IPV4_RE.match(target_ip):
        raise ValueError(f"Invalid target IP address: {target_ip!r}")
    try:
        target_port = int(target_port)
        interval_seconds = int(interval_seconds)
        jitter_seconds = int(jitter_seconds)
        count = int(count)
    except (TypeError, ValueError):
        raise ValueError("target_port, interval_seconds, jitter_seconds, and count must all be integers")
    if not (1 <= target_port <= 65535):
        raise ValueError("target_port must be 1-65535")
    if not (5 <= interval_seconds <= 3600):
        raise ValueError("interval_seconds must be 5-3600")
    if not (0 <= jitter_seconds <= interval_seconds):
        raise ValueError("jitter_seconds must be 0 and not exceed interval_seconds")
    if not (3 <= count <= 100):
        raise ValueError("count must be 3-100")
    if interval_seconds * count > 86400:
        raise ValueError("interval_seconds * count must not exceed 86400 seconds (24h) -- lower the count or interval")

    # Every value below is already a Python-side literal (validated above), not a
    # PowerShell variable that needs runtime interpolation -- so the child script's
    # entire body can be written to disk via a non-interpolating single-quoted
    # here-string (@'...'@) in the outer script, with no backtick-escaping of `$`/`{`/`}`
    # needed between the two script layers, unlike a double-quoted here-string would need.
    child_body = f"""$ip = '{target_ip}'
$port = {target_port}
$interval = {interval_seconds}
$jitter = {jitter_seconds}
$count = {count}
for ($i = 0; $i -lt $count; $i++) {{
    try {{
        $client = New-Object System.Net.Sockets.TcpClient
        $task = $client.ConnectAsync($ip, $port)
        $task.Wait(3000) | Out-Null
        $client.Close()
    }} catch {{}}
    if ($i -lt ($count - 1)) {{
        $off = Get-Random -Minimum (-$jitter) -Maximum ($jitter + 1)
        $sleepFor = [Math]::Max(1, $interval + $off)
        Start-Sleep -Seconds $sleepFor
    }}
}}
Remove-Item -Path $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"""
    estimated_seconds = interval_seconds * (count - 1)
    return f"""$dir = "C:\\ProgramData\\MicroDFIR\\BeaconSim"
if (-not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
$childScript = Join-Path $dir "beacon_$stamp.ps1"
@'
{child_body}
'@ | Set-Content -Path $childScript -Encoding UTF8
Start-Process -FilePath "powershell.exe" -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$childScript`"") -WindowStyle Hidden
@{{ status = 'started'; target = '{target_ip}:{target_port}'; interval_seconds = {interval_seconds}; jitter_seconds = {jitter_seconds}; connection_count = {count}; estimated_finish = (Get-Date).AddSeconds({estimated_seconds}).ToString('yyyy-MM-dd HH:mm:ss') }} | ConvertTo-Json -Compress
"""

def _ps_hashset_literal(values):
    return ','.join("'" + v + "'" for v in values)

def ioc_sweep(hashes, md5_hashes=None, sha1_hashes=None):
    # Only ever trust hex-shaped values here regardless of what the caller passed —
    # these ultimately come from the live threat-intel IOC list, whose ioc_type
    # labeling is inconsistent across feeds (see _get_live_ioc_*_hashes in app.py), so
    # re-validating by shape at the point the value gets embedded into a script is the
    # actual safety boundary, not a redundant check.
    valid_sha256 = sorted({(h or '').strip().lower() for h in hashes if _SHA256_RE.match((h or '').strip())})
    valid_md5 = sorted({(h or '').strip().lower() for h in (md5_hashes or []) if _MD5_RE.match((h or '').strip())})
    valid_sha1 = sorted({(h or '').strip().lower() for h in (sha1_hashes or []) if _SHA1_RE.match((h or '').strip())})
    if not valid_sha256 and not valid_md5 and not valid_sha1:
        # A real, expected state (no hash IOCs of any kind currently loaded) — emit a
        # script that reports that clearly rather than one that silently "succeeds"
        # with a zero-hit sweep that looks identical to a clean host.
        return "Write-Output '{\"error\":\"no IOC hashes are currently available to sweep for\"}'"
    # Bounded to common malware-drop locations, recently-modified, executable-ish
    # files under 50MB — a full-disk hash sweep would blow past the agent's 90s
    # command timeout on any real machine, and this is also where live-response
    # triage actually looks first.
    script = """$sha256Set = New-Object System.Collections.Generic.HashSet[string]
@(__SHA256_HASHES__) | ForEach-Object { [void]$sha256Set.Add($_) }
$md5Set = New-Object System.Collections.Generic.HashSet[string]
@(__MD5_HASHES__) | ForEach-Object { [void]$md5Set.Add($_) }
$sha1Set = New-Object System.Collections.Generic.HashSet[string]
@(__SHA1_HASHES__) | ForEach-Object { [void]$sha1Set.Add($_) }
$sha256Algo = [System.Security.Cryptography.SHA256]::Create()
$md5Algo = [System.Security.Cryptography.MD5]::Create()
$sha1Algo = [System.Security.Cryptography.SHA1]::Create()
$paths = @($env:TEMP, $env:APPDATA, $env:ProgramData, (Join-Path $env:USERPROFILE 'Downloads'))
$cutoff = (Get-Date).AddDays(-14)
$exts = @('.exe','.dll','.scr','.ps1','.bat','.vbs','.js','.jar','.msi')
$scanned = 0
$hits = @()
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }
    Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff -and $exts -contains $_.Extension.ToLower() -and $_.Length -lt 50MB } |
        ForEach-Object {
            $scanned++
            try {
                # Hashed once from a single in-memory read, not three separate
                # Get-FileHash calls, so adding MD5/SHA1 costs no extra file I/O.
                $bytes = [IO.File]::ReadAllBytes($_.FullName)
                $sha256 = [BitConverter]::ToString($sha256Algo.ComputeHash($bytes)).Replace('-', '').ToLower()
                $md5 = [BitConverter]::ToString($md5Algo.ComputeHash($bytes)).Replace('-', '').ToLower()
                $sha1 = [BitConverter]::ToString($sha1Algo.ComputeHash($bytes)).Replace('-', '').ToLower()
                $matched = @()
                if ($sha256Set.Contains($sha256)) { $matched += 'sha256' }
                if ($md5Set.Contains($md5)) { $matched += 'md5' }
                if ($sha1Set.Contains($sha1)) { $matched += 'sha1' }
                if ($matched.Count -gt 0) {
                    $hits += [PSCustomObject]@{ path=$_.FullName; sha256=$sha256; md5=$md5; sha1=$sha1; matched=@($matched); size=$_.Length; modified=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
                }
            } catch {}
        }
}
[PSCustomObject]@{ scanned=$scanned; hits=$hits } | ConvertTo-Json -Compress -Depth 6
"""
    return (script.replace('__SHA256_HASHES__', _ps_hashset_literal(valid_sha256))
                  .replace('__MD5_HASHES__', _ps_hashset_literal(valid_md5))
                  .replace('__SHA1_HASHES__', _ps_hashset_literal(valid_sha1)))

def _ps_escape_literal(s):
    return s.replace("'", "''")

def string_sweep(patterns):
    # patterns: [{rule, file, string}, ...] from the live-imported YARA rule strings
    # (app.py's _get_live_yara_strings). Deduped by string value for the actual search
    # list — Select-String only needs the value once — with a value->rule map kept for
    # hit attribution; if the exact same literal string appears in more than one
    # imported rule, the first one wins (rare, and not worth complicating the report).
    seen = {}
    for p in (patterns or []):
        val = (p.get('string') or '').strip()
        if not val or val in seen:
            continue
        seen[val] = p.get('rule') or 'unknown'
    if not seen:
        return "Write-Output '{\"error\":\"no YARA string patterns are currently available to sweep for\"}'"
    pattern_list = ','.join("'" + _ps_escape_literal(v) + "'" for v in seen)
    rule_map = ';'.join("'" + _ps_escape_literal(v) + "'='" + _ps_escape_literal(r) + "'" for v, r in seen.items())
    # Same bounded scope as ioc_sweep, but a lower size cap — scanning file *content*
    # for hundreds of literal substrings is heavier per file than hashing, and still
    # has to fit inside the agent's command timeout.
    #
    # This used to pass the whole $patterns array straight to a single Select-String
    # call (-SimpleMatch -Pattern $patterns), which looks like one pass but isn't:
    # PowerShell checks every line against *each* pattern independently, so cost scales
    # with file_size * pattern_count -- confirmed in production, every run timed out
    # with 0 files reported scanned. The first fix attempt combined the patterns into
    # one [regex] alternation instead -- correct in principle, but measured empirically
    # (real generated script, real ~2MB files) at only ~3s/file: .NET's backtracking
    # regex engine doesn't turn a large literal alternation into a single efficient
    # pass the way a proper multi-pattern search (e.g. Aho-Corasick) would, so it still
    # scales with pattern count under the hood. A plain per-pattern String.Contains()
    # loop measured ~2.8x faster than that at the same scale (Contains uses .NET's own
    # optimized substring search rather than a regex engine at all) and is what's used
    # below, combined with a lower pattern cap and size cap (see _get_live_yara_strings
    # in app.py and the 5MB threshold here) to keep total worst-case time well inside
    # the agent's command timeout even on a machine with many candidate files.
    # Real production output (95 files scanned, generic strings like "Microsoft" and
    # "Uninstall" still in the pattern set at the time) produced a single-file result
    # with 100+ matched patterns and a total payload well past the server's stdout
    # storage cap -- silently truncated mid-string into invalid JSON, which is worse
    # than an intentional, visible limit. Both caps below are enforced with an explicit
    # count/flag in the output so the UI can say "showing 8 of 143 matches" rather than
    # just quietly dropping data and looking identical to a small, complete result.
    script = """$patterns = @(__PATTERNS__)
$ruleMap = @{__RULEMAP__}
$paths = @($env:TEMP, $env:APPDATA, $env:ProgramData, (Join-Path $env:USERPROFILE 'Downloads'))
$cutoff = (Get-Date).AddDays(-14)
$exts = @('.exe','.dll','.scr','.ps1','.bat','.vbs','.js','.jar','.msi')
$maxHits = 50
$maxMatchesPerFile = 8
$scanned = 0
$hits = @()
$totalMatchingFiles = 0
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }
    Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff -and $exts -contains $_.Extension.ToLower() -and $_.Length -lt 5MB } |
        ForEach-Object {
            $scanned++
            try {
                $content = [IO.File]::ReadAllText($_.FullName)
                $found = @($patterns | Where-Object { $content.Contains($_) })
                if ($found.Count -gt 0) {
                    $totalMatchingFiles++
                    if ($hits.Count -lt $maxHits) {
                        $matchCount = $found.Count
                        $foundCapped = @($found | Select-Object -First $maxMatchesPerFile)
                        $matches = @($foundCapped | ForEach-Object { [PSCustomObject]@{ rule = $ruleMap[$_]; string = $_ } })
                        $hits += [PSCustomObject]@{ path=$_.FullName; size=$_.Length; modified=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); matches=$matches; match_count=$matchCount; matches_truncated=($matchCount -gt $maxMatchesPerFile) }
                    }
                }
            } catch {}
        }
}
[PSCustomObject]@{ scanned=$scanned; hits=$hits; total_matching_files=$totalMatchingFiles; hits_truncated=($totalMatchingFiles -gt $maxHits) } | ConvertTo-Json -Compress -Depth 6
"""
    return script.replace('__PATTERNS__', pattern_list).replace('__RULEMAP__', rule_map)

def _ps_string_array_literal(values):
    return ','.join("'" + _ps_escape_literal(v) + "'" for v in values)

def yara_condition_sweep(rule_conditions):
    # rule_conditions: [{rule, strings, required_n, condition_label}, ...] from
    # app.py's _get_live_yara_rule_conditions() -- a real condition check ("at least
    # required_n of these strings must be present"), not string_sweep's independent
    # any-string-hit reporting. required_n already folds any/all/N-of-them into one
    # plain integer threshold, so the only comparison needed here is count >= required_n.
    rules = [r for r in (rule_conditions or []) if r.get('strings') and r.get('required_n')]
    if not rules:
        return "Write-Output '{\"error\":\"no condition-evaluable YARA rules are currently available to sweep for\"}'"
    rules_src = ','.join(
        "[PSCustomObject]@{ rule='%s'; requiredN=%d; label='%s'; strings=@(%s) }" % (
            _ps_escape_literal(r['rule']), int(r['required_n']), _ps_escape_literal(r.get('condition_label', '')),
            _ps_string_array_literal(r['strings']),
        )
        for r in rules
    )
    # Same bounded scope/extension list as string_sweep() above, and the same
    # Contains()-loop-over-a-flat-pattern-list performance lesson applies here too --
    # per-rule string counts are summed with the same per-pattern .Contains() loop,
    # just grouped by rule afterward instead of reported independently.
    script = """$rules = @(__RULES__)
$paths = @($env:TEMP, $env:APPDATA, $env:ProgramData, (Join-Path $env:USERPROFILE 'Downloads'))
$cutoff = (Get-Date).AddDays(-14)
$exts = @('.exe','.dll','.scr','.ps1','.bat','.vbs','.js','.jar','.msi')
$maxHits = 50
$scanned = 0
$hits = @()
$totalMatchingFiles = 0
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }
    Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff -and $exts -contains $_.Extension.ToLower() -and $_.Length -lt 5MB } |
        ForEach-Object {
            $scanned++
            try {
                $content = [IO.File]::ReadAllText($_.FullName)
                $matchedRules = @()
                foreach ($r in $rules) {
                    $count = 0
                    foreach ($s in $r.strings) { if ($content.Contains($s)) { $count++ } }
                    if ($count -ge $r.requiredN) {
                        $matchedRules += [PSCustomObject]@{ rule=$r.rule; condition=$r.label; matched_strings=$count; total_strings=$r.strings.Count }
                    }
                }
                if ($matchedRules.Count -gt 0) {
                    $totalMatchingFiles++
                    if ($hits.Count -lt $maxHits) {
                        $hits += [PSCustomObject]@{ path=$_.FullName; size=$_.Length; modified=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); matched_rules=$matchedRules }
                    }
                }
            } catch {}
        }
}
[PSCustomObject]@{ scanned=$scanned; hits=$hits; rules_evaluated=$rules.Count; total_matching_files=$totalMatchingFiles; hits_truncated=($totalMatchingFiles -gt $maxHits) } | ConvertTo-Json -Compress -Depth 6
"""
    return script.replace('__RULES__', rules_src)

# Progress records (e.g. from Get-FileHash on multiple files in collect_triage) get
# serialized as CLIXML and mixed straight into stdout when PowerShell runs
# non-interactively with its output captured — confirmed in production, where a
# collect_triage result had a "#< CLIXML" progress blob appended after the real JSON.
# Silencing progress up front keeps every template's stdout clean.
_PROGRESS_SILENT = "$ProgressPreference = 'SilentlyContinue'\n"

# A dedicated, much deeper enumeration than collect_triage()'s 2-key autoruns snippet
# above -- Run/RunOnce under both HKLM and HKCU, scheduled tasks, services (with their
# binary path, since a malicious service often points somewhere outside System32),
# every Startup folder (per-user and all-users), and WMI event subscriptions (a classic
# fileless-persistence technique: __EventFilter/__EventConsumer/__FilterToConsumerBinding).
# Inspired by Sysinternals Autoruns and Velociraptor's persistence-focused artifacts.
#
# Diffs against a baseline persisted to persistence_baseline.json in the agent's own
# INSTALL_DIR (the first script of its kind to read-diff-write local JSON state in
# PowerShell rather than Python -- ConvertFrom-Json/ConvertTo-Json handle the
# serialization, PSObject.Properties rebuilds a hashtable for key lookups since
# ConvertFrom-Json returns a PSCustomObject, not a hashtable) -- an analyst re-running
# this repeatedly during an investigation sees only what's new/changed/gone since the
# last run, not a full re-dump every time. The very first run against a host with no
# baseline yet reports everything as "new" (first_run=true) -- expected, not a bug,
# same as the FIM feature's own first-check behavior. Runs as a one-shot dispatched
# script (see run_remote_script() in micro_agent_windows.py), not the always-running
# poll loop, so two sweeps queued back-to-back faster than one poll cycle apart could
# theoretically race on this same file -- low-probability given typical usage, not
# guarded against here.
def persistence_sweep():
    return r"""$StatePath = "C:\Program Files\MicroDFIR\persistence_baseline.json"
$current = @{}
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
    $current["task:$($_.TaskPath)$($_.TaskName)"] = "$($_.State)|$actions"
}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $current["service:$($_.Name)"] = "$($_.State)|$($_.StartMode)|$($_.PathName)"
}
foreach ($key in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $current["runkey:$key\$($_.Name)"] = "$($_.Value)"
        }
    }
}
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | ForEach-Object {
    $current["startup:$($_.FullName)"] = "$($_.Length)|$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
}
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
    $current["wmi_filter:$($_.Name)"] = "$($_.Query)"
}
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    $current["wmi_consumer:$($_.Name)"] = "$($_.CommandLineTemplate)$($_.ScriptFileName)"
}
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
    $current["wmi_binding:$($_.Filter)"] = "$($_.Consumer)"
}

$baseline = @{}
if (Test-Path $StatePath) {
    try {
        $loaded = Get-Content $StatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $loaded.PSObject.Properties | ForEach-Object { $baseline[$_.Name] = $_.Value }
    } catch {}
}

$newEntries = @{}
$changedEntries = @{}
$removedKeys = @()
foreach ($k in $current.Keys) {
    if (-not $baseline.ContainsKey($k)) {
        $newEntries[$k] = $current[$k]
    } elseif ($baseline[$k] -ne $current[$k]) {
        $changedEntries[$k] = @{ old = $baseline[$k]; new = $current[$k] }
    }
}
foreach ($k in $baseline.Keys) {
    if (-not $current.ContainsKey($k)) { $removedKeys += $k }
}

try {
    $stateDir = Split-Path $StatePath -Parent
    if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
    $current | ConvertTo-Json -Depth 4 -Compress | Set-Content -Path $StatePath -Encoding utf8
} catch {}

@{ total_entries = $current.Count; new = $newEntries; changed = $changedEntries; removed = $removedKeys; first_run = ($baseline.Count -eq 0) } | ConvertTo-Json -Depth 5 -Compress
"""

# Metadata/listing only, not binary parsing -- History/places.sqlite are locked while
# the browser's running (hashing just fails gracefully via try/catch, same pattern as
# collect_triage's own process hashes), and there's no SQLite reader built into vanilla
# PowerShell to query browsing history without a new dependency. Walks every profile
# under C:\Users (the agent runs at highest privilege via its scheduled task, not just
# the interactively-logged-in user) rather than just $env:USERPROFILE.
def collect_browser_artifacts():
    return r"""$result = @{}
$browsers = New-Object System.Collections.ArrayList
$downloads = New-Object System.Collections.ArrayList
$visitedUrls = New-Object System.Collections.ArrayList
# Byte-level varint/record decoding in interpreted PowerShell is slow -- empirically
# ~0.03s/row against a real production-sized History file, so this cap is chosen to
# keep total parsing time (across every Chrome/Edge profile found) comfortably inside
# the agent's SCRIPT_TIMEOUT_SECONDS (180s) budget rather than risking the whole
# response action timing out on a host with a large or multi-profile history.
$HISTORY_ROW_CAP = 600

# Minimal, dependency-free SQLite table-B-tree reader -- no System.Data.SQLite/ODBC
# provider available on a vanilla Windows endpoint, so this parses the file format
# directly per the public spec (https://sqlite.org/fileformat2.html). Reads a named
# table's rows via a full leaf-page traversal from its root page (found via
# sqlite_master); a payload that spills to an overflow page (rare for url/title-length
# text) is flagged Overflowed=$true with a null value rather than guessed at.
function Get-SqliteVarint {
    param([byte[]]$Bytes, [int64]$Offset)
    $result = [int64]0
    for ($i = 0; $i -lt 8; $i++) {
        $b = [int64]$Bytes[$Offset + $i]
        $result = ($result -shl 7) -bor ($b -band 0x7F)
        if (($b -band 0x80) -eq 0) { return , @($result, ($i + 1)) }
    }
    $b = [int64]$Bytes[$Offset + 8]
    $result = ($result -shl 8) -bor $b
    return , @($result, 9)
}

function ConvertFrom-SqliteBigEndianInt {
    param([byte[]]$Bytes, [int64]$Offset, [int]$Length)
    $isNegative = ($Bytes[$Offset] -band 0x80) -ne 0
    $buf = New-Object byte[] 8
    for ($i = 0; $i -lt 8; $i++) { $buf[$i] = if ($isNegative) { 0xFF } else { 0x00 } }
    for ($i = 0; $i -lt $Length; $i++) { $buf[$Length - 1 - $i] = $Bytes[$Offset + $i] }
    return [BitConverter]::ToInt64($buf, 0)
}

function Read-SqliteTable {
    # -PreferHighRowid walks pages so the highest-rowid cells (in SQLite's own ascending-
    # rowid page ordering) are read first. This matters when MaxRows caps a genuinely
    # large table: a table's rowid climbs by INSERTION order, not by when a row was last
    # touched, so reading in plain ascending (on-disk) order returns the OLDEST rows
    # first -- for Chrome/Edge's `urls` table specifically, the oldest first-ever-visited
    # URLs, not recent browsing activity. Preferring high rowids first is a much better
    # proxy for "recent" given a capped scan budget.
    param([string]$DbPath, [string]$TableName, [int]$MaxRows = 500, [switch]$PreferHighRowid)
    $bytes = [System.IO.File]::ReadAllBytes($DbPath)
    if ($bytes.Length -lt 100) { throw "Not a SQLite file (too small)" }
    if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 16) -ne "SQLite format 3`0") { throw "Not a SQLite file (bad header)" }
    $pageSize = ([int]$bytes[16] -shl 8) -bor [int]$bytes[17]
    if ($pageSize -eq 1) { $pageSize = 65536 }
    if ($pageSize -lt 512 -or $pageSize -gt 65536) { throw "Unexpected page size $pageSize" }
    function Get-PageOffset([int64]$pageNum) { return ($pageNum - 1) * $pageSize }
    function Read-Record([int64]$payloadOffset, [int64]$payloadLength, [int64]$usableSize) {
        # Per the SQLite file format spec (fileformat2.html section 1.5): X = usableSize-35
        # is the max local payload for a table leaf cell; when P > X, the number of bytes
        # actually stored locally is K = M + ((P-M) % (usableSize-4)), clamped to M when
        # K > X -- where M = ((usableSize-12)*32/255)-23 (integer division), NOT X itself.
        # An earlier version of this function substituted X for M in that formula, which
        # for a typical 4096-byte page overestimates the local length by roughly 2-3x
        # (e.g. computes 3153 bytes local where the true value is 908) -- reading well
        # past the record's real boundary and risking misinterpreting trailing overflow-
        # pointer/adjacent-cell bytes as genuine string/blob content instead of correctly
        # falling through to the $colOverflowed = $true / null path below.
        $maxLocal = $usableSize - 35
        $overflowed = $payloadLength -gt $maxLocal
        if ($overflowed) {
            # PowerShell's `/` always yields a double, and casting that to [int64] ROUNDS
            # to nearest rather than truncating -- the spec requires floor (truncating)
            # integer division here, so [math]::Floor is required, not a plain [int64] cast.
            $minLocal = [int64][math]::Floor((($usableSize - 12) * 32) / 255.0) - 23
            $k = $minLocal + (($payloadLength - $minLocal) % ($usableSize - 4))
            $localLength = if ($k -le $maxLocal) { $k } else { $minLocal }
        } else {
            $localLength = $payloadLength
        }
        if ($localLength -gt $payloadLength) { $localLength = $payloadLength }
        $pos = $payloadOffset
        $r = Get-SqliteVarint $bytes $pos
        $headerLen = $r[0]; $pos += $r[1]
        $headerEnd = $payloadOffset + $headerLen
        $serialTypes = New-Object System.Collections.Generic.List[int64]
        while ($pos -lt $headerEnd) {
            $r2 = Get-SqliteVarint $bytes $pos
            $serialTypes.Add($r2[0]) | Out-Null
            $pos += $r2[1]
        }
        $dataPos = $headerEnd
        $localEnd = $payloadOffset + $localLength
        $values = New-Object System.Collections.Generic.List[object]
        foreach ($st in $serialTypes) {
            $colOverflowed = $false
            $val = $null
            if ($st -eq 0) { $val = $null }
            elseif ($st -ge 1 -and $st -le 6) {
                $lenMap = @{1=1;2=2;3=3;4=4;5=6;6=8}
                $len = $lenMap[[int]$st]
                if ($dataPos + $len -le $localEnd) { $val = ConvertFrom-SqliteBigEndianInt $bytes $dataPos $len } else { $colOverflowed = $true }
                $dataPos += $len
            } elseif ($st -eq 7) {
                if ($dataPos + 8 -le $localEnd) {
                    $rev = New-Object byte[] 8
                    for ($i = 0; $i -lt 8; $i++) { $rev[$i] = $bytes[$dataPos + 7 - $i] }
                    $val = [BitConverter]::ToDouble($rev, 0)
                } else { $colOverflowed = $true }
                $dataPos += 8
            } elseif ($st -eq 8) { $val = [int64]0 }
            elseif ($st -eq 9) { $val = [int64]1 }
            elseif ($st -ge 12) {
                $isText = ($st % 2) -eq 1
                $len = if ($isText) { ($st - 13) / 2 } else { ($st - 12) / 2 }
                if ($dataPos + $len -le $localEnd) {
                    if ($len -eq 0) { $val = if ($isText) { "" } else { , (New-Object byte[] 0) } }
                    elseif ($isText) { $val = [System.Text.Encoding]::UTF8.GetString($bytes, $dataPos, $len) }
                    else { $val = $bytes[$dataPos..($dataPos + $len - 1)] }
                } else { $colOverflowed = $true }
                $dataPos += $len
            }
            if ($colOverflowed) { $values.Add($null) | Out-Null } else { $values.Add($val) | Out-Null }
        }
        return , @($values, $overflowed)
    }
    $rows = New-Object System.Collections.Generic.List[object]
    function Walk-Page([int64]$pageNum, [bool]$isFirstPage, [int64]$usableSize) {
        if ($rows.Count -ge $MaxRows) { return }
        $pageStart = Get-PageOffset $pageNum
        $hdrStart = if ($isFirstPage) { $pageStart + 100 } else { $pageStart }
        $pageType = $bytes[$hdrStart]
        $numCells = ([int]$bytes[$hdrStart + 3] -shl 8) -bor [int]$bytes[$hdrStart + 4]
        $cellPtrArrayStart = $hdrStart + $(if ($pageType -eq 0x05 -or $pageType -eq 0x02) { 12 } else { 8 })
        if ($pageType -eq 0x0d) {
            $cellRange = if ($PreferHighRowid) { ($numCells - 1)..0 } else { 0..($numCells - 1) }
            foreach ($c in $cellRange) {
                if ($rows.Count -ge $MaxRows) { break }
                $cellPtrOffset = $cellPtrArrayStart + ($c * 2)
                $cellOffset = $pageStart + (([int]$bytes[$cellPtrOffset] -shl 8) -bor [int]$bytes[$cellPtrOffset + 1])
                $pos = $cellOffset
                $r = Get-SqliteVarint $bytes $pos
                $payloadLen = $r[0]; $pos += $r[1]
                $r2 = Get-SqliteVarint $bytes $pos
                $rowId = $r2[0]; $pos += $r2[1]
                $rec = Read-Record $pos $payloadLen $usableSize
                $rows.Add(@{ RowId = $rowId; Values = $rec[0]; Overflowed = $rec[1] }) | Out-Null
            }
        } elseif ($pageType -eq 0x05) {
            $rightMost = ([int64]$bytes[$hdrStart+8] -shl 24) -bor ([int64]$bytes[$hdrStart+9] -shl 16) -bor ([int64]$bytes[$hdrStart+10] -shl 8) -bor [int64]$bytes[$hdrStart+11]
            if ($PreferHighRowid) { Walk-Page $rightMost $false $usableSize | Out-Null }
            $childRange = if ($PreferHighRowid) { ($numCells - 1)..0 } else { 0..($numCells - 1) }
            if ($numCells -gt 0) {
                foreach ($c in $childRange) {
                    if ($rows.Count -ge $MaxRows) { break }
                    $cellPtrOffset = $cellPtrArrayStart + ($c * 2)
                    $cellOffset = $pageStart + (([int]$bytes[$cellPtrOffset] -shl 8) -bor [int]$bytes[$cellPtrOffset + 1])
                    $childPage = ([int64]$bytes[$cellOffset] -shl 24) -bor ([int64]$bytes[$cellOffset+1] -shl 16) -bor ([int64]$bytes[$cellOffset+2] -shl 8) -bor [int64]$bytes[$cellOffset+3]
                    Walk-Page $childPage $false $usableSize | Out-Null
                }
            }
            if (-not $PreferHighRowid) { Walk-Page $rightMost $false $usableSize | Out-Null }
        }
    }
    $reservedSpace = $bytes[20]
    $usableSize = $pageSize - $reservedSpace
    Walk-Page 1 $true $usableSize | Out-Null
    $masterRows = $rows.ToArray()
    $rows.Clear()
    $rootPage = $null
    foreach ($mr in $masterRows) {
        $v = $mr.Values
        if ($v.Count -ge 4 -and $v[0] -eq 'table' -and $v[1] -eq $TableName) { $rootPage = $v[3]; break }
    }
    if ($null -eq $rootPage) { throw "Table '$TableName' not found in sqlite_master" }
    Walk-Page $rootPage $($rootPage -eq 1) $usableSize | Out-Null
    # The comma operator is load-bearing: bare "return $rows" lets PowerShell's pipeline
    # auto-enumerate the List<object>, so a 1-row result unwraps to its lone row object
    # instead of a 1-element list. ", $rows" returns the List itself, unconditionally.
    return , $rows
}

function Get-ChromeHistoryUrls([string]$SrcPath, [string]$UserName, [string]$BrowserName) {
    # Chrome/Edge keep History open with an exclusive lock while running -- copy first
    # so a byte-level read never races the live browser process.
    $tmpCopy = [System.IO.Path]::GetTempFileName()
    try {
        Copy-Item -Path $SrcPath -Destination $tmpCopy -Force -ErrorAction Stop
        $rows = Read-SqliteTable -DbPath $tmpCopy -TableName 'urls' -MaxRows $HISTORY_ROW_CAP -PreferHighRowid
        $chromeEpoch = [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        $parsed = foreach ($r in $rows) {
            $v = $r.Values
            if ($v.Count -lt 6) { continue }
            $lastVisitStr = $null
            if ($v[5] -is [int64] -and $v[5] -gt 0) {
                try { $lastVisitStr = $chromeEpoch.AddTicks($v[5] * 10).ToString('yyyy-MM-dd HH:mm:ss') } catch {}
            }
            if (-not $lastVisitStr) { continue }
            [PSCustomObject]@{ user=$UserName; browser=$BrowserName; url=$v[1]; title=$v[2]; visit_count=$v[3]; typed_count=$v[4]; last_visit_time=$lastVisitStr }
        }
        return @($parsed | Sort-Object last_visit_time -Descending | Select-Object -First 100)
    } catch {
        return @()
    } finally {
        Remove-Item $tmpCopy -Force -ErrorAction SilentlyContinue
    }
}

Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $uname = $_.Name
    $uhome = $_.FullName
    $chromeCandidates = @(
        @{ path=(Join-Path $uhome 'AppData\Local\Google\Chrome\User Data\Default\History'); browser='Chrome' },
        @{ path=(Join-Path $uhome 'AppData\Local\Microsoft\Edge\User Data\Default\History'); browser='Edge' }
    )
    foreach ($c in $chromeCandidates) {
        $p = $c.path
        if (Test-Path $p) {
            $item = Get-Item $p -ErrorAction SilentlyContinue
            if ($item) {
                $h = try { (Get-FileHash $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null }
                [void]$browsers.Add([PSCustomObject]@{ user=$uname; path=$p; size=$item.Length; last_write=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); sha256=$h })
                foreach ($u in (Get-ChromeHistoryUrls -SrcPath $p -UserName $uname -BrowserName $c.browser)) { [void]$visitedUrls.Add($u) }
            }
        }
    }
    $ffProfiles = Join-Path $uhome 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (Test-Path $ffProfiles) {
        Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $places = Join-Path $_.FullName 'places.sqlite'
            if (Test-Path $places) {
                $item = Get-Item $places -ErrorAction SilentlyContinue
                $h = try { (Get-FileHash $places -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null }
                [void]$browsers.Add([PSCustomObject]@{ user=$uname; path=$places; size=$item.Length; last_write=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); sha256=$h })
            }
        }
    }
    $dl = Join-Path $uhome 'Downloads'
    if (Test-Path $dl) {
        Get-ChildItem $dl -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 30 | ForEach-Object {
            [void]$downloads.Add([PSCustomObject]@{ user=$uname; name=$_.Name; size=$_.Length; last_write=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') })
        }
    }
}
$result.browser_history_files = $browsers
$result.recent_visited_urls = @($visitedUrls | Sort-Object last_visit_time -Descending | Select-Object -First 100)
$result.recent_downloads = $downloads
$result.note = "Chrome/Edge History is parsed for real url/title/visit_count/last_visit_time data (a locked-safe copy of the file is read, up to $HISTORY_ROW_CAP of the most-recently-created URL rows scanned per file for performance, then the 100 most recent visits among those shown). This favors recently-added URLs; a revisit of a URL that was first added long ago (e.g. a frequently-reused bookmark) can fall outside the scan cap even though its last-visit time is recent -- collect the file via 'Collect File' for exhaustive offline analysis if needed. Firefox places.sqlite uses a different, unparsed schema and stays metadata-only (hash+timestamp)."
$result | ConvertTo-Json -Depth 4 -Compress
"""

# Prefetch is listed directly (filenames/timestamps are already meaningful without
# parsing the binary body). Amcache/Shimcache are genuinely proprietary binary formats
# with no built-in PowerShell reader -- reported as metadata/existence only, same
# scope discipline as collect_browser_artifacts above, with an explicit pointer to
# offline tooling rather than a half-parsed guess at their internal structure.
def collect_forensic_timestamps():
    return r"""$result = @{}
$result.prefetch_enabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction SilentlyContinue).EnablePrefetcher
$result.prefetch_files = @(Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 150 | ForEach-Object { [PSCustomObject]@{ name=$_.Name; size=$_.Length; last_write=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); created=$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') } })
$amcachePath = 'C:\Windows\AppCompat\Programs\Amcache.hve'
if (Test-Path $amcachePath) {
    $item = Get-Item $amcachePath -ErrorAction SilentlyContinue
    $result.amcache = [PSCustomObject]@{ path=$amcachePath; size=$item.Length; last_write=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
} else {
    $result.amcache = $null
}
try {
    $shim = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name 'AppCompatCache' -ErrorAction Stop).AppCompatCache
    $result.shimcache_blob_bytes = $shim.Length
} catch {
    $result.shimcache_blob_bytes = $null
}
$result.note = "Prefetch is listed (name/timestamps); Amcache/Shimcache are proprietary binary formats reported as metadata only (existence/size/byte length) -- collect the file/hive via 'Collect File' and parse offline with a real tool (e.g. Eric Zimmerman's AmcacheParser/AppCompatCacheParser)."
$result | ConvertTo-Json -Depth 4 -Compress
"""

# A literal USN journal excerpt would need real offset/record parsing against
# `fsutil usn readjournal` (no built-in "last N minutes" filter, and reading from an
# unbounded starting point risks streaming the entire journal and blowing the script
# timeout) -- not safely buildable as a bounded one-shot script. This is the practical,
# reliably-bounded substitute: a straight recently-modified-files scan across the
# locations that matter for triage, which answers the same underlying question ("what
# changed on this host recently") without the USN parsing risk.
def collect_recent_file_changes():
    return r"""$result = @{}
$cutoff = (Get-Date).AddHours(-24)
$paths = @('C:\Windows\System32\Tasks', 'C:\Windows\Temp', "$env:ProgramData", "$env:WINDIR\System32\drivers")
$hits = @()
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }
    Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff } |
        Select-Object -First 300 |
        ForEach-Object { $hits += [PSCustomObject]@{ path=$_.FullName; size=$_.Length; last_write=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } }
}
$result.cutoff = $cutoff.ToString('yyyy-MM-dd HH:mm:ss')
$result.changed_files = $hits | Sort-Object last_write -Descending | Select-Object -First 200
$result.note = "A recently-modified-files scan (last 24h) across common drop/persistence locations -- not a literal USN journal parse (unbounded and timeout-risky as a one-shot script)."
$result | ConvertTo-Json -Depth 4 -Compress
"""

# A focused incident-triage bundle -- distinct from collect_triage()'s lighter
# always-useful snapshot (processes/connections/autoruns/users/startup) and from
# persistence_sweep()'s persistence-only deep dive. This is the artifact set an
# analyst actually reaches for once an alert has fired and the host is a real
# suspect: USB device history, PowerShell command-line history, targeted
# high-value Security-log events, BitLocker recovery keys (in case the disk needs
# offline imaging later), and each user's "Recent Items" LNK shortcuts (far more
# targeted than a blind recursive C:\Users scan, and a canonical execution/
# file-access artifact -- Windows auto-generates one there every time a user opens
# a file). Every sub-collection is independently try/caught and bounded (Select
# -Object -First N / -MaxEvents), so one missing feature (e.g. BitLocker module
# absent on this SKU) degrades that one section to null/empty rather than failing
# the whole run -- same resilience discipline as collect_forensic_timestamps above.
#
# Deliberately NOT attempted here (would need real binary/journal parsing, not a
# safely-boundable one-shot PowerShell script -- same reasoning as
# collect_recent_file_changes' USN-journal note above): raw memory/disk imaging,
# Amcache/Shimcache *parsing* (their existence/metadata is already covered by
# collect_forensic_timestamps), and Sigma/IOC matching against any of this (that's
# what ioc_sweep/string_sweep and the server-side detection engine already do).
def collect_live_forensics():
    return r"""$result = @{}

$result.usb_history = @(try {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction Stop | ForEach-Object {
        $deviceKey = $_
        Get-ChildItem $deviceKey.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            [PSCustomObject]@{ device = $deviceKey.PSChildName; serial = $_.PSChildName; friendly_name = $props.FriendlyName; mfg = $props.Mfg }
        }
    } | Select-Object -First 50
} catch { @() })

$maxPsHistoryUsers = 8
$maxPsHistoryLines = 15
$psHistoryFiles = @(Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -ErrorAction SilentlyContinue)
$result.ps_console_history = @($psHistoryFiles | Select-Object -First $maxPsHistoryUsers | ForEach-Object {
    [PSCustomObject]@{
        user = $_.FullName.Split('\')[2]
        last_write = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        recent_lines = @(Get-Content $_.FullName -ErrorAction SilentlyContinue -Tail $maxPsHistoryLines)
    }
})
$result.ps_console_history_truncated = ($psHistoryFiles.Count -gt $maxPsHistoryUsers)

# Capped well below string_sweep's own hard-won 60-event/200-char limits (see that
# function's comment above on the server's 60000-char stdout storage cap silently
# truncating mid-string into invalid JSON) -- a busy Security log across 5 event IDs
# over 24h can otherwise produce a payload several times that cap on its own.
# security_events_truncated flags when the cap itself (not just the 24h window) is
# the reason some events are missing, the same explicit-rather-than-silent discipline
# string_sweep's hits_truncated/matches_truncated flags already established.
$maxSecurityEvents = 60
$result.security_events = @(try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4672,4688; StartTime=(Get-Date).AddHours(-24)} -MaxEvents $maxSecurityEvents -ErrorAction Stop |
        Select-Object TimeCreated,Id,@{N='Message';E={($_.Message -replace '\s+',' ').Substring(0, [Math]::Min(200, ($_.Message -replace '\s+',' ').Length))}}
} catch { @() })
$result.security_events_truncated = ($result.security_events.Count -ge $maxSecurityEvents)

$result.bitlocker = @(try {
    Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
        $vol = $_
        [PSCustomObject]@{
            mount_point = $vol.MountPoint
            protection_status = $vol.ProtectionStatus.ToString()
            volume_status = $vol.VolumeStatus.ToString()
            recovery_keys = @($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | ForEach-Object { [PSCustomObject]@{ id = $_.KeyProtectorId; recovery_password = $_.RecoveryPassword } })
        }
    }
} catch { @() })

$lnkHits = New-Object System.Collections.ArrayList
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $uname = $_.Name
    $recentDir = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
    if (Test-Path $recentDir) {
        Get-ChildItem $recentDir -Filter '*.lnk' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 15 | ForEach-Object {
            [void]$lnkHits.Add([PSCustomObject]@{ user = $uname; name = $_.Name; last_write = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') })
        }
    }
}
# Per-user cap above bounds one user's Recent folder from monopolizing the collection,
# but a box with several real profiles (confirmed in production -- a single active
# profile alone produced enough .lnk entries to matter) can still add up past the
# server's 60000-char stdout cap. Re-sort the combined set and take the 60 most
# recent overall, same explicit-flag discipline as security_events_truncated above.
$maxLnkFiles = 60
$lnkSorted = @($lnkHits | Sort-Object last_write -Descending)
$result.recent_lnk_files = @($lnkSorted | Select-Object -First $maxLnkFiles)
$result.recent_lnk_files_truncated = ($lnkSorted.Count -gt $maxLnkFiles)

$result.note = "BitLocker recovery keys and USB/PowerShell/LNK history are metadata/secrets, not raw disk or memory images -- collect a specific file via 'Collect File' for anything needing deeper offline analysis."
$result | ConvertTo-Json -Depth 5 -Compress
"""

# Registry Uninstall keys are the standard, side-effect-free way to enumerate installed
# software on Windows -- unlike Win32_Product (WMI), which silently triggers a repair
# reconfiguration of every MSI-installed app it enumerates and is notoriously slow.
# Covers native 64-bit apps (HKLM), 32-bit apps on 64-bit Windows (WOW6432Node), and
# per-user installs (HKCU) -- the three places a DisplayName/DisplayVersion pair
# realistically lives. Feeds server-side CVE correlation (see
# _correlate_software_vulnerabilities in app.py), not shown as an end in itself.
def collect_software_inventory():
    return r"""$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } |
    Select-Object @{N='name';E={$_.DisplayName}}, @{N='version';E={$_.DisplayVersion}}, @{N='publisher';E={$_.Publisher}}
$apps = @($apps | Sort-Object name, version -Unique)
[PSCustomObject]@{ count = $apps.Count; apps = $apps } | ConvertTo-Json -Compress -Depth 3
"""

# Windows-only -- Get-ItemProperty over the Uninstall keys above never lists installed
# KB hotfixes (they aren't registered as regular "programs" the way applications are),
# so nothing in collect_software_inventory() covers OS-level patch state at all today.
# Linux doesn't need an equivalent: collect_software_inventory_linux() already reads
# every dpkg/rpm package's exact version, and a distro security patch IS a package
# version bump -- that data already feeds the existing vuln-matching pipeline.
#
# Deliberately NOT claiming per-CVE-to-KB precision here (e.g. "CVE-2024-1234 is
# unpatched because KB5028166 is missing") -- that mapping isn't derivable from a
# general CVE/NVD feed at all; it lives only in Microsoft's own separate Security
# Update Guide (MSRC) data, which isn't ingested anywhere in this app. What IS honest
# and useful from this data alone: the full hotfix list, and how long it's been since
# the most recent one landed (a stale "last patched" date is a real, meaningful signal
# on its own, same "approximate, not the full licensed thing" posture sca_check()
# already takes).
def collect_installed_patches():
    return r"""$hotfixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
    Select-Object @{N='hotfix_id';E={$_.HotFixID}}, @{N='description';E={$_.Description}},
        @{N='installed_on';E={ if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' } }}
$hotfixes = @($hotfixes | Sort-Object installed_on -Descending)
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue |
    Select-Object Caption, Version, BuildNumber, OSArchitecture, @{N='LastBootUpTime';E={$_.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')}}
[PSCustomObject]@{ count = $hotfixes.Count; hotfixes = $hotfixes; os = $os } | ConvertTo-Json -Compress -Depth 3
"""

# A small, hand-authored set of CIS-Benchmark-flavored hardening checks, not the real
# CIS content itself (that's a licensed, hundreds-of-checks-per-OS policy library --
# see the comment on migrate_cve_affected_products for the same "approximate, not the
# real thing" posture applied elsewhere this pass). Each check is independently
# try/caught so one check that can't run on a given Windows edition/config (a cmdlet
# not present, a registry value simply never set) reports 'error' with a reason
# instead of aborting the whole sweep.
def sca_check():
    return r"""$results = @()
function AddCheck($id, $title, $status, $detail) {
    $script:results += [PSCustomObject]@{ id = $id; title = $title; status = $status; detail = $detail }
}

try {
    $fw = Get-NetFirewallProfile -ErrorAction Stop
    $allOn = @($fw | Where-Object { -not $_.Enabled }).Count -eq 0
    AddCheck 'firewall_enabled' 'Windows Firewall enabled (all profiles)' $(if ($allOn) { 'pass' } else { 'fail' }) (($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ')
} catch { AddCheck 'firewall_enabled' 'Windows Firewall enabled (all profiles)' 'error' "$_" }

try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    AddCheck 'smb1_disabled' 'SMBv1 protocol disabled' $(if ($smb1.State -eq 'Disabled') { 'pass' } else { 'fail' }) "State=$($smb1.State)"
} catch { AddCheck 'smb1_disabled' 'SMBv1 protocol disabled' 'error' "$_" }

try {
    $nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop
    AddCheck 'rdp_nla' 'RDP requires Network Level Authentication' $(if ($nla.UserAuthentication -eq 1) { 'pass' } else { 'fail' }) "UserAuthentication=$($nla.UserAuthentication)"
} catch { AddCheck 'rdp_nla' 'RDP requires Network Level Authentication' 'error' "$_" }

try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    AddCheck 'defender_realtime' 'Windows Defender real-time protection enabled' $(if ($defender.RealTimeProtectionEnabled) { 'pass' } else { 'fail' }) "RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled)"
} catch { AddCheck 'defender_realtime' 'Windows Defender real-time protection enabled' 'error' "$_" }

try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
    AddCheck 'guest_disabled' 'Guest account disabled' $(if (-not $guest.Enabled) { 'pass' } else { 'fail' }) "Enabled=$($guest.Enabled)"
} catch { AddCheck 'guest_disabled' 'Guest account disabled' 'error' "$_" }

try {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
    AddCheck 'uac_enabled' 'User Account Control (UAC) enabled' $(if ($uac.EnableLUA -eq 1) { 'pass' } else { 'fail' }) "EnableLUA=$($uac.EnableLUA)"
} catch { AddCheck 'uac_enabled' 'User Account Control (UAC) enabled' 'error' "$_" }

try {
    $lmhash = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -ErrorAction Stop
    AddCheck 'lm_hash_disabled' 'LM hash storage disabled' $(if ($lmhash.NoLMHash -eq 1) { 'pass' } else { 'fail' }) "NoLMHash=$($lmhash.NoLMHash)"
} catch { AddCheck 'lm_hash_disabled' 'LM hash storage disabled' 'error' 'Registry value not set (default varies by Windows version/edition)' }

try {
    $autorun = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction Stop
    AddCheck 'autorun_disabled' 'AutoRun disabled for all drive types' $(if ($autorun.NoDriveTypeAutoRun -ge 255) { 'pass' } else { 'fail' }) "NoDriveTypeAutoRun=$($autorun.NoDriveTypeAutoRun)"
} catch { AddCheck 'autorun_disabled' 'AutoRun disabled for all drive types' 'error' 'Registry value not set (AutoRun is enabled by default when unset)' }

try {
    $policy = Get-ExecutionPolicy -Scope LocalMachine
    AddCheck 'ps_execution_policy' 'PowerShell execution policy is not Unrestricted/Bypass' $(if ($policy -in @('Restricted', 'AllSigned', 'RemoteSigned')) { 'pass' } else { 'fail' }) "Policy=$policy"
} catch { AddCheck 'ps_execution_policy' 'PowerShell execution policy is not Unrestricted/Bypass' 'error' "$_" }

try {
    $bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    AddCheck 'bitlocker_enabled' 'BitLocker enabled on the system drive' $(if ($bitlocker.ProtectionStatus -eq 'On') { 'pass' } else { 'fail' }) "ProtectionStatus=$($bitlocker.ProtectionStatus)"
} catch { AddCheck 'bitlocker_enabled' 'BitLocker enabled on the system drive' 'error' "$_" }

try {
    $wu = Get-Service -Name wuauserv -ErrorAction Stop
    AddCheck 'windows_update_service' 'Windows Update service is not disabled' $(if ($wu.StartType -ne 'Disabled') { 'pass' } else { 'fail' }) "Status=$($wu.Status), StartType=$($wu.StartType)"
} catch { AddCheck 'windows_update_service' 'Windows Update service is not disabled' 'error' "$_" }

try {
    $lockoutLine = (net accounts) | Select-String 'Lockout threshold'
    $threshold = ($lockoutLine -split ':')[-1].Trim()
    $pass = ($threshold -ne 'Never') -and ([int]::TryParse($threshold, [ref]0)) -and ([int]$threshold -gt 0)
    AddCheck 'account_lockout' 'Account lockout policy configured (threshold > 0)' $(if ($pass) { 'pass' } else { 'fail' }) "Threshold=$threshold"
} catch { AddCheck 'account_lockout' 'Account lockout policy configured (threshold > 0)' 'error' "$_" }

try {
    # The same 12 subcategories reconcile_windows_audit_policy() (micro_agent_windows.py)
    # pushes via `auditpol /set` -- duplicated here rather than shared, matching this
    # repo's own "small catalogs are duplicated per file, not shared via import"
    # convention (this script's text is built server-side and shipped as a standalone
    # string, so it has no access to that file's Python list at all). auditpol has never
    # had a read-back path anywhere in this app until now -- only /set calls existed --
    # so this is the first time "what's actually in effect" gets compared against "what
    # this appliance expects", closing the drift-detection gap a GPO refresh (or manual
    # tampering) could otherwise silently reintroduce with no visibility.
    $auditSubcats = @('Logon','Logoff','Special Logon','Kerberos Authentication Service','Kerberos Service Ticket Operations','Credential Validation','User Account Management','Security Group Management','Process Creation','Audit Policy Change','Security State Change','Other Object Access Events')
    # auditpol is a native console exe, not a cmdlet -- it never throws a PowerShell
    # exception on failure (e.g. insufficient privilege), it just writes an error to its
    # own output and returns a non-zero exit code. Without this explicit check, a failed
    # call's empty/error output would silently parse as zero matching rows, which the
    # loop below would then misreport as "all 12 subcategories drifted" (status 'fail')
    # instead of "could not determine" (status 'error') -- confirmed live: running this
    # unelevated reproduced exactly that false-fail.
    $auditRaw = auditpol /get /category:* /r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /get failed (exit $LASTEXITCODE): $($auditRaw -join ' ')" }
    $auditCsv = $auditRaw | ConvertFrom-Csv
    if (-not $auditCsv -or @($auditCsv).Count -eq 0) { throw "auditpol /get returned no parseable rows" }
    # GPO-sourced Advanced Audit Policy only applies to domain-joined hosts -- included as
    # a diagnostic hint (not a gate on whether this check runs at all) since drift on a
    # non-domain host points at something else (manual tampering, a failed local push).
    $domainJoined = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
    $drifted = @()
    foreach ($subcat in $auditSubcats) {
        $row = $auditCsv | Where-Object { $_.Subcategory -eq $subcat } | Select-Object -First 1
        $setting = if ($row) { $row.'Inclusion Setting' } else { 'Not Found' }
        if ($setting -ne 'Success and Failure') { $drifted += "$subcat=$setting" }
    }
    $domainNote = if ($null -eq $domainJoined) { 'unknown' } elseif ($domainJoined) { 'yes -- a domain GPO refresh may be the cause' } else { 'no' }
    if ($drifted.Count -eq 0) {
        AddCheck 'audit_policy_compliance' "Advanced Audit Policy matches this appliance's expected baseline (Success and Failure, 12 subcategories)" 'pass' "All 12 subcategories enabled. Domain-joined: $domainNote."
    } else {
        AddCheck 'audit_policy_compliance' "Advanced Audit Policy matches this appliance's expected baseline (Success and Failure, 12 subcategories)" 'fail' "$($drifted.Count) subcategory(s) drifted from expected: $($drifted -join '; '). Domain-joined: $domainNote. Events this appliance depends on for detection may be silently missing."
    }
} catch { AddCheck 'audit_policy_compliance' "Advanced Audit Policy matches this appliance's expected baseline (Success and Failure, 12 subcategories)" 'error' "$_" }

$passed = @($results | Where-Object { $_.status -eq 'pass' }).Count
$failed = @($results | Where-Object { $_.status -eq 'fail' }).Count
$errored = @($results | Where-Object { $_.status -eq 'error' }).Count
[PSCustomObject]@{ checks = $results; passed = $passed; failed = $failed; errored = $errored; total = $results.Count } | ConvertTo-Json -Depth 4 -Compress
"""

def collect_network_connections():
    return r"""$result = @{}
$result.tcp = @(try {
    Get-NetTCPConnection -ErrorAction Stop |
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Select-Object -First 200
} catch { @() })
$result.udp = @(try {
    Get-NetUDPEndpoint -ErrorAction Stop |
        Select-Object LocalAddress,LocalPort,OwningProcess,@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Select-Object -First 200
} catch { @() })
$result.tcp_truncated = ($result.tcp.Count -ge 200)
$result.udp_truncated = ($result.udp.Count -ge 200)
$result | ConvertTo-Json -Depth 4 -Compress
"""

def collect_dns_arp():
    return r"""$result = @{}
$result.dns_cache = @(try {
    Get-DnsClientCache -ErrorAction Stop | Select-Object Entry,RecordType,Status,Data | Select-Object -First 200
} catch { @() })
$result.arp_table = @(try {
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.State -ne 'Unreachable' } |
        Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias |
        Select-Object -First 200
} catch { @() })
$result | ConvertTo-Json -Depth 4 -Compress
"""

# Deliberately informational, not a verdict -- a process with no on-disk backing path or
# an unsigned/invalid-signature binary is a real, well-known indicator technique
# (hollowing, reflective injection, a deleted-after-launch dropper), but is ALSO common
# for perfectly ordinary unsigned third-party software. Framed the same honest way
# sca_check's own results are: real machine-specific data for an analyst to triage, not
# an automated "this is malicious" claim -- matches this codebase's established
# never-guess-wrong-on-severity philosophy.
def check_process_injection_indicators():
    return r"""$result = @{}
$procs = Get-Process -ErrorAction SilentlyContinue

$result.no_backing_path = @($procs | Where-Object { -not $_.Path -and $_.Id -ne 0 } |
    Select-Object Id,ProcessName | Select-Object -First 100)

# Live-verified real bug: checking every running process serially with
# Get-AuthenticodeSignature timed out at 180s on real production data --
# catalog-signature verification (how nearly every Windows system binary is
# signed, rather than an embedded signature) is genuinely slow per file. Two
# fixes: (1) skip C:\Windows entirely for the signature check specifically
# -- system binaries are both the slowest case AND the lowest-value target
# (injected/malicious code realistically runs from Temp/AppData/Downloads,
# not a faked Windows system path), still fully covered by no_backing_path
# above, which is cheap; (2) dedupe by path first so N processes sharing one
# binary (svchost.exe et al) only pay the verification cost once, and cap
# the distinct-path count as a hard ceiling regardless of host process count.
$candidates = @($procs | Where-Object { $_.Path -and $_.Path -notlike 'C:\Windows\*' } |
    Group-Object Path | ForEach-Object { $_.Group | Select-Object -First 1 } | Select-Object -First 50)

$result.unsigned = @($candidates | ForEach-Object {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {
            [PSCustomObject]@{ id = $_.Id; name = $_.ProcessName; path = $_.Path; signature_status = $sig.Status.ToString() }
        }
    } catch {}
} | Select-Object -First 100)
$result.unsigned_scope = "Non-system paths only (excludes C:\Windows\*), deduplicated by binary, capped at 50 distinct executables checked -- catalog-signature verification is too slow to run against every running process."

$result.note = "Informational only -- a process with no backing file path or an unsigned/invalid-signature binary is common for both malicious injection AND ordinary unsigned third-party software. Not a verdict, a starting point for manual triage."
$result | ConvertTo-Json -Depth 3 -Compress
"""

_REGISTRY_HIVE_RE = re.compile(r'^(HKLM|HKCU|HKCR|HKU|HKCC):\\', re.IGNORECASE)

# The persistence sweep and SCA check only ever look at a handful of FIXED keys (Run/
# RunOnce, a few hardening settings) -- this is the general-purpose escape hatch for
# whatever specific key an analyst is actually investigating, not limited to those.
def collect_registry_key(key_path):
    if not _REGISTRY_HIVE_RE.match(key_path.strip()):
        raise ValueError(f"key_path must start with HKLM:\\, HKCU:\\, HKCR:\\, HKU:\\, or HKCC:\\ (got {key_path!r})")
    esc = key_path.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f"""$k = "{esc}"
if (-not (Test-Path $k)) {{ '{{"error":"registry key not found"}}'; exit }}
try {{
    $item = Get-Item -Path $k -ErrorAction Stop
    $values = @{{}}
    foreach ($name in $item.Property) {{
        $propName = if ($name -eq '') {{ '(Default)' }} else {{ $name }}
        $values[$propName] = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).$name
    }}
    $subkeys = @(Get-ChildItem -Path $k -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName | Select-Object -First 200)
    @{{ path = $k; values = $values; subkeys = $subkeys; subkeys_truncated = ($subkeys.Count -ge 200) }} | ConvertTo-Json -Depth 4 -Compress
}} catch {{
    $errMsg = $_.Exception.Message -replace '"', "'"
    "{{`"error`":`"failed to read registry key: $errMsg`"}}"
}}
"""

# Scoped to scheduled tasks specifically (the most common, most cleanly-identified
# autostart mechanism the persistence sweep surfaces) rather than a universal remover
# across every mechanism type (services, Run keys, startup folder, WMI subscriptions) --
# each of those has different enough removal semantics that folding them into one action
# would mean guessing which the analyst meant from the name alone.
def kill_scheduled_task(task_name):
    esc = task_name.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f"""$n = "{esc}"
$task = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
if (-not $task) {{ '{{"error":"scheduled task not found"}}'; exit }}
try {{
    Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction Stop
    "{{`"status`":`"removed`",`"task_name`":`"$n`"}}"
}} catch {{
    $errMsg = $_.Exception.Message -replace '"', "'"
    "{{`"error`":`"failed to remove scheduled task: $errMsg`"}}"
}}
"""

# label -> (builder, required param names)
WINDOWS_TEMPLATES = {
    'list_processes': (lambda params: _PROGRESS_SILENT + list_processes(), []),
    'kill_process': (lambda params: _PROGRESS_SILENT + kill_process(params['pid']), ['pid']),
    'kill_process_by_name': (lambda params: _PROGRESS_SILENT + kill_process_by_name(params['pattern']), ['pattern']),
    'isolate_host': (lambda params: _PROGRESS_SILENT + isolate_host(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: _PROGRESS_SILENT + restore_network(), []),
    'block_ip': (lambda params: _PROGRESS_SILENT + block_ip(params['target_ip']), ['target_ip']),
    'unblock_ip': (lambda params: _PROGRESS_SILENT + unblock_ip(params['target_ip']), ['target_ip']),
    'collect_triage': (lambda params: _PROGRESS_SILENT + collect_triage(), []),
    'persistence_sweep': (lambda params: _PROGRESS_SILENT + persistence_sweep(), []),
    'collect_file': (lambda params: _PROGRESS_SILENT + collect_file(params['path']), ['path']),
    'quarantine_file': (lambda params: _PROGRESS_SILENT + quarantine_file(params['path']), ['path']),
    'capture_process_memory': (lambda params: _PROGRESS_SILENT + capture_process_memory(params['pid']), ['pid']),
    'capture_top_suspicious_memory': (lambda params: _PROGRESS_SILENT + capture_top_suspicious_memory(), []),
    'defender_quick_scan': (lambda params: _PROGRESS_SILENT + defender_quick_scan(), []),
    'defender_full_scan': (lambda params: _PROGRESS_SILENT + defender_full_scan(), []),
    'beacon_simulator': (lambda params: _PROGRESS_SILENT + beacon_simulator(params['target_ip'], params['target_port'], params['interval_seconds'], params['jitter_seconds'], params['count']), ['target_ip', 'target_port', 'interval_seconds', 'jitter_seconds', 'count']),
    'collect_registry_key': (lambda params: _PROGRESS_SILENT + collect_registry_key(params['key_path']), ['key_path']),
    'kill_scheduled_task': (lambda params: _PROGRESS_SILENT + kill_scheduled_task(params['task_name']), ['task_name']),
    'collect_browser_artifacts': (lambda params: _PROGRESS_SILENT + collect_browser_artifacts(), []),
    'collect_forensic_timestamps': (lambda params: _PROGRESS_SILENT + collect_forensic_timestamps(), []),
    'collect_recent_file_changes': (lambda params: _PROGRESS_SILENT + collect_recent_file_changes(), []),
    'collect_live_forensics': (lambda params: _PROGRESS_SILENT + collect_live_forensics(), []),
    'collect_software_inventory': (lambda params: _PROGRESS_SILENT + collect_software_inventory(), []),
    'collect_installed_patches': (lambda params: _PROGRESS_SILENT + collect_installed_patches(), []),
    'sca_check': (lambda params: _PROGRESS_SILENT + sca_check(), []),
    'collect_network_connections': (lambda params: _PROGRESS_SILENT + collect_network_connections(), []),
    'collect_dns_arp': (lambda params: _PROGRESS_SILENT + collect_dns_arp(), []),
    'check_process_injection_indicators': (lambda params: _PROGRESS_SILENT + check_process_injection_indicators(), []),
    # 'hashes'/'md5_hashes'/'sha1_hashes' and 'patterns' are always server-populated
    # from the live IOC list / imported YARA rules right before dispatch (see app.py's
    # api_agent_commands()), never client-supplied — deliberately not in the required
    # list, since an empty live set is a real, valid state the builder already handles,
    # not a missing-parameter error.
    'ioc_sweep': (lambda params: _PROGRESS_SILENT + ioc_sweep(params.get('hashes', []), params.get('md5_hashes', []), params.get('sha1_hashes', [])), []),
    'string_sweep': (lambda params: _PROGRESS_SILENT + string_sweep(params.get('patterns', [])), []),
    'yara_condition_sweep': (lambda params: _PROGRESS_SILENT + yara_condition_sweep(params.get('rule_conditions', [])), []),
}

# ---- Linux (bash) ----
# Unlike PowerShell, plain shell command output is already human-readable text with no
# serialization step needed — these return native `ps`/`ss`/etc. output rather than
# forcing everything through a JSON encoder the way the Windows templates do.

def list_processes_linux():
    return "ps -eo pid,ppid,user,pcpu,pmem,etime,comm --sort=-pcpu --no-headers | head -100"

def kill_process_linux(pid):
    pid = int(pid)
    return (
        f'if kill -0 {pid} 2>/dev/null; then\n'
        f'    kill -9 {pid} && echo "Process {pid} terminated." || echo "Failed to terminate PID {pid}."\n'
        f'else\n'
        f'    echo "Failed to terminate PID {pid}: no such process."\n'
        f'fi'
    )

# Same "match by name/path substring, not a live PID" rationale as the Windows
# kill_process_by_name(). Uses `ps -Ao pid=,comm=,args=` (works identically on Linux and
# macOS -- no /proc dependency) rather than /proc/<pid>/exe, so this one function is
# shared verbatim by both POSIX agents instead of a Linux-only procfs version plus a
# separate macOS one.
def kill_process_by_name_linux(pattern):
    esc = pattern.replace('\\', '\\\\').replace("'", "\\'")
    return f"""python3 - <<'PYEOF'
import json, os, re, signal, subprocess

pattern = re.compile(re.escape('{esc}'), re.IGNORECASE)
out = subprocess.run(['ps', '-Ao', 'pid=,comm=,args='], capture_output=True, text=True, timeout=15).stdout
killed, failed = [], []
my_pid = os.getpid()
for line in out.splitlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split(None, 2)
    if len(parts) < 2:
        continue
    try:
        pid = int(parts[0])
    except ValueError:
        continue
    comm = parts[1]
    args = parts[2] if len(parts) > 2 else ''
    if pid <= 1 or pid == my_pid:
        continue
    if pattern.search(comm) or pattern.search(args):
        try:
            os.kill(pid, signal.SIGKILL)
            killed.append({{'pid': pid, 'name': comm}})
        except Exception as e:
            failed.append({{'pid': pid, 'name': comm, 'error': str(e)}})
print(json.dumps({{'killed': killed, 'failed': failed}}))
PYEOF
"""

# A dedicated chain (rather than editing INPUT/OUTPUT's default policy directly, as the
# Windows firewall-profile approach does) makes isolate/restore a clean flush-and-remove
# pair — restore_network_linux() can't accidentally leave stray rules behind or clobber
# other firewall rules that were already on the host before isolation.
_ISOLATION_CHAIN = "MICRODFIR_ISOLATION"

def isolate_host_linux(soc_ip):
    if not _IPV4_RE.match(soc_ip):
        raise ValueError(f"Invalid SOC IP address: {soc_ip!r}")
    return f"""iptables -D INPUT -j {_ISOLATION_CHAIN} 2>/dev/null
iptables -D OUTPUT -j {_ISOLATION_CHAIN} 2>/dev/null
iptables -F {_ISOLATION_CHAIN} 2>/dev/null
iptables -X {_ISOLATION_CHAIN} 2>/dev/null
iptables -N {_ISOLATION_CHAIN}
iptables -A {_ISOLATION_CHAIN} -d {soc_ip} -j ACCEPT
iptables -A {_ISOLATION_CHAIN} -s {soc_ip} -j ACCEPT
iptables -A {_ISOLATION_CHAIN} -j DROP
iptables -I INPUT 1 -j {_ISOLATION_CHAIN}
iptables -I OUTPUT 1 -j {_ISOLATION_CHAIN}
echo "Host isolated. Only traffic to/from {soc_ip} is permitted."
"""

def restore_network_linux():
    return f"""iptables -D INPUT -j {_ISOLATION_CHAIN} 2>/dev/null
iptables -D OUTPUT -j {_ISOLATION_CHAIN} 2>/dev/null
iptables -F {_ISOLATION_CHAIN} 2>/dev/null
iptables -X {_ISOLATION_CHAIN} 2>/dev/null
echo "Network isolation removed. Host restored to normal connectivity."
"""

def collect_triage_linux():
    return r"""echo "=== Processes ==="
ps -eo pid,ppid,user,comm,pcpu,pmem --sort=-pcpu --no-headers | head -60
echo
echo "=== Established Connections ==="
ss -tnp state established 2>/dev/null | head -60
echo
echo "=== Cron / Autostart ==="
for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] && echo "--$f--" && cat "$f"; done 2>/dev/null
systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | head -40
echo
echo "=== Users (uid 0 or >= 1000) ==="
getent passwd | awk -F: '$3>=1000 || $3==0 {print $1,$3,$6,$7}'
echo
echo "=== Autostart Files Modified in the Last 7 Days ==="
find /etc/cron.d /etc/systemd/system -type f -newermt "-7 days" 2>/dev/null
"""

def collect_file_linux(path):
    # A quoted heredoc delimiter ('PYEOF') disables all shell expansion inside the
    # block, so the path only needs escaping for its own Python string-literal context
    # below — not for bash at all, unlike the PowerShell version of this template.
    # 40KB raw, not 4MB -- see collect_file()'s comment: base64 inflation blows through
    # the server's 60,000-char stdout truncation (api_agent_result, app.py) well before
    # 4MB, corrupting the JSON mid-string. Same fix applied identically here.
    esc = path.replace('\\', '\\\\').replace("'", "\\'")
    return f"""python3 - <<'PYEOF'
import base64, hashlib, json, os
p = '{esc}'
if not os.path.isfile(p):
    print(json.dumps({{'error': 'file not found'}}))
else:
    size = os.path.getsize(p)
    if size > 40 * 1024:
        print(json.dumps({{'error': 'file too large (%d bytes, 40KB limit)' % size}}))
    else:
        with open(p, 'rb') as f:
            data = f.read()
        print(json.dumps({{'path': p, 'size': size, 'sha256': hashlib.sha256(data).hexdigest(), 'content_b64': base64.b64encode(data).decode()}}))
PYEOF
"""

# Same contain-not-just-collect rationale as the Windows quarantine_file(). chmod 000
# alone is a real baseline (the agent runs as root -- see install_agent() -- but chmod
# 000 still blocks every OTHER account, and blocks root's own accidental double-click/
# execution via a path lookup). chattr +i (immutable) is attempted best-effort on top --
# not all filesystems support it (tmpfs, some network mounts don't), so its real success
# is reported back rather than assumed.
def quarantine_file_linux(path):
    esc = path.replace('\\', '\\\\').replace("'", "\\'")
    return f"""python3 - <<'PYEOF'
import hashlib, json, os, shutil, subprocess, datetime

p = '{esc}'
if not os.path.isfile(p):
    print(json.dumps({{'error': 'file not found'}}))
else:
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    sha256 = h.hexdigest()

    qdir = '/opt/microdfir-agent/quarantine'
    os.makedirs(qdir, exist_ok=True)
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    dest_name = f'{{stamp}}_{{sha256[:16]}}_{{os.path.basename(p)}}.quarantined'
    dest = os.path.join(qdir, dest_name)
    try:
        shutil.move(p, dest)
        os.chmod(dest, 0o000)
        immutable = False
        try:
            r = subprocess.run(['chattr', '+i', dest], capture_output=True, timeout=5)
            immutable = (r.returncode == 0)
        except Exception:
            pass
        manifest = {{'original_path': p, 'quarantined_path': dest, 'sha256': sha256, 'quarantined_at': stamp, 'immutable': immutable}}
        with open(dest + '.manifest.json', 'w') as f:
            json.dump(manifest, f)
        print(json.dumps(manifest))
    except Exception as e:
        print(json.dumps({{'error': f'failed to quarantine: {{e}}'}}))
PYEOF
"""

def _py_set_literal(values):
    return ', '.join(repr(v) for v in values)

def ioc_sweep_linux(hashes, md5_hashes=None, sha1_hashes=None):
    valid_sha256 = sorted({(h or '').strip().lower() for h in hashes if _SHA256_RE.match((h or '').strip())})
    valid_md5 = sorted({(h or '').strip().lower() for h in (md5_hashes or []) if _MD5_RE.match((h or '').strip())})
    valid_sha1 = sorted({(h or '').strip().lower() for h in (sha1_hashes or []) if _SHA1_RE.match((h or '').strip())})
    if not valid_sha256 and not valid_md5 and not valid_sha1:
        return "echo '{\"error\": \"no IOC hashes are currently available to sweep for\"}'"
    # Same quoted-heredoc trick as collect_file_linux — no shell expansion happens
    # inside the block, so the hash lists only need to be valid Python (already
    # guaranteed: every entry matched its length-specific regex, so none can break out
    # of the set literal), not escaped for bash at all.
    script = """python3 - <<'PYEOF'
import hashlib, json, os, time

SHA256_HASHES = {__SHA256_HASHES__}
MD5_HASHES = {__MD5_HASHES__}
SHA1_HASHES = {__SHA1_HASHES__}
PATHS = ['/tmp', '/var/tmp', '/dev/shm', os.path.expanduser('~/Downloads')]
EXTS = {'', '.sh', '.bin', '.elf', '.py', '.php', '.pl', '.out'}
CUTOFF = time.time() - 14 * 86400
MAX_SIZE = 50 * 1024 * 1024

scanned = 0
hits = []
for base in PATHS:
    if not os.path.isdir(base):
        continue
    for root, dirs, files in os.walk(base):
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_mtime < CUTOFF or st.st_size > MAX_SIZE:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext not in EXTS:
                continue
            scanned += 1
            try:
                # Hashed once from a single chunked read, not three separate file
                # reads, so adding MD5/SHA1 costs no extra I/O.
                h256, hmd5, h1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        h256.update(chunk); hmd5.update(chunk); h1.update(chunk)
                d256, dmd5, d1 = h256.hexdigest(), hmd5.hexdigest(), h1.hexdigest()
            except OSError:
                continue
            matched = []
            if d256 in SHA256_HASHES: matched.append('sha256')
            if dmd5 in MD5_HASHES: matched.append('md5')
            if d1 in SHA1_HASHES: matched.append('sha1')
            if matched:
                hits.append({
                    'path': path, 'sha256': d256, 'md5': dmd5, 'sha1': d1, 'matched': matched,
                    'size': st.st_size, 'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)),
                })

print(json.dumps({'scanned': scanned, 'hits': hits}))
PYEOF
"""
    return (script.replace('__SHA256_HASHES__', _py_set_literal(valid_sha256))
                  .replace('__MD5_HASHES__', _py_set_literal(valid_md5))
                  .replace('__SHA1_HASHES__', _py_set_literal(valid_sha1)))

def string_sweep_linux(patterns):
    seen = {}
    for p in (patterns or []):
        val = (p.get('string') or '').strip()
        if not val or val in seen:
            continue
        seen[val] = p.get('rule') or 'unknown'
    if not seen:
        return "echo '{\"error\": \"no YARA string patterns are currently available to sweep for\"}'"
    # repr() is valid-Python-literal escaping (quotes, backslashes, control chars) --
    # patterns are free-form text pulled from rule files, unlike the regex-validated
    # hash values above, so this needs real escaping rather than trusted-shape values.
    pattern_map_src = ', '.join(f"{repr(v)}: {repr(r)}" for v, r in seen.items())
    script = """python3 - <<'PYEOF'
import json, os, time

PATTERN_RULES = {__PATTERN_MAP__}
PATTERNS = [(p, p.encode('utf-8', 'ignore')) for p in PATTERN_RULES]
PATHS = ['/tmp', '/var/tmp', '/dev/shm', os.path.expanduser('~/Downloads')]
EXTS = {'', '.sh', '.bin', '.elf', '.py', '.php', '.pl', '.out'}
CUTOFF = time.time() - 14 * 86400
MAX_SIZE = 10 * 1024 * 1024

scanned = 0
hits = []
for base in PATHS:
    if not os.path.isdir(base):
        continue
    for root, dirs, files in os.walk(base):
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_mtime < CUTOFF or st.st_size > MAX_SIZE:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext not in EXTS:
                continue
            scanned += 1
            try:
                with open(path, 'rb') as f:
                    data = f.read()
            except OSError:
                continue
            found = [p for p, b in PATTERNS if b in data]
            if found:
                hits.append({
                    'path': path, 'size': st.st_size,
                    'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)),
                    'matches': [{'rule': PATTERN_RULES[p], 'string': p} for p in found],
                })

print(json.dumps({'scanned': scanned, 'hits': hits}))
PYEOF
"""
    return script.replace('__PATTERN_MAP__', pattern_map_src)

def yara_condition_sweep_linux(rule_conditions):
    # rule_conditions: [{rule, strings, required_n, condition_label}, ...] from
    # app.py's _get_live_yara_rule_conditions() -- a real condition check ("at least
    # required_n of these strings must be present"), not string_sweep's independent
    # any-string-hit reporting. required_n already folds any/all/N-of-them into one
    # plain integer threshold, so the only comparison needed here is count >= required_n.
    rules = [r for r in (rule_conditions or []) if r.get('strings') and r.get('required_n')]
    if not rules:
        return "echo '{\"error\": \"no condition-evaluable YARA rules are currently available to sweep for\"}'"
    # repr() is valid-Python-literal escaping, same as string_sweep_linux() above --
    # rule/string text is free-form content pulled from rule files, not a trusted shape.
    rules_src = repr([
        {'rule': r['rule'], 'strings': list(r['strings']), 'required_n': int(r['required_n']), 'condition_label': r.get('condition_label', '')}
        for r in rules
    ])
    script = """python3 - <<'PYEOF'
import json, os, time

RULES = __RULES__
for r in RULES:
    r['string_bytes'] = [s.encode('utf-8', 'ignore') for s in r['strings']]
PATHS = ['/tmp', '/var/tmp', '/dev/shm', os.path.expanduser('~/Downloads')]
EXTS = {'', '.sh', '.bin', '.elf', '.py', '.php', '.pl', '.out'}
CUTOFF = time.time() - 14 * 86400
MAX_SIZE = 10 * 1024 * 1024
MAX_HITS = 50

scanned = 0
hits = []
total_matching_files = 0
for base in PATHS:
    if not os.path.isdir(base):
        continue
    for root, dirs, files in os.walk(base):
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_mtime < CUTOFF or st.st_size > MAX_SIZE:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext not in EXTS:
                continue
            scanned += 1
            try:
                with open(path, 'rb') as f:
                    data = f.read()
            except OSError:
                continue
            matched_rules = []
            for r in RULES:
                count = sum(1 for b in r['string_bytes'] if b in data)
                if count >= r['required_n']:
                    matched_rules.append({'rule': r['rule'], 'condition': r['condition_label'], 'matched_strings': count, 'total_strings': len(r['strings'])})
            if matched_rules:
                total_matching_files += 1
                if len(hits) < MAX_HITS:
                    hits.append({
                        'path': path, 'size': st.st_size,
                        'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)),
                        'matched_rules': matched_rules,
                    })

print(json.dumps({'scanned': scanned, 'hits': hits, 'rules_evaluated': len(RULES), 'total_matching_files': total_matching_files, 'hits_truncated': total_matching_files > MAX_HITS}))
PYEOF
"""
    return script.replace('__RULES__', rules_src)

# Deeper than collect_triage_linux()'s lighter cron/systemd touch above -- every user's
# own crontab individually (not just the system-wide files), the FULL enabled-unit list
# (no head cap), /etc/init.d SysV scripts, shell profile files (a classic persistence
# spot -- .bashrc/.profile run on every login), and any LD_PRELOAD reference (a
# well-known library-injection persistence technique). Inspired by the same
# Autoruns/Velociraptor philosophy as persistence_sweep() above, just for Linux's own
# autostart mechanisms.
#
# Diffs against a baseline persisted to persistence_baseline.json in the agent's own
# INSTALL_DIR -- same python3-heredoc pattern already used elsewhere in this file
# (collect_file_linux, ioc_sweep_linux) for real JSON/dict logic bash can't do cleanly.
# An analyst re-running this repeatedly during an investigation sees only what's
# new/changed/gone since the last run, not a full re-dump every time. The very first
# run against a host with no baseline yet reports everything as "new" (first_run=true)
# -- expected, not a bug, same as the FIM feature's own first-check behavior.
def persistence_sweep_linux():
    return r"""python3 - <<'PYEOF'
import glob, json, os, subprocess

STATE_PATH = '/opt/microdfir-agent/persistence_baseline.json'

def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, 'w') as f:
            json.dump(state, f)
    except Exception:
        pass

def run(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ''

current = {}

for u in run("cut -f1 -d: /etc/passwd").split():
    out = run("crontab -l -u %s 2>/dev/null" % u).strip()
    if out:
        current['crontab:%s' % u] = out

for path in ['/etc/crontab'] + glob.glob('/etc/cron.d/*'):
    if os.path.isfile(path):
        try:
            with open(path) as f:
                current['file:%s' % path] = f.read()
        except Exception:
            pass

for line in run("systemctl list-unit-files --state=enabled --no-legend 2>/dev/null").splitlines():
    parts = line.split()
    if parts:
        current['unit:%s' % parts[0]] = line.strip()

if os.path.isdir('/etc/init.d'):
    for name in os.listdir('/etc/init.d'):
        path = os.path.join('/etc/init.d', name)
        if os.path.isfile(path):
            try:
                st = os.stat(path)
                current['initd:%s' % path] = '%d:%d' % (st.st_size, int(st.st_mtime))
            except Exception:
                pass

for path in ['/etc/profile', '/root/.bashrc', '/root/.profile'] + glob.glob('/etc/profile.d/*.sh'):
    if os.path.isfile(path):
        try:
            with open(path) as f:
                current['file:%s' % path] = f.read()
        except Exception:
            pass

ld_out = run("grep -H LD_PRELOAD /etc/environment /etc/ld.so.preload 2>/dev/null").strip()
if ld_out:
    current['ld_preload'] = ld_out

# ---- Lightweight rootcheck-equivalent additions ----
# A newly-loaded kernel module is worth a second look -- LKM-based rootkits typically
# load as a module (even ones that later unlink themselves from /proc/modules to hide
# still show up here on the sweep that catches them mid-load).
for line in run("lsmod 2>/dev/null").splitlines()[1:]:
    parts = line.split()
    if parts:
        current['kmod:%s' % parts[0]] = line.strip()

# A NEW root-owned SUID/SGID binary appearing is a classic persistence/privesc trick --
# bounded to common binary paths plus world-writable tmp dirs, not a full disk walk.
for base in ('/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin', '/usr/local/sbin', '/tmp', '/var/tmp'):
    if os.path.isdir(base):
        try:
            names = os.listdir(base)
        except Exception:
            names = []
        for name in names:
            path = os.path.join(base, name)
            try:
                st = os.stat(path)
                if (st.st_mode & 0o6000) and st.st_uid == 0:  # SUID or SGID, owned by root
                    current['suid:%s' % path] = '%d:%d:%o' % (st.st_size, int(st.st_mtime), st.st_mode & 0o7777)
            except Exception:
                pass

baseline = load_state()
new_entries = {}
changed_entries = {}
for k, v in current.items():
    if k not in baseline:
        new_entries[k] = v
    elif baseline[k] != v:
        changed_entries[k] = {'old': baseline[k], 'new': v}
removed_keys = [k for k in baseline if k not in current]

# Current-state checks, NOT run through the baseline diff above -- these must
# re-report on every sweep while the condition holds (an interface left promiscuous
# stays worth flagging every time, not just the first sweep that noticed it), unlike
# the "new since last time" entries above.
#
# Hidden processes: a PID directory exists under /proc but never appears in `ps`
# output -- many LKM rootkits hook the syscalls `ps` reads through to hide their own
# process, but can't hide the /proc entry itself without much deeper (rarer) hooking.
# Best-effort: a process that exits in the brief window between the two commands can
# cause a false positive, so this is a lead to investigate, not a guaranteed finding.
proc_pids = {p for p in os.listdir('/proc') if p.isdigit()}
ps_pids = set(run("ps -eo pid --no-headers").split())
hidden_processes = sorted(proc_pids - ps_pids, key=int)

# Promiscuous interfaces: Linux sets the IFF_PROMISC flag (bit 0x100) in
# /sys/class/net/<iface>/flags -- a classic packet-sniffer/MITM indicator.
promiscuous_interfaces = []
for iface_flags in glob.glob('/sys/class/net/*/flags'):
    try:
        with open(iface_flags) as f:
            flags = int(f.read().strip(), 16)
        if flags & 0x100:
            promiscuous_interfaces.append(iface_flags.split('/')[-2])
    except Exception:
        pass

print(json.dumps({
    'total_entries': len(current), 'new': new_entries, 'changed': changed_entries,
    'removed': removed_keys, 'first_run': (not baseline),
    'hidden_processes': hidden_processes, 'promiscuous_interfaces': sorted(promiscuous_interfaces),
}))

save_state(current)
PYEOF
"""

# Same uid>=1000-or-root user enumeration idiom as collect_triage_linux()'s
# getent/awk line -- shell history (last 100 lines per shell, not the whole file, since
# a long-lived interactive session's history can run to many thousands of lines) plus
# every real user's authorized_keys and known_hosts, both classic SSH-based persistence
# and lateral-movement artifacts.
def collect_ssh_artifacts_linux():
    return r"""echo "=== Shell History (last 100 lines, uid 0 or >= 1000) ==="
getent passwd | awk -F: '$3>=1000 || $3==0 {print $1":"$6}' | while IFS=: read -r user home; do
    for hf in .bash_history .zsh_history; do
        f="$home/$hf"
        [ -f "$f" ] && echo "--$user:$f--" && tail -n 100 "$f"
    done
done
echo
echo "=== authorized_keys (uid 0 or >= 1000) ==="
getent passwd | awk -F: '$3>=1000 || $3==0 {print $1":"$6}' | while IFS=: read -r user home; do
    f="$home/.ssh/authorized_keys"
    [ -f "$f" ] && echo "--$user:$f--" && cat "$f"
done
echo
echo "=== known_hosts (uid 0 or >= 1000) ==="
getent passwd | awk -F: '$3>=1000 || $3==0 {print $1":"$6}' | while IFS=: read -r user home; do
    f="$home/.ssh/known_hosts"
    [ -f "$f" ] && echo "--$user:$f--" && cat "$f"
done
"""

# Linux counterpart to collect_live_forensics() (Windows) -- same JSON shape/field-
# naming convention (arrays capped with an explicit *_truncated flag, a closing 'note'
# disclaimer) so agents.html's generic collect_*/persistence_sweep renderer displays it
# identically with zero JS changes. Windows' own fields don't all have a clean Linux
# equivalent (no registry, no BitLocker, no .lnk shortcuts; shell history/authorized_keys/
# known_hosts are already covered by collect_ssh_artifacts_linux, not duplicated here) --
# this covers the two gaps that ARE real and missing: recent USB/removable-media activity
# and a general recent-file-changes scan, plus a short recent-auth-events pull as the
# closest Linux analog to Windows' targeted Security-log events.
def collect_live_forensics_linux():
    return r"""python3 - <<'PYEOF'
import json, shutil, subprocess

def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ''

result = {}

# Best-effort, not a real audit trail -- there's no persistent USB-history equivalent to
# Windows' USBSTOR registry key without auditd rules already watching for it. journalctl
# (present on any systemd host) is tried first since it survives a reboot via the
# persistent journal; dmesg (ring-buffer only, lost on reboot) is the fallback for
# non-systemd or non-persistent-journal hosts.
max_usb_lines = 50
usb_lines = []
if shutil.which('journalctl'):
    out = run(['journalctl', '-k', '--no-pager', '-g', 'usb|mmc', '-i', '--since', '-7 days'], timeout=20)
    usb_lines = [l for l in out.splitlines() if l.strip()]
elif shutil.which('dmesg'):
    out = run(['dmesg'], timeout=10)
    usb_lines = [l for l in out.splitlines() if 'usb' in l.lower() or 'mmc' in l.lower()]
result['usb_removable_media_events'] = usb_lines[-max_usb_lines:]
result['usb_removable_media_events_truncated'] = len(usb_lines) > max_usb_lines

# Recent auth activity -- the closest Linux analog to Windows' targeted 4624/4625/4648/
# 4672/4688 Security-log pull. journalctl again preferred over grepping /var/log/auth.log
# or /var/log/secure directly since which file exists (and whether it's even text, vs.
# binary wtmp/btmp) varies by distro; journalctl abstracts that away.
max_auth_lines = 60
auth_lines = []
if shutil.which('journalctl'):
    out = run(['journalctl', '--no-pager', '-g', 'sshd|sudo|su:|useradd|passwd', '-i', '--since', '-24 hours'], timeout=20)
    auth_lines = [l for l in out.splitlines() if l.strip()]
result['auth_events'] = auth_lines[-max_auth_lines:]
result['auth_events_truncated'] = len(auth_lines) > max_auth_lines

# General recent-file-changes scan -- the gap persistence_sweep_linux's own "Autostart
# Files Modified in the Last 7 Days" section doesn't cover (that's scoped to
# /etc/cron.d and /etc/systemd/system only). -xdev on each starting path keeps this
# from wandering into a separately-mounted network share or removable volume.
max_file_changes = 100
out = run(['find', '/tmp', '/var/tmp', '/root', '/home', '/etc', '-xdev', '-type', 'f',
           '-newermt', '-24 hours'], timeout=30)
file_lines = [l for l in out.splitlines() if l.strip()]
result['recent_file_changes'] = file_lines[:max_file_changes]
result['recent_file_changes_truncated'] = len(file_lines) > max_file_changes

# Current mount snapshot for context -- deliberately labeled as a snapshot, not
# "history" (no persistent mount-history mechanism exists here without auditd).
mounts = []
try:
    with open('/proc/mounts') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and not parts[0].startswith(('proc', 'sysfs', 'cgroup', 'devpts', 'tmpfs', 'devtmpfs')):
                mounts.append({'device': parts[0], 'mount_point': parts[1], 'fstype': parts[2]})
except Exception:
    pass
result['current_mounts'] = mounts

result['note'] = ("USB/removable-media and recent-file-change data here is a best-effort snapshot from "
                   "kernel/journal logs and a timestamp scan, not a full audit trail -- shell history, "
                   "authorized_keys, and known_hosts are covered separately by Collect-SSH-Artifacts. "
                   "Use 'Collect File' for anything needing deeper offline analysis.")
print(json.dumps(result))
PYEOF
"""

def enable_exec_auditing():
    return r"""RULES_FILE=/etc/audit/rules.d/microdfir.rules
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditd is not installed on this host -- install the 'audit' (or 'auditd') package first."
    exit 1
fi
mkdir -p /etc/audit/rules.d
cat > "$RULES_FILE" <<'EOF'
-a exec,always -F arch=b64 -S execve -k microdfir_exec
-a exec,always -F arch=b32 -S execve -k microdfir_exec
EOF
auditctl -a exec,always -F arch=b64 -S execve -k microdfir_exec 2>/dev/null
auditctl -a exec,always -F arch=b32 -S execve -k microdfir_exec 2>/dev/null
# augenrules persists the rule file across a reboot/auditd restart; auditctl above loads
# it into the running kernel rule set immediately, without waiting for that reload.
augenrules --load 2>/dev/null
echo "Exec auditing enabled (key=microdfir_exec). Rule persisted to $RULES_FILE."
"""

def disable_exec_auditing():
    return r"""RULES_FILE=/etc/audit/rules.d/microdfir.rules
rm -f "$RULES_FILE"
auditctl -d exec,always -F arch=b64 -S execve -k microdfir_exec 2>/dev/null
auditctl -d exec,always -F arch=b32 -S execve -k microdfir_exec 2>/dev/null
augenrules --load 2>/dev/null
echo "Exec auditing disabled and rule file removed."
"""

# dpkg (Debian/Ubuntu) or rpm (RHEL/CentOS/Fedora/Amazon Linux) -- whichever package
# manager is actually present, tried in that order. Feeds server-side CVE correlation
# (see _correlate_software_vulnerabilities in app.py), same purpose as
# collect_software_inventory() does for Windows.
def collect_software_inventory_linux():
    return r"""python3 - <<'PYEOF'
import json, shutil, subprocess

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return ''

apps = []
if shutil.which('dpkg-query'):
    for line in run(['dpkg-query', '-W', '-f=${Package}\t${Version}\n']).splitlines():
        parts = line.split('\t')
        if len(parts) == 2 and parts[0]:
            apps.append({'name': parts[0], 'version': parts[1], 'publisher': ''})
elif shutil.which('rpm'):
    for line in run(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n']).splitlines():
        parts = line.split('\t')
        if len(parts) == 2 and parts[0]:
            apps.append({'name': parts[0], 'version': parts[1], 'publisher': ''})

print(json.dumps({'count': len(apps), 'apps': apps}))
PYEOF
"""

# Same "hand-authored, CIS-flavored, not the real licensed benchmark content" posture
# as sca_check() (Windows) above -- each check is independently try/excepted so one
# check that can't run (a config file that doesn't exist, a sysctl not present on this
# kernel) reports 'error' with a reason instead of aborting the whole sweep.
def sca_check_linux():
    return r"""python3 - <<'PYEOF'
import json, os, re, subprocess

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return ''

def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return None

checks = []
def add(id_, title, status, detail):
    checks.append({'id': id_, 'title': title, 'status': status, 'detail': detail})

def sshd_config_value(key):
    text = read_file('/etc/ssh/sshd_config')
    if text is None:
        return None
    m = re.search(rf'^\s*{key}\s+(\S+)', text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).lower() if m else None

val = sshd_config_value('PermitRootLogin')
if val is None:
    add('ssh_root_login', 'SSH root login disabled', 'error', '/etc/ssh/sshd_config not found or PermitRootLogin not set (default varies by distro/version)')
else:
    add('ssh_root_login', 'SSH root login disabled', 'pass' if val in ('no', 'prohibit-password') else 'fail', f'PermitRootLogin={val}')

val = sshd_config_value('PasswordAuthentication')
if val is None:
    add('ssh_password_auth', 'SSH password authentication disabled', 'error', '/etc/ssh/sshd_config not found or PasswordAuthentication not set')
else:
    add('ssh_password_auth', 'SSH password authentication disabled', 'pass' if val == 'no' else 'fail', f'PasswordAuthentication={val}')

if run(['which', 'ufw']).strip():
    out = run(['ufw', 'status'])
    add('firewall_active', 'A host firewall is active', 'pass' if 'active' in out.lower() else 'fail', out.strip().splitlines()[0] if out.strip() else 'no output')
elif run(['which', 'firewall-cmd']).strip():
    out = run(['firewall-cmd', '--state'])
    add('firewall_active', 'A host firewall is active', 'pass' if 'running' in out.lower() else 'fail', out.strip())
else:
    rules = run(['iptables', '-L', '-n'])
    has_rules = len([l for l in rules.splitlines() if l and not l.startswith('Chain') and not l.startswith('target')]) > 0
    add('firewall_active', 'A host firewall is active', 'pass' if has_rules else 'error', 'ufw/firewalld not found; checked iptables directly' if rules else 'Unable to determine firewall state')

try:
    st = os.stat('/etc/passwd')
    ok = oct(st.st_mode & 0o777) in ('0o644', '0o640', '0o444') and st.st_uid == 0
    add('passwd_perms', '/etc/passwd has safe permissions, owned by root', 'pass' if ok else 'fail', f'mode={oct(st.st_mode & 0o777)}, uid={st.st_uid}')
except Exception as e:
    add('passwd_perms', '/etc/passwd has safe permissions, owned by root', 'error', str(e))

try:
    st = os.stat('/etc/shadow')
    ok = (st.st_mode & 0o777) <= 0o640 and st.st_uid == 0
    add('shadow_perms', '/etc/shadow is not world/group readable, owned by root', 'pass' if ok else 'fail', f'mode={oct(st.st_mode & 0o777)}, uid={st.st_uid}')
except Exception as e:
    add('shadow_perms', '/etc/shadow is not world/group readable, owned by root', 'error', str(e))

shadow = read_file('/etc/shadow')
if shadow is None:
    add('no_empty_passwords', 'No accounts with an empty password hash', 'error', 'Cannot read /etc/shadow (needs root)')
else:
    empty = [line.split(':')[0] for line in shadow.splitlines() if len(line.split(':')) > 1 and line.split(':')[1] == '']
    add('no_empty_passwords', 'No accounts with an empty password hash', 'pass' if not empty else 'fail', f'{len(empty)} account(s): {", ".join(empty[:10])}' if empty else 'none found')

login_defs = read_file('/etc/login.defs')
if login_defs is None:
    add('password_min_len', 'Minimum password length policy set (>= 8)', 'error', '/etc/login.defs not found')
else:
    m = re.search(r'^\s*PASS_MIN_LEN\s+(\d+)', login_defs, re.MULTILINE)
    n = int(m.group(1)) if m else 0
    add('password_min_len', 'Minimum password length policy set (>= 8)', 'pass' if n >= 8 else 'fail', f'PASS_MIN_LEN={n if m else "not set"}')

if login_defs is None:
    # Every other check here reports 'error' (a real, counted entry) rather than
    # silently vanishing when its underlying file is missing -- omitting this one
    # entirely would make the total check count vary by host state, which breaks any
    # attempt to compare coverage/scores across hosts or over time.
    add('password_max_days', 'Password expiration policy set (not effectively disabled)', 'error', '/etc/login.defs not found')
else:
    m = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    n = int(m.group(1)) if m else 99999
    add('password_max_days', 'Password expiration policy set (not effectively disabled)', 'pass' if 0 < n < 99999 else 'fail', f'PASS_MAX_DAYS={n}')

def sysctl(name):
    out = run(['sysctl', '-n', name]).strip()
    return out if out else None

v = sysctl('fs.suid_dumpable')
add('core_dumps_restricted', 'SUID core dumps restricted (fs.suid_dumpable=0)', 'error' if v is None else ('pass' if v == '0' else 'fail'), f'fs.suid_dumpable={v}')

v = sysctl('kernel.randomize_va_space')
add('aslr_enabled', 'ASLR fully enabled (kernel.randomize_va_space=2)', 'error' if v is None else ('pass' if v == '2' else 'fail'), f'kernel.randomize_va_space={v}')

active_services = []
for svc in ('systemd-timesyncd', 'chronyd', 'ntpd'):
    if run(['systemctl', 'is-active', svc]).strip() == 'active':
        active_services.append(svc)
add('time_sync_active', 'A time synchronization service is active', 'pass' if active_services else 'fail', ', '.join(active_services) if active_services else 'none of systemd-timesyncd/chronyd/ntpd are active')

passed = sum(1 for c in checks if c['status'] == 'pass')
failed = sum(1 for c in checks if c['status'] == 'fail')
errored = sum(1 for c in checks if c['status'] == 'error')
print(json.dumps({'checks': checks, 'passed': passed, 'failed': failed, 'errored': errored, 'total': len(checks)}))
PYEOF
"""

def collect_network_connections_linux():
    return "ss -tunapl 2>/dev/null | head -300 || netstat -tunapl 2>/dev/null | head -300"

def collect_dns_arp_linux():
    return r"""echo "=== ARP / Neighbor Table ==="
ip neigh show 2>/dev/null || arp -an 2>/dev/null || echo "(no ARP tooling available)"
echo
echo "=== DNS Resolver Cache (systemd-resolved, if active) ==="
if command -v resolvectl >/dev/null 2>&1; then
    resolvectl statistics 2>/dev/null || echo "(resolvectl present but the query failed)"
else
    echo "(systemd-resolved not in use on this host -- no system-wide DNS cache to query)"
fi
"""

# Same informational-not-a-verdict framing as the Windows counterpart. A deleted-but-
# running executable (/proc/*/exe resolving to a "(deleted)" target -- the binary on
# disk was removed or replaced after the process started) and an executable memory
# mapping with no backing file at all are both well-known reflective-injection/packing
# indicators, but can also occur legitimately (a self-updating binary, a JIT compiler,
# a package upgrade replacing a still-running binary).
def check_process_injection_indicators_linux():
    return r"""python3 - <<'PYEOF'
import json, os

result = {'deleted_but_running': [], 'anon_exec_mappings': []}

for pid_dir in os.listdir('/proc'):
    if not pid_dir.isdigit():
        continue
    try:
        target = os.readlink(f'/proc/{pid_dir}/exe')
    except (OSError, PermissionError):
        continue
    try:
        with open(f'/proc/{pid_dir}/comm') as f:
            comm = f.read().strip()
    except Exception:
        comm = ''

    if '(deleted)' in target:
        result['deleted_but_running'].append({'pid': int(pid_dir), 'comm': comm, 'exe': target})

    try:
        with open(f'/proc/{pid_dir}/maps') as f:
            maps = f.read()
    except (OSError, PermissionError):
        continue
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        addr, perms = parts[0], parts[1]
        path = parts[5].strip() if len(parts) > 5 else ''
        # Executable with no backing file (or a backing file that's been deleted) --
        # every legitimately mapped shared library always has a real path here.
        if 'x' in perms and (not path or '(deleted)' in path):
            result['anon_exec_mappings'].append({'pid': int(pid_dir), 'comm': comm, 'region': addr, 'perms': perms})
            break  # one hit per process is enough signal, avoid flooding on a chatty process

result['deleted_but_running'] = result['deleted_but_running'][:100]
result['anon_exec_mappings'] = result['anon_exec_mappings'][:100]
result['note'] = "Informational only. A deleted-but-running executable or an executable memory region with no backing file is a strong reflective-injection/packing indicator, but can also occur legitimately (e.g. a self-updating binary, a JIT compiler). Not a verdict, a starting point for manual triage."
print(json.dumps(result))
PYEOF
"""

LINUX_TEMPLATES = {
    'list_processes': (lambda params: list_processes_linux(), []),
    'kill_process': (lambda params: kill_process_linux(params['pid']), ['pid']),
    'kill_process_by_name': (lambda params: kill_process_by_name_linux(params['pattern']), ['pattern']),
    'isolate_host': (lambda params: isolate_host_linux(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: restore_network_linux(), []),
    'collect_triage': (lambda params: collect_triage_linux(), []),
    'persistence_sweep': (lambda params: persistence_sweep_linux(), []),
    'collect_file': (lambda params: collect_file_linux(params['path']), ['path']),
    'quarantine_file': (lambda params: quarantine_file_linux(params['path']), ['path']),
    'collect_ssh_artifacts': (lambda params: collect_ssh_artifacts_linux(), []),
    'collect_live_forensics': (lambda params: collect_live_forensics_linux(), []),
    'collect_software_inventory': (lambda params: collect_software_inventory_linux(), []),
    'sca_check': (lambda params: sca_check_linux(), []),
    'collect_network_connections': (lambda params: collect_network_connections_linux(), []),
    'collect_dns_arp': (lambda params: collect_dns_arp_linux(), []),
    'check_process_injection_indicators': (lambda params: check_process_injection_indicators_linux(), []),
    'ioc_sweep': (lambda params: ioc_sweep_linux(params.get('hashes', []), params.get('md5_hashes', []), params.get('sha1_hashes', [])), []),
    'string_sweep': (lambda params: string_sweep_linux(params.get('patterns', [])), []),
    'yara_condition_sweep': (lambda params: yara_condition_sweep_linux(params.get('rule_conditions', [])), []),
    'enable_exec_auditing': (lambda params: enable_exec_auditing(), []),
    'disable_exec_auditing': (lambda params: disable_exec_auditing(), []),
}

# ---- macOS (bash) ----
# Same shell-argument-passing shape as the Linux templates (no shell-quoting step
# needed -- the whole script travels as one subprocess argument). Deliberately a
# smaller core set than Windows/Linux for this first pass -- persistence sweep
# (LaunchAgents/LaunchDaemons/cron differ enough from systemd/cron to deserve their own
# careful design, not a rushed adaptation), software inventory, SCA hardening checks,
# and the sweep/injection-indicator actions are real gaps left for a follow-up, not
# silently dropped. NONE of this has been live-verified against a real Mac (no macOS
# hardware available) -- verified only by real-execution unit tests on the pure-Python
# pieces and structural/shellcheck-style validation on the bash. isolate_host/
# restore_network in particular (pfctl anchor rules) is the piece most worth a careful
# first live test before ever relying on it for a real incident.

def list_processes_macos():
    # BSD ps (macOS) has no GNU --sort/--no-headers -- -r sorts by %cpu descending
    # directly; tail -n +2 drops the header line for output-shape parity with the
    # Linux/Windows equivalents.
    return "ps -Aceo pid,ppid,user,pcpu,pmem,etime,comm -r | tail -n +2 | head -100"

def kill_process_macos(pid):
    pid = int(pid)
    return (
        f'if kill -0 {pid} 2>/dev/null; then\n'
        f'    kill -9 {pid} && echo "Process {pid} terminated." || echo "Failed to terminate PID {pid}."\n'
        f'else\n'
        f'    echo "Failed to terminate PID {pid}: no such process."\n'
        f'fi'
    )

# Identical shape to kill_process_by_name_linux() -- `ps -Ao pid=,comm=,args=` output is
# the same on both POSIX agents, no /proc dependency either way.
def kill_process_by_name_macos(pattern):
    esc = pattern.replace('\\', '\\\\').replace("'", "\\'")
    return f"""python3 - <<'PYEOF'
import json, os, re, signal, subprocess

pattern = re.compile(re.escape('{esc}'), re.IGNORECASE)
out = subprocess.run(['ps', '-Ao', 'pid=,comm=,args='], capture_output=True, text=True, timeout=15).stdout
killed, failed = [], []
my_pid = os.getpid()
for line in out.splitlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split(None, 2)
    if len(parts) < 2:
        continue
    try:
        pid = int(parts[0])
    except ValueError:
        continue
    comm = parts[1]
    args = parts[2] if len(parts) > 2 else ''
    if pid <= 1 or pid == my_pid:
        continue
    if pattern.search(comm) or pattern.search(args):
        try:
            os.kill(pid, signal.SIGKILL)
            killed.append({{'pid': pid, 'name': comm}})
        except Exception as e:
            failed.append({{'pid': pid, 'name': comm, 'error': str(e)}})
print(json.dumps({{'killed': killed, 'failed': failed}}))
PYEOF
"""

# pfctl anchor-based isolation -- same "dedicated ruleset, flush-and-remove on restore"
# shape as the Linux agent's iptables chain, so restore can't leave stray rules behind
# or clobber whatever pf rules already existed on the host. Uses `pfctl -a <anchor> -f -`
# to load an ad-hoc anchor from stdin (works without needing an `anchor` line already
# present in /etc/pf.conf) and `pfctl -e` to make sure pf itself is enabled -- NOT
# live-verified against a real Mac; if this doesn't take effect as expected, `pfctl -s
# rules -a microdfir/isolation` on the host is the first thing to check.
_PF_ANCHOR = "microdfir/isolation"

def isolate_host_macos(soc_ip):
    if not _IPV4_RE.match(soc_ip):
        raise ValueError(f"Invalid SOC IP address: {soc_ip!r}")
    return f"""cat <<'PFRULES' | pfctl -a {_PF_ANCHOR} -f - 2>&1
block all
pass out quick proto tcp from any to {soc_ip}
pass in quick proto tcp from {soc_ip} to any
PFRULES
pfctl -e 2>&1 | grep -v 'already enabled'
echo "Host isolated (pfctl anchor {_PF_ANCHOR}). Only traffic to/from {soc_ip} is permitted."
"""

def restore_network_macos():
    return f"""pfctl -a {_PF_ANCHOR} -F all 2>&1
echo "Network isolation removed (pfctl anchor {_PF_ANCHOR} flushed)."
"""

def collect_triage_macos():
    return r"""echo "=== Processes ==="
ps -Aceo pid,ppid,user,pcpu,pmem,comm -r | head -60
echo
echo "=== Established Connections ==="
netstat -an -p tcp 2>/dev/null | grep ESTABLISHED | head -60
echo
echo "=== LaunchAgents / LaunchDaemons (user + system) ==="
for d in /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents /System/Library/LaunchAgents /System/Library/LaunchDaemons; do
    [ -d "$d" ] && echo "--$d--" && ls -1 "$d" 2>/dev/null
done
echo
echo "=== Logged-in Users ==="
who
echo
echo "=== Login Items Modified in the Last 7 Days ==="
find /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents -type f -mtime -7 2>/dev/null
"""

def collect_file_macos(path):
    # Identical shape/escaping to collect_file_linux() -- a quoted heredoc delimiter
    # disables all shell expansion, so the path only needs Python string-literal
    # escaping, not bash escaping. 40KB raw, not 4MB -- see collect_file()'s comment:
    # base64 inflation blows through the server's 60,000-char stdout truncation
    # (api_agent_result, app.py) well before 4MB, corrupting the JSON mid-string.
    esc = path.replace('\\', '\\\\').replace("'", "\\'")
    return f"""python3 - <<'PYEOF'
import base64, hashlib, json, os
p = '{esc}'
if not os.path.isfile(p):
    print(json.dumps({{'error': 'file not found'}}))
else:
    size = os.path.getsize(p)
    if size > 40 * 1024:
        print(json.dumps({{'error': 'file too large (%d bytes, 40KB limit)' % size}}))
    else:
        with open(p, 'rb') as f:
            data = f.read()
        print(json.dumps({{'path': p, 'size': size, 'sha256': hashlib.sha256(data).hexdigest(), 'content_b64': base64.b64encode(data).decode()}}))
PYEOF
"""

def quarantine_file_macos(path):
    # Identical shape to quarantine_file_linux() -- chmod 000 is the real baseline
    # (agent runs as root via the launchd plist, so this still blocks every OTHER
    # account). chflags uchg (the BSD "user immutable" flag, macOS's closest analog to
    # Linux's chattr +i) is attempted best-effort on top; not guaranteed to be honored
    # depending on SIP/filesystem, so its real success is reported back rather than
    # assumed, same honesty as the Linux chattr attempt.
    esc = path.replace('\\', '\\\\').replace("'", "\\'")
    return f"""python3 - <<'PYEOF'
import hashlib, json, os, shutil, subprocess, datetime

p = '{esc}'
if not os.path.isfile(p):
    print(json.dumps({{'error': 'file not found'}}))
else:
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    sha256 = h.hexdigest()

    qdir = '/usr/local/microdfir-agent/quarantine'
    os.makedirs(qdir, exist_ok=True)
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    dest_name = f'{{stamp}}_{{sha256[:16]}}_{{os.path.basename(p)}}.quarantined'
    dest = os.path.join(qdir, dest_name)
    try:
        shutil.move(p, dest)
        os.chmod(dest, 0o000)
        immutable = False
        try:
            r = subprocess.run(['chflags', 'uchg', dest], capture_output=True, timeout=5)
            immutable = (r.returncode == 0)
        except Exception:
            pass
        manifest = {{'original_path': p, 'quarantined_path': dest, 'sha256': sha256, 'quarantined_at': stamp, 'immutable': immutable}}
        with open(dest + '.manifest.json', 'w') as f:
            json.dump(manifest, f)
        print(json.dumps(manifest))
    except Exception as e:
        print(json.dumps({{'error': f'failed to quarantine: {{e}}'}}))
PYEOF
"""

MACOS_TEMPLATES = {
    'list_processes': (lambda params: list_processes_macos(), []),
    'kill_process': (lambda params: kill_process_macos(params['pid']), ['pid']),
    'kill_process_by_name': (lambda params: kill_process_by_name_macos(params['pattern']), ['pattern']),
    'isolate_host': (lambda params: isolate_host_macos(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: restore_network_macos(), []),
    'collect_triage': (lambda params: collect_triage_macos(), []),
    'collect_file': (lambda params: collect_file_macos(params['path']), ['path']),
    'quarantine_file': (lambda params: quarantine_file_macos(params['path']), ['path']),
}

TEMPLATES_BY_OS = {'windows': WINDOWS_TEMPLATES, 'linux': LINUX_TEMPLATES, 'macos': MACOS_TEMPLATES}
TEMPLATES = WINDOWS_TEMPLATES  # back-compat alias
