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
    # Backtick must be escaped first — escaping "/$ afterward would otherwise
    # produce a fresh backtick that pairs with a pre-existing one in the input
    # and cancels out, letting an embedded $(...) execute as a subexpression.
    esc = path.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f"""$p = "{esc}"
if (-not (Test-Path $p)) {{ '{{"error":"file not found"}}'; exit }}
$size = (Get-Item $p).Length
if ($size -gt 4MB) {{ "{{`"error`":`"file too large ($size bytes, 4MB limit)`"}}"; exit }}
$bytes = [IO.File]::ReadAllBytes($p)
$b64 = [Convert]::ToBase64String($bytes)
$hash = (Get-FileHash $p -Algorithm SHA256).Hash
@{{ path=$p; size=$size; sha256=$hash; content_b64=$b64 }} | ConvertTo-Json -Compress
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
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $uname = $_.Name
    $uhome = $_.FullName
    $candidates = @(
        (Join-Path $uhome 'AppData\Local\Google\Chrome\User Data\Default\History'),
        (Join-Path $uhome 'AppData\Local\Microsoft\Edge\User Data\Default\History')
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) {
            $item = Get-Item $p -ErrorAction SilentlyContinue
            if ($item) {
                $h = try { (Get-FileHash $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null }
                [void]$browsers.Add([PSCustomObject]@{ user=$uname; path=$p; size=$item.Length; last_write=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); sha256=$h })
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
$result.recent_downloads = $downloads
$result.note = "History/places.sqlite listed with hash+timestamps only, not parsed -- collect the file via 'Collect File' for offline analysis (e.g. with a SQLite browser)."
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

# label -> (builder, required param names)
WINDOWS_TEMPLATES = {
    'list_processes': (lambda params: _PROGRESS_SILENT + list_processes(), []),
    'kill_process': (lambda params: _PROGRESS_SILENT + kill_process(params['pid']), ['pid']),
    'isolate_host': (lambda params: _PROGRESS_SILENT + isolate_host(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: _PROGRESS_SILENT + restore_network(), []),
    'collect_triage': (lambda params: _PROGRESS_SILENT + collect_triage(), []),
    'persistence_sweep': (lambda params: _PROGRESS_SILENT + persistence_sweep(), []),
    'collect_file': (lambda params: _PROGRESS_SILENT + collect_file(params['path']), ['path']),
    'collect_browser_artifacts': (lambda params: _PROGRESS_SILENT + collect_browser_artifacts(), []),
    'collect_forensic_timestamps': (lambda params: _PROGRESS_SILENT + collect_forensic_timestamps(), []),
    'collect_recent_file_changes': (lambda params: _PROGRESS_SILENT + collect_recent_file_changes(), []),
    'collect_live_forensics': (lambda params: _PROGRESS_SILENT + collect_live_forensics(), []),
    'collect_software_inventory': (lambda params: _PROGRESS_SILENT + collect_software_inventory(), []),
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
    esc = path.replace('\\', '\\\\').replace("'", "\\'")
    return f"""python3 - <<'PYEOF'
import base64, hashlib, json, os
p = '{esc}'
if not os.path.isfile(p):
    print(json.dumps({{'error': 'file not found'}}))
else:
    size = os.path.getsize(p)
    if size > 4 * 1024 * 1024:
        print(json.dumps({{'error': 'file too large (%d bytes, 4MB limit)' % size}}))
    else:
        with open(p, 'rb') as f:
            data = f.read()
        print(json.dumps({{'path': p, 'size': size, 'sha256': hashlib.sha256(data).hexdigest(), 'content_b64': base64.b64encode(data).decode()}}))
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
    'isolate_host': (lambda params: isolate_host_linux(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: restore_network_linux(), []),
    'collect_triage': (lambda params: collect_triage_linux(), []),
    'persistence_sweep': (lambda params: persistence_sweep_linux(), []),
    'collect_file': (lambda params: collect_file_linux(params['path']), ['path']),
    'collect_ssh_artifacts': (lambda params: collect_ssh_artifacts_linux(), []),
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

TEMPLATES_BY_OS = {'windows': WINDOWS_TEMPLATES, 'linux': LINUX_TEMPLATES}
TEMPLATES = WINDOWS_TEMPLATES  # back-compat alias
