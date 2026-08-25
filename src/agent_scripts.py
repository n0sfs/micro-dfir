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
def persistence_sweep():
    return r"""$result = @{}
$result.scheduled_tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskName,TaskPath,State,@{N='Actions';E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}}
$result.services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,State,StartMode,PathName
$result.run_keys = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
$result.startup_files = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime
$result.wmi_event_filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query
$result.wmi_event_consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate,ScriptFileName
$result.wmi_bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter,Consumer
$result | ConvertTo-Json -Depth 5 -Compress
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
    # 'hashes'/'md5_hashes'/'sha1_hashes' and 'patterns' are always server-populated
    # from the live IOC list / imported YARA rules right before dispatch (see app.py's
    # api_agent_commands()), never client-supplied — deliberately not in the required
    # list, since an empty live set is a real, valid state the builder already handles,
    # not a missing-parameter error.
    'ioc_sweep': (lambda params: _PROGRESS_SILENT + ioc_sweep(params.get('hashes', []), params.get('md5_hashes', []), params.get('sha1_hashes', [])), []),
    'string_sweep': (lambda params: _PROGRESS_SILENT + string_sweep(params.get('patterns', [])), []),
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

# Deeper than collect_triage_linux()'s lighter cron/systemd touch above -- every user's
# own crontab individually (not just the system-wide files), the FULL enabled-unit list
# (no head cap), /etc/init.d SysV scripts, shell profile files (a classic persistence
# spot -- .bashrc/.profile run on every login), and any LD_PRELOAD reference (a
# well-known library-injection persistence technique). Inspired by the same
# Autoruns/Velociraptor philosophy as persistence_sweep() above, just for Linux's own
# autostart mechanisms.
def persistence_sweep_linux():
    return r"""echo "=== User Crontabs ==="
for u in $(cut -f1 -d: /etc/passwd); do
    out=$(crontab -l -u "$u" 2>/dev/null)
    [ -n "$out" ] && echo "--$u--" && echo "$out"
done
echo
echo "=== System Cron ==="
for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] && echo "--$f--" && cat "$f"; done 2>/dev/null
echo
echo "=== Enabled systemd Units (full list) ==="
systemctl list-unit-files --state=enabled --no-legend 2>/dev/null
echo
echo "=== /etc/init.d Scripts ==="
ls -la /etc/init.d/ 2>/dev/null
echo
echo "=== Shell Profile Files ==="
for f in /etc/profile /etc/profile.d/*.sh /root/.bashrc /root/.profile; do
    [ -f "$f" ] && echo "--$f--" && cat "$f"
done 2>/dev/null
echo
echo "=== LD_PRELOAD References ==="
grep -H LD_PRELOAD /etc/environment /etc/ld.so.preload 2>/dev/null || echo "(none found)"
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

LINUX_TEMPLATES = {
    'list_processes': (lambda params: list_processes_linux(), []),
    'kill_process': (lambda params: kill_process_linux(params['pid']), ['pid']),
    'isolate_host': (lambda params: isolate_host_linux(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: restore_network_linux(), []),
    'collect_triage': (lambda params: collect_triage_linux(), []),
    'persistence_sweep': (lambda params: persistence_sweep_linux(), []),
    'collect_file': (lambda params: collect_file_linux(params['path']), ['path']),
    'collect_ssh_artifacts': (lambda params: collect_ssh_artifacts_linux(), []),
    'ioc_sweep': (lambda params: ioc_sweep_linux(params.get('hashes', []), params.get('md5_hashes', []), params.get('sha1_hashes', [])), []),
    'string_sweep': (lambda params: string_sweep_linux(params.get('patterns', [])), []),
    'enable_exec_auditing': (lambda params: enable_exec_auditing(), []),
    'disable_exec_auditing': (lambda params: disable_exec_auditing(), []),
}

TEMPLATES_BY_OS = {'windows': WINDOWS_TEMPLATES, 'linux': LINUX_TEMPLATES}
TEMPLATES = WINDOWS_TEMPLATES  # back-compat alias
