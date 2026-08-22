# Canned response-action templates, one script-builder set per agent OS. Each function
# returns a ready-to-run script string; the caller is responsible for
# validating/sanitizing any parameters before formatting. Windows templates are
# PowerShell (run by the agent via `powershell -EncodedCommand`); Linux templates are
# bash (run by the agent via `subprocess.run(['bash', '-c', script])`, which sidesteps
# shell-quoting entirely since the whole script travels as one argument — no
# encoding step is needed the way PowerShell's -EncodedCommand needs one).
import re

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')

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

def ioc_sweep(hashes):
    # Only ever trust hex-shaped 64-char values here regardless of what the caller
    # passed — hashes ultimately comes from the live threat-intel IOC list, whose
    # ioc_type labeling is inconsistent across feeds (see _get_live_ioc_sha256_hashes
    # in app.py), so re-validating by shape at the point the value gets embedded into
    # a script is the actual safety boundary, not a redundant check.
    valid = sorted({(h or '').strip().lower() for h in hashes if _SHA256_RE.match((h or '').strip())})
    if not valid:
        # A real, expected state (no SHA-256 IOCs currently loaded) — emit a script
        # that reports that clearly rather than one that silently "succeeds" with a
        # zero-hit sweep that looks identical to a clean host.
        return "Write-Output '{\"error\":\"no SHA-256 IOC hashes are currently available to sweep for\"}'"
    hash_list = ','.join("'" + h + "'" for h in valid)
    # Bounded to common malware-drop locations, recently-modified, executable-ish
    # files under 50MB — a full-disk hash sweep would blow past the agent's 90s
    # command timeout on any real machine, and this is also where live-response
    # triage actually looks first.
    script = """$hashSet = New-Object System.Collections.Generic.HashSet[string]
@(__HASHES__) | ForEach-Object { [void]$hashSet.Add($_) }
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
                $h = (Get-FileHash -Algorithm SHA256 -Path $_.FullName -ErrorAction Stop).Hash.ToLower()
                if ($hashSet.Contains($h)) {
                    $hits += [PSCustomObject]@{ path=$_.FullName; sha256=$h; size=$_.Length; modified=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
                }
            } catch {}
        }
}
[PSCustomObject]@{ scanned=$scanned; hits=$hits } | ConvertTo-Json -Compress -Depth 4
"""
    return script.replace('__HASHES__', hash_list)

# Progress records (e.g. from Get-FileHash on multiple files in collect_triage) get
# serialized as CLIXML and mixed straight into stdout when PowerShell runs
# non-interactively with its output captured — confirmed in production, where a
# collect_triage result had a "#< CLIXML" progress blob appended after the real JSON.
# Silencing progress up front keeps every template's stdout clean.
_PROGRESS_SILENT = "$ProgressPreference = 'SilentlyContinue'\n"

# label -> (builder, required param names)
WINDOWS_TEMPLATES = {
    'list_processes': (lambda params: _PROGRESS_SILENT + list_processes(), []),
    'kill_process': (lambda params: _PROGRESS_SILENT + kill_process(params['pid']), ['pid']),
    'isolate_host': (lambda params: _PROGRESS_SILENT + isolate_host(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: _PROGRESS_SILENT + restore_network(), []),
    'collect_triage': (lambda params: _PROGRESS_SILENT + collect_triage(), []),
    'collect_file': (lambda params: _PROGRESS_SILENT + collect_file(params['path']), ['path']),
    # 'hashes' is always server-populated from the live IOC list right before dispatch
    # (see app.py's api_agent_commands()), never client-supplied — it's deliberately
    # not in the required list, since an empty live hash set is a real, valid state
    # the builder already handles, not a missing-parameter error.
    'ioc_sweep': (lambda params: _PROGRESS_SILENT + ioc_sweep(params.get('hashes', [])), []),
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

def ioc_sweep_linux(hashes):
    valid = sorted({(h or '').strip().lower() for h in hashes if _SHA256_RE.match((h or '').strip())})
    if not valid:
        return "echo '{\"error\": \"no SHA-256 IOC hashes are currently available to sweep for\"}'"
    hash_list = ', '.join("'" + h + "'" for h in valid)
    # Same quoted-heredoc trick as collect_file_linux — no shell expansion happens
    # inside the block, so the hash list only needs to be valid Python (already
    # guaranteed: every entry matched _SHA256_RE, so none can break out of the set
    # literal), not escaped for bash at all.
    script = """python3 - <<'PYEOF'
import hashlib, json, os, time

HASHES = {__HASHES__}
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
                h = hashlib.sha256()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        h.update(chunk)
                digest = h.hexdigest()
            except OSError:
                continue
            if digest in HASHES:
                hits.append({'path': path, 'sha256': digest, 'size': st.st_size, 'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))})

print(json.dumps({'scanned': scanned, 'hits': hits}))
PYEOF
"""
    return script.replace('__HASHES__', hash_list)

LINUX_TEMPLATES = {
    'list_processes': (lambda params: list_processes_linux(), []),
    'kill_process': (lambda params: kill_process_linux(params['pid']), ['pid']),
    'isolate_host': (lambda params: isolate_host_linux(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: restore_network_linux(), []),
    'collect_triage': (lambda params: collect_triage_linux(), []),
    'collect_file': (lambda params: collect_file_linux(params['path']), ['path']),
    'ioc_sweep': (lambda params: ioc_sweep_linux(params.get('hashes', [])), []),
}

TEMPLATES_BY_OS = {'windows': WINDOWS_TEMPLATES, 'linux': LINUX_TEMPLATES}
TEMPLATES = WINDOWS_TEMPLATES  # back-compat alias
