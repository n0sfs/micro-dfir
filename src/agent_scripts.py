# Canned PowerShell templates for agent response actions.
# Each function returns a ready-to-run script string; the caller is
# responsible for validating/sanitizing any parameters before formatting.
import re

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

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

# label -> (builder, required param names)
TEMPLATES = {
    'list_processes': (lambda params: list_processes(), []),
    'kill_process': (lambda params: kill_process(params['pid']), ['pid']),
    'isolate_host': (lambda params: isolate_host(params['soc_ip']), ['soc_ip']),
    'restore_network': (lambda params: restore_network(), []),
    'collect_triage': (lambda params: collect_triage(), []),
    'collect_file': (lambda params: collect_file(params['path']), ['path']),
}
