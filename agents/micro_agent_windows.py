# Micro DFIR Windows Agent
import urllib.request, json, time, sys, os, subprocess, socket, random, ssl, base64

INSTALL_DIR = r"C:\Program Files\MicroDFIR"
TASK_NAME = "MicroDFIRAgent"
SERVER_URL = 'https://__HOST_URL__/api/agent/config'
INGEST_URL = 'https://__HOST_URL__/api/ingest'
RESULT_URL = 'https://__HOST_URL__/api/agent/result'
SOC_TOKEN = '__SOC_TOKEN__'
POLL_INTERVAL = 10
SCRIPT_TIMEOUT_SECONDS = 90

def install_agent():
    try:
        if not os.path.exists(INSTALL_DIR): os.makedirs(INSTALL_DIR)
        target_path = os.path.join(INSTALL_DIR, "micro_agent_windows.py")
        with open(os.path.abspath(__file__), 'r', encoding='utf-8') as src, open(target_path, 'w', encoding='utf-8') as dst:
            dst.write(src.read())
        vbs_path = os.path.join(INSTALL_DIR, "run_hidden.vbs")
        with open(vbs_path, 'w') as f:
            f.write('Set objShell = WScript.CreateObject("WScript.Shell")\n')
            f.write('objShell.Run """' + sys.executable + '"" ""' + target_path + '""", 0, False\n')
        cmd = f'schtasks /create /tn "{TASK_NAME}" /tr "wscript.exe \\"{vbs_path}\\"" /sc ONSTART /rl HIGHEST /f'
        subprocess.run(cmd, shell=True)
        subprocess.run(f'schtasks /run /tn "{TASK_NAME}"', shell=True)
    except: pass

def uninstall_agent():
    subprocess.run(f'schtasks /delete /tn "{TASK_NAME}" /f', shell=True, capture_output=True)

def run_remote_script(context, cmd_id, script):
    print(f"[*] Executing remote command #{cmd_id}...", flush=True)
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    exit_code, stdout, stderr = 1, '', ''
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
            capture_output=True, encoding='utf-8', errors='ignore', timeout=SCRIPT_TIMEOUT_SECONDS
        )
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        stderr = f"Command timed out after {SCRIPT_TIMEOUT_SECONDS}s"
    except Exception as e:
        stderr = f"Failed to execute command: {e}"

    try:
        payload = json.dumps({'id': cmd_id, 'exit_code': exit_code, 'stdout': stdout, 'stderr': stderr}).encode('utf-8')
        req = urllib.request.Request(RESULT_URL, data=payload, headers={'Content-Type': 'application/json', 'X-Agent-Token': SOC_TOKEN})
        urllib.request.urlopen(req, context=context, timeout=10)
        print(f"[+] Result for command #{cmd_id} reported (exit {exit_code}).", flush=True)
    except Exception as e:
        print(f"[-] Failed to report result for command #{cmd_id}: {e}", flush=True)

_sent_event_sigs = set()
_SENT_SIG_CAP = 5000

def _event_signature(host, base, e):
    msg = str(e.get('Message', ''))
    return f"{host}|{base}|{e.get('TimeCreated','')}|{e.get('Id','')}|{msg[:80]}"

_CHANNEL_LOG_NAMES = {
    'windowsdefender': ('Windows Defender', 'Microsoft-Windows-Windows Defender/Operational'),
    'sysmon': ('Sysmon', 'Microsoft-Windows-Sysmon/Operational'),
    'powershell': ('PowerShell', 'Windows PowerShell'),
}

def fetch_windows_logs(channels, last_seconds):
    logs = []
    host = socket.gethostname()
    for channel in channels:
        channel = channel.strip()
        raw_base = channel.split(" (")[0].strip()
        # The server's channel config key ("WindowsDefender", no space — the JSON key the
        # Log Pipeline UI saves) doesn't match the display name ("Windows Defender", with a
        # space) that used to be compared against directly, so Get-WinEvent was being asked
        # for a log named "WindowsDefender" — not a real channel — and silently returned
        # nothing every cycle. Matching on a space/case-normalized key fixes that regardless
        # of which form the channel arrives in, and canonicalizes the display name too so
        # historical and future rows use the same "app" value instead of splitting in two.
        lookup_key = raw_base.replace(' ', '').replace('-', '').lower()
        base, log_name = _CHANNEL_LOG_NAMES.get(lookup_key, (raw_base, raw_base))
        cmd = "powershell -Command \"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-WinEvent -FilterHashtable @{LogName='" + log_name + "'; StartTime=(Get-Date).AddSeconds(-" + str(last_seconds) + ")} -ErrorAction SilentlyContinue | Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Id, LevelDisplayName, @{N='User';E={if($_.UserId){try{(New-Object System.Security.Principal.SecurityIdentifier($_.UserId.Value)).Translate([System.Security.Principal.NTAccount]).Value}catch{$_.UserId.Value}}else{'SYSTEM'}}}, Message | ConvertTo-Json -Compress\""
        try:
            out = subprocess.check_output(cmd, shell=True, encoding='utf-8', errors='ignore', stderr=subprocess.DEVNULL).strip()
            if out:
                events = json.loads(out)
                if isinstance(events, dict): events = [events]
                for e in events:
                    sig = _event_signature(host, base, e)
                    if sig in _sent_event_sigs:
                        continue  # already sent this exact event in a prior cycle — skip
                    _sent_event_sigs.add(sig)
                    if len(_sent_event_sigs) > _SENT_SIG_CAP:
                        _sent_event_sigs.pop()
                    logs.append({"time": str(e.get('TimeCreated', '')), "host": host, "app": base, "severity": "ALERT" if e.get('LevelDisplayName') in ['Error', 'Critical'] else "WARN" if e.get('LevelDisplayName') == 'Warning' else "INFO", "event_id": str(e.get('Id', '-')), "username": str(e.get('User', 'SYSTEM')).split('\\')[-1], "message": str(e.get('Message', ''))[:1000]})
        except: pass
    return logs

def run_agent():
    global INGEST_URL
    print("[*] Agent starting up! Initializing...", flush=True)
    context = urllib.request.ssl._create_unverified_context()
    active_channels = ['Security', 'System']
    last_config_check = 0
    LOG_INTERVAL = 15
    CONFIG_INTERVAL = 15
    
    while True:
        current_time = time.time()
        
        # 1. Config Check with Retry Loop & Custom Hostname Header
        if current_time - last_config_check > CONFIG_INTERVAL:
            for attempt in range(3):
                try:
                    print(f"[*] Checking in with {SERVER_URL} (Attempt {attempt + 1})...", flush=True)
                    headers = {'X-Agent-Hostname': socket.gethostname(), 'X-Agent-Token': SOC_TOKEN}
                    req = urllib.request.Request(SERVER_URL, headers=headers)
                    with urllib.request.urlopen(req, context=context, timeout=5) as response:
                        data = json.loads(response.read().decode())

                        # Server pushed a management command (e.g. uninstall)
                        if data.get('command') == 'uninstall':
                            print("[*] Uninstall command received. Removing agent...", flush=True)
                            uninstall_agent()
                            return

                        # Server pushed a response-action script (process list, isolate, triage collection, etc.)
                        if data.get('run_script'):
                            rs = data['run_script']
                            run_remote_script(context, rs.get('id'), rs.get('script', ''))

                        # Update Channels
                        if data.get('channels'):
                            active_channels = data['channels'].split(',')

                        # Zero-Touch Ingestion Routing!
                        if data.get('ingest_url'):
                            new_ingest = data['ingest_url']
                            if INGEST_URL != new_ingest:
                                print(f"[*] Network Shift Detected! Updating Ingest URL to: {new_ingest}", flush=True)
                                INGEST_URL = new_ingest

                    print("[+] Check-in successful!", flush=True)
                    break
                except Exception as e:
                    print(f"[-] Config Check Attempt {attempt + 1} Failed: {e}", flush=True)
                    time.sleep(1)
            last_config_check = time.time()
            
        # 2. Log Ingestion
        try:
            print("[*] Fetching Windows event logs...", flush=True)
            new_logs = fetch_windows_logs(active_channels, LOG_INTERVAL)
            if new_logs:
                print(f"[*] Sending {len(new_logs)} logs to {INGEST_URL}...", flush=True)
                payload = json.dumps({"logs": new_logs}).encode('utf-8')
                req = urllib.request.Request(INGEST_URL, data=payload, headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {SOC_TOKEN}'})
                urllib.request.urlopen(req, context=context, timeout=5)
                print("[+] Logs sent successfully!", flush=True)
            else:
                print("[*] No new logs to send right now.", flush=True)
        except Exception as e: 
            print(f"[-] Ingest Failed: {e}", flush=True)
            
        print(f"[*] Sleeping for {LOG_INTERVAL} seconds...", flush=True)
        time.sleep(LOG_INTERVAL)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'install': install_agent()
    elif len(sys.argv) > 1 and sys.argv[1] == 'uninstall': uninstall_agent()
    else: run_agent()
