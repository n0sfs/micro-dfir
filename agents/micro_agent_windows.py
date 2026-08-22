# Micro DFIR Windows Agent
import urllib.request, json, time, sys, os, subprocess, socket, random, ssl, tempfile, threading

# Bump this on every change to this file — it's reported on every check-in
# (X-Agent-Version header) so the Agents page can show what each deployed endpoint is
# actually running and when it last picked up an upgrade.
AGENT_VERSION = "2026.08.21.4"

INSTALL_DIR = r"C:\Program Files\MicroDFIR"
TASK_NAME = "MicroDFIRAgent"
SERVER_URL = 'https://__HOST_URL__/api/agent/config'
INGEST_URL = 'https://__HOST_URL__/api/ingest'
RESULT_URL = 'https://__HOST_URL__/api/agent/result'
SOC_TOKEN = '__SOC_TOKEN__'
# The server's own cert, pinned so the agent can verify it without a real CA (it's
# self-signed) — see build_ssl_context() below. Left as the literal placeholder if the
# script is run without ever going through the server's build step (e.g. tampered with
# by hand), in which case the agent falls back to unverified rather than refusing to run.
SERVER_CERT_PEM = """__SERVER_CERT_PEM__"""
SCRIPT_TIMEOUT_SECONDS = 90

def build_ssl_context():
    # A structural check (does this look like a real PEM cert?) rather than checking
    # for the literal placeholder token's absence — _build_agent_source's substitution
    # is a blind whole-file replace of that exact token, which would otherwise also
    # rewrite this very check (it contains that same token as a substring) and corrupt
    # the file into invalid Python the moment a real cert got substituted in.
    if not SERVER_CERT_PEM.strip().startswith('-----BEGIN CERTIFICATE-----'):
        print("[!] WARNING: no pinned server certificate embedded — falling back to unverified TLS. Re-download the agent package to fix this.", flush=True)
        return ssl._create_unverified_context()
    try:
        # The cert is self-signed with no SAN, so there's no hostname to check against —
        # trusting only this exact pinned cert as its own CA (cert-chain verification
        # stays on) is what replaces hostname matching here.
        context = ssl.create_default_context(cadata=SERVER_CERT_PEM)
        context.check_hostname = False
        return context
    except ssl.SSLError as e:
        print(f"[!] WARNING: failed to load the pinned server certificate ({e}) — falling back to unverified TLS.", flush=True)
        return ssl._create_unverified_context()

def _kill_other_agent_instances():
    # A manual reinstall previously just registered a new scheduled-task run without
    # ever stopping whatever instance was already running in the background — leaving
    # two copies polling and shipping logs concurrently until the machine next
    # rebooted. Finds and stops any OTHER running instance of the long-lived agent
    # process (excluding one-shot `install`/`uninstall` invocations, and this process
    # itself) before handing off to the new one.
    try:
        my_pid = os.getpid()
        ps = (
            "Get-CimInstance Win32_Process | Where-Object { "
            "$_.CommandLine -like '*micro_agent_windows.py*' "
            "-and $_.CommandLine -notlike '* install*' -and $_.CommandLine -notlike '* uninstall*' "
            f"-and $_.ProcessId -ne {my_pid} "
            "} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
        )
        subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', ps], capture_output=True, timeout=15)
    except Exception:
        pass

def install_agent():
    try:
        _kill_other_agent_instances()
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

def upgrade_agent(new_source):
    # Remote self-update: overwrite the installed copy with the source the server just
    # sent, then hand off to a fresh instance via the scheduled task. Only returns True
    # (telling the caller to let this process exit) once the new file is safely on
    # disk — if the write fails, the old process keeps running rather than vanishing
    # with nothing to replace it, unlike uninstall which always removes itself.
    if not new_source.strip():
        print("[-] Upgrade command had no source; ignoring.", flush=True)
        return False
    try:
        if not os.path.exists(INSTALL_DIR): os.makedirs(INSTALL_DIR)
        target_path = os.path.join(INSTALL_DIR, "micro_agent_windows.py")
        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(new_source)
        print("[+] Agent script updated on disk. Handing off to a fresh instance...", flush=True)
        subprocess.run(f'schtasks /run /tn "{TASK_NAME}"', shell=True)
        return True
    except Exception as e:
        print(f"[-] Upgrade failed: {e}", flush=True)
        return False

def run_remote_script(context, cmd_id, script):
    # Runs on a background thread (see run_agent()) so a slow or hung command can't
    # stall the agent's own check-in/log-shipping loop for up to SCRIPT_TIMEOUT_SECONDS —
    # previously this ran inline in the main loop, so one stuck response action also
    # delayed every subsequent poll and log upload until it finished or timed out.
    print(f"[*] Executing remote command #{cmd_id}...", flush=True)
    # Suppresses progress-stream output (e.g. Get-FileHash's progress bar), which
    # otherwise gets serialized as a CLIXML blob appended straight into stdout when
    # PowerShell runs non-interactively with its output captured — confirmed in
    # production contaminating a collect_triage result.
    full_script = "$ProgressPreference = 'SilentlyContinue'\n" + script
    exit_code, stdout, stderr = 1, '', ''
    tmp_path = None
    try:
        # -EncodedCommand embeds the whole script directly in the process's command-line
        # arguments, which Windows caps at ~32K characters total (CreateProcess) — fine
        # for the original small canned actions, but confirmed in production: an
        # ioc_sweep command carrying a few hundred live IOC hashes blows straight
        # through that limit and fails with WinError 206 ("filename or extension is too
        # long") before anything even runs. Writing the script to a temp .ps1 file and
        # invoking it with -File has no such ceiling, so this scales with the action's
        # actual content instead of a fixed limit that only gets easier to hit as the
        # IOC list grows. utf-8-sig (UTF-8 with a BOM) is what makes PowerShell reliably
        # detect the file as UTF-8 rather than falling back to the system ANSI codepage.
        fd, tmp_path = tempfile.mkstemp(suffix='.ps1')
        with os.fdopen(fd, 'w', encoding='utf-8-sig') as f:
            f.write(full_script)
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmp_path],
            capture_output=True, encoding='utf-8', errors='ignore', timeout=SCRIPT_TIMEOUT_SECONDS
        )
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        stderr = f"Command timed out after {SCRIPT_TIMEOUT_SECONDS}s"
    except Exception as e:
        stderr = f"Failed to execute command: {e}"
    finally:
        if tmp_path:
            try: os.remove(tmp_path)
            except Exception: pass

    # A command that ran (or timed out) but whose result never reaches the server sits
    # "Sent" forever with nothing to show for it — retry the report a couple of times
    # before giving up, rather than one transient network hiccup silently losing it.
    payload = json.dumps({'id': cmd_id, 'exit_code': exit_code, 'stdout': stdout, 'stderr': stderr}).encode('utf-8')
    for attempt in range(3):
        try:
            req = urllib.request.Request(RESULT_URL, data=payload, headers={'Content-Type': 'application/json', 'X-Agent-Token': SOC_TOKEN})
            urllib.request.urlopen(req, context=context, timeout=10)
            print(f"[+] Result for command #{cmd_id} reported (exit {exit_code}).", flush=True)
            return
        except Exception as e:
            print(f"[-] Failed to report result for command #{cmd_id} (attempt {attempt + 1}/3): {e}", flush=True)
            if attempt < 2:
                time.sleep(2)

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
    context = build_ssl_context()
    active_channels = ['Security', 'System']
    last_config_check = 0
    LOG_INTERVAL = 8
    CONFIG_INTERVAL = 8
    
    while True:
        current_time = time.time()
        
        # 1. Config Check with Retry Loop & Custom Hostname Header
        if current_time - last_config_check > CONFIG_INTERVAL:
            for attempt in range(3):
                try:
                    print(f"[*] Checking in with {SERVER_URL} (Attempt {attempt + 1})...", flush=True)
                    headers = {'X-Agent-Hostname': socket.gethostname(), 'X-Agent-Token': SOC_TOKEN, 'X-Agent-Version': AGENT_VERSION, 'X-Agent-OS': 'windows'}
                    req = urllib.request.Request(SERVER_URL, headers=headers)
                    with urllib.request.urlopen(req, context=context, timeout=5) as response:
                        data = json.loads(response.read().decode())

                        # Server pushed a management command (e.g. uninstall)
                        if data.get('command') == 'uninstall':
                            print("[*] Uninstall command received. Removing agent...", flush=True)
                            uninstall_agent()
                            return

                        # Server pushed a remote self-upgrade with the new agent source
                        # embedded in the response
                        if data.get('command') == 'upgrade':
                            print("[*] Upgrade command received. Updating agent...", flush=True)
                            if upgrade_agent(data.get('source', '')):
                                return

                        # Server pushed a response-action script (process list, isolate, triage collection, etc.)
                        # Dispatched on a background thread so a slow/hung command can't
                        # delay this agent's own check-ins or log shipping.
                        if data.get('run_script'):
                            rs = data['run_script']
                            threading.Thread(
                                target=run_remote_script, args=(context, rs.get('id'), rs.get('script', '')), daemon=True
                            ).start()

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
