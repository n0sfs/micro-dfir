# Micro DFIR Windows Agent
import urllib.request, json, time, sys, os, subprocess, socket, random, ssl, tempfile, threading, hashlib, zipfile, shutil

# Bump this on every change to this file — it's reported on every check-in
# (X-Agent-Version header) so the Agents page can show what each deployed endpoint is
# actually running and when it last picked up an upgrade.
AGENT_VERSION = "2026.09.03.1"

INSTALL_DIR = r"C:\Program Files\MicroDFIR"
TASK_NAME = "MicroDFIRAgent"

# Optional INSTALL_DIR\agent_config.json, dropped there by the NSIS installer (see
# installer/agent_installer.nsi) BEFORE it runs `install` -- that installer bundles a
# generic, un-substituted copy of this script (built once, not per download), so the
# per-deployment host/token/cert can't be baked into the .py source the way the plain-
# script .zip download does. When present, its values win; the __HOST_URL__/__SOC_TOKEN__/
# __SERVER_CERT_PEM__ placeholders below stay as the fallback for that existing plain-
# script path, unchanged. Deliberately keyed on the fixed INSTALL_DIR constant, not
# os.path.dirname(__file__) -- install_agent() below copies this same script's own
# source into INSTALL_DIR\micro_agent_windows.py by opening that exact path for both
# read and write, so having the installer stage the source script anywhere OTHER than
# INSTALL_DIR itself (e.g. NSIS's own $PLUGINSDIR) avoids a same-file read/write hazard,
# while the config file goes straight into its permanent INSTALL_DIR home either way.
def _load_external_config():
    path = os.path.join(INSTALL_DIR, "agent_config.json")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

_EXTERNAL_CONFIG = _load_external_config()
# Two distinct host:port values, not one -- _build_agent_source's own substitution (see
# src/app.py) already uses ui_port for /api/agent/config and /api/agent/result but
# ingest_port for /api/ingest (they can genuinely differ, see _resolve_ingest_port), so
# collapsing both into a single __HOST_URL__-equivalent here would silently break
# ingestion on any deployment where those two ports aren't the same.
_HOST_URL = _EXTERNAL_CONFIG.get('host_url')
_INGEST_HOST_URL = _EXTERNAL_CONFIG.get('ingest_host_url') or _HOST_URL
SERVER_URL = f'https://{_HOST_URL}/api/agent/config' if _HOST_URL else 'https://__HOST_URL__/api/agent/config'
RESULT_URL = f'https://{_HOST_URL}/api/agent/result' if _HOST_URL else 'https://__HOST_URL__/api/agent/result'
INGEST_URL = f'https://{_INGEST_HOST_URL}/api/ingest' if _INGEST_HOST_URL else 'https://__HOST_URL__/api/ingest'
SYSMON_CONFIG_URL = f'https://{_HOST_URL}/api/agent/sysmon-config' if _HOST_URL else 'https://__HOST_URL__/api/agent/sysmon-config'
SOC_TOKEN = _EXTERNAL_CONFIG.get('soc_token') or '__SOC_TOKEN__'
# The server's own cert, pinned so the agent can verify it without a real CA (it's
# self-signed) — see build_ssl_context() below. Left as the literal placeholder if the
# script is run without ever going through the server's build step (e.g. tampered with
# by hand), in which case the agent falls back to unverified rather than refusing to run.
SERVER_CERT_PEM = _EXTERNAL_CONFIG.get('server_cert_pem') or """__SERVER_CERT_PEM__"""
# Was 90s -- too tight for string_sweep (content search across many files is inherently
# heavier than ioc_sweep's single-pass hashing, and 90s wasn't enough margin even after
# fixing string_sweep's own O(pattern_count) blowup, see agent_scripts.py).
SCRIPT_TIMEOUT_SECONDS = 180

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

# Neither is on by default in Windows, and neither needs Sysmon (that's a separate
# concern, see _ensure_sysmon_installed) -- these are the two built-in-Windows settings
# the already-enabled "Security" and "PowerShell" log channels need turned on before
# they'll actually produce anything. Safe and fully reversible (`auditpol .../success:
# disable`, delete the registry keys) -- no new software installed. Each setting is
# independently try/excepted (not one big try/except around all four) -- these are 3
# unrelated settings, so one failing (e.g. a locked-down machine rejecting the auditpol
# change) is no reason to skip the other two.
def _configure_windows_audit_logging():
    def _run(cmd):
        try:
            subprocess.run(cmd, shell=True, timeout=15)
        except Exception:
            pass
    # Security log Event ID 4688 (process creation) is off by default.
    _run('auditpol /set /subcategory:"Process Creation" /success:enable')
    # Without this, 4688 events omit the actual command line -- most of the value of
    # process-creation auditing in the first place.
    _run(
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" '
        '/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f'
    )
    # PowerShell Module Logging (Event ID 4103, classic "Windows PowerShell" log -- the
    # exact channel this agent watches, see _CHANNEL_LOG_NAMES['powershell'] below). "*"
    # logs every module's pipeline execution detail, not just a hand-picked subset.
    _run(
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" '
        '/v EnableModuleLogging /t REG_DWORD /d 1 /f'
    )
    _run(
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames" '
        '/v "*" /t REG_SZ /d "*" /f'
    )

# Distinct from the audit-policy settings above -- Sysmon is real third-party software
# (Sysinternals), not a Windows setting, so it's never silently bundled into install().
# Instead, this is checked on every regular config poll (see run_agent()) and only acts
# when the server reports the Sysmon channel is enabled (Log Pipeline tab) -- toggling
# that checkbox IS the install trigger, on whatever cadence agents already poll at, no
# separate "push install" mechanism needed.
SYSMON_RETRY_COOLDOWN_SECONDS = 1800  # 30 min -- a failed attempt (no internet, blocked
# download, AV interference) shouldn't retry on every ~8s config poll

def _sysmon_already_installed():
    try:
        for svc in ('Sysmon64', 'Sysmon'):
            result = subprocess.run(['sc', 'query', svc], capture_output=True, text=True, timeout=10)
            if 'RUNNING' in result.stdout or 'STOPPED' in result.stdout:
                return True
    except Exception:
        pass
    return False

def _ensure_sysmon_installed(context):
    if _sysmon_already_installed():
        return
    marker_path = os.path.join(INSTALL_DIR, "sysmon_install_attempt.json")
    try:
        if os.path.exists(marker_path):
            with open(marker_path, 'r') as f:
                last_attempt = json.load(f).get('last_attempt', 0)
            if time.time() - last_attempt < SYSMON_RETRY_COOLDOWN_SECONDS:
                return
    except Exception:
        pass
    try:
        with open(marker_path, 'w') as f:
            json.dump({'last_attempt': time.time()}, f)
    except Exception:
        pass

    tmp_dir = tempfile.mkdtemp(prefix="microdfir_sysmon_")
    try:
        print("[*] Sysmon channel enabled but not installed -- installing now...", flush=True)
        zip_path = os.path.join(tmp_dir, "Sysmon.zip")
        req = urllib.request.Request("https://download.sysinternals.com/files/Sysmon.zip", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as resp, open(zip_path, 'wb') as f:
            f.write(resp.read())

        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp_dir)

        sysmon_exe = os.path.join(tmp_dir, "Sysmon64.exe")
        if not os.path.exists(sysmon_exe):
            sysmon_exe = os.path.join(tmp_dir, "Sysmon.exe")
        if not os.path.exists(sysmon_exe):
            print("[-] Sysmon.zip didn't contain the expected executable -- aborting install.", flush=True)
            return

        # Config comes from the server, not bundled in this script -- editable/tunable
        # server-side (agents/sysmon_config.xml) without redistributing a new agent
        # install to every endpoint.
        config_path = os.path.join(tmp_dir, "sysmon_config.xml")
        config_req = urllib.request.Request(SYSMON_CONFIG_URL, headers={'X-Agent-Hostname': socket.gethostname(), 'X-Agent-Token': SOC_TOKEN})
        with urllib.request.urlopen(config_req, context=context, timeout=15) as resp, open(config_path, 'wb') as f:
            f.write(resp.read())

        result = subprocess.run(f'"{sysmon_exe}" -accepteula -i "{config_path}"', shell=True, capture_output=True, text=True, timeout=60)
        print(f"[*] Sysmon install output: {(result.stdout or '')[-500:]}", flush=True)

        if _sysmon_already_installed():
            print("[+] Sysmon successfully installed and running.", flush=True)
        else:
            print("[-] Sysmon install command completed but the service isn't showing as installed -- check permissions/AV interference.", flush=True)
    except Exception as e:
        print(f"[-] Sysmon auto-install failed: {e}", flush=True)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

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
        # A Scheduled Task's ONSTART trigger only fires at boot -- it does NOT restart on
        # crash/kill/OOM the way systemd's Restart=always (Linux) or launchd's KeepAlive
        # (macOS) do for their own installers. This second task is what actually gives
        # Windows that same resilience: it runs watchdog_check() every 5 minutes, which
        # relaunches the main task if the agent process it started has died.
        watchdog_vbs_path = os.path.join(INSTALL_DIR, "run_watchdog.vbs")
        with open(watchdog_vbs_path, 'w') as f:
            f.write('Set objShell = WScript.CreateObject("WScript.Shell")\n')
            f.write('objShell.Run """' + sys.executable + '"" ""' + target_path + '"" watchdog", 0, True\n')
        watchdog_cmd = f'schtasks /create /tn "{TASK_NAME}Watchdog" /tr "wscript.exe \\"{watchdog_vbs_path}\\"" /sc MINUTE /mo 5 /rl HIGHEST /f'
        subprocess.run(watchdog_cmd, shell=True)
    except: pass

def watchdog_check():
    # Invoked by the separate MicroDFIRAgentWatchdog scheduled task, NOT the long-lived
    # agent process itself -- checks whether the PID the main process recorded at its
    # own startup is still alive, and relaunches the main task if not. See the comment
    # above the watchdog task creation in install_agent() for why this exists.
    pid_path = os.path.join(INSTALL_DIR, "agent.pid")
    try:
        with open(pid_path, 'r') as f:
            pid = int(f.read().strip())
        result = subprocess.run(
            ['tasklist', '/FI', f'PID eq {pid}', '/FI', 'IMAGENAME eq python.exe', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, timeout=15
        )
        if str(pid) in result.stdout:
            return  # still alive, nothing to do
    except (FileNotFoundError, ValueError, OSError):
        pass  # no pidfile yet, or unreadable -- treat as not running, relaunch below
    try:
        subprocess.run(f'schtasks /run /tn "{TASK_NAME}"', shell=True, timeout=15)
    except Exception:
        pass

def uninstall_agent():
    subprocess.run(f'schtasks /delete /tn "{TASK_NAME}" /f', shell=True, capture_output=True)
    subprocess.run(f'schtasks /delete /tn "{TASK_NAME}Watchdog" /f', shell=True, capture_output=True)

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

def fetch_windows_logs(channel_configs, last_seconds):
    logs = []
    host = socket.gethostname()
    for cfg in channel_configs:
        channel = (cfg.get('name') or '').strip()
        if not channel:
            continue
        capture_xml = bool(cfg.get('capture_xml'))
        # Pre-built server-side (see _build_powershell_id_clause in app.py) from the
        # channel's saved include/exclude event-ID filter -- this agent does zero
        # parsing/validation of its own, just splices the ready expression in.
        where_clause = cfg.get('where_clause') or ''
        raw_base = channel.split(" (")[0].strip()
        # The server's channel config key ("WindowsDefender", no space — the JSON key the
        # Log Pipeline UI saves) doesn't match the display name ("Windows Defender", with a
        # space) that used to be compared against directly, so Get-WinEvent was being asked
        # for a log named "WindowsDefender" — not a real channel — and silently returned
        # nothing every cycle. Matching on a space/case-normalized key fixes that regardless
        # of which form the channel arrives in, and canonicalizes the display name too so
        # historical and future rows use the same "app" value instead of splitting in two.
        # Unrecognized names (custom channels) fall through to using the raw string
        # directly as the LogName -- this is what lets an admin-added custom channel
        # work with no agent-side changes.
        lookup_key = raw_base.replace(' ', '').replace('-', '').lower()
        base, log_name = _CHANNEL_LOG_NAMES.get(lookup_key, (raw_base, raw_base))
        where_stage = f" | Where-Object {{ {where_clause} }}" if where_clause else ""
        xml_prop = ", @{N='Xml';E={$_.ToXml()}}" if capture_xml else ""
        cmd = (
            "powershell -Command \"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "Get-WinEvent -FilterHashtable @{LogName='" + log_name + "'; StartTime=(Get-Date).AddSeconds(-" + str(last_seconds) + ")} -ErrorAction SilentlyContinue"
            + where_stage +
            " | Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Id, LevelDisplayName, "
            "@{N='User';E={if($_.UserId){try{(New-Object System.Security.Principal.SecurityIdentifier($_.UserId.Value)).Translate([System.Security.Principal.NTAccount]).Value}catch{$_.UserId.Value}}else{'SYSTEM'}}}, Message"
            + xml_prop +
            " | ConvertTo-Json -Compress\""
        )
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
                    # No length cap -- the server stores the entire raw message (live_logs.message
                    # is plain TEXT with no size limit), and last session's field-parsing logic
                    # depends on seeing the whole thing (ParentImage/ParentCommandLine/Hashes can
                    # all sit past where any fixed cap would cut).
                    log_entry = {"time": str(e.get('TimeCreated', '')), "host": host, "app": base, "severity": "ALERT" if e.get('LevelDisplayName') in ['Error', 'Critical'] else "WARN" if e.get('LevelDisplayName') == 'Warning' else "INFO", "event_id": str(e.get('Id', '-')), "username": str(e.get('User', 'SYSTEM')).split('\\')[-1], "message": str(e.get('Message', ''))}
                    if capture_xml and e.get('Xml'):
                        log_entry["xml"] = str(e.get('Xml'))
                    logs.append(log_entry)
        except: pass
    return logs

# ---- File Integrity Monitoring ----
# A plain JSON file living next to the agent script in INSTALL_DIR -- upgrade_agent()
# only ever overwrites the script file itself, so this baseline survives a remote
# self-upgrade the same way sigma_engine.py's own STATE_FILE survives an app restart.
FIM_STATE_PATH = os.path.join(INSTALL_DIR, "fim_state.json")

def _load_fim_state():
    try:
        with open(FIM_STATE_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_fim_state(state):
    try:
        if not os.path.exists(INSTALL_DIR): os.makedirs(INSTALL_DIR)
        with open(FIM_STATE_PATH, 'w', encoding='utf-8') as f:
            json.dump(state, f)
    except Exception:
        pass

def _hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# Single files only, not directories, not recursive -- deliberately lightweight (a
# handful of high-value paths like hosts or a config file, not a full-tree watcher).
# A path from a fresh admin config always logs one "now being monitored" event on its
# first check (nothing in the baseline yet to compare against) -- expected, not a bug.
def run_fim_check(paths):
    host = socket.gethostname()
    state = _load_fim_state()
    logs = []
    seen = set()
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    for path in paths:
        seen.add(path)
        prev = state.get(path)
        if not os.path.isfile(path):
            if prev:
                logs.append({"time": now, "host": host, "app": "FIM", "severity": "HIGH", "event_id": "-", "username": "-", "message": f"File removed: {path}"})
                del state[path]
            continue
        try:
            st = os.stat(path)
        except Exception:
            continue
        cur = {"mtime": st.st_mtime, "size": st.st_size}
        if prev is None:
            cur["hash"] = _hash_file(path)
            state[path] = cur
            logs.append({"time": now, "host": host, "app": "FIM", "severity": "MEDIUM", "event_id": "-", "username": "-", "message": f"New file now being monitored: {path}", "sha256": cur["hash"]})
        elif prev.get("mtime") != cur["mtime"] or prev.get("size") != cur["size"]:
            cur["hash"] = _hash_file(path)
            if cur["hash"] != prev.get("hash"):
                # sha256 rides along as its own field (not just embedded in the message)
                # so the server can check it against the live IOC hash list without
                # having to parse it back out of free text -- see api_ingest()'s
                # FIM-hash branch, the server-side half of this same feature.
                logs.append({"time": now, "host": host, "app": "FIM", "severity": "HIGH", "event_id": "-", "username": "-", "message": f"File changed: {path}", "sha256": cur["hash"]})
            state[path] = cur
    # A path an admin stopped watching is just dropped from the baseline, silently --
    # only paths still in the config can ever produce a "removed" alert above.
    for stale in list(state.keys()):
        if stale not in seen:
            del state[stale]
    _save_fim_state(state)
    return logs

def run_agent():
    global INGEST_URL
    print("[*] Agent starting up! Initializing...", flush=True)
    # Read by the MicroDFIRAgentWatchdog task's watchdog_check() to detect a crashed/
    # killed agent process and relaunch it -- see install_agent().
    try:
        with open(os.path.join(INSTALL_DIR, "agent.pid"), 'w') as f:
            f.write(str(os.getpid()))
    except Exception:
        pass
    # Applied on every process start (fresh install, reboot, watchdog relaunch, AND a
    # remote "Upgrade Agent" -- upgrade_agent() just swaps the script file and relaunches
    # via the same scheduled task, it never calls install_agent() again). Each individual
    # setting is idempotent (re-applying an already-set auditpol/registry value is a
    # harmless no-op), so calling this on every startup rather than only once at install
    # time is what makes it actually reach an agent that was installed before this
    # existed, not just brand new ones.
    _configure_windows_audit_logging()
    context = build_ssl_context()
    active_channel_configs = [
        {'name': 'Security', 'capture_xml': False, 'where_clause': ''},
        {'name': 'System', 'capture_xml': False, 'where_clause': ''},
    ]
    active_fim_paths = []
    last_config_check = 0
    last_fim_check = 0
    LOG_INTERVAL = 8
    CONFIG_INTERVAL = 8
    # Deliberately much coarser than LOG_INTERVAL by default -- hashing a handful of
    # files every 8s would be wasted work when nothing on disk changes anywhere near
    # that often. Server-configurable (Agents page > File Integrity Monitoring) rather
    # than a fixed constant -- updated from each config check-in below, same as
    # active_fim_paths.
    fim_interval = 300

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

                        # Update Channels -- channel_config (per-channel capture_xml/
                        # where_clause) takes priority; the flat 'channels' string is
                        # kept only as a fallback for a server that hasn't been updated
                        # yet (or an in-flight upgrade window).
                        if data.get('channel_config') is not None:
                            active_channel_configs = data['channel_config']
                        elif data.get('channels'):
                            active_channel_configs = [
                                {'name': c, 'capture_xml': False, 'where_clause': ''}
                                for c in data['channels'].split(',')
                            ]

                        # Zero-Touch Ingestion Routing!
                        if data.get('ingest_url'):
                            new_ingest = data['ingest_url']
                            if INGEST_URL != new_ingest:
                                print(f"[*] Network Shift Detected! Updating Ingest URL to: {new_ingest}", flush=True)
                                INGEST_URL = new_ingest

                        if data.get('fim_paths') is not None:
                            active_fim_paths = data['fim_paths']

                        if data.get('fim_interval_seconds'):
                            fim_interval = data['fim_interval_seconds']

                        # Toggling the Sysmon channel on (Log Pipeline tab) is the whole
                        # trigger -- no separate "push install" action exists. Dispatched
                        # on its own thread (same pattern as run_remote_script above) so
                        # a slow download/install can never delay this agent's own
                        # check-ins or log shipping. _ensure_sysmon_installed() itself
                        # no-ops immediately if Sysmon is already installed.
                        if data.get('sysmon_required'):
                            threading.Thread(target=_ensure_sysmon_installed, args=(context,), daemon=True).start()

                    print("[+] Check-in successful!", flush=True)
                    break
                except Exception as e:
                    print(f"[-] Config Check Attempt {attempt + 1} Failed: {e}", flush=True)
                    time.sleep(1)
            last_config_check = time.time()

        # 2. Log Ingestion (FIM folds into this same batch/POST -- no separate ingest
        # endpoint or request needed, it's just more rows in the same "logs" list)
        try:
            print("[*] Fetching Windows event logs...", flush=True)
            new_logs = fetch_windows_logs(active_channel_configs, LOG_INTERVAL)

            if current_time - last_fim_check > fim_interval:
                if active_fim_paths:
                    try:
                        fim_logs = run_fim_check(active_fim_paths)
                        if fim_logs:
                            print(f"[*] FIM detected {len(fim_logs)} change(s).", flush=True)
                        new_logs.extend(fim_logs)
                    except Exception as e:
                        print(f"[-] FIM check failed: {e}", flush=True)
                last_fim_check = current_time

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
    elif len(sys.argv) > 1 and sys.argv[1] == 'watchdog': watchdog_check()
    else: run_agent()
