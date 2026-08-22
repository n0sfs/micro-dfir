# Micro DFIR Linux Agent
import urllib.request, json, time, sys, os, subprocess, socket, ssl, threading

# Bump this on every change to this file — it's reported on every check-in
# (X-Agent-Version header) so the Agents page can show what each deployed endpoint is
# actually running and when it last picked up an upgrade.
AGENT_VERSION = "2026.08.21.2"

INSTALL_DIR = "/opt/microdfir-agent"
SERVICE_NAME = "microdfir-agent"
SERVICE_PATH = f"/etc/systemd/system/{SERVICE_NAME}.service"
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

def install_agent():
    # Installing over an already-running instance (managed by systemd) just means
    # `systemctl restart` below hands off to the freshly-written copy — no separate
    # "kill any stray instance" step is needed the way the Windows agent needs one,
    # since a systemd-managed service doesn't leave orphaned processes behind the way
    # a manually re-run scheduled task could.
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        target_path = os.path.join(INSTALL_DIR, "micro_agent_linux.py")
        with open(os.path.abspath(__file__), 'r', encoding='utf-8') as src, open(target_path, 'w', encoding='utf-8') as dst:
            dst.write(src.read())
        unit = f"""[Unit]
Description=Micro DFIR Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={sys.executable} {target_path}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
        with open(SERVICE_PATH, 'w', encoding='utf-8') as f:
            f.write(unit)
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
        subprocess.run(['systemctl', 'enable', '--now', SERVICE_NAME], capture_output=True)
    except Exception as e:
        print(f"[-] Install failed: {e}", flush=True)

def uninstall_agent():
    subprocess.run(['systemctl', 'disable', '--now', SERVICE_NAME], capture_output=True)
    try:
        if os.path.exists(SERVICE_PATH):
            os.remove(SERVICE_PATH)
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
    except Exception:
        pass

def upgrade_agent(new_source):
    # Remote self-update: overwrite the installed copy with the source the server just
    # sent, then hand off to a fresh instance via systemd. Only returns True (telling
    # the caller to let this process exit) once the new file is safely on disk — if the
    # write fails, the old process keeps running rather than vanishing with nothing to
    # replace it, unlike uninstall which always removes itself.
    if not new_source.strip():
        print("[-] Upgrade command had no source; ignoring.", flush=True)
        return False
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        target_path = os.path.join(INSTALL_DIR, "micro_agent_linux.py")
        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(new_source)
        print("[+] Agent script updated on disk. Handing off to a fresh instance...", flush=True)
        subprocess.run(['systemctl', 'restart', SERVICE_NAME], capture_output=True)
        return True
    except Exception as e:
        print(f"[-] Upgrade failed: {e}", flush=True)
        return False

def run_remote_script(context, cmd_id, script):
    # Runs on a background thread (see run_agent()) so a slow or hung command can't
    # stall the agent's own check-in/log-shipping loop for up to SCRIPT_TIMEOUT_SECONDS.
    print(f"[*] Executing remote command #{cmd_id}...", flush=True)
    exit_code, stdout, stderr = 1, '', ''
    try:
        # Passing the script as a single subprocess argument (rather than building a
        # shell command line) means no quoting/escaping step is needed here at all —
        # bash receives the whole multi-line script as one -c argument regardless of
        # what quotes, `$()`, or newlines it contains.
        proc = subprocess.run(
            ['bash', '-c', script], capture_output=True, encoding='utf-8', errors='ignore', timeout=SCRIPT_TIMEOUT_SECONDS
        )
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        stderr = f"Command timed out after {SCRIPT_TIMEOUT_SECONDS}s"
    except Exception as e:
        stderr = f"Failed to execute command: {e}"

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

# journald's own __CURSOR field is a stable, globally unique per-entry identifier —
# a cleaner dedup key than the Windows agent's build-your-own event signature, since
# there's no risk of two distinct entries ever colliding on it.
_PRIORITY_SEVERITY = {'0': 'ALERT', '1': 'ALERT', '2': 'ALERT', '3': 'ALERT', '4': 'WARN'}

def fetch_journal_logs(last_seconds):
    logs = []
    host = socket.gethostname()
    try:
        out = subprocess.check_output(
            ['journalctl', '-o', 'json', '--no-pager', f'--since=-{last_seconds}s'],
            encoding='utf-8', errors='ignore', stderr=subprocess.DEVNULL
        )
    except Exception:
        return logs
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        cursor = e.get('__CURSOR', '')
        if not cursor or cursor in _sent_event_sigs:
            continue
        _sent_event_sigs.add(cursor)
        if len(_sent_event_sigs) > _SENT_SIG_CAP:
            _sent_event_sigs.pop()
        ts_us = e.get('__REALTIME_TIMESTAMP')
        try:
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts_us) / 1_000_000)) if ts_us else ''
        except (TypeError, ValueError):
            ts = ''
        logs.append({
            "time": ts, "host": host,
            "app": e.get('SYSLOG_IDENTIFIER') or e.get('_COMM') or 'journald',
            "severity": _PRIORITY_SEVERITY.get(str(e.get('PRIORITY', '6')), 'INFO'),
            "event_id": "-",
            "username": e.get('_UID', 'root') if e.get('_UID') is not None else 'root',
            "message": str(e.get('MESSAGE', ''))[:1000],
        })
    return logs

def run_agent():
    global INGEST_URL
    print("[*] Agent starting up! Initializing...", flush=True)
    context = build_ssl_context()
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
                    headers = {'X-Agent-Hostname': socket.gethostname(), 'X-Agent-Token': SOC_TOKEN, 'X-Agent-Version': AGENT_VERSION, 'X-Agent-OS': 'linux'}
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

        # 2. Log Ingestion (system journal — not scoped to the Windows Event Log
        # "channel" names, since journald has no equivalent grouping to filter by)
        try:
            print("[*] Fetching journal logs...", flush=True)
            new_logs = fetch_journal_logs(LOG_INTERVAL)
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
