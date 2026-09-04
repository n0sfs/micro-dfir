# Micro DFIR macOS Agent
#
# Same architecture as the Linux/Windows agents (poll/check-in loop, FIM, response
# actions, log shipping) with three deliberate scope differences, called out here
# rather than left implicit:
#   - No real-time exec-auditing equivalent to Linux's auditd integration. macOS's
#     modern answer to that is the EndpointSecurity framework, which requires a
#     compiled, Apple-notarized system extension with a special entitlement Apple
#     grants case-by-case -- not achievable as a plain Python script. Process activity
#     here comes from on-demand snapshots (list_processes/collect_triage), not a
#     continuous stream.
#   - System log ingestion uses the `log show` unified-logging CLI (Default/Error/
#     Fault levels only -- macOS's unified log is notoriously verbose at Info/Debug),
#     polled the same way journalctl is on Linux, not a persistent `log stream`.
#   - Host isolation uses pfctl (the BSD packet filter) instead of iptables/Windows
#     Firewall -- same "one dedicated anchor, flush-and-remove on restore" shape as
#     the Linux agent's iptables chain, so it can't leave stray rules behind or
#     clobber whatever pf rules were already on the host.
import urllib.request, json, time, sys, os, subprocess, socket, ssl, threading, hashlib, re

# Bump this on every change to this file — it's reported on every check-in
# (X-Agent-Version header) so the Agents page can show what each deployed endpoint is
# actually running and when it last picked up an upgrade.
AGENT_VERSION = "2026.08.31.2"

_OS_DETAIL_CACHE = None

def _get_os_detail():
    # platform.mac_ver() is stdlib, no subprocess needed -- computed once and cached.
    global _OS_DETAIL_CACHE
    if _OS_DETAIL_CACHE is not None:
        return _OS_DETAIL_CACHE
    try:
        import platform
        ver = platform.mac_ver()[0]
        _OS_DETAIL_CACHE = f"macOS {ver}" if ver else "macOS (unknown version)"
    except Exception:
        _OS_DETAIL_CACHE = "macOS (unknown version)"
    _OS_DETAIL_CACHE = _OS_DETAIL_CACHE.replace('\r', '').replace('\n', '')[:200]
    return _OS_DETAIL_CACHE

INSTALL_DIR = "/usr/local/microdfir-agent"
SERVICE_LABEL = "com.microdfir.agent"
LAUNCHD_PLIST_PATH = f"/Library/LaunchDaemons/{SERVICE_LABEL}.plist"
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

_LAUNCHD_PLIST_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>{target}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/microdfir-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/microdfir-agent.log</string>
</dict>
</plist>
"""

def install_agent():
    # Installing over an already-running instance (managed by launchd, KeepAlive=true)
    # just means `launchctl bootout` + `bootstrap` below hands off to the freshly-written
    # copy -- same "no separate orphan-process cleanup needed" reasoning as the Linux
    # agent's systemd install, since launchd (like systemd) won't leave a stray process
    # behind the way a manually re-run scheduled task could.
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        target_path = os.path.join(INSTALL_DIR, "micro_agent_macos.py")
        with open(os.path.abspath(__file__), 'r', encoding='utf-8') as src, open(target_path, 'w', encoding='utf-8') as dst:
            dst.write(src.read())
        plist = _LAUNCHD_PLIST_TEMPLATE.format(label=SERVICE_LABEL, python=sys.executable, target=target_path)
        with open(LAUNCHD_PLIST_PATH, 'w', encoding='utf-8') as f:
            f.write(plist)
        os.chmod(LAUNCHD_PLIST_PATH, 0o644)
        subprocess.run(['launchctl', 'bootout', f'system/{SERVICE_LABEL}'], capture_output=True)
        subprocess.run(['launchctl', 'bootstrap', 'system', LAUNCHD_PLIST_PATH], capture_output=True)
        subprocess.run(['launchctl', 'enable', f'system/{SERVICE_LABEL}'], capture_output=True)
    except Exception as e:
        print(f"[-] Install failed: {e}", flush=True)

def uninstall_agent():
    subprocess.run(['launchctl', 'bootout', f'system/{SERVICE_LABEL}'], capture_output=True)
    try:
        if os.path.exists(LAUNCHD_PLIST_PATH):
            os.remove(LAUNCHD_PLIST_PATH)
    except Exception:
        pass

def upgrade_agent(new_source):
    # Remote self-update: overwrite the installed copy with the source the server just
    # sent, then hand off to a fresh instance via launchd. Only returns True (telling
    # the caller to let this process exit) once the new file is safely on disk -- if the
    # write fails, the old process keeps running rather than vanishing with nothing to
    # replace it, unlike uninstall which always removes itself.
    if not new_source.strip():
        print("[-] Upgrade command had no source; ignoring.", flush=True)
        return False
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        target_path = os.path.join(INSTALL_DIR, "micro_agent_macos.py")
        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(new_source)
        print("[+] Agent script updated on disk. Handing off to a fresh instance...", flush=True)
        subprocess.run(['launchctl', 'kickstart', '-k', f'system/{SERVICE_LABEL}'], capture_output=True)
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
        # shell command line) means no quoting/escaping step is needed here at all --
        # bash receives the whole multi-line script as one -c argument regardless of
        # what quotes, $(), or newlines it contains. macOS ships /bin/bash (older,
        # but present) independent of the user's interactive default shell (zsh).
        proc = subprocess.run(
            ['bash', '-c', script], capture_output=True, encoding='utf-8', errors='ignore', timeout=SCRIPT_TIMEOUT_SECONDS
        )
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        stderr = f"Command timed out after {SCRIPT_TIMEOUT_SECONDS}s"
    except Exception as e:
        stderr = f"Failed to execute command: {e}"

    # A command that ran (or timed out) but whose result never reaches the server sits
    # "Sent" forever with nothing to show for it -- retry the report a couple of times
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

_TYPE_SEVERITY = {'Fault': 'ALERT', 'Error': 'ALERT', 'Default': 'WARN'}

# `log show` (not the persistent `log stream`) polled every cycle, same shape as the
# Linux agent's journalctl call -- Default/Error/Fault levels only (no --info/--debug;
# the unified log at those levels is extremely high-volume for the signal it adds).
# Overlapping time windows across polls are expected (this queries "last N seconds"
# fresh each cycle, there's no cursor to resume from the way journald's __CURSOR is) --
# _sent_event_sigs is what actually prevents re-sending the same entry twice.
def fetch_unified_logs(last_seconds):
    logs = []
    host = socket.gethostname()
    try:
        out = subprocess.check_output(
            ['log', 'show', '--style', 'ndjson', '--last', f'{last_seconds}s'],
            encoding='utf-8', errors='ignore', stderr=subprocess.DEVNULL
        )
    except Exception:
        return logs
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue  # `log show` prefixes its ndjson stream with a non-JSON banner line
        try:
            e = json.loads(line)
        except Exception:
            continue
        msg_type = e.get('messageType', 'Default')
        if msg_type not in _TYPE_SEVERITY:
            continue
        ts = str(e.get('timestamp', ''))[:19]  # "YYYY-MM-DD HH:MM:SS.ffffff+ZZZZ" -> trim to seconds
        process = e.get('process') or e.get('subsystem') or 'unified-log'
        message = str(e.get('eventMessage', ''))
        sig = f"{host}|{process}|{ts}|{message[:80]}"
        if sig in _sent_event_sigs:
            continue
        _sent_event_sigs.add(sig)
        if len(_sent_event_sigs) > _SENT_SIG_CAP:
            _sent_event_sigs.pop()
        logs.append({
            "time": ts, "host": host, "app": process,
            "severity": _TYPE_SEVERITY.get(msg_type, 'INFO'), "event_id": "-",
            "username": "-",  # unified logging doesn't cleanly expose a per-event username
            "message": message,
        })
    return logs

# ---- File Integrity Monitoring ----
# A plain JSON file living next to the agent script in INSTALL_DIR -- upgrade_agent()
# only ever overwrites the script file itself, so this baseline survives a remote
# self-upgrade the same way sigma_engine.py's own STATE_FILE survives an app restart.
# Identical logic to the Linux agent's FIM -- pure Python (hashlib/os.stat), no OS-
# specific behavior to adapt.
FIM_STATE_PATH = os.path.join(INSTALL_DIR, "fim_state.json")

def _load_fim_state():
    try:
        with open(FIM_STATE_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_fim_state(state):
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
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
# handful of high-value paths like /etc/passwd or /etc/hosts, not a full-tree watcher).
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
    context = build_ssl_context()
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
                    headers = {'X-Agent-Hostname': socket.gethostname(), 'X-Agent-Token': SOC_TOKEN, 'X-Agent-Version': AGENT_VERSION, 'X-Agent-OS': 'macos', 'X-Agent-OS-Detail': _get_os_detail()}
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

                        if data.get('fim_paths') is not None:
                            active_fim_paths = data['fim_paths']

                        if data.get('fim_interval_seconds'):
                            fim_interval = data['fim_interval_seconds']

                    print("[+] Check-in successful!", flush=True)
                    break
                except Exception as e:
                    print(f"[-] Config Check Attempt {attempt + 1} Failed: {e}", flush=True)
                    time.sleep(1)
            last_config_check = time.time()

        # 2. Log Ingestion (unified log -- not scoped to the Windows Event Log "channel"
        # names, same reasoning as the Linux agent's journald ingestion). FIM folds into
        # this same batch/POST -- no separate ingest endpoint or request needed.
        try:
            print("[*] Fetching unified logs...", flush=True)
            new_logs = fetch_unified_logs(LOG_INTERVAL)

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
    else: run_agent()
