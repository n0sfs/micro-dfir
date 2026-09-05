# Micro DFIR Linux Agent
import urllib.request, json, time, sys, os, subprocess, socket, ssl, threading, hashlib, re, shutil

# Bump this on every change to this file — it's reported on every check-in
# (X-Agent-Version header) so the Agents page can show what each deployed endpoint is
# actually running and when it last picked up an upgrade.
AGENT_VERSION = "2026.09.05.1"

_OS_DETAIL_CACHE = None

def _get_os_detail():
    # Plain file read (stdlib, no subprocess) -- computed once and cached, the OS
    # version doesn't change mid-session.
    global _OS_DETAIL_CACHE
    if _OS_DETAIL_CACHE is not None:
        return _OS_DETAIL_CACHE
    try:
        info = {}
        with open('/etc/os-release', 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if '=' in line:
                    k, _, v = line.strip().partition('=')
                    info[k] = v.strip('"')
        _OS_DETAIL_CACHE = info.get('PRETTY_NAME') or info.get('NAME') or 'Linux (unknown distro)'
    except Exception:
        _OS_DETAIL_CACHE = 'Linux (unknown distro)'
    # Sent as a raw HTTP header value -- strip any stray CR/LF and cap the length.
    _OS_DETAIL_CACHE = _OS_DETAIL_CACHE.replace('\r', '').replace('\n', '')[:200]
    return _OS_DETAIL_CACHE

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
            # No length cap -- the server stores the entire raw message (live_logs.message
            # is plain TEXT with no size limit).
            "message": str(e.get('MESSAGE', '')),
        })
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
# handful of high-value paths like /etc/passwd or /etc/shadow, not a full-tree watcher).
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

# ---- auditd exec auditing ----
# Always attempted every cycle regardless of whether the microdfir_exec rule is
# currently active (enable/disable_exec_auditing in agent_scripts.py) -- ausearch
# just returns nothing if the rule isn't loaded, so there's no need for local state
# to track whether auditing was ever turned on for this host.
_sent_audit_sigs = set()
_SENT_AUDIT_SIG_CAP = 5000

# Server-driven Linux logging channels (Log Pipeline > Linux Channels tab). The server
# sends the FULL rule text for every enabled channel -- both its curated catalog (11
# CIS/STIG-aligned bundles) and any admin-defined custom "watch this path" channels --
# as a list of {'key', 'audit_key', 'rules': [...]} dicts, so the agent needs no local
# knowledge of what a channel key even means; it just applies whatever it's handed. This
# also means a custom channel (a path/perms the admin typed into the UI, unknowable to
# this file ahead of time) works through the exact same code path as a built-in one.
# Deliberately a DIFFERENT key namespace (microdfir_ch_*/microdfir_identity/etc) and a
# SEPARATE rules file from the older one-off "Enable Exec Auditing" console action
# (/etc/audit/rules.d/microdfir.rules, key microdfir_exec) so the two mechanisms -- one
# manual per-host, one automatic per-group -- never overwrite or duplicate-count each
# other's rules.
LINUX_CHANNEL_RULES_PATH = '/etc/audit/rules.d/microdfir_channels.rules'
_last_applied_linux_channels = None
_sent_channel_audit_sigs = set()
_SENT_CHANNEL_AUDIT_SIG_CAP = 5000  # matches _SENT_AUDIT_SIG_CAP's own convention below

def reconcile_linux_audit_channels(channel_defs):
    """Declaratively applies whichever channel definitions the server sent for this
    host's group -- writes/removes LINUX_CHANNEL_RULES_PATH and reloads via augenrules,
    the same persist-then-load pattern the manual exec-auditing action already uses. A
    no-op unless the desired set actually changed since the last poll, so this never
    reloads audit rules on every log-shipping cycle for no reason."""
    global _last_applied_linux_channels
    channel_defs = channel_defs or []
    # Rule text is part of the signature (not just the key) -- editing a custom
    # channel's watched path server-side must trigger a real reload here, not get
    # silently ignored because its key didn't change.
    desired_sig = frozenset((d.get('key'), tuple(d.get('rules') or [])) for d in channel_defs)
    if desired_sig == _last_applied_linux_channels:
        return
    if shutil.which('auditctl') is None:
        # Nothing we can do on a host without auditd installed -- remember the desired
        # set anyway so this doesn't retry (and log a failure) on every single poll.
        _last_applied_linux_channels = desired_sig
        return
    lines = []
    for d in sorted(channel_defs, key=lambda x: x.get('key') or ''):
        lines.extend(d.get('rules') or [])
    try:
        os.makedirs(os.path.dirname(LINUX_CHANNEL_RULES_PATH), exist_ok=True)
        if lines:
            with open(LINUX_CHANNEL_RULES_PATH, 'w') as f:
                f.write('\n'.join(lines) + '\n')
        elif os.path.exists(LINUX_CHANNEL_RULES_PATH):
            os.remove(LINUX_CHANNEL_RULES_PATH)
        subprocess.run(['augenrules', '--load'], capture_output=True, timeout=15)
        _last_applied_linux_channels = desired_sig
        applied_keys = sorted(d.get('key') for d in channel_defs)
        print(f"[+] Reconciled Linux log channels: {applied_keys or 'none enabled'}", flush=True)
    except Exception as e:
        print(f"[!] Failed to reconcile Linux log channels: {e}", flush=True)

def fetch_channel_audit_logs(channel_defs, last_seconds):
    """Pulls ausearch results for each ENABLED channel's own audit key -- generalizes
    fetch_audit_exec_logs()'s single-key approach to the server-driven channel
    definitions above. Handles both execve (type=SYSCALL/EXECVE) and file-watch
    (type=PATH) audit record shapes, since most channels here use -w watch rules,
    not a syscall rule."""
    logs = []
    host = socket.gethostname()
    for d in (channel_defs or []):
        key = d.get('key')
        audit_key = d.get('audit_key')
        if not key or not audit_key:
            continue
        try:
            out = subprocess.check_output(
                ['ausearch', '-k', audit_key, '-ts', f'-{last_seconds}s', '-i'],
                encoding='utf-8', errors='ignore', stderr=subprocess.DEVNULL
            )
        except Exception:
            continue
        for record in out.split('----'):
            record = record.strip()
            if not record:
                continue
            sig = None
            exe, cmd_line, uid, paths, is_execve = '', '', 'root', [], False
            for line in record.splitlines():
                if 'audit(' in line and sig is None:
                    try:
                        sig = line.split('audit(', 1)[1].split(')', 1)[0]
                    except Exception:
                        pass
                if line.startswith('type=SYSCALL'):
                    for token in line.split():
                        if token.startswith('exe='):
                            exe = token.split('=', 1)[1].strip('"')
                        elif token.startswith('auid=') and 'unset' not in token:
                            uid = token.split('=', 1)[1]
                if line.startswith('type=EXECVE'):
                    is_execve = True
                    cmd_line = ' '.join(re.findall(r'a\d+="((?:[^"\\]|\\.)*)"', line))
                if line.startswith('type=PATH'):
                    for token in line.split():
                        if token.startswith('name='):
                            paths.append(token.split('=', 1)[1].strip('"'))
            if not sig:
                continue
            channel_sig = f'{key}:{sig}'
            if channel_sig in _sent_channel_audit_sigs:
                continue
            _sent_channel_audit_sigs.add(channel_sig)
            if len(_sent_channel_audit_sigs) > _SENT_CHANNEL_AUDIT_SIG_CAP:
                _sent_channel_audit_sigs.pop()
            try:
                ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(sig.split(':', 1)[0])))
            except (ValueError, IndexError):
                ts = ''
            # is_execve (an actual type=EXECVE record), not just "exe happened to be
            # set" -- type=SYSCALL's own exe= field is present on nearly every audit
            # record regardless of which syscall fired, so branching on it alone would
            # mislabel every identity_changes file-watch hit (open/write syscalls) as
            # an "exec:" event.
            if is_execve:
                message = f"exec: {exe} {cmd_line}".strip()
                event_id = 'execve'
            elif paths:
                message = f"file change: {', '.join(dict.fromkeys(paths))} (by {exe or 'unknown'})"
                event_id = 'file_watch'
            else:
                message = f"audit event (key={audit_key})"
                event_id = 'audit'
            logs.append({
                "time": ts, "host": host, "app": "auditd", "severity": "INFO", "event_id": event_id,
                "username": uid, "message": message,
            })
    return logs

def fetch_audit_exec_logs(last_seconds):
    logs = []
    host = socket.gethostname()
    try:
        out = subprocess.check_output(
            ['ausearch', '-k', 'microdfir_exec', '-ts', f'-{last_seconds}s', '-i'],
            encoding='utf-8', errors='ignore', stderr=subprocess.DEVNULL
        )
    except Exception:
        return logs
    # ausearch -i groups each execve syscall into a multi-line record separated by a
    # blank line, headed by a "----" separator and a "type=SYSCALL ... id=<serial>" line
    # that carries the one stable identifier (audit(timestamp:serial)) for dedup.
    for record in out.split('----'):
        record = record.strip()
        if not record or 'type=SYSCALL' not in record:
            continue
        sig = None
        exe, cmd_line, uid, ts = '', '', 'root', ''
        for line in record.splitlines():
            if 'audit(' in line and sig is None:
                try:
                    sig = line.split('audit(', 1)[1].split(')', 1)[0]
                except Exception:
                    pass
            if line.startswith('type=SYSCALL'):
                for token in line.split():
                    if token.startswith('exe='):
                        exe = token.split('=', 1)[1].strip('"')
                    elif token.startswith('auid=') and 'unset' not in token:
                        uid = token.split('=', 1)[1]
            if line.startswith('type=EXECVE'):
                # Reconstructs the real argv from the record's a0="...", a1="...", ...
                # tokens (in order) -- the raw line also carries unrelated audit
                # metadata (msg=audit(...), argc=N) that isn't part of the command.
                cmd_line = ' '.join(re.findall(r'a\d+="((?:[^"\\]|\\.)*)"', line))
        if not sig or sig in _sent_audit_sigs:
            continue
        _sent_audit_sigs.add(sig)
        if len(_sent_audit_sigs) > _SENT_AUDIT_SIG_CAP:
            _sent_audit_sigs.pop()
        try:
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(sig.split(':', 1)[0])))
        except (ValueError, IndexError):
            ts = ''
        logs.append({
            "time": ts, "host": host, "app": "auditd", "severity": "INFO", "event_id": "execve",
            "username": uid, "message": f"exec: {exe} {cmd_line}".strip(),
        })
    return logs

def run_agent():
    global INGEST_URL
    print("[*] Agent starting up! Initializing...", flush=True)
    context = build_ssl_context()
    active_fim_paths = []
    active_linux_channels = []
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
                    headers = {'X-Agent-Hostname': socket.gethostname(), 'X-Agent-Token': SOC_TOKEN, 'X-Agent-Version': AGENT_VERSION, 'X-Agent-OS': 'linux', 'X-Agent-OS-Detail': _get_os_detail()}
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

                        if data.get('linux_audit_channels') is not None:
                            active_linux_channels = data['linux_audit_channels']
                            reconcile_linux_audit_channels(active_linux_channels)

                        if data.get('fim_interval_seconds'):
                            fim_interval = data['fim_interval_seconds']

                        # Decoupled from each other server-side (see /api/agent/poll-
                        # interval) -- a large fleet wants command/upgrade check-ins to
                        # back off while log shipping stays frequent.
                        if data.get('config_interval_seconds'):
                            CONFIG_INTERVAL = data['config_interval_seconds']
                        if data.get('log_interval_seconds'):
                            LOG_INTERVAL = data['log_interval_seconds']

                    print("[+] Check-in successful!", flush=True)
                    break
                except Exception as e:
                    print(f"[-] Config Check Attempt {attempt + 1} Failed: {e}", flush=True)
                    time.sleep(1)
            last_config_check = time.time()

        # 2. Log Ingestion (system journal — not scoped to the Windows Event Log
        # "channel" names, since journald has no equivalent grouping to filter by).
        # FIM and auditd exec logs fold into this same batch/POST -- no separate ingest
        # endpoint or request needed, they're just more rows in the same "logs" list.
        try:
            print("[*] Fetching journal logs...", flush=True)
            new_logs = fetch_journal_logs(LOG_INTERVAL)

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

            try:
                new_logs.extend(fetch_audit_exec_logs(LOG_INTERVAL))
            except Exception as e:
                print(f"[-] auditd exec log fetch failed: {e}", flush=True)

            if active_linux_channels:
                try:
                    new_logs.extend(fetch_channel_audit_logs(active_linux_channels, LOG_INTERVAL))
                except Exception as e:
                    print(f"[-] Linux channel audit log fetch failed: {e}", flush=True)

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
