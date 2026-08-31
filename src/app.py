import os

# --- Enable SQLite WAL Mode for High Concurrency ---
try:
    import sqlite3
    _db_path = '/opt/micro-dfir/siem.db'
    if os.path.exists(_db_path):
        _conn = sqlite3.connect(_db_path, timeout=30)
        _conn.execute('PRAGMA journal_mode=WAL;')
        _conn.close()
except Exception as e:
    print(f"WAL setup error: {e}")

import os, json, re, sqlite3, tempfile, yaml, secrets, subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask import Flask, render_template, request, jsonify, g, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from yara_scanner import scan_file
from taxii_client import sync_one as ti_sync_one
import agent_scripts

app = Flask(__name__, template_folder='../templates')
DB_PATH = "/opt/micro-dfir/siem.db"

def _get_or_create_secret_key():
    # Generated once per install and persisted in the settings table — a hardcoded
    # session-signing key shipped in source would let anyone who reads the repo forge
    # session cookies for any deployment still using the default.
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        row = conn.execute("SELECT value FROM settings WHERE key = 'flask_secret_key'").fetchone()
        if row and row[0]:
            key = row[0]
        else:
            key = secrets.token_hex(32)
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('flask_secret_key', ?)", (key,))
            conn.commit()
        conn.close()
        return key
    except Exception:
        return secrets.token_hex(32)  # DB not ready yet — sessions won't survive a restart, but the app still runs

app.secret_key = _get_or_create_secret_key()
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

login_manager = LoginManager()
login_manager.init_app(app); login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def unauthorized():
    # Flask-Login's default @login_required response is a redirect to the login page
    # regardless of what kind of request triggered it. For a page load that's correct,
    # but every fetch() call in this app follows redirects by default, so a fetch to
    # any /api/* route with an expired session was silently ending up with the login
    # page's HTML as its "JSON" body — surfacing as a baffling "Unexpected token '<'"
    # parse error in whatever UI triggered it, with no indication the real problem was
    # just an expired session. API routes get a real 401 they can actually handle.
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Session expired. Please log in again.'}), 401
    return redirect(url_for('login'))

def csrf_token():
    from flask import session
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf():
    from flask import session
    submitted = request.form.get('csrf_token', '')
    expected = session.get('csrf_token', '')
    if not expected or not secrets.compare_digest(submitted, expected):
        flash('Your session expired or the form was submitted from an unexpected origin. Please try again.', 'danger')
        return False
    return True

app.jinja_env.globals['csrf_token'] = csrf_token

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id; self.username = username; self.role = role

# Named-permission RBAC, replacing the old fixed analyst/senior_analyst/admin rank
# ladder -- roles are now rows in the `roles` table (see migrate_role_permissions())
# with an arbitrary set of permission keys from PERMISSION_REGISTRY, so an admin can
# create custom roles instead of being limited to 3 fixed tiers. Grouped to match the
# app's own page/tab boundaries so the admin UI's checkbox matrix reads like the
# product's own navigation. Routes with no permission requirement below stay open to
# any logged-in user, same as before.
PERMISSION_REGISTRY = [
    {'key': 'cases.delete', 'label': 'Delete cases', 'category': 'Cases'},
    {'key': 'cases.queues.manage', 'label': 'Manage case queues', 'category': 'Cases'},
    {'key': 'logsearch.droprules.manage', 'label': 'Manage ingestion drop rules', 'category': 'Log Search'},
    {'key': 'rules.manage', 'label': 'Manage detection rules', 'category': 'Detection Rules'},
    {'key': 'ueba.config.manage', 'label': 'Manage UEBA config & anomaly rules', 'category': 'UEBA'},
    {'key': 'threatintel.manage', 'label': 'Manage TI feeds, entities & enrichment', 'category': 'Threat Intel'},
    {'key': 'edr.command.basic', 'label': 'Queue safe response actions', 'category': 'EDR / Agents'},
    {'key': 'edr.command.advanced', 'label': 'Queue advanced response actions', 'category': 'EDR / Agents'},
    {'key': 'edr.agent.manage', 'label': 'Manage agents (upgrade/uninstall/enroll/channels)', 'category': 'EDR / Agents'},
    {'key': 'edr.fim.manage', 'label': 'Manage File Integrity Monitoring', 'category': 'EDR / Agents'},
    {'key': 'soar.playbooks.manage', 'label': 'Manage SOAR playbooks', 'category': 'SOAR'},
    {'key': 'soar.secrets.manage', 'label': 'Manage playbook secrets', 'category': 'SOAR'},
    {'key': 'assets.manage', 'label': 'Manage assets & identities', 'category': 'Assets & Identity'},
    {'key': 'settings.reports.manage', 'label': 'Manage report branding & schedule', 'category': 'Settings'},
    {'key': 'settings.notifications.manage', 'label': 'Manage alert notification settings', 'category': 'Settings'},
    {'key': 'settings.case_sla.manage', 'label': 'Manage case SLA thresholds', 'category': 'Settings'},
    {'key': 'settings.users.manage', 'label': 'Manage users', 'category': 'Settings'},
    {'key': 'settings.roles.manage', 'label': 'Manage roles & permissions', 'category': 'Settings'},
    {'key': 'settings.network.manage', 'label': 'Manage network bindings & TLS certs', 'category': 'Settings'},
    {'key': 'settings.system.manage', 'label': 'Manage system settings (retention/backup/etc)', 'category': 'Settings'},
    {'key': 'audit.view', 'label': 'View audit log', 'category': 'Settings'},
]
PERMISSION_KEYS = {p['key'] for p in PERMISSION_REGISTRY}
# The two permissions a role must never lose, or an admin could lock the whole
# system out of user/role management with no way back in short of DB surgery --
# pinned onto the built-in 'admin' role specifically, mirroring the existing
# last-admin-delete protection's "never let the system lock itself out" intent.
PINNED_ADMIN_PERMISSIONS = {'settings.roles.manage', 'settings.users.manage'}

def _current_user_permissions():
    # Memoized on flask.g so multiple require_permission()/has_permission() calls
    # within one request only hit the DB once.
    if not hasattr(g, '_perms'):
        rows = get_db().execute(
            "SELECT rp.permission_key FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.slug = ?",
            (current_user.role,)
        ).fetchall()
        g._perms = {r['permission_key'] for r in rows}
    return g._perms

def require_permission(perm_key):
    if perm_key not in _current_user_permissions():
        label = next((p['label'] for p in PERMISSION_REGISTRY if p['key'] == perm_key), perm_key)
        return jsonify({'error': f'Missing permission: {label}'}), 403
    return None

def is_admin():
    # Stand-in for the old "role == 'admin'" check -- true for whichever role(s)
    # currently hold role/permission management, not tied to a specific role slug.
    return 'settings.roles.manage' in _current_user_permissions()

app.jinja_env.globals['has_permission'] = lambda key: key in _current_user_permissions()
app.jinja_env.globals['current_permissions'] = lambda: sorted(_current_user_permissions())

def current_role_label():
    row = get_db().execute("SELECT label FROM roles WHERE slug = ?", (current_user.role,)).fetchone()
    return row['label'] if row else current_user.role
app.jinja_env.globals['current_role_label'] = current_role_label

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if u: return User(u['id'], u['username'], u['role'])
    return None

def get_db():
    db = getattr(g, '_database', None)
    if db is None: db = g._database = sqlite3.connect(DB_PATH, timeout=30); db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_conn(e):
    if hasattr(g, '_database'): g._database.close()

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.cursor().executescript(open(os.path.join(os.path.dirname(__file__), "schema.sql")).read())
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        from werkzeug.security import generate_password_hash
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ('admin', generate_password_hash('changeme123'), 'admin'))
    conn.commit()
    conn.close()

# The only fields a drop rule can actually act on, post-remap -- generate_vector_config()
# and the preview endpoint (api_droprules_preview) both need this exact same list, since
# the preview's whole job is to faithfully predict what the real Vector config would drop.
DROP_RULE_FIELDS = ('app', 'host', 'event_id', 'message')

def generate_vector_config():
    db = get_db()
    rules = db.execute("SELECT * FROM drop_rules WHERE enabled = 1").fetchall()

    cursor = db.execute("SELECT key, value FROM settings")
    s = {row[0]: row[1] for row in cursor.fetchall()}
    ingest_ip = s.get("ingest_bind_ip", "0.0.0.0")
    ingest_port = _resolve_ingest_port(s.get("ui_port", "5001"))
    soc_token = get_soc_secret(db) or ''
    tcp_enabled = s.get("syslog_tcp_enabled") == "1"

    # Drop rules are defined (in the Log Pipeline UI) against live_logs' own field names
    # (app/host/event_id/message), so they're applied AFTER the remap below renames
    # Vector's raw syslog field names (appname/hostname) into that same shape — matching
    # them against the pre-remap names (the previous fmap here) silently matched nothing,
    # since the UI never sends "app_name"/"hostname", only "app"/"host"/"event_id".
    stmts = []
    for r in rules:
        field = r['field'] if r['field'] in DROP_RULE_FIELDS else 'message'
        val = (r['value'] or '').replace('\\', '\\\\').replace('"', '\\"')
        if r['operator'] == 'equals':
            cond = f'(to_string(.{field}) ?? "") == "{val}"'
        else:
            cond = f'contains((to_string(.{field}) ?? ""), "{val}")'
        desc = (r['description'] or '').replace('\n', ' ').replace('\r', ' ')
        stmts.append(f"  # {desc}\n  if {cond} {{ abort }}")
    drop_block = ('\n' + '\n'.join(stmts)) if stmts else ''

    # TCP is purely additive to the always-on UDP listener, not a replacement for it --
    # both bind the same port (514) without conflict since UDP and TCP are independent
    # transport-layer socket types. Opt-in (default off) since it's another open port,
    # toggled from Settings > Network.
    syslog_inputs = ['"syslog_in"']
    tcp_source_block = ""
    if tcp_enabled:
        syslog_inputs.append('"syslog_in_tcp"')
        tcp_source_block = f"""
[sources.syslog_in_tcp]
type = "syslog"
mode = "tcp"
address = "{ingest_ip}:514"
"""

    toml = f"""[api]
enabled = true
address = "127.0.0.1:8686"

# The syslog source below automatically adds a `.source_ip` field to every event --
# the real UDP/TCP peer address, distinct from `.hostname` (the syslog message's own
# self-reported HOSTNAME, used for .host below). shape_logs deliberately never touches
# .source_ip, so it passes through untouched to the app's /api/ingest, which reads it
# as the log's real source IP. Don't "fix" this by adding an explicit assignment here --
# there's nothing missing, this is Vector's own default behavior (verified against the
# installed 0.57.0).
[sources.syslog_in]
type = "syslog"
mode = "udp"
address = "{ingest_ip}:514"
{tcp_source_block}
[transforms.shape_logs]
type = "remap"
inputs = [{", ".join(syslog_inputs)}]
source = '''
  .host = .hostname
  .app = .appname
  .event_id = "-"
  .username = "-"
  .time = to_string(.timestamp) ?? ""
{drop_block}
'''

[sinks.microsoc_out]
type = "http"
inputs = ["shape_logs"]
uri = "https://127.0.0.1:{ingest_port}/api/ingest"
encoding.codec = "json"
tls.verify_certificate = false
auth.strategy = "bearer"
auth.token = "{soc_token}"
"""
    with open("/etc/vector/vector.toml", "w") as f: f.write(toml)
    subprocess.run(["systemctl", "reload", "vector"], check=False)

def _resolve_ingest_port(ui_port):
    # settings.ingest_port only reflects reality while the systemd unit still has the
    # dual --bind that /settings/network's save flow writes — a plain reinstall
    # (install.sh) resets the unit to a single bind on ui_port without resetting that
    # settings row, silently stranding agents on a port nothing listens on (they'd still
    # get told the stale ingest_port on every check-in via the zero-touch routing below).
    # Reading the live unit file is the ground truth for what gunicorn actually bound.
    try:
        with open('/etc/systemd/system/microsoc-web.service', 'r') as f:
            svc = f.read()
        ports = re.findall(r'--bind\s+[^\s:]+:(\d+)', svc)
        if len(ports) >= 2:
            return ports[1]
    except Exception:
        pass
    return ui_port

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf():
            return render_template('login.html')
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (request.form['username'],)).fetchone()
        if user and check_password_hash(user['password_hash'], request.form['password']):
            login_user(User(user['id'], user['username'], user['role']))
            log_audit('login_success', 'user', user['username'])
            return redirect(url_for('home'))
        # current_user is still anonymous here -- target_id records what was *typed*,
        # since that's the only identity available for a failed attempt, and repeated
        # failures against one username/IP is exactly what this is for spotting.
        log_audit('login_failed', 'user', request.form.get('username', ''))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit('logout', 'user', current_user.username)
    logout_user()
    return redirect(url_for('login'))

# Vector's syslog source (confirmed against the installed 0.57.0's own docs) already
# populates a real .source_ip field itself -- the actual UDP/TCP peer address, distinct
# from .hostname (the syslog message's own self-reported HOSTNAME, which is what .host
# comes from) -- and generate_vector_config()'s remap never touches it, so it passes
# through to this endpoint untouched and log.get('source_ip') below picks it up first.
# The Windows/Linux agents, by contrast, never send source_ip at all (Get-WinEvent's
# selection doesn't request a network-address property), so for agent-sourced events
# this falls back to regex-extracting it from Windows Security auth events' own
# human-readable message body (they carry it under this label), and finally to the
# request's own remote address -- which is only trustworthy for genuine direct
# connections (agents); for anything forwarded through Vector's local sink it would
# always read 127.0.0.1, so that specific case is excluded rather than trusted (see
# api_ingest below).
_SOURCE_IP_RE = re.compile(r'Source Network Address:\s*([0-9a-fA-F:.]+)')

def _extract_source_ip(message):
    if not message:
        return None
    m = _SOURCE_IP_RE.search(message)
    if not m:
        return None
    ip = m.group(1).strip()
    return ip if ip and ip != '-' else None

# Per-channel Windows Event ID include/exclude filter, e.g. "4000-5000, 5200" ->
# [(4000,5000), (5200,5200)]. Used both to validate a channel's saved filter_value at
# save time (api_agent_channels) and to build the ready-made PowerShell clause sent to
# the agent (agent_config) -- single source of truth, the agent does no parsing itself.
_EVENT_ID_TOKEN_RE = re.compile(r'^(\d{1,10})(?:-(\d{1,10}))?$')
_EVENT_ID_MAX_TOKENS = 50

def _parse_event_id_ranges(value):
    tokens = [t.strip() for t in (value or '').split(',') if t.strip()]
    if len(tokens) > _EVENT_ID_MAX_TOKENS:
        raise ValueError(f'too many entries (max {_EVENT_ID_MAX_TOKENS})')
    ranges = []
    for t in tokens:
        m = _EVENT_ID_TOKEN_RE.match(t)
        if not m:
            raise ValueError(f"'{t}' is not a valid event ID or range")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if hi < lo:
            raise ValueError(f"'{t}': range start must be <= end")
        ranges.append((lo, hi))
    return ranges

# Numeric -ge/-le comparison (not PowerShell's ".." range-array expansion) so a wide
# range like 1-65535 costs nothing extra at runtime -- no array ever gets built.
def _build_powershell_id_clause(ranges, mode):
    if not ranges or mode not in ('include', 'exclude'):
        return ''
    parts = [f'($_.Id -ge {lo} -and $_.Id -le {hi})' for lo, hi in ranges]
    expr = ' -or '.join(parts)
    return f'-not ({expr})' if mode == 'exclude' else expr

# Custom Windows Event Log channel names are spliced directly into a PowerShell
# -FilterHashtable string (fetch_windows_logs in the Windows agent) with no escaping --
# safe as long as the name can never contain a quote or PS metacharacter. The 6 preset
# channel names have always been safe because they came from hardcoded checkboxes;
# this allowlist is what keeps a free-typed custom channel name equally safe.
_CHANNEL_NAME_RE = re.compile(r'^[A-Za-z0-9 _\-/.]{1,255}$')

# Sysmon (and Security-log equivalents) render process-creation events as one
# "Label: value" pair per line in the human-readable message body -- confirmed against
# real published Sysmon Event ID 1 examples, not a sample from this deployment (none
# exists in this repo). `^[ \t]*Label:` rather than a bare `^Label:` tolerates a leading
# indent some renderers add; `ParentImage:`/`ParentCommandLine:` lines can't false-match
# the bare `Image:`/`CommandLine:` patterns since those lines start with "Parent", not
# "Image"/"Command".
_PROCESS_FIELD_PATTERNS = {
    'process_image': re.compile(r'^[ \t]*Image:\s*(.+)$', re.MULTILINE),
    'command_line': re.compile(r'^[ \t]*CommandLine:\s*(.+)$', re.MULTILINE),
    'parent_image': re.compile(r'^[ \t]*ParentImage:\s*(.+)$', re.MULTILINE),
    'parent_command_line': re.compile(r'^[ \t]*ParentCommandLine:\s*(.+)$', re.MULTILINE),
    'original_file_name': re.compile(r'^[ \t]*OriginalFileName:\s*(.+)$', re.MULTILINE),
    # Sysmon Event ID 1's raw multi-hash string ("MD5=xxx,SHA256=yyy,IMPHASH=zzz") --
    # collapsed to one canonical hash by _canonical_hash() below, not stored as-is.
    'hashes_raw': re.compile(r'^[ \t]*Hashes:\s*(.+)$', re.MULTILINE),
    # Sysmon Event ID 22 (DNS query) -- a bare hostname, not a full URL.
    'query_name': re.compile(r'^[ \t]*QueryName:\s*(.+)$', re.MULTILINE),
}

# "-" and "." both show up as real Sysmon/Windows Event placeholder-for-empty values
# depending on the field/provider (confirmed in production: a rare-process detection
# whose entire displayed process was a bare "." once this got past the old "-"-only
# check) -- neither is a real process identity, so both are rejected the same way.
_PROCESS_FIELD_PLACEHOLDER_VALUES = ('-', '.')

def _extract_process_fields(message):
    if not message:
        return {}
    out = {}
    for col, pattern in _PROCESS_FIELD_PATTERNS.items():
        m = pattern.search(message)
        if m:
            val = m.group(1).strip()  # .strip() drops a trailing \r on CRLF-sourced text
            if val and val not in _PROCESS_FIELD_PLACEHOLDER_VALUES:
                out[col] = val
    return out

# Maps the same 5 target columns as _PROCESS_FIELD_PATTERNS above, but reads them from
# a channel's raw event XML (captured when a channel has "Capture XML" enabled) instead
# of guessing at the rendered Message text -- every <Data Name="..."> is explicit, so
# this is strictly more reliable than the regex extractor whenever it's available.
_XML_PROCESS_FIELD_MAP = {
    'Image': 'process_image',
    'CommandLine': 'command_line',
    'ParentImage': 'parent_image',
    'ParentCommandLine': 'parent_command_line',
    'OriginalFileName': 'original_file_name',
    'Hashes': 'hashes_raw',
    'QueryName': 'query_name',
}

# Sysmon's Hashes field lists every configured algorithm as "ALGO=hex,ALGO=hex,..." --
# collapse to a single canonical value (preferring the strongest/most specific algorithm)
# so IOC-hash correlation has one column to compare against regardless of which
# algorithms a given Sysmon config happens to compute. IMPHASH is deliberately excluded
# from the preference order -- it identifies a compiled import table, not file content,
# so it isn't comparable to the file-content hashes (MD5/SHA1/SHA256) a feed's hash IOCs
# are actually keyed on.
_HASH_PAIR_RE = re.compile(r'\b(MD5|SHA1|SHA256)=([0-9A-Fa-f]{32,64})\b')
_HASH_ALGO_PREFERENCE = ('SHA256', 'SHA1', 'MD5')

def _canonical_hash(hashes_raw):
    if not hashes_raw:
        return None
    found = dict(_HASH_PAIR_RE.findall(hashes_raw))
    for algo in _HASH_ALGO_PREFERENCE:
        if algo in found:
            return found[algo].lower()
    return None

def _extract_process_fields_from_xml(xml_text):
    if not xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    out = {}
    for elem in root.iter():
        # The Windows Event Schema declares a default namespace (xmlns=...) on <Event>,
        # so ElementTree tags come back as "{namespace}Data" -- strip it rather than
        # hardcoding the exact namespace URI, which can vary by provider/OS version.
        tag = elem.tag.split('}', 1)[-1] if '}' in elem.tag else elem.tag
        if tag != 'Data':
            continue
        name = elem.get('Name')
        col = _XML_PROCESS_FIELD_MAP.get(name)
        if not col:
            continue
        val = (elem.text or '').strip()
        if val and val not in _PROCESS_FIELD_PLACEHOLDER_VALUES:
            out[col] = val
    return out

@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    from flask import request, jsonify
    import datetime
    from notifications import notify_if_configured
    try:
        db = get_db()
        expected_token = get_soc_secret(db)
        if expected_token and request.headers.get('Authorization') != f'Bearer {expected_token}':
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

        data = request.get_json()
        # The Windows/Linux agents send {"logs": [...]}, but Vector's http sink (used for
        # syslog ingestion) posts a bare JSON array of events with no wrapper key — accept
        # both instead of only the agent's shape.
        if isinstance(data, list):
            logs = data
        elif isinstance(data, dict) and isinstance(data.get('logs'), list):
            logs = data['logs']
        else:
            return jsonify({'status': 'error', 'message': 'Missing logs payload'}), 400

        count = 0
        for log in logs:
            ts = log.get('time', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            hst = log.get('host', 'UNKNOWN')
            app_n = log.get('app', 'Windows')
            sev = log.get('severity', 'INFO')
            eid = log.get('event_id', '-')
            usr = log.get('username', '-')
            msg = log.get('message', '')
            # Fall back to the IP the ingest request actually came from — an event with no
            # network-address text in its message (most Sysmon/System events) still comes
            # from a real endpoint, and request.remote_addr is that endpoint's address for
            # a genuine direct connection (agents). It's NOT trustworthy for anything
            # forwarded through Vector's local sink, though -- that always reads as
            # 127.0.0.1 (Vector posts to 127.0.0.1:{ingest_port}), so falling back to it
            # there would silently record Vector's own address instead of leaving the
            # field unset. log.get('source_ip') is checked first and already covers the
            # real syslog case (Vector's syslog source populates it natively).
            sip = log.get('source_ip') or _extract_source_ip(msg)
            if not sip and request.remote_addr not in ('127.0.0.1', '::1'):
                sip = request.remote_addr
            raw_xml = log.get('xml') or None
            # XML (when a channel has "Capture XML" enabled) has every field explicitly
            # tagged, so it's strictly more reliable than guessing at the rendered
            # Message text -- prefer it when present and it actually yields something,
            # falling back to the message-regex extractor otherwise (the common case,
            # since XML capture is opt-in per channel).
            proc = _extract_process_fields_from_xml(raw_xml) if raw_xml else {}
            if not proc:
                proc = _extract_process_fields(msg)
            # FIM sends its own computed sha256 as a dedicated field (not embedded in the
            # free-text message, which just reads "File changed: <path>") -- see
            # run_fim_check() in both agent scripts. Falls back to it only when the
            # generic process-hash extraction found nothing, since a real Sysmon-style
            # hash is the more specific signal when both happen to be present.
            fim_sha256 = (log.get('sha256') or '').strip().lower() if app_n == 'FIM' else ''
            file_hash = _canonical_hash(proc.get('hashes_raw')) or (fim_sha256 or None)
            db.execute(
                "INSERT INTO live_logs (timestamp, host, app, severity, event_id, username, source_ip, message, "
                "process_image, command_line, parent_image, parent_command_line, original_file_name, raw_xml, "
                "file_hash, query_name) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, hst, app_n, sev, eid, usr, sip, msg,
                 proc.get('process_image'), proc.get('command_line'), proc.get('parent_image'),
                 proc.get('parent_command_line'), proc.get('original_file_name'), raw_xml,
                 file_hash, proc.get('query_name'))
            )
            count += 1

            # --- INLINE DETECTION ENGINE (fast keyword heuristics; sigma_engine.py runs the real Sigma-rule pipeline) ---
            msg_lower = msg.lower()
            triggered_rule = None
            alert_sev = "INFO"

            # A file FIM just flagged as new/changed, whose hash matches a live
            # threat-intel IOC, is real evidence -- not just "something on disk changed"
            # but "something on disk changed AND it's a known-bad file". Checked ahead of
            # the keyword heuristics below (which a FIM message like "File changed: X"
            # would never match anyway) so this always wins when it fires.
            if fim_sha256 and fim_sha256 in _get_live_ioc_sha256_hashes(db):
                triggered_rule = "Known-Bad Hash Matched via FIM"
                alert_sev = "CRITICAL"
            elif "mimikatz" in msg_lower or "lsass" in msg_lower:
                triggered_rule = "Credential Dumping Activity"
                alert_sev = "CRITICAL"
            elif "powershell" in msg_lower and ("-enc" in msg_lower or "-w hidden" in msg_lower):
                triggered_rule = "Suspicious PowerShell Execution"
                alert_sev = "HIGH"
            elif "whoami" in msg_lower or "net user" in msg_lower or "ipconfig" in msg_lower:
                triggered_rule = "System Discovery Commands"
                alert_sev = "LOW"
                
            if triggered_rule:
                # Collapse a rule re-firing against the same host within a short rolling
                # window into the existing alert row (occurrence_count++, last_seen bumped)
                # instead of inserting a new one every time -- see migrate_alerts_dedup_columns.
                # rule_id IS NULL identifies this heuristic path's own rows (vs sigma_engine.py's
                # rule_id-based alerts), so rule_name is the match key here instead.
                existing = db.execute(
                    "SELECT id FROM alerts WHERE rule_id IS NULL AND rule_name = ? AND host = ? "
                    "AND COALESCE(last_seen, timestamp) >= datetime('now', '-15 minutes') ORDER BY id DESC LIMIT 1",
                    (triggered_rule, hst)
                ).fetchone()
                if existing:
                    db.execute(
                        "UPDATE alerts SET occurrence_count = occurrence_count + 1, last_seen = datetime('now'), message = ?, severity = ? WHERE id = ?",
                        (msg, alert_sev, existing['id'])
                    )
                else:
                    from geoip import lookup_country
                    country_code, country_name = lookup_country(sip)
                    db.execute(
                        "INSERT INTO alerts (timestamp, rule_name, severity, host, message, username, source_ip, occurrence_count, last_seen, country_code, country_name) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                        (ts, triggered_rule, alert_sev, hst, msg, usr, sip, ts, country_code, country_name)
                    )
                    # Same "only a brand-new alert notifies" rule as sigma_engine.py's path --
                    # a re-firing heuristic within the dedup window hits the `existing` branch
                    # above instead. This runs inline in the ingest request; notify_if_configured
                    # is a fast local settings lookup + a couple of short-timeout network calls
                    # at most, never raises, and only fires at all if an admin has actually
                    # configured a channel -- negligible added latency for the common case.
                    notify_if_configured(db, {
                        'rule_title': triggered_rule, 'severity': alert_sev, 'host': hst,
                        'username': usr, 'source_ip': sip, 'message': msg, 'timestamp': ts,
                    })
            # -------------------------------
        db.commit()
        return jsonify({'status': 'success', 'ingested': count}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/siem')
@login_required
def dash():
    active_tab = request.args.get('tab', 'search')
    return render_template('dashboard.html', active_tab=active_tab, current_user=current_user,
                            compliance_frameworks=COMPLIANCE_FRAMEWORKS, log_search_allowed_fields=LOG_SEARCH_ALLOWED_FIELDS)

# Home count queries reuse existing canonical data sources rather than new bookkeeping:
# ueba_entity_baselines is already this app's registry of every host/user the UEBA
# model tracks (Anomaly Detections tab and Data Insights already treat it that way).
@app.route('/')
@login_required
def home():
    # Home was merged into Dashboards -- kept as a route (rather than removed) so
    # url_for('home') call sites and any bookmarked '/' links keep working.
    return redirect(url_for('dashboards_page'))

@app.route('/api/home/stats')
@login_required
def api_home_stats():
    db = get_db()
    hosts_tracked = db.execute("SELECT COUNT(*) FROM ueba_entity_baselines WHERE entity_type = 'host'").fetchone()[0]
    users_tracked = db.execute("SELECT COUNT(*) FROM ueba_entity_baselines WHERE entity_type = 'user'").fetchone()[0]
    # "today" = calendar day (not a rolling 24h window), matching how the UEBA Timeline
    # tab's own stat tiles count "today" so the two pages never disagree.
    events_today = db.execute("SELECT COUNT(*) FROM live_logs WHERE date(timestamp) = date('now')").fetchone()[0]
    alerts_unacknowledged = db.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0]
    anomalies_today = db.execute(
        "SELECT COUNT(*) FROM events WHERE app_name = 'duckdb_ueba' AND date(timestamp) = date('now')"
    ).fetchone()[0]
    return jsonify({
        'hosts_tracked': hosts_tracked, 'users_tracked': users_tracked,
        'events_today': events_today, 'alerts_unacknowledged': alerts_unacknowledged,
        'anomalies_today': anomalies_today,
    })

@app.route('/rules')
@login_required
def rules():
    rule_id = request.args.get('rule_id')
    return redirect(url_for('dash', tab='rules', rule_id=rule_id) if rule_id else url_for('dash', tab='rules'))

@app.route('/rules/tuning')
@login_required
def detection_tuning(): return redirect(url_for('dash', tab='tuning'))

@app.route('/pipeline')
@login_required
def pipeline(): return redirect(url_for('dash', tab='pipeline'))

@app.route('/agents')
@login_required
def agents():
    db = get_db()
    s = {r[0]: r[1] for r in db.execute("SELECT key, value FROM settings").fetchall()}
    return render_template('agents.html', soc_token=s.get('soc_secret', ''), current_user=current_user)

@app.route('/dashboards')
@login_required
def dashboards_page():
    row = get_db().execute("SELECT default_dashboard_id FROM roles WHERE slug = ?", (current_user.role,)).fetchone()
    role_default_dashboard_id = row['default_dashboard_id'] if row else None
    return render_template('dashboards.html', current_user=current_user, role_default_dashboard_id=role_default_dashboard_id)

# Placeholder nav entry -- the SOAR *backend* already exists and runs today
# (microsoc-soar.service / src/soar_engine.py, a separate FastAPI process that
# receives high-severity Sigma alerts via webhook and acknowledges them), but has
# never had any UI. This just gives it a page to land on; no playbook management is
# wired up yet, matching the same "tab exists, marked coming soon" pattern already
# used for UEBA's Timeline tab.
@app.route('/soar')
@login_required
def soar_page():
    return render_template('soar.html', current_user=current_user)

@app.route('/cases')
@login_required
def cases_page():
    return render_template('cases.html', current_user=current_user)

# The triage lifecycle sits alongside (not instead of) the older binary `acknowledged`
# flag -- see migrate_alerts_triage(). 'new' is the schema DEFAULT so every alert starts
# here with no extra write needed.
ALERT_STATUSES = ('new', 'investigating', 'resolved', 'false_positive')

@app.route('/api/alerts')
@login_required
def api_alerts():
    db = get_db()
    limit = request.args.get('limit', 30, type=int)
    try:
        rows = db.execute("""
            SELECT a.id, a.timestamp, a.severity, a.acknowledged, a.status, a.assignee,
                   a.rule_id, a.username, a.source_ip, a.destination_ip,
                   a.occurrence_count, a.last_seen,
                   COALESCE(s.title, a.rule_name, 'YARA / Custom Rule Match') as rule_title,
                   COALESCE(l.message, a.message) as event_message,
                   COALESCE(l.host, a.host) as hostname
            FROM alerts a
            LEFT JOIN sigma_rules s ON a.rule_id = s.id
            LEFT JOIN live_logs l ON a.event_id = l.id
            ORDER BY a.id DESC LIMIT ?
        """, (limit,)).fetchall()
        alerts = [dict(row) for row in rows]
    except Exception:
        alerts = []
    return jsonify(alerts)

@app.route('/api/alerts/<int:aid>', methods=['PUT'])
@login_required
def api_alert_update(aid):
    # Any logged-in user can triage -- alert triage is an analyst task, matching every
    # other alert-facing route (viewing/exporting/case-linking), none of which are
    # admin-gated either. Each of acknowledged/status/assignee is optional and independent
    # -- a caller updates only what it means to change, no cross-field inference here (the
    # Home widget's quick-acknowledge button sets both acknowledged AND status explicitly
    # at the call site instead, so the "keep them in sync" behavior is visible there, not
    # hidden as magic in this route).
    db = get_db()
    if not db.execute("SELECT 1 FROM alerts WHERE id = ?", (aid,)).fetchone():
        return jsonify({"error": "Alert not found"}), 404
    data = request.get_json() or {}
    if not any(k in data for k in ('acknowledged', 'status', 'assignee')):
        return jsonify({"error": "at least one of acknowledged/status/assignee is required"}), 400

    if 'status' in data and data['status'] not in ALERT_STATUSES:
        return jsonify({"error": f"status must be one of {', '.join(ALERT_STATUSES)}"}), 400

    if 'acknowledged' in data:
        acked = 1 if data.get('acknowledged') else 0
        db.execute("UPDATE alerts SET acknowledged = ? WHERE id = ?", (acked, aid))
        log_audit('alert_acknowledge' if acked else 'alert_unacknowledge', 'alert', aid)
    if 'status' in data:
        db.execute("UPDATE alerts SET status = ? WHERE id = ?", (data['status'], aid))
        log_audit('alert_status_change', 'alert', aid, data['status'])
    if 'assignee' in data:
        assignee = (data.get('assignee') or '').strip() or None
        db.execute("UPDATE alerts SET assignee = ? WHERE id = ?", (assignee, aid))
        log_audit('alert_assign', 'alert', aid, assignee or '(unassigned)')
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/events')
@login_required
def api_ev(): return jsonify([dict(r) for r in get_db().execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (request.args.get('limit', 50, type=int),)).fetchall()])


# ==========================================
# THREAT HUNT & YARA SCANNER
# ==========================================
@app.route('/hunt')
@login_required
def hunt():
    # Threat Hunt is now a tab on the Threat Intel & Hunting page, not its own route —
    # the scan form posts directly to /threat-intel. This only exists to redirect old
    # bookmarks/links straight to the right tab instead of 404ing.
    return redirect(url_for('threat_intel', tab='hunt'))

@app.route('/api/hunt/search')
@login_required
def api_hunt():
    q = f"%{request.args.get('q', '')}%"
    return jsonify([dict(r) for r in get_db().execute("SELECT * FROM events WHERE message LIKE ? OR app_name LIKE ? OR source_ip LIKE ? ORDER BY timestamp DESC LIMIT 100", (q,q,q)).fetchall()])

@app.route('/api/ti/lookup', methods=['POST'])
@login_required
def api_ti_lookup():
    # Previously called ti_engine.py's lookup_ioc(), which hit ThreatFox's LIVE API on
    # every request with no caching, no rate limiting, and no UI ever actually called
    # it (confirmed dead code -- ti_engine.py has been deleted). An exact-match lookup
    # against the local IOC set (now ~130K+ real indicators post-MISP-feed-sync, see
    # the CTI gap-analysis Tier 1 work) plus sighting history is strictly more useful:
    # instant, works offline, and tells you whether this value has actually been
    # OBSERVED here, not just whether some feed once flagged it.
    body = request.get_json() or {}
    ioc = (body.get('ioc') or '').strip()
    feed_id = body.get('feed_id')  # optional: scope the match to one specific feed source
    if not ioc:
        return jsonify({'status': 'error', 'message': 'No IOC value provided'}), 400
    db = get_db()
    where = "WHERE LOWER(si.pattern) = LOWER(?)"
    params = [ioc]
    if feed_id:
        where += " AND si.feed_id = ?"
        params.append(feed_id)
    rows = db.execute(
        "SELECT si.stix_id, si.ioc_type, si.name, si.description, si.revoked, si.feed_id, tf.name as source_name, "
        "(SELECT COUNT(*) FROM ioc_sightings s WHERE s.stix_id = si.stix_id) as sighting_count, "
        "(SELECT MAX(seen_at) FROM ioc_sightings s WHERE s.stix_id = si.stix_id) as last_sighted "
        f"FROM stix_indicators si LEFT JOIN ti_feeds tf ON si.feed_id = tf.id {where}",
        params
    ).fetchall()
    if not rows:
        return jsonify({'status': 'clean', 'message': 'No match in the local Threat Intel IOC set.'})
    matches = [dict(r) for r in rows]
    active = [m for m in matches if not m['revoked']]
    if not active:
        return jsonify({'status': 'revoked', 'message': 'Matches only revoked/inactive IOC(s).', 'matches': matches})
    # Cross-feed corroboration: how many DISTINCT active feeds independently reported
    # this exact value -- every active row already fetched above, so no extra query.
    corroboration_count = len({m['feed_id'] for m in active if m['feed_id'] is not None})
    return jsonify({'status': 'malicious', 'matches': matches, 'corroboration_count': corroboration_count})

_ENRICHMENT_KEY_PLACEHOLDER = '••••••••'

@app.route('/api/ti/analyzers', methods=['GET'])
@login_required
def api_ti_analyzers():
    # Lists the live on-demand enrichment sources (analyzers.py's ANALYZERS) -- a
    # different mechanism from ti_feeds (synced IOC lists): these run one query per
    # lookup, nothing is bulk-synced into stix_indicators. Surfaced so Quick IOC
    # Lookup's source picker and the Feed Sources tab's Live Enrichment Sources list
    # can both show "is this one configured" without duplicating the key-lookup logic.
    from analyzers import ANALYZERS
    db = get_db()
    key_row = db.execute("SELECT value FROM settings WHERE key = 'enrichment_api_keys'").fetchone()
    api_keys = json.loads(key_row['value']) if key_row and key_row['value'] else {}
    return jsonify([{
        'key': a['key'], 'label': a['label'], 'ioc_types': list(a['ioc_types']),
        'requires_key': a['requires_key'],
        'configured': (not a['requires_key']) or bool(api_keys.get(a['settings_key'])),
    } for a in ANALYZERS])

@app.route('/api/settings/enrichment', methods=['GET', 'POST'])
@login_required
def api_enrichment_settings():
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = 'enrichment_api_keys'").fetchone()
    keys = json.loads(row['value']) if row and row['value'] else {}
    if request.method == 'GET':
        # Never echo a real key back to the browser -- same masked-placeholder pattern
        # as the alert-notifications SMTP password.
        return jsonify({'abuseipdb_api_key': _ENRICHMENT_KEY_PLACEHOLDER if keys.get('abuseipdb_api_key') else ''})
    err = require_permission('threatintel.manage')
    if err: return err
    d = request.json or {}
    new_key = d.get('abuseipdb_api_key')
    if new_key is not None and new_key != _ENRICHMENT_KEY_PLACEHOLDER:
        keys['abuseipdb_api_key'] = new_key
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('enrichment_api_keys', ?)", (json.dumps(keys),))
    db.commit()
    log_audit('enrichment_settings_change', 'settings', None, 'abuseipdb_api_key ' + ('set' if keys.get('abuseipdb_api_key') else 'cleared'))
    return jsonify({'status': 'success'})

@app.route('/api/ti/enrich', methods=['POST'])
@login_required
def api_ti_enrich():
    from analyzers import applicable_analyzers, ENRICHMENT_CACHE_TTL_HOURS
    d = request.get_json() or {}
    value = (d.get('value') or '').strip()
    ioc_type = (d.get('ioc_type') or '').strip()
    source = (d.get('source') or '').strip()  # optional: run just this one analyzer (Quick Lookup's source picker)
    if not value:
        return jsonify({'error': 'value is required'}), 400
    analyzers = applicable_analyzers(ioc_type)
    if source:
        analyzers = [a for a in analyzers if a['key'] == source]
    if not analyzers:
        msg = f'"{source}" does not apply to type "{ioc_type or "unknown"}".' if source else \
              f'No enrichment analyzers apply to type "{ioc_type or "unknown"}" yet.'
        return jsonify({'results': [], 'message': msg})

    db = get_db()
    key_row = db.execute("SELECT value FROM settings WHERE key = 'enrichment_api_keys'").fetchone()
    api_keys = json.loads(key_row['value']) if key_row and key_row['value'] else {}

    results = []
    for a in analyzers:
        cached = db.execute(
            "SELECT verdict, summary, fetched_at FROM enrichment_results WHERE value = ? AND source = ? "
            "AND fetched_at >= datetime('now', ?)",
            (value, a['key'], f'-{ENRICHMENT_CACHE_TTL_HOURS} hours')
        ).fetchone()
        if cached:
            results.append({'source': a['label'], 'verdict': cached['verdict'], 'summary': cached['summary'],
                             'cached': True, 'fetched_at': cached['fetched_at']})
            continue
        api_key = api_keys.get(a['settings_key']) if a.get('requires_key') else None
        out = a['run'](value, api_key)
        db.execute(
            "INSERT INTO enrichment_results (value, source, verdict, summary, raw_json, fetched_at) VALUES (?, ?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(value, source) DO UPDATE SET verdict=excluded.verdict, summary=excluded.summary, raw_json=excluded.raw_json, fetched_at=excluded.fetched_at",
            (value, a['key'], out['verdict'], out['summary'], json.dumps(out.get('raw') or {}))
        )
        db.commit()
        results.append({'source': a['label'], 'verdict': out['verdict'], 'summary': out['summary'], 'cached': False})
    return jsonify({'results': results})


# ==========================================
# THREAT INTELLIGENCE — FEEDS & IOCS
# ==========================================
YARA_RULES_DIR = '/opt/micro-dfir/rules/yara_imported'

# Best-effort extraction, not a real YARA parser -- just the first `description = "..."`
# meta field in the file (a file can define multiple `rule` blocks; the first one's
# description is representative enough for a one-line UI hint). Community rulesets
# consistently populate this field (spot-checked: ~80% of files under rules-master/).
_YARA_DESCRIPTION_RE = re.compile(r'description\s*=\s*"((?:[^"\\]|\\.)*)"')
_YARA_AUTHOR_RE = re.compile(r'author\s*=\s*"((?:[^"\\]|\\.)*)"')

def _yara_file_description(full_path):
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None
    m = _YARA_DESCRIPTION_RE.search(content)
    if not m:
        return None
    desc = m.group(1).replace('\\"', '"').strip()
    if not desc:
        return None
    a = _YARA_AUTHOR_RE.search(content)
    author = a.group(1).replace('\\"', '"').strip() if a else None
    return f"{desc} (by {author})" if author else desc

@app.route('/threat-intel', methods=['GET', 'POST'])
@login_required
def threat_intel():
    import os
    from flask import request, flash

    active_tab = request.args.get('tab', 'iocs')
    matches = []
    yara_files = []
    yara_available = True
    try:
        import yara
    except ImportError:
        yara_available = False
        if request.method == 'POST':
            flash("yara-python is missing. Run: pip install yara-python", "danger")

    # Fetch loaded YARA files for the UI checklist first — this is also the
    # allowlist for which rule paths a scan request may reference.
    yara_dir = YARA_RULES_DIR
    if os.path.exists(yara_dir):
        for root, dirs, files in os.walk(yara_dir):
            for file_name in files:
                if file_name.endswith(('.yar', '.yara')):
                    yara_files.append(os.path.relpath(os.path.join(root, file_name), yara_dir))
    yara_files.sort()
    yara_files_set = set(yara_files)
    # Grouped purely for display (identify where the rules came from) -- the flat
    # yara_files list above stays the actual POST-time validation allowlist. Category
    # is each file's IMMEDIATE parent directory, not the first path segment -- the
    # real category dirs (malware/, webshells/, crypto/, etc, each a checkout of the
    # community Yara-Rules/rules project) sit one level deeper than yara_dir, under a
    # rules-master/ wrapper (confirmed on disk: yara_dir also has a sibling
    # yaraify_synced/ for feed-synced rules, so segment[0] alone would lump everything
    # from either source into one bucket). Files with no parent dir at all fall back
    # to 'Other'.
    yara_files_by_category = {}
    yara_file_descriptions = {}
    for rf in yara_files:
        parts = rf.split(os.sep)
        category = parts[-2] if len(parts) > 1 else 'Other'
        yara_files_by_category.setdefault(category, []).append(rf)
        desc = _yara_file_description(os.path.join(yara_dir, rf))
        if desc:
            yara_file_descriptions[rf] = desc

    if request.method == 'POST' and yara_available:
        active_tab = 'hunt'
        if not validate_csrf():
            pass
        elif 'scan_file' not in request.files:
            flash("No file uploaded", "danger")
        else:
            file = request.files['scan_file']
            # Only accept rule paths that are actually in the discovered allowlist —
            # prevents path traversal via arbitrary values in selected_rules.
            selected_rules = [r for r in request.form.getlist('selected_rules') if r in yara_files_set]

            if file.filename == '':
                flash("No file selected for scanning.", "danger")
            elif not selected_rules:
                flash("You must select at least one valid YARA rule to run the scan.", "warning")
            else:
                file_data = file.read()
                compiled_rules = 0

                # Scan against ONLY the explicitly selected files
                for rule_file in selected_rules:
                    full_path = os.path.join(yara_dir, rule_file)
                    try:
                        rule = yara.compile(filepath=full_path)
                        compiled_rules += 1
                        rule_matches = rule.match(data=file_data)
                        for m in rule_matches:
                            matches.append({"rule": m.rule, "file": file.filename})
                    except Exception:
                        pass # Skip broken community rules

                if compiled_rules == 0:
                    flash("None of the selected YARA rules were valid or compiled successfully.", "warning")
                else:
                    flash(f"Scanned {file.filename} against {compiled_rules} active rules.", "info")

    return render_template(
        'threat_intel.html', matches=matches, yara_files=yara_files,
        yara_files_by_category=yara_files_by_category, yara_file_descriptions=yara_file_descriptions,
        active_tab=active_tab, current_user=current_user
    )

TI_FEED_TYPES = ('taxii', 'threatfox', 'otx', 'urlhaus', 'feodotracker', 'yaraify', 'misp', 'sslbl', 'spamhaus_drop', 'tor_exit', 'malwarebazaar', 'csv')

_CSV_VALUE_COLS = ('value', 'indicator', 'ioc', 'pattern', 'ip', 'url', 'domain', 'hash', 'ioc_value')
_CSV_TYPE_COLS = ('type', 'ioc_type')
_CSV_NAME_COLS = ('name', 'description', 'desc', 'notes')
_CSV_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_CSV_HASH_RE = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
_SHA256_HEX_RE = re.compile(r'^[a-fA-F0-9]{64}$')
_MD5_HEX_RE = re.compile(r'^[a-fA-F0-9]{32}$')
_SHA1_HEX_RE = re.compile(r'^[a-fA-F0-9]{40}$')
_CSV_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')

def _guess_csv_ioc_type(value):
    v = value.strip()
    if _CSV_IPV4_RE.match(v):
        return 'ip'
    if v.lower().startswith(('http://', 'https://')):
        return 'url'
    if _CSV_HASH_RE.match(v):
        return {32: 'md5', 40: 'sha1', 64: 'sha256'}[len(v)]
    if _CSV_DOMAIN_RE.match(v):
        return 'domain'
    return 'other'

def _guess_legacy_ioc_type(pattern):
    p = (pattern or '').strip()
    if not p:
        return 'other'
    if p.startswith('['):
        # A raw generic-TAXII STIX pattern, e.g. "[domain-name:value = 'x']" — pull the
        # leading object-type token the same way taxii_client._guess_stix_pattern_type does.
        m = re.match(r'\[\s*([a-zA-Z0-9\-]+):', p)
        return m.group(1) if m else 'stix-pattern'
    if not p.lower().startswith(('http://', 'https://')):
        p = re.sub(r':\d+$', '', p)  # strip a ThreatFox-style "ip:port" suffix
    return _guess_csv_ioc_type(p)

def _parse_csv_iocs(text):
    import csv, io
    reader = csv.DictReader(io.StringIO(text))
    # DictReader keys preserve the header's original casing/spacing; match against a
    # lowercased copy so "IP Address" and "ip" both resolve the same column.
    orig_by_lower = {(h or '').strip().lower(): h for h in (reader.fieldnames or [])}
    value_col = next((h for h in _CSV_VALUE_COLS if h in orig_by_lower), None)

    results = []
    if value_col:
        type_col = next((h for h in _CSV_TYPE_COLS if h in orig_by_lower), None)
        name_col = next((h for h in _CSV_NAME_COLS if h in orig_by_lower), None)
        for row in reader:
            raw_val = (row.get(orig_by_lower[value_col]) or '').strip()
            if not raw_val:
                continue
            ioc_type = (row.get(orig_by_lower[type_col]) or '').strip().lower() if type_col else ''
            name = (row.get(orig_by_lower[name_col]) or '').strip() if name_col else ''
            results.append({'value': raw_val, 'ioc_type': ioc_type or _guess_csv_ioc_type(raw_val), 'name': name})
    else:
        # No recognizable header — treat the file as one bare IOC value per line (this
        # also covers a genuinely headerless file, since re-reading from the start below
        # includes what would otherwise have been silently consumed as a header row).
        for row in csv.reader(io.StringIO(text)):
            if not row:
                continue
            raw_val = row[0].strip()
            if raw_val:
                results.append({'value': raw_val, 'ioc_type': _guess_csv_ioc_type(raw_val), 'name': ''})
    return results

def _parse_sync_interval(d):
    val = d.get('sync_interval_minutes')
    try:
        val = int(val)
    except (TypeError, ValueError):
        return None
    return val if val > 0 else None

@app.route('/api/ti/feeds', methods=['GET', 'POST'])
@login_required
def api_ti_feeds():
    db = get_db()
    if request.method == 'GET':
        # api_key itself is never sent to the browser (same as password) — has_api_key
        # tells the UI whether one's already configured without exposing the secret.
        rows = db.execute(
            "SELECT id, name, feed_type, discovery_url, collection_id, username, "
            "(api_key IS NOT NULL AND api_key != '') AS has_api_key, sync_interval_minutes, "
            "enabled, last_sync, last_status, last_count FROM ti_feeds ORDER BY id DESC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    err = require_permission('threatintel.manage')
    if err: return err
    d = request.json or {}
    name = (d.get('name') or '').strip()
    feed_type = d.get('feed_type')
    if not name or feed_type not in TI_FEED_TYPES:
        return jsonify({'error': f'name and a valid feed_type ({"/".join(TI_FEED_TYPES)}) are required'}), 400
    if feed_type == 'csv':
        return jsonify({'error': 'CSV feeds are created by uploading a file — use the CSV upload option instead'}), 400
    if feed_type == 'taxii' and not (d.get('discovery_url') and d.get('collection_id')):
        return jsonify({'error': 'TAXII feeds require a discovery_url and collection_id'}), 400
    if feed_type == 'otx' and not d.get('api_key'):
        return jsonify({'error': 'OTX feeds require an API key'}), 400
    if feed_type == 'malwarebazaar' and not d.get('api_key'):
        return jsonify({'error': 'MalwareBazaar now requires a free Auth-Key (get one at https://auth.abuse.ch/)'}), 400
    if feed_type == 'misp' and not d.get('discovery_url'):
        return jsonify({'error': 'MISP feeds require a feed base URL (the directory containing manifest.json)'}), 400
    db.execute(
        "INSERT INTO ti_feeds (name, feed_type, discovery_url, collection_id, username, password, api_key, sync_interval_minutes, enabled) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
        (name, feed_type, d.get('discovery_url', ''), d.get('collection_id', ''), d.get('username', ''),
         d.get('password', ''), d.get('api_key', ''), _parse_sync_interval(d))
    )
    db.commit()
    log_audit('ti_feed_create', 'ti_feed', name, f'feed_type={feed_type}')
    return jsonify({'status': 'success'})

@app.route('/api/ti/feeds/<int:fid>', methods=['PUT', 'DELETE'])
@login_required
def api_ti_feed_detail(fid):
    err = require_permission('threatintel.manage')
    if err: return err
    db = get_db()
    if request.method == 'DELETE':
        feed_row = db.execute("SELECT name FROM ti_feeds WHERE id = ?", (fid,)).fetchone()
        db.execute("DELETE FROM ti_feeds WHERE id = ?", (fid,))
        db.commit()
        log_audit('ti_feed_delete', 'ti_feed', feed_row['name'] if feed_row else fid)
        return jsonify({'ok': 1})

    d = request.json or {}
    # Blank password/api_key means "keep the existing one" rather than clearing it --
    # never log the actual secret value, only that the feed config was edited.
    db.execute(
        "UPDATE ti_feeds SET name=?, discovery_url=?, collection_id=?, username=?, "
        "password=COALESCE(NULLIF(?, ''), password), api_key=COALESCE(NULLIF(?, ''), api_key), "
        "sync_interval_minutes=?, enabled=? WHERE id=?",
        (d.get('name', ''), d.get('discovery_url', ''), d.get('collection_id', ''),
         d.get('username', ''), d.get('password', ''), d.get('api_key', ''),
         _parse_sync_interval(d), 1 if d.get('enabled') else 0, fid)
    )
    db.commit()
    log_audit('ti_feed_update', 'ti_feed', d.get('name', fid))
    return jsonify({'status': 'success'})

@app.route('/api/ti/feeds/<int:fid>/sync', methods=['POST'])
@login_required
def api_ti_feed_sync(fid):
    err = require_permission('threatintel.manage')
    if err: return err
    result = ti_sync_one(fid)
    log_audit('ti_feed_sync', 'ti_feed', fid, str(result.get('count', result.get('message', ''))))
    return jsonify(result), (200 if result.get('status') == 'success' else 502)

@app.route('/api/ti/feeds/upload_csv', methods=['POST'])
@login_required
def api_ti_feeds_upload_csv():
    err = require_permission('threatintel.manage')
    if err: return err
    if not validate_csrf():
        return jsonify({'error': 'Your session expired or the form was submitted from an unexpected origin. Please refresh and try again.'}), 400

    name = (request.form.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'A feed name is required'}), 400
    f = request.files.get('csv_file')
    if not f or not f.filename:
        return jsonify({'error': 'A CSV file is required'}), 400
    if not f.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Only .csv files are supported'}), 400

    raw = f.read(5 * 1024 * 1024 + 1)  # cap at 5MB; the +1 lets us detect an oversized file below
    if len(raw) > 5 * 1024 * 1024:
        return jsonify({'error': 'CSV file is too large (5MB max)'}), 400
    try:
        text = raw.decode('utf-8-sig', errors='replace')
    except Exception:
        return jsonify({'error': 'Could not read the file as text'}), 400

    iocs = _parse_csv_iocs(text)
    if not iocs:
        return jsonify({'error': 'No IOC values found in the CSV (expected a value/indicator/ioc column, or one IOC per line)'}), 400
    if len(iocs) > 50000:
        return jsonify({'error': f'CSV has {len(iocs)} rows; the limit is 50,000 per upload'}), 400

    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    cur = db.execute(
        "INSERT INTO ti_feeds (name, feed_type, discovery_url, collection_id, username, password, api_key, "
        "sync_interval_minutes, enabled, last_sync, last_status, last_count) "
        "VALUES (?, 'csv', '', '', '', '', '', NULL, 1, ?, 'success', ?)",
        (name, now, len(iocs))
    )
    feed_id = cur.lastrowid
    db.executemany(
        "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) "
        "VALUES (?, 'indicator', ?, ?, '', ?, ?, 0, ?)",
        [(f"csv--{feed_id}--{i}", ioc['ioc_type'], ioc['name'] or ioc['value'], ioc['value'], now, feed_id)
         for i, ioc in enumerate(iocs)]
    )
    db.commit()
    return jsonify({'status': 'success', 'feed_id': feed_id, 'count': len(iocs)})

@app.route('/api/ti/iocs', methods=['GET'])
@login_required
def api_ti_iocs():
    db = get_db()
    q = request.args.get('q', '').strip()
    limit = request.args.get('limit', 100, type=int)
    ioc_types = [t for t in request.args.get('type', '').split(',') if t]
    feed_ids = [f for f in request.args.get('feed_id', '').split(',') if f]
    statuses = [s for s in request.args.get('status', '').split(',') if s in ('0', '1')]
    sightings_vals = [s for s in request.args.get('sightings', '').split(',') if s in ('has', 'none')]

    # Aliased (si/tf) since this joins against ti_feeds to resolve each indicator's
    # source feed name — stix_indicators only ever stored a feed_id, never a name.
    conditions, params = [], []
    if q:
        conditions.append("(si.pattern LIKE ? OR si.name LIKE ? OR si.stix_id LIKE ?)")
        params.extend([f'%{q}%'] * 3)
    if ioc_types:
        conditions.append(f"si.ioc_type IN ({','.join('?' * len(ioc_types))})")
        params.extend(ioc_types)
    if feed_ids:
        conditions.append(f"si.feed_id IN ({','.join('?' * len(feed_ids))})")
        params.extend(feed_ids)
    if statuses:
        conditions.append(f"si.revoked IN ({','.join('?' * len(statuses))})")
        params.extend(statuses)
    # sighting_count is a computed subquery column, not a real one -- can't IN()-filter
    # it directly, so this only applies when exactly one of has/none is picked (both
    # selected naturally degrades to "no filter", same as selecting every option in any
    # of the other checkbox filters above already does).
    if len(sightings_vals) == 1:
        exists_clause = "EXISTS (SELECT 1 FROM ioc_sightings s WHERE s.stix_id = si.stix_id)"
        conditions.append(exists_clause if sightings_vals[0] == 'has' else f"NOT {exists_clause}")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = db.execute(
        f"SELECT si.stix_id, si.type, si.ioc_type, si.name, si.description, si.pattern, si.valid_from, si.revoked, "
        f"si.inserted_at, si.feed_id, tf.name AS source_name, "
        f"(SELECT COUNT(*) FROM ioc_sightings s WHERE s.stix_id = si.stix_id) AS sighting_count, "
        f"(SELECT MAX(seen_at) FROM ioc_sightings s WHERE s.stix_id = si.stix_id) AS last_sighted, "
        # Cross-feed corroboration, computed at read time rather than merged/deduped at
        # write time -- each feed's own row (and its own provenance: name/description/
        # feed_id) stays intact, but a value independently reported by more than one feed
        # is a real confidence signal worth surfacing. Uses the same idx_stix_pattern
        # index the q= search above already relies on, so this stays cheap per row.
        f"(SELECT COUNT(DISTINCT feed_id) FROM stix_indicators si2 WHERE si2.pattern = si.pattern AND si2.revoked = 0) AS corroboration_count "
        f"FROM stix_indicators si "
        f"LEFT JOIN ti_feeds tf ON si.feed_id = tf.id {where} ORDER BY si.inserted_at DESC LIMIT ?",
        params + [limit]
    ).fetchall()
    total = db.execute(f"SELECT COUNT(*) FROM stix_indicators si {where}", params).fetchone()[0]
    return jsonify({'iocs': [dict(r) for r in rows], 'total': total})

def _entity_row_to_dict(r):
    """ti_entities stores aliases/techniques comma-separated (same shape
    compliance_tags already uses on sigma_rules) -- parse back to lists for every
    in-Python consumer (matching index, JSON API, mitre_attack lookups)."""
    d = dict(r)
    d['aliases'] = [a for a in (d.get('aliases') or '').split(',') if a]
    d['techniques'] = [t for t in (d.get('techniques') or '').split(',') if t]
    return d

def _get_ti_entities(db):
    return [_entity_row_to_dict(r) for r in db.execute(
        "SELECT id, entity_type, name, aliases, description, techniques, source, confidence, attribution_note, external_references, "
        "(SELECT COUNT(*) FROM ti_relationships WHERE entity_id = ti_entities.id) as linked_count "
        "FROM ti_entities ORDER BY name"
    ).fetchall()]

def _build_actor_summary(rows, entities):
    """Cross-references IOC (name, description, stix_id) rows against the DB-backed
    entity set (ti_entities, seeded from src/threat_actors.py's curated ACTORS list
    but now admin-editable) -- purely informational, surfaced next to the MITRE
    coverage heatmap so an analyst can see which known actors the currently-synced
    feed data implicates and which techniques they're commonly associated with.
    `rows` is any iterable of objects with ['name']/['description']/['stix_id'] keys
    (a sqlite3.Row list or plain dicts); `entities` is the list _get_ti_entities()
    returns. `stix_ids` on each returned entry is consumed by the caller
    (api_ti_actor_summary) to look up real ioc_sightings against just this actor's
    matched IOCs, then stripped before the response is sent -- it's an internal
    join key, not something the frontend needs."""
    from threat_actors import build_index, find_entity_context
    from mitre_attack import lookup as mitre_lookup, TACTIC_LABELS

    index = build_index(entities)
    matched = {}  # entity name -> {entity, ioc_count, stix_ids}
    for r in rows:
        entity = find_entity_context(r['name'], index) or find_entity_context(r['description'], index)
        if not entity:
            continue
        entry = matched.setdefault(entity['name'], {'entity': entity, 'ioc_count': 0, 'stix_ids': set()})
        entry['ioc_count'] += 1
        if r['stix_id']:
            entry['stix_ids'].add(r['stix_id'])

    out = []
    for name, entry in matched.items():
        entity = entry['entity']
        techniques = []
        for tid in entity['techniques']:
            tname, tactic = mitre_lookup(tid)
            techniques.append({'id': tid, 'name': tname, 'tactic': tactic, 'tactic_label': TACTIC_LABELS.get(tactic, tactic)})
        out.append({
            'id': entity.get('id'), 'name': name, 'aliases': entity['aliases'], 'type': entity['entity_type'],
            'description': entity['description'], 'ioc_count': entry['ioc_count'],
            'techniques': techniques, 'stix_ids': sorted(entry['stix_ids']),
        })
    out.sort(key=lambda a: -a['ioc_count'])
    return out

_ACTOR_SUMMARY_CACHE = {}
_ACTOR_SUMMARY_CACHE_TTL = 300  # seconds -- informational cross-reference, doesn't need per-request freshness
_ACTOR_SUMMARY_SCAN_LIMIT = 15000  # bounds cost independent of how large stix_indicators grows over time

@app.route('/api/ti/actor-summary', methods=['GET'])
@login_required
def api_ti_actor_summary():
    # Live-verified real bug: scanning every stix_indicators row in Python (one
    # find_actor_context() regex pass per row) hung this endpoint indefinitely once
    # the table reached ~130K rows after the first real MISP feed sync -- same class of
    # unbounded-work-driven-by-external-data-volume issue the MISP sync itself hit.
    # Fixed two ways: (1) a coarse LIKE-based pre-filter pushed down into SQLite (native
    # code, still a full scan but far cheaper per-row than the Python loop it replaces),
    # bounded to the most recent N rows so cost stays roughly constant as the table keeps
    # growing rather than degrading over time; (2) a short cache, since this is an
    # informational cross-reference, not something that needs to recompute on every
    # dashboard load -- same TTL-cache shape as RULES_CACHE/_TOP_COUNTRIES_CACHE above.
    import time
    now = time.time()
    cached = _ACTOR_SUMMARY_CACHE.get('data')
    if cached is not None and (now - _ACTOR_SUMMARY_CACHE.get('time', 0)) < _ACTOR_SUMMARY_CACHE_TTL:
        return jsonify({'actors': cached})

    db = get_db()
    entities = _get_ti_entities(db)
    names = {e['name'] for e in entities} | {a for e in entities for a in e['aliases']}
    if not names:
        return jsonify({'actors': []})
    conditions, cond_params = [], []
    for n in names:
        conditions.append("(LOWER(name) LIKE ? OR LOWER(description) LIKE ?)")
        like = f"%{n.lower()}%"
        cond_params.extend([like, like])
    rows = db.execute(
        f"SELECT name, description, stix_id FROM "
        f"(SELECT name, description, stix_id FROM stix_indicators WHERE revoked = 0 ORDER BY inserted_at DESC LIMIT ?) "
        f"WHERE ({' OR '.join(conditions)})",
        [_ACTOR_SUMMARY_SCAN_LIMIT] + cond_params
    ).fetchall()
    result = _build_actor_summary(rows, entities)
    _attach_actor_sightings(db, result)
    _ACTOR_SUMMARY_CACHE['data'] = result
    _ACTOR_SUMMARY_CACHE['time'] = now
    return jsonify({'actors': result})

def _attach_actor_sightings(db, actors):
    """Mutates each actor dict in place: replaces the internal 'stix_ids' join key
    with a real 'sighting_count' + capped 'sightings' list, drawn from ioc_sightings
    -- "this IOC was actually observed in our environment" evidence, distinct from
    (and easy to conflate with) ioc_count, which only measures how many IOCs in the
    synced feed catalog matched this actor's name/aliases. Bounded to the stix_ids
    that actually matched an actor (never a full-table scan) and capped per actor at
    25 rows (matching this session's established capping convention for drill-downs)
    since a widely-seen IOC could otherwise return hundreds of rows to one widget."""
    all_stix_ids = sorted({sid for a in actors for sid in a['stix_ids']})
    sightings_by_stix = {}
    if all_stix_ids:
        placeholders = ','.join('?' * len(all_stix_ids))
        for row in db.execute(
            f"SELECT s.stix_id, s.seen_at, s.alert_id, al.severity, al.message, al.host, "
            f"COALESCE(sr.title, al.rule_name, 'YARA / Custom Rule Match') as rule_title "
            f"FROM ioc_sightings s LEFT JOIN alerts al ON al.id = s.alert_id "
            f"LEFT JOIN sigma_rules sr ON al.rule_id = sr.id "
            f"WHERE s.stix_id IN ({placeholders}) ORDER BY s.seen_at DESC",
            all_stix_ids
        ).fetchall():
            sightings_by_stix.setdefault(row['stix_id'], []).append(dict(row))

    for a in actors:
        sightings = []
        for sid in a['stix_ids']:
            sightings.extend(sightings_by_stix.get(sid, []))
        sightings.sort(key=lambda s: s['seen_at'] or '', reverse=True)
        a['sighting_count'] = len(sightings)
        a['sightings'] = sightings[:25]
        del a['stix_ids']

# Empty ('') means "not assessed yet", same pass-through-when-empty convention as case
# TLP/PAP -- distinct from an explicit low-confidence tier.
TI_ENTITY_CONFIDENCE_VALUES = ('confirmed', 'probable', 'possible')

@app.route('/api/ti/entities', methods=['GET', 'POST'])
@login_required
def api_ti_entities():
    db = get_db()
    if request.method == 'GET':
        return jsonify(_get_ti_entities(db))
    err = require_permission('threatintel.manage')
    if err: return err
    d = request.json or {}
    name = (d.get('name') or '').strip()
    entity_type = (d.get('entity_type') or '').strip()
    if not name or not entity_type:
        return jsonify({'error': 'name and entity_type are required'}), 400
    confidence = (d.get('confidence') or '').strip()
    if confidence and confidence not in TI_ENTITY_CONFIDENCE_VALUES:
        return jsonify({'error': f"confidence must be empty (not set) or one of {', '.join(TI_ENTITY_CONFIDENCE_VALUES)}"}), 400
    if db.execute("SELECT 1 FROM ti_entities WHERE name = ?", (name,)).fetchone():
        return jsonify({'error': f'An entity named "{name}" already exists'}), 400
    aliases = ','.join(a.strip() for a in (d.get('aliases') or '').split(',') if a.strip())
    techniques = ','.join(t.strip() for t in (d.get('techniques') or '').split(',') if t.strip())
    external_references = '\n'.join(l.strip() for l in (d.get('external_references') or '').splitlines() if l.strip())
    db.execute(
        "INSERT INTO ti_entities (entity_type, name, aliases, description, techniques, source, created_by, confidence, attribution_note, external_references) "
        "VALUES (?, ?, ?, ?, ?, 'admin', ?, ?, ?, ?)",
        (entity_type, name, aliases, (d.get('description') or '').strip(), techniques, current_user.username,
         confidence, (d.get('attribution_note') or '').strip(), external_references)
    )
    db.commit()
    _ACTOR_SUMMARY_CACHE.clear()
    log_audit('ti_entity_create', 'ti_entity', name)
    return jsonify({'status': 'success'})

@app.route('/api/ti/entities/<int:eid>', methods=['PUT', 'DELETE'])
@login_required
def api_ti_entity_detail_admin(eid):
    err = require_permission('threatintel.manage')
    if err: return err
    db = get_db()
    existing = db.execute("SELECT name FROM ti_entities WHERE id = ?", (eid,)).fetchone()
    if not existing:
        return jsonify({'error': 'Entity not found'}), 404
    if request.method == 'DELETE':
        db.execute("DELETE FROM ti_entities WHERE id = ?", (eid,))
        db.execute("DELETE FROM ti_relationships WHERE entity_id = ?", (eid,))
        db.commit()
        _ACTOR_SUMMARY_CACHE.clear()
        log_audit('ti_entity_delete', 'ti_entity', existing['name'])
        return jsonify({'ok': 1})

    d = request.json or {}
    name = (d.get('name') or '').strip()
    entity_type = (d.get('entity_type') or '').strip()
    if not name or not entity_type:
        return jsonify({'error': 'name and entity_type are required'}), 400
    confidence = (d.get('confidence') or '').strip()
    if confidence and confidence not in TI_ENTITY_CONFIDENCE_VALUES:
        return jsonify({'error': f"confidence must be empty (not set) or one of {', '.join(TI_ENTITY_CONFIDENCE_VALUES)}"}), 400
    if db.execute("SELECT 1 FROM ti_entities WHERE name = ? AND id != ?", (name, eid)).fetchone():
        return jsonify({'error': f'An entity named "{name}" already exists'}), 400
    aliases = ','.join(a.strip() for a in (d.get('aliases') or '').split(',') if a.strip())
    techniques = ','.join(t.strip() for t in (d.get('techniques') or '').split(',') if t.strip())
    external_references = '\n'.join(l.strip() for l in (d.get('external_references') or '').splitlines() if l.strip())
    db.execute(
        "UPDATE ti_entities SET entity_type = ?, name = ?, aliases = ?, description = ?, techniques = ?, "
        "confidence = ?, attribution_note = ?, external_references = ? WHERE id = ?",
        (entity_type, name, aliases, (d.get('description') or '').strip(), techniques,
         confidence, (d.get('attribution_note') or '').strip(), external_references, eid)
    )
    db.commit()
    _ACTOR_SUMMARY_CACHE.clear()
    log_audit('ti_entity_update', 'ti_entity', name)
    return jsonify({'status': 'success'})

@app.route('/api/ti/entities/<int:eid>/detail', methods=['GET'])
@login_required
def api_ti_entity_full_detail(eid):
    # A2: the entity detail view -- reuses the exact same LIKE-based matching as the
    # dashboard summary above, scoped to just this ONE entity's name/aliases instead
    # of all of them, so it stays cheap even though it isn't cached/bounded the same
    # way (a single entity's OR-clause is a small fraction of the full summary's cost).
    from threat_actors import build_index, find_entity_context
    from mitre_attack import lookup as mitre_lookup, TACTIC_LABELS

    db = get_db()
    row = db.execute(
        "SELECT id, entity_type, name, aliases, description, techniques, source, confidence, attribution_note, external_references "
        "FROM ti_entities WHERE id = ?", (eid,)
    ).fetchone()
    if not row:
        return jsonify({'error': 'Entity not found'}), 404
    entity = _entity_row_to_dict(row)

    names = {entity['name']} | set(entity['aliases'])
    conditions, cond_params = [], []
    for n in names:
        conditions.append("(LOWER(si.name) LIKE ? OR LOWER(si.description) LIKE ?)")
        like = f"%{n.lower()}%"
        cond_params.extend([like, like])
    matched_iocs = []
    if conditions:
        rows = db.execute(
            f"SELECT si.stix_id, si.ioc_type, si.name, si.description, si.pattern, si.revoked, tf.name AS source_name, "
            f"(SELECT COUNT(*) FROM ioc_sightings s WHERE s.stix_id = si.stix_id) AS sighting_count, "
            f"(SELECT COUNT(DISTINCT feed_id) FROM stix_indicators si2 WHERE si2.pattern = si.pattern AND si2.revoked = 0) AS corroboration_count "
            f"FROM stix_indicators si LEFT JOIN ti_feeds tf ON si.feed_id = tf.id "
            f"WHERE si.revoked = 0 AND ({' OR '.join(conditions)}) "
            # Sighted first -- an IOC actually observed in this environment is the whole
            # point of this view; without this, one could sit unseen past the LIMIT 200
            # cutoff behind 200 more-recently-inserted but never-sighted catalog entries.
            f"ORDER BY sighting_count DESC, si.inserted_at DESC LIMIT 200",
            cond_params
        ).fetchall()
        # Confirm each SQL-prefiltered candidate with the same whole-word match the
        # summary widget uses, so a substring false-positive (e.g. an unrelated IOC
        # whose name happens to CONTAIN this entity's name as part of a longer word)
        # doesn't show up on the detail page even though the LIKE pre-filter caught it.
        index = build_index([entity])
        for r in rows:
            rd = dict(r)
            if find_entity_context(rd['name'], index) or find_entity_context(rd.get('description', ''), index):
                del rd['description']  # internal confirmation input only, not part of the API shape
                matched_iocs.append(rd)

    # "Last seen active" = the most recent real ioc_sightings hit against this entity's
    # own confirmed matched_iocs (not the coarser actor-summary widget's matching) --
    # None means never observed in this environment, distinct from "no IOCs in feed".
    last_seen_active = None
    matched_stix_ids = [m['stix_id'] for m in matched_iocs]
    if matched_stix_ids:
        placeholders = ','.join('?' * len(matched_stix_ids))
        row = db.execute(
            f"SELECT MAX(seen_at) as last_seen FROM ioc_sightings WHERE stix_id IN ({placeholders})",
            matched_stix_ids
        ).fetchone()
        last_seen_active = row['last_seen'] if row else None

    techniques = []
    for tid in entity['techniques']:
        tname, tactic = mitre_lookup(tid)
        techniques.append({'id': tid, 'name': tname, 'tactic': tactic, 'tactic_label': TACTIC_LABELS.get(tactic, tactic)})

    # Entity-to-entity links are stored as one directed row (entity_id -> target_id),
    # but shown on BOTH entities' detail pages -- the UNION's second branch is this
    # entity's INCOMING side of a link some other entity created, with target_id
    # re-mapped to "the other entity" either way so the frontend can treat both
    # branches uniformly. Only entity-type relationships get an entity_name resolved;
    # alert/case/ioc/ueba_event rows keep the existing raw-target_id display.
    relationships = [dict(r) for r in db.execute(
        "SELECT id, target_type, target_id, relationship_type, created_by, created_at, 'outgoing' as direction, "
        "(SELECT name FROM ti_entities WHERE id = CAST(target_id AS INTEGER)) as entity_name "
        "FROM ti_relationships WHERE entity_id = ? "
        "UNION ALL "
        "SELECT id, target_type, CAST(entity_id AS TEXT) as target_id, relationship_type, created_by, created_at, 'incoming' as direction, "
        "(SELECT name FROM ti_entities WHERE id = entity_id) as entity_name "
        "FROM ti_relationships WHERE target_type = 'entity' AND target_id = ? "
        "ORDER BY created_at DESC",
        (eid, str(eid))
    ).fetchall()]

    return jsonify({**entity, 'techniques': techniques, 'matched_iocs': matched_iocs, 'relationships': relationships, 'last_seen_active': last_seen_active})

# A3: manual entity<->target links -- lets an analyst tie a specific alert/UEBA
# event/case/IOC to an entity when the automatic name/alias regex match (used by
# matched_iocs above and the actor-summary widget) doesn't catch it. Open to any
# logged-in user, not admin-gated -- same collaborative-annotation posture as case
# items/tasks/notes, distinct from entity CRUD which edits the canonical library.
TI_RELATIONSHIP_TARGET_TYPES = {'alert', 'ueba_event', 'case', 'ioc', 'entity'}

@app.route('/api/ti/entities/<int:eid>/relationships', methods=['POST'])
@login_required
def api_ti_entity_relationship_add(eid):
    db = get_db()
    if not db.execute("SELECT 1 FROM ti_entities WHERE id = ?", (eid,)).fetchone():
        return jsonify({'error': 'Entity not found'}), 404
    d = request.json or {}
    target_type = (d.get('target_type') or '').strip()
    target_id = str(d.get('target_id') or '').strip()
    relationship_type = (d.get('relationship_type') or 'indicates').strip()
    if target_type not in TI_RELATIONSHIP_TARGET_TYPES:
        return jsonify({'error': f"target_type must be one of {', '.join(sorted(TI_RELATIONSHIP_TARGET_TYPES))}"}), 400
    if not target_id:
        return jsonify({'error': 'target_id is required'}), 400
    if target_type == 'case' and target_id.isdigit():
        err = _require_open_case(db, int(target_id))
        if err: return err
    if target_type == 'entity':
        if not target_id.isdigit():
            return jsonify({'error': 'Entity target_id must be an entity ID'}), 400
        if int(target_id) == eid:
            return jsonify({'error': 'An entity cannot be linked to itself'}), 400
        if not db.execute("SELECT 1 FROM ti_entities WHERE id = ?", (int(target_id),)).fetchone():
            return jsonify({'error': 'Target entity not found'}), 404
    if db.execute(
        "SELECT 1 FROM ti_relationships WHERE entity_id = ? AND target_type = ? AND target_id = ?",
        (eid, target_type, target_id)
    ).fetchone():
        return jsonify({'error': 'That link already exists'}), 400
    db.execute(
        "INSERT INTO ti_relationships (entity_id, target_type, target_id, relationship_type, created_by) VALUES (?, ?, ?, ?, ?)",
        (eid, target_type, target_id, relationship_type, current_user.username)
    )
    db.commit()
    log_audit('ti_relationship_create', 'ti_entity', eid, f'{target_type}:{target_id}')
    return jsonify({'status': 'success'})

@app.route('/api/ti/entities/<int:eid>/relationships/<int:rid>', methods=['DELETE'])
@login_required
def api_ti_entity_relationship_delete(eid, rid):
    db = get_db()
    # An entity-to-entity link shows on both entities' pages (see the UNION in the
    # detail route above) and must be deletable from either -- the row itself is only
    # ever stored under the CREATING entity's entity_id, so the viewing-from-the-
    # target-side case needs the second OR branch to find it at all.
    rel = db.execute(
        "SELECT target_type, target_id FROM ti_relationships WHERE id = ? AND (entity_id = ? OR (target_type = 'entity' AND target_id = ?))",
        (rid, eid, str(eid))
    ).fetchone()
    if not rel:
        return jsonify({'error': 'Relationship not found'}), 404
    if rel['target_type'] == 'case' and rel['target_id'].isdigit():
        err = _require_open_case(db, int(rel['target_id']))
        if err: return err
    db.execute("DELETE FROM ti_relationships WHERE id = ?", (rid,))
    db.commit()
    log_audit('ti_relationship_delete', 'ti_entity', eid, str(rid))
    return jsonify({'ok': 1})

def _looks_like_ip_or_cidr(value):
    import ipaddress
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False

@app.route('/api/ti/warninglists', methods=['GET'])
@login_required
def api_ti_warninglists():
    db = get_db()
    rows = db.execute(
        "SELECT w.id, w.name, w.description, w.type, w.enabled, w.source_list, COUNT(e.id) AS entry_count "
        "FROM warninglists w LEFT JOIN warninglist_entries e ON e.warninglist_id = w.id "
        "GROUP BY w.id ORDER BY w.name"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/ti/warninglists/<int:wid>', methods=['PUT'])
@login_required
def api_ti_warninglist_toggle(wid):
    err = require_permission('threatintel.manage')
    if err: return err
    d = request.json or {}
    db = get_db()
    if not db.execute("SELECT 1 FROM warninglists WHERE id = ?", (wid,)).fetchone():
        return jsonify({'error': 'Warninglist not found'}), 404
    enabled = 1 if d.get('enabled') else 0
    db.execute("UPDATE warninglists SET enabled = ? WHERE id = ?", (enabled, wid))
    db.commit()
    log_audit('warninglist_toggle', 'warninglist', wid, 'enabled' if enabled else 'disabled')
    return jsonify({'status': 'success'})

@app.route('/api/ti/warninglists/<int:wid>', methods=['DELETE'])
@login_required
def api_ti_warninglist_delete(wid):
    err = require_permission('threatintel.manage')
    if err: return err
    db = get_db()
    w = db.execute("SELECT name FROM warninglists WHERE id = ?", (wid,)).fetchone()
    if not w:
        return jsonify({'error': 'Warninglist not found'}), 404
    db.execute("DELETE FROM warninglist_entries WHERE warninglist_id = ?", (wid,))
    db.execute("DELETE FROM warninglists WHERE id = ?", (wid,))
    db.commit()
    log_audit('warninglist_delete', 'warninglist', wid, w['name'])
    return jsonify({'status': 'success'})

@app.route('/api/ti/warninglists/<int:wid>/entries', methods=['GET'])
@login_required
def api_ti_warninglist_entries(wid):
    # Capped at 500 -- purely a "what's actually in this list" viewer, not a full
    # export; an admin who needs the whole thing already has it in src/warninglists.py
    # (seed lists) or can re-fetch the source (imported lists).
    db = get_db()
    w = db.execute("SELECT id, name FROM warninglists WHERE id = ?", (wid,)).fetchone()
    if not w:
        return jsonify({'error': 'Warninglist not found'}), 404
    total = db.execute("SELECT COUNT(*) FROM warninglist_entries WHERE warninglist_id = ?", (wid,)).fetchone()[0]
    entries = [r[0] for r in db.execute(
        "SELECT value FROM warninglist_entries WHERE warninglist_id = ? ORDER BY value LIMIT 500", (wid,)
    ).fetchall()]
    return jsonify({'name': w['name'], 'total': total, 'entries': entries})

_WARNINGLIST_CATALOG_CACHE = {}
_WARNINGLIST_CATALOG_CACHE_TTL = 3600  # seconds -- a repo directory listing, doesn't change often

@app.route('/api/ti/warninglists/catalog', methods=['GET'])
@login_required
def api_ti_warninglist_catalog():
    # Lists every list NAME available in the real MISP misp-warninglists project (one
    # cheap GitHub API call, cached an hour) so an admin can pick one to import --
    # deliberately NOT fetching every list's full content just to show entry counts,
    # since that would be 100+ requests on every page load. A specific list's real
    # content is only fetched at actual import time (see the import route below).
    import time, urllib.request, json as _json
    now = time.time()
    cached = _WARNINGLIST_CATALOG_CACHE.get('data')
    if cached is not None and (now - _WARNINGLIST_CATALOG_CACHE.get('time', 0)) < _WARNINGLIST_CATALOG_CACHE_TTL:
        names = cached
    else:
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/MISP/misp-warninglists/contents/lists",
                headers={'User-Agent': 'micro-dfir-appliance'}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read())
            names = sorted(item['name'] for item in data if item.get('type') == 'dir')
            _WARNINGLIST_CATALOG_CACHE['data'] = names
            _WARNINGLIST_CATALOG_CACHE['time'] = now
        except Exception as e:
            return jsonify({'error': f'Failed to fetch the misp-warninglists catalog: {e}'}), 502
    db = get_db()
    imported = {r[0] for r in db.execute(
        "SELECT source_list FROM warninglists WHERE source_list IS NOT NULL"
    ).fetchall()}
    return jsonify([{'name': n, 'imported': n in imported} for n in names])

@app.route('/api/ti/warninglists/import', methods=['POST'])
@login_required
def api_ti_warninglist_import():
    err = require_permission('threatintel.manage')
    if err: return err
    import urllib.request, json as _json, ipaddress
    list_name = ((request.json or {}).get('list_name') or '').strip()
    if not list_name or not re.match(r'^[a-z0-9_-]+$', list_name):
        return jsonify({'error': 'Invalid list name.'}), 400
    db = get_db()
    if db.execute("SELECT 1 FROM warninglists WHERE source_list = ?", (list_name,)).fetchone():
        return jsonify({'error': 'This list has already been imported.'}), 400
    try:
        req = urllib.request.Request(
            f"https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/{list_name}/list.json",
            headers={'User-Agent': 'micro-dfir-appliance'}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = _json.loads(resp.read())
    except Exception as e:
        return jsonify({'error': f'Failed to fetch "{list_name}": {e}'}), 502

    entries = data.get('list') or []
    if not entries:
        return jsonify({'error': f'"{list_name}" has no entries.'}), 400

    # This appliance's suppression only ever matches IPs (warninglists.py's
    # filter_warninglisted_ips) -- a MISP list of domains/hashes/strings would import
    # cleanly but silently suppress nothing, so validate the entries actually look
    # IP-shaped before accepting it, rather than trusting MISP's own declared 'type'
    # field (some CIDR-shaped lists are still tagged type='string' upstream).
    sample = entries[:25]
    ip_like = sum(1 for v in sample if _looks_like_ip_or_cidr(str(v)))
    if ip_like < len(sample) * 0.8:
        return jsonify({'error': f'"{list_name}" does not look like an IP/CIDR-based list (only usable warninglist type today).'}), 400

    local_type = 'cidr' if '/' in str(sample[0]) else 'ip'
    name = data.get('name') or list_name
    description = data.get('description') or f'Imported from misp-warninglists/{list_name}.'
    cur = db.execute(
        "INSERT INTO warninglists (name, description, type, enabled, source_list) VALUES (?, ?, ?, 1, ?)",
        (name, description, local_type, list_name)
    )
    wid = cur.lastrowid
    db.executemany(
        "INSERT INTO warninglist_entries (warninglist_id, value) VALUES (?, ?)",
        [(wid, str(v)) for v in entries]
    )
    db.commit()
    log_audit('warninglist_import', 'warninglist', wid, f'{list_name} ({len(entries)} entries)')
    return jsonify({'status': 'success', 'id': wid, 'name': name, 'entry_count': len(entries)})

@app.route('/api/ti/iocs/facets', methods=['GET'])
@login_required
def api_ti_iocs_facets():
    # The distinct ioc_type values across the *whole* table, not just the currently
    # loaded page — otherwise the Type filter's option list would silently miss
    # anything not present in the first `limit` rows.
    db = get_db()
    types = [r[0] for r in db.execute(
        "SELECT DISTINCT ioc_type FROM stix_indicators WHERE ioc_type IS NOT NULL AND ioc_type != '' ORDER BY ioc_type"
    ).fetchall()]
    return jsonify({'types': types})


@app.route('/api/droprules', methods=['GET', 'POST'])
@login_required
def api_drop_rules():
    db = get_db()
    if request.method == 'GET': return jsonify([dict(r) for r in db.execute("SELECT * FROM drop_rules ORDER BY id DESC").fetchall()])
    err = require_permission('logsearch.droprules.manage')
    if err: return err
    d = request.get_json()
    db.execute("INSERT INTO drop_rules (field, operator, value, description, enabled) VALUES (?, ?, ?, ?, 1)", (d.get('field'), d.get('operator'), d.get('value'), d.get('description')))
    db.commit(); generate_vector_config()
    log_audit('drop_rule_create', 'drop_rule', None, f"{d.get('field')} {d.get('operator')} {d.get('value')}")
    return jsonify({"status": "success"}), 201

@app.route('/api/droprules/<int:rid>/toggle', methods=['PUT'])
@login_required
def tog_drop(rid):
    err = require_permission('logsearch.droprules.manage')
    if err: return err
    get_db().execute("UPDATE drop_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id=?", (rid,)); get_db().commit(); generate_vector_config()
    log_audit('drop_rule_toggle', 'drop_rule', rid)
    return jsonify({"ok":1})

@app.route('/api/droprules/<int:rid>', methods=['DELETE'])
@login_required
def del_drop(rid):
    err = require_permission('logsearch.droprules.manage')
    if err: return err
    get_db().execute("DELETE FROM drop_rules WHERE id=?", (rid,)); get_db().commit(); generate_vector_config()
    log_audit('drop_rule_delete', 'drop_rule', rid)
    return jsonify({"ok":1})

DROP_RULE_PREVIEW_WINDOW_DAYS = 7
DROP_RULE_PREVIEW_SAMPLE_LIMIT = 20

# Dry-run a candidate field/operator/value against real recently-ingested logs, so an
# admin can see what a drop rule would actually have caught before saving it (drop
# rules run at the Vector layer, before a log ever reaches live_logs -- once a rule is
# live there's no way to see what it silently ate, so this is the only chance to check).
# Deliberately mirrors generate_vector_config()'s own VRL semantics as closely as SQL
# allows, not the Log Search page's (case-insensitive LIKE) filtering: VRL's `==` and
# `contains()` are both case-sensitive by default, so this uses `=` and SQLite's
# case-sensitive INSTR() rather than LIKE, and COALESCE(field, '') to mirror `?? ""`
# for rows where the field is NULL -- using the wrong casing/null semantics here would
# make the preview lie about what the real rule matches.
@app.route('/api/droprules/preview', methods=['POST'])
@login_required
def api_droprules_preview():
    d = request.get_json() or {}
    field = d.get('field') if d.get('field') in DROP_RULE_FIELDS else 'message'
    operator = d.get('operator')
    value = str(d.get('value', '')).strip()
    if not value:
        return jsonify({'error': 'A match value is required to preview.'}), 400

    if operator == 'equals':
        cond = f"COALESCE({field}, '') = ?"
    else:
        cond = f"INSTR(COALESCE({field}, ''), ?) > 0"
    where = f"{cond} AND timestamp >= datetime('now', ?)"
    params = (value, f'-{DROP_RULE_PREVIEW_WINDOW_DAYS} days')

    db = get_db()
    count = db.execute(f"SELECT COUNT(*) FROM live_logs WHERE {where}", params).fetchone()[0]
    rows = db.execute(
        f"SELECT timestamp, host, app, event_id, message FROM live_logs WHERE {where} "
        f"ORDER BY timestamp DESC LIMIT {DROP_RULE_PREVIEW_SAMPLE_LIMIT}",
        params
    ).fetchall()
    return jsonify({
        'count': count,
        'sample': [dict(r) for r in rows],
        'window_days': DROP_RULE_PREVIEW_WINDOW_DAYS,
    })

# ==========================================
# SIGMA RULES ENGINE
# ==========================================
RULES_CACHE = None
RULES_CACHE_TIME = 0
RULES_CACHE_TTL = 30  # seconds; bounds staleness against out-of-process writers like import_sigmahq.py
TUNING_CACHE = None
TUNING_CACHE_TIME = 0

# Sigma rules carry no compliance-framework metadata (SigmaHQ tags are almost entirely
# MITRE ATT&CK technique IDs) — there's no authoritative source to auto-map a rule to a
# framework, so these are assigned by hand per rule and just validated against this set.
# key -> human label. Previously a bare set here with an identical-but-separate labeled
# list duplicated in dashboard.html's JS (COMPLIANCE_FRAMEWORKS) -- the two could drift.
# This is now the one source of truth for the app; `in COMPLIANCE_FRAMEWORKS` validation
# below still works unchanged since `in` on a dict checks its keys.
COMPLIANCE_FRAMEWORKS = {
    'pci_dss': 'PCI DSS', 'hipaa': 'HIPAA', 'nist_800_53': 'NIST 800-53',
    'nist_csf': 'NIST CSF', 'iso_27001': 'ISO 27001', 'soc2': 'SOC 2',
    'cis_controls': 'CIS Controls', 'gdpr': 'GDPR',
}

COMPLIANCE_AUDIT_ACTIONS = ('rule_compliance_tag', 'rule_toggle', 'rule_bulk_toggle')

@app.route('/api/compliance/audit-trail', methods=['GET'])
@login_required
def api_compliance_audit_trail():
    # Who tagged/enabled/disabled a compliance-relevant rule, and when -- these three
    # actions already write real audit_log rows (log_audit calls in api_rule_compliance,
    # api_r_tog, api_rules_bulk), this just surfaces them filtered to compliance's own
    # slice instead of requiring a trip through the full unfiltered audit log. Gated the
    # same way the full audit log is (audit.view), not threatintel/rules.manage --
    # reading who-changed-what is an audit concern, not a rule-editing one.
    err = require_permission('audit.view')
    if err: return err
    db = get_db()
    placeholders = ','.join('?' * len(COMPLIANCE_AUDIT_ACTIONS))
    rows = db.execute(
        f"SELECT id, timestamp, username, action, target_id, details FROM audit_log "
        f"WHERE action IN ({placeholders}) ORDER BY id DESC LIMIT 25",
        COMPLIANCE_AUDIT_ACTIONS
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/compliance/coverage', methods=['GET'])
@login_required
def api_compliance_coverage():
    # Same tagged-vs-enabled coverage generate_compliance_report() computes for the
    # downloadable PDF (src/generate_report.py), exposed live for a Dashboards widget
    # instead of only ever being visible inside a generated report.
    db = get_db()
    rows = db.execute(
        "SELECT compliance_tags, enabled FROM sigma_rules WHERE compliance_tags IS NOT NULL AND compliance_tags != ''"
    ).fetchall()
    coverage = {key: {'key': key, 'label': label, 'total': 0, 'enabled': 0} for key, label in COMPLIANCE_FRAMEWORKS.items()}
    for row in rows:
        for tag in (row['compliance_tags'] or '').split(','):
            if tag in coverage:
                coverage[tag]['total'] += 1
                if row['enabled']:
                    coverage[tag]['enabled'] += 1
    frameworks = sorted(coverage.values(), key=lambda f: f['label'])
    return jsonify({
        'frameworks': frameworks,
        'full_coverage_count': sum(1 for f in frameworks if f['total'] > 0 and f['enabled'] == f['total']),
        'total_frameworks': len(frameworks),
    })

def _extract_cvss(metrics):
    # Prefer the newest CVSS version NVD has scored a CVE with -- v3.1 > v3.0 > v2.0.
    # v2 metric entries carry baseSeverity as a sibling of cvssData (not nested inside
    # it the way v3 entries do), so both locations are checked rather than assuming one.
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = (metrics or {}).get(key) or []
        if entries:
            m = entries[0]
            cvss_data = m.get('cvssData', {})
            return cvss_data.get('baseScore'), (m.get('baseSeverity') or cvss_data.get('baseSeverity'))
    return None, None

def _sync_cve_feed(db):
    # NVD's public CVE 2.0 API -- free, no API key needed at this request volume (one
    # bounded pull, not a polling loop). Pulls CVEs *published* in the last 7 days
    # (bounded window + resultsPerPage cap keeps this a predictable, cheap sync, not an
    # unbounded historical backfill) and upserts them -- an already-stored CVE whose
    # score/description NVD has since revised gets refreshed, not duplicated.
    import urllib.request, json as _json
    from datetime import timedelta
    end = datetime.utcnow()
    start = end - timedelta(days=7)
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?resultsPerPage=200&pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&pubEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
    )
    req = urllib.request.Request(url, headers={'User-Agent': 'micro-dfir/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = _json.loads(resp.read().decode('utf-8'))
    count = 0
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id')
        if not cve_id:
            continue
        desc = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
        score, severity = _extract_cvss(cve.get('metrics', {}))
        db.execute(
            "INSERT INTO cve_records (cve_id, description, cvss_score, severity, published_date, last_modified, fetched_at) "
            "VALUES (?, ?, ?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description, cvss_score=excluded.cvss_score, "
            "severity=excluded.severity, last_modified=excluded.last_modified, fetched_at=excluded.fetched_at",
            (cve_id, desc, score, severity, cve.get('published'), cve.get('lastModified'))
        )
        count += 1
    db.commit()
    return count

@app.route('/api/cve/records', methods=['GET'])
@login_required
def api_cve_records():
    db = get_db()
    conditions, params = [], []
    q = (request.args.get('q') or '').strip()
    if q:
        conditions.append("(cve_id LIKE ? OR description LIKE ?)")
        params.extend([f'%{q}%', f'%{q}%'])
    severity = (request.args.get('severity') or '').strip().upper()
    if severity:
        conditions.append("UPPER(severity) = ?")
        params.append(severity)
    min_score = request.args.get('min_score', type=float)
    if min_score is not None:
        conditions.append("cvss_score >= ?")
        params.append(min_score)
    where_sql = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
    except (TypeError, ValueError):
        limit = 100
    total = db.execute(f"SELECT COUNT(*) AS c FROM cve_records {where_sql}", params).fetchone()['c']
    rows = db.execute(
        f"SELECT cve_id, description, cvss_score, severity, published_date, last_modified FROM cve_records "
        f"{where_sql} ORDER BY published_date DESC LIMIT ?",
        params + [limit]
    ).fetchall()
    return jsonify({'rows': [dict(r) for r in rows], 'total': total})

@app.route('/api/cve/sync-status', methods=['GET'])
@login_required
def api_cve_sync_status():
    import json
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = 'cve_feed_status'").fetchone()
    status = json.loads(row['value']) if row and row['value'] else {}
    total = db.execute("SELECT COUNT(*) AS c FROM cve_records").fetchone()['c']
    return jsonify({**status, 'total_stored': total})

@app.route('/api/cve/sync', methods=['POST'])
@login_required
def api_cve_sync():
    import json
    err = require_permission('threatintel.manage')
    if err: return err
    db = get_db()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    try:
        count = _sync_cve_feed(db)
        status = {'last_sync': now, 'last_count': count, 'last_status': 'success', 'last_error': None}
    except Exception as e:
        status = {'last_sync': now, 'last_count': 0, 'last_status': 'error', 'last_error': str(e)}
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cve_feed_status', ?)", (json.dumps(status),))
    db.commit()
    log_audit('cve_feed_sync', 'cve_feed', None, f"status={status['last_status']}, count={status['last_count']}")
    if status['last_status'] == 'error':
        return jsonify({'error': status['last_error']}), 502
    return jsonify(status)

def invalidate_rules_cache():
    global RULES_CACHE, TUNING_CACHE
    RULES_CACHE = None
    TUNING_CACHE = None

# Deliberately never auto-purged (unlike live_logs, which has a configurable retention
# policy) -- every compliance framework this app tags rules for expects an audit trail
# retained far longer than raw event logs, and auto-deleting the record of what happened
# would defeat the point of having one. `details` is a short summary, not a full payload;
# where a full before/after already exists (rule edits -> sigma_rule_history), this just
# references it rather than duplicating it.
def log_audit(action, target_type=None, target_id=None, details=None):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (username, role, ip_address, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (getattr(current_user, 'username', None), getattr(current_user, 'role', None),
             request.remote_addr, action, target_type, str(target_id) if target_id is not None else None, details)
        )
        db.commit()
    except Exception as e:
        # Audit logging must never be the reason a real action fails -- print and move on.
        print(f"[-] log_audit failed for action={action!r}: {e}")

# Sigma's own status vocabulary is stable/test/experimental/deprecated/unsupported --
# unsupported means "this detection logic can't reliably work" and deprecated means
# "superseded by another rule", which are technically distinct, but from a "should I
# still rely on this rule" triage standpoint they're the same answer, so both collapse
# into one bucket here rather than needing two badges/filters that mean the same thing
# in practice.
_STATUS_ALIASES = {'unsupported': 'deprecated'}

def _normalize_rule_status(raw):
    s = (raw or '').strip().lower()
    return _STATUS_ALIASES.get(s, s) or 'unknown'

# Extracts a single-line "key: value" metadata field from raw Sigma rule YAML without
# a full YAML parse (this whole block trades correctness for speed across thousands of
# cached rules). `^` (MULTILINE) still anchors to the start of A line, so a field that
# merely ENDS in the same word -- e.g. ResponseStatus: or release_date: -- can't be
# mistaken for a real `status:`/`date:` (exact key-boundary match), and trailing inline
# comments (# ...) are excluded from the captured value. Deliberately allows leading
# indentation (`\s*`) -- product/service/category live nested under Sigma's `logsource:`
# block, never at column 0, so anchoring to column 0 (the original form of this regex)
# silently returned None for every one of those three fields on every real rule. The one
# residual risk this reintroduces: a `detection:` selector field that happens to be named
# identically to a metadata key (e.g. a log field literally called `product`) could
# false-match `re.search`'s first hit -- accepted because `logsource:` conventionally
# precedes `detection:` in Sigma rule ordering, so the real metadata field wins in
# practice, and this is the same class of tradeoff already implicit in this function.
def _extract_yaml_field(key, text):
    m = re.search(rf'^\s*{key}:\s*([^\n\r#]+)', text, re.MULTILINE)
    return m.group(1).strip().strip("'\"") if m else None

# Sigma's logsource.product/service vocabulary mapped to the live_logs.app values this
# appliance's Vector pipeline (config/vector.toml) actually tags ingested events with --
# curated once by hand against real ingestion, not a live sync (same "confirmed once,
# committed as a fixed list" pattern as src/warninglists.py). A (product, service) combo
# not listed here means "unknown" (this table hasn't been extended for it), NOT "absent"
# -- extending coverage means editing this dict directly.
SIGMA_LOGSOURCE_INGESTED_APPS = {
    ('windows', 'sysmon'): {'sysmon'},
    ('windows', 'security'): {'security'},
    ('windows', 'system'): {'system'},
    ('windows', 'application'): {'application'},
    ('windows', 'powershell'): {'powershell'},
    ('windows', 'powershell-classic'): {'powershell'},
    ('windows', 'windefend'): {'windows defender'},
    ('windows', None): {'sysmon', 'security', 'system', 'application', 'powershell', 'windows defender'},
    ('linux', 'auditd'): set(),
    ('linux', 'syslog'): set(),
    ('linux', None): {'systemd', 'sshd', 'kernel', 'cron', 'dbus-daemon', 'systemd-logind', 'wpa_supplicant', 'fwupd'},
    ('aws', None): set(),
    ('azure', None): set(),
    ('gcp', None): set(),
    ('okta', None): set(),
    ('m365', None): set(),
    ('github', None): set(),
}

_INGESTED_APPS_CACHE = {}
_INGESTED_APPS_CACHE_TTL = 300  # seconds -- same TTL-cache shape as _ACTOR_SUMMARY_CACHE

def _get_ingested_apps(db):
    """Lowercased set of every distinct live_logs.app value ever ingested -- an
    index-only scan on idx_live_logs_app, cheap even at millions of rows. This IS the
    "what's actually flowing into this appliance" registry; no separate log-source
    catalog needs to be invented."""
    import time
    now = time.time()
    cached = _INGESTED_APPS_CACHE.get('data')
    if cached is not None and (now - _INGESTED_APPS_CACHE.get('time', 0)) < _INGESTED_APPS_CACHE_TTL:
        return cached
    apps = {row[0].strip().lower() for row in db.execute(
        "SELECT DISTINCT app FROM live_logs WHERE app IS NOT NULL"
    ).fetchall() if row[0]}
    _INGESTED_APPS_CACHE['data'] = apps
    _INGESTED_APPS_CACHE['time'] = now
    return apps

def _rule_log_source_ingestible(product, service, ingested_apps):
    """True/False when SIGMA_LOGSOURCE_INGESTED_APPS has a definite answer for this
    (product, service) combo; None when the rule has no product at all (e.g. a
    correlation-only rule) or the combo isn't in our curated table yet -- None is
    deliberately treated as "unknown", never surfaced as a gap."""
    if not product:
        return None
    product = product.strip().lower()
    service = service.strip().lower() if service else None
    expected = SIGMA_LOGSOURCE_INGESTED_APPS.get((product, service))
    if expected is None:
        expected = SIGMA_LOGSOURCE_INGESTED_APPS.get((product, None))
    if expected is None:
        return None
    if not expected:
        return False
    return bool(expected & ingested_apps)

def _get_rules_cache(db):
    """Returns the rules_out list used by both /api/rules and /api/mitre/coverage,
    rebuilding from sigma_rules when the TTL cache is stale."""
    global RULES_CACHE, RULES_CACHE_TIME
    import time
    if RULES_CACHE is not None and (time.time() - RULES_CACHE_TIME) < RULES_CACHE_TTL:
        return RULES_CACHE

    ingested_apps = _get_ingested_apps(db)

    import re
    from mitre_attack import techniques_for_tags
    rules_out = []
    for r in db.execute(
        "SELECT id, title, rule_yaml, original_yaml, upstream_yaml, enabled, source, cloned_from, created_by, created_at, updated_by, updated_at, compliance_tags "
        "FROM sigma_rules ORDER BY id DESC"
    ).fetchall():
        rid = r['id']
        ry = r['rule_yaml']
        try:
            cat = _extract_yaml_field('category', ry) or 'unknown'
            raw_product = _extract_yaml_field('product', ry)
            raw_service = _extract_yaml_field('service', ry)
            platform = (raw_product or 'Global').title()
            log_source_ingestible = _rule_log_source_ingestible(raw_product, raw_service, ingested_apps)

            t_match = re.search(r'^tags:\s*\n((\s+-\s*[^\n\r]+\n?)+)', ry, re.MULTILINE)
            tags = [t.strip().strip('- ') for t in t_match.group(1).split('\n') if t.strip()] if t_match else []

            rule_type = "Generic"
            for t in tags:
                if t.startswith('compliance'):
                    rule_type = "Compliance"
                    break
                elif 'hunting' in t or 'threat_hunting' in t:
                    rule_type = "Threat Hunting"
                    break

            level = (_extract_yaml_field('level', ry) or 'medium').lower()
            status = _normalize_rule_status(_extract_yaml_field('status', ry))

            d_match = re.search(r'^modified:\s*([0-9]{4}[-/][0-9]{2}[-/][0-9]{2})', ry, re.MULTILINE) or \
                      re.search(r'^date:\s*([0-9]{4}[-/][0-9]{2}[-/][0-9]{2})', ry, re.MULTILINE)
            rule_date = d_match.group(1).replace('/', '-') if d_match else None
        except Exception:
            rule_type, platform, cat, tags = "Generic", "Global", "unknown", []
            level, status, rule_date = "medium", "unknown", None
            log_source_ingestible = None

        rules_out.append({
            "id": rid,
            "title": r['title'],
            "enabled": r['enabled'],
            "rule_type": rule_type,
            "platform": platform,
            "category": cat,
            "tags": tags,
            "mitre_techniques": techniques_for_tags(tags),
            "level": level,
            "status": status,
            "log_source_ingestible": log_source_ingestible,
            "is_modified": bool(r['original_yaml']) and ry != r['original_yaml'],
            # Only meaningful for a modified rule -- SigmaHQ's content has moved past the
            # baseline this rule was locally edited from, so a straight Revert would land
            # on stale content too. upstream_yaml is None until an import run has touched
            # a modified rule at least once (see migrate_sigma_rules_upstream_yaml).
            "upstream_drifted": bool(r['original_yaml']) and ry != r['original_yaml']
                                 and bool(r['upstream_yaml']) and r['upstream_yaml'] != r['original_yaml'],
            "source": r['source'] or 'sigma',
            "cloned_from": r['cloned_from'],
            "created_by": r['created_by'],
            "created_at": r['created_at'],
            "updated_by": r['updated_by'],
            "updated_at": r['updated_at'],
            "last_update": r['updated_at'] or rule_date or r['created_at'],
            "compliance_tags": [t for t in (r['compliance_tags'] or '').split(',') if t]
        })
    RULES_CACHE = rules_out
    RULES_CACHE_TIME = time.time()
    return RULES_CACHE

@app.route('/api/rules', methods=['GET', 'POST'])
@login_required
def api_rules():
    db = get_db()

    if request.method == 'GET':
        return jsonify(_get_rules_cache(db))

    err = require_permission('rules.manage')
    if err: return err
    ry = request.get_json().get('rule_yaml', '')
    import yaml
    try:
        parsed = yaml.safe_load(ry)
        t = parsed.get('title', 'Untitled') if isinstance(parsed, dict) else 'Untitled'
    except yaml.YAMLError as e:
        return jsonify({"error": f"Invalid rule YAML: {e}"}), 400
    db.execute(
        "INSERT INTO sigma_rules (title, rule_yaml, enabled, source, created_by, created_at) VALUES (?, ?, 1, 'custom', ?, CURRENT_TIMESTAMP)",
        (t, ry, current_user.username)
    )
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})

SIGMA_DRY_RUN_SAMPLE_LIMIT = 20
SIGMA_DRY_RUN_WINDOWS = {'1d': 1, '7d': 7, '30d': 30, '90d': 90}

# Backtests a rule (new, draft, or an existing rule being edited) against recent
# live_logs before it's ever enabled -- see sigma_engine.dry_run_rule() for how this
# stays behaviorally identical to a real detection cycle without any of its side
# effects. rule_id is optional: a brand-new, not-yet-saved rule has no exclusions to
# apply yet, but an existing rule being tested picks up whatever's already configured
# for it on the Tuning page, so the preview matches what re-enabling it would actually do.
@app.route('/api/rules/dry-run', methods=['POST'])
@login_required
def api_rules_dry_run():
    d = request.get_json() or {}
    rule_yaml = (d.get('rule_yaml') or '').strip()
    if not rule_yaml:
        return jsonify({'error': 'rule_yaml is required'}), 400
    days = SIGMA_DRY_RUN_WINDOWS.get(d.get('window'), 7)
    rule_id = d.get('rule_id')

    db = get_db()
    exclusions = []
    if rule_id:
        exclusions = [dict(e) for e in db.execute(
            "SELECT field, operator, value FROM rule_exclusions WHERE rule_id = ? AND enabled = 1", (rule_id,)
        ).fetchall()]

    from sigma_engine import dry_run_rule
    try:
        result = dry_run_rule(db, rule_yaml, days=days, exclusions=exclusions, preview_limit=SIGMA_DRY_RUN_SAMPLE_LIMIT)
    except Exception as e:
        return jsonify({'error': f'Rule failed to parse or convert: {e}'}), 400
    return jsonify(result)

# Runs every currently-ENABLED rule through sigma_engine.check_rule_converts() -- a
# compile-only check (no live_logs scan) -- and reports which ones fail. This is the
# systematic version of what the dry-run feature caught by accident for one rule:
# run_detection_cycle() silently swallows a per-rule conversion exception into a
# stdout print, so a rule can be broken for a long time with nothing in the UI ever
# showing it. Deliberately NOT built on dry_run_rule() (which DOES execute against
# live_logs, needed for a single rule's real match preview) -- looping that across
# every enabled rule in one request took minutes against this appliance's real log
# volume; compilation alone is pure in-memory work and checks the same failure class
# in a fraction of a second per rule. Only enabled rules are checked -- a disabled
# rule failing to convert has no live impact until someone enables it.
@app.route('/api/rules/validate-all', methods=['POST'])
@login_required
def api_rules_validate_all():
    db = get_db()
    rules = db.execute("SELECT id, title, rule_yaml FROM sigma_rules WHERE enabled = 1 ORDER BY id").fetchall()

    from sigma_engine import check_rule_converts
    ioc_cache = {}
    failed = []
    for r in rules:
        try:
            check_rule_converts(db, r['rule_yaml'], ioc_cache)
        except Exception as e:
            failed.append({'id': r['id'], 'title': r['title'], 'error': str(e)})
    return jsonify({'checked': len(rules), 'failed': failed})

# The real, execute-against-logs dry run (see api_rules_dry_run() above) for a
# hand-picked, bounded set of rules instead of one at a time -- e.g. the exact rules
# an analyst is about to enable, or a set they're curious about. Deliberately capped
# (SIGMA_VALIDATE_SELECTED_MAX) rather than left open-ended: this is the same
# execute-against-live_logs work api_rules_validate_all() specifically avoids for
# performance reasons (a full "Select All Visible" -> hundreds/thousands of rules
# would reproduce that exact multi-minute problem), so it only stays fast because the
# caller is choosing a small, deliberate set, not "every rule."
SIGMA_VALIDATE_SELECTED_MAX = 25
SIGMA_VALIDATE_SELECTED_PREVIEW_LIMIT = 5

@app.route('/api/rules/validate-selected', methods=['POST'])
@login_required
def api_rules_validate_selected():
    d = request.get_json() or {}
    rule_ids = d.get('rule_ids') or []
    if not isinstance(rule_ids, list) or not rule_ids:
        return jsonify({'error': 'rule_ids must be a non-empty list'}), 400
    if len(rule_ids) > SIGMA_VALIDATE_SELECTED_MAX:
        return jsonify({'error': f'Select at most {SIGMA_VALIDATE_SELECTED_MAX} rules at a time to test against real logs.'}), 400
    days = SIGMA_DRY_RUN_WINDOWS.get(d.get('window'), 7)

    db = get_db()
    from sigma_engine import dry_run_rule
    ioc_cache = {}
    results = []
    for rid in rule_ids:
        row = db.execute("SELECT title, rule_yaml FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
        if not row:
            results.append({'id': rid, 'title': f'(rule {rid})', 'ok': False, 'error': 'Rule not found'})
            continue
        exclusions = [dict(e) for e in db.execute(
            "SELECT field, operator, value FROM rule_exclusions WHERE rule_id = ? AND enabled = 1", (rid,)
        ).fetchall()]
        try:
            dr = dry_run_rule(db, row['rule_yaml'], days=days, exclusions=exclusions,
                               preview_limit=SIGMA_VALIDATE_SELECTED_PREVIEW_LIMIT, ioc_cache=ioc_cache)
            results.append({'id': rid, 'title': row['title'], 'ok': True, **dr})
        except Exception as e:
            results.append({'id': rid, 'title': row['title'], 'ok': False, 'error': f'Rule failed to parse or convert: {e}'})
    return jsonify({'window_days': days, 'results': results})

def _get_validated_technique_counts(db, days):
    """technique_id -> count of alerts in the last `days` whose triggering
    rule was tagged for that technique. Reads alerts.mitre_techniques
    (stamped by sigma_engine.py's alert-creation path using the same
    tag-extraction as techniques_for_tags()) -- historically accurate even
    if the rule's tags changed or the rule was deleted since. This is the
    one signal in the DB that distinguishes "a rule is enabled for this
    technique" from "this technique was actually detected" -- previously
    written but never read anywhere."""
    counts = {}
    rows = db.execute(
        "SELECT mitre_techniques FROM alerts WHERE timestamp >= datetime('now', ?) "
        "AND mitre_techniques IS NOT NULL AND mitre_techniques != ''",
        (f'-{days} days',)
    ).fetchall()
    for r in rows:
        for tid in (r['mitre_techniques'] or '').split(','):
            tid = tid.strip()
            if tid:
                counts[tid] = counts.get(tid, 0) + 1
    return counts

def _build_actor_technique_index(db):
    """technique_id -> [{id, name}] of threat/malware entities in the TI
    catalog known to use that technique, for cross-referencing against
    coverage gaps (a known adversary uses this technique and there's zero
    rule coverage for it -- the actionable prioritization signal)."""
    index = {}
    for e in _get_ti_entities(db):
        for tid in e['techniques']:
            index.setdefault(tid, []).append({'id': e['id'], 'name': e['name']})
    return index

def _build_mitre_coverage(rules, validated, actor_techniques):
    """Aggregates MITRE technique coverage across all rules (each a dict with
    'id', 'title', 'enabled', 'level', 'status' and 'mitre_techniques',
    matching _get_rules_cache()'s shape), grouped by tactic, into 4 tiers per
    technique:
      gap       - no rule mapped at all
      inactive  - rule(s) mapped, all currently disabled
      active    - an enabled rule exists, hasn't produced a validated alert
      validated - an enabled rule's alert actually fired (see `validated`,
                  from _get_validated_technique_counts)
    A rule that fired historically and was since disabled still lands in
    'inactive' -- its historical validated_count is kept on the technique
    for the drill-down to show as a footnote, rather than adding a 5th tier.
    Every curated technique appears even at zero coverage (so the grid shows
    gaps, not just hits); any technique tag found in a rule but missing from
    the curated table is still counted, under 'unmapped'. Each 'active'-tier
    technique also carries 'log_source_gap': True when every one of its
    enabled rules needs a log source this appliance doesn't actually ingest
    (see SIGMA_LOGSOURCE_INGESTED_APPS/_get_ingested_apps) -- again not a 5th
    tier, just a flag on top of 'active' for "looks covered, may never fire"."""
    from mitre_attack import TACTICS, TACTIC_LABELS, TECHNIQUES, _display_id

    enabled_counts = {}
    disabled_counts = {}
    # True once at least one enabled rule mapped to this (tactic, tid) has a log source
    # that's ingestible or of unknown ingestibility -- absence of a True entry here means
    # EVERY enabled rule is a confirmed non-ingestible log source (see log_source_gap
    # below). Tracked independent of rules_by_tech's 25-row cap so a technique with more
    # than 25 mapped rules still gets an accurate answer.
    enabled_log_source_ok = {}
    rules_by_tech = {}
    unmapped = {}
    for r in rules:
        for tech in r['mitre_techniques']:
            rule_ref = {'id': r['id'], 'title': r['title'], 'enabled': r['enabled'],
                        'level': r['level'], 'status': r['status'],
                        'log_source_ingestible': r.get('log_source_ingestible')}
            if tech['tactic'] == 'unmapped':
                entry = unmapped.setdefault(tech['id'], {'id': tech['id'], 'name': None, 'count': 0})
                if r['enabled']:
                    entry['count'] += 1
                continue
            key = (tech['tactic'], tech['id'])
            if r['enabled']:
                enabled_counts[key] = enabled_counts.get(key, 0) + 1
                if r.get('log_source_ingestible') is not False:
                    enabled_log_source_ok[key] = True
            else:
                disabled_counts[key] = disabled_counts.get(key, 0) + 1
            bucket = rules_by_tech.setdefault(tech['id'], [])
            if len(bucket) < 25:
                bucket.append(rule_ref)
            elif len(bucket) == 25:
                bucket.append({'more': True})

    seen_ids = set()
    tactics_out = []
    for tactic in TACTICS:
        techs = []
        tier_totals = {'gap': 0, 'inactive': 0, 'active': 0, 'validated': 0}
        for key, (name, t) in TECHNIQUES.items():
            if t != tactic:
                continue
            tid = _display_id(key)
            if tid in seen_ids:
                continue
            seen_ids.add(tid)
            enabled_n = enabled_counts.get((tactic, tid), 0)
            disabled_n = disabled_counts.get((tactic, tid), 0)
            validated_n = validated.get(tid, 0)
            if enabled_n == 0 and disabled_n == 0:
                tier = 'gap'
            elif enabled_n == 0:
                tier = 'inactive'
            elif validated_n == 0:
                tier = 'active'
            else:
                tier = 'validated'
            tier_totals[tier] += 1
            # Only meaningful for 'active' -- 'gap'/'inactive' are already flagged their
            # own way, and 'validated' means a real alert already proved the log source
            # works regardless of what this static mapping says.
            log_source_gap = tier == 'active' and not enabled_log_source_ok.get((tactic, tid), False)
            techs.append({
                'id': tid, 'name': name, 'count': enabled_n,
                'disabled_count': disabled_n, 'validated_count': validated_n,
                'tier': tier, 'rules': rules_by_tech.get(tid, []),
                'threat_actors': actor_techniques.get(tid, []) if tier == 'gap' else [],
                'log_source_gap': log_source_gap,
            })
        techs.sort(key=lambda x: (-x['count'], x['id']))
        tactics_out.append({
            'tactic': tactic, 'label': TACTIC_LABELS[tactic],
            'techniques': techs,
            'covered': sum(1 for x in techs if x['tier'] in ('active', 'validated')),
            'total': len(techs),
            'tiers': tier_totals,
        })

    return {
        'tactics': tactics_out,
        'unmapped': sorted(unmapped.values(), key=lambda x: -x['count']),
    }

@app.route('/api/mitre/coverage', methods=['GET'])
@login_required
def api_mitre_coverage():
    db = get_db()
    days = _dashboard_window_days(request)
    rules = _get_rules_cache(db)
    validated = _get_validated_technique_counts(db, days)
    actor_techniques = _build_actor_technique_index(db)
    return jsonify(_build_mitre_coverage(rules, validated, actor_techniques))

@app.route('/api/mitre/coverage/history', methods=['GET'])
@login_required
def api_mitre_coverage_history():
    # Backed by coverage_snapshots, written once a day by the cron-invoked
    # src/coverage_snapshot.py (see update.sh) -- coverage itself is always computed
    # live elsewhere; this is the one place a trend over time exists.
    days = request.args.get('days', 90, type=int)
    rows = get_db().execute(
        "SELECT snapshot_date, coverage_pct, techniques_total, gap_count, inactive_count, "
        "active_count, validated_count FROM coverage_snapshots "
        "WHERE snapshot_date >= date('now', ?) ORDER BY snapshot_date",
        (f'-{days} days',)
    ).fetchall()
    return jsonify({'snapshots': [dict(r) for r in rows]})

@app.route('/api/rules/<int:rid>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_rule_detail(rid):
    db = get_db()

    if request.method == 'GET':
        r = db.execute(
            "SELECT id, title, rule_yaml, original_yaml, upstream_yaml, enabled, source, cloned_from, created_by, created_at, updated_by, updated_at, compliance_tags "
            "FROM sigma_rules WHERE id = ?", (rid,)
        ).fetchone()
        if not r:
            return jsonify({"error": "Rule not found"}), 404
        out = dict(r)
        out['compliance_tags'] = [t for t in (r['compliance_tags'] or '').split(',') if t]
        return jsonify(out)

    err = require_permission('rules.manage')
    if err: return err

    if request.method == 'DELETE':
        title_row = db.execute("SELECT title FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
        db.execute("DELETE FROM sigma_rules WHERE id = ?", (rid,))
        db.execute("DELETE FROM sigma_rule_history WHERE rule_id = ?", (rid,))
        db.commit()
        invalidate_rules_cache()
        log_audit('rule_delete', 'rule', rid, title_row['title'] if title_row else None)
        return jsonify({"ok": 1})

    # PUT — update an existing rule's title/YAML. Sigma-sourced rules are directly
    # editable too (Revert to Default, POST /api/rules/<id>/revert, is the safety net
    # if an edit needs undoing) -- Clone remains available separately for forking off
    # a fully independent rule.
    existing = db.execute("SELECT rule_yaml, source FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
    if not existing:
        return jsonify({"error": "Rule not found"}), 404

    import yaml
    ry = (request.get_json() or {}).get('rule_yaml', '')
    try:
        parsed = yaml.safe_load(ry)
        t = parsed.get('title', 'Untitled') if isinstance(parsed, dict) else 'Untitled'
    except yaml.YAMLError as e:
        return jsonify({"error": f"Invalid rule YAML: {e}"}), 400
    db.execute(
        "INSERT INTO sigma_rule_history (rule_id, changed_by, old_yaml, new_yaml) VALUES (?, ?, ?, ?)",
        (rid, current_user.username, existing['rule_yaml'], ry)
    )
    db.execute(
        "UPDATE sigma_rules SET title = ?, rule_yaml = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (t, ry, current_user.username, rid)
    )
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/<int:rid>/clone', methods=['POST'])
@login_required
def api_rule_clone(rid):
    err = require_permission('rules.manage')
    if err: return err
    db = get_db()
    r = db.execute("SELECT title, rule_yaml FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    new_title = f"{r['title']} (Custom Copy)"
    cur = db.execute(
        "INSERT INTO sigma_rules (title, rule_yaml, enabled, source, cloned_from, created_by, created_at) "
        "VALUES (?, ?, 0, 'custom', ?, ?, CURRENT_TIMESTAMP)",
        (new_title, r['rule_yaml'], rid, current_user.username)
    )
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success", "id": cur.lastrowid})

@app.route('/api/rules/<int:rid>/revert', methods=['POST'])
@login_required
def api_rule_revert(rid):
    err = require_permission('rules.manage')
    if err: return err
    db = get_db()
    r = db.execute("SELECT title, rule_yaml, original_yaml FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
    if not r:
        return jsonify({"error": "Rule not found"}), 404
    if not r['original_yaml']:
        return jsonify({"error": "No default content recorded for this rule."}), 400
    if r['rule_yaml'] == r['original_yaml']:
        return jsonify({"error": "This rule already matches its default content."}), 400
    import yaml
    parsed = yaml.safe_load(r['original_yaml'])
    t = parsed.get('title', r['title']) if isinstance(parsed, dict) else r['title']
    # A revert IS an edit -- log it the same way PUT does, so the existing
    # history/diff viewer shows exactly when and by whom a rule was reverted.
    db.execute(
        "INSERT INTO sigma_rule_history (rule_id, changed_by, old_yaml, new_yaml) VALUES (?, ?, ?, ?)",
        (rid, current_user.username, r['rule_yaml'], r['original_yaml'])
    )
    db.execute(
        "UPDATE sigma_rules SET title = ?, rule_yaml = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (t, r['original_yaml'], current_user.username, rid)
    )
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/<int:rid>/history', methods=['GET'])
@login_required
def api_rule_history(rid):
    import difflib
    db = get_db()
    rows = db.execute(
        "SELECT changed_by, changed_at, old_yaml, new_yaml FROM sigma_rule_history WHERE rule_id = ? ORDER BY id DESC",
        (rid,)
    ).fetchall()
    out = []
    for row in rows:
        diff = '\n'.join(difflib.unified_diff(
            (row['old_yaml'] or '').splitlines(),
            (row['new_yaml'] or '').splitlines(),
            lineterm='', fromfile='before', tofile='after'
        ))
        out.append({"changed_by": row['changed_by'], "changed_at": row['changed_at'], "diff": diff})
    return jsonify(out)

@app.route('/api/rules/<int:rid>/compliance', methods=['PUT'])
@login_required
def api_rule_compliance(rid):
    # Compliance-framework tags are metadata layered on top of a rule, independent of
    # whether the rule's own YAML is Sigma-sourced (read-only) or custom — an admin can
    # tag either one without needing to clone a Sigma rule first.
    err = require_permission('rules.manage')
    if err: return err
    tags = (request.get_json() or {}).get('tags') or []
    if not isinstance(tags, list) or any(t not in COMPLIANCE_FRAMEWORKS for t in tags):
        return jsonify({"error": "Invalid compliance framework"}), 400
    db = get_db()
    if not db.execute("SELECT 1 FROM sigma_rules WHERE id = ?", (rid,)).fetchone():
        return jsonify({"error": "Rule not found"}), 404
    db.execute("UPDATE sigma_rules SET compliance_tags = ? WHERE id = ?", (','.join(sorted(set(tags))), rid))
    db.commit()
    invalidate_rules_cache()
    log_audit('rule_compliance_tag', 'rule', rid, ','.join(sorted(set(tags))) or '(cleared)')
    return jsonify({"status": "success"})

@app.route('/api/rules/import/sigmahq', methods=['POST'])
@login_required
def api_rules_import_sigmahq():
    err = require_permission('rules.manage')
    if err: return err
    try:
        stats = _run_sigmahq_import()
    except Exception as e:
        return jsonify({"error": f"Import failed: {e}"}), 500
    invalidate_rules_cache()
    log_audit('sigmahq_import', 'rule', None, f"inserted={stats['inserted']}, updated={stats['updated']}, skipped={stats['skipped']}, errors={stats['errors']}, upstream_drift={stats['upstream_drift']}")
    return jsonify({"status": "success", **stats})

@app.route('/api/rules/<int:rid>/toggle', methods=['PUT'])
@login_required
def api_r_tog(rid):
    err = require_permission('rules.manage')
    if err: return err
    db=get_db(); db.execute("UPDATE sigma_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id=?", (rid,)); db.commit(); invalidate_rules_cache()
    log_audit('rule_toggle', 'rule', rid)
    return jsonify({"ok":1})

@app.route('/api/rules/bulk_update', methods=['PUT'])
@login_required
def api_rules_bulk():
    err = require_permission('rules.manage')
    if err: return err
    data = request.get_json()
    ids = data.get('ids', [])
    enable = 1 if data.get('enable') else 0
    if ids:
        db = get_db()
        placeholders = ','.join('?' for _ in ids)
        db.execute(f"UPDATE sigma_rules SET enabled = ? WHERE id IN ({placeholders})", [enable] + ids)
        db.commit(); invalidate_rules_cache()
        log_audit('rule_bulk_toggle', 'rule', None, f"{'enabled' if enable else 'disabled'} {len(ids)} rule(s): {ids}")
    return jsonify({"ok": 1})

# ==========================================
# DETECTION TUNING — rule performance, exclusions, severity overrides
# ==========================================
@app.route('/api/rules/tuning')
@login_required
def api_rules_tuning():
    global TUNING_CACHE, TUNING_CACHE_TIME
    import time, re
    if TUNING_CACHE is not None and (time.time() - TUNING_CACHE_TIME) < RULES_CACHE_TTL:
        return jsonify(TUNING_CACHE)

    db = get_db()
    rows = db.execute("""
        SELECT sr.id, sr.title, sr.source, sr.enabled, sr.rule_yaml, sr.severity_override,
               sr.auto_case, sr.auto_case_template_id,
               COALESCE(c7.cnt, 0) as alerts_7d,
               COALESCE(c30.cnt, 0) as alerts_30d,
               COALESCE(ctot.cnt, 0) as alerts_total,
               lt.last_triggered,
               COALESCE(ec.cnt, 0) as exclusion_count
        FROM sigma_rules sr
        LEFT JOIN (SELECT rule_id, COUNT(*) cnt FROM alerts WHERE timestamp >= datetime('now', '-7 days') GROUP BY rule_id) c7 ON c7.rule_id = sr.id
        LEFT JOIN (SELECT rule_id, COUNT(*) cnt FROM alerts WHERE timestamp >= datetime('now', '-30 days') GROUP BY rule_id) c30 ON c30.rule_id = sr.id
        LEFT JOIN (SELECT rule_id, COUNT(*) cnt FROM alerts GROUP BY rule_id) ctot ON ctot.rule_id = sr.id
        LEFT JOIN (SELECT rule_id, MAX(timestamp) last_triggered FROM alerts GROUP BY rule_id) lt ON lt.rule_id = sr.id
        LEFT JOIN (SELECT rule_id, COUNT(*) cnt FROM rule_exclusions WHERE enabled = 1 GROUP BY rule_id) ec ON ec.rule_id = sr.id
        ORDER BY alerts_30d DESC, sr.title ASC
    """).fetchall()

    out = []
    for r in rows:
        ry = r['rule_yaml'] or ''
        level = (_extract_yaml_field('level', ry) or 'medium').lower()
        out.append({
            "id": r['id'], "title": r['title'], "source": r['source'] or 'sigma',
            "enabled": r['enabled'], "level": level, "severity_override": r['severity_override'],
            "auto_case": r['auto_case'], "auto_case_template_id": r['auto_case_template_id'],
            "alerts_7d": r['alerts_7d'], "alerts_30d": r['alerts_30d'], "alerts_total": r['alerts_total'],
            "last_triggered": r['last_triggered'], "exclusion_count": r['exclusion_count']
        })
    TUNING_CACHE = out
    TUNING_CACHE_TIME = time.time()
    return jsonify(TUNING_CACHE)

@app.route('/api/rules/<int:rid>/severity', methods=['PUT'])
@login_required
def api_rule_severity(rid):
    err = require_permission('rules.manage')
    if err: return err
    sev = (request.get_json() or {}).get('severity') or None
    if sev and sev not in ('critical', 'high', 'medium', 'low', 'informational'):
        return jsonify({"error": "Invalid severity"}), 400
    db = get_db()
    if not db.execute("SELECT 1 FROM sigma_rules WHERE id = ?", (rid,)).fetchone():
        return jsonify({"error": "Rule not found"}), 404
    db.execute("UPDATE sigma_rules SET severity_override = ? WHERE id = ?", (sev, rid))
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/<int:rid>/autocase', methods=['PUT'])
@login_required
def api_rule_autocase(rid):
    err = require_permission('rules.manage')
    if err: return err
    d = request.get_json() or {}
    enabled = 1 if d.get('auto_case') else 0
    template_id = d.get('auto_case_template_id') or None
    db = get_db()
    if not db.execute("SELECT 1 FROM sigma_rules WHERE id = ?", (rid,)).fetchone():
        return jsonify({"error": "Rule not found"}), 404
    if template_id and not db.execute("SELECT 1 FROM case_templates WHERE id = ?", (template_id,)).fetchone():
        return jsonify({"error": "Template not found"}), 400
    db.execute("UPDATE sigma_rules SET auto_case = ?, auto_case_template_id = ? WHERE id = ?", (enabled, template_id, rid))
    db.commit()
    invalidate_rules_cache()
    log_audit('rule_autocase_update', 'rule', rid, f"auto_case={enabled} template_id={template_id}")
    return jsonify({"status": "success"})

@app.route('/api/rules/<int:rid>/exclusions', methods=['GET', 'POST'])
@login_required
def api_rule_exclusions(rid):
    db = get_db()
    if request.method == 'GET':
        rows = db.execute(
            "SELECT id, rule_id, field, operator, value, description, enabled, created_by, created_at "
            "FROM rule_exclusions WHERE rule_id = ? ORDER BY id DESC", (rid,)
        ).fetchall()
        return jsonify([dict(row) for row in rows])

    err = require_permission('rules.manage')
    if err: return err
    data = request.get_json() or {}
    field = (data.get('field') or '').strip()
    operator = (data.get('operator') or 'contains').strip()
    value = (data.get('value') or '').strip()
    description = (data.get('description') or '').strip()
    if not field or not value:
        return jsonify({"error": "Field and value are required"}), 400
    if operator not in ('equals', 'contains', 'startswith', 'endswith'):
        return jsonify({"error": "Invalid operator"}), 400
    if not db.execute("SELECT 1 FROM sigma_rules WHERE id = ?", (rid,)).fetchone():
        return jsonify({"error": "Rule not found"}), 404
    db.execute(
        "INSERT INTO rule_exclusions (rule_id, field, operator, value, description, enabled, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP)",
        (rid, field, operator, value, description, current_user.username)
    )
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/exclusions/<int:eid>', methods=['PUT', 'DELETE'])
@login_required
def api_rule_exclusion_detail(eid):
    err = require_permission('rules.manage')
    if err: return err
    db = get_db()
    if not db.execute("SELECT 1 FROM rule_exclusions WHERE id = ?", (eid,)).fetchone():
        return jsonify({"error": "Exclusion not found"}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM rule_exclusions WHERE id = ?", (eid,))
        db.commit()
        invalidate_rules_cache()
        return jsonify({"ok": 1})

    data = request.get_json() or {}
    if 'enabled' in data:
        db.execute("UPDATE rule_exclusions SET enabled = ? WHERE id = ?", (1 if data['enabled'] else 0, eid))
    else:
        operator = (data.get('operator') or 'contains').strip()
        if operator not in ('equals', 'contains', 'startswith', 'endswith'):
            return jsonify({"error": "Invalid operator"}), 400
        db.execute(
            "UPDATE rule_exclusions SET field = ?, operator = ?, value = ?, description = ? WHERE id = ?",
            ((data.get('field') or '').strip(), operator, (data.get('value') or '').strip(),
             (data.get('description') or '').strip(), eid)
        )
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/yara/scan', methods=['POST'])
@login_required
def api_yara_scan():
    # Bucketed with hunting/investigation work (Tier 3), not with rule-authoring --
    # this uploads an arbitrary file to scan against existing YARA signatures, it
    # doesn't manage the signature library itself.
    err = require_permission('rules.manage')
    if err: return err
    f = request.files['file']
    p = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
    try:
        f.save(p); sr = scan_file(p); db = get_db()
        db.execute("INSERT INTO events (timestamp, app_name, severity, message, raw_json) VALUES (datetime('now'), 'yara_scanner', 'info', ?, ?)", (f"Scan: {f.filename}", json.dumps(sr)))
        db.commit(); os.remove(p); return jsonify(sr)
    except Exception as e:
        if os.path.exists(p): os.remove(p)
        return jsonify({"error": str(e)}), 500


# ==========================================
# REPORTING ENGINE ROUTES
# ==========================================
@app.route('/reports')
@login_required
def reports(): return redirect(url_for('dash', tab='reports'))

# Keyed off the report_history row's id, not a user-supplied filename -- the old
# <filename> route took whatever the client sent straight into send_from_directory
# with no validation at all (a real path-traversal bug). Looking the filename up
# server-side from the id removes user-controlled path input entirely rather than
# just sanitizing it, and doubles as the natural place to detect a file that's been
# deleted from disk since it was generated.
@app.route('/reports/download/<int:history_id>')
@login_required
def download_report(history_id):
    from flask import send_from_directory
    row = get_db().execute("SELECT filename FROM report_history WHERE id = ?", (history_id,)).fetchone()
    if not row or not os.path.exists(os.path.join('/opt/micro-dfir/reports', row['filename'])):
        flash("Report file not found.", "warning")
        return redirect(url_for('dash', tab='reports'))
    return send_from_directory('/opt/micro-dfir/reports', row['filename'], as_attachment=True)

REPORT_TYPES = ('security', 'compliance', 'audit')

@app.route('/reports/generate', methods=['POST'])
@login_required
def trigger_report():
    if not validate_csrf():
        return redirect(url_for('dash', tab='reports'))
    report_type = request.form.get('type', 'security')
    if report_type not in REPORT_TYPES:
        report_type = 'security'
    try:
        subprocess.run(
            ["/opt/micro-dfir/venv/bin/python3", "/opt/micro-dfir/src/generate_report.py",
             report_type, f"--user={current_user.username}", "--source=manual"],
            check=True, timeout=120
        )
        log_audit('report_generate', 'report', report_type)
        flash("Report successfully generated!", "success")
    except subprocess.TimeoutExpired:
        flash("Report generation timed out.", "danger")
    except Exception as e:
        flash(f"Failed to generate report: {str(e)}", "danger")
    return redirect(url_for('dash', tab='reports'))

@app.route('/api/reports/history', methods=['GET'])
@login_required
def api_report_history():
    # Case reports are scoped to their own case (see /api/cases/<id>/reports) and
    # deliberately excluded here -- this fleet-wide list is compliance/security/audit
    # reports, a different audience, and could otherwise be crowded out of its own
    # 100-row cap by a busy caseload.
    rows = [dict(r) for r in get_db().execute(
        "SELECT id, report_type, filename, status, triggered_by, trigger_source, "
        "started_at, completed_at, file_size_bytes, error_message "
        "FROM report_history WHERE case_id IS NULL ORDER BY id DESC LIMIT 100"
    ).fetchall()]
    for r in rows:
        r['file_exists'] = bool(r['filename']) and os.path.exists(os.path.join('/opt/micro-dfir/reports', r['filename']))
    return jsonify({'history': rows})

@app.route('/api/cases/<int:cid>/reports', methods=['GET', 'POST'])
@login_required
def api_case_reports(cid):
    db = get_db()
    case = db.execute("SELECT title FROM cases WHERE id = ?", (cid,)).fetchone()
    if not case:
        return jsonify({"error": "Case not found"}), 404

    if request.method == 'GET':
        rows = [dict(r) for r in db.execute(
            "SELECT id, filename, status, triggered_by, started_at, completed_at, file_size_bytes, error_message "
            "FROM report_history WHERE case_id = ? ORDER BY id DESC LIMIT 20", (cid,)
        ).fetchall()]
        for r in rows:
            r['file_exists'] = bool(r['filename']) and os.path.exists(os.path.join('/opt/micro-dfir/reports', r['filename']))
        return jsonify(rows)

    # Matches generate_report.py's own started_at = datetime.now().isoformat() exactly --
    # the two scripts' clocks/formats have to agree for the >= lookup below to be reliable.
    started_at = datetime.now().isoformat()
    try:
        subprocess.run(
            ["/opt/micro-dfir/venv/bin/python3", "/opt/micro-dfir/src/generate_report.py",
             "case", f"--case-id={cid}", f"--user={current_user.username}", "--source=manual"],
            check=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Report generation timed out."}), 500
    except subprocess.CalledProcessError:
        return jsonify({"error": "Report generation failed. Check the server logs."}), 500
    # generate_report.py records its own report_history row (case_id/started_at/etc. --
    # same single-chokepoint pattern the fleet-wide reports use) -- read back whichever
    # row it just wrote rather than duplicating that bookkeeping here.
    row = db.execute(
        "SELECT id, filename, status, error_message FROM report_history "
        "WHERE case_id = ? AND started_at >= ? ORDER BY id DESC LIMIT 1", (cid, started_at)
    ).fetchone()
    if not row or row['status'] != 'success':
        return jsonify({"error": (row['error_message'] if row else None) or "Report generation failed."}), 500
    log_audit('case_report_generate', 'case', cid, case['title'])
    return jsonify({"status": "success", "history_id": row['id'], "filename": row['filename']})

@app.route('/api/settings/report-branding', methods=['GET', 'POST'])
@login_required
def api_report_branding():
    db = get_db()
    if request.method == 'GET':
        return jsonify(get_report_branding_config(db))
    err = require_permission('settings.reports.manage')
    if err: return err
    cfg = get_report_branding_config(db)
    cfg['company_name'] = (request.form.get('company_name') or REPORT_BRANDING_DEFAULTS['company_name']).strip()[:120]
    cfg['footer_text'] = (request.form.get('footer_text') or REPORT_BRANDING_DEFAULTS['footer_text']).strip()[:200]
    accent = (request.form.get('accent_color') or '').strip()
    if re.match(r'^#[0-9a-fA-F]{6}$', accent):
        cfg['accent_color'] = accent
    logo_file = request.files.get('logo')
    if logo_file and logo_file.filename:
        ext = logo_file.filename.rsplit('.', 1)[-1].lower() if '.' in logo_file.filename else ''
        if ext not in REPORT_BRANDING_ALLOWED_LOGO_EXT:
            return jsonify({'error': f"Logo must be one of: {', '.join(sorted(REPORT_BRANDING_ALLOWED_LOGO_EXT))}"}), 400
        os.makedirs(REPORT_BRANDING_DIR, exist_ok=True)
        fname = secure_filename(f"logo.{ext}")
        logo_file.save(os.path.join(REPORT_BRANDING_DIR, fname))
        cfg['logo_filename'] = fname
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('report_branding_config', ?)", (json.dumps(cfg),))
    db.commit()
    log_audit('report_branding_change', 'settings')
    return jsonify({'status': 'success', 'config': cfg})

@app.route('/settings/branding/logo')
@login_required
def report_branding_logo():
    from flask import send_from_directory
    cfg = get_report_branding_config(get_db())
    if not cfg.get('logo_filename'):
        return '', 404
    return send_from_directory(REPORT_BRANDING_DIR, cfg['logo_filename'])

# Report scheduling -- same settings-table JSON-blob pattern as branding/risk config
# above. Only 'security' defaults to 'monthly' so a fresh install's out-of-the-box
# behavior matches what install.sh used to hardcode directly into crontab; compliance
# and audit start 'off' since they were always on-demand-only before this existed.
# Mirrored in src/sync_report_schedule.py (a standalone script, same reasoning as
# generate_report.py's own duplicated REPORT_BRANDING_DEFAULTS -- it has no Flask app
# context and is invoked once at deploy time, not imported from here).
REPORT_SCHEDULE_FREQUENCIES = ('off', 'weekly', 'monthly')
REPORT_SCHEDULE_DEFAULTS = {'security': 'monthly', 'compliance': 'off', 'audit': 'off'}
REPORT_SCHEDULE_CRON = {
    'weekly': '0 6 * * 1',   # Monday 06:00 -- lands before the start of the work week
    'monthly': '0 1 1 * *',  # 1st of month 01:00 -- matches install.sh's old convention
}

def get_report_schedule_config(db):
    import copy as _copy
    cfg = _copy.deepcopy(REPORT_SCHEDULE_DEFAULTS)
    row = db.execute("SELECT value FROM settings WHERE key = 'report_schedule_config'").fetchone()
    if row and row['value']:
        try:
            saved = json.loads(row['value'])
            cfg.update({k: v for k, v in saved.items() if k in REPORT_TYPES and v in REPORT_SCHEDULE_FREQUENCIES})
        except (json.JSONDecodeError, TypeError):
            pass
    return cfg

# Rewrites root's crontab entries for every report type's generate_report.py
# invocation, replacing whatever was there -- mirrors the idempotent
# `crontab -l | grep -v <marker> ; echo <newline> | crontab -` pattern update.sh already
# uses for the GeoIP cron job, except marker-per-report-type so multiple independent
# schedules coexist without clobbering each other, and any type set back to 'off' has
# its line simply not re-added (not left stale). Any OTHER cron line (ueba_engine.py,
# taxii_client.py, geoip_update.py) is left completely untouched. Uses argv-list
# subprocess (no shell=True) so there's no shell-injection surface, and report types
# are drawn from the fixed REPORT_TYPES tuple, never free-text from a request.
#
# Concurrency note: `crontab -l` then `crontab -` is a read-modify-write race if two
# saves happen at once -- accepted as-is for this single-admin appliance rather than
# adding a cross-process lock for a scenario this unlikely.
def apply_report_schedule_to_crontab(schedule_cfg):
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        existing_lines = result.stdout.splitlines() if result.returncode == 0 else []
    except FileNotFoundError:
        return False, 'crontab command not found'
    kept_lines = [l for l in existing_lines if 'generate_report.py' not in l]
    new_lines = []
    for report_type in REPORT_TYPES:
        freq = schedule_cfg.get(report_type, 'off')
        if freq not in ('weekly', 'monthly'):
            continue
        cmd = (f"/opt/micro-dfir/venv/bin/python3 /opt/micro-dfir/src/generate_report.py "
               f"{report_type} --source=scheduled >> /var/log/microdfir-report.log 2>&1")
        new_lines.append(f"{REPORT_SCHEDULE_CRON[freq]} {cmd}  # microdfir-report:{report_type}")
    final_crontab = '\n'.join(kept_lines + new_lines)
    if final_crontab and not final_crontab.endswith('\n'):
        final_crontab += '\n'
    proc = subprocess.run(['crontab', '-'], input=final_crontab, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, proc.stderr
    return True, None

@app.route('/api/settings/report-schedule', methods=['GET', 'POST'])
@login_required
def api_report_schedule():
    db = get_db()
    if request.method == 'GET':
        return jsonify(get_report_schedule_config(db))
    err = require_permission('settings.reports.manage')
    if err: return err
    d = request.json or {}
    cfg = get_report_schedule_config(db)
    for report_type in REPORT_TYPES:
        if report_type in d and d[report_type] in REPORT_SCHEDULE_FREQUENCIES:
            cfg[report_type] = d[report_type]
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('report_schedule_config', ?)", (json.dumps(cfg),))
    db.commit()
    ok, err = apply_report_schedule_to_crontab(cfg)
    log_audit('report_schedule_change', 'settings', None, json.dumps(cfg) + ('' if ok else f' (crontab write failed: {err})'))
    if not ok:
        return jsonify({'status': 'partial', 'config': cfg, 'warning': f'Settings saved but crontab update failed: {err}'})
    return jsonify({'status': 'success', 'config': cfg})

_SMTP_PASS_PLACEHOLDER = '••••••••'

@app.route('/api/settings/alert-notifications', methods=['GET', 'POST'])
@login_required
def api_alert_notification_settings():
    from notifications import get_alert_notification_config, ALERT_NOTIFICATION_DEFAULTS
    db = get_db()
    if request.method == 'GET':
        cfg = get_alert_notification_config(db)
        # Never echo the real secret back down to the browser -- the Save form only ever
        # sees a placeholder, and leaving it unchanged (see POST below) keeps the real
        # value intact rather than overwriting it with the placeholder string itself.
        cfg['smtp_pass'] = _SMTP_PASS_PLACEHOLDER if cfg.get('smtp_pass') else ''
        return jsonify(cfg)
    err = require_permission('settings.notifications.manage')
    if err: return err
    d = request.json or {}
    cfg = get_alert_notification_config(db)
    for k in ALERT_NOTIFICATION_DEFAULTS:
        if k not in d:
            continue
        if k == 'smtp_pass' and d[k] == _SMTP_PASS_PLACEHOLDER:
            continue  # unchanged placeholder from the GET above -- keep the existing secret
        cfg[k] = d[k]
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('alert_notification_config', ?)", (json.dumps(cfg),))
    db.commit()
    log_audit('alert_notification_settings_change', 'settings', None,
              f"smtp_enabled={cfg['smtp_enabled']} webhook_enabled={cfg['webhook_enabled']} min_severity={cfg['min_severity']}")
    return jsonify({'status': 'success'})

@app.route('/api/settings/alert-notifications/test', methods=['POST'])
@login_required
def api_alert_notification_test():
    err = require_permission('settings.notifications.manage')
    if err: return err
    from notifications import get_alert_notification_config, send_alert_notification
    db = get_db()
    cfg = get_alert_notification_config(db)
    result = send_alert_notification(cfg, {
        'rule_title': 'Test Notification', 'severity': 'High', 'host': 'test-host',
        'username': current_user.username, 'source_ip': '203.0.113.1',
        'message': 'This is a test alert notification triggered manually from Settings.',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })
    if not result:
        return jsonify({'error': 'No channel is enabled -- turn on Email and/or Webhook first.'}), 400
    return jsonify(result)

# ==========================================
# UEBA — BEHAVIORAL ANOMALY DETECTIONS
# ==========================================
@app.route('/ueba')
@login_required
def ueba():
    return render_template('ueba.html', current_user=current_user)

@app.route('/ueba/tuning')
@login_required
def ueba_tuning():
    # Anomaly Detections and Anomaly Tuning are now tabs on one page — redirect old
    # bookmarks/links straight to the right tab instead of 404ing.
    return redirect(url_for('ueba', tab='tuning'))

@app.route('/api/ueba/baselines')
@login_required
def api_ueba_baselines():
    db = get_db()
    entity_type = request.args.get('type')
    if entity_type and entity_type not in ('host', 'user'):
        return jsonify({"error": "Invalid entity type"}), 400
    query = "SELECT entity_type, entity_id, current_count, baseline_avg, baseline_stddev, threshold, is_anomalous, excluded, days_seen, baseline_mode, computed_at FROM ueba_entity_baselines"
    params = ()
    if entity_type:
        query += " WHERE entity_type = ?"
        params = (entity_type,)
    query += " ORDER BY (CAST(current_count AS REAL) / MAX(baseline_avg, 1)) DESC"
    try:
        rows = [dict(r) for r in db.execute(query, params).fetchall()]
    except Exception:
        rows = []
    computed_at = rows[0]['computed_at'] if rows else None
    return jsonify({'baselines': rows, 'computed_at': computed_at})

@app.route('/api/ueba/exclusions', methods=['GET', 'POST'])
@login_required
def api_ueba_exclusions():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute(
            "SELECT id, entity_type, entity_id, description, enabled, created_by, created_at FROM ueba_exclusions ORDER BY id DESC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    err = require_permission('ueba.config.manage')
    if err: return err
    data = request.get_json() or {}
    entity_type = (data.get('entity_type') or '').strip()
    entity_id = (data.get('entity_id') or '').strip()
    description = (data.get('description') or '').strip()
    if entity_type not in ('host', 'user'):
        return jsonify({"error": "Invalid entity type"}), 400
    if not entity_id:
        return jsonify({"error": "Entity ID is required"}), 400
    db.execute(
        "INSERT INTO ueba_exclusions (entity_type, entity_id, description, enabled, created_by, created_at) VALUES (?, ?, ?, 1, ?, CURRENT_TIMESTAMP)",
        (entity_type, entity_id, description, current_user.username)
    )
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/ueba/exclusions/<int:eid>', methods=['PUT', 'DELETE'])
@login_required
def api_ueba_exclusion_detail(eid):
    err = require_permission('ueba.config.manage')
    if err: return err
    db = get_db()
    if not db.execute("SELECT 1 FROM ueba_exclusions WHERE id = ?", (eid,)).fetchone():
        return jsonify({"error": "Exclusion not found"}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM ueba_exclusions WHERE id = ?", (eid,))
        db.commit()
        return jsonify({"ok": 1})

    data = request.get_json() or {}
    db.execute("UPDATE ueba_exclusions SET enabled = ? WHERE id = ?", (1 if data.get('enabled') else 0, eid))
    db.commit()
    return jsonify({"status": "success"})

# Applied at aggregation time (api_ueba_risk_scores' SUM(points) query) rather than at
# every one of the ~10 INSERT INTO risk_score_events call sites across ueba_engine.py --
# one place to change, and the raw per-event points stored in risk_score_events stay an
# honest, un-weighted record of what actually happened regardless of an asset/identity
# tag added or changed after the fact.
CRITICALITY_MULTIPLIERS = {'standard': 1.0, 'important': 1.5, 'critical': 2.0}

@app.route('/api/assets', methods=['GET', 'POST'])
@login_required
def api_assets():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute("SELECT id, host, criticality, owner, created_by, created_at FROM assets ORDER BY host").fetchall()
        return jsonify([dict(r) for r in rows])

    err = require_permission('assets.manage')
    if err: return err
    data = request.get_json() or {}
    host = (data.get('host') or '').strip()
    criticality = (data.get('criticality') or 'standard').strip()
    owner = (data.get('owner') or '').strip()
    if not host:
        return jsonify({"error": "Host is required"}), 400
    if criticality not in CRITICALITY_MULTIPLIERS:
        return jsonify({"error": f"criticality must be one of {', '.join(CRITICALITY_MULTIPLIERS)}"}), 400
    if db.execute("SELECT 1 FROM assets WHERE host = ?", (host,)).fetchone():
        return jsonify({"error": f"'{host}' already has an asset entry -- edit it instead of adding a duplicate"}), 400
    db.execute(
        "INSERT INTO assets (host, criticality, owner, created_by) VALUES (?, ?, ?, ?)",
        (host, criticality, owner, current_user.username)
    )
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/assets/<int:aid>', methods=['PUT', 'DELETE'])
@login_required
def api_asset_detail(aid):
    err = require_permission('assets.manage')
    if err: return err
    db = get_db()
    if not db.execute("SELECT 1 FROM assets WHERE id = ?", (aid,)).fetchone():
        return jsonify({"error": "Asset not found"}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM assets WHERE id = ?", (aid,))
        db.commit()
        return jsonify({"ok": 1})

    data = request.get_json() or {}
    existing = db.execute("SELECT criticality, owner FROM assets WHERE id = ?", (aid,)).fetchone()
    criticality = (data['criticality'].strip() if 'criticality' in data and data['criticality'] else existing['criticality'])
    if criticality not in CRITICALITY_MULTIPLIERS:
        return jsonify({"error": f"criticality must be one of {', '.join(CRITICALITY_MULTIPLIERS)}"}), 400
    owner = data['owner'].strip() if 'owner' in data else (existing['owner'] or '')
    db.execute("UPDATE assets SET criticality = ?, owner = ? WHERE id = ?", (criticality, owner, aid))
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/identities', methods=['GET', 'POST'])
@login_required
def api_identities():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute("SELECT id, username, department, privileged, created_by, created_at FROM identities ORDER BY username").fetchall()
        return jsonify([dict(r) for r in rows])

    err = require_permission('assets.manage')
    if err: return err
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    department = (data.get('department') or '').strip()
    privileged = bool(data.get('privileged'))
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if db.execute("SELECT 1 FROM identities WHERE username = ?", (username,)).fetchone():
        return jsonify({"error": f"'{username}' already has an identity entry -- edit it instead of adding a duplicate"}), 400
    db.execute(
        "INSERT INTO identities (username, department, privileged, created_by) VALUES (?, ?, ?, ?)",
        (username, department, privileged, current_user.username)
    )
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/identities/<int:iid>', methods=['PUT', 'DELETE'])
@login_required
def api_identity_detail(iid):
    err = require_permission('assets.manage')
    if err: return err
    db = get_db()
    if not db.execute("SELECT 1 FROM identities WHERE id = ?", (iid,)).fetchone():
        return jsonify({"error": "Identity not found"}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM identities WHERE id = ?", (iid,))
        db.commit()
        return jsonify({"ok": 1})

    data = request.get_json() or {}
    existing = db.execute("SELECT department, privileged FROM identities WHERE id = ?", (iid,)).fetchone()
    department = data['department'].strip() if 'department' in data else (existing['department'] or '')
    privileged = bool(data['privileged']) if 'privileged' in data else bool(existing['privileged'])
    db.execute(
        "UPDATE identities SET department = ?, privileged = ? WHERE id = ?",
        (department, privileged, iid)
    )
    db.commit()
    return jsonify({"status": "success"})

# 'ueba_event' rather than 'anomaly' to match the events table this actually points at --
# UNIFIED_LOGS_SQL's log_type for these rows is 'anomaly', but that's a display label,
# not the underlying table name, so the two are kept intentionally distinct here.
CASE_ITEM_TYPES = {'alert': 'alerts', 'ueba_event': 'events', 'command_result': 'agent_commands'}
CASE_TLP_VALUES = ('clear', 'green', 'amber', 'amber-strict', 'red')
CASE_PAP_VALUES = ('clear', 'green', 'amber', 'red')
# 'suspected' is the default starting state for anything an analyst adds to a case's
# asset list -- there's no separate "unknown" state since adding it to the case at all
# already implies at least a suspicion it's involved.
CASE_ASSET_STATUSES = ('suspected', 'confirmed', 'cleared')
CASE_SEVERITY_VALUES = ('critical', 'high', 'medium', 'low')
# Deliberately separate from the open/closed `status` -- see migrate_case_severity()'s
# comment for why the two aren't merged into one enum.
CASE_WORKFLOW_STATES = ('new', 'investigating', 'awaiting_input', 'resolved')

def _log_case_event(db, cid, event_type, detail=None):
    # Append-only -- never UPDATEd/DELETEd (except cascade-deleted alongside the case
    # itself), so this is always a truthful record of what actually happened, in order.
    # current_user is unavailable in its normal (logged-in) sense for the one caller with
    # no real session behind it -- the scheduled-playbook internal route, hit by
    # sigma_engine.py's background loop, not a browser -- where it's Flask-Login's
    # AnonymousUserMixin (no .username attribute) rather than a real user.
    try:
        actor = current_user.username
    except AttributeError:
        actor = 'scheduler'
    db.execute(
        "INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, ?, ?, ?)",
        (cid, actor, event_type, detail)
    )

# Closed = the formal administrative closing (read-only, still reopenable if new
# evidence surfaces) -- see the case-detail PUT handler below for the one path that's
# still allowed to write to a closed case (leaving 'closed' in that same request).
def _require_open_case(db, cid):
    case = db.execute("SELECT status FROM cases WHERE id = ?", (cid,)).fetchone()
    if not case:
        return jsonify({"error": "Case not found"}), 404
    if case['status'] == 'closed':
        return jsonify({"error": "This case is closed. Reopen it (change Status) to make changes."}), 403
    return None

@app.route('/api/case-queues', methods=['GET', 'POST'])
@login_required
def api_case_queues():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute(
            "SELECT q.id, q.name, q.description, q.created_by, q.created_at, "
            "(SELECT COUNT(*) FROM cases WHERE queue_id = q.id AND status = 'open') as open_case_count, "
            "(SELECT COUNT(*) FROM cases WHERE queue_id = q.id) as total_case_count "
            "FROM case_queues q ORDER BY q.name"
        ).fetchall()
        out = []
        for r in rows:
            members = [m['username'] for m in db.execute("SELECT username FROM queue_members WHERE queue_id = ? ORDER BY username", (r['id'],)).fetchall()]
            out.append({**dict(r), 'members': members})
        return jsonify(out)

    err = require_permission('cases.queues.manage')
    if err: return err
    d = request.json or {}
    name = (d.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if db.execute("SELECT 1 FROM case_queues WHERE name = ?", (name,)).fetchone():
        return jsonify({'error': f'A queue named "{name}" already exists'}), 400
    db.execute("INSERT INTO case_queues (name, description, created_by) VALUES (?, ?, ?)", (name, (d.get('description') or '').strip(), current_user.username))
    db.commit()
    log_audit('queue_create', 'case_queue', name)
    return jsonify({'status': 'success'})

@app.route('/api/case-queues/<int:qid>', methods=['PUT', 'DELETE'])
@login_required
def api_case_queue_detail(qid):
    err = require_permission('cases.queues.manage')
    if err: return err
    db = get_db()
    existing = db.execute("SELECT name FROM case_queues WHERE id = ?", (qid,)).fetchone()
    if not existing:
        return jsonify({'error': 'Queue not found'}), 404

    if request.method == 'DELETE':
        db.execute("UPDATE cases SET queue_id = NULL WHERE queue_id = ?", (qid,))
        db.execute("DELETE FROM queue_members WHERE queue_id = ?", (qid,))
        db.execute("DELETE FROM case_queues WHERE id = ?", (qid,))
        db.commit()
        log_audit('queue_delete', 'case_queue', existing['name'])
        return jsonify({'ok': 1})

    d = request.json or {}
    name = (d.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if db.execute("SELECT 1 FROM case_queues WHERE name = ? AND id != ?", (name, qid)).fetchone():
        return jsonify({'error': f'A queue named "{name}" already exists'}), 400
    db.execute("UPDATE case_queues SET name = ?, description = ? WHERE id = ?", (name, (d.get('description') or '').strip(), qid))
    db.commit()
    log_audit('queue_update', 'case_queue', name)
    return jsonify({'status': 'success'})

@app.route('/api/case-queues/<int:qid>/members', methods=['POST', 'DELETE'])
@login_required
def api_case_queue_members(qid):
    err = require_permission('cases.queues.manage')
    if err: return err
    db = get_db()
    if not db.execute("SELECT 1 FROM case_queues WHERE id = ?", (qid,)).fetchone():
        return jsonify({'error': 'Queue not found'}), 404
    username = ((request.json or {}).get('username') or '').strip()
    if not username:
        return jsonify({'error': 'username is required'}), 400
    if request.method == 'POST':
        if not db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            return jsonify({'error': 'User not found'}), 400
        db.execute("INSERT OR IGNORE INTO queue_members (queue_id, username) VALUES (?, ?)", (qid, username))
    else:
        db.execute("DELETE FROM queue_members WHERE queue_id = ? AND username = ?", (qid, username))
    db.commit()
    return jsonify({'status': 'success'})

@app.route('/api/cases', methods=['GET', 'POST'])
@login_required
def api_cases():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute(
            "SELECT c.id, c.title, c.status, c.severity, c.workflow_state, c.assignee, c.description, c.created_by, c.created_at, c.closed_at, c.acknowledged_at, c.tlp, c.pap, "
            "c.queue_id, q.name as queue_name, "
            "COUNT(DISTINCT ci.id) as item_count, "
            "COUNT(DISTINCT ct.id) as task_count, "
            "COUNT(DISTINCT CASE WHEN ct.status = 'done' THEN ct.id END) as task_done_count "
            "FROM cases c LEFT JOIN case_items ci ON ci.case_id = c.id LEFT JOIN case_tasks ct ON ct.case_id = c.id "
            "LEFT JOIN case_queues q ON q.id = c.queue_id "
            "GROUP BY c.id ORDER BY CASE WHEN c.status = 'open' THEN 0 ELSE 1 END, c.created_at DESC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({"error": "Title is required"}), 400
    assignee = (data.get('assignee') or '').strip()
    description = (data.get('description') or '').strip()
    # Unlike every other case field, TLP/PAP have no sensible forced default -- they're
    # an explicit information-sharing classification an analyst may not have assessed
    # yet, especially on a single-operator/internal-only appliance where "who else can
    # see this" often just doesn't apply. Empty string (not NULL -- tlp/pap stay NOT
    # NULL, no schema change) means "not set", distinct from an explicit 'clear'
    # classification (which means "assessed, no restriction").
    tlp = (data.get('tlp') or '').strip()
    pap = (data.get('pap') or '').strip()
    severity = (data.get('severity') or 'medium').strip()
    queue_id = data.get('queue_id') or None
    if tlp and tlp not in CASE_TLP_VALUES:
        return jsonify({"error": f"tlp must be empty (not set) or one of {', '.join(CASE_TLP_VALUES)}"}), 400
    if pap and pap not in CASE_PAP_VALUES:
        return jsonify({"error": f"pap must be empty (not set) or one of {', '.join(CASE_PAP_VALUES)}"}), 400
    if severity not in CASE_SEVERITY_VALUES:
        return jsonify({"error": f"severity must be one of {', '.join(CASE_SEVERITY_VALUES)}"}), 400
    if queue_id and not db.execute("SELECT 1 FROM case_queues WHERE id = ?", (queue_id,)).fetchone():
        return jsonify({"error": "Queue not found"}), 400
    cur = db.execute(
        "INSERT INTO cases (title, assignee, description, created_by, tlp, pap, severity, queue_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (title, assignee, description, current_user.username, tlp, pap, severity, queue_id)
    )
    cid = cur.lastrowid
    _log_case_event(db, cid, 'created', title)
    if queue_id:
        queue_name = db.execute("SELECT name FROM case_queues WHERE id = ?", (queue_id,)).fetchone()['name']
        _log_case_event(db, cid, 'queue_change', queue_name)

    # Optional template: bulk-create its task list on the new case.
    template_id = data.get('template_id')
    if template_id:
        tpl = db.execute("SELECT name, tasks FROM case_templates WHERE id = ?", (template_id,)).fetchone()
        if tpl:
            tasks = json.loads(tpl['tasks'])
            db.executemany(
                "INSERT INTO case_tasks (case_id, title, position, created_by) VALUES (?, ?, ?, ?)",
                [(cid, t, i, current_user.username) for i, t in enumerate(tasks)]
            )
            _log_case_event(db, cid, 'template_applied', tpl['name'])

    _run_playbooks_for_case(db, cid, 'case_created', queue_id, tlp, 'open', severity)
    if queue_id:
        _run_playbooks_for_case(db, cid, 'queue_changed', queue_id, tlp, 'open', severity)
    db.commit()
    return jsonify({"status": "success", "id": cid})

def _case_item_summary(db, item_type, item_id):
    if item_type == 'alert':
        r = db.execute(
            "SELECT a.timestamp, a.severity, a.host, a.username, a.source_ip, COALESCE(s.title, a.rule_name, 'Custom/YARA Rule') as label, a.message, "
            "a.country_code, a.country_name "
            "FROM alerts a LEFT JOIN sigma_rules s ON a.rule_id = s.id WHERE a.id = ?", (item_id,)
        ).fetchone()
    elif item_type == 'command_result':
        # Not the same shape as an alert/anomaly (no severity/username/source_ip of its
        # own) -- synthesized from exit_code/status so the existing severity-badge
        # rendering still has something sensible to color, rather than adding a whole
        # separate item-kind rendering path in cases.html for just this one field.
        r = db.execute(
            "SELECT queued_at as timestamp, hostname as host, NULL as username, NULL as source_ip, label, status, exit_code FROM agent_commands WHERE id = ?",
            (item_id,)
        ).fetchone()
        if not r:
            return None
        r = dict(r)
        if r['status'] != 'done':
            r['severity'] = 'INFO'
            r['message'] = f"Status: {r['status']}"
        elif r['exit_code'] not in (0, None):
            r['severity'] = 'HIGH'
            r['message'] = f"Completed with a non-zero exit code ({r['exit_code']})"
        else:
            r['severity'] = 'INFO'
            r['message'] = "Completed successfully"
        del r['status'], r['exit_code']
    else:
        r = db.execute(
            "SELECT timestamp, severity, hostname as host, NULL as username, NULL as source_ip, 'UEBA Anomaly' as label, message FROM events WHERE id = ?", (item_id,)
        ).fetchone()
    if not r:
        return None
    summary = dict(r)
    # An alert row already carries its own country_code/country_name, stamped once at
    # creation time (see migrate_alerts_geoip_columns) -- only fall back to an on-demand
    # lookup for a pre-migration alert row (columns present but NULL) or a non-alert item
    # type (command_result/ueba_event), neither of which has geoip columns of its own.
    if not summary.get('country_code') and summary.get('source_ip'):
        from geoip import lookup_country
        summary['country_code'], summary['country_name'] = lookup_country(summary['source_ip'])
    else:
        summary.setdefault('country_code', None)
        summary.setdefault('country_name', None)
    return summary

@app.route('/api/cases/<int:cid>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_case_detail(cid):
    db = get_db()
    case = db.execute("SELECT * FROM cases WHERE id = ?", (cid,)).fetchone()
    if not case:
        return jsonify({"error": "Case not found"}), 404

    if request.method == 'DELETE':
        # Deleting a case is destructive and irreversible -- unlike every other case
        # action (create/edit/tasks/notes/items), which stays open to any analyst as
        # day-to-day casework, this is gated to Tier 3+ so a case can't vanish by
        # accident or a Tier 1 mis-click.
        err = require_permission('cases.delete')
        if err: return err
        db.execute("DELETE FROM case_items WHERE case_id = ?", (cid,))
        db.execute("DELETE FROM case_tasks WHERE case_id = ?", (cid,))
        db.execute("DELETE FROM case_events WHERE case_id = ?", (cid,))
        db.execute("DELETE FROM cases WHERE id = ?", (cid,))
        db.commit()
        return jsonify({"ok": 1})

    if request.method == 'PUT':
        data = request.get_json() or {}
        title = data['title'].strip() if 'title' in data and data['title'] else case['title']
        status = data['status'].strip() if 'status' in data and data['status'] else case['status']
        assignee = data['assignee'].strip() if 'assignee' in data else (case['assignee'] or '')
        description = data['description'].strip() if 'description' in data else (case['description'] or '')
        # 'tlp' in data (not "and data['tlp']") -- an explicit empty string must actually
        # clear it back to not-set, not silently fall through to keeping the old value.
        tlp = data['tlp'].strip() if 'tlp' in data else case['tlp']
        pap = data['pap'].strip() if 'pap' in data else case['pap']
        severity = data['severity'].strip() if 'severity' in data and data['severity'] else case['severity']
        workflow_state = data['workflow_state'].strip() if 'workflow_state' in data and data['workflow_state'] else case['workflow_state']
        queue_id = data['queue_id'] if 'queue_id' in data else case['queue_id']
        queue_id = queue_id or None
        if status not in ('open', 'closed'):
            return jsonify({"error": "status must be 'open' or 'closed'"}), 400
        if tlp and tlp not in CASE_TLP_VALUES:
            return jsonify({"error": f"tlp must be empty (not set) or one of {', '.join(CASE_TLP_VALUES)}"}), 400
        if pap and pap not in CASE_PAP_VALUES:
            return jsonify({"error": f"pap must be empty (not set) or one of {', '.join(CASE_PAP_VALUES)}"}), 400
        if severity not in CASE_SEVERITY_VALUES:
            return jsonify({"error": f"severity must be one of {', '.join(CASE_SEVERITY_VALUES)}"}), 400
        if workflow_state not in CASE_WORKFLOW_STATES:
            return jsonify({"error": f"workflow_state must be one of {', '.join(CASE_WORKFLOW_STATES)}"}), 400
        if queue_id and not db.execute("SELECT 1 FROM case_queues WHERE id = ?", (queue_id,)).fetchone():
            return jsonify({"error": "Queue not found"}), 400
        # Closed cases are read-only -- the one exception is this same request also
        # leaving 'closed' (a reopen), which is allowed to carry other field changes too.
        if case['status'] == 'closed' and status == 'closed':
            return jsonify({"error": "This case is closed. Reopen it (change Status) before making changes."}), 403
        closed_at = case['closed_at']
        if status == 'closed' and case['status'] != 'closed':
            # UTC, not local time -- must match created_at's SQLite CURRENT_TIMESTAMP
            # default (also UTC) or every time-to-close calculation (case metrics/SLA
            # dashboard) silently skews by the server's local UTC offset.
            closed_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            # A case closed while still "New"/"Investigating" reads as a data-entry
            # gap on the timeline -- auto-advance to Resolved unless the caller already
            # told us what workflow_state they want.
            if 'workflow_state' not in data:
                workflow_state = 'resolved'
        elif status == 'open':
            closed_at = None
        # TTA (time to acknowledge): stamped once, the first time a case's workflow
        # moves off the 'new' starting state -- never re-stamped after that.
        acknowledged_at = case['acknowledged_at']
        if workflow_state != 'new' and not acknowledged_at:
            acknowledged_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        # Timeline entries only for what actually CHANGED -- a save that only edits the
        # description shouldn't manufacture a spurious "status changed to open" event.
        status_changed = status != case['status']
        assignee_changed = assignee != (case['assignee'] or '')
        queue_changed = queue_id != case['queue_id']
        if status_changed:
            _log_case_event(db, cid, 'status_change', status)
        if assignee_changed:
            _log_case_event(db, cid, 'assignee_change', assignee or '(unassigned)')
        if tlp != case['tlp']:
            _log_case_event(db, cid, 'tlp_change', tlp)
        if pap != case['pap']:
            _log_case_event(db, cid, 'pap_change', pap)
        if severity != case['severity']:
            _log_case_event(db, cid, 'severity_change', severity)
        if workflow_state != case['workflow_state']:
            _log_case_event(db, cid, 'workflow_state_change', workflow_state)
        if queue_changed:
            queue_name = db.execute("SELECT name FROM case_queues WHERE id = ?", (queue_id,)).fetchone()['name'] if queue_id else '(none)'
            _log_case_event(db, cid, 'queue_change', queue_name)
        db.execute(
            "UPDATE cases SET title = ?, status = ?, assignee = ?, description = ?, closed_at = ?, tlp = ?, pap = ?, severity = ?, workflow_state = ?, acknowledged_at = ?, queue_id = ? WHERE id = ?",
            (title, status, assignee, description, closed_at, tlp, pap, severity, workflow_state, acknowledged_at, queue_id, cid)
        )
        if status_changed:
            _run_playbooks_for_case(db, cid, 'status_changed', queue_id, tlp, status, severity)
        if queue_changed:
            _run_playbooks_for_case(db, cid, 'queue_changed', queue_id, tlp, status, severity)
        if assignee_changed:
            _run_playbooks_for_case(db, cid, 'assignee_changed', queue_id, tlp, status, severity)
        db.commit()
        return jsonify({"status": "success"})

    items = db.execute("SELECT id, item_type, item_id, added_by, added_at FROM case_items WHERE case_id = ? ORDER BY added_at DESC", (cid,)).fetchall()
    items_out = []
    for it in items:
        summary = _case_item_summary(db, it['item_type'], it['item_id'])
        items_out.append({**dict(it), 'summary': summary})
    tasks = [dict(t) for t in db.execute(
        "SELECT id, title, status, assignee, position, created_by, created_at FROM case_tasks WHERE case_id = ? ORDER BY position, id", (cid,)
    ).fetchall()]
    events = [dict(e) for e in db.execute(
        "SELECT id, ts, actor, event_type, detail FROM case_events WHERE case_id = ? ORDER BY ts DESC, id DESC", (cid,)
    ).fetchall()]
    case_assets = [dict(a) for a in db.execute(
        "SELECT ca.id, ca.host, ca.compromise_status, ca.related_indicator, ca.notes, ca.added_by, ca.added_at, a.criticality "
        "FROM case_assets ca LEFT JOIN assets a ON a.host = ca.host WHERE ca.case_id = ? ORDER BY ca.added_at", (cid,)
    ).fetchall()]
    case_iocs = [dict(i) for i in db.execute(
        "SELECT id, ioc_type, value, notes, added_by, added_at FROM case_iocs WHERE case_id = ? ORDER BY added_at", (cid,)
    ).fetchall()]
    return jsonify({**dict(case), 'items': items_out, 'tasks': tasks, 'events': events, 'assets': case_assets, 'iocs': case_iocs})

@app.route('/api/cases/<int:cid>/items', methods=['POST'])
@login_required
def api_case_add_item(cid):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    data = request.get_json() or {}
    item_type = data.get('item_type')
    item_id = data.get('item_id')
    if item_type not in CASE_ITEM_TYPES:
        return jsonify({"error": f"item_type must be one of {', '.join(CASE_ITEM_TYPES)}"}), 400
    if not item_id:
        return jsonify({"error": "item_id is required"}), 400
    if db.execute("SELECT 1 FROM case_items WHERE case_id = ? AND item_type = ? AND item_id = ?", (cid, item_type, item_id)).fetchone():
        return jsonify({"error": "That item is already in this case"}), 400
    db.execute(
        "INSERT INTO case_items (case_id, item_type, item_id, added_by) VALUES (?, ?, ?, ?)",
        (cid, item_type, str(item_id), current_user.username)
    )
    _log_case_event(db, cid, 'item_added', f"{item_type}:{item_id}")
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/cases/<int:cid>/items/<int:item_row_id>', methods=['DELETE'])
@login_required
def api_case_remove_item(cid, item_row_id):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    item = db.execute("SELECT item_type, item_id FROM case_items WHERE id = ? AND case_id = ?", (item_row_id, cid)).fetchone()
    if not item:
        return jsonify({"error": "Case item not found"}), 404
    db.execute("DELETE FROM case_items WHERE id = ?", (item_row_id,))
    _log_case_event(db, cid, 'item_removed', f"{item['item_type']}:{item['item_id']}")
    db.commit()
    return jsonify({"ok": 1})

@app.route('/api/cases/<int:cid>/assets', methods=['POST'])
@login_required
def api_case_add_asset(cid):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    data = request.get_json() or {}
    host = (data.get('host') or '').strip()
    if not host:
        return jsonify({"error": "host is required"}), 400
    status = (data.get('compromise_status') or 'suspected').strip()
    if status not in CASE_ASSET_STATUSES:
        return jsonify({"error": f"compromise_status must be one of {', '.join(CASE_ASSET_STATUSES)}"}), 400
    if db.execute("SELECT 1 FROM case_assets WHERE case_id = ? AND host = ?", (cid, host)).fetchone():
        return jsonify({"error": "That host is already tracked in this case"}), 400
    related_indicator = (data.get('related_indicator') or '').strip() or None
    notes = (data.get('notes') or '').strip() or None
    db.execute(
        "INSERT INTO case_assets (case_id, host, compromise_status, related_indicator, notes, added_by) VALUES (?, ?, ?, ?, ?, ?)",
        (cid, host, status, related_indicator, notes, current_user.username)
    )
    _log_case_event(db, cid, 'asset_added', f"{host} ({status})")
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/cases/<int:cid>/assets/<int:asset_id>', methods=['PUT', 'DELETE'])
@login_required
def api_case_asset_detail(cid, asset_id):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    asset = db.execute("SELECT * FROM case_assets WHERE id = ? AND case_id = ?", (asset_id, cid)).fetchone()
    if not asset:
        return jsonify({"error": "Case asset not found"}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM case_assets WHERE id = ?", (asset_id,))
        _log_case_event(db, cid, 'asset_removed', asset['host'])
        db.commit()
        return jsonify({"ok": 1})

    data = request.get_json() or {}
    status = (data['compromise_status'].strip() if data.get('compromise_status') else asset['compromise_status'])
    if status not in CASE_ASSET_STATUSES:
        return jsonify({"error": f"compromise_status must be one of {', '.join(CASE_ASSET_STATUSES)}"}), 400
    related_indicator = (data['related_indicator'].strip() if 'related_indicator' in data else (asset['related_indicator'] or '')) or None
    notes = (data['notes'].strip() if 'notes' in data else (asset['notes'] or '')) or None
    status_changed = status != asset['compromise_status']
    db.execute(
        "UPDATE case_assets SET compromise_status = ?, related_indicator = ?, notes = ? WHERE id = ?",
        (status, related_indicator, notes, asset_id)
    )
    if status_changed:
        _log_case_event(db, cid, 'asset_status_change', f"{asset['host']} → {status}")
    db.commit()
    return jsonify({"status": "success"})

# Structured observables (hash/domain/IP/URL) a case is built around -- distinct from
# Case Assets (which tracks implicated HOSTS with a compromise-status judgment call).
# An IOC here is a raw indicator value with no host attached: something to check
# against the local Threat Intel set (/api/ti/lookup) and pivot from, not something
# with a compromise-status lifecycle of its own.
CASE_IOC_TYPES = ('ip', 'domain', 'hash', 'url')

@app.route('/api/cases/<int:cid>/iocs', methods=['POST'])
@login_required
def api_case_add_ioc(cid):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    data = request.get_json() or {}
    ioc_type = (data.get('ioc_type') or '').strip()
    value = (data.get('value') or '').strip()
    if ioc_type not in CASE_IOC_TYPES:
        return jsonify({"error": f"ioc_type must be one of {', '.join(CASE_IOC_TYPES)}"}), 400
    if not value:
        return jsonify({"error": "value is required"}), 400
    if db.execute("SELECT 1 FROM case_iocs WHERE case_id = ? AND ioc_type = ? AND value = ?", (cid, ioc_type, value)).fetchone():
        return jsonify({"error": "That indicator is already tracked in this case"}), 400
    notes = (data.get('notes') or '').strip() or None
    db.execute(
        "INSERT INTO case_iocs (case_id, ioc_type, value, notes, added_by) VALUES (?, ?, ?, ?, ?)",
        (cid, ioc_type, value, notes, current_user.username)
    )
    _log_case_event(db, cid, 'ioc_added', f"{ioc_type}: {value}")
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/cases/<int:cid>/iocs/<int:ioc_id>', methods=['DELETE'])
@login_required
def api_case_ioc_detail(cid, ioc_id):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    ioc = db.execute("SELECT * FROM case_iocs WHERE id = ? AND case_id = ?", (ioc_id, cid)).fetchone()
    if not ioc:
        return jsonify({"error": "Case indicator not found"}), 404
    db.execute("DELETE FROM case_iocs WHERE id = ?", (ioc_id,))
    _log_case_event(db, cid, 'ioc_removed', f"{ioc['ioc_type']}: {ioc['value']}")
    db.commit()
    return jsonify({"ok": 1})

@app.route('/api/cases/<int:cid>/tasks', methods=['POST'])
@login_required
def api_case_add_task(cid):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    title = ((request.get_json() or {}).get('title') or '').strip()
    if not title:
        return jsonify({"error": "Task title is required"}), 400
    max_pos = db.execute("SELECT COALESCE(MAX(position), -1) FROM case_tasks WHERE case_id = ?", (cid,)).fetchone()[0]
    db.execute(
        "INSERT INTO case_tasks (case_id, title, position, created_by) VALUES (?, ?, ?, ?)",
        (cid, title, max_pos + 1, current_user.username)
    )
    _log_case_event(db, cid, 'task_added', title)
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/cases/<int:cid>/tasks/<int:tid>', methods=['PUT', 'DELETE'])
@login_required
def api_case_task_detail(cid, tid):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    task = db.execute("SELECT * FROM case_tasks WHERE id = ? AND case_id = ?", (tid, cid)).fetchone()
    if not task:
        return jsonify({"error": "Task not found"}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM case_tasks WHERE id = ?", (tid,))
        _log_case_event(db, cid, 'task_removed', task['title'])
        db.commit()
        return jsonify({"ok": 1})

    data = request.get_json() or {}
    title = data['title'].strip() if 'title' in data and data['title'] else task['title']
    status = data['status'].strip() if 'status' in data and data['status'] else task['status']
    assignee = data['assignee'].strip() if 'assignee' in data else (task['assignee'] or '')
    if status not in ('open', 'done'):
        return jsonify({"error": "status must be 'open' or 'done'"}), 400
    if status != task['status']:
        _log_case_event(db, cid, 'task_done' if status == 'done' else 'task_reopened', title)
    db.execute("UPDATE case_tasks SET title = ?, status = ?, assignee = ? WHERE id = ?", (title, status, assignee, tid))
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/cases/<int:cid>/notes', methods=['POST'])
@login_required
def api_case_add_note(cid):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    text = ((request.get_json() or {}).get('text') or '').strip()
    if not text:
        return jsonify({"error": "Note text is required"}), 400
    _log_case_event(db, cid, 'note', text)
    db.commit()
    return jsonify({"status": "success"})

# Batch C of the alert/UEBA -> case automation workflow: a deterministic (not LLM-
# generated -- see the session's explicit choice for this) rollup of what's known about
# a host/user, run on demand from the case detail view and posted straight to the
# timeline. Reuses the exact same weighted risk-score SQL as /api/ueba/risk-scores and
# ueba_engine.py's run_autocase_check() (so "the score" means the same number everywhere
# in the app), and the same enrichment cache-then-run pattern as /api/ti/enrich (so a
# host analyzed twice in the same day doesn't re-hit AbuseIPDB's free-tier rate limit).
# UEBA anomalies (the `events` table) are host-only -- there is no username column on
# that table, so a user analysis skips that section rather than guessing at a join.
MAX_ANALYZE_ENRICH_IPS = 5

# Split out from the /analyze route so the playbook engine's 'analyze_entity' action
# (see _run_playbook_action below) can run the exact same rollup a human triggers from
# the case detail view, instead of a second copy that could quietly drift from it.
def _run_case_analysis(db, cid, entity_type, entity_id):
    risk_cfg = get_risk_score_config(db)
    window = f"-{risk_cfg['window_days']} days"
    host_or_user_col = 'host' if entity_type == 'host' else 'username'

    alert_rows = db.execute(
        f"SELECT a.severity, COALESCE(s.title, a.rule_name, 'Custom/YARA Rule') as rule_title, a.source_ip, "
        f"a.timestamp, a.last_seen, a.occurrence_count "
        f"FROM alerts a LEFT JOIN sigma_rules s ON a.rule_id = s.id "
        f"WHERE a.{host_or_user_col} = ? AND COALESCE(a.last_seen, a.timestamp) >= datetime('now', ?) "
        f"ORDER BY a.timestamp DESC",
        (entity_id, window)
    ).fetchall()

    severity_counts, rule_counts, source_ips = {}, {}, []
    seen_ips = set()
    first_seen = last_seen = None
    total_occurrences = 0
    for r in alert_rows:
        sev = (r['severity'] or 'unknown').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        rule_counts[r['rule_title']] = rule_counts.get(r['rule_title'], 0) + 1
        if r['source_ip'] and r['source_ip'] not in seen_ips:
            seen_ips.add(r['source_ip'])
            source_ips.append(r['source_ip'])
        total_occurrences += r['occurrence_count'] or 1
        ts = r['timestamp']
        if ts and (first_seen is None or ts < first_seen): first_seen = ts
        ls = r['last_seen'] or ts
        if ls and (last_seen is None or ls > last_seen): last_seen = ls

    ueba_count = 0
    if entity_type == 'host':
        ueba_count = db.execute(
            "SELECT COUNT(*) FROM events WHERE hostname = ? AND timestamp >= datetime('now', ?)",
            (entity_id, window)
        ).fetchone()[0]

    if entity_type == 'host':
        score_row = db.execute(
            "SELECT ROUND(SUM(rse.points) * COALESCE(CASE a.criticality WHEN 'critical' THEN 2.0 WHEN 'important' THEN 1.5 ELSE 1.0 END, 1.0), 1) as score "
            "FROM risk_score_events rse LEFT JOIN assets a ON rse.entity_id = a.host "
            "WHERE rse.entity_type = 'host' AND rse.entity_id = ? AND rse.computed_at >= datetime('now', ?)",
            (entity_id, window)
        ).fetchone()
    else:
        score_row = db.execute(
            "SELECT ROUND(SUM(rse.points) * COALESCE(CASE WHEN i.privileged = 1 THEN 1.5 ELSE 1.0 END, 1.0), 1) as score "
            "FROM risk_score_events rse LEFT JOIN identities i ON rse.entity_id = i.username "
            "WHERE rse.entity_type = 'user' AND rse.entity_id = ? AND rse.computed_at >= datetime('now', ?)",
            (entity_id, window)
        ).fetchone()
    score = score_row['score'] if score_row and score_row['score'] is not None else 0
    tier = _risk_tier(score, risk_cfg['tiers'])

    from analyzers import applicable_analyzers, ENRICHMENT_CACHE_TTL_HOURS
    key_row = db.execute("SELECT value FROM settings WHERE key = 'enrichment_api_keys'").fetchone()
    api_keys = json.loads(key_row['value']) if key_row and key_row['value'] else {}
    ip_analyzers = applicable_analyzers('ip')
    enrichment_lines = []
    for ip in source_ips[:MAX_ANALYZE_ENRICH_IPS]:
        parts = []
        for a in ip_analyzers:
            cached = db.execute(
                "SELECT verdict, summary FROM enrichment_results WHERE value = ? AND source = ? AND fetched_at >= datetime('now', ?)",
                (ip, a['key'], f'-{ENRICHMENT_CACHE_TTL_HOURS} hours')
            ).fetchone()
            if cached:
                parts.append(f"{a['label']}: {cached['summary']}")
                continue
            api_key = api_keys.get(a['settings_key']) if a.get('requires_key') else None
            out = a['run'](ip, api_key)
            db.execute(
                "INSERT INTO enrichment_results (value, source, verdict, summary, raw_json, fetched_at) VALUES (?, ?, ?, ?, ?, datetime('now')) "
                "ON CONFLICT(value, source) DO UPDATE SET verdict=excluded.verdict, summary=excluded.summary, raw_json=excluded.raw_json, fetched_at=excluded.fetched_at",
                (ip, a['key'], out['verdict'], out['summary'], json.dumps(out.get('raw') or {}))
            )
            parts.append(f"{a['label']}: {out['summary']}")
        enrichment_lines.append(f"{ip} — {'; '.join(parts) if parts else 'no analyzers applicable'}")

    label = 'Host' if entity_type == 'host' else 'User'
    lines = [f"{label} Analysis: {entity_id} (last {risk_cfg['window_days']} days)", '']
    lines.append(f"Risk Score: {score} ({tier} tier)")
    lines.append('')
    if alert_rows:
        sev_str = ', '.join(f"{c} {s}" for s, c in sorted(severity_counts.items(), key=lambda x: -x[1]))
        lines.append(f"Alerts: {len(alert_rows)} distinct ({total_occurrences} occurrence(s) total) — {sev_str}")
        top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
        lines.append("Top rules: " + ', '.join(f"{t} ({c})" for t, c in top_rules))
        lines.append(f"First seen: {first_seen}   Last seen: {last_seen}")
    else:
        lines.append("Alerts: none in this window.")
    if entity_type == 'host':
        lines.append('')
        lines.append(f"UEBA Anomalies: {ueba_count} in this window.")
    lines.append('')
    if source_ips:
        lines.append(f"IOC Enrichment ({len(enrichment_lines)} of {len(source_ips)} distinct source IP(s) checked):")
        lines.extend(f"- {l}" for l in enrichment_lines)
    else:
        lines.append("IOC Enrichment: no source IPs found on this entity's alerts in this window.")

    summary = '\n'.join(lines)
    _log_case_event(db, cid, 'analysis', summary)
    return summary

@app.route('/api/cases/<int:cid>/analyze', methods=['POST'])
@login_required
def api_case_analyze(cid):
    db = get_db()
    err = _require_open_case(db, cid)
    if err: return err
    d = request.get_json() or {}
    entity_type = (d.get('entity_type') or '').strip()
    entity_id = (d.get('entity_id') or '').strip()
    if entity_type not in ('host', 'user'):
        return jsonify({"error": "entity_type must be 'host' or 'user'"}), 400
    if not entity_id:
        return jsonify({"error": "entity_id is required"}), 400
    summary = _run_case_analysis(db, cid, entity_type, entity_id)
    db.commit()
    return jsonify({'status': 'success', 'summary': summary})

# ---- Playbooks (SOAR) ----
PLAYBOOK_TRIGGERS = ('case_created', 'status_changed', 'queue_changed', 'assignee_changed', 'scheduled')
PLAYBOOK_ACTION_TYPES = ('apply_template', 'add_task', 'add_note', 'set_queue', 'analyze_entity', 'send_webhook', 'send_slack', 'isolate_host')
PLAYBOOK_APPROVAL_STATUSES = ('pending', 'approved', 'rejected')
# isolate_host is the one playbook action type with real, physical consequences (it
# cuts network access on a real endpoint) -- requires_approval is forced to 1 for it at
# save time (see api_playbooks/api_playbook_detail below), never left to the editor's
# checkbox, so there's no way to configure an unattended auto-isolate.
PLAYBOOK_ACTION_TYPES_ALWAYS_GATED = {'isolate_host'}

def _parse_max_runs_per_hour(d):
    val = d.get('max_runs_per_hour')
    if val in (None, ''):
        return None
    try:
        val = int(val)
    except (TypeError, ValueError):
        return None
    return val if val > 0 else None

def _parse_schedule_interval(d):
    val = d.get('schedule_interval_minutes')
    if val in (None, ''):
        return None
    try:
        val = int(val)
    except (TypeError, ValueError):
        return None
    return val if val > 0 else None

def _fill_playbook_template(text, cid, case_row):
    # Deliberately plain string substitution, not a real template engine -- the
    # placeholder set is small and fixed (unlike Jinja in the case-report generator),
    # and this runs against admin-authored config, not untrusted input.
    if not text:
        return text
    values = {
        '{{case_id}}': str(cid),
        '{{case_title}}': (case_row['title'] if case_row else '') or '',
        '{{status}}': (case_row['status'] if case_row else '') or '',
        '{{tlp}}': (case_row['tlp'] if case_row else '') or '',
        '{{pap}}': (case_row['pap'] if case_row else '') or '',
    }
    for k, v in values.items():
        text = text.replace(k, v)
    return text

# One action's execution. Returns a short human-readable result string on success;
# raises on a genuine failure so the caller (_run_playbooks_for_case) can record it in
# that run's detail without aborting the rest of the playbook's actions.
#
# dry_run=True runs every lookup/validation exactly as normal (so a "would skip" reason
# is the real one, not a guess) but returns BEFORE the one mutating statement in each
# branch -- no INSERT/UPDATE/executemany, no requests.post, no _log_case_event. This is
# the single source of truth for what a playbook does; the alternative (a separate
# _dry_run_playbook_action with its own copy of every lookup) would drift from this
# function the next time either one gets edited.
def _run_playbook_action(db, cid, action_type, params, dry_run=False):
    params = params or {}

    if action_type == 'apply_template':
        tpl = db.execute("SELECT name, tasks FROM case_templates WHERE id = ?", (params.get('template_id'),)).fetchone()
        if not tpl:
            return "template not found, skipped"
        tasks = json.loads(tpl['tasks'])
        if dry_run:
            return f"would apply template '{tpl['name']}' ({len(tasks)} tasks)"
        max_pos = db.execute("SELECT COALESCE(MAX(position), -1) FROM case_tasks WHERE case_id = ?", (cid,)).fetchone()[0]
        db.executemany(
            "INSERT INTO case_tasks (case_id, title, position, created_by) VALUES (?, ?, ?, 'playbook')",
            [(cid, t, max_pos + 1 + i) for i, t in enumerate(tasks)]
        )
        _log_case_event(db, cid, 'template_applied', tpl['name'])
        return f"applied template '{tpl['name']}' ({len(tasks)} tasks)"

    if action_type == 'add_task':
        title = (params.get('title') or '').strip()
        if not title:
            return "no task title configured, skipped"
        if dry_run:
            return f"would add task '{title}'"
        max_pos = db.execute("SELECT COALESCE(MAX(position), -1) FROM case_tasks WHERE case_id = ?", (cid,)).fetchone()[0]
        db.execute("INSERT INTO case_tasks (case_id, title, position, created_by) VALUES (?, ?, ?, 'playbook')", (cid, title, max_pos + 1))
        _log_case_event(db, cid, 'task_added', title)
        return f"added task '{title}'"

    if action_type == 'add_note':
        text = (params.get('text') or '').strip()
        if not text:
            return "no note text configured, skipped"
        if dry_run:
            preview = text if len(text) <= 80 else text[:80] + '…'
            return f'would add a note: "{preview}"'
        _log_case_event(db, cid, 'note', text)
        return "added a note"

    if action_type == 'set_queue':
        queue_id = params.get('queue_id') or None
        if queue_id:
            row = db.execute("SELECT name FROM case_queues WHERE id = ?", (queue_id,)).fetchone()
            if not row:
                return "queue not found, skipped"
            queue_name = row['name']
        else:
            queue_name = '(none)'
        if dry_run:
            return f"would set queue to {queue_name}"
        db.execute("UPDATE cases SET queue_id = ? WHERE id = ?", (queue_id, cid))
        _log_case_event(db, cid, 'queue_change', queue_name)
        return f"set queue to {queue_name}"

    if action_type == 'analyze_entity':
        entity_type = params.get('entity_type') if params.get('entity_type') in ('host', 'user') else 'host'
        # A playbook is authored ahead of time and can't know a specific hostname/
        # username -- only which KIND of entity to analyze. Resolved at run time from
        # the case's own linked items: the first one (alert, or a host-type UEBA event)
        # that actually carries a value in that column.
        col = 'host' if entity_type == 'host' else 'username'
        item_rows = db.execute("SELECT item_type, item_id FROM case_items WHERE case_id = ? ORDER BY added_at", (cid,)).fetchall()
        entity_id = None
        for it in item_rows:
            if it['item_type'] == 'alert':
                r = db.execute(f"SELECT {col} as v FROM alerts WHERE id = ?", (it['item_id'],)).fetchone()
            elif it['item_type'] == 'ueba_event' and entity_type == 'host':
                r = db.execute("SELECT hostname as v FROM events WHERE id = ?", (it['item_id'],)).fetchone()
            else:
                continue
            if r and r['v']:
                entity_id = r['v']
                break
        if not entity_id:
            return f"no linked item has a {entity_type}, skipped"
        if dry_run:
            return f"would analyze {entity_type} '{entity_id}'"
        _run_case_analysis(db, cid, entity_type, entity_id)
        return f"analyzed {entity_type} '{entity_id}'"

    if action_type == 'send_webhook':
        # url_secret (a stored secret's NAME) takes precedence over a literal url --
        # the resolved value is used to make the real request but is NEVER included in
        # any returned string (dry-run preview, success message, or failure message),
        # since those strings get persisted into playbook_runs.detail and the case
        # timeline where any case viewer -- not just admins -- can read them.
        secret_name = (params.get('url_secret') or '').strip()
        if secret_name:
            row = db.execute("SELECT value FROM playbook_secrets WHERE name = ?", (secret_name,)).fetchone()
            if not row:
                return f"secret '{secret_name}' not found, skipped"
            url, url_display = row['value'], f"[secret: {secret_name}]"
        else:
            url = url_display = (params.get('url') or '').strip()
        if not url:
            return "no URL configured, skipped"
        case = db.execute("SELECT title, status, tlp, pap FROM cases WHERE id = ?", (cid,)).fetchone()
        body_text = _fill_playbook_template(params.get('body') or '{"case_id": "{{case_id}}", "title": "{{case_title}}", "status": "{{status}}"}', cid, case)
        if dry_run:
            return f"would POST to {url_display} with body: {body_text}"
        try:
            payload = json.loads(body_text)
        except (ValueError, TypeError):
            payload = {"case_id": cid, "raw": body_text}
        import requests
        requests.post(url, json=payload, timeout=8)
        return f"posted webhook to {url_display}"

    if action_type == 'send_slack':
        secret_name = (params.get('webhook_url_secret') or '').strip()
        if secret_name:
            row = db.execute("SELECT value FROM playbook_secrets WHERE name = ?", (secret_name,)).fetchone()
            if not row:
                return f"secret '{secret_name}' not found, skipped"
            webhook_url, url_display = row['value'], f"[secret: {secret_name}]"
        else:
            webhook_url = url_display = (params.get('webhook_url') or '').strip()
        if not webhook_url:
            return "no Slack webhook URL configured, skipped"
        case = db.execute("SELECT title, status, tlp, pap FROM cases WHERE id = ?", (cid,)).fetchone()
        message = _fill_playbook_template(params.get('message') or 'Case #{{case_id}}: {{case_title}} ({{status}})', cid, case)
        if dry_run:
            return f'would send Slack message via {url_display}: "{message}"'
        import requests
        requests.post(webhook_url, json={'text': message}, timeout=8)
        return f"sent Slack message via {url_display}"

    if action_type == 'isolate_host':
        # No params -- unlike analyze_entity, a playbook can't be authored against a
        # specific hostname ahead of time. Targets every Case Asset an analyst has
        # explicitly marked 'confirmed' compromised (not every host merely mentioned in
        # a linked alert) -- the same curated, analyst-judged list the one-click Isolate
        # button on the case page itself already targets, not a broader auto-derived set.
        confirmed_hosts = [r['host'] for r in db.execute(
            "SELECT host FROM case_assets WHERE case_id = ? AND compromise_status = 'confirmed'", (cid,)
        ).fetchall()]
        if not confirmed_hosts:
            return "no confirmed-compromised hosts in this case, skipped"
        if dry_run:
            return f"would isolate {len(confirmed_hosts)} confirmed host(s): {', '.join(confirmed_hosts)}"
        # Same soc_ip auto-fill api_agent_commands() applies when the caller (there, the
        # EDR console UI; here, an approved playbook action) doesn't supply one.
        settings_map = {r[0]: r[1] for r in db.execute("SELECT key, value FROM settings").fetchall()}
        soc_ip = settings_map.get('ingest_bind_ip', '0.0.0.0')
        if soc_ip == '0.0.0.0':
            soc_ip = request.host.split(':')[0]
        queued = []
        for host in confirmed_hosts:
            builder, _ = agent_scripts.TEMPLATES_BY_OS[_get_host_os(db, host)]['isolate_host']
            script = builder({'soc_ip': soc_ip})
            db.execute(
                "INSERT INTO agent_commands (hostname, label, script, queued_by) VALUES (?, 'isolate_host', ?, 'playbook')",
                (host, script)
            )
            queued.append(host)
        return f"queued isolate_host for {len(queued)} host(s): {', '.join(queued)}"

    return f"unknown action type '{action_type}', skipped"

# Companion to the /api/playbooks/<id>/dry-run route -- checks whether a playbook's OWN
# configured trigger would currently match a given case's condition filters, then runs
# every one of its actions in dry_run mode. No db.commit() needed anywhere in this path:
# dry_run=True guarantees _run_playbook_action never executes a mutating statement.
def _dry_run_playbook(db, playbook_id, cid):
    pb = db.execute("SELECT * FROM playbooks WHERE id = ?", (playbook_id,)).fetchone()
    if not pb:
        return None
    case = db.execute("SELECT * FROM cases WHERE id = ?", (cid,)).fetchone()
    if not case:
        return None

    skip_reasons = []
    if not pb['enabled']:
        skip_reasons.append('the playbook is disabled')
    if pb['condition_queue_id'] and pb['condition_queue_id'] != case['queue_id']:
        skip_reasons.append("the case's queue doesn't match the condition")
    if pb['condition_tlp'] and pb['condition_tlp'] != case['tlp']:
        skip_reasons.append("the case's TLP doesn't match the condition")
    if pb['condition_status'] and pb['condition_status'] != case['status']:
        skip_reasons.append("the case's status doesn't match the condition")
    if pb['condition_severity'] and pb['condition_severity'] != case['severity']:
        skip_reasons.append("the case's severity doesn't match the condition")

    actions = db.execute(
        "SELECT action_type, params, requires_approval FROM playbook_actions WHERE playbook_id = ? ORDER BY position", (playbook_id,)
    ).fetchall()
    previews = []
    for a in actions:
        try:
            action_params = json.loads(a['params']) if a['params'] else {}
            result = _run_playbook_action(db, cid, a['action_type'], action_params, dry_run=True)
            if a['requires_approval']:
                result = f"[requires approval] {result}"
        except Exception as e:
            result = f"would fail: {e}"
        previews.append({'action_type': a['action_type'], 'result': result})

    return {
        'trigger_event': pb['trigger_event'],
        'would_fire': not skip_reasons,
        'skip_reasons': skip_reasons,
        'actions': previews,
    }

# Shared by every REAL (non-dry-run) execution path -- a triggered run
# (_run_playbooks_for_case) and a manual "Run Now" (api_playbook_run) both go through
# this so the approval-gate behavior can't drift between the two. An action flagged
# requires_approval is never executed here: it's queued in playbook_approvals and the
# loop moves on to the next action (same "one action's outcome doesn't stop the rest"
# isolation _run_playbook_action's own try/except already gives ordinary failures).
def _execute_playbook_actions(db, cid, playbook_id, actions):
    results = []
    overall_status = 'success'
    for a in actions:
        action_params = json.loads(a['params']) if a['params'] else {}
        if a['requires_approval']:
            db.execute(
                "INSERT INTO playbook_approvals (playbook_id, case_id, action_type, params) VALUES (?, ?, ?, ?)",
                (playbook_id, cid, a['action_type'], json.dumps(action_params))
            )
            results.append(f"{a['action_type']}: queued for approval")
            if overall_status == 'success':
                overall_status = 'pending_approval'
            continue
        try:
            result = _run_playbook_action(db, cid, a['action_type'], action_params)
            results.append(f"{a['action_type']}: {result}")
        except Exception as e:
            results.append(f"{a['action_type']}: FAILED ({e})")
            overall_status = 'partial'
    detail = '; '.join(results) if results else 'no actions configured'
    return detail, overall_status

# The one call site every trigger point (case create, status/queue/assignee change)
# routes through. queue_id/tlp/status are the case's state AFTER whatever change just
# happened -- passed in directly rather than re-queried, since every call site already
# has them as local variables from computing what to write. Matches ANY enabled playbook
# for this trigger whose optional condition filters are unset or satisfied; one
# playbook's action failing doesn't stop another matching playbook from running, and
# doesn't stop the rest of ITS OWN actions either (see _execute_playbook_actions).
# Guards against a misconfigured playbook re-firing in a loop (e.g. a status_changed
# playbook whose own set_queue/webhook action indirectly re-triggers itself). Checked
# against playbook_runs, not some separate counter, so it's always looking at the real
# execution history -- no separate state to drift out of sync. Tripping it auto-disables
# the playbook (not just this one run) since a rate that was fine a minute ago clearly
# isn't now; re-enabling is a deliberate admin action via the same toggle as any other
# disable, not automatic.
def _check_playbook_rate_limit(db, pb, cid):
    if not pb['max_runs_per_hour']:
        return True
    recent = db.execute(
        "SELECT COUNT(*) FROM playbook_runs WHERE playbook_id = ? AND triggered_at >= datetime('now', '-1 hour')",
        (pb['id'],)
    ).fetchone()[0]
    if recent < pb['max_runs_per_hour']:
        return True
    db.execute("UPDATE playbooks SET enabled = 0 WHERE id = ?", (pb['id'],))
    detail = f"rate limit tripped ({recent}/{pb['max_runs_per_hour']} runs in the last hour) -- playbook auto-disabled"
    db.execute(
        "INSERT INTO playbook_runs (playbook_id, case_id, status, detail) VALUES (?, ?, 'rate_limited', ?)",
        (pb['id'], cid, detail)
    )
    _log_case_event(db, cid, 'playbook_run', f"{pb['name']}: {detail}")
    return False

def _run_playbooks_for_case(db, cid, trigger_event, queue_id, tlp, status, severity):
    playbooks = db.execute(
        "SELECT * FROM playbooks WHERE enabled = 1 AND trigger_event = ? "
        "AND (condition_queue_id IS NULL OR condition_queue_id = ?) "
        "AND (condition_tlp IS NULL OR condition_tlp = ?) "
        "AND (condition_status IS NULL OR condition_status = ?) "
        "AND (condition_severity IS NULL OR condition_severity = ?)",
        (trigger_event, queue_id, tlp, status, severity)
    ).fetchall()
    for pb in playbooks:
        if not _check_playbook_rate_limit(db, pb, cid):
            continue
        actions = db.execute("SELECT action_type, params, requires_approval FROM playbook_actions WHERE playbook_id = ? ORDER BY position", (pb['id'],)).fetchall()
        detail, overall_status = _execute_playbook_actions(db, cid, pb['id'], actions)
        db.execute(
            "INSERT INTO playbook_runs (playbook_id, case_id, status, detail) VALUES (?, ?, ?, ?)",
            (pb['id'], cid, overall_status, detail)
        )
        _log_case_event(db, cid, 'playbook_run', f"{pb['name']}: {detail}")

# A scheduled playbook has no single case_id from a trigger event to act on -- its
# condition_queue_id/tlp/status/severity filters become a case SELECTOR here (picking
# which open cases to sweep) instead of a fire-time check against one case in hand, the
# same filter columns doing double duty rather than a parallel set just for this.
# condition_status, when set, is taken at face value (an admin who explicitly wants to
# sweep closed cases can); left unset, only currently-open cases are swept by default --
# a "check every open case in this queue every morning" playbook has no business ever
# touching a case that's already closed.
def _run_scheduled_playbooks(db):
    playbooks = db.execute(
        "SELECT * FROM playbooks WHERE enabled = 1 AND trigger_event = 'scheduled' AND schedule_interval_minutes IS NOT NULL"
    ).fetchall()
    now = datetime.utcnow()
    for pb in playbooks:
        due = True
        if pb['last_scheduled_run']:
            try:
                last = datetime.strptime(pb['last_scheduled_run'], '%Y-%m-%d %H:%M:%S')
                due = (now - last).total_seconds() >= pb['schedule_interval_minutes'] * 60
            except (ValueError, TypeError):
                due = True
        if not due:
            continue

        conditions, params = [], []
        if pb['condition_queue_id']:
            conditions.append("queue_id = ?"); params.append(pb['condition_queue_id'])
        if pb['condition_tlp']:
            conditions.append("tlp = ?"); params.append(pb['condition_tlp'])
        if pb['condition_status']:
            conditions.append("status = ?"); params.append(pb['condition_status'])
        else:
            conditions.append("status != 'closed'")
        if pb['condition_severity']:
            conditions.append("severity = ?"); params.append(pb['condition_severity'])
        matching_cases = db.execute(f"SELECT id FROM cases WHERE {' AND '.join(conditions)}", params).fetchall()

        actions = db.execute("SELECT action_type, params, requires_approval FROM playbook_actions WHERE playbook_id = ? ORDER BY position", (pb['id'],)).fetchall()
        for case_row in matching_cases:
            cid = case_row['id']
            if not _check_playbook_rate_limit(db, pb, cid):
                break  # this playbook just auto-disabled itself -- stop sweeping the rest
            detail, overall_status = _execute_playbook_actions(db, cid, pb['id'], actions)
            db.execute(
                "INSERT INTO playbook_runs (playbook_id, case_id, status, detail) VALUES (?, ?, ?, ?)",
                (pb['id'], cid, overall_status, detail)
            )
            _log_case_event(db, cid, 'playbook_run', f"{pb['name']} (scheduled): {detail}")
        db.execute("UPDATE playbooks SET last_scheduled_run = datetime('now') WHERE id = ?", (pb['id'],))
        db.commit()

# Wazuh's model auto-runs its hash/YARA checks on a timer instead of waiting for an
# analyst to notice and dispatch one -- ioc_sweep/string_sweep already do the real
# detection work (see api_agent_commands()'s POST branch), this just queues them the
# same way on a schedule instead of only from a manual click. Config lives in
# settings['agent_sweep_config'] (JSON: interval_hours, last_run) -- interval_hours
# 0/absent means disabled, matching the "empty means off" convention used elsewhere.
def _run_scheduled_agent_sweeps(db):
    import json as _json
    from datetime import timedelta
    cfg_row = db.execute("SELECT value FROM settings WHERE key = 'agent_sweep_config'").fetchone()
    cfg = _json.loads(cfg_row['value']) if cfg_row and cfg_row['value'] else {}
    interval_hours = cfg.get('interval_hours') or 0
    if not interval_hours:
        return

    now = datetime.utcnow()
    last_run = cfg.get('last_run')
    if last_run:
        try:
            last = datetime.strptime(last_run, '%Y-%m-%d %H:%M:%S')
            if (now - last).total_seconds() < interval_hours * 3600:
                return
        except (ValueError, TypeError):
            pass

    # Online or Idle hosts only (same 300s freshness window agent_checkins() uses) --
    # a host that's actually gone (uninstalled, powered off) has nothing to gain from a
    # queued command it will never come back to pick up, and this keeps the queue from
    # silently piling up stale commands for decommissioned endpoints. agent_polls.timestamp
    # is written with local server time (datetime.datetime.now() in the poll route), NOT
    # UTC -- comparing it against a UTC cutoff here would silently misjudge every host's
    # freshness by the server's UTC offset, so this cutoff deliberately uses local time
    # too even though `now`/last_run above are UTC (self-consistent with each other).
    cutoff = (datetime.now() - timedelta(seconds=300)).strftime('%Y-%m-%d %H:%M:%S')
    hosts = db.execute(
        "SELECT user_agent as hostname, os FROM agent_polls "
        "WHERE id IN (SELECT MAX(id) FROM agent_polls GROUP BY ip_address) AND timestamp >= ?",
        (cutoff,)
    ).fetchall()
    if not hosts:
        cfg['last_run'] = now.strftime('%Y-%m-%d %H:%M:%S')
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('agent_sweep_config', ?)", (_json.dumps(cfg),))
        db.commit()
        return

    # Recomputed fresh here too, same as the manual-dispatch branch in
    # api_agent_commands() -- a sweep queued today reflects today's live IOC/YARA
    # state, not whatever it was at some earlier point.
    sweep_params = {
        'ioc_sweep': {
            'hashes': _get_live_ioc_sha256_hashes(db),
            'md5_hashes': _get_live_ioc_md5_hashes(db),
            'sha1_hashes': _get_live_ioc_sha1_hashes(db),
        },
        'string_sweep': {'patterns': _get_live_yara_strings()},
        'yara_condition_sweep': {'rule_conditions': _get_live_yara_rule_conditions()},
    }
    for h in hosts:
        os_name = h['os'] if h['os'] in ('windows', 'linux') else 'windows'
        templates = agent_scripts.TEMPLATES_BY_OS[os_name]
        for label, params in sweep_params.items():
            builder, required = templates[label]
            # NOT `required` here -- ioc_sweep/string_sweep/yara_condition_sweep all
            # register required=[] (an empty live list is a legitimate STATE the
            # builder itself already handles gracefully, not a missing-param user
            # error), so that list is always empty and this check would never actually
            # skip anything. Checking the live sweep data directly is what actually
            # avoids queuing a no-op command to a host with nothing loaded to check yet.
            if not any(params.values()):
                continue  # nothing loaded to sweep for yet (no IOCs / no YARA rules)
            try:
                script = builder(params)
            except Exception:
                continue
            db.execute(
                "INSERT INTO agent_commands (hostname, label, script, queued_by) VALUES (?, ?, ?, 'scheduled_sweep')",
                (h['hostname'], label, script)
            )
    cfg['last_run'] = now.strftime('%Y-%m-%d %H:%M:%S')
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('agent_sweep_config', ?)", (_json.dumps(cfg),))
    db.commit()

@app.route('/api/settings/agent-sweeps', methods=['GET', 'POST'])
@login_required
def api_settings_agent_sweeps():
    import json
    db = get_db()
    if request.method == 'GET':
        row = db.execute("SELECT value FROM settings WHERE key = 'agent_sweep_config'").fetchone()
        cfg = json.loads(row['value']) if row and row['value'] else {}
        return jsonify({'interval_hours': cfg.get('interval_hours') or 0, 'last_run': cfg.get('last_run')})
    err = require_permission('edr.command.advanced')
    if err: return err
    d = request.json or {}
    try:
        interval_hours = int(d.get('interval_hours') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'interval_hours must be a whole number'}), 400
    if interval_hours < 0:
        return jsonify({'error': 'interval_hours cannot be negative'}), 400
    row = db.execute("SELECT value FROM settings WHERE key = 'agent_sweep_config'").fetchone()
    cfg = json.loads(row['value']) if row and row['value'] else {}
    cfg['interval_hours'] = interval_hours
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('agent_sweep_config', ?)", (json.dumps(cfg),))
    db.commit()
    log_audit('agent_sweep_config_change', 'settings', None, f'interval_hours={interval_hours}')
    return jsonify({'status': 'success'})

# Hit by sigma_engine.py's background loop (every ~30s, same cadence as its TI-feed
# auto-sync check) -- not a user-facing route, so no @login_required/current_user. The
# due-check inside _run_scheduled_playbooks() makes this cheap to call that often (a
# no-op unless something's actually due), same shape as taxii_client.sync_due_feeds().
# Restricted to localhost since this process and the Flask app always run on the same
# host and there's no legitimate reason for this to be reachable from outside it.
@app.route('/api/internal/run-scheduled-playbooks', methods=['POST'])
def api_run_scheduled_playbooks():
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return jsonify({'error': 'Forbidden'}), 403
    db = get_db()
    _run_scheduled_playbooks(db)
    _run_scheduled_agent_sweeps(db)
    return jsonify({'status': 'success'})

@app.route('/api/playbooks', methods=['GET', 'POST'])
@login_required
def api_playbooks():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute(
            "SELECT p.*, q.name as condition_queue_name, "
            "(SELECT COUNT(*) FROM playbook_runs WHERE playbook_id = p.id) as run_count "
            "FROM playbooks p LEFT JOIN case_queues q ON q.id = p.condition_queue_id ORDER BY p.name"
        ).fetchall()
        out = []
        for r in rows:
            actions = [dict(a) for a in db.execute(
                "SELECT id, action_type, params, position, requires_approval FROM playbook_actions WHERE playbook_id = ? ORDER BY position", (r['id'],)
            ).fetchall()]
            for a in actions:
                a['params'] = json.loads(a['params']) if a['params'] else {}
            out.append({**dict(r), 'actions': actions})
        return jsonify(out)

    err = require_permission('soar.playbooks.manage')
    if err: return err
    d = request.json or {}
    name = (d.get('name') or '').strip()
    trigger_event = d.get('trigger_event')
    actions = d.get('actions') or []
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if trigger_event not in PLAYBOOK_TRIGGERS:
        return jsonify({'error': f"trigger_event must be one of {', '.join(PLAYBOOK_TRIGGERS)}"}), 400
    if not actions:
        return jsonify({'error': 'At least one action is required'}), 400
    for a in actions:
        if a.get('action_type') not in PLAYBOOK_ACTION_TYPES:
            return jsonify({'error': f"invalid action_type: {a.get('action_type')}"}), 400
    if db.execute("SELECT 1 FROM playbooks WHERE name = ?", (name,)).fetchone():
        return jsonify({'error': f'A playbook named "{name}" already exists'}), 400
    condition_queue_id = d.get('condition_queue_id') or None
    if condition_queue_id and not db.execute("SELECT 1 FROM case_queues WHERE id = ?", (condition_queue_id,)).fetchone():
        return jsonify({'error': 'Condition queue not found'}), 400
    condition_tlp = (d.get('condition_tlp') or '').strip() or None
    condition_status = (d.get('condition_status') or '').strip() or None
    condition_severity = (d.get('condition_severity') or '').strip() or None
    max_runs_per_hour = _parse_max_runs_per_hour(d)
    schedule_interval_minutes = _parse_schedule_interval(d)
    if trigger_event == 'scheduled' and not schedule_interval_minutes:
        return jsonify({'error': 'Scheduled playbooks require a schedule interval (in minutes)'}), 400
    cur = db.execute(
        "INSERT INTO playbooks (name, description, trigger_event, enabled, condition_queue_id, condition_tlp, condition_status, condition_severity, max_runs_per_hour, schedule_interval_minutes, created_by) "
        "VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
        (name, (d.get('description') or '').strip(), trigger_event, condition_queue_id, condition_tlp, condition_status, condition_severity, max_runs_per_hour, schedule_interval_minutes, current_user.username)
    )
    pid = cur.lastrowid
    for i, a in enumerate(actions):
        gated = a['action_type'] in PLAYBOOK_ACTION_TYPES_ALWAYS_GATED or bool(a.get('requires_approval'))
        db.execute("INSERT INTO playbook_actions (playbook_id, position, action_type, params, requires_approval) VALUES (?, ?, ?, ?, ?)",
                   (pid, i, a['action_type'], json.dumps(a.get('params') or {}), 1 if gated else 0))
    db.commit()
    log_audit('playbook_create', 'playbook', name)
    return jsonify({'status': 'success', 'id': pid})

@app.route('/api/playbooks/<int:pid>', methods=['PUT', 'DELETE'])
@login_required
def api_playbook_detail(pid):
    err = require_permission('soar.playbooks.manage')
    if err: return err
    db = get_db()
    existing = db.execute("SELECT name FROM playbooks WHERE id = ?", (pid,)).fetchone()
    if not existing:
        return jsonify({'error': 'Playbook not found'}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM playbook_actions WHERE playbook_id = ?", (pid,))
        db.execute("DELETE FROM playbook_runs WHERE playbook_id = ?", (pid,))
        db.execute("DELETE FROM playbooks WHERE id = ?", (pid,))
        db.commit()
        log_audit('playbook_delete', 'playbook', existing['name'])
        return jsonify({'ok': 1})

    d = request.json or {}
    # Full replace of the action list (delete-and-reinsert) -- simplest correct
    # semantics for an ordered list with no partial-edit route, same choice
    # case_templates made for its own JSON task-list column.
    name = (d.get('name') or '').strip()
    trigger_event = d.get('trigger_event')
    actions = d.get('actions') or []
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if trigger_event not in PLAYBOOK_TRIGGERS:
        return jsonify({'error': f"trigger_event must be one of {', '.join(PLAYBOOK_TRIGGERS)}"}), 400
    if not actions:
        return jsonify({'error': 'At least one action is required'}), 400
    for a in actions:
        if a.get('action_type') not in PLAYBOOK_ACTION_TYPES:
            return jsonify({'error': f"invalid action_type: {a.get('action_type')}"}), 400
    if db.execute("SELECT 1 FROM playbooks WHERE name = ? AND id != ?", (name, pid)).fetchone():
        return jsonify({'error': f'A playbook named "{name}" already exists'}), 400
    condition_queue_id = d.get('condition_queue_id') or None
    if condition_queue_id and not db.execute("SELECT 1 FROM case_queues WHERE id = ?", (condition_queue_id,)).fetchone():
        return jsonify({'error': 'Condition queue not found'}), 400
    condition_tlp = (d.get('condition_tlp') or '').strip() or None
    condition_status = (d.get('condition_status') or '').strip() or None
    condition_severity = (d.get('condition_severity') or '').strip() or None
    max_runs_per_hour = _parse_max_runs_per_hour(d)
    schedule_interval_minutes = _parse_schedule_interval(d)
    if trigger_event == 'scheduled' and not schedule_interval_minutes:
        return jsonify({'error': 'Scheduled playbooks require a schedule interval (in minutes)'}), 400
    db.execute(
        "UPDATE playbooks SET name = ?, description = ?, trigger_event = ?, condition_queue_id = ?, condition_tlp = ?, condition_status = ?, condition_severity = ?, max_runs_per_hour = ?, schedule_interval_minutes = ? WHERE id = ?",
        (name, (d.get('description') or '').strip(), trigger_event, condition_queue_id, condition_tlp, condition_status, condition_severity, max_runs_per_hour, schedule_interval_minutes, pid)
    )
    db.execute("DELETE FROM playbook_actions WHERE playbook_id = ?", (pid,))
    for i, a in enumerate(actions):
        gated = a['action_type'] in PLAYBOOK_ACTION_TYPES_ALWAYS_GATED or bool(a.get('requires_approval'))
        db.execute("INSERT INTO playbook_actions (playbook_id, position, action_type, params, requires_approval) VALUES (?, ?, ?, ?, ?)",
                   (pid, i, a['action_type'], json.dumps(a.get('params') or {}), 1 if gated else 0))
    db.commit()
    log_audit('playbook_update', 'playbook', name)
    return jsonify({'status': 'success'})

@app.route('/api/playbooks/<int:pid>/toggle', methods=['PUT'])
@login_required
def api_playbook_toggle(pid):
    err = require_permission('soar.playbooks.manage')
    if err: return err
    db = get_db()
    if not db.execute("SELECT 1 FROM playbooks WHERE id = ?", (pid,)).fetchone():
        return jsonify({'error': 'Playbook not found'}), 404
    enabled = 1 if (request.json or {}).get('enabled') else 0
    db.execute("UPDATE playbooks SET enabled = ? WHERE id = ?", (enabled, pid))
    db.commit()
    log_audit('playbook_toggle', 'playbook', pid, 'enabled' if enabled else 'disabled')
    return jsonify({'status': 'success'})

@app.route('/api/playbooks/<int:pid>/runs', methods=['GET'])
@login_required
def api_playbook_runs(pid):
    db = get_db()
    rows = db.execute(
        "SELECT pr.id, pr.case_id, c.title as case_title, pr.triggered_at, pr.status, pr.detail "
        "FROM playbook_runs pr LEFT JOIN cases c ON c.id = pr.case_id WHERE pr.playbook_id = ? ORDER BY pr.triggered_at DESC LIMIT 50",
        (pid,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/playbooks/<int:pid>/dry-run', methods=['POST'])
@login_required
def api_playbook_dry_run(pid):
    db = get_db()
    case_id = (request.json or {}).get('case_id')
    if not case_id:
        return jsonify({'error': 'case_id is required'}), 400
    result = _dry_run_playbook(db, pid, case_id)
    if result is None:
        return jsonify({'error': 'Playbook or case not found'}), 404
    return jsonify(result)

# Manual "Run Now" -- lets an analyst fire a playbook against a specific case on demand
# (backfill tasks/notes onto an existing case, re-send a webhook) instead of only ever
# waiting for its trigger event. Same condition check as _dry_run_playbook (a playbook
# whose own filters don't match the chosen case is refused, not silently skipped) but
# executes for real through _execute_playbook_actions -- same approval-gating and same
# playbook_runs/case-timeline bookkeeping a triggered run gets, so a run's origin
# (trigger vs. manual) doesn't change what gets recorded. Gated the same as editing a
# playbook: this causes real side effects (task/note writes, outbound webhooks).
@app.route('/api/playbooks/<int:pid>/run', methods=['POST'])
@login_required
def api_playbook_run(pid):
    err = require_permission('soar.playbooks.manage')
    if err: return err
    db = get_db()
    case_id = (request.json or {}).get('case_id')
    if not case_id:
        return jsonify({'error': 'case_id is required'}), 400
    pb = db.execute("SELECT * FROM playbooks WHERE id = ?", (pid,)).fetchone()
    if not pb:
        return jsonify({'error': 'Playbook not found'}), 404
    case = db.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        return jsonify({'error': 'Case not found'}), 404

    skip_reasons = []
    if not pb['enabled']:
        skip_reasons.append('the playbook is disabled')
    if pb['condition_queue_id'] and pb['condition_queue_id'] != case['queue_id']:
        skip_reasons.append("the case's queue doesn't match the condition")
    if pb['condition_tlp'] and pb['condition_tlp'] != case['tlp']:
        skip_reasons.append("the case's TLP doesn't match the condition")
    if pb['condition_status'] and pb['condition_status'] != case['status']:
        skip_reasons.append("the case's status doesn't match the condition")
    if pb['condition_severity'] and pb['condition_severity'] != case['severity']:
        skip_reasons.append("the case's severity doesn't match the condition")
    if skip_reasons:
        return jsonify({'error': "This playbook wouldn't fire for this case: " + '; '.join(skip_reasons)}), 400
    if not _check_playbook_rate_limit(db, pb, case_id):
        db.commit()  # persist the rate-limit run row + auto-disable _check_playbook_rate_limit already staged
        return jsonify({'error': f"Rate limit reached ({pb['max_runs_per_hour']} runs/hour) -- the playbook has been auto-disabled."}), 429

    actions = db.execute("SELECT action_type, params, requires_approval FROM playbook_actions WHERE playbook_id = ? ORDER BY position", (pid,)).fetchall()
    detail, overall_status = _execute_playbook_actions(db, case_id, pid, actions)
    db.execute(
        "INSERT INTO playbook_runs (playbook_id, case_id, status, detail) VALUES (?, ?, ?, ?)",
        (pid, case_id, overall_status, detail)
    )
    _log_case_event(db, case_id, 'playbook_run', f"{pb['name']} (run manually): {detail}")
    db.commit()
    return jsonify({'status': 'success', 'run_status': overall_status, 'detail': detail})

@app.route('/api/playbook-approvals', methods=['GET'])
@login_required
def api_playbook_approvals():
    db = get_db()
    status = request.args.get('status') or 'pending'
    if status not in PLAYBOOK_APPROVAL_STATUSES:
        return jsonify({'error': f"status must be one of {', '.join(PLAYBOOK_APPROVAL_STATUSES)}"}), 400
    rows = db.execute(
        "SELECT pa.id, pa.playbook_id, p.name as playbook_name, pa.case_id, c.title as case_title, "
        "pa.action_type, pa.params, pa.status, pa.requested_at, pa.decided_by, pa.decided_at "
        "FROM playbook_approvals pa "
        "LEFT JOIN playbooks p ON p.id = pa.playbook_id "
        "LEFT JOIN cases c ON c.id = pa.case_id "
        "WHERE pa.status = ? ORDER BY pa.requested_at DESC",
        (status,)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d['params'] = json.loads(d['params']) if d['params'] else {}
        out.append(d)
    return jsonify(out)

# Approve executes the ONE gated action for real (through the same _run_playbook_action
# every other action in this app runs through) and logs it to the case timeline;
# reject just records the decision and never executes anything. Neither path re-checks
# the playbook's trigger conditions -- an approval is a decision about this one queued
# action, not a re-evaluation of whether the playbook should have fired at all.
@app.route('/api/playbook-approvals/<int:approval_id>', methods=['PUT'])
@login_required
def api_playbook_approval_decide(approval_id):
    err = require_permission('soar.playbooks.manage')
    if err: return err
    db = get_db()
    approval = db.execute("SELECT * FROM playbook_approvals WHERE id = ?", (approval_id,)).fetchone()
    if not approval:
        return jsonify({'error': 'Approval not found'}), 404
    if approval['status'] != 'pending':
        return jsonify({'error': f"This approval was already {approval['status']}"}), 400
    decision = (request.json or {}).get('decision')
    if decision not in ('approve', 'reject'):
        return jsonify({'error': "decision must be 'approve' or 'reject'"}), 400

    pb = db.execute("SELECT name FROM playbooks WHERE id = ?", (approval['playbook_id'],)).fetchone()
    playbook_name = pb['name'] if pb else f"playbook #{approval['playbook_id']}"
    if decision == 'approve':
        params = json.loads(approval['params']) if approval['params'] else {}
        try:
            result = _run_playbook_action(db, approval['case_id'], approval['action_type'], params)
        except Exception as e:
            result = f"FAILED ({e})"
        _log_case_event(db, approval['case_id'], 'playbook_action_approved', f"{playbook_name} — {approval['action_type']}: {result}")
        db.execute(
            "UPDATE playbook_approvals SET status = 'approved', decided_by = ?, decided_at = datetime('now') WHERE id = ?",
            (current_user.username, approval_id)
        )
    else:
        _log_case_event(db, approval['case_id'], 'playbook_action_rejected', f"{playbook_name} — {approval['action_type']}")
        db.execute(
            "UPDATE playbook_approvals SET status = 'rejected', decided_by = ?, decided_at = datetime('now') WHERE id = ?",
            (current_user.username, approval_id)
        )
    db.commit()
    return jsonify({'status': 'success'})

# Named secrets for playbook send_webhook/send_slack actions, so a live webhook/Slack
# URL doesn't have to be typed as a literal, visible-to-anyone-who-opens-the-playbook
# string in playbook_actions.params. Values are write-only after creation -- GET never
# returns them, matching how _run_playbook_action's dry-run/success/failure strings also
# never include a resolved secret value (see the comment there). This is plaintext at
# rest, the same posture every other credential in this app already has (VirusTotal/
# AbuseIPDB/Shodan keys in the `settings` table) -- not a new encryption story, just a
# named, reusable, write-only reference instead of a literal string repeated inline.
@app.route('/api/playbook-secrets', methods=['GET', 'POST'])
@login_required
def api_playbook_secrets():
    db = get_db()
    err = require_permission('soar.secrets.manage')
    if err: return err
    if request.method == 'GET':
        rows = db.execute("SELECT id, name, description, created_by, created_at FROM playbook_secrets ORDER BY name").fetchall()
        return jsonify([dict(r) for r in rows])
    d = request.json or {}
    name = (d.get('name') or '').strip()
    value = (d.get('value') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if not value:
        return jsonify({'error': 'value is required'}), 400
    if db.execute("SELECT 1 FROM playbook_secrets WHERE name = ?", (name,)).fetchone():
        return jsonify({'error': f'A secret named "{name}" already exists'}), 400
    db.execute(
        "INSERT INTO playbook_secrets (name, value, description, created_by) VALUES (?, ?, ?, ?)",
        (name, value, (d.get('description') or '').strip(), current_user.username)
    )
    db.commit()
    log_audit('playbook_secret_create', 'playbook_secret', name)
    return jsonify({'status': 'success'})

@app.route('/api/playbook-secrets/<int:sid>', methods=['DELETE'])
@login_required
def api_playbook_secret_delete(sid):
    err = require_permission('soar.secrets.manage')
    if err: return err
    db = get_db()
    existing = db.execute("SELECT name FROM playbook_secrets WHERE id = ?", (sid,)).fetchone()
    if not existing:
        return jsonify({'error': 'Secret not found'}), 404
    db.execute("DELETE FROM playbook_secrets WHERE id = ?", (sid,))
    db.commit()
    log_audit('playbook_secret_delete', 'playbook_secret', existing['name'])
    return jsonify({'ok': 1})

@app.route('/api/case-templates', methods=['GET'])
@login_required
def api_case_templates():
    db = get_db()
    rows = db.execute("SELECT id, name, description, tasks FROM case_templates ORDER BY name").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d['tasks'] = json.loads(d['tasks'])
        out.append(d)
    return jsonify(out)

UEBA_CONFIG_DEFAULTS = {
    'ueba_lookback_days': '30', 'ueba_stddev_multiplier': '3', 'ueba_min_baseline': '50',
    'ueba_min_days_observed': '4', 'ueba_new_ip_enabled': '1',
    'ueba_new_process_enabled': '1', 'ueba_new_dest_ip_enabled': '1',
    'ueba_process_lineage_enabled': '1', 'ueba_off_hours_enabled': '1',
    'ueba_rare_process_enabled': '1', 'ueba_rare_process_max_hosts': '2',
    'ueba_convergence_enabled': '1', 'ueba_convergence_min_indicators': '3',
    'ueba_convergence_window_hours': '24',
    'ueba_sequence_chain_enabled': '1', 'ueba_sequence_chain_window_hours': '24',
    'ueba_priority_enabled': '1', 'ueba_priority_window_days': '30', 'ueba_priority_half_life_hours': '24',
    'ueba_autocase_enabled': '0', 'ueba_autocase_threshold': '80', 'ueba_autocase_template_id': '',
    'ueba_autocase_cooldown_hours': '24',
}

@app.route('/api/ueba/config', methods=['GET', 'POST'])
@login_required
def api_ueba_config():
    db = get_db()

    if request.method == 'GET':
        rows = db.execute(
            "SELECT key, value FROM settings WHERE key IN "
            "('ueba_lookback_days', 'ueba_stddev_multiplier', 'ueba_min_baseline', 'ueba_min_days_observed', 'ueba_new_ip_enabled', "
            "'ueba_new_process_enabled', 'ueba_new_dest_ip_enabled', 'ueba_process_lineage_enabled', 'ueba_off_hours_enabled', "
            "'ueba_rare_process_enabled', 'ueba_rare_process_max_hosts', "
            "'ueba_convergence_enabled', 'ueba_convergence_min_indicators', 'ueba_convergence_window_hours', "
            "'ueba_sequence_chain_enabled', 'ueba_sequence_chain_window_hours', "
            "'ueba_priority_enabled', 'ueba_priority_window_days', 'ueba_priority_half_life_hours', "
            "'ueba_autocase_enabled', 'ueba_autocase_threshold', 'ueba_autocase_template_id', 'ueba_autocase_cooldown_hours')"
        ).fetchall()
        cfg = {**UEBA_CONFIG_DEFAULTS, **{r['key']: r['value'] for r in rows}}
        return jsonify({
            'lookback_days': int(cfg['ueba_lookback_days']),
            'stddev_multiplier': float(cfg['ueba_stddev_multiplier']),
            'min_baseline': float(cfg['ueba_min_baseline']),
            'min_days_observed': int(cfg['ueba_min_days_observed']),
            'new_ip_enabled': str(cfg['ueba_new_ip_enabled']) not in ('0', 'false', 'False'),
            'new_process_enabled': str(cfg['ueba_new_process_enabled']) not in ('0', 'false', 'False'),
            'new_dest_ip_enabled': str(cfg['ueba_new_dest_ip_enabled']) not in ('0', 'false', 'False'),
            'process_lineage_enabled': str(cfg['ueba_process_lineage_enabled']) not in ('0', 'false', 'False'),
            'off_hours_enabled': str(cfg['ueba_off_hours_enabled']) not in ('0', 'false', 'False'),
            'rare_process_enabled': str(cfg['ueba_rare_process_enabled']) not in ('0', 'false', 'False'),
            'rare_process_max_hosts': int(cfg['ueba_rare_process_max_hosts']),
            'convergence_enabled': str(cfg['ueba_convergence_enabled']) not in ('0', 'false', 'False'),
            'convergence_min_indicators': int(cfg['ueba_convergence_min_indicators']),
            'convergence_window_hours': int(cfg['ueba_convergence_window_hours']),
            'sequence_chain_enabled': str(cfg['ueba_sequence_chain_enabled']) not in ('0', 'false', 'False'),
            'sequence_chain_window_hours': int(cfg['ueba_sequence_chain_window_hours']),
            'priority_enabled': str(cfg['ueba_priority_enabled']) not in ('0', 'false', 'False'),
            'priority_window_days': int(cfg['ueba_priority_window_days']),
            'priority_half_life_hours': float(cfg['ueba_priority_half_life_hours']),
            'autocase_enabled': str(cfg['ueba_autocase_enabled']) not in ('0', 'false', 'False'),
            'autocase_threshold': int(cfg['ueba_autocase_threshold']),
            'autocase_template_id': int(cfg['ueba_autocase_template_id']) if str(cfg['ueba_autocase_template_id']) not in ('', 'None') else None,
            'autocase_cooldown_hours': int(cfg['ueba_autocase_cooldown_hours']),
        })

    err = require_permission('ueba.config.manage')
    if err: return err

    data = request.json or {}
    try:
        lookback_days = int(data.get('lookback_days'))
        stddev_multiplier = float(data.get('stddev_multiplier'))
        min_baseline = float(data.get('min_baseline'))
        min_days_observed = int(data.get('min_days_observed'))
        new_ip_enabled = bool(data.get('new_ip_enabled'))
        new_process_enabled = bool(data.get('new_process_enabled'))
        new_dest_ip_enabled = bool(data.get('new_dest_ip_enabled'))
        process_lineage_enabled = bool(data.get('process_lineage_enabled'))
        off_hours_enabled = bool(data.get('off_hours_enabled'))
        rare_process_enabled = bool(data.get('rare_process_enabled'))
        rare_process_max_hosts = int(data.get('rare_process_max_hosts'))
        convergence_enabled = bool(data.get('convergence_enabled'))
        convergence_min_indicators = int(data.get('convergence_min_indicators'))
        convergence_window_hours = int(data.get('convergence_window_hours'))
        sequence_chain_enabled = bool(data.get('sequence_chain_enabled'))
        sequence_chain_window_hours = int(data.get('sequence_chain_window_hours'))
        priority_enabled = bool(data.get('priority_enabled'))
        priority_window_days = int(data.get('priority_window_days'))
        priority_half_life_hours = float(data.get('priority_half_life_hours'))
        autocase_enabled = bool(data.get('autocase_enabled'))
        autocase_threshold = int(data.get('autocase_threshold'))
        autocase_template_id = data.get('autocase_template_id')
        autocase_template_id = int(autocase_template_id) if autocase_template_id not in (None, '') else None
        autocase_cooldown_hours = int(data.get('autocase_cooldown_hours'))
        if not (1 <= lookback_days <= 365): raise ValueError('lookback_days must be 1-365')
        if not (0.5 <= stddev_multiplier <= 10): raise ValueError('stddev_multiplier must be 0.5-10')
        if not (0 <= min_baseline <= 1000000): raise ValueError('min_baseline must be 0-1000000')
        if not (1 <= min_days_observed <= 52): raise ValueError('min_days_observed must be 1-52')
        if not (1 <= rare_process_max_hosts <= 50): raise ValueError('rare_process_max_hosts must be 1-50')
        if not (2 <= convergence_min_indicators <= 10): raise ValueError('convergence_min_indicators must be 2-10')
        if not (1 <= convergence_window_hours <= 168): raise ValueError('convergence_window_hours must be 1-168')
        if not (1 <= sequence_chain_window_hours <= 168): raise ValueError('sequence_chain_window_hours must be 1-168')
        if not (1 <= priority_window_days <= 365): raise ValueError('priority_window_days must be 1-365')
        if not (1 <= priority_half_life_hours <= 8760): raise ValueError('priority_half_life_hours must be 1-8760')
        if not (1 <= autocase_threshold <= 1000): raise ValueError('autocase_threshold must be 1-1000')
        if not (1 <= autocase_cooldown_hours <= 8760): raise ValueError('autocase_cooldown_hours must be 1-8760')
        if autocase_template_id and not db.execute("SELECT 1 FROM case_templates WHERE id = ?", (autocase_template_id,)).fetchone():
            raise ValueError('Template not found')
    except (TypeError, ValueError) as e:
        return jsonify({'error': str(e) or 'Invalid config values'}), 400

    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_lookback_days', ?)", (str(lookback_days),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_stddev_multiplier', ?)", (str(stddev_multiplier),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_min_baseline', ?)", (str(min_baseline),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_min_days_observed', ?)", (str(min_days_observed),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_new_ip_enabled', ?)", ('1' if new_ip_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_new_process_enabled', ?)", ('1' if new_process_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_new_dest_ip_enabled', ?)", ('1' if new_dest_ip_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_process_lineage_enabled', ?)", ('1' if process_lineage_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_off_hours_enabled', ?)", ('1' if off_hours_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_rare_process_enabled', ?)", ('1' if rare_process_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_rare_process_max_hosts', ?)", (str(rare_process_max_hosts),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_convergence_enabled', ?)", ('1' if convergence_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_convergence_min_indicators', ?)", (str(convergence_min_indicators),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_convergence_window_hours', ?)", (str(convergence_window_hours),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_sequence_chain_enabled', ?)", ('1' if sequence_chain_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_sequence_chain_window_hours', ?)", (str(sequence_chain_window_hours),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_priority_enabled', ?)", ('1' if priority_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_priority_window_days', ?)", (str(priority_window_days),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_priority_half_life_hours', ?)", (str(priority_half_life_hours),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_autocase_enabled', ?)", ('1' if autocase_enabled else '0',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_autocase_threshold', ?)", (str(autocase_threshold),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_autocase_template_id', ?)", (str(autocase_template_id) if autocase_template_id else '',))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_autocase_cooldown_hours', ?)", (str(autocase_cooldown_hours),))
    db.commit()
    return jsonify({'status': 'success'})

# Duplicated from ueba_engine.py's RISK_SCORE_DEFAULTS rather than imported -- same
# reasoning as UEBA_CONFIG_DEFAULTS just above and taxii_client.py's own DB_PATH
# constant: this module and the standalone engine script each keep their own copy
# rather than one importing the other.
RISK_SCORE_DEFAULTS = {
    'window_days': 7,
    'points': {
        'alert_critical': 40, 'alert_high': 25, 'alert_medium': 10, 'alert_low': 5, 'alert_informational': 1,
        'sweep_hit': 35, 'failed_login': 10,
        'volume_anomaly_critical': 30, 'volume_anomaly_high': 20, 'volume_anomaly_medium': 10,
        'new_source_ip': 15,
        'new_process': 20, 'new_destination_ip': 15, 'process_lineage': 25, 'off_hours_activity': 10,
        'rare_process_population': 18,
        'multi_signal_convergence': 30,
        'sequence_chain_progression': 15,
    },
    'tiers': {'low': 0, 'medium': 20, 'high': 50, 'critical': 100},
}

# Which columns an anomaly_rules row is allowed to reference for each source table --
# enforced at rule-CRUD time here, and re-checked defensively in ueba_engine.py before
# ever interpolating a stored entity_field into a raw SQL column reference.
# Sigma alerts only for now -- audit_log-sourced rules were pulled back out shortly
# after shipping; may return as a source later.
ANOMALY_RULE_SOURCES = {
    'alerts': {'fields': ('severity', 'rule_name', 'host', 'username', 'source_ip', 'destination_ip'), 'entity_fields': ('host', 'username')},
}
ANOMALY_RULE_OPERATORS = ('equals', 'not_equals', 'contains', 'starts_with', 'ends_with')
ANOMALY_RULE_ENTITY_TYPES = ('user', 'host')
# How a condition combines with the one before it in the list. Evaluated strictly
# left-to-right (no parentheses/precedence) -- see _rule_matches_all() in
# ueba_engine.py. The first condition's own logic value is stored but ignored (nothing
# precedes it to combine with).
ANOMALY_RULE_LOGIC_OPS = ('AND', 'OR')

ANOMALY_RULES_CACHE = None
ANOMALY_RULES_CACHE_TIME = 0

def invalidate_anomaly_rules_cache():
    global ANOMALY_RULES_CACHE
    ANOMALY_RULES_CACHE = None

def _deep_merge_risk_config(base, override):
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge_risk_config(base[k], v)
        else:
            base[k] = v
    return base

def get_risk_score_config(db):
    import copy as _copy
    cfg = _copy.deepcopy(RISK_SCORE_DEFAULTS)
    row = db.execute("SELECT value FROM settings WHERE key = 'risk_score_config'").fetchone()
    if row and row['value']:
        try:
            _deep_merge_risk_config(cfg, json.loads(row['value']))
        except (json.JSONDecodeError, TypeError):
            pass
    return cfg

# Report PDF branding -- same settings-table JSON-blob pattern as risk_score_config
# above, just a flat dict (no nested deep-merge needed). Mirrored in
# generate_report.py's own REPORT_BRANDING_DEFAULTS/REPORT_BRANDING_DIR since that
# script has no Flask app context to import this from (cron invokes it directly).
REPORT_BRANDING_DIR = "/opt/micro-dfir/data/branding"
REPORT_BRANDING_ALLOWED_LOGO_EXT = {'png', 'jpg', 'jpeg'}
REPORT_BRANDING_DEFAULTS = {
    "company_name": "Micro DFIR", "logo_filename": None,
    "footer_text": "Generated by Micro DFIR SOAR Engine", "accent_color": "#0d6efd",
}

def get_report_branding_config(db):
    import copy as _copy
    cfg = _copy.deepcopy(REPORT_BRANDING_DEFAULTS)
    row = db.execute("SELECT value FROM settings WHERE key = 'report_branding_config'").fetchone()
    if row and row['value']:
        try:
            cfg.update(json.loads(row['value']))
        except (json.JSONDecodeError, TypeError):
            pass
    return cfg

def _risk_tier(score, tiers):
    if score >= tiers['critical']: return 'Critical'
    if score >= tiers['high']: return 'High'
    if score >= tiers['medium']: return 'Medium'
    return 'Low'

@app.route('/api/ueba/risk-scores', methods=['GET'])
@login_required
def api_ueba_risk_scores():
    db = get_db()
    cfg = get_risk_score_config(db)
    # The criticality/privileged multiplier is applied INSIDE the query (not multiplied
    # onto the raw SUM afterward in Python) so ranking and the LIMIT 200 cutoff both
    # happen on the WEIGHTED score -- otherwise a high-criticality entity with a modest
    # raw score could get cut from the top-200 before its weighting ever had a chance to
    # matter, defeating the entire point of marking it important. The multiplier values
    # here must match CRITICALITY_MULTIPLIERS above exactly (see test coverage) --
    # duplicated rather than parameterized since SQLite has no clean way to join a
    # Python dict in as a lookup table for 4 fixed values.
    rows = db.execute(
        "SELECT rse.entity_type as entity_type, rse.entity_id as entity_id, "
        "SUM(rse.points) as raw_score, "
        "ROUND(SUM(rse.points) * COALESCE("
        "    CASE WHEN rse.entity_type = 'host' THEN "
        "        CASE a.criticality WHEN 'critical' THEN 2.0 WHEN 'important' THEN 1.5 ELSE 1.0 END "
        "    WHEN rse.entity_type = 'user' THEN "
        "        CASE WHEN i.privileged = 1 THEN 1.5 ELSE 1.0 END "
        "    END, 1.0), 1) as score, "
        "COALESCE(CASE WHEN rse.entity_type = 'host' THEN "
        "    CASE a.criticality WHEN 'critical' THEN 2.0 WHEN 'important' THEN 1.5 ELSE 1.0 END "
        "WHEN rse.entity_type = 'user' THEN "
        "    CASE WHEN i.privileged = 1 THEN 1.5 ELSE 1.0 END END, 1.0) as multiplier, "
        "COUNT(*) as event_count, MAX(rse.computed_at) as last_event, "
        "ps.priority_score as priority_score "
        "FROM risk_score_events rse "
        "LEFT JOIN assets a ON rse.entity_type = 'host' AND rse.entity_id = a.host "
        "LEFT JOIN identities i ON rse.entity_type = 'user' AND rse.entity_id = i.username "
        "LEFT JOIN ueba_priority_scores ps ON rse.entity_type = ps.entity_type AND rse.entity_id = ps.entity_id "
        "WHERE rse.computed_at >= datetime('now', ?) "
        "GROUP BY rse.entity_type, rse.entity_id HAVING score > 0 ORDER BY score DESC LIMIT 200",
        (f"-{cfg['window_days']} days",)
    ).fetchall()
    out = [{**dict(r), 'tier': _risk_tier(r['score'], cfg['tiers'])} for r in rows]
    return jsonify({'entities': out, 'window_days': cfg['window_days']})

@app.route('/api/ueba/risk-scores/<entity_type>/<path:entity_id>', methods=['GET'])
@login_required
def api_ueba_risk_score_detail(entity_type, entity_id):
    db = get_db()
    cfg = get_risk_score_config(db)
    rows = db.execute(
        "SELECT indicator, points, detail, source_table, source_id, computed_at FROM risk_score_events "
        "WHERE entity_type = ? AND entity_id = ? AND computed_at >= datetime('now', ?) ORDER BY id DESC",
        (entity_type, entity_id, f"-{cfg['window_days']} days")
    ).fetchall()
    events = [dict(r) for r in rows]
    score = sum(e['points'] for e in events)
    priority_row = db.execute(
        "SELECT priority_score, distinct_indicators, peak_points, decay_score, computed_at FROM ueba_priority_scores "
        "WHERE entity_type = ? AND entity_id = ?", (entity_type, entity_id)
    ).fetchone()
    return jsonify({'entity_type': entity_type, 'entity_id': entity_id, 'score': score,
                     'tier': _risk_tier(score, cfg['tiers']), 'events': events, 'window_days': cfg['window_days'],
                     'priority': dict(priority_row) if priority_row else None})

@app.route('/api/ueba/risk-config', methods=['GET', 'POST'])
@login_required
def api_ueba_risk_config():
    db = get_db()
    if request.method == 'GET':
        return jsonify(get_risk_score_config(db))

    err = require_permission('ueba.config.manage')
    if err: return err
    data = request.json or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'Config must be a JSON object'}), 400
    # Validate against the default shape before storing -- reject anything that isn't
    # a plausible partial override rather than silently storing garbage that would
    # only surface as a confusing failure the next time the engine runs.
    for section in ('points', 'tiers'):
        if section in data and not isinstance(data[section], dict):
            return jsonify({'error': f"'{section}' must be an object"}), 400
        for k, v in (data.get(section) or {}).items():
            if not isinstance(v, (int, float)):
                return jsonify({'error': f"'{section}.{k}' must be a number"}), 400
    if 'window_days' in data and not (1 <= int(data['window_days']) <= 90):
        return jsonify({'error': 'window_days must be 1-90'}), 400
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('risk_score_config', ?)", (json.dumps(data),))
    db.commit()
    log_audit('risk_score_config_change', 'settings')
    return jsonify({'status': 'success'})

def _validate_anomaly_rule(d):
    source = d.get('source')
    allowed = ANOMALY_RULE_SOURCES.get(source)
    if not allowed:
        return f"source must be one of {', '.join(ANOMALY_RULE_SOURCES)}"
    if not (d.get('name') or '').strip():
        return 'name is required'
    conditions = d.get('conditions')
    if not isinstance(conditions, list) or not conditions:
        return 'at least one condition is required'
    for c in conditions:
        if not isinstance(c, dict):
            return 'each condition must be an object'
        if c.get('field') not in allowed['fields']:
            return f"condition field must be one of {', '.join(allowed['fields'])} for source '{source}'"
        if c.get('operator') not in ANOMALY_RULE_OPERATORS:
            return f"condition operator must be one of {', '.join(ANOMALY_RULE_OPERATORS)}"
        if not str(c.get('value', '')).strip():
            return 'condition value is required'
        if c.get('logic', 'AND') not in ANOMALY_RULE_LOGIC_OPS:
            return f"condition logic must be one of {', '.join(ANOMALY_RULE_LOGIC_OPS)}"
    if d.get('entity_field') not in allowed['entity_fields']:
        return f"entity_field must be one of {', '.join(allowed['entity_fields'])} for source '{source}'"
    if d.get('entity_type') not in ANOMALY_RULE_ENTITY_TYPES:
        return f"entity_type must be one of {', '.join(ANOMALY_RULE_ENTITY_TYPES)}"
    try:
        int(d.get('points'))
    except (TypeError, ValueError):
        return 'points must be a number'
    if d.get('first_time_bonus_points') not in (None, ''):
        try:
            int(d.get('first_time_bonus_points'))
        except (TypeError, ValueError):
            return 'first_time_bonus_points must be a number'
    # Both sequence fields are optional together -- a rule not part of any progression
    # simply leaves both unset. Setting one without the other is rejected rather than
    # silently ignored, since a stage number with no sequence name (or vice versa) can't
    # be matched against anything.
    seq_name = (d.get('sequence_name') or '').strip()
    seq_stage = d.get('sequence_stage')
    if seq_name and seq_stage in (None, ''):
        return 'sequence_stage is required when sequence_name is set'
    if seq_stage not in (None, '') and not seq_name:
        return 'sequence_name is required when sequence_stage is set'
    if seq_stage not in (None, ''):
        try:
            seq_stage = int(seq_stage)
        except (TypeError, ValueError):
            return 'sequence_stage must be a whole number'
        if not (1 <= seq_stage <= 20):
            return 'sequence_stage must be between 1 and 20'
    return None

def _condition_summary(conditions):
    parts = []
    for i, c in enumerate(conditions):
        prefix = '' if i == 0 else f"{c.get('logic', 'AND')} "
        parts.append(f"{prefix}{c['field']} {c['operator']} {c['value']}")
    return ' '.join(parts)

def _replace_anomaly_rule_conditions(db, rule_id, conditions):
    db.execute("DELETE FROM anomaly_rule_conditions WHERE rule_id = ?", (rule_id,))
    db.executemany(
        "INSERT INTO anomaly_rule_conditions (rule_id, field, operator, value, logic) VALUES (?, ?, ?, ?, ?)",
        [(rule_id, c['field'], c['operator'], str(c['value']), c.get('logic', 'AND')) for c in conditions]
    )

# Match counts are LEFT JOINed off risk_score_events.rule_id the same way
# /api/rules/tuning joins alerts.rule_id against sigma_rules -- see ANOMALY_RULES_CACHE
# below for the matching cache pattern (same RULES_CACHE_TTL, invalidated on any write).
_ANOMALY_RULES_TUNING_SQL = """
    SELECT ar.*,
           COALESCE(c7.cnt, 0) as matches_7d,
           COALESCE(c30.cnt, 0) as matches_30d,
           COALESCE(ctot.cnt, 0) as matches_total,
           lm.last_matched
    FROM anomaly_rules ar
    LEFT JOIN (SELECT rule_id, COUNT(*) cnt FROM risk_score_events WHERE rule_id IS NOT NULL AND computed_at >= datetime('now', '-7 days') GROUP BY rule_id) c7 ON c7.rule_id = ar.id
    LEFT JOIN (SELECT rule_id, COUNT(*) cnt FROM risk_score_events WHERE rule_id IS NOT NULL AND computed_at >= datetime('now', '-30 days') GROUP BY rule_id) c30 ON c30.rule_id = ar.id
    LEFT JOIN (SELECT rule_id, COUNT(*) cnt FROM risk_score_events WHERE rule_id IS NOT NULL GROUP BY rule_id) ctot ON ctot.rule_id = ar.id
    LEFT JOIN (SELECT rule_id, MAX(computed_at) last_matched FROM risk_score_events WHERE rule_id IS NOT NULL GROUP BY rule_id) lm ON lm.rule_id = ar.id
    ORDER BY matches_30d DESC, ar.name ASC
"""

@app.route('/api/ueba/anomaly-rules', methods=['GET', 'POST'])
@login_required
def api_anomaly_rules():
    global ANOMALY_RULES_CACHE, ANOMALY_RULES_CACHE_TIME
    db = get_db()
    if request.method == 'GET':
        import time
        if ANOMALY_RULES_CACHE is not None and (time.time() - ANOMALY_RULES_CACHE_TIME) < RULES_CACHE_TTL:
            return jsonify(ANOMALY_RULES_CACHE)
        rules = [dict(r) for r in db.execute(_ANOMALY_RULES_TUNING_SQL).fetchall()]
        conds_by_rule = {}
        for c in db.execute("SELECT rule_id, field, operator, value, logic FROM anomaly_rule_conditions ORDER BY id").fetchall():
            conds_by_rule.setdefault(c['rule_id'], []).append({'field': c['field'], 'operator': c['operator'], 'value': c['value'], 'logic': c['logic']})
        for r in rules:
            r['conditions'] = conds_by_rule.get(r['id'], [])
        ANOMALY_RULES_CACHE = rules
        ANOMALY_RULES_CACHE_TIME = time.time()
        return jsonify(ANOMALY_RULES_CACHE)
    err = require_permission('ueba.config.manage')
    if err: return err
    d = request.get_json() or {}
    err = _validate_anomaly_rule(d)
    if err:
        return jsonify({'error': err}), 400
    bonus = d.get('first_time_bonus_points')
    bonus = int(bonus) if bonus not in (None, '') else None
    seq_name = (d.get('sequence_name') or '').strip() or None
    seq_stage = int(d['sequence_stage']) if d.get('sequence_stage') not in (None, '') else None
    cur = db.execute(
        "INSERT INTO anomaly_rules (name, source, entity_field, entity_type, points, first_time_bonus_points, sequence_name, sequence_stage, enabled, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
        (d['name'].strip(), d['source'], d['entity_field'], d['entity_type'], int(d['points']), bonus, seq_name, seq_stage, current_user.username)
    )
    _replace_anomaly_rule_conditions(db, cur.lastrowid, d['conditions'])
    db.commit()
    invalidate_anomaly_rules_cache()
    log_audit('anomaly_rule_create', 'anomaly_rule', cur.lastrowid, f"{d['name']}: {_condition_summary(d['conditions'])} -> {d['points']} pts")
    return jsonify({'status': 'success'}), 201

@app.route('/api/ueba/anomaly-rules/<int:rid>', methods=['PUT', 'DELETE'])
@login_required
def api_anomaly_rule_detail(rid):
    db = get_db()
    err = require_permission('ueba.config.manage')
    if err: return err
    if request.method == 'DELETE':
        db.execute("DELETE FROM anomaly_rules WHERE id = ?", (rid,))
        db.execute("DELETE FROM anomaly_rule_conditions WHERE rule_id = ?", (rid,))
        db.commit()
        invalidate_anomaly_rules_cache()
        log_audit('anomaly_rule_delete', 'anomaly_rule', rid)
        return jsonify({'ok': 1})

    d = request.get_json() or {}
    # A bare {"enabled": ...} toggle request skips full validation, matching the
    # exclusions/drop-rules toggle pattern -- a full edit still gets full validation.
    if set(d.keys()) <= {'enabled'}:
        db.execute("UPDATE anomaly_rules SET enabled = ? WHERE id = ?", (1 if d.get('enabled') else 0, rid))
        db.commit()
        invalidate_anomaly_rules_cache()
        log_audit('anomaly_rule_toggle', 'anomaly_rule', rid)
        return jsonify({'ok': 1})

    err = _validate_anomaly_rule(d)
    if err:
        return jsonify({'error': err}), 400
    bonus = d.get('first_time_bonus_points')
    bonus = int(bonus) if bonus not in (None, '') else None
    seq_name = (d.get('sequence_name') or '').strip() or None
    seq_stage = int(d['sequence_stage']) if d.get('sequence_stage') not in (None, '') else None
    db.execute(
        "UPDATE anomaly_rules SET name=?, source=?, entity_field=?, entity_type=?, points=?, "
        "first_time_bonus_points=?, sequence_name=?, sequence_stage=?, enabled=?, updated_by=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (d['name'].strip(), d['source'], d['entity_field'], d['entity_type'],
         int(d['points']), bonus, seq_name, seq_stage, 1 if d.get('enabled', True) else 0, current_user.username, rid)
    )
    _replace_anomaly_rule_conditions(db, rid, d['conditions'])
    db.commit()
    invalidate_anomaly_rules_cache()
    log_audit('anomaly_rule_update', 'anomaly_rule', rid, f"{d['name']}: {_condition_summary(d['conditions'])} -> {d['points']} pts")
    return jsonify({'status': 'success'})

# ---- Data Insights: per-entity and per-model behavior histograms ----
# Read-only exploration over data that already exists (live_logs, alerts,
# risk_score_events, audit_log, ueba_entity_baselines) -- no new tables, no new
# engine/cron job. Modeled on Exabeam's old Data Insights page (search by model name
# or by entity), adapted to what this app actually tracks; a geographic/map histogram
# is deliberately not included -- there's no GeoIP data anywhere in this app to build
# one from honestly.
def _histogram(db, query, params, count_key='count'):
    rows = db.execute(query, params).fetchall()
    total = sum(r[count_key] for r in rows)
    return {'rows': [dict(r) for r in rows], 'unique_count': len(rows), 'total_count': total}

@app.route('/api/ueba/insights/entities', methods=['GET'])
@login_required
def api_ueba_insights_entities():
    db = get_db()
    q = (request.args.get('q') or '').strip()
    entity_type = request.args.get('type')
    where, params = [], []
    if q:
        where.append("entity_id LIKE ?")
        params.append(f"%{q}%")
    if entity_type in ('host', 'user'):
        where.append("entity_type = ?")
        params.append(entity_type)
    where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''
    rows = db.execute(
        f"SELECT DISTINCT entity_type, entity_id FROM ueba_entity_baselines {where_sql} ORDER BY entity_id LIMIT 50",
        params
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/ueba/insights/entity/<entity_type>/<path:entity_id>', methods=['GET'])
@login_required
def api_ueba_insights_entity(entity_type, entity_id):
    if entity_type not in ('host', 'user'):
        return jsonify({'error': 'entity_type must be host or user'}), 400
    db = get_db()
    col = 'host' if entity_type == 'host' else 'username'
    other_col = 'username' if entity_type == 'host' else 'host'
    result = {'entity_type': entity_type, 'entity_id': entity_id, 'related_entity_type': 'user' if other_col == 'username' else 'host'}

    # Activity pattern: day-of-week (0=Sunday) x hour-of-day event counts.
    tow_rows = db.execute(
        f"SELECT CAST(strftime('%w', timestamp) AS INTEGER) as dow, CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count "
        f"FROM live_logs WHERE {col} = ? GROUP BY dow, hour",
        (entity_id,)
    ).fetchall()
    grid = [[0] * 24 for _ in range(7)]
    total_events = 0
    for r in tow_rows:
        grid[r['dow']][r['hour']] = r['count']
        total_events += r['count']
    last_seen = db.execute(f"SELECT MAX(timestamp) as t FROM live_logs WHERE {col} = ?", (entity_id,)).fetchone()
    result['activity_pattern'] = {'grid': grid, 'total_count': total_events, 'last_seen': last_seen['t'] if last_seen else None}

    for field, key in (('source_ip', 'top_source_ips'), ('destination_ip', 'top_destination_ips')):
        result[key] = _histogram(db,
            f"SELECT {field} as value, COUNT(*) as count, MAX(timestamp) as last_seen FROM live_logs "
            f"WHERE {col} = ? AND {field} IS NOT NULL AND {field} != '' GROUP BY {field} ORDER BY count DESC LIMIT 15",
            (entity_id,))

    result['top_alerts'] = _histogram(db,
        f"SELECT rule_name as value, severity, COUNT(*) as count, MAX(timestamp) as last_seen FROM alerts "
        f"WHERE {col} = ? GROUP BY rule_name, severity ORDER BY count DESC LIMIT 15",
        (entity_id,))

    result['risk_contributions'] = _histogram(db,
        "SELECT indicator as value, SUM(points) as points, COUNT(*) as count, MAX(computed_at) as last_seen FROM risk_score_events "
        "WHERE entity_type = ? AND entity_id = ? GROUP BY indicator ORDER BY points DESC",
        (entity_type, entity_id))

    result['related_entities'] = _histogram(db,
        f"SELECT {other_col} as value, COUNT(*) as count, MAX(timestamp) as last_seen FROM live_logs "
        f"WHERE {col} = ? AND {other_col} IS NOT NULL AND {other_col} NOT IN ('', '-', 'UNKNOWN') "
        f"GROUP BY {other_col} ORDER BY count DESC LIMIT 15",
        (entity_id,))

    if entity_type == 'user':
        result['admin_activity'] = _histogram(db,
            "SELECT action as value, COUNT(*) as count, MAX(timestamp) as last_seen FROM audit_log "
            "WHERE username = ? GROUP BY action ORDER BY count DESC",
            (entity_id,))

    return jsonify(result)

@app.route('/api/ueba/insights/model/<indicator>', methods=['GET'])
@login_required
def api_ueba_insights_model(indicator):
    db = get_db()
    result = _histogram(db,
        "SELECT entity_type, entity_id as value, SUM(points) as points, COUNT(*) as count, MAX(computed_at) as last_seen "
        "FROM risk_score_events WHERE indicator = ? GROUP BY entity_type, entity_id ORDER BY points DESC LIMIT 25",
        (indicator,))
    result['indicator'] = indicator
    return jsonify(result)


# ==========================================
# DASHBOARDS — CROSS-CUTTING ANALYTICS
# ==========================================
# A separate BI-style page from Home (which stays a lightweight, user-customizable
# landing tile strip) -- these endpoints all share one time-range selector (7/30/90
# days) rather than each having their own, so DASHBOARD_RANGES/_dashboard_window_days
# is the one thing every route below has in common.
DASHBOARD_RANGES = {'7d': 7, '30d': 30, '90d': 90}

def _dashboard_window_days(req):
    return DASHBOARD_RANGES.get(req.args.get('range', '30d'), 30)

@app.route('/api/dashboards/alert-trend', methods=['GET'])
@login_required
def api_dashboard_alert_trend():
    days = _dashboard_window_days(request)
    # Same granularity-scales-with-range idea as /api/logs/timeline, just simplified
    # to this page's 3 fixed ranges instead of that endpoint's much larger range set.
    bucket = "strftime('%Y-%m-%d %H:00', timestamp)" if days <= 7 else "strftime('%Y-%m-%d', timestamp)"
    rows = get_db().execute(
        f"SELECT {bucket} as t_bucket, COUNT(*) as count FROM alerts "
        f"WHERE timestamp >= datetime('now', ?) GROUP BY t_bucket ORDER BY t_bucket ASC",
        (f'-{days} days',)
    ).fetchall()
    return jsonify({'trend': [dict(r) for r in rows]})

@app.route('/api/dashboards/alert-severity', methods=['GET'])
@login_required
def api_dashboard_alert_severity():
    days = _dashboard_window_days(request)
    # Grouped case-insensitively (alerts.severity casing isn't guaranteed consistent --
    # ueba_engine.py's own scoring already has to .lower() it for the same reason) so a
    # rule that writes "high" and one that writes "High" don't split into two slices.
    rows = get_db().execute(
        "SELECT severity, COUNT(*) as count FROM alerts "
        "WHERE timestamp >= datetime('now', ?) GROUP BY LOWER(COALESCE(severity, 'unknown')) ORDER BY count DESC",
        (f'-{days} days',)
    ).fetchall()
    return jsonify({'severity': [dict(r) for r in rows]})

@app.route('/api/dashboards/risk-trend', methods=['GET'])
@login_required
def api_dashboard_risk_trend():
    days = _dashboard_window_days(request)
    rows = get_db().execute(
        "SELECT date(computed_at) as day, SUM(points) as total_points FROM risk_score_events "
        "WHERE computed_at >= datetime('now', ?) GROUP BY day ORDER BY day ASC",
        (f'-{days} days',)
    ).fetchall()
    return jsonify({'trend': [dict(r) for r in rows]})

@app.route('/api/dashboards/top-risk-entities', methods=['GET'])
@login_required
def api_dashboard_top_risk_entities():
    days = _dashboard_window_days(request)
    db = get_db()
    cfg = get_risk_score_config(db)
    rows = db.execute(
        "SELECT entity_type, entity_id, SUM(points) as score, COUNT(*) as event_count, MAX(computed_at) as last_event "
        "FROM risk_score_events WHERE computed_at >= datetime('now', ?) "
        "GROUP BY entity_type, entity_id HAVING score > 0 ORDER BY score DESC LIMIT 10",
        (f'-{days} days',)
    ).fetchall()
    out = [{**dict(r), 'tier': _risk_tier(r['score'], cfg['tiers'])} for r in rows]
    return jsonify({'entities': out})

@app.route('/api/dashboards/top-anomaly-rules', methods=['GET'])
@login_required
def api_dashboard_top_anomaly_rules():
    days = _dashboard_window_days(request)
    rows = get_db().execute(
        "SELECT ar.id, ar.name, ar.entity_type, COUNT(rse.id) as matches "
        "FROM anomaly_rules ar JOIN risk_score_events rse ON rse.rule_id = ar.id "
        "WHERE rse.computed_at >= datetime('now', ?) AND ar.enabled = 1 "
        "GROUP BY ar.id ORDER BY matches DESC LIMIT 10",
        (f'-{days} days',)
    ).fetchall()
    return jsonify({'rules': [dict(r) for r in rows]})

_TOP_COUNTRIES_CACHE = {}

# Dedupe source IPs BEFORE doing any mmdb lookups -- a naive per-alert-row lookup on a
# 90-day window with thousands of alerts would mean thousands of redundant lookups for
# the same handful of IPs. `ip_counts` is already the SQL-deduped (source_ip, count)
# rows (capped at 500 distinct IPs by the caller's query); `lookup_fn` is injected so
# this can be unit tested without a real GeoIP database on disk.
def _aggregate_country_counts(ip_counts, lookup_fn):
    country_counts = {}
    for source_ip, count in ip_counts:
        iso, name = lookup_fn(source_ip)
        if not iso:
            continue  # private/reserved/unresolvable IPs excluded, not bucketed as "Unknown"
        entry = country_counts.setdefault(iso, {'iso_code': iso, 'country': name, 'count': 0})
        entry['count'] += count
    return sorted(country_counts.values(), key=lambda c: c['count'], reverse=True)[:10]

@app.route('/api/dashboards/top-countries', methods=['GET'])
@login_required
def api_dashboard_top_countries():
    from geoip import lookup_country
    import time
    days = _dashboard_window_days(request)
    cached = _TOP_COUNTRIES_CACHE.get(days)
    if cached and (time.time() - cached[0]) < RULES_CACHE_TTL:
        return jsonify(cached[1])
    rows = get_db().execute(
        "SELECT source_ip, COUNT(*) as count FROM alerts "
        "WHERE timestamp >= datetime('now', ?) AND source_ip IS NOT NULL AND source_ip != '' "
        "GROUP BY source_ip ORDER BY count DESC LIMIT 500",
        (f'-{days} days',)
    ).fetchall()
    result = {'countries': _aggregate_country_counts([(r['source_ip'], r['count']) for r in rows], lookup_country)}
    _TOP_COUNTRIES_CACHE[days] = (time.time(), result)
    return jsonify(result)

# Reuses agent_checkins()'s exact 45s/300s thresholds (see that route for why those
# specific numbers) so this widget's numbers agree with the EDR page's own.
def _agent_status_from_age(age_seconds):
    if age_seconds <= 45:
        return 'Online'
    if age_seconds <= 300:
        return 'Idle'
    return 'Offline'

@app.route('/api/dashboards/agent-status', methods=['GET'])
@login_required
def api_dashboard_agent_status():
    # No LIMIT 20 (unlike agent_checkins()), since this widget reports a total count
    # across every known agent, not just the most recently active ones. Deliberately
    # NOT range-filtered by the shared time selector -- "online right now" is a
    # point-in-time state, not a trend, so the frontend marks this widget as
    # real-time-only.
    import datetime  # shadows the module-level `from datetime import datetime` class
                      # import with the actual module, same as agent_checkins() does --
                      # needed for datetime.datetime.strptime below.
    db = get_db()
    rows = db.execute('SELECT * FROM agent_polls WHERE id IN (SELECT MAX(id) FROM agent_polls GROUP BY ip_address)').fetchall()
    now = datetime.datetime.now()
    counts = {'Online': 0, 'Idle': 0, 'Offline': 0, 'Unknown': 0}
    for r in rows:
        ts = r['timestamp'] if 'timestamp' in r.keys() else ''
        status = 'Unknown'
        try:
            age = (now - datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')).total_seconds()
            status = _agent_status_from_age(age)
        except (ValueError, TypeError):
            pass
        counts[status] += 1
    return jsonify({'status_counts': counts, 'total': len(rows)})

# Case metrics/SLA -- a single global SLA target (case_sla_hours, default 24) applies
# to every case; no per-queue/per-severity SLA tiers, matching the scope of every other
# single-appliance simplification in this app (queues, playbooks) over a full policy
# engine. julianday() diffs against created_at/closed_at require BOTH to be UTC (see
# the fix in api_case_detail()'s PUT handler) -- created_at already is, via SQLite's
# own CURRENT_TIMESTAMP default.
DEFAULT_CASE_SLA_HOURS = 24

def _case_sla_hours(db):
    row = db.execute("SELECT value FROM settings WHERE key = 'case_sla_hours'").fetchone()
    try:
        return int(row['value']) if row and row['value'] else DEFAULT_CASE_SLA_HOURS
    except (ValueError, TypeError):
        return DEFAULT_CASE_SLA_HOURS

@app.route('/api/dashboards/case-stats', methods=['GET'])
@login_required
def api_dashboard_case_stats():
    days = _dashboard_window_days(request)
    db = get_db()
    sla_hours = _case_sla_hours(db)
    open_count = db.execute("SELECT COUNT(*) FROM cases WHERE status = 'open'").fetchone()[0]
    closed_in_range = db.execute(
        "SELECT COUNT(*) FROM cases WHERE status = 'closed' AND closed_at >= datetime('now', ?)", (f'-{days} days',)
    ).fetchone()[0]
    avg_close_hours = db.execute(
        "SELECT AVG((julianday(closed_at) - julianday(created_at)) * 24) FROM cases "
        "WHERE status = 'closed' AND closed_at IS NOT NULL AND closed_at >= datetime('now', ?)", (f'-{days} days',)
    ).fetchone()[0]
    sla_breached = db.execute(
        "SELECT COUNT(*) FROM cases WHERE status = 'open' AND (julianday('now') - julianday(created_at)) * 24 > ?", (sla_hours,)
    ).fetchone()[0]
    return jsonify({
        'open_count': open_count,
        'closed_in_range_count': closed_in_range,
        'avg_close_hours': round(avg_close_hours, 1) if avg_close_hours is not None else None,
        'sla_target_hours': sla_hours,
        'sla_breached_count': sla_breached,
    })

@app.route('/api/dashboards/case-aging', methods=['GET'])
@login_required
def api_dashboard_case_aging():
    # Deliberately NOT range-filtered -- like agent-status/mitre-coverage, this is a
    # point-in-time snapshot of the CURRENT open caseload, not a trend over the range.
    rows = get_db().execute(
        "SELECT (julianday('now') - julianday(created_at)) * 24 as age_hours FROM cases WHERE status = 'open'"
    ).fetchall()
    buckets = [
        {'label': '< 1 day', 'count': 0}, {'label': '1-3 days', 'count': 0},
        {'label': '3-7 days', 'count': 0}, {'label': '7+ days', 'count': 0},
    ]
    for r in rows:
        h = r['age_hours'] or 0
        idx = 0 if h < 24 else (1 if h < 72 else (2 if h < 168 else 3))
        buckets[idx]['count'] += 1
    return jsonify({'buckets': buckets})

@app.route('/api/dashboards/case-queue-backlog', methods=['GET'])
@login_required
def api_dashboard_case_queue_backlog():
    rows = get_db().execute(
        "SELECT COALESCE(q.name, 'Unassigned') as name, COUNT(*) as count FROM cases c "
        "LEFT JOIN case_queues q ON q.id = c.queue_id WHERE c.status = 'open' "
        "GROUP BY c.queue_id ORDER BY count DESC"
    ).fetchall()
    return jsonify({'queues': [dict(r) for r in rows]})

@app.route('/api/dashboards/case-workload', methods=['GET'])
@login_required
def api_dashboard_case_workload():
    # GROUP BY on the COALESCE/NULLIF expression itself, not the raw `assignee` column --
    # grouping by the raw column would keep NULL and '' as two separate groups (both
    # display as "Unassigned" but count separately), splitting one bucket into two.
    rows = get_db().execute(
        "SELECT COALESCE(NULLIF(assignee, ''), 'Unassigned') as assignee, COUNT(*) as count FROM cases "
        "WHERE status = 'open' GROUP BY COALESCE(NULLIF(assignee, ''), 'Unassigned') ORDER BY count DESC"
    ).fetchall()
    return jsonify({'assignees': [dict(r) for r in rows]})

@app.route('/api/dashboards/case-close-trend', methods=['GET'])
@login_required
def api_dashboard_case_close_trend():
    days = _dashboard_window_days(request)
    rows = get_db().execute(
        "SELECT date(closed_at) as day, COUNT(*) as count FROM cases "
        "WHERE status = 'closed' AND closed_at >= datetime('now', ?) GROUP BY day ORDER BY day ASC", (f'-{days} days',)
    ).fetchall()
    return jsonify({'trend': [dict(r) for r in rows]})

@app.route('/api/settings/case-sla', methods=['GET', 'POST'])
@login_required
def api_case_sla_config():
    db = get_db()
    if request.method == 'GET':
        return jsonify({'sla_hours': _case_sla_hours(db)})
    err = require_permission('settings.case_sla.manage')
    if err: return err
    try:
        hours = int((request.json or {}).get('sla_hours'))
    except (TypeError, ValueError):
        return jsonify({'error': 'sla_hours must be a whole number'}), 400
    if hours < 1 or hours > 8760:
        return jsonify({'error': 'sla_hours must be between 1 and 8760 (1 year)'}), 400
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('case_sla_hours', ?)", (str(hours),))
    db.commit()
    log_audit('case_sla_update', 'settings', 'case_sla_hours', str(hours))
    return jsonify({'status': 'success', 'sla_hours': hours})

@app.route('/api/dashboards', methods=['GET', 'POST'])
@login_required
def api_dashboards():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute(
            "SELECT d.id, d.name, d.created_by, d.created_at, "
            "(SELECT COUNT(*) FROM dashboard_widgets WHERE dashboard_id = d.id) as widget_count "
            "FROM dashboards d ORDER BY d.name"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    # Unlike case_queues' POST (admin-only), any logged-in user can create a
    # dashboard here -- it's meant as "my own view," not fleet/team routing config.
    d = request.json or {}
    name = (d.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if db.execute("SELECT 1 FROM dashboards WHERE name = ?", (name,)).fetchone():
        return jsonify({'error': f'A dashboard named "{name}" already exists'}), 400
    cur = db.execute("INSERT INTO dashboards (name, created_by) VALUES (?, ?)", (name, current_user.username))
    db.commit()
    log_audit('dashboard_create', 'dashboard', name)
    return jsonify({'status': 'success', 'id': cur.lastrowid})

@app.route('/api/dashboards/<int:did>', methods=['PUT', 'DELETE'])
@login_required
def api_dashboard_detail(did):
    db = get_db()
    existing = db.execute("SELECT name, created_by FROM dashboards WHERE id = ?", (did,)).fetchone()
    if not existing:
        return jsonify({'error': 'Dashboard not found'}), 404
    # The one place in this app that checks a row's own created_by as an ACL rather
    # than a flat role check -- creators own the dashboards they made, admins can
    # clean up anyone's. Everything else here (GET, adding/moving widgets) is open
    # to any logged-in user; only rename/delete of the dashboard itself is gated.
    if existing['created_by'] != current_user.username and not is_admin():
        return jsonify({'error': 'Only the dashboard creator or an admin can modify this dashboard'}), 403

    if request.method == 'DELETE':
        # Manual cascade, matching queue_members' precedent -- this app never enables
        # PRAGMA foreign_keys, so an ON DELETE CASCADE in the schema would be a no-op.
        db.execute("UPDATE roles SET default_dashboard_id = NULL WHERE default_dashboard_id = ?", (did,))
        db.execute("DELETE FROM dashboard_widgets WHERE dashboard_id = ?", (did,))
        db.execute("DELETE FROM dashboards WHERE id = ?", (did,))
        db.commit()
        log_audit('dashboard_delete', 'dashboard', existing['name'])
        return jsonify({'ok': 1})

    d = request.json or {}
    name = (d.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if db.execute("SELECT 1 FROM dashboards WHERE name = ? AND id != ?", (name, did)).fetchone():
        return jsonify({'error': f'A dashboard named "{name}" already exists'}), 400
    db.execute("UPDATE dashboards SET name = ? WHERE id = ?", (name, did))
    db.commit()
    log_audit('dashboard_rename', 'dashboard', name)
    return jsonify({'status': 'success'})

@app.route('/api/dashboards/<int:did>/widgets', methods=['GET', 'POST'])
@login_required
def api_dashboard_widgets(did):
    db = get_db()
    if not db.execute("SELECT 1 FROM dashboards WHERE id = ?", (did,)).fetchone():
        return jsonify({'error': 'Dashboard not found'}), 404

    if request.method == 'GET':
        rows = db.execute(
            "SELECT id, widget_type, x, y, w, h, config FROM dashboard_widgets WHERE dashboard_id = ? ORDER BY id",
            (did,)
        ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item['config'] = json.loads(item['config']) if item['config'] else {}
            out.append(item)
        return jsonify(out)

    # Adding/removing/rearranging widgets is open to any logged-in user, matching
    # how case items/tasks are editable by anyone today -- only the dashboard row
    # itself (rename/delete) is creator-or-admin gated, see api_dashboard_detail().
    d = request.json or {}
    widget_type = d.get('widget_type')
    if widget_type not in WIDGET_TYPES:
        return jsonify({'error': f'Unknown widget_type: {widget_type}'}), 400
    x, y, w, h = d.get('x', 0), d.get('y', 0), d.get('w', 4), d.get('h', 4)
    config = json.dumps(d.get('config')) if d.get('config') else None
    cur = db.execute(
        "INSERT INTO dashboard_widgets (dashboard_id, widget_type, x, y, w, h, config) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (did, widget_type, x, y, w, h, config)
    )
    db.commit()
    return jsonify({'status': 'success', 'id': cur.lastrowid})

@app.route('/api/dashboards/<int:did>/widgets/layout', methods=['PUT'])
@login_required
def api_dashboard_widgets_layout(did):
    db = get_db()
    if not db.execute("SELECT 1 FROM dashboards WHERE id = ?", (did,)).fetchone():
        return jsonify({'error': 'Dashboard not found'}), 404
    items = request.json or []
    if not isinstance(items, list):
        return jsonify({'error': 'expected a JSON array'}), 400
    for item in items:
        wid = item.get('id')
        if wid is None:
            continue
        # The "AND dashboard_id = ?" guard stops a stale/forged client payload from
        # repointing another dashboard's widget rows.
        db.execute(
            "UPDATE dashboard_widgets SET x = ?, y = ?, w = ?, h = ? WHERE id = ? AND dashboard_id = ?",
            (item.get('x', 0), item.get('y', 0), item.get('w', 4), item.get('h', 4), wid, did)
        )
    db.commit()
    return jsonify({'status': 'success'})

@app.route('/api/dashboards/<int:did>/widgets/<int:wid>', methods=['PUT', 'DELETE'])
@login_required
def api_dashboard_widget_detail(did, wid):
    db = get_db()
    if not db.execute("SELECT 1 FROM dashboard_widgets WHERE id = ? AND dashboard_id = ?", (wid, did)).fetchone():
        return jsonify({'error': 'Widget not found'}), 404
    if request.method == 'DELETE':
        db.execute("DELETE FROM dashboard_widgets WHERE id = ?", (wid,))
        db.commit()
        return jsonify({'ok': 1})
    d = request.json or {}
    if 'config' in d:
        config = json.dumps(d.get('config')) if d.get('config') else None
        db.execute("UPDATE dashboard_widgets SET config = ? WHERE id = ?", (config, wid))
        db.commit()
    return jsonify({'status': 'success'})

# ==========================================
# GLOBAL SETTINGS & AGENT DEPLOYMENT ROUTES
# ==========================================
def migrate_settings():
    try:
        import sqlite3
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('soc_secret', ?)", (secrets.token_hex(16),))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('soar_api_key', ?)", (secrets.token_hex(24),))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_lookback_days', '30')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_stddev_multiplier', '3')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_min_baseline', '50')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_min_days_observed', '4')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_new_ip_enabled', '1')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_new_process_enabled', '1')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_new_dest_ip_enabled', '1')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_process_lineage_enabled', '1')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_off_hours_enabled', '1')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_rare_process_enabled', '1')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_rare_process_max_hosts', '2')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_convergence_enabled', '1')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_convergence_min_indicators', '3')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_convergence_window_hours', '24')")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ti_feeds():
    try:
        import sqlite3
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS ti_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            feed_type TEXT NOT NULL,
            discovery_url TEXT,
            collection_id TEXT,
            username TEXT,
            password TEXT,
            api_key TEXT,
            sync_interval_minutes INTEGER,
            enabled BOOLEAN DEFAULT 1,
            last_sync DATETIME,
            last_status TEXT,
            last_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        cols = {row[1] for row in conn.execute("PRAGMA table_info(ti_feeds)").fetchall()}
        if 'api_key' not in cols:
            conn.execute("ALTER TABLE ti_feeds ADD COLUMN api_key TEXT")
        if 'sync_interval_minutes' not in cols:
            conn.execute("ALTER TABLE ti_feeds ADD COLUMN sync_interval_minutes INTEGER")
        conn.execute("INSERT OR IGNORE INTO ti_feeds (id, name, feed_type, enabled) VALUES (1, 'ThreatFox Recent (Public)', 'threatfox', 1)")
        # Seeded disabled — public/no-auth so they work the moment a user flips them
        # on, but auto-adding new IOC volume to an existing deployment without being
        # asked isn't this migration's call to make.
        conn.execute("INSERT OR IGNORE INTO ti_feeds (id, name, feed_type, enabled) VALUES (2, 'URLhaus Recent Malicious URLs (Public)', 'urlhaus', 0)")
        conn.execute("INSERT OR IGNORE INTO ti_feeds (id, name, feed_type, enabled) VALUES (3, 'Feodo Tracker Botnet C2 IPs (Public)', 'feodotracker', 0)")
        # Not a fixed id like the three above -- those are safe only because they've
        # claimed ids 1-3 since this table's very first row ever, before a user could
        # add a custom feed of their own. Added later, id 4 has no such guarantee (a
        # real deployment can easily have already auto-assigned it to a user's own
        # feed by now), so this checks by feed_type and lets AUTOINCREMENT pick
        # whatever id is actually free instead of risking a silent INSERT OR IGNORE
        # no-op against an unrelated row that happens to already own id 4.
        if not conn.execute("SELECT 1 FROM ti_feeds WHERE feed_type = 'tor_exit'").fetchone():
            conn.execute("INSERT INTO ti_feeds (name, feed_type, enabled) VALUES ('Tor Exit Nodes (Public)', 'tor_exit', 0)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_stix_indicators():
    # `type` has only ever held the literal STIX object type ("indicator") on every
    # row from every feed — useless for filtering. ioc_type carries each feed's own
    # classification (ip, url, domain, FileHash-SHA256, ...) instead. feed_id lets the
    # IOC browser show and filter by which feed an indicator actually came from,
    # which the schema never tracked before this.
    try:
        import sqlite3
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(stix_indicators)").fetchall()}
        if 'ioc_type' not in cols:
            conn.execute("ALTER TABLE stix_indicators ADD COLUMN ioc_type TEXT")
        if 'feed_id' not in cols:
            conn.execute("ALTER TABLE stix_indicators ADD COLUMN feed_id INTEGER")
        conn.commit()

        # One-time backfill for rows synced before ioc_type/feed_id existed. A resync
        # only INSERT OR REPLACEs whatever's still in a feed's *current* export, so an
        # indicator that's since rotated out of ThreatFox/URLhaus/etc.'s rolling window
        # never gets touched again — without this, it shows a blank Type and "Unknown"
        # Source in the Indicator Browser forever. Best-effort infer feed_id from the
        # stix_id's own "<feed_type>--..." prefix (every feed type but generic TAXII
        # stamps one) and ioc_type from the pattern's shape.
        blank_rows = conn.execute(
            "SELECT stix_id, pattern FROM stix_indicators WHERE ioc_type IS NULL OR ioc_type = ''"
        ).fetchall()
        if blank_rows:
            feed_id_by_type = {}
            for fid, ftype in conn.execute("SELECT id, feed_type FROM ti_feeds ORDER BY id").fetchall():
                feed_id_by_type.setdefault(ftype, fid)
            prefix_to_type = (('threatfox--', 'threatfox'), ('urlhaus--', 'urlhaus'),
                               ('feodotracker--', 'feodotracker'), ('otx--', 'otx'), ('csv--', 'csv'))
            updates = []
            for stix_id, pattern in blank_rows:
                feed_type = next((t for p, t in prefix_to_type if stix_id.startswith(p)), None)
                feed_id = feed_id_by_type.get(feed_type) if feed_type else None
                updates.append((_guess_legacy_ioc_type(pattern), feed_id, stix_id))
            conn.executemany(
                "UPDATE stix_indicators SET ioc_type = ?, feed_id = COALESCE(feed_id, ?) WHERE stix_id = ?",
                updates
            )
            conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_agent_commands():
    try:
        import sqlite3
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS agent_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            label TEXT NOT NULL,
            script TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            queued_by TEXT,
            queued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            exit_code INTEGER,
            stdout TEXT,
            stderr TEXT
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_commands_host_status ON agent_commands(hostname, status)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_alerts_columns():
    # alerts predates the wider schema (rule_name/host/message added alongside the
    # rule_id/event_id FK columns for the inline keyword-detection path) — on any database
    # where the table already existed, `CREATE TABLE IF NOT EXISTS` in schema.sql is a no-op
    # and never adds the new columns. ALTER TABLE here catches already-deployed databases up.
    try:
        import sqlite3
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        for col in ('rule_name', 'host', 'message'):
            if col not in cols:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_alerts_enrichment():
    # sigma_engine's alert path only ever stored rule_id/event_id/severity, leaving host/
    # message to be looked up via a live join to live_logs whenever an alert needed to be
    # displayed — fine for one alert at a time, but expensive for Log Search's unified
    # view once it has to UNION against multi-million-row live_logs on every query.
    # sigma_engine.py now writes host/message/username/source_ip/destination_ip directly
    # onto the alert row at insert time; this backfills existing rows once so historical
    # alerts don't show blank/UNKNOWN after the join is removed from that query.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        for col in ('username', 'source_ip', 'destination_ip', 'log_event_id', 'log_app'):
            if col not in cols:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
        conn.execute("""
            UPDATE alerts SET
                host = COALESCE(host, (SELECT host FROM live_logs WHERE live_logs.id = alerts.event_id)),
                message = COALESCE(message, (SELECT message FROM live_logs WHERE live_logs.id = alerts.event_id)),
                username = COALESCE(username, (SELECT username FROM live_logs WHERE live_logs.id = alerts.event_id)),
                source_ip = COALESCE(source_ip, (SELECT source_ip FROM live_logs WHERE live_logs.id = alerts.event_id)),
                destination_ip = COALESCE(destination_ip, (SELECT destination_ip FROM live_logs WHERE live_logs.id = alerts.event_id)),
                log_event_id = COALESCE(log_event_id, (SELECT event_id FROM live_logs WHERE live_logs.id = alerts.event_id)),
                log_app = COALESCE(log_app, (SELECT app FROM live_logs WHERE live_logs.id = alerts.event_id))
            WHERE event_id IS NOT NULL AND (host IS NULL OR message IS NULL OR log_event_id IS NULL)
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass

# The same rule firing repeatedly against the same host/user within a short window used
# to insert a brand-new alerts row every time -- occurrence_count/last_seen let a
# recurrence update the existing row instead (see sigma_engine.py's pending_alerts
# write phase and api_ingest's inline heuristic path), collapsing repeat noise into one
# tracked alert with a count. occurrence_count defaults to 1 so every pre-existing row
# reads correctly without a backfill pass.
def migrate_alerts_dedup_columns():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if 'occurrence_count' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1")
        if 'last_seen' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN last_seen DATETIME")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_alerts_triage():
    # Adds the triage lifecycle (status + assignee) on top of the existing binary
    # acknowledged flag -- acknowledged is left untouched (still drives the Home widget's
    # "unacknowledged" list unchanged) so this is purely additive, no behavior change for
    # anyone who never opens the new status/assignee controls.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if 'status' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'new'")
        if 'assignee' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN assignee TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_alerts_geoip_columns():
    # Stamped once at alert-creation time (both alert-insert paths: the inline
    # heuristic path in api_ingest and sigma_engine.py's rule pipeline) instead of the
    # every-render on-demand geoip.lookup_country() call this used to require in the
    # case-item summary, log search response, and top-countries chart -- those three
    # read sites now prefer these columns and only fall back to a live lookup for a
    # row created before this migration (where the columns are still NULL).
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if 'country_code' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN country_code TEXT")
        if 'country_name' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN country_name TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_alerts_mitre_column():
    # Comma-joined MITRE technique IDs (same convention as sigma_rules.compliance_tags
    # and ti_entities.techniques), stamped once by sigma_engine.py at alert-creation
    # time from the triggering rule's own tags -- an alert can now be queried/filtered
    # by technique directly, without joining back to sigma_rules and re-parsing its
    # rule_yaml. The heuristic detection path in api_ingest has no Sigma rule behind it
    # (no tags to draw from), so those alerts simply keep this column NULL/empty.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if 'mitre_techniques' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN mitre_techniques TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_sigma_rules_columns():
    # sigma_rules originally had no provenance columns — rules bulk-imported from SigmaHQ
    # and rules hand-written in the editor were indistinguishable. ALTER TABLE catches
    # already-deployed databases up; existing rows are backfilled as source='sigma' since
    # the SigmaHQ bulk import is overwhelmingly what populated them historically.
    try:
        import sqlite3, re as _re
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sigma_rules)").fetchall()}
        need_uuid_backfill = 'sigma_uuid' not in cols

        if 'source' not in cols:
            conn.execute("ALTER TABLE sigma_rules ADD COLUMN source TEXT DEFAULT 'sigma'")
            conn.execute("UPDATE sigma_rules SET source = 'sigma' WHERE source IS NULL")
        for col, coltype in (('sigma_uuid', 'TEXT'), ('cloned_from', 'INTEGER'),
                              ('created_by', 'TEXT'), ('created_at', 'DATETIME'),
                              ('updated_by', 'TEXT'), ('updated_at', 'DATETIME')):
            if col not in cols:
                conn.execute(f"ALTER TABLE sigma_rules ADD COLUMN {col} {coltype}")

        if need_uuid_backfill:
            # One-time pass so re-importing SigmaHQ later can upsert by UUID instead of
            # blindly re-inserting every rule already loaded by the original import script.
            id_re = _re.compile(r'^id:\s*([0-9a-fA-F-]{36})\s*$', _re.MULTILINE)
            for rid, ry in conn.execute("SELECT id, rule_yaml FROM sigma_rules WHERE sigma_uuid IS NULL").fetchall():
                m = id_re.search(ry or '')
                if m:
                    conn.execute("UPDATE sigma_rules SET sigma_uuid = ? WHERE id = ?", (m.group(1), rid))

        conn.execute('''CREATE TABLE IF NOT EXISTS sigma_rule_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            changed_by TEXT,
            changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            old_yaml TEXT,
            new_yaml TEXT
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sigma_rule_history_rule ON sigma_rule_history(rule_id)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_rule_tuning():
    # Detection Tuning needs a per-rule severity override and a table of per-rule
    # exclusion filters — neither existed when sigma_rules/rule_exclusions were first
    # deployed, so ALTER TABLE / CREATE TABLE IF NOT EXISTS catch already-deployed DBs up.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sigma_rules)").fetchall()}
        if 'severity_override' not in cols:
            conn.execute("ALTER TABLE sigma_rules ADD COLUMN severity_override TEXT")
        conn.execute('''CREATE TABLE IF NOT EXISTS rule_exclusions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            field TEXT NOT NULL,
            operator TEXT NOT NULL DEFAULT 'contains',
            value TEXT NOT NULL,
            description TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_exclusions_rule ON rule_exclusions(rule_id)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_rule_autocase():
    # Lets an admin flag a rule so a genuinely NEW alert from it (not a re-occurrence
    # bump within sigma_engine.py's existing 15-minute dedup window) auto-creates a
    # Case, optionally seeded from a case_templates task list -- same ALTER-TABLE-catch-
    # up pattern as migrate_rule_tuning()'s severity_override column above.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sigma_rules)").fetchall()}
        if 'auto_case' not in cols:
            conn.execute("ALTER TABLE sigma_rules ADD COLUMN auto_case BOOLEAN DEFAULT 0")
        if 'auto_case_template_id' not in cols:
            conn.execute("ALTER TABLE sigma_rules ADD COLUMN auto_case_template_id INTEGER")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ueba_math_v2():
    # Day-of-week baselines + a flat-baseline fallback for entities that don't have
    # enough same-weekday history yet — both need to record which mode produced the
    # numbers (days_seen, baseline_mode) so the visibility view can show it honestly.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(ueba_entity_baselines)").fetchall()}
        if 'days_seen' not in cols:
            conn.execute("ALTER TABLE ueba_entity_baselines ADD COLUMN days_seen INTEGER")
        if 'baseline_mode' not in cols:
            conn.execute("ALTER TABLE ueba_entity_baselines ADD COLUMN baseline_mode TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

# Lets an admin mark a specific host or user as more important than the fleet default,
# so its risk score is weighted up (see CRITICALITY_MULTIPLIERS and where it's applied
# in api_ueba_risk_scores below) -- a domain controller or an
# admin account tripping the same indicator as a random workstation deserves more
# attention, not the same flat score. One row per host/username (UNIQUE), admin-managed.
def migrate_assets_identities():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL UNIQUE,
            criticality TEXT NOT NULL DEFAULT 'standard',
            owner TEXT,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS identities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            department TEXT,
            privileged BOOLEAN DEFAULT 0,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_cases():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            assignee TEXT,
            description TEXT,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            closed_at DATETIME
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS case_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            item_id TEXT NOT NULL,
            added_by TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_case_items_case ON case_items(case_id)')
        conn.commit()
        conn.close()
    except Exception:
        pass

QUEUE_SEED = [
    ('Insider Threat', 'Suspected malicious or negligent insider activity.'),
    ('SOC Tier 1', 'Initial triage -- first responders.'),
    ('SOC Tier 2', 'Escalated cases requiring deeper investigation.'),
    ('SOC Tier 3', 'Advanced/specialist escalation -- threat hunting, forensics, incident command.'),
]

CASE_TEMPLATES_SEED = [
    {'name': 'Phishing Investigation', 'description': 'Standard checklist for a reported phishing email.',
     'tasks': ['Identify sender/return-path and originating IP', 'Check for other recipients of the same message',
               'Extract and detonate/analyze attachments or links', 'Check if any recipient clicked/entered credentials',
               'Block sender domain/URL at the mail gateway', 'Force password reset if credentials were entered',
               'Notify affected users']},
    {'name': 'Malware Incident', 'description': 'Standard checklist for a confirmed malware detection on an endpoint.',
     'tasks': ['Isolate the affected host', 'Identify the malware family and initial access vector',
               'Collect and hash the malicious file(s)', 'Check for lateral movement / other affected hosts',
               'Sweep environment for the same IOC (hash/domain/IP)', 'Remove/reimage the affected host',
               'Document root cause and update detections']},
    {'name': 'Compromised Account', 'description': 'Standard checklist for a suspected or confirmed account compromise.',
     'tasks': ['Force password reset and revoke active sessions', 'Review sign-in logs for anomalous locations/times',
               'Check for mailbox rules, forwarding, or OAuth grants added by the attacker',
               'Check for lateral use of the account (other systems accessed)', 'Notify the account owner',
               'Enable/verify MFA on the account']},
    {'name': 'Generic Investigation', 'description': 'A minimal starting checklist for anything else.',
     'tasks': ['Scope what triggered this case', 'Determine affected hosts/users', 'Contain if needed',
               'Document findings', 'Close out or escalate']},
]

def migrate_case_upgrade():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
        if 'tlp' not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN tlp TEXT NOT NULL DEFAULT 'clear'")
        if 'pap' not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN pap TEXT NOT NULL DEFAULT 'clear'")
        conn.execute('''CREATE TABLE IF NOT EXISTS case_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            assignee TEXT,
            position INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_case_tasks_case ON case_tasks(case_id)')
        conn.execute('''CREATE TABLE IF NOT EXISTS case_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            actor TEXT,
            event_type TEXT NOT NULL,
            detail TEXT
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events(case_id)')
        conn.execute('''CREATE TABLE IF NOT EXISTS case_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            tasks TEXT NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        # Same growable-seed pattern as ti_entities: INSERT OR IGNORE per-row, keyed on
        # UNIQUE(name), so a future built-in template ships automatically without
        # touching a template an admin has already edited.
        for t in CASE_TEMPLATES_SEED:
            conn.execute(
                "INSERT OR IGNORE INTO case_templates (name, description, tasks, created_by) VALUES (?, ?, ?, 'system')",
                (t['name'], t['description'], json.dumps(t['tasks']))
            )
        conn.commit()
        conn.close()
    except Exception:
        pass

# Mirrors Exabeam Case Manager's queue model (per the session's own research pass):
# a queue is just a named group cases get manually routed into/between, with a
# membership list -- no rule-based auto-routing exists there either, so this doesn't
# either. Same growable-seed pattern as case_templates above (INSERT OR IGNORE keyed
# on UNIQUE(name)) so the 4 starter queues reappear if deleted but an admin's rename/
# edit of one survives a re-run.
def migrate_case_queues():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS case_queues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS queue_members (
            queue_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            PRIMARY KEY (queue_id, username)
        )''')
        cols = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
        if 'queue_id' not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN queue_id INTEGER")
        for name, desc in QUEUE_SEED:
            conn.execute("INSERT OR IGNORE INTO case_queues (name, description, created_by) VALUES (?, ?, 'system')", (name, desc))
        conn.commit()
        conn.close()
    except Exception:
        pass

# A case's "blast radius" -- which hosts are actually implicated, at what confidence
# (an analyst's own judgment call, not auto-derived), and optionally what indicator
# put them there. `host` is a plain string (matching how every other host reference in
# this app works -- alerts.host, events.hostname, live_logs.host are none of them FKs
# either) rather than a hard link to the global `assets` table, since a case can easily
# involve a host that has no `assets` row yet; the UI still joins against `assets` by
# host name to show criticality when one exists.
def migrate_case_assets():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS case_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            compromise_status TEXT NOT NULL DEFAULT 'suspected',
            related_indicator TEXT,
            notes TEXT,
            added_by TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id, host)
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_case_assets_case ON case_assets(case_id)")
        conn.commit()
        conn.close()
    except Exception:
        pass

# Layered on top of the existing open/closed `status` (which SLA math, playbook
# `condition_status` filters, and the cases-list sort all key off of and which this
# migration deliberately leaves untouched) rather than replacing it -- `workflow_state`
# is the analyst-facing triage-progress indicator (New/Investigating/Awaiting Input/
# Resolved), `severity` is a plain priority signal, and `acknowledged_at` is TTA (time
# to acknowledge): set once, the first time workflow_state moves off 'new'.
def migrate_case_severity():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
        if 'severity' not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN severity TEXT NOT NULL DEFAULT 'medium'")
        if 'workflow_state' not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN workflow_state TEXT NOT NULL DEFAULT 'new'")
        if 'acknowledged_at' not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN acknowledged_at DATETIME")
        conn.commit()
        conn.close()
    except Exception:
        pass

# A case's structured observables (hash/domain/IP/URL) -- distinct from case_assets
# (implicated HOSTS with a compromise-status lifecycle). See CASE_IOC_TYPES' comment
# for why these are kept as separate concepts rather than folded together.
def migrate_case_iocs():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS case_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            notes TEXT,
            added_by TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id, ioc_type, value)
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_case_iocs_case ON case_iocs(case_id)")
        conn.commit()
        conn.close()
    except Exception:
        pass

# widget_type -> {} for now (validation only -- rendering is entirely client-side,
# see WIDGET_REGISTRY in dashboards.html). The 5 app_* keys (Alerts/Cases/Log Search/
# Threat Hunter/EDR Response Actions) land in a later batch as a purely additive diff
# to this same dict -- nothing else here needs to change when they do.
WIDGET_TYPES = {
    'chart_alert_trend': {}, 'chart_severity': {}, 'chart_risk_trend': {},
    'chart_top_risk_entities': {}, 'chart_top_anomaly_rules': {}, 'chart_top_countries': {},
    'chart_agent_status': {}, 'chart_mitre_coverage': {}, 'chart_threat_actors': {},
    'chart_case_stats': {}, 'chart_case_aging': {}, 'chart_case_queue_backlog': {},
    'chart_case_workload': {}, 'chart_case_close_trend': {}, 'chart_compliance_coverage': {},
    # "App" widgets (Batch 2) -- compact live embeds of other pages, all reusing their
    # existing endpoints (/api/alerts, /api/cases, /api/logs/search, /api/ti/lookup,
    # /api/agent/commands) rather than any new backend logic. Purely additive to this
    # dict; see WIDGET_REGISTRY in dashboards.html for the actual render functions.
    'app_alerts': {}, 'app_cases': {}, 'app_log_search': {},
    'app_threat_hunter': {}, 'app_edr_actions': {},
    # Ported from the retired standalone Home page -- see DEFAULT_HOME_WIDGETS below.
    'app_stat_tiles': {},
}

# The default "Overview" dashboard's seeded layout -- reproduces today's fixed-page
# 2-column visual rhythm on a 12-column GridStack grid, so upgrading users see no
# loss of functionality: it just becomes an editable/deletable dashboard like any
# other instead of the only page that ever existed. chart_case_stats bundles the 4
# SLA stat tiles as one widget, matching how they're already one card today.
DEFAULT_OVERVIEW_WIDGETS = [
    ('chart_alert_trend', 0, 0, 8, 4),
    ('chart_severity', 8, 0, 4, 4),
    ('chart_risk_trend', 0, 4, 8, 4),
    ('chart_top_risk_entities', 8, 4, 4, 4),
    ('chart_top_anomaly_rules', 0, 8, 4, 4),
    ('chart_top_countries', 4, 8, 4, 4),
    ('chart_agent_status', 8, 8, 4, 4),
    ('chart_mitre_coverage', 0, 12, 12, 5),
    ('chart_threat_actors', 0, 17, 12, 5),
    ('chart_case_stats', 0, 22, 12, 3),
    ('chart_case_aging', 0, 25, 4, 4),
    ('chart_case_queue_backlog', 4, 25, 4, 4),
    ('chart_case_workload', 8, 25, 4, 4),
    ('chart_case_close_trend', 0, 29, 12, 4),
]

# Reproduces the retired Home page's fixed layout (stat strip + Recent Alerts +
# Top Risk Entities) as a second seeded dashboard, additive alongside 'Overview' --
# see migrate_role_default_dashboard() for how roles get pointed at this by default.
DEFAULT_HOME_WIDGETS = [
    ('app_stat_tiles', 0, 0, 12, 2),
    ('app_alerts', 0, 2, 6, 5),
    ('chart_top_risk_entities', 6, 2, 6, 5),
]

# Tier 3's own default -- leans into what that tier owns beyond Tier 1/2 (hunting,
# detection-rule tuning signal, UEBA/risk visibility, MITRE coverage) while still
# surfacing Alerts/Cases for triage oversight. See migrate_role_default_dashboard_v2().
DEFAULT_SENIOR_ANALYST_WIDGETS = [
    ('app_threat_hunter', 0, 0, 4, 4),
    ('chart_top_anomaly_rules', 4, 0, 4, 4),
    ('chart_top_risk_entities', 8, 0, 4, 4),
    ('chart_risk_trend', 0, 4, 8, 4),
    ('chart_case_workload', 8, 4, 4, 4),
    ('chart_mitre_coverage', 0, 8, 12, 5),
    ('app_alerts', 0, 13, 6, 5),
    ('app_cases', 6, 13, 6, 5),
]

def migrate_dashboards():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS dashboards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS dashboard_widgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dashboard_id INTEGER NOT NULL,
            widget_type TEXT NOT NULL,
            x INTEGER NOT NULL DEFAULT 0,
            y INTEGER NOT NULL DEFAULT 0,
            w INTEGER NOT NULL DEFAULT 4,
            h INTEGER NOT NULL DEFAULT 4,
            config TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_dashboard ON dashboard_widgets(dashboard_id)")

        row = conn.execute("SELECT id FROM dashboards WHERE name = 'Overview'").fetchone()
        if not row:
            cur = conn.execute("INSERT INTO dashboards (name, created_by) VALUES ('Overview', 'system')")
            did = cur.lastrowid
            for widget_type, x, y, w, h in DEFAULT_OVERVIEW_WIDGETS:
                conn.execute(
                    "INSERT INTO dashboard_widgets (dashboard_id, widget_type, x, y, w, h) VALUES (?, ?, ?, ?, ?, ?)",
                    (did, widget_type, x, y, w, h)
                )

        home_row = conn.execute("SELECT id FROM dashboards WHERE name = 'Home'").fetchone()
        if not home_row:
            cur = conn.execute("INSERT INTO dashboards (name, created_by) VALUES ('Home', 'system')")
            did = cur.lastrowid
            for widget_type, x, y, w, h in DEFAULT_HOME_WIDGETS:
                conn.execute(
                    "INSERT INTO dashboard_widgets (dashboard_id, widget_type, x, y, w, h) VALUES (?, ?, ?, ?, ?, ?)",
                    (did, widget_type, x, y, w, h)
                )

        sa_row = conn.execute("SELECT id FROM dashboards WHERE name = 'Senior Analyst'").fetchone()
        if not sa_row:
            cur = conn.execute("INSERT INTO dashboards (name, created_by) VALUES ('Senior Analyst', 'system')")
            did = cur.lastrowid
            for widget_type, x, y, w, h in DEFAULT_SENIOR_ANALYST_WIDGETS:
                conn.execute(
                    "INSERT INTO dashboard_widgets (dashboard_id, widget_type, x, y, w, h) VALUES (?, ?, ?, ?, ?, ?)",
                    (did, widget_type, x, y, w, h)
                )
        conn.commit()
        conn.close()
    except Exception:
        pass

# One-time cleanup for the 'Analyst'/'Admin' (capitalized) role-casing bug: the old
# ALTER TABLE default and the user-create route both wrote capitalized values, but
# every real permission check in this app compares lowercase ('admin', now also
# 'senior_analyst'/'analyst') -- an account written as 'Admin' was silently treated as
# a non-admin everywhere except its own badge color. Also normalizes the legacy
# two-tier 'Admin'/'Analyst' vocabulary to the new three-tier one; anything already
# using the new lowercase values (including 'senior_analyst', which was never
# capitalized since it didn't exist before this migration) is left untouched.
def migrate_role_casing():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute("UPDATE users SET role = 'admin' WHERE role = 'Admin'")
        conn.execute("UPDATE users SET role = 'analyst' WHERE role = 'Analyst'")
        conn.commit()
        conn.close()
    except Exception:
        pass

# Named-permission roles, replacing the old fixed analyst/senior_analyst/admin rank
# ladder. Seeded ONLY the first time this runs (roles table starts empty) with the 3
# original tiers as built-in (is_builtin=1, never deletable) roles, and their exact
# former permission sets, so this migration is a behavior-preserving upgrade -- an
# existing user's access doesn't change on the day this ships. See PERMISSION_REGISTRY
# above for what each key gates.
_SENIOR_ANALYST_PERMISSIONS = {
    'cases.delete', 'logsearch.droprules.manage', 'rules.manage', 'ueba.config.manage',
    'threatintel.manage', 'edr.command.basic', 'edr.command.advanced', 'edr.agent.manage',
    'edr.fim.manage', 'soar.playbooks.manage', 'assets.manage', 'settings.reports.manage',
    'settings.notifications.manage',
}
_BUILTIN_ROLE_SEED = {
    'analyst': ('Tier 1/2 Analyst', 'Triage, cases, incident response', {'edr.command.basic'}),
    'senior_analyst': ('Tier 3 Senior Analyst', 'Adds hunting, detection tuning, backend data', _SENIOR_ANALYST_PERMISSIONS),
    'admin': ('Admin', 'Adds users, certs, backups, system settings', PERMISSION_KEYS),
}

def migrate_role_permissions():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            description TEXT,
            is_builtin INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_key TEXT NOT NULL,
            PRIMARY KEY (role_id, permission_key)
        )''')
        if conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0] == 0:
            for slug, (label, description, perms) in _BUILTIN_ROLE_SEED.items():
                cur = conn.execute(
                    "INSERT INTO roles (slug, label, description, is_builtin) VALUES (?, ?, ?, 1)",
                    (slug, label, description)
                )
                rid = cur.lastrowid
                conn.executemany(
                    "INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)",
                    [(rid, key) for key in perms]
                )
        conn.commit()
        conn.close()
    except Exception:
        pass

# Lets each role default into a specific dashboard on login instead of always
# falling back to 'Overview' -- see loadDashboards()'s fallback chain in
# dashboards.html. Backfill only touches rows still NULL, so re-running this
# after an admin has customized a role's default via Settings never clobbers it.
def migrate_role_default_dashboard():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(roles)").fetchall()}
        if 'default_dashboard_id' not in cols:
            conn.execute("ALTER TABLE roles ADD COLUMN default_dashboard_id INTEGER")
        home_row = conn.execute("SELECT id FROM dashboards WHERE name = 'Home'").fetchone()
        if home_row:
            conn.execute(
                "UPDATE roles SET default_dashboard_id = ? "
                "WHERE slug IN ('analyst','senior_analyst','admin') AND default_dashboard_id IS NULL",
                (home_row[0],)
            )
        conn.commit()
        conn.close()
    except Exception:
        pass

# Re-points the 3 built-in roles from the generic 'Home' seed to tier-specific
# dashboards -- 'analyst' reuses the existing hand-built 'Analyst Triage' dashboard
# rather than a redundant new one; 'senior_analyst' gets the new seeded dashboard;
# 'admin' moves to 'Overview' (already built for the fleet-wide/leadership view an
# admin wants). Only touches a role that's still on NULL or still on the exact 'Home'
# id -- i.e. untouched since migrate_role_default_dashboard() ran -- so a real
# customization made via Settings in between is never clobbered.
def migrate_role_default_dashboard_v2():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.row_factory = sqlite3.Row
        home_row = conn.execute("SELECT id FROM dashboards WHERE name = 'Home'").fetchone()
        home_id = home_row['id'] if home_row else None

        def repoint(slug, dashboard_name):
            target = conn.execute("SELECT id FROM dashboards WHERE name = ?", (dashboard_name,)).fetchone()
            if not target:
                return
            conn.execute(
                "UPDATE roles SET default_dashboard_id = ? "
                "WHERE slug = ? AND (default_dashboard_id IS NULL OR default_dashboard_id = ?)",
                (target['id'], slug, home_id)
            )
        repoint('admin', 'Overview')
        repoint('analyst', 'Analyst Triage')
        repoint('senior_analyst', 'Senior Analyst')
        conn.commit()
        conn.close()
    except Exception:
        pass

# The SOAR module's real content (mirrors Exabeam Incident Responder's playbook concept,
# scoped way down): a trigger event, optional condition filters (queue/TLP/status), and
# an ordered list of actions run against the case that fired it. Deliberately not a
# visual builder with 40+ third-party integrations -- every action type reuses machinery
# this app already has (case templates, tasks, notes, queue routing, the host/user
# analysis above) plus two generic outbound-HTTP actions (webhook, Slack) for the one
# genuinely new "integration" surface. Runs synchronously inside the request that fired
# the trigger (case create/update) -- this appliance has no task queue anywhere else
# either, and action volume here is low (a handful of playbooks, a few actions each).
def migrate_playbooks():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS playbooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            trigger_event TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            condition_queue_id INTEGER,
            condition_tlp TEXT,
            condition_status TEXT,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS playbook_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id INTEGER NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            action_type TEXT NOT NULL,
            params TEXT
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_playbook_actions_playbook ON playbook_actions(playbook_id)')
        conn.execute('''CREATE TABLE IF NOT EXISTS playbook_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id INTEGER NOT NULL,
            case_id INTEGER NOT NULL,
            triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'success',
            detail TEXT
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_playbook_runs_case ON playbook_runs(case_id)')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_playbook_secrets():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS playbook_secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            value TEXT NOT NULL,
            description TEXT,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

# Approval gate for individual playbook actions -- an action flagged requires_approval
# on the playbook editor is queued here instead of executing immediately, whether the
# playbook fired from a real trigger (_run_playbooks_for_case) or a manual "Run Now"
# (api_playbook_run). Deliberately generic (any action type can be gated, not just a
# hypothetical future EDR one) since even send_webhook/send_slack are real external
# side effects worth pausing on. See the SOAR research: this is the prerequisite for
# ever safely wiring a playbook to something like isolate_host later -- not built here.
def migrate_playbook_approvals():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(playbook_actions)").fetchall()}
        if 'requires_approval' not in cols:
            conn.execute("ALTER TABLE playbook_actions ADD COLUMN requires_approval INTEGER NOT NULL DEFAULT 0")
        pb_cols = {row[1] for row in conn.execute("PRAGMA table_info(playbooks)").fetchall()}
        if 'condition_severity' not in pb_cols:
            conn.execute("ALTER TABLE playbooks ADD COLUMN condition_severity TEXT")
        if 'max_runs_per_hour' not in pb_cols:
            conn.execute("ALTER TABLE playbooks ADD COLUMN max_runs_per_hour INTEGER")
        if 'schedule_interval_minutes' not in pb_cols:
            conn.execute("ALTER TABLE playbooks ADD COLUMN schedule_interval_minutes INTEGER")
        if 'last_scheduled_run' not in pb_cols:
            conn.execute("ALTER TABLE playbooks ADD COLUMN last_scheduled_run DATETIME")
        conn.execute('''CREATE TABLE IF NOT EXISTS playbook_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id INTEGER NOT NULL,
            case_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            params TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            decided_by TEXT,
            decided_at DATETIME
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_playbook_approvals_status ON playbook_approvals(status)')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_live_logs_archive():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS live_logs_archive (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            host TEXT, app TEXT, severity TEXT, event_id TEXT, username TEXT,
            source_ip TEXT, destination_ip TEXT, message TEXT NOT NULL,
            process_image TEXT, command_line TEXT, parent_image TEXT,
            parent_command_line TEXT, original_file_name TEXT, raw_xml TEXT,
            file_hash TEXT, query_name TEXT
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_live_logs_archive_timestamp ON live_logs_archive(timestamp)')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ueba_priority_scores():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS ueba_priority_scores (
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            priority_score REAL,
            distinct_indicators INTEGER,
            peak_points INTEGER,
            decay_score REAL,
            computed_at DATETIME,
            PRIMARY KEY (entity_type, entity_id)
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ueba_autocase():
    # Tracks the last time each entity crossed the UEBA auto-case risk threshold, so a
    # persistently-high-risk entity doesn't spawn a new case every scoring cycle -- the
    # cooldown window (ueba_autocase_cooldown_hours) is checked against last_triggered_at
    # before creating another one.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS ueba_autocase_log (
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            last_triggered_at DATETIME,
            case_id INTEGER,
            PRIMARY KEY (entity_type, entity_id)
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_fim_paths():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS fim_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            description TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_saved_searches():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS saved_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            query_params TEXT NOT NULL,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_warninglists():
    try:
        from warninglists import SEED_WARNINGLISTS
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS warninglists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            type TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS warninglist_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            warninglist_id INTEGER NOT NULL,
            value TEXT NOT NULL
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_warninglist_entries_wid ON warninglist_entries(warninglist_id)")
        cols = {row[1] for row in conn.execute("PRAGMA table_info(warninglists)").fetchall()}
        if 'source_list' not in cols:
            # The misp-warninglists directory name a list was imported from (see
            # api_ti_warninglist_import), NULL for the 3 hand-curated seed lists and any
            # manually-added custom ones -- lets the catalog picker mark "already
            # imported" without re-fetching GitHub on every page load.
            conn.execute("ALTER TABLE warninglists ADD COLUMN source_list TEXT")
        # Seed once, on an empty table only -- an admin who's since disabled one of the
        # curated lists shouldn't have it silently re-enabled by a later restart/update.
        if conn.execute("SELECT COUNT(*) FROM warninglists").fetchone()[0] == 0:
            for wl in SEED_WARNINGLISTS:
                cur = conn.execute(
                    "INSERT INTO warninglists (name, description, type, enabled) VALUES (?, ?, ?, 1)",
                    (wl['name'], wl['description'], wl['type'])
                )
                wid = cur.lastrowid
                conn.executemany(
                    "INSERT INTO warninglist_entries (warninglist_id, value) VALUES (?, ?)",
                    [(wid, v) for v in wl['entries']]
                )
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ioc_sightings():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS ioc_sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stix_id TEXT NOT NULL,
            seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT,
            log_ref TEXT
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_sightings_stix_id ON ioc_sightings(stix_id)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ioc_sightings_alert_id():
    # log_ref was always a free-text "alert_id=N, host=..." string (sigma_engine.py's
    # _record_ioc_sightings) -- fine for a human reading it, useless for a query. This
    # adds a real column so the actor-summary widget can join sightings back to their
    # alert's severity/message/host directly instead of regex-parsing log_ref at read
    # time. Backfilled from existing rows' log_ref so historical sightings recorded
    # before this column existed don't lose their alert linkage.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(ioc_sightings)").fetchall()}
        if 'alert_id' not in cols:
            conn.execute("ALTER TABLE ioc_sightings ADD COLUMN alert_id INTEGER")
            for rid, log_ref in conn.execute(
                "SELECT id, log_ref FROM ioc_sightings WHERE log_ref LIKE 'alert_id=%'"
            ).fetchall():
                m = re.match(r'alert_id=(\d+)', log_ref or '')
                if m:
                    conn.execute("UPDATE ioc_sightings SET alert_id = ? WHERE id = ?", (int(m.group(1)), rid))
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_coverage_snapshots():
    # One row per day, written by the cron-invoked src/coverage_snapshot.py (see
    # update.sh) -- coverage itself is always computed live everywhere else; this is
    # the only place a trend over time exists, backing the Coverage tab's history chart.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS coverage_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_date DATE NOT NULL UNIQUE,
            techniques_total INTEGER NOT NULL,
            gap_count INTEGER NOT NULL,
            inactive_count INTEGER NOT NULL,
            active_count INTEGER NOT NULL,
            validated_count INTEGER NOT NULL,
            coverage_pct REAL NOT NULL
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_sigma_rules_original_yaml():
    # No pristine copy of a Sigma-sourced rule was ever kept before this --
    # _run_sigmahq_import() silently overwrote rule_yaml in place on every upstream
    # change. Backfilling original_yaml from each row's CURRENT rule_yaml is the
    # honest best-effort baseline: for a rule already locally modified before this
    # column existed, its current (modified) content becomes its new "default" going
    # forward -- there's no way to recover the true original after the fact.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sigma_rules)").fetchall()}
        if 'original_yaml' not in cols:
            conn.execute("ALTER TABLE sigma_rules ADD COLUMN original_yaml TEXT")
            conn.execute("UPDATE sigma_rules SET original_yaml = rule_yaml WHERE source = 'sigma'")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_sigma_rules_upstream_yaml():
    # Tracks the latest fetched SigmaHQ content for a rule the user has locally
    # modified -- _run_sigmahq_import() no longer overwrites rule_yaml/original_yaml
    # for a modified rule (that would silently clobber the edit), so without this
    # there'd be no way to tell "upstream has changed since you customized this" from
    # "upstream is unchanged". NULL until the next import run touches this rule.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sigma_rules)").fetchall()}
        if 'upstream_yaml' not in cols:
            conn.execute("ALTER TABLE sigma_rules ADD COLUMN upstream_yaml TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

# The __IOC_..._LIST__ correlation mechanism (see sigma_engine.py) is a capability, not
# an active rule -- nothing alerts on it until some rule actually references one of the
# placeholders. Seeded once (matched by title, so a user who deletes/edits it doesn't
# get it silently reinstated on the next update) so IOC correlation is live immediately
# after this feature ships, not just configurable. source='sigma' (not 'custom') makes
# it read-only-until-cloned in the UI, same protection SigmaHQ-imported rules get,
# since editing it in place is easy to break silently (a typo'd field name just stops
# matching, with no error surfaced anywhere).
_IOC_CORRELATION_RULE_TITLE = 'Known-Bad IOC Matched (IP / Hash / DNS Query)'
_IOC_CORRELATION_RULE_YAML = f"""title: {_IOC_CORRELATION_RULE_TITLE}
description: Fires when a log's source/destination IP, file hash, or DNS query name matches a currently-synced Threat Intel IOC (Threat Intel & Hunting > IOCs). The match set is recomputed every detection cycle, not frozen at rule-creation time.
status: stable
level: high
logsource:
  category: custom
  product: custom
detection:
  sel_ip_src:
    SourceIpIOC: __IOC_IP_LIST__
  sel_ip_dst:
    DestinationIpIOC: __IOC_IP_LIST__
  sel_hash:
    FileHashIOC: __IOC_HASH_LIST__
  sel_domain:
    DestinationDomainIOC: __IOC_DOMAIN_LIST__
  condition: sel_ip_src or sel_ip_dst or sel_hash or sel_domain
tags:
  - attack.command-and-control
"""

def migrate_seed_ioc_correlation_rule():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        existing = conn.execute("SELECT 1 FROM sigma_rules WHERE title = ?", (_IOC_CORRELATION_RULE_TITLE,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO sigma_rules (title, rule_yaml, enabled, source, created_by, created_at) "
                "VALUES (?, ?, 1, 'sigma', 'system', CURRENT_TIMESTAMP)",
                (_IOC_CORRELATION_RULE_TITLE, _IOC_CORRELATION_RULE_YAML)
            )
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_enrichment_results():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS enrichment_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            verdict TEXT,
            summary TEXT,
            raw_json TEXT,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(value, source)
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ti_entities():
    try:
        from threat_actors import ACTORS
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS ti_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            name TEXT NOT NULL UNIQUE,
            aliases TEXT,
            description TEXT,
            techniques TEXT,
            source TEXT DEFAULT 'curated',
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS ti_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL DEFAULT 'indicates',
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(entity_id, target_type, target_id)
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ti_relationships_entity ON ti_relationships(entity_id)")
        # INSERT OR IGNORE per-row (not gated on an empty table) rather than the
        # seed-once-only pattern warninglists uses -- ACTORS is a growable reference
        # list (new curated entries can ship in a later update), so every deploy
        # should pick up anything new without re-touching rows an admin already
        # edited/deleted. Matched on the UNIQUE(name) constraint.
        for a in ACTORS:
            conn.execute(
                "INSERT OR IGNORE INTO ti_entities (entity_type, name, aliases, description, techniques, source) "
                "VALUES (?, ?, ?, ?, ?, 'curated')",
                (a['type'], a['name'], ','.join(a.get('aliases') or []), a['description'], ','.join(a.get('techniques') or []))
            )
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ti_entities_confidence():
    # Same "empty means not assessed yet" convention as case TLP/PAP -- confidence
    # defaults to '' (not a specific tier), distinct from an explicit low-confidence
    # assessment. attribution_note is a free-text citation ("per Mandiant M-Trends
    # 2024") since a single curated source list can't cover every analyst's own
    # sourcing.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(ti_entities)").fetchall()}
        if 'confidence' not in cols:
            conn.execute("ALTER TABLE ti_entities ADD COLUMN confidence TEXT NOT NULL DEFAULT ''")
        if 'attribution_note' not in cols:
            conn.execute("ALTER TABLE ti_entities ADD COLUMN attribution_note TEXT NOT NULL DEFAULT ''")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ti_entities_references():
    # One "Label | https://..." reference per line, free text like attribution_note --
    # no structured citation format exists elsewhere in this codebase to match.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(ti_entities)").fetchall()}
        if 'external_references' not in cols:
            conn.execute("ALTER TABLE ti_entities ADD COLUMN external_references TEXT NOT NULL DEFAULT ''")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_live_logs_ip_columns():
    # source_ip/destination_ip were added to schema.sql at some point but no migration
    # ever backfilled them onto already-deployed databases, and no ingest path ever
    # populated them — Log Search's "Source IP"/"Destination IP" field filters have
    # been silently failing (caught by api_search's blanket try/except) on any DB that
    # predates these columns. destination_ip is added for schema completeness but stays
    # unpopulated for now — there's no reliable extraction source for it yet.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(live_logs)").fetchall()}
        if 'source_ip' not in cols:
            conn.execute("ALTER TABLE live_logs ADD COLUMN source_ip TEXT")
        if 'destination_ip' not in cols:
            conn.execute("ALTER TABLE live_logs ADD COLUMN destination_ip TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_live_logs_process_columns():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(live_logs)").fetchall()}
        for col in ('process_image', 'command_line', 'parent_image', 'parent_command_line', 'original_file_name', 'raw_xml'):
            if col not in cols:
                conn.execute(f"ALTER TABLE live_logs ADD COLUMN {col} TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_live_logs_hash_dns_columns():
    # Backing columns for the Tier 2 CTI-gap-analysis correlation extension: file_hash
    # (canonicalized from Sysmon Event ID 1's Hashes field, see _canonical_hash()) and
    # query_name (Sysmon Event ID 22 DNS query) -- extends IOC correlation beyond IP,
    # same __IOC_..._LIST__ placeholder mechanism as sigma_engine.py's existing IP path.
    # Added to live_logs_archive too, since archive_logs.py's ARCHIVE_COLUMNS list
    # copies whatever columns both tables actually share.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        for table in ('live_logs', 'live_logs_archive'):
            cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for col in ('file_hash', 'query_name'):
                if col not in cols:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_agent_versions():
    # agent_polls predates version reporting — add the column for already-deployed
    # databases. agent_version_history is new: one row per (hostname, version) pair,
    # first-seen timestamped, so the Agents page can show not just what version an
    # endpoint is running but when it started running it (i.e. when it was last
    # upgraded), without bloating on every single check-in.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(agent_polls)").fetchall()}
        if 'version' not in cols:
            conn.execute("ALTER TABLE agent_polls ADD COLUMN version TEXT")
        if 'os' not in cols:
            # Agents that predate OS reporting (or haven't checked in since the Linux
            # agent shipped) simply won't send X-Agent-OS — NULL here, treated as
            # 'windows' everywhere this is read, since every agent before this was one.
            conn.execute("ALTER TABLE agent_polls ADD COLUMN os TEXT")
        conn.execute('''CREATE TABLE IF NOT EXISTS agent_version_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            version TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            UNIQUE(hostname, version)
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_agent_tokens():
    # Every agent used to share one global secret (soc_secret) as its only credential,
    # with hostname self-reported and completely unverified — any device holding that
    # secret could claim to *be* any other enrolled host and pick up its queued
    # commands. Agents built from now on instead get a unique per-download token, bound
    # to whichever hostname first authenticates with it (trust-on-first-use) — a second
    # device presenting that same token under a different hostname is rejected instead
    # of silently accepted. The old shared secret still works (see _validate_agent_auth)
    # so already-deployed agents keep functioning until they're re-downloaded/upgraded.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS agent_tokens (
            token TEXT PRIMARY KEY,
            hostname TEXT,
            created_at TEXT NOT NULL,
            bound_at TEXT,
            last_seen TEXT
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_agent_groups():
    # Purely organizational (filtering/bulk-dispatch), not a config-inheritance system --
    # FIM paths/interval and log channels stay genuinely global (see fim_paths, the
    # settings-table fim_interval_seconds, and api_agent_channels), so a group here means
    # "these hosts, together" for response-action fan-out, not "these hosts share a
    # policy". agent_tokens is the closest thing to a one-row-per-enrolled-host identity
    # table today (bound to a hostname on first check-in), so the group lives there.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(agent_tokens)").fetchall()}
        if 'group_name' not in cols:
            conn.execute("ALTER TABLE agent_tokens ADD COLUMN group_name TEXT NOT NULL DEFAULT ''")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_cve_records():
    # A dedicated table, not a new stix_indicators/ti_feeds row shape -- a CVE record
    # (a vulnerability in a piece of software, identified by ID/CVSS/affected product)
    # is a fundamentally different kind of record than an IOC (an indicator seen in
    # traffic/files, identified by pattern/type), even though both are "threat intel" in
    # the loose sense. Forcing it into stix_indicators' pattern-matching shape would be
    # a real schema misfit, not just reuse.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS cve_records (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            published_date TEXT,
            last_modified TEXT,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_records_severity ON cve_records(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_records_published ON cve_records(published_date)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_ueba_entities():
    # UEBA originally modeled hosts only, with a fixed 'HIGH' severity and no way to
    # quiet a legitimately bursty entity. Adds: entity_type on events (host vs user,
    # column reused for either kind of entity id), an exclusions table (mirrors
    # rule_exclusions), and a baseline snapshot table so every modeled entity's current
    # numbers are visible, not just the ones that fired.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
        if 'entity_type' not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN entity_type TEXT")
        conn.execute('''CREATE TABLE IF NOT EXISTS ueba_exclusions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            description TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ueba_exclusions_entity ON ueba_exclusions(entity_type, entity_id)")
        conn.execute('''CREATE TABLE IF NOT EXISTS ueba_entity_baselines (
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            current_count INTEGER,
            baseline_avg REAL,
            baseline_stddev REAL,
            threshold REAL,
            is_anomalous BOOLEAN DEFAULT 0,
            excluded BOOLEAN DEFAULT 0,
            computed_at DATETIME,
            PRIMARY KEY (entity_type, entity_id)
        )''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_compliance_tags():
    # Compliance-framework tagging is manual (Sigma rules carry no such metadata), so this
    # just needs a column to hold an admin-assigned, comma-separated list of framework keys.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sigma_rules)").fetchall()}
        if 'compliance_tags' not in cols:
            conn.execute("ALTER TABLE sigma_rules ADD COLUMN compliance_tags TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_audit_log():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT, role TEXT, ip_address TEXT,
            action TEXT NOT NULL, target_type TEXT, target_id TEXT, details TEXT
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_risk_scoring():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS risk_score_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
            indicator TEXT NOT NULL, points INTEGER NOT NULL,
            detail TEXT, source_table TEXT, source_id TEXT,
            computed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_score_events_entity ON risk_score_events(entity_type, entity_id, computed_at)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_anomaly_rules():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        # Current (post-cleanup) shape -- conditions (field/operator/value) live in
        # their own table now, see migrate_anomaly_rule_conditions() below. This
        # CREATE TABLE only actually does anything if anomaly_rules doesn't exist at
        # all yet; an existing install with the old inline field/operator/value columns
        # is handled by that migration's rebuild, not by this IF NOT EXISTS no-op.
        conn.execute('''CREATE TABLE IF NOT EXISTS anomaly_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, source TEXT NOT NULL,
            entity_field TEXT NOT NULL, entity_type TEXT NOT NULL, points INTEGER NOT NULL,
            first_time_bonus_points INTEGER, enabled BOOLEAN DEFAULT 1,
            created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT, updated_at DATETIME
        )''')
        # audit_log support (and the 14 sensitive-action rows this originally seeded)
        # was pulled back out shortly after shipping -- Sigma alerts only for now. Clean
        # up any rows a prior deploy already seeded; harmless no-op once none remain.
        conn.execute("DELETE FROM anomaly_rules WHERE source = 'audit_log'")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_anomaly_rules_sequence_columns():
    # Optional sequence chain fields -- a rule with sequence_name set is one STAGE of a
    # named, ordered progression (e.g. "New IP" stage 1 -> "New Process" stage 2 ->
    # "New Destination IP" stage 3). Both NULL means an ordinary standalone rule,
    # unaffected. See run_sequence_chain_scoring() in ueba_engine.py.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(anomaly_rules)").fetchall()]
        if 'sequence_name' not in cols:
            conn.execute("ALTER TABLE anomaly_rules ADD COLUMN sequence_name TEXT")
        if 'sequence_stage' not in cols:
            conn.execute("ALTER TABLE anomaly_rules ADD COLUMN sequence_stage INTEGER")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_anomaly_rule_conditions():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(anomaly_rules)").fetchall()]
        conn.execute('''CREATE TABLE IF NOT EXISTS anomaly_rule_conditions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL,
            field TEXT NOT NULL, operator TEXT NOT NULL DEFAULT 'equals', value TEXT NOT NULL,
            logic TEXT NOT NULL DEFAULT 'AND',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_rule_conditions_rule ON anomaly_rule_conditions(rule_id)")
        if 'field' not in cols:
            # Already on the new shape (or a fresh install that started there) --
            # nothing left to backfill or rebuild.
            conn.commit()
            conn.close()
            return
        # Old shape detected: move each rule's single field/operator/value into its own
        # condition row (skip any rule that somehow already has conditions, so this stays
        # safe to re-run), then rebuild anomaly_rules without those columns for real --
        # SQLite's DROP COLUMN support varies by version, so this doesn't rely on it.
        rows = conn.execute("SELECT id, field, operator, value FROM anomaly_rules").fetchall()
        for rid, field, operator, value in rows:
            already = conn.execute("SELECT COUNT(*) FROM anomaly_rule_conditions WHERE rule_id = ?", (rid,)).fetchone()[0]
            if already == 0:
                conn.execute(
                    "INSERT INTO anomaly_rule_conditions (rule_id, field, operator, value) VALUES (?, ?, ?, ?)",
                    (rid, field, operator, value)
                )
        conn.execute('''CREATE TABLE anomaly_rules_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, source TEXT NOT NULL,
            entity_field TEXT NOT NULL, entity_type TEXT NOT NULL, points INTEGER NOT NULL,
            first_time_bonus_points INTEGER, enabled BOOLEAN DEFAULT 1,
            created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT, updated_at DATETIME
        )''')
        # Explicit id column in both the INSERT and SELECT preserves every rule's
        # original id -- risk_score_events.rule_id and the just-backfilled
        # anomaly_rule_conditions.rule_id both reference it, and losing that link would
        # silently break match-history/tuning-stat attribution for every existing rule.
        conn.execute('''INSERT INTO anomaly_rules_new
            (id, name, source, entity_field, entity_type, points, first_time_bonus_points, enabled, created_by, created_at, updated_by, updated_at)
            SELECT id, name, source, entity_field, entity_type, points, first_time_bonus_points, enabled, created_by, created_at, updated_by, updated_at
            FROM anomaly_rules''')
        conn.execute("DROP TABLE anomaly_rules")
        conn.execute("ALTER TABLE anomaly_rules_new RENAME TO anomaly_rules")
        conn.commit()
        conn.close()
    except Exception:
        pass

# Separate from migrate_anomaly_rule_conditions() above: that migration's own CREATE
# TABLE IF NOT EXISTS already includes the logic column for a fresh install, but an
# install that ran the pre-OR-support version of that migration already has the table
# without it -- ADD COLUMN is the only piece needed to bring it current.
def migrate_anomaly_rule_conditions_logic():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(anomaly_rule_conditions)").fetchall()]
        if 'logic' not in cols:
            conn.execute("ALTER TABLE anomaly_rule_conditions ADD COLUMN logic TEXT NOT NULL DEFAULT 'AND'")
        conn.commit()
        conn.close()
    except Exception:
        pass

# Starter pack of custom UEBA anomaly rules -- these ADD to the flat per-severity
# scoring _score_alerts() already gives every host/username on every alert (see
# ueba_engine.py's RISK_SCORE_DEFAULTS: alert_critical/high/medium/low/informational),
# so nothing here just re-scores plain severity -- that would double-count. Each rule
# instead picks out a qualitatively distinct pattern:
#   - the 3 inline-heuristic-engine rule_name values (api_ingest's keyword detector,
#     not the real Sigma pipeline -- Sigma-matched alerts.rule_name is always NULL,
#     since sigma_engine.py's INSERT never sets it) get their own weighted scoring;
#   - "named user" rules require username not_equals 'SYSTEM'. A blank/NULL username
#     round-trips through _condition_matches() as '' (see the coercion there), which
#     would technically satisfy that check too -- but these all use entity_field=
#     'username', and _score_alerts() already skips any event whose entity_field value
#     is falsy (`if not entity_id: continue`), so a blank-username alert never scores
#     regardless of what the conditions evaluate to. (A blank-vs-'SYSTEM' distinction
#     can't be expressed as a condition at all: _validate_anomaly_rule() rejects any
#     condition with an empty value outright -- "condition value is required" -- so
#     there is no not_equals-blank check to write here even if a host-entity variant
#     wanted one; entity_field=host rules below avoid needing that distinction instead.)
#   - "internal lateral movement" rules use starts_with on the two easy-to-prefix RFC
#     1918 ranges (192.168.0.0/16, 10.0.0.0/8 -- 172.16.0.0/12 is skipped, it isn't a
#     single string prefix) as a stand-in for "this IP field is actually populated with
#     a private/internal address", since there's no presence-check operator available.
#     The two starts_with conditions are OR'd together *first*, then AND'd with the
#     rest -- conditions evaluate strictly left-to-right with no precedence (see
#     _rule_matches_all() in ueba_engine.py), so "(A OR B) AND C" only comes out right
#     if A/B are listed before C, not after.
# `severity` is matched with `contains` + a lowercase value rather than `equals`,
# because _condition_matches() only lowercases for contains/starts_with/ends_with --
# Sigma-sourced alerts store Title-case severity ('Critical') while the inline heuristic
# engine stores upper-case ('CRITICAL'); `equals` would only ever match one of the two.
_INTERNAL_IP_OR = [
    {'operator': 'starts_with', 'value': '192.168.'},
    {'operator': 'starts_with', 'value': '10.', 'logic': 'OR'},
]

def _internal_ip_conditions(field, *rest):
    return [{'field': field, **c} for c in _INTERNAL_IP_OR] + list(rest)

_SEED_UEBA_RULES = [
    {
        'name': 'Credential Dumping Activity Detected', 'entity_field': 'host', 'entity_type': 'host',
        'points': 50, 'first_time_bonus_points': 75,
        'conditions': [{'field': 'rule_name', 'operator': 'contains', 'value': 'Credential Dumping'}],
    },
    {
        'name': 'Suspicious PowerShell Execution Detected', 'entity_field': 'host', 'entity_type': 'host',
        'points': 30, 'first_time_bonus_points': 40,
        'conditions': [{'field': 'rule_name', 'operator': 'contains', 'value': 'Suspicious PowerShell'}],
    },
    {
        'name': 'System Discovery Commands Detected', 'entity_field': 'host', 'entity_type': 'host',
        'points': 8, 'first_time_bonus_points': 10,
        'conditions': [{'field': 'rule_name', 'operator': 'contains', 'value': 'Discovery Commands'}],
    },
    {
        'name': 'Critical Alert Attributed to Named User', 'entity_field': 'username', 'entity_type': 'user',
        'points': 25, 'first_time_bonus_points': 40,
        'conditions': [
            {'field': 'severity', 'operator': 'contains', 'value': 'critical'},
            {'field': 'username', 'operator': 'not_equals', 'value': 'SYSTEM', 'logic': 'AND'},
        ],
    },
    {
        'name': 'High-Severity Alert Attributed to Named User', 'entity_field': 'username', 'entity_type': 'user',
        'points': 15, 'first_time_bonus_points': 20,
        'conditions': [
            {'field': 'severity', 'operator': 'contains', 'value': 'high'},
            {'field': 'username', 'operator': 'not_equals', 'value': 'SYSTEM', 'logic': 'AND'},
        ],
    },
    {
        'name': 'Medium-Severity Alert Attributed to Named User', 'entity_field': 'username', 'entity_type': 'user',
        'points': 8, 'first_time_bonus_points': 10,
        'conditions': [
            {'field': 'severity', 'operator': 'contains', 'value': 'medium'},
            {'field': 'username', 'operator': 'not_equals', 'value': 'SYSTEM', 'logic': 'AND'},
        ],
    },
    {
        'name': 'Critical Alert with Internal Lateral Movement (Host)', 'entity_field': 'host', 'entity_type': 'host',
        'points': 25, 'first_time_bonus_points': 35,
        'conditions': _internal_ip_conditions('destination_ip', {'field': 'severity', 'operator': 'contains', 'value': 'critical', 'logic': 'AND'}),
    },
    {
        'name': 'Critical Alert with Internal Lateral Movement (User)', 'entity_field': 'username', 'entity_type': 'user',
        'points': 20, 'first_time_bonus_points': 30,
        'conditions': _internal_ip_conditions('destination_ip', {'field': 'severity', 'operator': 'contains', 'value': 'critical', 'logic': 'AND'}),
    },
    {
        'name': 'High-Severity Alert with Internal Lateral Movement (Host)', 'entity_field': 'host', 'entity_type': 'host',
        'points': 15, 'first_time_bonus_points': 20,
        'conditions': _internal_ip_conditions('destination_ip', {'field': 'severity', 'operator': 'contains', 'value': 'high', 'logic': 'AND'}),
    },
    {
        'name': 'High-Severity Alert with Internal Lateral Movement (User)', 'entity_field': 'username', 'entity_type': 'user',
        'points': 10, 'first_time_bonus_points': 15,
        'conditions': _internal_ip_conditions('destination_ip', {'field': 'severity', 'operator': 'contains', 'value': 'high', 'logic': 'AND'}),
    },
    {
        'name': 'Critical Alert Sourced from Internal Network (Host)', 'entity_field': 'host', 'entity_type': 'host',
        'points': 20, 'first_time_bonus_points': 30,
        'conditions': _internal_ip_conditions('source_ip', {'field': 'severity', 'operator': 'contains', 'value': 'critical', 'logic': 'AND'}),
    },
    {
        'name': 'Critical Alert Sourced from Internal Network (User)', 'entity_field': 'username', 'entity_type': 'user',
        'points': 15, 'first_time_bonus_points': 25,
        'conditions': _internal_ip_conditions('source_ip', {'field': 'severity', 'operator': 'contains', 'value': 'critical', 'logic': 'AND'}),
    },
    {
        'name': 'High-Severity Alert Sourced from Internal Network (Host)', 'entity_field': 'host', 'entity_type': 'host',
        'points': 12, 'first_time_bonus_points': 15,
        'conditions': _internal_ip_conditions('source_ip', {'field': 'severity', 'operator': 'contains', 'value': 'high', 'logic': 'AND'}),
    },
    {
        'name': 'Named-User Alert with Internal Lateral Movement', 'entity_field': 'username', 'entity_type': 'user',
        'points': 18, 'first_time_bonus_points': 25,
        'conditions': _internal_ip_conditions('destination_ip', {'field': 'username', 'operator': 'not_equals', 'value': 'SYSTEM', 'logic': 'AND'}),
    },
    {
        'name': 'Named-User Alert Sourced from Internal Network', 'entity_field': 'username', 'entity_type': 'user',
        'points': 18, 'first_time_bonus_points': 25,
        'conditions': _internal_ip_conditions('source_ip', {'field': 'username', 'operator': 'not_equals', 'value': 'SYSTEM', 'logic': 'AND'}),
    },
]

def migrate_seed_ueba_rules():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.row_factory = sqlite3.Row
        existing = {row['name'] for row in conn.execute("SELECT name FROM anomaly_rules").fetchall()}
        for rule in _SEED_UEBA_RULES:
            if rule['name'] in existing:
                continue
            cur = conn.execute(
                "INSERT INTO anomaly_rules (name, source, entity_field, entity_type, points, first_time_bonus_points, enabled, created_by) "
                "VALUES (?, 'alerts', ?, ?, ?, ?, 1, 'system')",
                (rule['name'], rule['entity_field'], rule['entity_type'], rule['points'], rule['first_time_bonus_points'])
            )
            rule_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO anomaly_rule_conditions (rule_id, field, operator, value, logic) VALUES (?, ?, ?, ?, ?)",
                [(rule_id, c['field'], c['operator'], c['value'], c.get('logic', 'AND')) for c in rule['conditions']]
            )
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_risk_score_events_rule_id():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        try:
            conn.execute("ALTER TABLE risk_score_events ADD COLUMN rule_id INTEGER")
        except Exception:
            pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_score_events_rule ON risk_score_events(rule_id)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_report_history():
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.execute('''CREATE TABLE IF NOT EXISTS report_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, report_type TEXT NOT NULL, filename TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'success', triggered_by TEXT, trigger_source TEXT NOT NULL DEFAULT 'manual',
            started_at DATETIME, completed_at DATETIME, file_size_bytes INTEGER, error_message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_report_history_type_time ON report_history(report_type, created_at)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_report_history_case_id():
    # case_title is a snapshot at generation time, not a live join -- a report generated
    # for a case that's later deleted should still show what it was a report OF.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(report_history)").fetchall()}
        if 'case_id' not in cols:
            conn.execute("ALTER TABLE report_history ADD COLUMN case_id INTEGER")
        if 'case_title' not in cols:
            conn.execute("ALTER TABLE report_history ADD COLUMN case_title TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_report_history_case ON report_history(case_id)")
        conn.commit()
        conn.close()
    except Exception:
        pass

def migrate_log_search_indexes():
    # _build_log_filters() (Log Search / UEBA Timeline) filters on host/app/severity/
    # username/event_id constantly, but only `timestamp` was ever indexed on live_logs/
    # live_logs_archive/alerts/events -- every non-time filter was a full table scan.
    # CREATE INDEX IF NOT EXISTS is idempotent, so unlike most migrate_*() functions here
    # this doesn't need a PRAGMA table_info column-existence check first.
    try:
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        for stmt in (
            "CREATE INDEX IF NOT EXISTS idx_live_logs_host ON live_logs(host)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_app ON live_logs(app)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_severity ON live_logs(severity)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_username ON live_logs(username)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_event_id ON live_logs(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_archive_host ON live_logs_archive(host)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_archive_app ON live_logs_archive(app)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_archive_severity ON live_logs_archive(severity)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_archive_username ON live_logs_archive(username)",
            "CREATE INDEX IF NOT EXISTS idx_live_logs_archive_event_id ON live_logs_archive(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
            "CREATE INDEX IF NOT EXISTS idx_events_app_name ON events(app_name)",
        ):
            conn.execute(stmt)
        conn.commit()
        conn.close()
    except Exception:
        pass

def _run_sigmahq_import():
    import urllib.request, zipfile, tempfile, shutil, socket, sqlite3
    import yaml as _yaml
    t = tempfile.mkdtemp()
    stats = {'inserted': 0, 'updated': 0, 'skipped': 0, 'errors': 0, 'upstream_drift': 0}
    try:
        zp = os.path.join(t, "sigma.zip")
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(60)
        try:
            urllib.request.urlretrieve("https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip", zp)
        finally:
            socket.setdefaulttimeout(old_timeout)
        with zipfile.ZipFile(zp, 'r') as z:
            z.extractall(t)
        conn = sqlite3.connect('/opt/micro-dfir/siem.db', timeout=30)
        conn.row_factory = sqlite3.Row
        rules_dir = os.path.join(t, "sigma-master", "rules")
        for root, _, files in os.walk(rules_dir):
            for f in files:
                if not f.endswith(('.yml', '.yaml')):
                    continue
                try:
                    with open(os.path.join(root, f), 'r', encoding='utf-8') as fh:
                        ry = fh.read()
                    parsed = _yaml.safe_load(ry)
                    if not parsed or 'title' not in parsed:
                        stats['skipped'] += 1
                        continue
                    title = parsed['title']
                    uuid_ = parsed.get('id')
                    existing = conn.execute(
                        "SELECT id, rule_yaml, original_yaml FROM sigma_rules WHERE sigma_uuid = ?", (uuid_,)
                    ).fetchone() if uuid_ else None
                    if existing:
                        # Sigma rules are directly editable now (Revert to Default is the
                        # safety net) -- a rule whose live content has diverged from its
                        # recorded default has real local edits an import must never
                        # silently clobber. Only rules still matching their own baseline
                        # get updated (and their baseline moves forward with them), same
                        # as this route's original "update if upstream differs" behavior.
                        if existing['rule_yaml'] == existing['original_yaml'] and existing['rule_yaml'] != ry:
                            conn.execute(
                                "UPDATE sigma_rules SET title = ?, rule_yaml = ?, original_yaml = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                                (title, ry, ry, existing['id'])
                            )
                            stats['updated'] += 1
                        elif existing['rule_yaml'] != existing['original_yaml']:
                            # Locally modified -- rule_yaml/original_yaml are left untouched
                            # above, but the latest fetched content is tracked separately so
                            # the "upstream has drifted from your edit's baseline" indicator
                            # can compare it against original_yaml without a live fetch.
                            conn.execute("UPDATE sigma_rules SET upstream_yaml = ? WHERE id = ?", (ry, existing['id']))
                            if ry != existing['original_yaml']:
                                stats['upstream_drift'] += 1
                    else:
                        conn.execute(
                            "INSERT INTO sigma_rules (title, rule_yaml, original_yaml, enabled, source, sigma_uuid, created_at) VALUES (?, ?, ?, 0, 'sigma', ?, CURRENT_TIMESTAMP)",
                            (title, ry, ry, uuid_)
                        )
                        stats['inserted'] += 1
                except Exception:
                    stats['errors'] += 1
        conn.commit()
        conn.close()
    finally:
        shutil.rmtree(t, ignore_errors=True)
    return stats

@app.route('/api/audit-log', methods=['GET'])
@login_required
def api_audit_log():
    err = require_permission('audit.view')
    if err: return err
    db = get_db()
    where, params = [], []
    action = request.args.get('action')
    if action:
        where.append('action = ?'); params.append(action)
    username = request.args.get('username')
    if username:
        where.append('username = ?'); params.append(username)
    date_from = request.args.get('date_from')
    if date_from:
        where.append('timestamp >= ?'); params.append(date_from)
    date_to = request.args.get('date_to')
    if date_to:
        where.append('timestamp <= ?'); params.append(date_to)
    where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''

    try:
        limit = min(int(request.args.get('limit', 100)), 500)
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(int(request.args.get('offset', 0)), 0)
    except (TypeError, ValueError):
        offset = 0

    total = db.execute(f"SELECT COUNT(*) AS c FROM audit_log {where_sql}", params).fetchone()['c']
    rows = db.execute(
        f"SELECT id, timestamp, username, role, ip_address, action, target_type, target_id, details "
        f"FROM audit_log {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    actions = [r['action'] for r in db.execute("SELECT DISTINCT action FROM audit_log ORDER BY action").fetchall()]
    return jsonify({'rows': [dict(r) for r in rows], 'total': total, 'actions': actions})

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    import sqlite3
    from flask import render_template

    # The old POST branch here (a bare <form> field, no role check) let ANY logged-in
    # user rotate the SOC ingestion secret -- a real gap, since /api/settings/token
    # added the properly admin-gated version of the same write and no form in the UI
    # has posted to this route since. Removed rather than gated: it was unreachable
    # dead code, not a real feature to preserve.
    conn = sqlite3.connect("/opt/micro-dfir/siem.db", timeout=30)
    cursor = conn.cursor()

    # Fetch all settings to populate the Network Configuration card
    cursor.execute("SELECT key, value FROM settings")
    all_settings = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()

    return render_template("settings.html", all_settings=all_settings, current_user=current_user)

@app.route('/api/settings/token', methods=['POST'])
@login_required
def api_settings_token():
    from flask import request, jsonify
    err = require_permission('settings.system.manage')
    if err: return err
    token = (request.json or {}).get('token', '').strip()
    if not token:
        return jsonify({'error': 'Token cannot be empty'}), 400
    db = get_db()
    db.execute("UPDATE settings SET value = ? WHERE key = 'soc_secret'", (token,))
    db.commit()
    log_audit('soc_token_change', 'settings')  # never log the token value itself
    return jsonify({'status': 'success'})

@app.route('/api/settings/backup', methods=['GET'])
@login_required
def api_settings_backup():
    from flask import send_file
    import datetime
    err = require_permission('settings.system.manage')
    if err: return err
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(DB_PATH, mimetype='application/octet-stream', as_attachment=True, download_name=f'microdfir_backup_{stamp}.db')

@app.route('/api/settings/purge', methods=['POST'])
@login_required
def api_settings_purge():
    from flask import request, jsonify
    import datetime
    err = require_permission('settings.system.manage')
    if err: return err

    days = (request.json or {}).get('days', 30)
    try:
        days = int(days)
        if days < 1:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'days must be a positive integer'}), 400

    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    cur = db.execute("DELETE FROM live_logs WHERE timestamp < ?", (cutoff,))
    deleted = cur.rowcount
    db.commit()
    log_audit('manual_log_purge', 'settings', None, f'deleted={deleted}, cutoff={cutoff}')
    return jsonify({'status': 'success', 'deleted': deleted, 'cutoff': cutoff})

@app.route('/api/settings/retention', methods=['GET', 'POST'])
@login_required
def api_settings_retention():
    from flask import request, jsonify
    db = get_db()

    if request.method == 'GET':
        days_row = db.execute("SELECT value FROM settings WHERE key = 'log_retention_days'").fetchone()
        last_row = db.execute("SELECT value FROM settings WHERE key = 'log_retention_last_purge'").fetchone()
        days = int(days_row['value']) if days_row and days_row['value'] else None
        return jsonify({'days': days, 'last_purge': last_row['value'] if last_row and last_row['value'] else None})

    err = require_permission('settings.system.manage')
    if err: return err
    d = request.json or {}
    days = d.get('days')
    if days in (None, '', 0, '0'):
        # Explicitly disabling automatic purge — sigma_engine.py's scheduled check
        # (see run_due_log_purge()) skips entirely when this key is blank, same as a
        # threat-intel feed left on "Manual only" is never touched by sync_due_feeds().
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_days', '')")
        db.commit()
        log_audit('retention_policy_change', 'settings', None, 'disabled')
        return jsonify({'status': 'success', 'days': None})
    try:
        days = int(days)
        if days < 1:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'days must be a positive integer, or omitted/0 to disable automatic purge'}), 400
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_days', ?)", (str(days),))
    db.commit()
    log_audit('retention_policy_change', 'settings', None, f'{days} days')
    return jsonify({'status': 'success', 'days': days})

# Mirrors archive_logs.py's own DEFAULT_ARCHIVE_DAYS -- duplicated rather than imported
# since this route only needs the number for display, not the archiving logic itself.
DEFAULT_LOG_ARCHIVE_DAYS = 90

# Mirrors sigma_engine.py's own DEFAULT_IOC_RETENTION_DAYS -- see run_due_ioc_purge()
# there for why this is enabled by default (unlike log retention/purge above): an IOC
# that ages out just re-syncs if its feed still carries it, and the "this was actually
# observed here" evidence lives in ioc_sightings, untouched by this purge.
DEFAULT_IOC_RETENTION_DAYS = 30

@app.route('/api/settings/archive', methods=['GET', 'POST'])
@login_required
def api_settings_archive():
    from flask import request, jsonify
    db = get_db()

    if request.method == 'GET':
        days_row = db.execute("SELECT value FROM settings WHERE key = 'log_archive_days'").fetchone()
        last_row = db.execute("SELECT value FROM settings WHERE key = 'log_archive_last_run'").fetchone()
        days = int(days_row['value']) if days_row and days_row['value'] else DEFAULT_LOG_ARCHIVE_DAYS
        return jsonify({'days': days, 'last_run': last_row['value'] if last_row and last_row['value'] else None})

    err = require_permission('settings.system.manage')
    if err: return err
    d = request.json or {}
    days = d.get('days')
    if days in (None, '', 0, '0'):
        # Disabling archiving entirely -- everything stays in the hot live_logs table
        # forever (subject to the separate retention purge, if that's enabled).
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('log_archive_days', '0')")
        db.commit()
        log_audit('archive_policy_change', 'settings', None, 'disabled')
        return jsonify({'status': 'success', 'days': 0})
    try:
        days = int(days)
        if days < 1:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'days must be a positive integer, or 0 to disable archiving'}), 400
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('log_archive_days', ?)", (str(days),))
    db.commit()
    log_audit('archive_policy_change', 'settings', None, f'{days} days')
    return jsonify({'status': 'success', 'days': days})

@app.route('/api/settings/archive/run', methods=['POST'])
@login_required
def api_settings_archive_run():
    err = require_permission('settings.system.manage')
    if err: return err
    from archive_logs import archive_old_logs
    days_override = (request.json or {}).get('days') if request.is_json else None
    if days_override is not None:
        try:
            days_override = int(days_override)
        except (TypeError, ValueError):
            return jsonify({'error': 'days must be a positive integer'}), 400
    result = archive_old_logs(days_override)
    log_audit('manual_log_archive', 'settings', None, f"archived={result['archived']}, cutoff={result['cutoff']}")
    return jsonify({'status': 'success', **result})

@app.route('/api/settings/ioc-retention', methods=['GET', 'POST'])
@login_required
def api_settings_ioc_retention():
    from flask import request, jsonify
    db = get_db()

    if request.method == 'GET':
        days_row = db.execute("SELECT value FROM settings WHERE key = 'ioc_retention_days'").fetchone()
        last_row = db.execute("SELECT value FROM settings WHERE key = 'ioc_retention_last_purge'").fetchone()
        days = int(days_row['value']) if days_row and days_row['value'] else DEFAULT_IOC_RETENTION_DAYS
        return jsonify({'days': days, 'last_purge': last_row['value'] if last_row and last_row['value'] else None})

    err = require_permission('settings.system.manage')
    if err: return err
    d = request.json or {}
    days = d.get('days')
    if days in (None, '', 0, '0'):
        # '0' is a real stored sentinel (not just an unset row) so run_due_ioc_purge()
        # can tell "admin explicitly disabled this" from "never configured" -- the
        # latter still defaults to DEFAULT_IOC_RETENTION_DAYS above/there.
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ioc_retention_days', '0')")
        db.commit()
        log_audit('ioc_retention_policy_change', 'settings', None, 'disabled')
        return jsonify({'status': 'success', 'days': 0})
    try:
        days = int(days)
        if days < 1:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'days must be a positive integer, or 0 to disable automatic purge'}), 400
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ioc_retention_days', ?)", (str(days),))
    db.commit()
    log_audit('ioc_retention_policy_change', 'settings', None, f'{days} days')
    return jsonify({'status': 'success', 'days': days})

@app.route('/api/settings/ioc-retention/run', methods=['POST'])
@login_required
def api_settings_ioc_retention_run():
    from flask import request, jsonify
    import datetime
    err = require_permission('settings.system.manage')
    if err: return err
    db = get_db()
    days = (request.json or {}).get('days') if request.is_json else None
    if days is None:
        days_row = db.execute("SELECT value FROM settings WHERE key = 'ioc_retention_days'").fetchone()
        days = int(days_row['value']) if days_row and days_row['value'] else DEFAULT_IOC_RETENTION_DAYS
    try:
        days = int(days)
        if days < 1:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'days must be a positive integer'}), 400

    now = datetime.datetime.now()
    cutoff = (now - datetime.timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    cur = db.execute("DELETE FROM stix_indicators WHERE inserted_at < ?", (cutoff,))
    deleted = cur.rowcount
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ioc_retention_last_purge', ?)", (now.strftime('%Y-%m-%d %H:%M:%S'),))
    db.commit()
    log_audit('manual_ioc_purge', 'settings', None, f'deleted={deleted}, cutoff={cutoff}')
    return jsonify({'status': 'success', 'deleted': deleted, 'cutoff': cutoff})

@app.route('/api/settings/vacuum', methods=['POST'])
@login_required
def api_settings_vacuum():
    err = require_permission('settings.system.manage')
    if err: return err
    import sqlite3
    try:
        before = os.path.getsize(DB_PATH)
        conn = sqlite3.connect(DB_PATH, timeout=120)
        conn.execute('VACUUM')
        conn.close()
        after = os.path.getsize(DB_PATH)
        before_mb, after_mb = round(before / (1024 * 1024), 1), round(after / (1024 * 1024), 1)
        log_audit('db_vacuum', 'settings', None, f'{before_mb}MB -> {after_mb}MB')
        return jsonify({
            'status': 'success',
            'before_mb': before_mb,
            'after_mb': after_mb,
        })
    except Exception as e:
        return jsonify({'error': f'Vacuum failed: {e}'}), 500

@app.route("/settings/network", methods=["POST"])
@login_required
def settings_network():
    import sqlite3, subprocess
    from flask import request, flash, redirect, url_for

    if "settings.network.manage" not in _current_user_permissions(): return redirect(url_for("home"))
    if not validate_csrf(): return redirect(url_for("settings"))

    ui_ip = request.form.get("ui_bind_ip", "0.0.0.0")
    ui_port = request.form.get("ui_port", "5001")
    ingest_ip = request.form.get("ingest_bind_ip", "0.0.0.0")
    ingest_port = request.form.get("ingest_port", "5000")
    # Checkboxes send no field at all when unchecked, so absence means "off" -- stored
    # as the same '1'/(absent -> default 'off') string-flag convention already used
    # elsewhere in settings rather than introducing a real boolean column.
    syslog_tcp_enabled = "1" if request.form.get("syslog_tcp_enabled") else "0"

    conn = sqlite3.connect("/opt/micro-dfir/siem.db", timeout=30)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ui_bind_ip', ?)", (ui_ip,))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ui_port', ?)", (ui_port,))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ingest_bind_ip', ?)", (ingest_ip,))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ingest_port', ?)", (ingest_port,))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('syslog_tcp_enabled', ?)", (syslog_tcp_enabled,))
    conn.commit()
    conn.close()
    log_audit('network_config_change', 'settings', None, f'ui={ui_ip}:{ui_port}, ingest={ingest_ip}:{ingest_port}, syslog_tcp={syslog_tcp_enabled}')

    # 1. Background task to rewrite the Gunicorn systemd file and restart the UI
    import re as sys_re
    service_file = "/etc/systemd/system/microsoc-web.service"
    try:
        with open(service_file, "r") as sf: svc_content = sf.read()
        # Find the bind string and replace it with a dual bind for both UI and Ingest networks
        svc_content = sys_re.sub(r"--bind\s+[^\s]+(?:\s+--bind\s+[^\s]+)*", f"--bind {ui_ip}:{ui_port} --bind {ingest_ip}:{ingest_port}", svc_content)
        with open(service_file, "w") as sf: sf.write(svc_content)
        subprocess.Popen("systemctl daemon-reload && (sleep 3 && systemctl restart microsoc-web.service) &", shell=True)
    except Exception as e:
        print("Could not update service file:", e)
        
    generate_vector_config()
    
    flash(f"Network settings applied! The UI is moving to {ui_ip}:{ui_port}. Please reconnect in a moment.", "success")
    return redirect(url_for("settings"))


def get_soc_secret(db):
    row = db.execute("SELECT value FROM settings WHERE key = 'soc_secret'").fetchone()
    return row['value'] if row and row['value'] else None

def _validate_agent_auth(db, token, hostname):
    # Two tiers of credential. The legacy global soc_secret is shared across every
    # agent and carries no hostname binding — kept working only so already-deployed
    # agents don't drop off until they're re-downloaded/upgraded onto a per-agent
    # token. A per-agent token (see migrate_agent_tokens) is unknown to the server
    # until issued via a real download/upgrade, and gets bound to whichever hostname
    # first authenticates with it (trust-on-first-use); a second device presenting
    # that same token under a *different* hostname is a spoofing attempt and is
    # rejected, not silently accepted the way the shared secret always was.
    import datetime
    expected_secret = get_soc_secret(db)
    if not expected_secret:
        return True  # no secret configured yet (fresh/unconfigured install) — unchanged from before this existed
    if token and secrets.compare_digest(token, expected_secret):
        return True
    if not token:
        return False
    row = db.execute("SELECT hostname FROM agent_tokens WHERE token = ?", (token,)).fetchone()
    if not row:
        return False
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if row['hostname'] is None:
        db.execute("UPDATE agent_tokens SET hostname = ?, bound_at = ?, last_seen = ? WHERE token = ?", (hostname, now, now, token))
        db.commit()
        return True
    if row['hostname'] != hostname:
        return False
    db.execute("UPDATE agent_tokens SET last_seen = ? WHERE token = ?", (now, token))
    db.commit()
    return True

@app.route('/api/agent/config', methods=['GET'])
def agent_config():
    from flask import request, jsonify
    import datetime
    db = get_db()

    ip = request.remote_addr
    agent_host = request.headers.get('X-Agent-Hostname')
    ua = agent_host if agent_host else request.headers.get('User-Agent', 'Unknown')

    if not _validate_agent_auth(db, request.headers.get('X-Agent-Token'), ua):
        return jsonify({'error': 'Unauthorized'}), 401

    # Agents that predate version reporting simply won't send this header — surfaced
    # as "unknown" in the UI rather than guessed at, since that's itself a useful
    # signal that the endpoint hasn't been upgraded since version tracking shipped.
    agent_version = request.headers.get('X-Agent-Version', 'unknown')
    # Agents that predate OS reporting send no header at all — defaulting to 'windows'
    # matches every agent that existed before this, rather than surfacing a confusing
    # third "unknown" OS state in the UI for endpoints that just haven't upgraded yet.
    agent_os = request.headers.get('X-Agent-OS', 'windows')
    if agent_os not in ('windows', 'linux'):
        agent_os = 'windows'
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db.execute('CREATE TABLE IF NOT EXISTS agent_polls (id INTEGER PRIMARY KEY, timestamp TEXT, ip_address TEXT, user_agent TEXT, version TEXT, os TEXT)')
    db.execute('INSERT INTO agent_polls (timestamp, ip_address, user_agent, version, os) VALUES (?, ?, ?, ?, ?)', (now, ip, ua, agent_version, agent_os))
    db.execute(
        "INSERT OR IGNORE INTO agent_version_history (hostname, version, first_seen) VALUES (?, ?, ?)",
        (ua, agent_version, now)
    )

    # A command marked 'sent' means the response left the server, but if the connection
    # dropped before the agent actually processed it (or the agent crashed mid-run), it
    # would otherwise sit "Sent" forever with no result and no way to retry. Requeue
    # anything that's been sent for more than 5 minutes without a reported result.
    stale_cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
    db.execute(
        "UPDATE agent_commands SET status = 'pending' WHERE hostname = ? AND status = 'sent' AND queued_at < ?",
        (ua, stale_cutoff)
    )
    db.commit()

    cmd_row = db.execute(
        "SELECT id, label, script FROM agent_commands WHERE hostname = ? AND status = 'pending' ORDER BY id LIMIT 1",
        (ua,)
    ).fetchone()
    if cmd_row:
        # 'uninstall' and 'upgrade' are fire-and-forget: the agent applies them and
        # either removes itself or restarts into the new version without ever calling
        # back to /api/agent/result — there's no client-side code path that reports a
        # result for either. Marking them 'sent' left them looking like they were still
        # awaiting a result that would never arrive; the 5-minute stale-command requeue
        # above would then keep flipping them back to pending and redispatching them
        # forever, and since they always carry the lowest id in this host's queue, they
        # permanently blocked every command queued after them from ever being sent.
        # Marking them 'done' the moment they're actually delivered reflects that the
        # server's own part is complete once the agent has the instruction in hand.
        if cmd_row['label'] in ('uninstall', 'upgrade'):
            db.execute("UPDATE agent_commands SET status = 'done', completed_at = ? WHERE id = ?", (now, cmd_row['id']))
        else:
            db.execute("UPDATE agent_commands SET status = 'sent' WHERE id = ?", (cmd_row['id'],))
        db.commit()
        if cmd_row['label'] == 'uninstall':
            return jsonify({'command': 'uninstall'})
        if cmd_row['label'] == 'upgrade':
            # Embeds the current agent source (with the same __HOST_URL__/__SOC_TOKEN__
            # substitution as the manual download) directly in the poll response — the
            # agent overwrites its own installed copy and restarts itself with it.
            # agent_os is this exact check-in's own header, so no extra lookup is
            # needed to know which source file matches the endpoint asking for it.
            # Re-embeds the agent's *own* current token (whatever it just authenticated
            # this check-in with) rather than the legacy shared secret, so an agent
            # already running on a per-agent token doesn't get regressed back onto the
            # unscoped shared one by upgrading.
            server_ip = request.host.split(':')[0]
            cursor = db.execute("SELECT key, value FROM settings")
            s = {r[0]: r[1] for r in cursor.fetchall()}
            ui_port = s.get("ui_port", "5001")
            ingest_port = _resolve_ingest_port(ui_port)
            agent_filename = 'micro_agent_linux.py' if agent_os == 'linux' else 'micro_agent_windows.py'
            source = _build_agent_source(agent_filename, server_ip, ui_port, ingest_port, request.headers.get('X-Agent-Token') or '')
            if source:
                return jsonify({'command': 'upgrade', 'source': source})
        return jsonify({'run_script': {'id': cmd_row['id'], 'script': cmd_row['script']}})

    all_channels = get_agent_channels()
    enabled_channels = {name: v for name, v in all_channels.items() if v.get('enabled')}
    channels = ','.join(enabled_channels.keys()) or 'Security,System,Application,PowerShell'

    # Rich per-channel config for agents that understand it (capture_xml + a ready-made
    # PowerShell Where-Object clause built from the saved event-ID filter) -- the flat
    # 'channels' string above stays as a fallback for an agent mid-upgrade. filter_value
    # was already validated at save time (api_agent_channels), but re-parsing is wrapped
    # defensively so a corrupted config file can never break every agent's poll cycle.
    channel_config = []
    for name, v in enabled_channels.items():
        try:
            ranges = _parse_event_id_ranges(v.get('filter_value', ''))
            where_clause = _build_powershell_id_clause(ranges, v.get('filter_mode', 'none'))
        except ValueError:
            where_clause = ''
        channel_config.append({'name': name, 'capture_xml': bool(v.get('capture_xml')), 'where_clause': where_clause})

    # Grab the active Ingestion IP/Port to pass to the agent
    cursor = db.execute("SELECT key, value FROM settings")
    s = {r[0]: r[1] for r in cursor.fetchall()}
    ing_ip = s.get("ingest_bind_ip", "0.0.0.0")
    ing_port = _resolve_ingest_port(s.get("ui_port", "5001"))

    # If set to 0.0.0.0, fallback to the IP the agent connected to
    if ing_ip == "0.0.0.0":
        ing_ip = request.host.split(":")[0]

    dynamic_ingest_url = f"https://{ing_ip}:{ing_port}/api/ingest"

    fim_paths = [r['path'] for r in db.execute("SELECT path FROM fim_paths WHERE enabled = 1").fetchall()]
    try:
        fim_interval_seconds = int(s.get('fim_interval_seconds') or DEFAULT_FIM_INTERVAL_SECONDS)
    except (TypeError, ValueError):
        fim_interval_seconds = DEFAULT_FIM_INTERVAL_SECONDS

    return jsonify({
        'channels': channels, 'channel_config': channel_config, 'ingest_url': dynamic_ingest_url,
        'fim_paths': fim_paths, 'fim_interval_seconds': fim_interval_seconds,
    })

# Log Search spans three tables that were previously siloed from each other: raw
# ingested events (live_logs), Sigma/custom detection-rule hits (alerts), and UEBA
# behavioral anomalies (events, app_name='duckdb_ueba') — an analyst investigating an
# incident needs all three in one searchable timeline, not three separate pages.
# Every branch is normalized to the same column shape so the existing filter/search
# logic (built for live_logs alone) works unchanged against the union.
#
# Kept as individual fragments (rather than one flat unioned string) so
# api_logs_search/export_logs_csv can push WHERE+ORDER BY+LIMIT into each branch
# separately -- see _build_optimized_log_query()'s comment for why. api_logs_timeline
# still wants the flat, all-branches-always-unioned shape (it aggregates via its own
# GROUP BY, not subject to the same cost), so UNIFIED_LOGS_SQL/_WITH_ARCHIVE stay
# defined below, just derived from these same fragments instead of duplicating them.
_LOG_BRANCH_SQL = """SELECT timestamp, severity, host, app, event_id, username, source_ip, destination_ip, message, 'log' as log_type,
       NULL as rule_id, NULL as rule_source, NULL as log_event_id, NULL as log_app, NULL as raw_json,
       process_image, command_line, parent_image, parent_command_line, original_file_name, raw_xml,
       NULL as occurrence_count, NULL as last_seen, NULL as item_id, NULL as entity_type,
       NULL as status, NULL as assignee, file_hash, query_name
FROM live_logs"""

_LOG_ARCHIVE_BRANCH_SQL = _LOG_BRANCH_SQL.replace("FROM live_logs", "FROM live_logs_archive")

_ALERT_BRANCH_SQL = """SELECT a.timestamp, a.severity,
       COALESCE(a.host, 'UNKNOWN') as host,
       COALESCE(s.title, a.rule_name, 'Custom/YARA Rule') as app,
       '-' as event_id,
       COALESCE(a.username, '-') as username,
       a.source_ip as source_ip,
       a.destination_ip as destination_ip,
       COALESCE(a.message, '') as message,
       'alert' as log_type,
       a.rule_id as rule_id,
       CASE WHEN a.rule_id IS NULL THEN 'heuristic' ELSE COALESCE(s.source, 'sigma') END as rule_source,
       a.log_event_id as log_event_id,
       a.log_app as log_app,
       NULL as raw_json,
       NULL as process_image, NULL as command_line, NULL as parent_image, NULL as parent_command_line, NULL as original_file_name, NULL as raw_xml,
       a.occurrence_count as occurrence_count, a.last_seen as last_seen, a.id as item_id, NULL as entity_type,
       a.status as status, a.assignee as assignee, NULL as file_hash, NULL as query_name
FROM alerts a
LEFT JOIN sigma_rules s ON a.rule_id = s.id"""

_ANOMALY_BRANCH_SQL = """SELECT timestamp, severity, hostname as host, 'UEBA Anomaly' as app, '-' as event_id, '-' as username,
       NULL as source_ip, NULL as destination_ip, message, 'anomaly' as log_type,
       NULL as rule_id, 'ueba' as rule_source, NULL as log_event_id, NULL as log_app, raw_json,
       NULL as process_image, NULL as command_line, NULL as parent_image, NULL as parent_command_line, NULL as original_file_name, NULL as raw_xml,
       NULL as occurrence_count, NULL as last_seen, id as item_id, entity_type,
       NULL as status, NULL as assignee, NULL as file_hash, NULL as query_name
FROM events
WHERE app_name = 'duckdb_ueba'"""

# (log_type, branch_sql) pairs, in the same branch order as the historical flat unions.
LOG_TYPE_BRANCHES = [('log', _LOG_BRANCH_SQL), ('alert', _ALERT_BRANCH_SQL), ('anomaly', _ANOMALY_BRANCH_SQL)]
LOG_TYPE_BRANCHES_WITH_ARCHIVE = [
    ('log', _LOG_BRANCH_SQL), ('log', _LOG_ARCHIVE_BRANCH_SQL), ('alert', _ALERT_BRANCH_SQL), ('anomaly', _ANOMALY_BRANCH_SQL)
]

UNIFIED_LOGS_SQL = "(\n" + "\nUNION ALL\n".join(sql for _, sql in LOG_TYPE_BRANCHES) + "\n) AS unified_logs"
UNIFIED_LOGS_SQL_WITH_ARCHIVE = "(\n" + "\nUNION ALL\n".join(sql for _, sql in LOG_TYPE_BRANCHES_WITH_ARCHIVE) + "\n) AS unified_logs"

_RANGE_DELTAS = {
    '5m': ('minutes', 5), '15m': ('minutes', 15), '30m': ('minutes', 30),
    '1h': ('hours', 1), '4h': ('hours', 4), '12h': ('hours', 12), '24h': ('hours', 24),
    '3d': ('days', 3), '7d': ('days', 7), '30d': ('days', 30),
}

def _parse_datetime_local(s):
    # <input type="datetime-local"> yields "YYYY-MM-DDTHH:MM" (seconds omitted when the
    # user doesn't set them) — normalize to the "YYYY-MM-DD HH:MM:SS" format timestamp
    # comparisons use elsewhere in this file.
    if not s:
        return None
    s = s.strip().replace('T', ' ')
    if len(s) == 16:  # no seconds
        s += ':00'
    return s

# Single source of truth for "which columns can Log Search's field-specific filter
# target" -- both _build_log_filters()'s server-side allowlist and the Field Manager UI's
# key picker (dashboard.html) read from this. Previously the UI had its own independent,
# unvalidated list (a free-text field name the user typed), so a custom field could be
# added to the picklist that silently fell back to searching `message` server-side with
# no indication anything was wrong -- this list is what closes that gap.
LOG_SEARCH_ALLOWED_FIELDS = [
    {'key': 'username', 'label': 'User'},
    {'key': 'host', 'label': 'Host'},
    {'key': 'event_id', 'label': 'Event ID'},
    {'key': 'source_ip', 'label': 'Src IP'},
    {'key': 'destination_ip', 'label': 'Dest IP'},
    {'key': 'message', 'label': 'Message'},
    {'key': 'log_type', 'label': 'Type'},
    {'key': 'process_image', 'label': 'Process Image'},
    {'key': 'command_line', 'label': 'Command Line'},
    {'key': 'parent_image', 'label': 'Parent Image'},
    {'key': 'parent_command_line', 'label': 'Parent Command Line'},
    {'key': 'original_file_name', 'label': 'Original File Name'},
    {'key': 'raw_xml', 'label': 'Raw XML'},
    {'key': 'file_hash', 'label': 'File Hash'},
    {'key': 'query_name', 'label': 'DNS Query'},
]

# Sortable via the Log Search results table's clickable column headers -- restricted to
# columns that exist with consistent meaning across all 3 UNIFIED_LOGS_SQL branches
# (unlike e.g. `message`, sorting alphabetically on a free-text column has little value
# and isn't worth exposing as a header click target).
_SORTABLE_LOG_COLUMNS = {'timestamp', 'severity', 'host', 'app', 'event_id', 'username',
                          'source_ip', 'destination_ip', 'log_type'}

def _resolve_sort_column(args):
    col = args.get('sort', 'timestamp')
    return col if col in _SORTABLE_LOG_COLUMNS else 'timestamp'

def _build_log_sort(args):
    col = _resolve_sort_column(args)
    direction = 'ASC' if args.get('dir', 'desc').lower() == 'asc' else 'DESC'
    # Must include the SAME tiebreak columns _build_log_cursor() compares on, in the same
    # order -- SQLite makes no guarantee about the relative order of tied rows unless the
    # ORDER BY itself fully disambiguates them, so an ORDER BY that stops at just the sort
    # column would let ties come back in a different order on each paginated query,
    # silently breaking the cursor's "no gaps, no dupes" guarantee for exactly the rows
    # that share a sort_col+timestamp value.
    if col == 'timestamp':
        return f"ORDER BY timestamp {direction}, message {direction}"
    return f"ORDER BY {col} {direction}, timestamp {direction}, message {direction}"

# Keyset ("cursor") pagination for Log Search's Load More: rather than re-scanning from row
# 1 with an ever-larger LIMIT on every click (which is what UEBA Timeline's own Load More
# still does -- fine at its scale, but exactly the "offset paging, not cursor" pattern the
# SIEM gap audit called out), each page after the first carries the last row it rendered as
# a WHERE-clause continuation token, so the next page's query only has to seek forward from
# that point instead of re-scanning everything before it.
#
# Neither the sort column alone nor (sort_col, timestamp) together are guaranteed unique --
# this app's own event volume (~100k+/day on a busy host) makes multiple rows sharing both
# the same sort-column value AND the same to-the-second timestamp a real, not theoretical,
# case (a burst of Sysmon events for one host in one second). A 2-level cursor silently
# DROPS whichever tied rows land past the cursor's own tie-group boundary -- caught by a
# real-fixture test with an intentional exact-timestamp tie before this was fixed to a
# 3-level (sort_col, timestamp, message) tiebreak. `message` isn't a guaranteed-unique
# tiebreaker either (two genuinely identical log lines at the same timestamp would still
# tie) but at that point the two rows are indistinguishable from each other anyway -- this
# is the same "good enough, not mathematically perfect" trade-off the surrounding query-
# language code already makes elsewhere (e.g. no true USN-journal parsing).
def _build_log_cursor(args):
    cursor_time = args.get('cursor_time')
    if not cursor_time:
        return None, []
    sort_col = _resolve_sort_column(args)
    op = '>' if args.get('dir', 'desc').lower() == 'asc' else '<'
    cursor_tiebreak = args.get('cursor_tiebreak', '')
    if sort_col == 'timestamp':
        # The tuple collapses to (timestamp, message) since sort_col IS timestamp already.
        return (
            f"(timestamp {op} ? OR (timestamp = ? AND COALESCE(message, '') {op} COALESCE(?, '')))",
            [cursor_time, cursor_time, cursor_tiebreak]
        )
    cursor_val = args.get('cursor_sort', '')
    return (
        f"(COALESCE({sort_col}, '') {op} COALESCE(?, '') "
        f"OR (COALESCE({sort_col}, '') = COALESCE(?, '') AND timestamp {op} ?) "
        f"OR (COALESCE({sort_col}, '') = COALESCE(?, '') AND timestamp = ? AND COALESCE(message, '') {op} COALESCE(?, '')))",
        [cursor_val, cursor_val, cursor_time, cursor_val, cursor_time, cursor_tiebreak]
    )

# The Global Search query language: space-separated terms AND together implicitly (like
# every mature search box -- Splunk/Elastic/Google all treat unquoted multi-word input as
# an implicit AND of terms, not one literal substring, which is the actual behavior change
# from the old single-LIKE-blob this replaces). Supports "quoted phrases", -exclude / NOT
# exclude negation, explicit OR between two terms, field:value scoping to one column
# (validated against LOG_SEARCH_ALLOWED_FIELDS -- an unrecognized field: prefix is honestly
# treated as a literal term rather than silently redirected, unlike the old Field Manager
# bug), and * / ? wildcards translated to SQL LIKE's % / _.
_QUERY_TOKEN_RE = re.compile(r'"([^"]*)"|(\S+)')
_QUERY_DEFAULT_COLUMNS = ('host', 'app', 'event_id', 'username', 'message')

def _tokenize_search_query(q):
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in _QUERY_TOKEN_RE.finditer(q.strip())]

def _wildcard_term_to_like(value):
    # Escape SQL LIKE's own special chars first so a literal % or _ in the search term
    # (e.g. searching for "50%") isn't misinterpreted as a wildcard -- done BEFORE
    # translating * / ? so those two never collide with the escaping step. A term
    # containing * or ? is used as the user wrote it (translated to SQL's % / _, no
    # auto-wrap) since the wildcard placement is deliberate; a plain term with neither
    # gets wrapped in %...% for the usual substring/"contains" behavior.
    has_wildcard = '*' in value or '?' in value
    escaped = value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    if has_wildcard:
        return escaped.replace('*', '%').replace('?', '_')
    return f'%{escaped}%'

def _parse_search_query(q):
    allowed_fields = {f['key'] for f in LOG_SEARCH_ALLOWED_FIELDS}
    tokens = _tokenize_search_query(q)
    clauses = []  # list of (join, sql, params); join is how this clause joins the PREVIOUS one
    pending_join = 'AND'
    pending_not = False
    for raw_tok in tokens:
        upper = raw_tok.upper()
        if upper == 'AND':
            pending_join = 'AND'
            continue
        if upper == 'OR':
            pending_join = 'OR'
            continue
        if upper == 'NOT':
            pending_not = True
            continue

        term = raw_tok
        negate = pending_not
        pending_not = False
        if term.startswith('-') and len(term) > 1:
            negate = True
            term = term[1:]

        field = None
        value = term
        if ':' in term and not term.startswith(':'):
            maybe_field, maybe_value = term.split(':', 1)
            if maybe_field in allowed_fields and maybe_value:
                field, value = maybe_field, maybe_value

        like_value = _wildcard_term_to_like(value).lower()

        if field:
            sql = f"LOWER({field}) LIKE ? ESCAPE '\\'"
            term_params = [like_value]
        else:
            sql = '(' + ' OR '.join(f"LOWER({c}) LIKE ? ESCAPE '\\'" for c in _QUERY_DEFAULT_COLUMNS) + ')'
            term_params = [like_value] * len(_QUERY_DEFAULT_COLUMNS)

        if negate:
            sql = f"NOT {sql}"
        clauses.append((pending_join, sql, term_params))
        pending_join = 'AND'

    if not clauses:
        return None, []
    sql = clauses[0][1]
    params = list(clauses[0][2])
    for join, clause_sql, clause_params in clauses[1:]:
        sql += f' {join} {clause_sql}'
        params.extend(clause_params)
    return f'({sql})', params

# Factored out of _build_log_filters so the route handlers can also use it to skip
# building/unioning a branch entirely when it's excluded, not just filter it out after.
def _active_log_types(args):
    return {t.strip() for t in args.get('types', '').split(',') if t.strip()}

def _build_log_filters(args):
    import datetime
    q = args.get('q', '').lower()
    time_range = args.get('range', '24h')
    app_filter = args.get('app', '')
    severity_filter = args.get('severity', '')
    active_types = _active_log_types(args)
    field_key = args.get('fieldKey', '')
    field_op = args.get('fieldOp', 'contains')
    field_val = args.get('fieldVal', '').lower()

    params, conditions = [], []

    if time_range == 'custom':
        start = _parse_datetime_local(args.get('start', ''))
        end = _parse_datetime_local(args.get('end', ''))
        if start:
            conditions.append("timestamp >= ?")
            params.append(start)
        if end:
            conditions.append("timestamp <= ?")
            params.append(end)
    elif time_range and time_range.lower() != 'all':
        now = datetime.datetime.now()
        unit, amount = _RANGE_DELTAS.get(time_range, ('hours', 24))
        delta = datetime.timedelta(**{unit: amount})
        conditions.append("timestamp >= ?")
        params.append((now - delta).strftime('%Y-%m-%d %H:%M:%S'))

    if app_filter:
        apps = [a.strip() for a in app_filter.split(',') if a.strip()]
        if apps:
            conditions.append(f"app IN ({','.join(['?']*len(apps))})")
            params.extend(apps)

    if active_types:
        # log_type is one of 'log' / 'alert' / 'anomaly' -- both the UEBA Timeline tab's
        # event-type checkboxes and Log Search's own Type filter drive this, same IN-list
        # shape as the app/severity filters above. Kept even though api_logs_search/
        # export_logs_csv also skip excluded branches entirely (see LOG_TYPE_BRANCHES) --
        # this is what api_logs_timeline (which unions every branch unconditionally) relies
        # on, and it's a harmless no-op redundancy for the other two callers.
        conditions.append(f"log_type IN ({','.join(['?']*len(active_types))})")
        params.extend(active_types)

    if severity_filter:
        # Sigma/UEBA severities are Title-case (Critical/High/Medium), live_logs and the
        # legacy inline-heuristic alerts are upper-case (INFO/CRITICAL/HIGH) — normalize
        # both sides so one filter list matches every source's casing.
        sevs = [s.strip().upper() for s in severity_filter.split(',') if s.strip()]
        if sevs:
            conditions.append(f"UPPER(severity) IN ({','.join(['?']*len(sevs))})")
            params.extend(sevs)

    allowed_columns = [f['key'] for f in LOG_SEARCH_ALLOWED_FIELDS]
    if field_key and field_val:
        col = field_key if field_key in allowed_columns else 'message'
        if field_op == 'equals':
            conditions.append(f"LOWER({col}) = ?"); params.append(field_val)
        elif field_op == 'not_equals':
            conditions.append(f"LOWER({col}) != ?"); params.append(field_val)
        elif field_op == 'starts_with':
            conditions.append(f"LOWER({col}) LIKE ?"); params.append(f'{field_val}%')
        elif field_op == 'ends_with':
            conditions.append(f"LOWER({col}) LIKE ?"); params.append(f'%{field_val}')
        elif field_op == 'gt':
            conditions.append(f"{col} > ?"); params.append(field_val)
        elif field_op == 'lt':
            conditions.append(f"{col} < ?"); params.append(field_val)
        else:
            conditions.append(f"LOWER({col}) LIKE ?"); params.append(f'%{field_val}%')

    if q:
        query_sql, query_params = _parse_search_query(q)
        if query_sql:
            conditions.append(query_sql)
            params.extend(query_params)

    where_clause = (" WHERE " + " and ".join(conditions)) if conditions else ""
    return where_clause, params

# Pushes WHERE + ORDER BY + LIMIT into EACH branch before unioning, instead of applying
# them once after the union closes (the old SELECT * FROM (<union>) WHERE ... ORDER BY
# ... LIMIT ? shape). SQLite has no per-branch-index-then-merge strategy for a UNION ALL
# wrapped in an outer ORDER BY/LIMIT -- it has to gather every row matching the WHERE
# from every branch into a temporary sorter, sort the ENTIRE matched set, and only then
# trim to LIMIT. For a broad time range with no other filter that's most of live_logs.
# Pushing LIMIT into each branch lets that branch's own timestamp index satisfy an
# efficient top-K scan instead. This is exact, not an approximation: the global top-K
# under any sort comparator is always a subset of each branch's own top-K under that
# same comparator, so per-branch LIMIT can never drop a row that belonged in the result.
def _build_optimized_log_query(branches, where_clause, where_params, sort_clause, limit):
    # SQLite doesn't allow a bare "(SELECT ... LIMIT ?) UNION ALL (SELECT ... LIMIT ?)"
    # -- parenthesizing an individual compound-select operand isn't valid syntax there
    # (unlike Postgres). Each per-branch top-K query is wrapped as its own FROM
    # subquery instead, so the outer UNION ALL operand is a plain, unparenthesized
    # SELECT * FROM (...) with the ORDER BY/LIMIT safely nested inside.
    per_branch_sql, all_params = [], []
    for _, branch_sql in branches:
        per_branch_sql.append(f"SELECT * FROM (SELECT * FROM ({branch_sql}) {where_clause} {sort_clause} LIMIT ?)")
        all_params.extend(where_params)
        all_params.append(limit)
    merged = "(\n" + "\nUNION ALL\n".join(per_branch_sql) + "\n) AS unified_logs"
    all_params.append(limit)
    return f"SELECT * FROM {merged} {sort_clause} LIMIT ?", all_params

# Per-branch COUNT(*), summed, rather than SELECT COUNT(*) FROM (<union>) WHERE ... --
# same reasoning as _build_optimized_log_query: lets each branch's own index satisfy its
# own filtered count instead of depending on whether SQLite's optimizer flattens the
# union and pushes the WHERE down (a real but unconfirmable-without-EXPLAIN-QUERY-PLAN
# question on the union-wrapped shape).
def _count_log_rows(db, branches, where_clause, where_params):
    return sum(
        db.execute(f"SELECT COUNT(*) FROM ({branch_sql}) {where_clause}", where_params).fetchone()[0]
        for _, branch_sql in branches
    )

# Shared by /api/logs/search and /api/logs/export's format=json path, so the two never
# drift into different row shapes -- both consume the same sqlite3.Row list straight off
# UNIFIED_LOGS_SQL/_WITH_ARCHIVE.
def _build_log_response_rows(rows):
    from geoip import lookup_country
    logs = []
    for r in rows:
        process_image, command_line, parent_image = r['process_image'], r['command_line'], r['parent_image']
        if r['log_type'] == 'anomaly' and r['raw_json']:
            # UEBA anomaly rows don't carry real process_image/command_line columns
            # (they're log lines from `events`, not Sysmon-parsed live_logs rows) -- the
            # process detail ueba_engine.py captured lives inside raw_json instead, same
            # as /api/ueba/detections used to parse before that endpoint was folded into
            # this one for the merged UEBA Timeline tab.
            try:
                raw = json.loads(r['raw_json'])
            except (TypeError, ValueError):
                raw = {}
            process_image = process_image or raw.get('process_image')
            command_line = command_line or raw.get('command_line')
            parent_image = parent_image or raw.get('parent_image')
        # A fast local mmdb lookup (no network call, cached reader) -- applied to every
        # row type. A private/reserved/non-routable source_ip (common on raw log/anomaly
        # rows) just resolves to (None, None), same as it always has for those.
        country_code = country_name = None
        if r['source_ip']:
            country_code, country_name = lookup_country(r['source_ip'])
        logs.append({
            'id': r['item_id'],
            'time': r['timestamp'],
            'severity': r['severity'],
            'host': r['host'],
            'app': r['app'],
            'event_id': r['event_id'],
            'username': r['username'],
            'entity_type': r['entity_type'],
            'source_ip': r['source_ip'] if r['source_ip'] is not None else '-',
            'destination_ip': r['destination_ip'] if r['destination_ip'] is not None else '-',
            'country_code': country_code,
            'country_name': country_name,
            'message': r['message'],
            'type': r['log_type'],
            'rule_id': r['rule_id'],
            'rule_source': r['rule_source'],
            'log_event_id': r['log_event_id'],
            'log_app': r['log_app'],
            'raw_json': r['raw_json'],
            'process_image': process_image,
            'command_line': command_line,
            'parent_image': parent_image,
            'parent_command_line': r['parent_command_line'],
            'original_file_name': r['original_file_name'],
            'raw_xml': r['raw_xml'],
            'occurrence_count': r['occurrence_count'],
            'last_seen': r['last_seen'],
            'status': r['status'],
            'assignee': r['assignee'],
            'file_hash': r['file_hash'],
            'query_name': r['query_name']
        })
    return logs

@app.route('/api/logs/search', methods=['GET'])
@login_required
def api_logs_search():
    from flask import request, jsonify
    try:
        db = get_db()
        where_clause, params = _build_log_filters(request.args)
        active_types = _active_log_types(request.args)
        branches = LOG_TYPE_BRANCHES_WITH_ARCHIVE if request.args.get('include_archive') == '1' else LOG_TYPE_BRANCHES
        if active_types:
            branches = [(t, sql) for t, sql in branches if t in active_types]
        sort_clause = _build_log_sort(request.args)
        limit = max(1, min(request.args.get('limit', 300, type=int) or 300, 2000))

        if not branches:
            return jsonify({'logs': [], 'count': 0, 'total_matches': 0})

        # Load More passes cursor_time (+ cursor_sort when not sorting by timestamp) from
        # the last row of the page it already has -- folded into the same WHERE as an
        # additional AND'd condition, same connective as every other filter here.
        cursor_clause, cursor_params = _build_log_cursor(request.args)
        full_where = where_clause
        full_params = list(params)
        if cursor_clause:
            full_params += cursor_params
            full_where = f"{where_clause} AND {cursor_clause}" if where_clause else f" WHERE {cursor_clause}"

        # The total-match count never changes between pages of the SAME search (filters
        # are identical, only the cursor differs), so Load More passes skip_count=1 to
        # avoid re-running that full COUNT(*) scan on every click -- the frontend already
        # has the real total from page 1 and just keeps displaying it.
        if request.args.get('skip_count') == '1':
            total_count = None
        else:
            total_count = _count_log_rows(db, branches, where_clause, params)
        query_sql, query_params = _build_optimized_log_query(branches, full_where, full_params, sort_clause, limit)
        rows = db.execute(query_sql, query_params).fetchall()
        logs = _build_log_response_rows(rows)

        # `poll=1` marks an auto-refresh (UEBA Timeline's Live Streaming Mode), not a
        # deliberate search -- auditing every 5-second poll would flood audit_log with
        # near-duplicate entries for an otherwise-idle browser tab. A user-initiated search
        # (button click, filter change, Timeline tab load) always gets logged. A Load More
        # click is real user activity too, so it's still logged (only poll=1 is excluded).
        if request.args.get('poll') != '1':
            log_audit('log_search', 'search', None,
                      f"q={request.args.get('q', '')[:100]!r} range={request.args.get('range', '24h')} matches={total_count}")

        return jsonify({'logs': logs, 'count': len(logs), 'total_matches': total_count})
    except Exception as e:
        return jsonify({'error': str(e), 'logs': [], 'count': 0, 'total_matches': 0})

@app.route('/api/logs/export', methods=['GET'])
@login_required
def export_logs_csv():
    from flask import request, Response
    import csv, io
    try:
        db = get_db()
        where_clause, params = _build_log_filters(request.args)
        active_types = _active_log_types(request.args)
        branches = LOG_TYPE_BRANCHES_WITH_ARCHIVE if request.args.get('include_archive') == '1' else LOG_TYPE_BRANCHES
        if active_types:
            branches = [(t, sql) for t, sql in branches if t in active_types]
        sort_clause = _build_log_sort(request.args)
        export_format = 'json' if request.args.get('format') == 'json' else 'csv'

        # Increased export limit (10,000 records) for deep incident analysis.
        if branches:
            query, query_params = _build_optimized_log_query(branches, where_clause, params, sort_clause, 10000)
            cursor = db.execute(query, query_params)
            rows = cursor.fetchall()
        else:
            cursor, rows = None, []

        # Exports are always a deliberate action (unlike search, never auto-polled) --
        # data leaving the system is exactly the chain-of-custody moment worth recording.
        log_audit('log_export', 'search', None,
                  f"format={export_format} rows={len(rows)} q={request.args.get('q', '')[:100]!r}")

        if export_format == 'json':
            logs = _build_log_response_rows(rows)
            return Response(
                json.dumps({'logs': logs, 'count': len(logs)}, default=str),
                mimetype="application/json",
                headers={"Content-Disposition": "attachment;filename=micro_soc_complete_export.json"}
            )

        column_names = [description[0] for description in cursor.description] if cursor and cursor.description else [
            'timestamp', 'severity', 'host', 'app', 'event_id', 'username', 'source_ip', 'destination_ip', 'message', 'log_type'
        ]

        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(column_names)
        for r in rows:
            cw.writerow([str(r[col]) if r[col] is not None else '' for col in column_names])

        return Response(
            si.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=micro_soc_complete_export.csv"}
        )
    except Exception as e:
        return str(e), 500

@app.route('/api/logs/timeline', methods=['GET'])
@login_required
def api_logs_timeline():
    from flask import request, jsonify
    import datetime
    try:
        db = get_db()
        where_clause, params = _build_log_filters(request.args)
        time_range = request.args.get('range', '24h')

        if time_range in ('5m', '15m', '30m', '1h'):
            time_format = "strftime('%Y-%m-%d %H:%M', timestamp)"
        elif time_range in ('4h', '12h', '24h'):
            time_format = "strftime('%Y-%m-%d %H:00', timestamp)"
        elif time_range == 'custom':
            # Bucket width scales with the span the user actually picked instead of a
            # single fixed granularity, since a custom range could be 10 minutes or 10 years.
            start = _parse_datetime_local(request.args.get('start', ''))
            end = _parse_datetime_local(request.args.get('end', ''))
            span = None
            try:
                if start and end:
                    span = (datetime.datetime.strptime(end, '%Y-%m-%d %H:%M:%S') -
                            datetime.datetime.strptime(start, '%Y-%m-%d %H:%M:%S'))
            except ValueError:
                span = None
            if span and span <= datetime.timedelta(hours=2):
                time_format = "strftime('%Y-%m-%d %H:%M', timestamp)"
            elif span and span <= datetime.timedelta(days=3):
                time_format = "strftime('%Y-%m-%d %H:00', timestamp)"
            else:
                time_format = "strftime('%Y-%m-%d', timestamp)"
        else:
            # 3d/7d/30d/all
            time_format = "strftime('%Y-%m-%d', timestamp)"

        source_sql = UNIFIED_LOGS_SQL_WITH_ARCHIVE if request.args.get('include_archive') == '1' else UNIFIED_LOGS_SQL
        query = f"SELECT {time_format} as t_bucket, COUNT(*) as count FROM {source_sql}{where_clause} GROUP BY t_bucket ORDER BY t_bucket ASC"
        rows = db.execute(query, params).fetchall()

        timeline = [{'time': r['t_bucket'], 'count': r['count']} for r in rows]
        return jsonify({'timeline': timeline})
    except Exception as e:
        return jsonify({'timeline': [], 'error': str(e)})

# Saved searches store the same filter-state object the frontend already builds for every
# /api/logs/search call (q/app/severity/range/start/end/fieldKey/fieldOp/fieldVal/types/
# sort/dir/include_archive) as one JSON blob -- loading one just repopulates the filter
# panel and re-runs the existing search, no separate query-execution path needed. Shared
# across all users (not scoped to created_by), matching every other shared resource in
# this app (cases, alerts, rules) -- there's no per-user data privacy model here.
@app.route('/api/saved-searches', methods=['GET', 'POST'])
@login_required
def api_saved_searches():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute("SELECT id, name, query_params, created_by, created_at FROM saved_searches ORDER BY name COLLATE NOCASE").fetchall()
        return jsonify([dict(r) for r in rows])
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    query_params = data.get('query_params')
    if not isinstance(query_params, dict):
        return jsonify({'error': 'query_params must be an object'}), 400
    db.execute(
        "INSERT INTO saved_searches (name, query_params, created_by) VALUES (?, ?, ?)",
        (name, json.dumps(query_params), current_user.username)
    )
    db.commit()
    log_audit('saved_search_create', 'saved_search', None, name)
    return jsonify({'status': 'success'})

@app.route('/api/saved-searches/<int:sid>', methods=['DELETE'])
@login_required
def api_saved_search_delete(sid):
    db = get_db()
    row = db.execute("SELECT name FROM saved_searches WHERE id = ?", (sid,)).fetchone()
    if not row:
        return jsonify({'error': 'Saved search not found'}), 404
    db.execute("DELETE FROM saved_searches WHERE id = ?", (sid,))
    db.commit()
    log_audit('saved_search_delete', 'saved_search', sid, row['name'])
    return jsonify({'status': 'success'})

# --- PERSISTENT CHANNELS CONFIG ---
import json, os
AGENT_CONFIG_PATH = '/opt/micro-dfir/agent_config.json'

_DEFAULT_CHANNEL_ENABLED = {
    'Security': True,
    'System': True,
    'Application': True,
    'PowerShell': False,
    'Sysmon': False,
    'WindowsDefender': False,
}

def _default_channel_setting(enabled=False):
    return {'enabled': bool(enabled), 'capture_xml': False, 'filter_mode': 'none', 'filter_value': ''}

def get_agent_channels():
    file_existed = os.path.exists(AGENT_CONFIG_PATH)
    data = {}
    if file_existed:
        try:
            with open(AGENT_CONFIG_PATH, 'r') as f:
                data = json.load(f)
        except Exception:
            data = {}

    # Transparently upgrades the old flat {"Security": true, ...} shape (each value a
    # plain bool) to the richer per-channel settings object below -- same lazy-upgrade
    # spirit as this file's migrate_*() functions, just for a JSON file instead of a
    # SQL table. Any other malformed entry is dropped rather than crashing the page.
    upgraded = False
    channels = {}
    for name, value in data.items():
        if isinstance(value, bool):
            channels[name] = _default_channel_setting(value)
            upgraded = True
        elif isinstance(value, dict):
            setting = _default_channel_setting(value.get('enabled', False))
            setting['capture_xml'] = bool(value.get('capture_xml', False))
            if value.get('filter_mode') in ('none', 'include', 'exclude'):
                setting['filter_mode'] = value.get('filter_mode')
            setting['filter_value'] = str(value.get('filter_value') or '')
            channels[name] = setting

    for name, default_enabled in _DEFAULT_CHANNEL_ENABLED.items():
        if name not in channels:
            channels[name] = _default_channel_setting(default_enabled)
            if file_existed:
                upgraded = True

    if file_existed and upgraded:
        save_agent_channels(channels)
    return channels

def save_agent_channels(data):
    with open(AGENT_CONFIG_PATH, 'w') as f:
        json.dump(data, f)

@app.route('/api/agent/channels', methods=['GET', 'POST'])
@login_required
def api_agent_channels():
    from flask import request, jsonify
    if request.method == 'POST':
        # Ingestion filters/collection config, same "backend data" bucket as the
        # Sigma drop-rules pipeline -- this was previously ungated (any logged-in
        # user could change what gets collected), inconsistent with every
        # neighboring settings route.
        err = require_permission('edr.agent.manage')
        if err: return err
        posted = request.json or {}
        channels = {}
        for name, value in posted.items():
            name = (name or '').strip()
            if not name:
                continue
            # Channel names are spliced unescaped into a PowerShell -FilterHashtable
            # string on the agent (fetch_windows_logs) -- this allowlist is what makes
            # a free-typed custom channel name as safe as the fixed presets always were.
            if not _CHANNEL_NAME_RE.match(name):
                return jsonify({'status': 'error', 'message': f"'{name}' is not a valid channel name"}), 400
            if not isinstance(value, dict):
                return jsonify({'status': 'error', 'message': f"'{name}': invalid channel settings"}), 400
            filter_mode = value.get('filter_mode') if value.get('filter_mode') in ('none', 'include', 'exclude') else 'none'
            filter_value = str(value.get('filter_value', '') or '')
            if filter_mode != 'none':
                try:
                    _parse_event_id_ranges(filter_value)
                except ValueError as e:
                    return jsonify({'status': 'error', 'message': f"'{name}' event ID filter: {e}"}), 400
            channels[name] = {
                'enabled': bool(value.get('enabled')),
                'capture_xml': bool(value.get('capture_xml')),
                'filter_mode': filter_mode,
                'filter_value': filter_value,
            }
        # Presets always exist even if the posted payload omitted one.
        for name, default_enabled in _DEFAULT_CHANNEL_ENABLED.items():
            channels.setdefault(name, _default_channel_setting(default_enabled))
        save_agent_channels(channels)
        return jsonify({'status': 'success', 'channels': channels})
    return jsonify(get_agent_channels())




# --- SETTINGS API ENDPOINTS ---
import shutil, subprocess
from werkzeug.security import generate_password_hash

@app.route('/api/settings/metrics', methods=['GET'])
@login_required
def api_settings_metrics():
    from flask import jsonify
    try:
        # CPU Usage (using top)
        cpu = subprocess.check_output("top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'", shell=True).decode('utf-8').strip()
        if not cpu: cpu = "0.0"
        
        # RAM Usage (using free)
        ram = subprocess.check_output("free -m | awk 'NR==2{printf \"%.1f\", $3*100/$2 }'", shell=True).decode('utf-8').strip()
        
        # Disk Usage
        total, used, free = shutil.disk_usage("/")
        disk_pct = round((used / total) * 100, 1)
        disk_total_gb = round(total / (1024**3), 1)
        disk_free_gb = round(free / (1024**3), 1)
        
        # Database Size
        db_path = "/opt/micro-dfir/siem.db"
        db_size_mb = round(os.path.getsize(db_path) / (1024*1024), 2) if os.path.exists(db_path) else 0

        return jsonify({
            'cpu': cpu, 
            'ram': ram, 
            'disk_pct': disk_pct, 
            'disk_free_gb': disk_free_gb,
            'disk_total_gb': disk_total_gb,
            'db_size_mb': db_size_mb
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/cert', methods=['POST'])
@login_required
def api_settings_cert():
    from flask import request, jsonify
    import ssl
    err = require_permission('settings.network.manage')
    if err: return err
    if 'cert_file' not in request.files or 'key_file' not in request.files:
        return jsonify({'error': 'Both Certificate and Private Key files are required.'}), 400

    cert = request.files['cert_file']
    key = request.files['key_file']
    cert_bytes = cert.read()
    key_bytes = key.read()

    # Validate the pair actually loads as a matching cert+key before touching anything
    # the running server depends on — an unvalidated bad upload here would take down
    # HTTPS for the entire UI with no way to recover except SSH.
    with tempfile.NamedTemporaryFile(suffix='.pem') as tmp_cert, tempfile.NamedTemporaryFile(suffix='.pem') as tmp_key:
        tmp_cert.write(cert_bytes); tmp_cert.flush()
        tmp_key.write(key_bytes); tmp_key.flush()
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(tmp_cert.name, tmp_key.name)
        except ssl.SSLError as e:
            return jsonify({'error': f'Invalid certificate/key pair: {e}'}), 400

    # Gunicorn's systemd unit (microsoc-web.service) always points --certfile/--keyfile
    # at AGENT_TLS_CERT_PATH's directory — the previous /opt/micro-dfir/certs/ location
    # was never actually read by anything, so an uploaded cert silently never took
    # effect even after a restart.
    cert_dir = os.path.dirname(AGENT_TLS_CERT_PATH)
    os.makedirs(cert_dir, exist_ok=True)
    with open(os.path.join(cert_dir, 'cert.pem'), 'wb') as f:
        f.write(cert_bytes)
    with open(os.path.join(cert_dir, 'key.pem'), 'wb') as f:
        f.write(key_bytes)

    # Same background-restart pattern as Save & Apply Network Settings — the cert files
    # are only read at process startup, so nothing picks up the change until gunicorn
    # actually restarts.
    subprocess.Popen("(sleep 2 && systemctl restart microsoc-web.service) &", shell=True)
    log_audit('tls_cert_upload', 'settings')

    return jsonify({'status': 'success', 'message': 'Certificate validated and applied. The web UI is restarting now — you may need to reconnect in a few seconds.'})

@app.route('/api/settings/users', methods=['GET', 'POST'])
@login_required
def api_settings_users():
    from flask import request, jsonify
    db = get_db()
    # Ensure users table has a role column -- lowercase default, matching every role
    # slug this app stores (roles.slug is always lowercase). A prior version of this
    # migration defaulted to 'Analyst' (capitalized), which never matched any real
    # permission check -- see migrate_role_casing() below for the one-time cleanup of
    # any rows that bug already wrote.
    try:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'analyst'")
        db.commit()
    except Exception:
        pass # Column already exists

    if request.method == 'POST':
        err = require_permission('settings.users.manage')
        if err: return err
        data = request.json
        action = data.get('action')

        if action == 'create':
            username = data.get('username')
            password = generate_password_hash(data.get('password'))
            role = data.get('role', 'analyst')
            valid_roles = {r['slug'] for r in db.execute("SELECT slug FROM roles").fetchall()}
            if role not in valid_roles:
                return jsonify({'error': f"role must be one of {', '.join(sorted(valid_roles))}"}), 400
            try:
                db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, password, role))
                db.commit()
                log_audit('user_create', 'user', username, f'role={role}')
                return jsonify({'status': 'success'})
            except Exception as e:
                return jsonify({'error': 'Username may already exist.'}), 400

        elif action == 'reset':
            user_id = data.get('id')
            new_password = generate_password_hash(data.get('password'))
            target_user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password, user_id))
            db.commit()
            log_audit('user_password_reset', 'user', target_user['username'] if target_user else user_id)
            return jsonify({'status': 'success'})

        elif action == 'delete':
            user_id = data.get('id')
            target_user = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
            if not target_user:
                return jsonify({'error': 'User not found'}), 404
            if target_user['id'] == current_user.id:
                return jsonify({'error': "You can't delete your own account."}), 400
            # Generalizes the old "last admin" guard to whichever role(s) currently hold
            # role/permission management -- with custom roles, that's no longer
            # necessarily the literal 'admin' slug.
            target_can_manage_roles = db.execute(
                "SELECT 1 FROM role_permissions rp JOIN roles r ON r.id = rp.role_id "
                "WHERE r.slug = ? AND rp.permission_key = 'settings.roles.manage'", (target_user['role'],)
            ).fetchone() is not None
            if target_can_manage_roles:
                remaining = db.execute(
                    "SELECT COUNT(*) FROM users u JOIN roles r ON r.slug = u.role JOIN role_permissions rp ON rp.role_id = r.id "
                    "WHERE rp.permission_key = 'settings.roles.manage' AND u.id != ?", (user_id,)
                ).fetchone()[0]
                if remaining == 0:
                    return jsonify({'error': 'Cannot delete the last user who can manage roles & users.'}), 400
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            log_audit('user_delete', 'user', target_user['username'])
            return jsonify({'status': 'success'})

    # GET request
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify({'users': [dict(u) for u in users]})

_ROLE_SLUG_RE = re.compile(r'^[a-z][a-z0-9_]*$')

@app.route('/api/settings/roles', methods=['GET', 'POST'])
@login_required
def api_settings_roles():
    db = get_db()
    if request.method == 'GET':
        roles = []
        for r in db.execute("SELECT id, slug, label, description, is_builtin, default_dashboard_id FROM roles ORDER BY is_builtin DESC, label").fetchall():
            perms = [row['permission_key'] for row in db.execute(
                "SELECT permission_key FROM role_permissions WHERE role_id = ?", (r['id'],)
            ).fetchall()]
            member_count = db.execute("SELECT COUNT(*) FROM users WHERE role = ?", (r['slug'],)).fetchone()[0]
            dash_name = None
            if r['default_dashboard_id']:
                dn = db.execute("SELECT name FROM dashboards WHERE id = ?", (r['default_dashboard_id'],)).fetchone()
                dash_name = dn['name'] if dn else None
            roles.append({**dict(r), 'permissions': perms, 'member_count': member_count, 'default_dashboard_name': dash_name})
        return jsonify({'roles': roles, 'registry': PERMISSION_REGISTRY})

    err = require_permission('settings.roles.manage')
    if err: return err
    d = request.json or {}
    slug = (d.get('slug') or '').strip().lower()
    label = (d.get('label') or '').strip()
    description = (d.get('description') or '').strip()
    perms = [p for p in (d.get('permissions') or []) if p in PERMISSION_KEYS]
    default_dashboard_id = d.get('default_dashboard_id') or None
    if not _ROLE_SLUG_RE.match(slug):
        return jsonify({'error': 'slug must start with a lowercase letter and contain only lowercase letters, numbers, and underscores'}), 400
    if not label:
        return jsonify({'error': 'label is required'}), 400
    if db.execute("SELECT 1 FROM roles WHERE slug = ?", (slug,)).fetchone():
        return jsonify({'error': f'A role with slug "{slug}" already exists'}), 400
    if default_dashboard_id and not db.execute("SELECT 1 FROM dashboards WHERE id = ?", (default_dashboard_id,)).fetchone():
        return jsonify({'error': 'default_dashboard_id does not exist'}), 400
    cur = db.execute(
        "INSERT INTO roles (slug, label, description, is_builtin, default_dashboard_id) VALUES (?, ?, ?, 0, ?)",
        (slug, label, description, default_dashboard_id)
    )
    rid = cur.lastrowid
    db.executemany("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)", [(rid, p) for p in perms])
    db.commit()
    log_audit('role_create', 'role', slug, f'permissions={",".join(sorted(perms))}')
    return jsonify({'status': 'success', 'id': rid})

@app.route('/api/settings/roles/<int:rid>', methods=['PUT', 'DELETE'])
@login_required
def api_settings_role_detail(rid):
    err = require_permission('settings.roles.manage')
    if err: return err
    db = get_db()
    existing = db.execute("SELECT slug, is_builtin FROM roles WHERE id = ?", (rid,)).fetchone()
    if not existing:
        return jsonify({'error': 'Role not found'}), 404

    if request.method == 'DELETE':
        if existing['is_builtin']:
            return jsonify({'error': 'Built-in roles cannot be deleted.'}), 400
        member_count = db.execute("SELECT COUNT(*) FROM users WHERE role = ?", (existing['slug'],)).fetchone()[0]
        if member_count > 0:
            return jsonify({'error': f'{member_count} user(s) still have this role -- reassign them first.'}), 400
        db.execute("DELETE FROM role_permissions WHERE role_id = ?", (rid,))
        db.execute("DELETE FROM roles WHERE id = ?", (rid,))
        db.commit()
        log_audit('role_delete', 'role', existing['slug'])
        return jsonify({'ok': 1})

    d = request.json or {}
    label = (d.get('label') or '').strip()
    description = (d.get('description') or '').strip()
    perms = {p for p in (d.get('permissions') or []) if p in PERMISSION_KEYS}
    default_dashboard_id = d.get('default_dashboard_id') or None
    if not label:
        return jsonify({'error': 'label is required'}), 400
    if default_dashboard_id and not db.execute("SELECT 1 FROM dashboards WHERE id = ?", (default_dashboard_id,)).fetchone():
        return jsonify({'error': 'default_dashboard_id does not exist'}), 400
    # The built-in admin role can never lose the two permissions that manage
    # users/roles -- without this, an admin could accidentally lock the whole
    # system out of user/role management with no way back in short of DB surgery.
    if existing['slug'] == 'admin':
        perms |= PINNED_ADMIN_PERMISSIONS
    db.execute(
        "UPDATE roles SET label = ?, description = ?, default_dashboard_id = ? WHERE id = ?",
        (label, description, default_dashboard_id, rid)
    )
    db.execute("DELETE FROM role_permissions WHERE role_id = ?", (rid,))
    db.executemany("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)", [(rid, p) for p in perms])
    db.commit()
    log_audit('role_update', 'role', existing['slug'], f'permissions={",".join(sorted(perms))}')
    return jsonify({'status': 'success'})


def _get_host_os(db, hostname):
    # Response actions are queued from the UI, not by the agent itself, so there's no
    # X-Agent-OS header on that request to read — look up what this hostname last
    # reported on its own check-in instead. Defaults to 'windows' for a host that's
    # never checked in with an OS at all, matching agent_config()'s own default.
    row = db.execute(
        "SELECT os FROM agent_polls WHERE user_agent = ? AND os IS NOT NULL AND os != '' ORDER BY id DESC LIMIT 1",
        (hostname,)
    ).fetchone()
    return row['os'] if row and row['os'] in ('windows', 'linux') else 'windows'

def _get_live_ioc_sha256_hashes(db):
    # ioc_type labeling for hashes is inconsistent across feeds ('md5'/'sha1'/'sha256'
    # from CSV uploads, 'file'/'unknown' from generic TAXII, whatever a live feed's own
    # vocabulary happens to send) — matching on the pattern value's own shape, the same
    # approach _guess_csv_ioc_type/_guess_legacy_ioc_type already use, is what actually
    # catches every feed's SHA-256 IOCs regardless of how each one labeled itself.
    rows = db.execute(
        "SELECT DISTINCT pattern FROM stix_indicators WHERE revoked = 0 AND LENGTH(pattern) = 64"
    ).fetchall()
    return sorted({r['pattern'].strip().lower() for r in rows if _SHA256_HEX_RE.match((r['pattern'] or '').strip())})

def _get_live_ioc_md5_hashes(db):
    rows = db.execute(
        "SELECT DISTINCT pattern FROM stix_indicators WHERE revoked = 0 AND LENGTH(pattern) = 32"
    ).fetchall()
    return sorted({r['pattern'].strip().lower() for r in rows if _MD5_HEX_RE.match((r['pattern'] or '').strip())})

def _get_live_ioc_sha1_hashes(db):
    rows = db.execute(
        "SELECT DISTINCT pattern FROM stix_indicators WHERE revoked = 0 AND LENGTH(pattern) = 40"
    ).fetchall()
    return sorted({r['pattern'].strip().lower() for r in rows if _SHA1_HEX_RE.match((r['pattern'] or '').strip())})

_YARA_RULE_NAME_RE = re.compile(r'^\s*rule\s+(\w+)')
# Matches a plain double-quoted YARA string definition ($name = "literal" <modifiers>),
# capturing the literal's raw (still-escaped) content and whatever modifier text follows
# on the same line. Hex patterns ({ .. }) and regex patterns (/../) use different syntax
# entirely and simply never match this, so they're excluded for free.
_YARA_STRING_DEF_RE = re.compile(r'^\s*\$\w+\s*=\s*"((?:[^"\\]|\\.)*)"\s*(.*)$')
# nocase/wide/base64 all change what bytes actually need to be searched for — a plain
# case-sensitive ASCII substring search (the whole point of keeping this agent-side
# matcher dependency-free) can't faithfully represent any of them, so those strings are
# skipped rather than shipped as a pattern that would silently mismatch what YARA means.
_YARA_SKIP_MODIFIERS = ('nocase', 'wide', 'base64')

def _unescape_yara_string(s):
    # Minimal YARA string-escape decoding — just enough to recover the real bytes a
    # literal represents (\", \\, \t, \n, \r, \xHH). Anything else is left as-is; worst
    # case that produces a pattern with a stray backslash that simply never matches
    # anything (a safe failure mode — a missed pattern, not a false hit).
    out = []
    i = 0
    mapping = {'\\': '\\', '"': '"', 't': '\t', 'n': '\n', 'r': '\r'}
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == 'x' and i + 3 < len(s):
                try:
                    out.append(chr(int(s[i + 2:i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
        out.append(c)
        i += 1
    return ''.join(out)

def _get_live_yara_strings(limit=150):
    # Same "recompute fresh every use" philosophy as the live IOC hash helpers above —
    # the imported rule files rarely change and the walk is cheap, so there's no reason
    # to cache a stale list. Sourced from the same rules/yara_imported directory the
    # File Scan mode already compiles against, so this hunts with the rules actually
    # loaded in the app, not a separate/parallel rule set.
    #
    # Capped well below the old 500 -- string_sweep's per-file cost in agent_scripts.py
    # scales with pattern count no matter how it's implemented (Contains-loop, regex,
    # or otherwise), so this cap is what actually keeps a real sweep inside the agent's
    # command timeout, not just an implementation detail of the search algorithm.
    results = []
    seen = set()
    if not os.path.isdir(YARA_RULES_DIR):
        return results
    for root, dirs, files in os.walk(YARA_RULES_DIR):
        for fname in sorted(files):
            if not fname.endswith(('.yar', '.yara')):
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, YARA_RULES_DIR)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
            except OSError:
                continue
            current_rule = rel_path
            for line in text.splitlines():
                rule_m = _YARA_RULE_NAME_RE.match(line)
                if rule_m:
                    current_rule = rule_m.group(1)
                    continue
                m = _YARA_STRING_DEF_RE.match(line)
                if not m:
                    continue
                raw, tail = m.group(1), m.group(2).lower()
                if any(mod in tail for mod in _YARA_SKIP_MODIFIERS):
                    continue
                value = _unescape_yara_string(raw)
                # Real production string_sweep output showed 6-char strings like
                # "Microsoft"/"Uninstall" (9 chars each) matching on huge swaths of
                # ordinary Windows binaries -- individual short YARA strings are normally
                # only meaningful combined with a rule's other conditions, which this
                # agent-side substring search deliberately doesn't (can't) evaluate. 10
                # is still short enough to keep plenty of real signal (API names, PDB
                # paths, C2 domains all comfortably clear it) while cutting the shortest,
                # noisiest generic tokens.
                if len(value) < 10:
                    continue
                key = (current_rule, value)
                if key in seen:
                    continue
                seen.add(key)
                results.append({'rule': current_rule, 'file': rel_path, 'string': value})
                if len(results) >= limit:
                    return results
    return results

_YARA_ANY_STRING_DEF_RE = re.compile(r'^\s*\$\w+\s*=')
_YARA_CONDITION_START_RE = re.compile(r'^\s*condition\s*:\s*(.*)$')
_YARA_CONDITION_ANY_RE = re.compile(r'^\s*(?:any|1)\s+of\s+them\s*;?\s*$', re.IGNORECASE)
_YARA_CONDITION_ALL_RE = re.compile(r'^\s*all\s+of\s+them\s*;?\s*$', re.IGNORECASE)
_YARA_CONDITION_NOF_RE = re.compile(r'^\s*(\d+)\s+of\s+them\s*;?\s*$', re.IGNORECASE)

def _get_live_yara_rule_conditions(max_rules=60, max_strings_per_rule=25):
    # A step beyond _get_live_yara_strings()'s flat any-string-hit list: groups a rule's
    # strings together and classifies its condition into one of the few forms simple
    # enough to safely evaluate without a real YARA engine on the endpoint --
    # "any/1 of them", "all of them", "N of them". Anything else (named-string boolean
    # logic, hex/regex strings, PE/math modules, offsets) is genuinely out of reach for a
    # dependency-free pure-Python matcher, so a rule using any of that -- or containing
    # even ONE string this can't cleanly extract (hex/regex/nocase/wide/base64) -- is
    # dropped entirely rather than guessed at: a rule silently excluded from the
    # condition-aware sweep is a missed detection; a rule wrongly reported as
    # condition-satisfied is a false CRITICAL alert. Only the former is acceptable here.
    rules_out = []
    if not os.path.isdir(YARA_RULES_DIR):
        return rules_out
    for root, dirs, files in os.walk(YARA_RULES_DIR):
        for fname in sorted(files):
            if not fname.endswith(('.yar', '.yara')):
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, YARA_RULES_DIR)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.read().splitlines()
            except OSError:
                continue

            i = 0
            while i < len(lines):
                rule_m = _YARA_RULE_NAME_RE.match(lines[i])
                if not rule_m:
                    i += 1
                    continue
                rule_name = rule_m.group(1)
                strings, supported, condition = [], True, None
                i += 1
                while i < len(lines) and not _YARA_RULE_NAME_RE.match(lines[i]):
                    line = lines[i]
                    cond_m = _YARA_CONDITION_START_RE.match(line)
                    if cond_m:
                        # Condition text may continue on following lines up to the
                        # closing brace -- join them, since "N of them" etc. is always
                        # written as one logical expression even if line-wrapped.
                        cond_lines = [cond_m.group(1)]
                        j = i + 1
                        while j < len(lines) and lines[j].strip() != '}':
                            cond_lines.append(lines[j])
                            j += 1
                        cond_text = re.sub(r'//.*$', '', ' '.join(cond_lines), flags=re.MULTILINE).strip()
                        if _YARA_CONDITION_ANY_RE.match(cond_text):
                            condition = 'any'
                        elif _YARA_CONDITION_ALL_RE.match(cond_text):
                            condition = 'all'
                        else:
                            nof_m = _YARA_CONDITION_NOF_RE.match(cond_text)
                            condition = ('n_of', int(nof_m.group(1))) if nof_m else None
                        i = j
                        continue
                    str_m = _YARA_STRING_DEF_RE.match(line)
                    if str_m:
                        raw, tail = str_m.group(1), str_m.group(2).lower()
                        unescaped = _unescape_yara_string(raw)
                        # No length-based noise filter here, unlike _get_live_yara_strings()
                        # above -- for "all of them"/"N of them" a real condition needs
                        # EVERY string checked or the count is wrong, which can turn a
                        # partial (false) match into a reported "condition satisfied". A
                        # too-short/degenerate literal (empty, or so short it's not really
                        # a signature) makes the WHOLE rule unsafe to evaluate instead of
                        # just being dropped, since dropping it would silently weaken an
                        # AND-style condition into something easier to satisfy than the
                        # real rule.
                        if any(mod in tail for mod in _YARA_SKIP_MODIFIERS) or len(unescaped) < 2:
                            supported = False
                        else:
                            strings.append(unescaped)
                    elif _YARA_ANY_STRING_DEF_RE.match(line):
                        supported = False  # a $-string def that ISN'T the plain-text form (hex/regex)
                    i += 1

                if supported and condition and strings and len(strings) <= max_strings_per_rule:
                    deduped = sorted(set(strings))
                    # Resolved to a plain integer threshold ("at least N of these strings
                    # must be present") -- any/all/N-of-them are really the same check
                    # with a different N, so the agent only has to implement one
                    # comparison instead of three branches of condition logic.
                    if condition == 'any':
                        required_n, label = 1, 'any of them'
                    elif condition == 'all':
                        required_n, label = len(deduped), 'all of them'
                    else:
                        required_n, label = condition[1], f'{condition[1]} of them'
                    if required_n <= len(deduped):  # can't require more matches than strings exist
                        rules_out.append({'rule': rule_name, 'file': rel_path, 'strings': deduped, 'required_n': required_n, 'condition_label': label})
                if len(rules_out) >= max_rules:
                    return rules_out
    return rules_out

AGENT_TLS_CERT_PATH = '/opt/micro-dfir/config/cert.pem'

def _build_agent_source(agent_filename, server_ip, ui_port, ingest_port, soc_token):
    # Shared by the manual download route and the remote self-upgrade path (agent_config())
    # so both ever inject the placeholders the exact same way.
    agents_dir = '/opt/micro-dfir/agents'
    target_file = os.path.join(agents_dir, agent_filename)
    if not os.path.exists(target_file):
        return None
    with open(target_file, 'r', encoding='utf-8') as f:
        script_data = f.read()
    script_data = script_data.replace('https://__HOST_URL__/api/agent/config', f'https://{server_ip}:{ui_port}/api/agent/config')
    script_data = script_data.replace('https://__HOST_URL__/api/agent/result', f'https://{server_ip}:{ui_port}/api/agent/result')
    script_data = script_data.replace('https://__HOST_URL__/api/ingest', f'https://{server_ip}:{ingest_port}/api/ingest')
    script_data = script_data.replace('__SOC_TOKEN__', soc_token)
    # The server's cert is self-signed with no CA to chain to and no SAN for the IP
    # agents actually connect over — pinning this exact cert (see the agent's own
    # ssl.create_default_context(cadata=...) call) is what makes verification possible
    # at all here, in place of skipping verification outright.
    try:
        with open(AGENT_TLS_CERT_PATH, 'r', encoding='utf-8') as f:
            cert_pem = f.read()
    except OSError:
        cert_pem = ''
    script_data = script_data.replace('__SERVER_CERT_PEM__', cert_pem.replace('\\', '\\\\').replace('"""', '\\"\\"\\"'))
    return script_data

@app.route('/api/agent/download/<os_type>', methods=['GET'])
@login_required
def api_download_agent(os_type):
    from flask import send_file, request
    import io, zipfile, tarfile, os

    # Mints a fresh enrollment credential and ships a full installer -- agent
    # deployment, gated the same as every other "manage backend data" Tier 3+ action.
    err = require_permission('edr.agent.manage')
    if err: return err

    # Grab the exact IP the user is connecting to the UI with
    server_ip = request.host.split(':')[0]

    db = get_db()
    cursor = db.execute("SELECT key, value FROM settings")
    s = {r[0]: r[1] for r in cursor.fetchall()}
    ui_port = s.get("ui_port", "5001")
    ingest_port = _resolve_ingest_port(ui_port)
    # A fresh per-agent token for this specific download, not the shared soc_secret —
    # it's unbound to any hostname until the endpoint it actually gets installed on
    # first checks in (see _validate_agent_auth), so a leaked token from one download
    # can't be replayed to impersonate a different already-enrolled host the way the
    # single shared secret could.
    import datetime as _dt
    soc_token = secrets.token_hex(32)
    db.execute(
        "INSERT INTO agent_tokens (token, hostname, created_at) VALUES (?, NULL, ?)",
        (soc_token, _dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    db.commit()

    memory_file = io.BytesIO()

    if os_type == 'windows':
        script_data = _build_agent_source('micro_agent_windows.py', server_ip, ui_port, ingest_port, soc_token)
        if script_data is None:
            return "Windows agent not found on server.", 404

        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('micro_agent_windows.py', script_data)

        memory_file.seek(0)
        return send_file(memory_file, download_name='MicroDFIR_Windows_Agent.zip', as_attachment=True)

    elif os_type == 'linux':
        script_data = _build_agent_source('micro_agent_linux.py', server_ip, ui_port, ingest_port, soc_token)
        if script_data is None:
            return "Linux agent not found on server.", 404

        with tarfile.open(fileobj=memory_file, mode='w:gz') as tf:
            tarinfo = tarfile.TarInfo('micro_agent_linux.py')
            tarinfo.size = len(script_data.encode('utf-8'))
            tf.addfile(tarinfo, io.BytesIO(script_data.encode('utf-8')))
            
        memory_file.seek(0)
        return send_file(memory_file, download_name='MicroDFIR_Linux_Agent.tar.gz', as_attachment=True)
        
    return "Invalid OS type requested.", 400


@app.route('/api/agent/checkins', methods=['GET'])
@login_required
def agent_checkins():
    from flask import jsonify
    import datetime
    db = get_db()
    try:
        rows = db.execute('SELECT * FROM agent_polls WHERE id IN (SELECT MAX(id) FROM agent_polls GROUP BY ip_address) ORDER BY id DESC LIMIT 20').fetchall()
        now = datetime.datetime.now()
        mapped = []
        hostnames = []
        for r in rows:
            ts = r["timestamp"] if "timestamp" in r.keys() else ""
            # Every row used to be hardcoded "Online" regardless of how long ago it actually
            # checked in — an agent that stopped polling (uninstalled, powered off, network
            # drop) would sit at the top of this list looking perpetually alive forever.
            # The agent checks in roughly every 15s under normal operation, so a healthy
            # margin above that (45s) still counts as Online; anything not heard from in
            # over 5 minutes is genuinely gone, not just a missed beat.
            status = "Unknown"
            try:
                last_seen = datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                age = (now - last_seen).total_seconds()
                if age <= 45: status = "Online"
                elif age <= 300: status = "Idle"
                else: status = "Offline"
            except (ValueError, TypeError):
                pass
            hostname = r["user_agent"] if "user_agent" in r.keys() else "Windows-Endpoint"
            hostnames.append(hostname)
            version = r["version"] if "version" in r.keys() and r["version"] else "unknown"
            os_name = r["os"] if "os" in r.keys() and r["os"] in ("windows", "linux") else "windows"
            mapped.append({
                "hostname": hostname,
                "endpoint_ip": r["ip_address"] if "ip_address" in r.keys() else "Unknown",
                "status": status,
                "last_check_in": ts,
                "version": version,
                "version_since": None,
                "os": os_name,
                "group": "",
                "recent_polls": []
            })

        if hostnames:
            placeholders = ','.join('?' * len(hostnames))
            # A host re-enrolled onto a new per-download token leaves its OLD agent_tokens
            # row behind (still hostname-matched, just stale) -- ordering oldest-first so
            # the most-recently-bound row's group_name is what survives the dict build below.
            group_rows = db.execute(
                f"SELECT hostname, group_name FROM agent_tokens WHERE hostname IN ({placeholders}) AND group_name != '' ORDER BY bound_at ASC",
                hostnames
            ).fetchall()
            group_by_host = {gr['hostname']: gr['group_name'] for gr in group_rows}
            for m in mapped:
                m['group'] = group_by_host.get(m['hostname'], '')

        # Recent check-in timestamps per host, for the heartbeat sparkline on the Agents
        # page — one bulk query bounded to the last 2000 polls across the visible hosts,
        # rather than a separate query per row.
        if hostnames:
            placeholders = ','.join('?' * len(hostnames))
            poll_rows = db.execute(
                f"SELECT user_agent, timestamp FROM agent_polls WHERE user_agent IN ({placeholders}) ORDER BY id DESC LIMIT 2000",
                hostnames
            ).fetchall()
            polls_by_host = {}
            for pr in poll_rows:
                bucket = polls_by_host.setdefault(pr['user_agent'], [])
                if len(bucket) < 20:
                    bucket.append(pr['timestamp'])
            for m in mapped:
                m['recent_polls'] = polls_by_host.get(m['hostname'], [])

            # When each host's currently-reported version was first seen — i.e. when it
            # was last upgraded to (or installed at) that version — one bulk lookup
            # against the (hostname, version) pairs actually present rather than a
            # query per row.
            version_pairs = [(m['hostname'], m['version']) for m in mapped if m.get('version') and m['version'] != 'unknown']
            if version_pairs:
                or_clause = ' OR '.join(['(hostname = ? AND version = ?)'] * len(version_pairs))
                vh_params = [v for pair in version_pairs for v in pair]
                vh_rows = db.execute(
                    f"SELECT hostname, version, first_seen FROM agent_version_history WHERE {or_clause}",
                    vh_params
                ).fetchall()
                vh_map = {(vr['hostname'], vr['version']): vr['first_seen'] for vr in vh_rows}
                for m in mapped:
                    m['version_since'] = vh_map.get((m['hostname'], m['version']))

        return jsonify(mapped)
    except Exception as e:
        print("Checkins error:", e)
        return jsonify([])

# Was hardcoded as FIM_INTERVAL = 300 directly in both agent scripts -- moved here so
# it's viewable/settable from the Agents page instead of requiring a code change +
# redeploy + re-upgrade of every endpoint just to retune how often FIM runs.
DEFAULT_FIM_INTERVAL_SECONDS = 300

@app.route('/api/fim/interval', methods=['GET', 'POST'])
@login_required
def api_fim_interval():
    db = get_db()
    if request.method == 'GET':
        row = db.execute("SELECT value FROM settings WHERE key = 'fim_interval_seconds'").fetchone()
        seconds = int(row['value']) if row and row['value'] else DEFAULT_FIM_INTERVAL_SECONDS
        return jsonify({'interval_seconds': seconds})

    err = require_permission('edr.fim.manage')
    if err: return err
    data = request.get_json() or {}
    try:
        seconds = int(data.get('interval_seconds'))
        if not (60 <= seconds <= 86400):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "interval_seconds must be an integer between 60 (1 minute) and 86400 (24 hours)"}), 400
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('fim_interval_seconds', ?)", (str(seconds),))
    db.commit()
    return jsonify({"status": "success", "interval_seconds": seconds})

@app.route('/api/fim/paths', methods=['GET', 'POST'])
@login_required
def api_fim_paths():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute(
            "SELECT id, path, description, enabled, created_by, created_at FROM fim_paths ORDER BY path"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    err = require_permission('edr.fim.manage')
    if err: return err
    data = request.get_json() or {}
    path = (data.get('path') or '').strip()
    description = (data.get('description') or '').strip()
    if not path:
        return jsonify({"error": "Path is required"}), 400
    db.execute(
        "INSERT INTO fim_paths (path, description, enabled, created_by) VALUES (?, ?, 1, ?)",
        (path, description, current_user.username)
    )
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/fim/paths/<int:fid>', methods=['PUT', 'DELETE'])
@login_required
def api_fim_path_detail(fid):
    err = require_permission('edr.fim.manage')
    if err: return err
    db = get_db()
    if not db.execute("SELECT 1 FROM fim_paths WHERE id = ?", (fid,)).fetchone():
        return jsonify({"error": "Path not found"}), 404

    if request.method == 'DELETE':
        db.execute("DELETE FROM fim_paths WHERE id = ?", (fid,))
        db.commit()
        return jsonify({"ok": 1})

    data = request.get_json() or {}
    db.execute("UPDATE fim_paths SET enabled = ? WHERE id = ?", (1 if data.get('enabled') else 0, fid))
    db.commit()
    return jsonify({"status": "success"})

# Isolating a host, restoring it, pulling a triage bundle, or killing a known-bad
# process by PID are exactly the "incident response" work Tier 1/2 owns -- no
# collateral risk beyond the action itself, and no backend data/detection-logic
# access involved. Every other label (custom scripts, agent lifecycle, and the
# heavier hunt-flavored sweeps/collections) stays gated to Tier 3+ below.
AGENT_COMMAND_TIER1_LABELS = {'isolate_host', 'restore_network', 'collect_triage', 'kill_process'}

def _queue_agent_command(db, hostname, label, params, script_in, queued_by):
    """Builds and queues one command for one host -- the exact per-host logic
    api_agent_commands()'s POST branch always ran, now shared between the single-host
    path and the group fan-out path below so a group dispatch behaves identically to
    queuing the same command by hand to each member one at a time. Returns
    (cmd_id, None) on success or (None, error_message) on failure -- never raises, so
    one bad host in a group dispatch doesn't abort the rest."""
    # Response actions are queued from the UI (not by the agent), so there's no
    # X-Agent-OS header on this request — the target host's own last-reported OS
    # decides which script flavor (PowerShell vs bash) gets built.
    host_templates = agent_scripts.TEMPLATES_BY_OS[_get_host_os(db, hostname)]

    if label == 'custom':
        script = script_in or ''
        if not script.strip():
            return None, 'script is required for a custom command'
    elif label in host_templates:
        builder, required = host_templates[label]
        if label == 'ioc_sweep':
            # Always recomputed fresh at dispatch time, never client-supplied — a sweep
            # queued today reflects whatever's in the IOC browser today, the same way
            # sigma_engine.py's IOC-match rule condition recomputes its own IP list
            # fresh every detection cycle rather than freezing it at some earlier point.
            params['hashes'] = _get_live_ioc_sha256_hashes(db)
            params['md5_hashes'] = _get_live_ioc_md5_hashes(db)
            params['sha1_hashes'] = _get_live_ioc_sha1_hashes(db)
        if label == 'string_sweep':
            params['patterns'] = _get_live_yara_strings()
        if label == 'yara_condition_sweep':
            params['rule_conditions'] = _get_live_yara_rule_conditions()
        if label == 'isolate_host' and not params.get('soc_ip'):
            s = {r[0]: r[1] for r in db.execute("SELECT key, value FROM settings").fetchall()}
            soc_ip = s.get('ingest_bind_ip', '0.0.0.0')
            if soc_ip == '0.0.0.0':
                soc_ip = request.host.split(':')[0]
            params['soc_ip'] = soc_ip
        missing = [p for p in required if not params.get(p)]
        if missing:
            return None, f"Missing required parameter(s): {', '.join(missing)}"
        try:
            script = builder(params)
        except Exception as e:
            return None, f'Failed to build script: {e}'
    elif label == 'upgrade':
        # No script to build here — agent_config() recognizes this label specially and
        # embeds the current agent source directly in the poll response, mirroring how
        # 'uninstall' is handled.
        script = ''
    else:
        return None, f'Unknown command label: {label}'

    cur = db.execute(
        "INSERT INTO agent_commands (hostname, label, script, queued_by) VALUES (?, ?, ?, ?)",
        (hostname, label, script, queued_by)
    )
    return cur.lastrowid, None

@app.route('/api/agent/commands', methods=['GET', 'POST'])
@login_required
def api_agent_commands():
    db = get_db()

    if request.method == 'GET':
        hostname = request.args.get('hostname', '')
        label_filter = request.args.get('label', '')
        cmd_id = request.args.get('id', type=int)
        limit = request.args.get('limit', 30, type=int)
        conditions, params = [], []
        if hostname:
            conditions.append("hostname = ?")
            params.append(hostname)
        if label_filter:
            conditions.append("label = ?")
            params.append(label_filter)
        if cmd_id is not None:
            conditions.append("id = ?")
            params.append(cmd_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = db.execute(
            f"SELECT id, hostname, label, status, queued_by, queued_at, completed_at, exit_code, stdout, stderr FROM agent_commands {where} ORDER BY id DESC LIMIT ?",
            params + [limit]
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    d = request.json or {}
    hostname = (d.get('hostname') or '').strip()
    group_name = (d.get('group') or '').strip()
    label = d.get('label')
    if not label or (not hostname and not group_name):
        return jsonify({'error': 'hostname (or group) and label are required'}), 400
    err = require_permission('edr.command.basic' if label in AGENT_COMMAND_TIER1_LABELS else 'edr.command.advanced')
    if err: return err

    if group_name:
        # Only hosts that have both a group assignment AND a live check-in history --
        # a group can't dispatch to a host that no longer exists in agent_polls (already
        # uninstalled/decommissioned), same "must actually be a known endpoint" guard
        # the single-host path gets implicitly from the Agents page only ever listing
        # real hosts.
        hosts = [r['hostname'] for r in db.execute(
            "SELECT DISTINCT a.hostname FROM agent_tokens a "
            "WHERE a.group_name = ? AND a.hostname IN (SELECT user_agent FROM agent_polls)",
            (group_name,)
        ).fetchall()]
        if not hosts:
            return jsonify({'error': f'No known agents are in group "{group_name}"'}), 400
        queued, failed = [], []
        for h in hosts:
            cmd_id, error = _queue_agent_command(db, h, label, dict(d.get('params') or {}), d.get('script'), current_user.username)
            (failed if error else queued).append({'hostname': h, **({'error': error} if error else {'id': cmd_id})})
        db.commit()
        return jsonify({'status': 'success', 'queued': queued, 'failed': failed})

    cmd_id, error = _queue_agent_command(db, hostname, label, d.get('params', {}) or {}, d.get('script'), current_user.username)
    if error:
        return jsonify({'error': error}), 400
    db.commit()
    return jsonify({'status': 'success', 'id': cmd_id})

@app.route('/api/agent/result', methods=['POST'])
def api_agent_result():
    import datetime
    db = get_db()
    d = request.json or {}
    cmd_id = d.get('id')
    if not cmd_id:
        return jsonify({'error': 'id is required'}), 400

    # Cross-checked against the specific command's own hostname (not just "is this
    # token valid at all") so a token bound to one host can't submit a fake result for
    # a command that was queued for a *different* host.
    cmd = db.execute("SELECT hostname, label FROM agent_commands WHERE id = ?", (cmd_id,)).fetchone()
    if not cmd:
        return jsonify({'error': 'Unknown command id'}), 404
    if not _validate_agent_auth(db, request.headers.get('X-Agent-Token'), cmd['hostname']):
        return jsonify({'error': 'Unauthorized'}), 401

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = 'done' if d.get('exit_code', 1) == 0 else 'failed'
    # Was 20000 -- confirmed too tight in production: a string_sweep result (JSON, one
    # object per hit file) blew straight through it and got cut off mid-string into
    # invalid JSON. string_sweep now bounds its own output size on the agent side
    # (agent_scripts.py), but this is a safety margin for that and every other action's
    # output, not a value to size exactly around one script's current caps.
    stdout = str(d.get('stdout', ''))[:60000]
    db.execute(
        "UPDATE agent_commands SET status = ?, completed_at = ?, exit_code = ?, stdout = ?, stderr = ? WHERE id = ?",
        (status, now, d.get('exit_code'), stdout, str(d.get('stderr', ''))[:5000], cmd_id)
    )
    # A confirmed IOC/string-sweep hit today only lives inside this command's own
    # stdout JSON -- nothing queryable by entity. Mirrors exactly how UEBA anomalies
    # already surface (events, app_name-tagged) so a hit becomes visible in Log Search
    # and scorable by the composite risk engine (ueba_engine.py's run_risk_scoring),
    # instead of only being visible from the Sweep Results view that queued it.
    if status == 'done' and cmd['label'] in ('ioc_sweep', 'string_sweep'):
        try:
            hits = (json.loads(stdout or '{}') or {}).get('hits') or []
        except (json.JSONDecodeError, TypeError, AttributeError):
            hits = []
        if hits:
            message = f"{cmd['hostname']} (host) — {len(hits)} IOC match(es) found in a {cmd['label']} sweep."
            db.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, 'host', 'ioc_sweep', 'High', ?, ?)",
                (cmd['hostname'], message, json.dumps({'command_id': cmd_id, 'label': cmd['label'], 'hit_count': len(hits), 'detection_type': 'ioc_sweep_hit'}))
            )
    db.commit()
    return jsonify({'status': 'success'})

@app.route('/api/agent/groups', methods=['GET'])
@login_required
def api_agent_groups():
    db = get_db()
    rows = db.execute("SELECT DISTINCT group_name FROM agent_tokens WHERE group_name != '' ORDER BY group_name").fetchall()
    return jsonify([r['group_name'] for r in rows])

@app.route('/api/agent/<hostname>/group', methods=['PUT'])
@login_required
def api_agent_set_group(hostname):
    err = require_permission('edr.agent.manage')
    if err: return err
    db = get_db()
    group_name = ((request.json or {}).get('group_name') or '').strip()
    # Requires an already-bound agent_tokens row (the common case -- see
    # _validate_agent_auth, which binds one on a host's first check-in with a real
    # per-download token). A host still running the legacy *shared* secret never gets a
    # row at all (that auth path doesn't touch agent_tokens), and agent_tokens is keyed
    # by TOKEN, not hostname -- fabricating a placeholder row here to work around that
    # would leave an orphaned duplicate the day that host is re-downloaded onto a real
    # token, silently splitting its group between two rows. Simplest honest fix: ask for
    # a re-download/upgrade first, same as every other per-host feature already does.
    existing = db.execute("SELECT rowid FROM agent_tokens WHERE hostname = ? ORDER BY bound_at DESC LIMIT 1", (hostname,)).fetchone()
    if not existing:
        return jsonify({'error': 'This agent has no per-agent token on file yet (still on the legacy shared secret). Re-download/upgrade it once, then grouping will work.'}), 400
    db.execute("UPDATE agent_tokens SET group_name = ? WHERE rowid = ?", (group_name, existing['rowid']))
    db.commit()
    log_audit('agent_group_change', 'agent', hostname, f'group={group_name or "(none)"}')
    return jsonify({'status': 'success'})

@app.route('/api/agent/<hostname>', methods=['DELETE'])
@login_required
def delete_agent(hostname):
    from flask import jsonify
    err = require_permission('edr.agent.manage')
    if err: return err
    db = get_db()
    db.execute('DELETE FROM agent_polls WHERE user_agent = ?', (hostname,))
    cur = db.execute(
        "INSERT INTO agent_commands (hostname, label, script, queued_by) VALUES (?, 'uninstall', '', ?)",
        (hostname, current_user.username)
    )
    db.commit()
    return jsonify({"status": "success", "id": cur.lastrowid})

# ==========================================
# STARTUP — schema migrations + config regeneration
# ==========================================
# Placed at the true end of the file (after every def/route) rather than interleaved
# among the function definitions above, specifically so nothing here can accidentally
# call a name that hasn't been defined yet at the point it runs — that exact ordering
# bug bit both _resolve_ingest_port and get_soc_secret when this block sat mid-file.
migrate_settings()
migrate_ti_feeds()
migrate_stix_indicators()
migrate_agent_commands()
migrate_alerts_columns()
migrate_alerts_enrichment()
migrate_alerts_dedup_columns()
migrate_sigma_rules_columns()
migrate_rule_tuning()
migrate_rule_autocase()
migrate_compliance_tags()
migrate_ueba_entities()
migrate_ueba_math_v2()
migrate_assets_identities()
migrate_cases()
migrate_case_upgrade()
migrate_case_queues()
migrate_case_assets()
migrate_case_severity()
migrate_case_iocs()
migrate_dashboards()
migrate_role_casing()
migrate_role_permissions()
migrate_role_default_dashboard()
migrate_role_default_dashboard_v2()
migrate_playbooks()
migrate_playbook_secrets()
migrate_playbook_approvals()
migrate_live_logs_archive()
migrate_fim_paths()
migrate_ueba_priority_scores()
migrate_ueba_autocase()
migrate_live_logs_ip_columns()
migrate_live_logs_process_columns()
migrate_live_logs_hash_dns_columns()
migrate_agent_versions()
migrate_agent_tokens()
migrate_agent_groups()
migrate_cve_records()
migrate_audit_log()
migrate_risk_scoring()
migrate_anomaly_rules()
migrate_anomaly_rules_sequence_columns()
migrate_anomaly_rule_conditions()
migrate_anomaly_rule_conditions_logic()
migrate_seed_ueba_rules()
migrate_risk_score_events_rule_id()
migrate_report_history()
migrate_report_history_case_id()
migrate_log_search_indexes()
migrate_alerts_triage()
migrate_alerts_geoip_columns()
migrate_alerts_mitre_column()
migrate_saved_searches()
migrate_warninglists()
migrate_ioc_sightings()
migrate_ioc_sightings_alert_id()
migrate_coverage_snapshots()
migrate_sigma_rules_original_yaml()
migrate_sigma_rules_upstream_yaml()
migrate_seed_ioc_correlation_rule()
migrate_enrichment_results()
migrate_ti_entities()
migrate_ti_entities_confidence()
migrate_ti_entities_references()

try:
    # Regenerates /etc/vector/vector.toml from current settings/drop_rules on every
    # startup — self-heals a config left stale or hand-patched by a prior bug (wrong
    # port, wrong scheme, placeholder auth token) without needing an admin to touch a
    # drop rule or the Network settings form to trigger a regeneration.
    with app.app_context():
        generate_vector_config()
    print("[startup] vector.toml regenerated", flush=True)
except Exception:
    import traceback
    print("[startup] Could not regenerate vector.toml:", flush=True)
    traceback.print_exc()
    import sys as _sys
    _sys.stdout.flush(); _sys.stderr.flush()
