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
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask import Flask, render_template, request, jsonify, g, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ti_engine import lookup_ioc
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
def generate_vector_config():
    db = get_db()
    rules = db.execute("SELECT * FROM drop_rules WHERE enabled = 1").fetchall()

    cursor = db.execute("SELECT key, value FROM settings")
    s = {row[0]: row[1] for row in cursor.fetchall()}
    ingest_ip = s.get("ingest_bind_ip", "0.0.0.0")
    ingest_port = _resolve_ingest_port(s.get("ui_port", "5001"))
    soc_token = get_soc_secret(db) or ''

    # Drop rules are defined (in the Log Pipeline UI) against live_logs' own field names
    # (app/host/event_id/message), so they're applied AFTER the remap below renames
    # Vector's raw syslog field names (appname/hostname) into that same shape — matching
    # them against the pre-remap names (the previous fmap here) silently matched nothing,
    # since the UI never sends "app_name"/"hostname", only "app"/"host"/"event_id".
    stmts = []
    for r in rules:
        field = r['field'] if r['field'] in ('app', 'host', 'event_id', 'message') else 'message'
        val = (r['value'] or '').replace('\\', '\\\\').replace('"', '\\"')
        if r['operator'] == 'equals':
            cond = f'(to_string(.{field}) ?? "") == "{val}"'
        else:
            cond = f'contains((to_string(.{field}) ?? ""), "{val}")'
        desc = (r['description'] or '').replace('\n', ' ').replace('\r', ' ')
        stmts.append(f"  # {desc}\n  if {cond} {{ abort }}")
    drop_block = ('\n' + '\n'.join(stmts)) if stmts else ''

    toml = f"""[api]
enabled = true
address = "127.0.0.1:8686"

[sources.syslog_in]
type = "syslog"
mode = "udp"
address = "{ingest_ip}:514"

[transforms.shape_logs]
type = "remap"
inputs = ["syslog_in"]
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
            return redirect(url_for('dash'))
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

# live_logs.source_ip has never been populated by any ingest path — the Windows agent's
# Get-WinEvent selection doesn't request a network-address property, and nothing extracts
# one from the message text either. Windows Security auth events (4624/4625/4648, etc.)
# do carry it in their human-readable message body under this label, so best-effort regex
# extraction there is enough to make source_ip usable without changing the agent.
_SOURCE_IP_RE = re.compile(r'Source Network Address:\s*([0-9a-fA-F:.]+)')

def _extract_source_ip(message):
    if not message:
        return None
    m = _SOURCE_IP_RE.search(message)
    if not m:
        return None
    ip = m.group(1).strip()
    return ip if ip and ip != '-' else None

@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    from flask import request, jsonify
    import datetime
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
            # from a real endpoint, and request.remote_addr is that endpoint's address.
            sip = log.get('source_ip') or _extract_source_ip(msg) or request.remote_addr
            db.execute("INSERT INTO live_logs (timestamp, host, app, severity, event_id, username, source_ip, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (ts, hst, app_n, sev, eid, usr, sip, msg))
            count += 1

            # --- INLINE DETECTION ENGINE (fast keyword heuristics; sigma_engine.py runs the real Sigma-rule pipeline) ---
            msg_lower = msg.lower()
            triggered_rule = None
            alert_sev = "INFO"
            
            if "mimikatz" in msg_lower or "lsass" in msg_lower:
                triggered_rule = "Credential Dumping Activity"
                alert_sev = "CRITICAL"
            elif "powershell" in msg_lower and ("-enc" in msg_lower or "-w hidden" in msg_lower):
                triggered_rule = "Suspicious PowerShell Execution"
                alert_sev = "HIGH"
            elif "whoami" in msg_lower or "net user" in msg_lower or "ipconfig" in msg_lower:
                triggered_rule = "System Discovery Commands"
                alert_sev = "LOW"
                
            if triggered_rule:
                db.execute("INSERT INTO alerts (timestamp, rule_name, severity, host, message) VALUES (?, ?, ?, ?, ?)", (ts, triggered_rule, alert_sev, hst, msg))
            # -------------------------------
        db.commit()
        return jsonify({'status': 'success', 'ingested': count}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/')
@login_required
def dash():
    active_tab = request.args.get('tab', 'search')
    report_dir = '/opt/micro-dfir/reports'
    os.makedirs(report_dir, exist_ok=True)
    pdfs = [f for f in os.listdir(report_dir) if f.endswith('.pdf')]
    pdfs.sort(reverse=True)
    return render_template('dashboard.html', reports=pdfs, channels=get_agent_channels(), active_tab=active_tab, current_user=current_user, compliance_frameworks=COMPLIANCE_FRAMEWORKS)

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

@app.route('/api/alerts')
@login_required
def api_alerts():
    db = get_db()
    limit = request.args.get('limit', 30, type=int)
    try:
        rows = db.execute("""
            SELECT a.id, a.timestamp, a.severity, a.acknowledged,
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
def api_ti(): return jsonify(lookup_ioc(request.get_json().get('ioc')))


# ==========================================
# THREAT INTELLIGENCE — FEEDS & IOCS
# ==========================================
YARA_RULES_DIR = '/opt/micro-dfir/rules/yara_imported'

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

    return render_template('threat_intel.html', matches=matches, yara_files=yara_files, active_tab=active_tab, current_user=current_user)

TI_FEED_TYPES = ('taxii', 'threatfox', 'otx', 'urlhaus', 'feodotracker', 'yaraify', 'csv')

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

    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    result = ti_sync_one(fid)
    log_audit('ti_feed_sync', 'ti_feed', fid, str(result.get('count', result.get('message', ''))))
    return jsonify(result), (200 if result.get('status') == 'success' else 502)

@app.route('/api/ti/feeds/upload_csv', methods=['POST'])
@login_required
def api_ti_feeds_upload_csv():
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = db.execute(
        f"SELECT si.stix_id, si.type, si.ioc_type, si.name, si.description, si.pattern, si.valid_from, si.revoked, "
        f"si.inserted_at, si.feed_id, tf.name AS source_name FROM stix_indicators si "
        f"LEFT JOIN ti_feeds tf ON si.feed_id = tf.id {where} ORDER BY si.inserted_at DESC LIMIT ?",
        params + [limit]
    ).fetchall()
    total = db.execute(f"SELECT COUNT(*) FROM stix_indicators si {where}", params).fetchone()[0]
    return jsonify({'iocs': [dict(r) for r in rows], 'total': total})

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
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    d = request.get_json()
    db.execute("INSERT INTO drop_rules (field, operator, value, description, enabled) VALUES (?, ?, ?, ?, 1)", (d.get('field'), d.get('operator'), d.get('value'), d.get('description')))
    db.commit(); generate_vector_config()
    log_audit('drop_rule_create', 'drop_rule', None, f"{d.get('field')} {d.get('operator')} {d.get('value')}")
    return jsonify({"status": "success"}), 201

@app.route('/api/droprules/<int:rid>/toggle', methods=['PUT'])
@login_required
def tog_drop(rid):
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    get_db().execute("UPDATE drop_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id=?", (rid,)); get_db().commit(); generate_vector_config()
    log_audit('drop_rule_toggle', 'drop_rule', rid)
    return jsonify({"ok":1})

@app.route('/api/droprules/<int:rid>', methods=['DELETE'])
@login_required
def del_drop(rid):
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    get_db().execute("DELETE FROM drop_rules WHERE id=?", (rid,)); get_db().commit(); generate_vector_config()
    log_audit('drop_rule_delete', 'drop_rule', rid)
    return jsonify({"ok":1})


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
# cached rules). Anchored to the start of a line (^, MULTILINE) so a nested/indented
# field that merely ends in the same word -- e.g. a detection field named
# ResponseStatus: or release_date: -- can't be mistaken for the real top-level
# metadata key, and trailing inline comments (# ...) are excluded from the captured
# value rather than becoming part of it.
def _extract_yaml_field(key, text):
    m = re.search(rf'^{key}:\s*([^\n\r#]+)', text, re.MULTILINE)
    return m.group(1).strip().strip("'\"") if m else None

@app.route('/api/rules', methods=['GET', 'POST'])
@login_required
def api_rules():
    global RULES_CACHE, RULES_CACHE_TIME
    import time
    db = get_db()

    if request.method == 'GET':
        if RULES_CACHE is not None and (time.time() - RULES_CACHE_TIME) < RULES_CACHE_TTL:
            return jsonify(RULES_CACHE)

        import re
        rules_out = []
        for r in db.execute(
            "SELECT id, title, rule_yaml, enabled, source, cloned_from, created_by, created_at, updated_by, updated_at, compliance_tags "
            "FROM sigma_rules ORDER BY id DESC"
        ).fetchall():
            rid = r['id']
            ry = r['rule_yaml']
            try:
                cat = _extract_yaml_field('category', ry) or 'unknown'
                platform = (_extract_yaml_field('product', ry) or 'Global').title()

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

            rules_out.append({
                "id": rid,
                "title": r['title'],
                "enabled": r['enabled'],
                "rule_type": rule_type,
                "platform": platform,
                "category": cat,
                "tags": tags,
                "level": level,
                "status": status,
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
        return jsonify(RULES_CACHE)

    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
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
@app.route('/api/rules/<int:rid>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_rule_detail(rid):
    db = get_db()

    if request.method == 'GET':
        r = db.execute(
            "SELECT id, title, rule_yaml, enabled, source, cloned_from, created_by, created_at, updated_by, updated_at, compliance_tags "
            "FROM sigma_rules WHERE id = ?", (rid,)
        ).fetchone()
        if not r:
            return jsonify({"error": "Rule not found"}), 404
        out = dict(r)
        out['compliance_tags'] = [t for t in (r['compliance_tags'] or '').split(',') if t]
        return jsonify(out)

    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403

    if request.method == 'DELETE':
        title_row = db.execute("SELECT title FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
        db.execute("DELETE FROM sigma_rules WHERE id = ?", (rid,))
        db.execute("DELETE FROM sigma_rule_history WHERE rule_id = ?", (rid,))
        db.commit()
        invalidate_rules_cache()
        log_audit('rule_delete', 'rule', rid, title_row['title'] if title_row else None)
        return jsonify({"ok": 1})

    # PUT — update an existing rule's title/YAML. Sigma-sourced rules are read-only;
    # they must be cloned into a custom rule before they can be edited.
    existing = db.execute("SELECT rule_yaml, source FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
    if not existing:
        return jsonify({"error": "Rule not found"}), 404
    if existing['source'] == 'sigma':
        return jsonify({"error": "Sigma-sourced rules are read-only. Clone this rule to create an editable custom copy."}), 403

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
    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
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
    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
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
    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
    try:
        stats = _run_sigmahq_import()
    except Exception as e:
        return jsonify({"error": f"Import failed: {e}"}), 500
    invalidate_rules_cache()
    log_audit('sigmahq_import', 'rule', None, f"inserted={stats['inserted']}, updated={stats['updated']}, skipped={stats['skipped']}, errors={stats['errors']}")
    return jsonify({"status": "success", **stats})

@app.route('/api/rules/<int:rid>/toggle', methods=['PUT'])
@login_required
def api_r_tog(rid):
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    db=get_db(); db.execute("UPDATE sigma_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id=?", (rid,)); db.commit(); invalidate_rules_cache()
    log_audit('rule_toggle', 'rule', rid)
    return jsonify({"ok":1})

@app.route('/api/rules/bulk_update', methods=['PUT'])
@login_required
def api_rules_bulk():
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
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
            "alerts_7d": r['alerts_7d'], "alerts_30d": r['alerts_30d'], "alerts_total": r['alerts_total'],
            "last_triggered": r['last_triggered'], "exclusion_count": r['exclusion_count']
        })
    TUNING_CACHE = out
    TUNING_CACHE_TIME = time.time()
    return jsonify(TUNING_CACHE)

@app.route('/api/rules/<int:rid>/severity', methods=['PUT'])
@login_required
def api_rule_severity(rid):
    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
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

    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
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
    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
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
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
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

@app.route('/reports/download/<filename>')
@login_required
def download_report(filename):
    from flask import send_from_directory
    return send_from_directory('/opt/micro-dfir/reports', filename, as_attachment=True)

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
        subprocess.run(["/opt/micro-dfir/venv/bin/python3", "/opt/micro-dfir/src/generate_report.py", report_type], check=True)
        log_audit('report_generate', 'report', report_type)
        flash("Report successfully generated!", "success")
    except Exception as e:
        flash(f"Failed to generate report: {str(e)}", "danger")
    return redirect(url_for('dash', tab='reports'))


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

@app.route('/api/ueba/detections')
@login_required
def api_ueba_detections():
    db = get_db()
    limit = request.args.get('limit', 100, type=int)
    rows = db.execute(
        "SELECT timestamp, hostname, entity_type, severity, message FROM events WHERE app_name = 'duckdb_ueba' ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    detections = [dict(r) for r in rows]
    total = db.execute("SELECT COUNT(*) FROM events WHERE app_name = 'duckdb_ueba'").fetchone()[0]
    today = db.execute("SELECT COUNT(*) FROM events WHERE app_name = 'duckdb_ueba' AND date(timestamp) = date('now')").fetchone()[0]
    entities_flagged = db.execute("SELECT COUNT(DISTINCT hostname || '|' || COALESCE(entity_type, '')) FROM events WHERE app_name = 'duckdb_ueba'").fetchone()[0]
    latest = detections[0]['timestamp'] if detections else None
    return jsonify({
        'detections': detections,
        'total': total,
        'today': today,
        'entities_flagged': entities_flagged,
        'latest': latest
    })

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

    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
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
    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403
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

UEBA_CONFIG_DEFAULTS = {
    'ueba_lookback_days': '30', 'ueba_stddev_multiplier': '3', 'ueba_min_baseline': '50',
    'ueba_min_days_observed': '4', 'ueba_new_ip_enabled': '1',
}

@app.route('/api/ueba/config', methods=['GET', 'POST'])
@login_required
def api_ueba_config():
    db = get_db()

    if request.method == 'GET':
        rows = db.execute(
            "SELECT key, value FROM settings WHERE key IN "
            "('ueba_lookback_days', 'ueba_stddev_multiplier', 'ueba_min_baseline', 'ueba_min_days_observed', 'ueba_new_ip_enabled')"
        ).fetchall()
        cfg = {**UEBA_CONFIG_DEFAULTS, **{r['key']: r['value'] for r in rows}}
        return jsonify({
            'lookback_days': int(cfg['ueba_lookback_days']),
            'stddev_multiplier': float(cfg['ueba_stddev_multiplier']),
            'min_baseline': float(cfg['ueba_min_baseline']),
            'min_days_observed': int(cfg['ueba_min_days_observed']),
            'new_ip_enabled': str(cfg['ueba_new_ip_enabled']) not in ('0', 'false', 'False'),
        })

    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403

    data = request.json or {}
    try:
        lookback_days = int(data.get('lookback_days'))
        stddev_multiplier = float(data.get('stddev_multiplier'))
        min_baseline = float(data.get('min_baseline'))
        min_days_observed = int(data.get('min_days_observed'))
        new_ip_enabled = bool(data.get('new_ip_enabled'))
        if not (1 <= lookback_days <= 365): raise ValueError('lookback_days must be 1-365')
        if not (0.5 <= stddev_multiplier <= 10): raise ValueError('stddev_multiplier must be 0.5-10')
        if not (0 <= min_baseline <= 1000000): raise ValueError('min_baseline must be 0-1000000')
        if not (1 <= min_days_observed <= 52): raise ValueError('min_days_observed must be 1-52')
    except (TypeError, ValueError) as e:
        return jsonify({'error': str(e) or 'Invalid config values'}), 400

    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_lookback_days', ?)", (str(lookback_days),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_stddev_multiplier', ?)", (str(stddev_multiplier),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_min_baseline', ?)", (str(min_baseline),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_min_days_observed', ?)", (str(min_days_observed),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_new_ip_enabled', ?)", ('1' if new_ip_enabled else '0',))
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

def _run_sigmahq_import():
    import urllib.request, zipfile, tempfile, shutil, socket, sqlite3
    import yaml as _yaml
    t = tempfile.mkdtemp()
    stats = {'inserted': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
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
                        "SELECT id, rule_yaml FROM sigma_rules WHERE sigma_uuid = ?", (uuid_,)
                    ).fetchone() if uuid_ else None
                    if existing:
                        if existing['rule_yaml'] != ry:
                            conn.execute(
                                "UPDATE sigma_rules SET title = ?, rule_yaml = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                                (title, ry, existing['id'])
                            )
                            stats['updated'] += 1
                    else:
                        conn.execute(
                            "INSERT INTO sigma_rules (title, rule_yaml, enabled, source, sigma_uuid, created_at) VALUES (?, ?, 0, 'sigma', ?, CURRENT_TIMESTAMP)",
                            (title, ry, uuid_)
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
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    import sqlite3
    from flask import request, render_template, flash

    conn = sqlite3.connect("/opt/micro-dfir/siem.db", timeout=30)
    cursor = conn.cursor()

    if request.method == "POST":
        new_secret = request.form.get("soc_secret")
        if new_secret:
            cursor.execute("UPDATE settings SET value = ? WHERE key = 'soc_secret'", (new_secret,))
            conn.commit()
            flash("Settings updated successfully!", "success")

    # Fetch all settings to populate the Network Configuration card
    cursor.execute("SELECT key, value FROM settings")
    all_settings = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()

    return render_template("settings.html", all_settings=all_settings, current_user=current_user)

@app.route('/api/settings/token', methods=['POST'])
@login_required
def api_settings_token():
    from flask import request, jsonify
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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
    if current_user.role != 'admin':
        return "Admin required", 403
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(DB_PATH, mimetype='application/octet-stream', as_attachment=True, download_name=f'microdfir_backup_{stamp}.db')

@app.route('/api/settings/purge', methods=['POST'])
@login_required
def api_settings_purge():
    from flask import request, jsonify
    import datetime
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403

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

    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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

@app.route('/api/settings/vacuum', methods=['POST'])
@login_required
def api_settings_vacuum():
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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

    if current_user.role != "admin": return redirect(url_for("dash"))
    if not validate_csrf(): return redirect(url_for("settings"))

    ui_ip = request.form.get("ui_bind_ip", "0.0.0.0")
    ui_port = request.form.get("ui_port", "5001")
    ingest_ip = request.form.get("ingest_bind_ip", "0.0.0.0")
    ingest_port = request.form.get("ingest_port", "5000")

    conn = sqlite3.connect("/opt/micro-dfir/siem.db", timeout=30)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ui_bind_ip', ?)", (ui_ip,))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ui_port', ?)", (ui_port,))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ingest_bind_ip', ?)", (ingest_ip,))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ingest_port', ?)", (ingest_port,))
    conn.commit()
    conn.close()
    log_audit('network_config_change', 'settings', None, f'ui={ui_ip}:{ui_port}, ingest={ingest_ip}:{ingest_port}')

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

    channels = ','.join(k for k, v in get_agent_channels().items() if v) or 'Security,System,Application,PowerShell'

    # Grab the active Ingestion IP/Port to pass to the agent
    cursor = db.execute("SELECT key, value FROM settings")
    s = {r[0]: r[1] for r in cursor.fetchall()}
    ing_ip = s.get("ingest_bind_ip", "0.0.0.0")
    ing_port = _resolve_ingest_port(s.get("ui_port", "5001"))

    # If set to 0.0.0.0, fallback to the IP the agent connected to
    if ing_ip == "0.0.0.0":
        ing_ip = request.host.split(":")[0]

    dynamic_ingest_url = f"https://{ing_ip}:{ing_port}/api/ingest"

    return jsonify({'channels': channels, 'ingest_url': dynamic_ingest_url})

# Log Search spans three tables that were previously siloed from each other: raw
# ingested events (live_logs), Sigma/custom detection-rule hits (alerts), and UEBA
# behavioral anomalies (events, app_name='duckdb_ueba') — an analyst investigating an
# incident needs all three in one searchable timeline, not three separate pages.
# Every branch is normalized to the same column shape so the existing filter/search
# logic (built for live_logs alone) works unchanged against the union.
UNIFIED_LOGS_SQL = """(
SELECT timestamp, severity, host, app, event_id, username, source_ip, destination_ip, message, 'log' as log_type,
       NULL as rule_id, NULL as rule_source, NULL as log_event_id, NULL as log_app, NULL as raw_json
FROM live_logs
UNION ALL
SELECT a.timestamp, a.severity,
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
       NULL as raw_json
FROM alerts a
LEFT JOIN sigma_rules s ON a.rule_id = s.id
UNION ALL
SELECT timestamp, severity, hostname as host, 'UEBA Anomaly' as app, '-' as event_id, '-' as username,
       NULL as source_ip, NULL as destination_ip, message, 'anomaly' as log_type,
       NULL as rule_id, 'ueba' as rule_source, NULL as log_event_id, NULL as log_app, raw_json
FROM events
WHERE app_name = 'duckdb_ueba'
) AS unified_logs"""

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

def _build_log_filters(args):
    import datetime
    q = args.get('q', '').lower()
    time_range = args.get('range', '24h')
    app_filter = args.get('app', '')
    severity_filter = args.get('severity', '')
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

    if severity_filter:
        # Sigma/UEBA severities are Title-case (Critical/High/Medium), live_logs and the
        # legacy inline-heuristic alerts are upper-case (INFO/CRITICAL/HIGH) — normalize
        # both sides so one filter list matches every source's casing.
        sevs = [s.strip().upper() for s in severity_filter.split(',') if s.strip()]
        if sevs:
            conditions.append(f"UPPER(severity) IN ({','.join(['?']*len(sevs))})")
            params.extend(sevs)

    allowed_columns = ['username', 'host', 'event_id', 'source_ip', 'destination_ip', 'message', 'log_type']
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
        conditions.append("(LOWER(host) LIKE ? OR LOWER(app) LIKE ? OR LOWER(event_id) LIKE ? OR LOWER(username) LIKE ? OR LOWER(message) LIKE ?)")
        params.extend([f'%{q}%'] * 5)

    where_clause = (" WHERE " + " and ".join(conditions)) if conditions else ""
    return where_clause, params

@app.route('/api/logs/search', methods=['GET'])
@login_required
def api_logs_search():
    from flask import request, jsonify
    try:
        db = get_db()
        where_clause, params = _build_log_filters(request.args)

        total_count = db.execute(f"SELECT COUNT(*) FROM {UNIFIED_LOGS_SQL}{where_clause}", params).fetchone()[0]
        rows = db.execute(f"SELECT * FROM {UNIFIED_LOGS_SQL}{where_clause} ORDER BY timestamp DESC LIMIT 300", params).fetchall()

        logs = [{
            'time': r['timestamp'],
            'severity': r['severity'],
            'host': r['host'],
            'app': r['app'],
            'event_id': r['event_id'],
            'username': r['username'],
            'source_ip': r['source_ip'] if r['source_ip'] is not None else '-',
            'destination_ip': r['destination_ip'] if r['destination_ip'] is not None else '-',
            'message': r['message'],
            'type': r['log_type'],
            'rule_id': r['rule_id'],
            'rule_source': r['rule_source'],
            'log_event_id': r['log_event_id'],
            'log_app': r['log_app'],
            'raw_json': r['raw_json']
        } for r in rows]

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

        # Increased export limit (10,000 records) for deep incident analysis.
        query = f"SELECT * FROM {UNIFIED_LOGS_SQL}{where_clause} ORDER BY timestamp DESC LIMIT 10000"
        cursor = db.execute(query, params)
        rows = cursor.fetchall()

        column_names = [description[0] for description in cursor.description] if cursor.description else [
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

        query = f"SELECT {time_format} as t_bucket, COUNT(*) as count FROM {UNIFIED_LOGS_SQL}{where_clause} GROUP BY t_bucket ORDER BY t_bucket ASC"
        rows = db.execute(query, params).fetchall()

        timeline = [{'time': r['t_bucket'], 'count': r['count']} for r in rows]
        return jsonify({'timeline': timeline})
    except Exception as e:
        return jsonify({'timeline': [], 'error': str(e)})

# Global storage for agent channel template
_ACTIVE_CHANNELS = {
    'Security': True,
    'System': True,
    'Application': True,
    'PowerShell': False,
    'Sysmon': False,
    'WindowsDefender': False
}

# --- PERSISTENT CHANNELS CONFIG ---
import json, os
AGENT_CONFIG_PATH = '/opt/micro-dfir/agent_config.json'

def get_agent_channels():
    defaults = {
        'Security': True,
        'System': True,
        'Application': True,
        'PowerShell': False,
        'Sysmon': False,
        'WindowsDefender': False
    }
    if os.path.exists(AGENT_CONFIG_PATH):
        try:
            with open(AGENT_CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return defaults
    return defaults

def save_agent_channels(data):
    with open(AGENT_CONFIG_PATH, 'w') as f:
        json.dump(data, f)

@app.route('/api/agent/channels', methods=['GET', 'POST'])
@login_required
def api_agent_channels():
    from flask import request, jsonify
    channels = get_agent_channels()
    if request.method == 'POST':
        data = request.json or {}
        for k in channels.keys():
            if k in data:
                channels[k] = bool(data[k])
        save_agent_channels(channels)
        return jsonify({'status': 'success', 'channels': channels})
    return jsonify(channels)




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
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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
    # Ensure users table has a role column
    try:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'Analyst'")
        db.commit()
    except Exception:
        pass # Column already exists

    if request.method == 'POST':
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin required'}), 403
        data = request.json
        action = data.get('action')
        
        if action == 'create':
            username = data.get('username')
            password = generate_password_hash(data.get('password'))
            role = data.get('role', 'Analyst')
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
            target_user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            log_audit('user_delete', 'user', target_user['username'] if target_user else user_id)
            return jsonify({'status': 'success'})

    # GET request
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify({'users': [dict(u) for u in users]})


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

def _get_live_yara_strings(limit=500):
    # Same "recompute fresh every use" philosophy as the live IOC hash helpers above —
    # the imported rule files rarely change and the walk is cheap, so there's no reason
    # to cache a stale list. Sourced from the same rules/yara_imported directory the
    # File Scan mode already compiles against, so this hunts with the rules actually
    # loaded in the app, not a separate/parallel rule set.
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
                if len(value) < 6:
                    continue
                key = (current_rule, value)
                if key in seen:
                    continue
                seen.add(key)
                results.append({'rule': current_rule, 'file': rel_path, 'string': value})
                if len(results) >= limit:
                    return results
    return results

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
                "recent_polls": []
            })

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

@app.route('/api/agent/commands', methods=['GET', 'POST'])
@login_required
def api_agent_commands():
    db = get_db()

    if request.method == 'GET':
        hostname = request.args.get('hostname', '')
        label_filter = request.args.get('label', '')
        limit = request.args.get('limit', 30, type=int)
        conditions, params = [], []
        if hostname:
            conditions.append("hostname = ?")
            params.append(hostname)
        if label_filter:
            conditions.append("label = ?")
            params.append(label_filter)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = db.execute(
            f"SELECT id, hostname, label, status, queued_by, queued_at, completed_at, exit_code, stdout, stderr FROM agent_commands {where} ORDER BY id DESC LIMIT ?",
            params + [limit]
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    d = request.json or {}
    hostname = (d.get('hostname') or '').strip()
    label = d.get('label')
    if not hostname or not label:
        return jsonify({'error': 'hostname and label are required'}), 400

    # Response actions are queued from the UI (not by the agent), so there's no
    # X-Agent-OS header on this request — the target host's own last-reported OS
    # decides which script flavor (PowerShell vs bash) gets built.
    host_templates = agent_scripts.TEMPLATES_BY_OS[_get_host_os(db, hostname)]

    if label == 'custom':
        script = d.get('script', '')
        if not script.strip():
            return jsonify({'error': 'script is required for a custom command'}), 400
    elif label in host_templates:
        builder, required = host_templates[label]
        params = d.get('params', {}) or {}
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
        if label == 'isolate_host' and not params.get('soc_ip'):
            s = {r[0]: r[1] for r in db.execute("SELECT key, value FROM settings").fetchall()}
            soc_ip = s.get('ingest_bind_ip', '0.0.0.0')
            if soc_ip == '0.0.0.0':
                soc_ip = request.host.split(':')[0]
            params['soc_ip'] = soc_ip
        missing = [p for p in required if not params.get(p)]
        if missing:
            return jsonify({'error': f"Missing required parameter(s): {', '.join(missing)}"}), 400
        try:
            script = builder(params)
        except Exception as e:
            return jsonify({'error': f'Failed to build script: {e}'}), 400
    elif label == 'upgrade':
        # No script to build here — agent_config() recognizes this label specially and
        # embeds the current agent source directly in the poll response, mirroring how
        # 'uninstall' is handled.
        script = ''
    else:
        return jsonify({'error': f'Unknown command label: {label}'}), 400

    cur = db.execute(
        "INSERT INTO agent_commands (hostname, label, script, queued_by) VALUES (?, ?, ?, ?)",
        (hostname, label, script, current_user.username)
    )
    db.commit()
    return jsonify({'status': 'success', 'id': cur.lastrowid})

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
    cmd = db.execute("SELECT hostname FROM agent_commands WHERE id = ?", (cmd_id,)).fetchone()
    if not cmd:
        return jsonify({'error': 'Unknown command id'}), 404
    if not _validate_agent_auth(db, request.headers.get('X-Agent-Token'), cmd['hostname']):
        return jsonify({'error': 'Unauthorized'}), 401

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = 'done' if d.get('exit_code', 1) == 0 else 'failed'
    db.execute(
        "UPDATE agent_commands SET status = ?, completed_at = ?, exit_code = ?, stdout = ?, stderr = ? WHERE id = ?",
        (status, now, d.get('exit_code'), str(d.get('stdout', ''))[:20000], str(d.get('stderr', ''))[:5000], cmd_id)
    )
    db.commit()
    return jsonify({'status': 'success'})

@app.route('/api/agent/<hostname>', methods=['DELETE'])
@login_required
def delete_agent(hostname):
    from flask import jsonify
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
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
migrate_sigma_rules_columns()
migrate_rule_tuning()
migrate_compliance_tags()
migrate_ueba_entities()
migrate_ueba_math_v2()
migrate_live_logs_ip_columns()
migrate_agent_versions()
migrate_agent_tokens()
migrate_audit_log()

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
