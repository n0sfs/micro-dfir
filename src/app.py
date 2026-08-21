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

import os, json, sqlite3, tempfile, yaml, secrets, subprocess
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask import Flask, render_template, request, jsonify, g, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ti_engine import lookup_ioc
from yara_scanner import scan_file

app = Flask(__name__, template_folder='../templates')
app.secret_key = '0a3e3de8e8ca7ef43a3bb4645178baa03fa4d3612046968dfeeb86b13f19dd09'
DB_PATH = "/opt/micro-dfir/siem.db"
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['WEBHOOK_SECRET'] = "YOUR_SECRET_MICRO_SOC_KEY"

login_manager = LoginManager()
login_manager.init_app(app); login_manager.login_view = 'login'

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
    ingest_port = s.get("ingest_port", "5000")
    
    stmts = []
    fmap = {"app_name": ".appname", "hostname": ".hostname", "severity": ".severity", "message": "string!(.message)"}
    for r in rules:
        vf = fmap.get(r['field'], ".message")
        cond = f'{vf} == "{r["value"]}"' if r['operator'] == "equals" else f'includes({vf}, "{r["value"]}")'
        stmts.append(f"  # {r['description']}\n  if {cond} {{ abort }}")

    toml = f"""[sources.syslog_in]
type = "syslog"
mode = "udp"
address = "{ingest_ip}:514"

[transforms.shape_logs]
type = "remap"
inputs = ["syslog_in"]
source = '''\n{chr(10).join(stmts)}\n'''

[sinks.microsoc_out]
type = "http"
inputs = ["shape_logs"]
uri = f"http://127.0.0.1:{ingest_port}/api/ingest"
encoding.codec = "json"
"""
    with open("/etc/vector/vector.toml", "w") as f: f.write(toml)
    subprocess.run(["systemctl", "reload", "vector"], check=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (request.form['username'],)).fetchone()
        if user and check_password_hash(user['password_hash'], request.form['password']):
            login_user(User(user['id'], user['username'], user['role']))
            return redirect(url_for('dash'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

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
        if not data or 'logs' not in data:
            return jsonify({'status': 'error', 'message': 'Missing logs payload'}), 400

        count = 0
        for log in data['logs']:
            ts = log.get('time', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            hst = log.get('host', 'UNKNOWN')
            app_n = log.get('app', 'Windows')
            sev = log.get('severity', 'INFO')
            eid = log.get('event_id', '-')
            usr = log.get('username', '-')
            msg = log.get('message', '')
            db.execute("INSERT INTO live_logs (timestamp, host, app, severity, event_id, username, message) VALUES (?, ?, ?, ?, ?, ?, ?)", (ts, hst, app_n, sev, eid, usr, msg))
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
def dash(): return render_template('dashboard.html', current_user=current_user)

@app.route('/rules')
@login_required
def rules(): return render_template('rules.html', current_user=current_user)

@app.route('/pipeline')
@login_required
def pipeline(): return render_template('pipeline.html', current_user=current_user, channels=get_agent_channels())

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
@app.route('/hunt', methods=['GET', 'POST'])
@login_required
def hunt():
    import os
    from flask import request, render_template, flash
    try:
        import yara
    except ImportError:
        flash("yara-python is missing. Run: pip install yara-python", "danger")
        return render_template('hunt.html', matches=[], yara_files=[], current_user=current_user)

    matches = []
    yara_dir = '/opt/micro-dfir/rules/yara_imported'

    # Fetch loaded YARA files for the UI checklist first — this is also the
    # allowlist for which rule paths a scan request may reference.
    yara_files = []
    if os.path.exists(yara_dir):
        for root, dirs, files in os.walk(yara_dir):
            for file_name in files:
                if file_name.endswith(('.yar', '.yara')):
                    yara_files.append(os.path.relpath(os.path.join(root, file_name), yara_dir))
    yara_files.sort()
    yara_files_set = set(yara_files)

    if request.method == 'POST':
        if 'scan_file' not in request.files:
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

    return render_template('hunt.html', matches=matches, yara_files=yara_files, current_user=current_user)

@app.route('/api/hunt/search')
@login_required
def api_hunt():
    q = f"%{request.args.get('q', '')}%"
    return jsonify([dict(r) for r in get_db().execute("SELECT * FROM events WHERE message LIKE ? OR app_name LIKE ? OR source_ip LIKE ? ORDER BY timestamp DESC LIMIT 100", (q,q,q)).fetchall()])

@app.route('/api/ti/lookup', methods=['POST'])
@login_required
def api_ti(): return jsonify(lookup_ioc(request.get_json().get('ioc')))

@app.route('/api/droprules', methods=['GET', 'POST'])
@login_required
def api_drop_rules():
    db = get_db()
    if request.method == 'GET': return jsonify([dict(r) for r in db.execute("SELECT * FROM drop_rules ORDER BY id DESC").fetchall()])
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    d = request.get_json()
    db.execute("INSERT INTO drop_rules (field, operator, value, description, enabled) VALUES (?, ?, ?, ?, 1)", (d.get('field'), d.get('operator'), d.get('value'), d.get('description')))
    db.commit(); generate_vector_config(); return jsonify({"status": "success"}), 201

@app.route('/api/droprules/<int:rid>/toggle', methods=['PUT'])
@login_required
def tog_drop(rid): 
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    get_db().execute("UPDATE drop_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id=?", (rid,)); get_db().commit(); generate_vector_config(); return jsonify({"ok":1})

@app.route('/api/droprules/<int:rid>', methods=['DELETE'])
@login_required
def del_drop(rid):
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    get_db().execute("DELETE FROM drop_rules WHERE id=?", (rid,)); get_db().commit(); generate_vector_config(); return jsonify({"ok":1})


# ==========================================
# SIGMA RULES ENGINE
# ==========================================
RULES_CACHE = None
RULES_CACHE_TIME = 0
RULES_CACHE_TTL = 30  # seconds; bounds staleness against out-of-process writers like import_sigmahq.py

def invalidate_rules_cache():
    global RULES_CACHE
    RULES_CACHE = None

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
        for r in db.execute("SELECT id, title, rule_yaml, enabled FROM sigma_rules ORDER BY id DESC").fetchall():
            rid = r['id']
            ry = r['rule_yaml']
            try:
                c_match = re.search(r'category:\s*([^\n\r]+)', ry)
                cat = c_match.group(1).strip().strip("'\"") if c_match else 'unknown'

                p_match = re.search(r'product:\s*([^\n\r]+)', ry)
                platform = p_match.group(1).strip().strip("'\"").title() if p_match else 'Global'

                t_match = re.search(r'tags:\s*\n((\s+-\s*[^\n\r]+\n?)+)', ry)
                tags = [t.strip().strip('- ') for t in t_match.group(1).split('\n') if t.strip()] if t_match else []

                rule_type = "Generic"
                for t in tags:
                    if t.startswith('compliance'):
                        rule_type = "Compliance"
                        break
                    elif 'hunting' in t or 'threat_hunting' in t:
                        rule_type = "Threat Hunting"
                        break
            except Exception:
                rule_type, platform, cat, tags = "Generic", "Global", "unknown", []

            rules_out.append({
                "id": rid,
                "title": r['title'],
                "enabled": r['enabled'],
                "rule_type": rule_type,
                "platform": platform,
                "category": cat,
                "tags": tags
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
    db.execute("INSERT INTO sigma_rules (title, rule_yaml, enabled) VALUES (?, ?, 1)", (t, ry))
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})
@app.route('/api/rules/<int:rid>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_rule_detail(rid):
    db = get_db()

    if request.method == 'GET':
        r = db.execute("SELECT id, title, rule_yaml, enabled FROM sigma_rules WHERE id = ?", (rid,)).fetchone()
        if not r:
            return jsonify({"error": "Rule not found"}), 404
        return jsonify(dict(r))

    if current_user.role != 'admin':
        return jsonify({"error": "Admin required"}), 403

    if request.method == 'DELETE':
        db.execute("DELETE FROM sigma_rules WHERE id = ?", (rid,))
        db.commit()
        invalidate_rules_cache()
        return jsonify({"ok": 1})

    # PUT — update an existing rule's title/YAML
    import yaml
    ry = (request.get_json() or {}).get('rule_yaml', '')
    try:
        parsed = yaml.safe_load(ry)
        t = parsed.get('title', 'Untitled') if isinstance(parsed, dict) else 'Untitled'
    except yaml.YAMLError as e:
        return jsonify({"error": f"Invalid rule YAML: {e}"}), 400
    db.execute("UPDATE sigma_rules SET title = ?, rule_yaml = ? WHERE id = ?", (t, ry, rid))
    db.commit()
    invalidate_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/<int:rid>/toggle', methods=['PUT'])
@login_required
def api_r_tog(rid): 
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    db=get_db(); db.execute("UPDATE sigma_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id=?", (rid,)); db.commit(); invalidate_rules_cache(); return jsonify({"ok":1})

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
    return jsonify({"ok": 1})

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
def reports():
    import os
    report_dir = '/opt/micro-dfir/reports'
    os.makedirs(report_dir, exist_ok=True)
    
    pdfs = [f for f in os.listdir(report_dir) if f.endswith('.pdf')]
    pdfs.sort(reverse=True) # Newest first
    return render_template('reports.html', reports=pdfs, current_user=current_user)

@app.route('/reports/download/<filename>')
@login_required
def download_report(filename):
    from flask import send_from_directory
    return send_from_directory('/opt/micro-dfir/reports', filename, as_attachment=True)
    
@app.route('/reports/generate', methods=['POST'])
@login_required
def trigger_report():
    import subprocess
    try:
        subprocess.run(["/opt/micro-dfir/venv/bin/python3", "/opt/micro-dfir/src/generate_report.py"], check=True)
        flash("Report successfully generated!", "success")
    except Exception as e:
        flash(f"Failed to generate report: {str(e)}", "danger")
    return redirect(url_for('reports'))


# ==========================================
# UEBA — BEHAVIORAL ANOMALY DETECTIONS
# ==========================================
@app.route('/ueba')
@login_required
def ueba():
    return render_template('ueba.html', current_user=current_user)

@app.route('/api/ueba/detections')
@login_required
def api_ueba_detections():
    db = get_db()
    limit = request.args.get('limit', 100, type=int)
    rows = db.execute(
        "SELECT timestamp, hostname, severity, message FROM events WHERE app_name = 'duckdb_ueba' ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    detections = [dict(r) for r in rows]
    total = db.execute("SELECT COUNT(*) FROM events WHERE app_name = 'duckdb_ueba'").fetchone()[0]
    today = db.execute("SELECT COUNT(*) FROM events WHERE app_name = 'duckdb_ueba' AND date(timestamp) = date('now')").fetchone()[0]
    hosts_flagged = db.execute("SELECT COUNT(DISTINCT hostname) FROM events WHERE app_name = 'duckdb_ueba'").fetchone()[0]
    latest = detections[0]['timestamp'] if detections else None
    return jsonify({
        'detections': detections,
        'total': total,
        'today': today,
        'hosts_flagged': hosts_flagged,
        'latest': latest
    })

UEBA_CONFIG_DEFAULTS = {'ueba_lookback_days': '30', 'ueba_stddev_multiplier': '3', 'ueba_min_baseline': '50'}

@app.route('/api/ueba/config', methods=['GET', 'POST'])
@login_required
def api_ueba_config():
    db = get_db()

    if request.method == 'GET':
        rows = db.execute(
            "SELECT key, value FROM settings WHERE key IN ('ueba_lookback_days', 'ueba_stddev_multiplier', 'ueba_min_baseline')"
        ).fetchall()
        cfg = {**UEBA_CONFIG_DEFAULTS, **{r['key']: r['value'] for r in rows}}
        return jsonify({
            'lookback_days': int(cfg['ueba_lookback_days']),
            'stddev_multiplier': float(cfg['ueba_stddev_multiplier']),
            'min_baseline': float(cfg['ueba_min_baseline']),
        })

    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403

    data = request.json or {}
    try:
        lookback_days = int(data.get('lookback_days'))
        stddev_multiplier = float(data.get('stddev_multiplier'))
        min_baseline = float(data.get('min_baseline'))
        if not (1 <= lookback_days <= 365): raise ValueError('lookback_days must be 1-365')
        if not (0.5 <= stddev_multiplier <= 10): raise ValueError('stddev_multiplier must be 0.5-10')
        if not (0 <= min_baseline <= 1000000): raise ValueError('min_baseline must be 0-1000000')
    except (TypeError, ValueError) as e:
        return jsonify({'error': str(e) or 'Invalid config values'}), 400

    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_lookback_days', ?)", (str(lookback_days),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_stddev_multiplier', ?)", (str(stddev_multiplier),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ueba_min_baseline', ?)", (str(min_baseline),))
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
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('soc_secret', 'YOUR_SECRET_MICRO_SOC_KEY')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_lookback_days', '30')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_stddev_multiplier', '3')")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('ueba_min_baseline', '50')")
        conn.commit()
        conn.close()
    except Exception:
        pass

migrate_settings()

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

    return render_template("settings.html", all_settings=all_settings, soc_token=all_settings.get('soc_secret', ''), current_user=current_user)

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
    return jsonify({'status': 'success', 'deleted': deleted, 'cutoff': cutoff})

@app.route("/settings/network", methods=["POST"])
@login_required
def settings_network():
    import sqlite3, subprocess
    from flask import request, flash, redirect, url_for

    if current_user.role != "admin": return redirect(url_for("dash"))

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

@app.route('/api/agent/config', methods=['GET'])
def agent_config():
    from flask import request, jsonify
    import datetime
    db = get_db()

    expected_token = get_soc_secret(db)
    if expected_token and request.headers.get('X-Agent-Token') != expected_token:
        return jsonify({'error': 'Unauthorized'}), 401

    ip = request.remote_addr
    agent_host = request.headers.get('X-Agent-Hostname')
    ua = agent_host if agent_host else request.headers.get('User-Agent', 'Unknown')
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db.execute('CREATE TABLE IF NOT EXISTS agent_polls (id INTEGER PRIMARY KEY, timestamp TEXT, ip_address TEXT, user_agent TEXT)')
    db.execute('INSERT INTO agent_polls (timestamp, ip_address, user_agent) VALUES (?, ?, ?)', (now, ip, ua))
    db.execute('CREATE TABLE IF NOT EXISTS pending_commands (hostname TEXT PRIMARY KEY, command TEXT)')
    db.commit()
    cmd_row = db.execute('SELECT command FROM pending_commands WHERE hostname = ?', (ua,)).fetchone()
    if cmd_row and cmd_row['command'] == 'uninstall':
        db.execute('DELETE FROM pending_commands WHERE hostname = ?', (ua,))
        db.commit()
        return jsonify({'command': 'uninstall'})

    channels = ','.join(k for k, v in get_agent_channels().items() if v) or 'Security,System,Application,PowerShell'

    # Grab the active Ingestion IP/Port to pass to the agent
    cursor = db.execute("SELECT key, value FROM settings")
    s = {r[0]: r[1] for r in cursor.fetchall()}
    ing_ip = s.get("ingest_bind_ip", "0.0.0.0")
    ing_port = s.get("ingest_port", "5000")

    # If set to 0.0.0.0, fallback to the IP the agent connected to
    if ing_ip == "0.0.0.0":
        ing_ip = request.host.split(":")[0]

    dynamic_ingest_url = f"https://{ing_ip}:{ing_port}/api/ingest"

    return jsonify({'channels': channels, 'ingest_url': dynamic_ingest_url})

@app.route('/api/logs/search', methods=['GET'])
@login_required
def api_logs_search():
    from flask import request, jsonify
    import datetime
    try:
        q = request.args.get('q', '').lower()
        time_range = request.args.get('range', '24h')
        app_filter = request.args.get('app', '')
        severity_filter = request.args.get('severity', '')
        field_key = request.args.get('fieldKey', '')
        field_op = request.args.get('fieldOp', 'contains')
        field_val = request.args.get('fieldVal', '').lower()
        
        db = get_db()
        base_query = "FROM live_logs"
        params, conditions = [], []
        
        if time_range and time_range.lower() != 'all':
            now = datetime.datetime.now()
            if time_range == '5m': delta = datetime.timedelta(minutes=5)
            elif time_range == '15m': delta = datetime.timedelta(minutes=15)
            elif time_range == '1h': delta = datetime.timedelta(hours=1)
            elif time_range == '12h': delta = datetime.timedelta(hours=12)
            elif time_range == '7d': delta = datetime.timedelta(days=7)
            else: delta = datetime.timedelta(hours=24)
            conditions.append("timestamp >= ?")
            params.append((now - delta).strftime('%Y-%m-%d %H:%M:%S'))
            
        if app_filter:
            apps = [a.strip() for a in app_filter.split(',') if a.strip()]
            if apps:
                conditions.append(f"app IN ({','.join(['?']*len(apps))})")
                params.extend(apps)
        if severity_filter:
            sevs = [s.strip() for s in severity_filter.split(',') if s.strip()]
            if sevs:
                conditions.append(f"severity IN ({','.join(['?']*len(sevs))})")
                params.extend(sevs)
            
        allowed_columns = ['username', 'host', 'event_id', 'source_ip', 'destination_ip', 'email', 'message']
        if field_key and field_val:
            col = field_key if field_key in allowed_columns else 'message'
            if field_op == 'equals':
                conditions.append(f"LOWER({col}) = ?")
                params.append(field_val)
            elif field_op == 'not_equals':
                conditions.append(f"LOWER({col}) != ?")
                params.append(field_val)
            elif field_op == 'starts_with':
                conditions.append(f"LOWER({col}) LIKE ?")
                params.append(f'{field_val}%')
            elif field_op == 'ends_with':
                conditions.append(f"LOWER({col}) LIKE ?")
                params.append(f'%{field_val}')
            elif field_op == 'gt':
                conditions.append(f"{col} > ?")
                params.append(field_val)
            elif field_op == 'lt':
                conditions.append(f"{col} < ?")
                params.append(field_val)
            else:
                conditions.append(f"LOWER({col}) LIKE ?")
                params.append(f'%{field_val}%')
            
        if q:
            conditions.append("(LOWER(host) LIKE ? OR LOWER(app) LIKE ? OR LOWER(event_id) LIKE ? OR LOWER(username) LIKE ? OR LOWER(message) LIKE ?)")
            params.extend([f'%{q}%'] * 5)
            
        where_clause = ""
        if conditions:
            where_clause = " WHERE " + " and ".join(conditions)
            
        # Get true total count
        count_query = f"SELECT COUNT(*) {base_query}{where_clause}"
        total_count = db.execute(count_query, params).fetchone()[0]
        
        # Get limited rows for display
        data_query = f"SELECT * {base_query}{where_clause} ORDER BY timestamp DESC LIMIT 300"
        rows = db.execute(data_query, params).fetchall()
        
        logs = [{
            'time': r['timestamp'], 
            'severity': r['severity'], 
            'host': r['host'], 
            'app': r['app'], 
            'event_id': r['event_id'], 
            'username': r['username'], 
            'source_ip': r['source_ip'] if 'source_ip' in r.keys() else '-',
            'destination_ip': r['destination_ip'] if 'destination_ip' in r.keys() else '-',
            'message': r['message']
        } for r in rows]
        
        return jsonify({'logs': logs, 'count': len(logs), 'total_matches': total_count})
    except Exception as e:
        return jsonify({'error': str(e), 'logs': [], 'count': 0, 'total_matches': 0})

@app.route('/api/logs/export', methods=['GET'])
@login_required
def export_logs_csv():
    from flask import request, Response
    import datetime, csv, io
    try:
        q = request.args.get('q', '').lower()
        time_range = request.args.get('range', '24h')
        app_filter = request.args.get('app', '')
        severity_filter = request.args.get('severity', '')
        field_key = request.args.get('fieldKey', '')
        field_op = request.args.get('fieldOp', 'contains')
        field_val = request.args.get('fieldVal', '').lower()
        
        db = get_db()
        query = "SELECT * FROM live_logs"
        params, conditions = [], []
        
        if time_range and time_range.lower() != 'all':
            now = datetime.datetime.now()
            if time_range == '5m': delta = datetime.timedelta(minutes=5)
            elif time_range == '15m': delta = datetime.timedelta(minutes=15)
            elif time_range == '1h': delta = datetime.timedelta(hours=1)
            elif time_range == '12h': delta = datetime.timedelta(hours=12)
            elif time_range == '7d': delta = datetime.timedelta(days=7)
            else: delta = datetime.timedelta(hours=24)
            conditions.append("timestamp >= ?")
            params.append((now - delta).strftime('%Y-%m-%d %H:%M:%S'))
            
        if app_filter:
            apps = [a.strip() for a in app_filter.split(',') if a.strip()]
            if apps:
                conditions.append(f"app IN ({','.join(['?']*len(apps))})")
                params.extend(apps)
        if severity_filter:
            sevs = [s.strip() for s in severity_filter.split(',') if s.strip()]
            if sevs:
                conditions.append(f"severity IN ({','.join(['?']*len(sevs))})")
                params.extend(sevs)
            
        allowed_columns = ['username', 'host', 'event_id', 'source_ip', 'destination_ip', 'email', 'message']
        if field_key and field_val:
            col = field_key if field_key in allowed_columns else 'message'
            if field_op == 'equals':
                conditions.append(f"LOWER({col}) = ?")
                params.append(field_val)
            elif field_op == 'not_equals':
                conditions.append(f"LOWER({col}) != ?")
                params.append(field_val)
            elif field_op == 'starts_with':
                conditions.append(f"LOWER({col}) LIKE ?")
                params.append(f'{field_val}%')
            elif field_op == 'ends_with':
                conditions.append(f"LOWER({col}) LIKE ?")
                params.append(f'%{field_val}')
            elif field_op == 'gt':
                conditions.append(f"{col} > ?")
                params.append(field_val)
            elif field_op == 'lt':
                conditions.append(f"{col} < ?")
                params.append(field_val)
            else:
                conditions.append(f"LOWER({col}) LIKE ?")
                params.append(f'%{field_val}%')
            
        if q:
            conditions.append("(LOWER(host) LIKE ? OR LOWER(app) LIKE ? OR LOWER(event_id) LIKE ? OR LOWER(username) LIKE ? OR LOWER(message) LIKE ?)")
            params.extend([f'%{q}%'] * 5)
            
        if conditions:
            query += " WHERE " + " and ".join(conditions)
            
        # Increase export limit to 10,000 records for deep incident analysis
        query += " ORDER BY timestamp DESC LIMIT 10000"
        
        cursor = db.execute(query, params)
        rows = cursor.fetchall()
        
        # Dynamically extract all available column names from the sqlite cursor description
        column_names = [description[0] for description in cursor.description] if cursor.description else [
            'timestamp', 'severity', 'host', 'app', 'event_id', 'username', 'source_ip', 'destination_ip', 'message'
        ]
        
        si = io.StringIO()
        cw = csv.writer(si)
        
        # Write clean header row
        cw.writerow(column_names)
        
        # Write full untruncated rows
        for r in rows:
            row_data = []
            for col in column_names:
                val = r[col] if col in r.keys() else ''
                row_data.append(str(val) if val is not None else '')
            cw.writerow(row_data)
            
        output = si.getvalue()
        return Response(
            output,
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
        time_range = request.args.get('range', '24h')
        app_filter = request.args.get('app', '')
        severity_filter = request.args.get('severity', '')
        
        db = get_db()
        params, conditions = [], []
        
        if time_range and time_range.lower() != 'all':
            now = datetime.datetime.now()
            if time_range == '5m': delta = datetime.timedelta(minutes=5)
            elif time_range == '15m': delta = datetime.timedelta(minutes=15)
            elif time_range == '1h': delta = datetime.timedelta(hours=1)
            elif time_range == '12h': delta = datetime.timedelta(hours=12)
            elif time_range == '7d': delta = datetime.timedelta(days=7)
            else: delta = datetime.timedelta(hours=24)
            conditions.append("timestamp >= ?")
            params.append((now - delta).strftime('%Y-%m-%d %H:%M:%S'))
            
        if app_filter:
            apps = [a.strip() for a in app_filter.split(',') if a.strip()]
            if apps:
                conditions.append(f"app IN ({','.join(['?']*len(apps))})")
                params.extend(apps)
        if severity_filter:
            sevs = [s.strip() for s in severity_filter.split(',') if s.strip()]
            if sevs:
                conditions.append(f"severity IN ({','.join(['?']*len(sevs))})")
                params.extend(sevs)
            
        where_clause = ""
        if conditions:
            where_clause = " WHERE " + " and ".join(conditions)
            
        # Group by minute or hour depending on range
        if time_range in ['5m', '15m', '1h']:
            # Group by minute: YYYY-MM-DD HH:MM
            time_format = "strftime('%Y-%m-%d %H:%M', timestamp)"
        elif time_range in ['7d']:
            # Group by day: YYYY-MM-DD
            time_format = "strftime('%Y-%m-%d', timestamp)"
        else:
            # Default 24h/12h: Group by hour: YYYY-MM-DD HH:00
            time_format = "strftime('%Y-%m-%d %H:00', timestamp)"
            
        query = f"SELECT {time_format} as t_bucket, COUNT(*) as count FROM live_logs {where_clause} GROUP BY t_bucket ORDER BY t_bucket ASC"
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
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    if 'cert_file' not in request.files or 'key_file' not in request.files:
        return jsonify({'error': 'Both Certificate and Private Key files are required.'}), 400
    
    cert = request.files['cert_file']
    key = request.files['key_file']
    
    cert_dir = '/opt/micro-dfir/certs'
    os.makedirs(cert_dir, exist_ok=True)
    
    cert.save(os.path.join(cert_dir, 'cert.pem'))
    key.save(os.path.join(cert_dir, 'key.pem'))
    
    return jsonify({'status': 'success', 'message': 'Certificates updated successfully. Service restart required to apply.'})

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
                return jsonify({'status': 'success'})
            except Exception as e:
                return jsonify({'error': 'Username may already exist.'}), 400
                
        elif action == 'reset':
            user_id = data.get('id')
            new_password = generate_password_hash(data.get('password'))
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password, user_id))
            db.commit()
            return jsonify({'status': 'success'})
            
        elif action == 'delete':
            user_id = data.get('id')
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            return jsonify({'status': 'success'})

    # GET request
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify({'users': [dict(u) for u in users]})


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
    ingest_port = s.get("ingest_port", "5000")
    soc_token = get_soc_secret(db) or ''

    agents_dir = '/opt/micro-dfir/agents'
    memory_file = io.BytesIO()

    if os_type == 'windows':
        target_file = os.path.join(agents_dir, 'micro_agent_windows.py')
        if not os.path.exists(target_file):
            return "Windows agent not found on server.", 404

        with open(target_file, 'r', encoding='utf-8') as f:
            script_data = f.read()

        # Dynamically inject the IP, Ports, and agent auth token!
        script_data = script_data.replace('https://__HOST_URL__/api/agent/config', f'https://{server_ip}:{ui_port}/api/agent/config')
        script_data = script_data.replace('https://__HOST_URL__/api/ingest', f'https://{server_ip}:{ingest_port}/api/ingest')
        script_data = script_data.replace('__SOC_TOKEN__', soc_token)

        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('micro_agent_windows.py', script_data)

        memory_file.seek(0)
        return send_file(memory_file, download_name='MicroDFIR_Windows_Agent.zip', as_attachment=True)

    elif os_type == 'linux':
        target_file = os.path.join(agents_dir, 'micro_agent_linux.py')
        if not os.path.exists(target_file):
            return "Linux agent not found on server.", 404

        with open(target_file, 'r', encoding='utf-8') as f:
            script_data = f.read()

        script_data = script_data.replace('https://__HOST_URL__/api/agent/config', f'https://{server_ip}:{ui_port}/api/agent/config')
        script_data = script_data.replace('https://__HOST_URL__/api/ingest', f'https://{server_ip}:{ingest_port}/api/ingest')
        script_data = script_data.replace('__SOC_TOKEN__', soc_token)

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
    db = get_db()
    try:
        rows = db.execute('SELECT * FROM agent_polls WHERE id IN (SELECT MAX(id) FROM agent_polls GROUP BY ip_address) ORDER BY id DESC LIMIT 20').fetchall()
        mapped = []
        for r in rows:
            mapped.append({
                "hostname": r["user_agent"] if "user_agent" in r.keys() else "Windows-Endpoint",
                "endpoint_ip": r["ip_address"] if "ip_address" in r.keys() else "192.168.86.49",
                "client_info": "Active Agent",
                "status": "Online",
                "last_check_in": r["timestamp"] if "timestamp" in r.keys() else ""
            })
        return jsonify(mapped)
    except Exception as e:
        print("Checkins error:", e)
        return jsonify([])

@app.route('/api/agent/<hostname>', methods=['DELETE'])
@login_required
def delete_agent(hostname):
    from flask import jsonify
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    db = get_db()
    db.execute('DELETE FROM agent_polls WHERE user_agent = ?', (hostname,))
    db.execute('CREATE TABLE IF NOT EXISTS pending_commands (hostname TEXT PRIMARY KEY, command TEXT)')
    db.execute('INSERT OR REPLACE INTO pending_commands (hostname, command) VALUES (?, ?)', (hostname, 'uninstall'))
    db.commit()
    return jsonify({"status": "success"})
