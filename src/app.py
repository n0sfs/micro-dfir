import os, json, sqlite3, tempfile, yaml, secrets, subprocess
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask import Flask, render_template, request, jsonify, g, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ti_engine import lookup_ioc
from yara_scanner import scan_file

app = Flask(__name__, template_folder='../templates')
app.secret_key = secrets.token_hex(32)
DB_PATH = os.path.abspath("siem.db")
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
    if db is None: db = g._database = sqlite3.connect(DB_PATH); db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_conn(e):
    if hasattr(g, '_database'): g._database.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.cursor().executescript(open(os.path.join(os.path.dirname(__file__), "schema.sql")).read())
    conn.commit(); conn.close()

def generate_vector_config():
    rules = get_db().execute("SELECT * FROM drop_rules WHERE enabled = 1").fetchall()
    stmts = []
    fmap = {"app_name": ".appname", "hostname": ".hostname", "severity": ".severity", "message": "string!(.message)"}
    for r in rules:
        vf = fmap.get(r['field'], ".message")
        cond = f'{vf} == "{r["value"]}"' if r['operator'] == 'equals' else f'includes({vf}, "{r["value"]}")'
        stmts.append(f"  # {r['description']}\n  if {cond} {{ abort }}")
    
    toml = f"[sources.syslog_in]\ntype = \"syslog\"\nmode = \"udp\"\naddress = \"0.0.0.0:514\"\n[transforms.shape_logs]\ntype = \"remap\"\ninputs = [\"syslog_in\"]\nsource = '''\n{chr(10).join(stmts)}\n'''\n[sinks.microsoc_out]\ntype = \"http\"\ninputs = [\"shape_logs\"]\nuri = \"http://127.0.0.1:5001/api/ingest\"\nencoding.codec = \"json\"\nauth.strategy = \"bearer\"\nauth.token = \"{app.config['WEBHOOK_SECRET']}\""
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

@app.route('/')
@login_required
def dash(): return render_template('dashboard.html', current_user=current_user)

@app.route('/hunt')
@login_required
def hunt(): return render_template('hunt.html', current_user=current_user)

@app.route('/rules')
@login_required
def rules(): return render_template('rules.html', current_user=current_user)

@app.route('/pipeline')
@login_required
def pipeline(): return render_template('pipeline.html', current_user=current_user)

@app.route('/api/ingest', methods=['POST'])
def webhook():
    if request.headers.get('Authorization') != f"Bearer {app.config['WEBHOOK_SECRET']}": return jsonify({"error": "Auth"}), 401
    d = request.get_json()
    get_db().execute("INSERT INTO events (timestamp, source_ip, hostname, app_name, facility, severity, message, raw_json) VALUES (datetime('now'), ?, ?, ?, 'local0', ?, ?, ?)", (request.remote_addr, d.get('hostname'), d.get('app_name', 'webhook'), d.get('severity', 'info'), d.get('message', ''), json.dumps(d)))
    get_db().commit(); return jsonify({"status": "ok"}), 201

@app.route('/api/events')
@login_required
def api_ev(): return jsonify([dict(r) for r in get_db().execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (request.args.get('limit', 50, type=int),)).fetchall()])

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

@app.route('/api/rules', methods=['GET', 'POST'])
@login_required
def api_rules():
    db = get_db()
    if request.method == 'GET': return jsonify([dict(r) for r in db.execute("SELECT id, title, enabled FROM sigma_rules ORDER BY id DESC").fetchall()])
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    ry = request.get_json().get('rule_yaml', '')
    t = yaml.safe_load(ry).get('title', 'Untitled')
    db.execute("INSERT INTO sigma_rules (title, rule_yaml, enabled) VALUES (?, ?, 1)", (t, ry)); db.commit(); return jsonify({"status": "success"})

@app.route('/api/rules/<int:rid>/toggle', methods=['PUT'])
@login_required
def api_r_tog(rid): 
    if current_user.role != 'admin': return jsonify({"error": "Admin required"}), 403
    db=get_db(); db.execute("UPDATE sigma_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id=?", (rid,)); db.commit(); return jsonify({"ok":1})

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
# DYNAMIC SETTINGS & AGENT DEPLOYMENT ROUTES
# ==========================================
def migrate_settings():
    try:
        import sqlite3
        conn = sqlite3.connect('/opt/micro-dfir/siem.db')
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('soc_secret', 'YOUR_SECRET_MICRO_SOC_KEY')")
        conn.commit()
        conn.close()
    except Exception:
        pass

migrate_settings()

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    import sqlite3
    from flask import request, render_template, flash
    
    conn = sqlite3.connect('/opt/micro-dfir/siem.db')
    cursor = conn.cursor()
    
    if request.method == 'POST':
        new_secret = request.form.get('soc_secret')
        if new_secret:
            cursor.execute("UPDATE settings SET value = ? WHERE key = 'soc_secret'", (new_secret,))
            conn.commit()
            flash('Settings updated successfully!', 'success')
            
    cursor.execute("SELECT value FROM settings WHERE key = 'soc_secret'")
    result = cursor.fetchone()
    current_secret = result[0] if result else "YOUR_SECRET_MICRO_SOC_KEY"
    conn.close()
    
    return render_template('settings.html', soc_secret=current_secret)

@app.route('/download/agent/<os_type>')
def download_agent(os_type):
    import sqlite3
    from flask import Response, request
    
    conn = sqlite3.connect('/opt/micro-dfir/siem.db')
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'soc_secret'")
    result = cursor.fetchone()
    secret = result[0] if result else "YOUR_SECRET_MICRO_SOC_KEY"
    conn.close()
    
    host_ip = request.host.split(':')[0]
    
    try:
        with open('/opt/micro-dfir/agents/install_agent.py', 'r') as f:
            script_content = f.read()
    except FileNotFoundError:
        return "Agent script not found on server.", 404
        
    script_content = script_content.replace('YOUR_SECRET_MICRO_SOC_KEY', secret)
    script_content = script_content.replace('MICRO_SOC_IP_PLACEHOLDER', host_ip)
    
    return Response(
        script_content,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename=micro_agent_{os_type}.py"}
    )
    
@app.route('/settings/yara/sync', methods=['POST'])
def sync_yara():
    import urllib.request, zipfile, io, os
    from flask import request, flash, redirect, url_for
    
    repo_url = request.form.get('repo_url')
    dest_dir = '/opt/micro-dfir/rules/yara_imported'
    
    try:
        os.makedirs(dest_dir, exist_ok=True)
        req = urllib.request.Request(repo_url, headers={'User-Agent': 'MicroSOC-Admin/1.0'})
        with urllib.request.urlopen(req) as response:
            with zipfile.ZipFile(io.BytesIO(response.read())) as z:
                z.extractall(dest_dir)
                
        flash(f'YARA rules successfully downloaded and extracted to {dest_dir}', 'success')
    except Exception as e:
        flash(f'Failed to import rules: {str(e)}', 'danger')
        
    return redirect(url_for('settings'))
  
if __name__ == '__main__':
    if not os.path.exists(DB_PATH): init_db()
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)

