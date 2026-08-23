import json, os, sqlite3, subprocess

# Standalone counterpart to app.py's get_report_schedule_config()/
# apply_report_schedule_to_crontab() -- run once at deploy time (install.sh for a
# fresh install, update.sh for an existing one moving off the old hardcoded cron line)
# to sync root's crontab to whatever schedule is currently saved, without needing a
# full Flask app import. Duplicated rather than imported, same reasoning as
# generate_report.py's own REPORT_BRANDING_DEFAULTS -- this script has no Flask app
# context and app.py isn't meant to be imported standalone.
BASE_DIR = "/opt/micro-dfir"
DB_PATH = os.path.join(BASE_DIR, "siem.db")

REPORT_TYPES = ('security', 'compliance', 'audit')
REPORT_SCHEDULE_FREQUENCIES = ('off', 'weekly', 'monthly')
REPORT_SCHEDULE_DEFAULTS = {'security': 'monthly', 'compliance': 'off', 'audit': 'off'}
REPORT_SCHEDULE_CRON = {'weekly': '0 6 * * 1', 'monthly': '0 1 1 * *'}

def get_report_schedule_config():
    cfg = dict(REPORT_SCHEDULE_DEFAULTS)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        row = conn.execute("SELECT value FROM settings WHERE key = 'report_schedule_config'").fetchone()
        conn.close()
        if row and row[0]:
            saved = json.loads(row[0])
            cfg.update({k: v for k, v in saved.items() if k in REPORT_TYPES and v in REPORT_SCHEDULE_FREQUENCIES})
    except Exception:
        pass
    return cfg

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
        cmd = (f"{BASE_DIR}/venv/bin/python3 {BASE_DIR}/src/generate_report.py "
               f"{report_type} --source=scheduled >> /var/log/microdfir-report.log 2>&1")
        new_lines.append(f"{REPORT_SCHEDULE_CRON[freq]} {cmd}  # microdfir-report:{report_type}")
    final_crontab = '\n'.join(kept_lines + new_lines)
    if final_crontab and not final_crontab.endswith('\n'):
        final_crontab += '\n'
    proc = subprocess.run(['crontab', '-'], input=final_crontab, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, proc.stderr
    return True, None

if __name__ == "__main__":
    ok, err = apply_report_schedule_to_crontab(get_report_schedule_config())
    if not ok:
        print(f"[!] Failed to sync report schedule to crontab: {err}")
