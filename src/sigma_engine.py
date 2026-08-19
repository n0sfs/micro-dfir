import os, json, time, sqlite3, requests
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
DB_PATH = os.path.abspath("siem.db")
STATE_FILE = "sigma_state.json"

def run_detection_cycle():
    if not os.path.exists(DB_PATH): return
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
    last_id = json.load(open(STATE_FILE)).get("last_id", 0) if os.path.exists(STATE_FILE) else 0

    try: current_max = cursor.execute("SELECT MAX(id) as m FROM events").fetchone()['m'] or 0
    except: return
    if current_max <= last_id: return

    cursor.execute(f"CREATE TEMP VIEW recent_events AS SELECT * FROM events WHERE id > {last_id} AND id <= {current_max}")
    rules = cursor.execute("SELECT id, title, rule_yaml FROM sigma_rules WHERE enabled = 1").fetchall()
    backend = sqliteBackend()

    for r in rules:
        try:
            for q in backend.convert(SigmaCollection.from_yaml(r['rule_yaml'])):
                for m in cursor.execute(q.replace("FROM log", "FROM recent_events")).fetchall():
                    cursor.execute("INSERT INTO alerts (rule_id, event_id, severity) VALUES (?, ?, ?)", (r['id'], m['id'], 'High'))
                    try:
                        agent_id = json.loads(m['raw_json']).get('agent', {}).get('id', 'unknown')
                        requests.post("http://127.0.0.1:8000/webhook/alert", json={"rule_title": r['title'], "severity": "High", "hostname": m['hostname'], "agent_id": agent_id, "raw_log": m['raw_json']}, headers={"Authorization": "Bearer SUPER_SECRET_SOAR_KEY_123"}, timeout=2)
                    except: pass
        except: pass
    conn.commit(); conn.close()
    json.dump({"last_id": current_max}, open(STATE_FILE, 'w'))

if __name__ == "__main__":
    while True: run_detection_cycle(); time.sleep(30)
