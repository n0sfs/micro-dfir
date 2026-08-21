import os, json, time, sqlite3, requests
from dataclasses import dataclass, field as dc_field
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem

DB_PATH = "/opt/micro-dfir/siem.db"
STATE_FILE = os.path.join(os.path.dirname(DB_PATH), "sigma_state.json")

# live_logs/recent_events is a flat SIEM-style table (timestamp, host, app, severity,
# event_id, username, message) with no per-field structured data — there's no CommandLine,
# Image, TargetFilename, etc. column to map Sigma's field names onto. Rather than silently
# failing to match anything (the previous behavior), every Sigma field reference is mapped
# onto the free-text `message` column, turning field-scoped conditions into substring
# search across the raw event text. This trades field-level precision for actually working:
# a rule like `CommandLine|contains: mimikatz` becomes `message LIKE '%mimikatz%'`, which
# will still catch it if that text appears anywhere in the logged event, at the cost of
# being less precise than genuine structured-field matching.
@dataclass
class MapAllFieldsToMessage(FieldMappingTransformation):
    mapping: dict = dc_field(default_factory=dict)
    def get_mapping(self, field_name):
        return "message"

def _make_backend():
    pipeline = ProcessingPipeline(items=[ProcessingItem(transformation=MapAllFieldsToMessage())])
    backend = sqliteBackend(processing_pipeline=pipeline)
    backend.table = "recent_events"  # the backend's default table is a literal "<TABLE_NAME>" placeholder
    return backend

def run_detection_cycle():
    if not os.path.exists(DB_PATH): return
    conn = sqlite3.connect(DB_PATH, timeout=30); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
    last_id = json.load(open(STATE_FILE)).get("last_id", 0) if os.path.exists(STATE_FILE) else 0

    try: current_max = cursor.execute("SELECT MAX(id) as m FROM live_logs").fetchone()['m'] or 0
    except Exception as e:
        print(f"[-] Could not read live_logs: {e}")
        return
    if current_max <= last_id: return

    cursor.execute(f"CREATE TEMP VIEW recent_events AS SELECT * FROM live_logs WHERE id > {last_id} AND id <= {current_max}")
    rules = cursor.execute("SELECT id, title, rule_yaml FROM sigma_rules WHERE enabled = 1").fetchall()
    backend = _make_backend()

    for r in rules:
        try:
            for q in backend.convert(SigmaCollection.from_yaml(r['rule_yaml'])):
                for m in cursor.execute(q).fetchall():
                    cursor.execute("INSERT INTO alerts (rule_id, event_id, severity) VALUES (?, ?, ?)", (r['id'], m['id'], 'High'))
                    try:
                        requests.post("http://127.0.0.1:8000/webhook/alert", json={"rule_title": r['title'], "severity": "High", "hostname": m['host'], "agent_id": m['host'], "raw_log": m['message']}, headers={"Authorization": "Bearer SUPER_SECRET_SOAR_KEY_123"}, timeout=2)
                    except Exception as e:
                        print(f"[-] SOAR webhook failed for rule '{r['title']}': {e}")
        except Exception as e:
            print(f"[-] Rule '{r['title']}' failed to convert/execute: {e}")
    conn.commit(); conn.close()
    json.dump({"last_id": current_max}, open(STATE_FILE, 'w'))

if __name__ == "__main__":
    while True: run_detection_cycle(); time.sleep(30)
