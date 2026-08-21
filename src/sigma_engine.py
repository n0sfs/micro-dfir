import os, json, re, time, sqlite3, requests
from dataclasses import dataclass, field as dc_field
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem

DB_PATH = "/opt/micro-dfir/siem.db"
STATE_FILE = os.path.join(os.path.dirname(DB_PATH), "sigma_state.json")

# live_logs/recent_events is a flat SIEM-style table (timestamp, host, app, severity,
# event_id, username, source_ip, destination_ip, message) with no per-field structured data
# for most Sigma fields — there's no CommandLine, Image, TargetFilename, etc. column to map
# onto. Field names with a known, high-confidence correspondence to an actual column (host,
# event ID, username, source/destination IP, log channel) are mapped onto that column for a
# precise match; everything else falls back onto the free-text `message` column, turning
# field-scoped conditions into substring search across the raw event text. That fallback
# trades field-level precision for actually working: a rule like `CommandLine|contains:
# mimikatz` becomes `message LIKE '%mimikatz%'`, which will still catch it if that text
# appears anywhere in the logged event, at the cost of being less precise than genuine
# structured-field matching.
_FIELD_COLUMN_ALIASES = {
    'host': 'host', 'hostname': 'host', 'computername': 'host', 'computer': 'host', 'dvc': 'host',
    'channel': 'app', 'app': 'app', 'application': 'app', 'source': 'app',
    'eventid': 'event_id', 'event_id': 'event_id',
    'username': 'username', 'user': 'username', 'targetusername': 'username',
    'subjectusername': 'username', 'accountname': 'username', 'user_id': 'username',
    'sourceip': 'source_ip', 'source_ip': 'source_ip', 'src_ip': 'source_ip',
    'srcip': 'source_ip', 'clientip': 'source_ip', 'ipaddress': 'source_ip', 'src': 'source_ip',
    'destinationip': 'destination_ip', 'destination_ip': 'destination_ip', 'dst_ip': 'destination_ip',
    'dstip': 'destination_ip', 'dst': 'destination_ip',
    'message': 'message',
}

@dataclass
class MapFieldsToColumns(FieldMappingTransformation):
    mapping: dict = dc_field(default_factory=dict)
    def get_mapping(self, field_name):
        return _FIELD_COLUMN_ALIASES.get((field_name or '').lower(), 'message')

# Many older SigmaHQ rules predate the spec settling on strict ISO 8601 (yyyy-mm-dd) for
# date/modified fields and still use yyyy/mm/dd, which pysigma's SigmaRule validation
# rejects outright — the rule fails to even parse. ~30% of the imported rule set is affected.
_SLASH_DATE_RE = re.compile(r'^(date|modified):\s*(\d{4})/(\d{2})/(\d{2})', re.MULTILINE)

def _normalize_rule_dates(rule_yaml):
    return _SLASH_DATE_RE.sub(lambda m: f"{m.group(1)}: {m.group(2)}-{m.group(3)}-{m.group(4)}", rule_yaml)

_LEVEL_RE = re.compile(r'^level:\s*([^\n\r]+)', re.MULTILINE)

def _extract_level(rule_yaml):
    m = _LEVEL_RE.search(rule_yaml or '')
    return m.group(1).strip().strip('"\'').capitalize() if m else None

def _exclusion_matches(excl, row):
    # Exclusions are defined against the same field vocabulary as the guided rule
    # builder (Host/Channel/EventID/User/SourceIp/DestinationIp/Message), so they share
    # the same field->column mapping used to convert Sigma rules to SQL.
    col = _FIELD_COLUMN_ALIASES.get((excl['field'] or '').lower(), 'message')
    try:
        val = row[col]
    except (IndexError, KeyError):
        return False
    val = (str(val) if val is not None else '').lower()
    target = (excl['value'] or '').lower()
    op = excl['operator']
    if op == 'equals': return val == target
    if op == 'startswith': return val.startswith(target)
    if op == 'endswith': return val.endswith(target)
    return target in val  # contains (default)

def _make_backend():
    pipeline = ProcessingPipeline(items=[ProcessingItem(transformation=MapFieldsToColumns())])
    backend = sqliteBackend(processing_pipeline=pipeline)
    backend.table = "recent_events"  # the backend's default table is a literal "<TABLE_NAME>" placeholder
    return backend

def _get_soar_api_key(cursor):
    row = cursor.execute("SELECT value FROM settings WHERE key = 'soar_api_key'").fetchone()
    return row['value'] if row and row['value'] else None

def run_detection_cycle():
    if not os.path.exists(DB_PATH): return
    conn = sqlite3.connect(DB_PATH, timeout=30); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
    last_id = json.load(open(STATE_FILE)).get("last_id", 0) if os.path.exists(STATE_FILE) else 0
    soar_api_key = _get_soar_api_key(cursor)

    try: current_max = cursor.execute("SELECT MAX(id) as m FROM live_logs").fetchone()['m'] or 0
    except Exception as e:
        print(f"[-] Could not read live_logs: {e}")
        return
    if current_max <= last_id: return

    cursor.execute(f"CREATE TEMP VIEW recent_events AS SELECT * FROM live_logs WHERE id > {last_id} AND id <= {current_max}")
    rules = cursor.execute("SELECT id, title, rule_yaml, severity_override FROM sigma_rules WHERE enabled = 1").fetchall()
    backend = _make_backend()

    exclusions_by_rule = {}
    for e in cursor.execute("SELECT rule_id, field, operator, value FROM rule_exclusions WHERE enabled = 1").fetchall():
        exclusions_by_rule.setdefault(e['rule_id'], []).append(e)

    for r in rules:
        try:
            rule_exclusions = exclusions_by_rule.get(r['id'], [])
            severity = (r['severity_override'] or '').capitalize() or _extract_level(r['rule_yaml']) or 'High'
            for q in backend.convert(SigmaCollection.from_yaml(_normalize_rule_dates(r['rule_yaml']))):
                for m in cursor.execute(q).fetchall():
                    if any(_exclusion_matches(e, m) for e in rule_exclusions):
                        continue
                    cursor.execute("INSERT INTO alerts (rule_id, event_id, severity) VALUES (?, ?, ?)", (r['id'], m['id'], severity))
                    try:
                        if soar_api_key:
                            requests.post("http://127.0.0.1:8000/webhook/alert", json={"rule_title": r['title'], "severity": severity, "hostname": m['host'], "agent_id": m['host'], "raw_log": m['message']}, headers={"Authorization": f"Bearer {soar_api_key}"}, timeout=2)
                    except Exception as e:
                        print(f"[-] SOAR webhook failed for rule '{r['title']}': {e}")
        except Exception as e:
            print(f"[-] Rule '{r['title']}' failed to convert/execute: {e}")
    conn.commit(); conn.close()
    json.dump({"last_id": current_max}, open(STATE_FILE, 'w'))

if __name__ == "__main__":
    while True: run_detection_cycle(); time.sleep(30)
