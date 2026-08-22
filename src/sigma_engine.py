import os, json, re, time, sqlite3, requests, datetime
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
    # IOC-match builder fields (see _substitute_ioc_placeholder) map onto the same
    # source_ip/destination_ip columns as their plain counterparts — the only
    # difference is the *value* side, a live list instead of a single typed-in value.
    'sourceipioc': 'source_ip', 'destinationipioc': 'destination_ip',
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

# The guided rule builder's "Source IP / Destination IP — matches live IOC list"
# fields emit this literal token as an unquoted YAML scalar (e.g. `SourceIp:
# __IOC_IP_LIST__`) rather than a typed-in value. Substituting it with a real
# flow-sequence YAML list *before* parsing — instead of baking a static list into the
# stored rule at save time — means the match set is always whatever's currently in
# stix_indicators, including anything ingested since the rule was created.
IOC_IP_PLACEHOLDER = "__IOC_IP_LIST__"
_PORT_SUFFIX_RE = re.compile(r':\d+$')

def _get_ioc_ip_list_yaml(cursor):
    # ioc_type vocabulary varies a lot by feed (ip, ipv4-addr, IPv4, ip:port, ...) —
    # nothing in this codebase normalizes it to one taxonomy, so a substring match is
    # the pragmatic way to catch all of them without also catching unrelated types
    # (domain, url, md5_hash, FileHash-SHA256, ...), none of which contain "ip".
    rows = cursor.execute(
        "SELECT DISTINCT pattern FROM stix_indicators WHERE revoked = 0 "
        "AND pattern IS NOT NULL AND pattern != '' AND LOWER(ioc_type) LIKE '%ip%'"
    ).fetchall()
    values = set()
    for r in rows:
        # ThreatFox stores some IPs as "ip:port" in the pattern itself — strip the
        # port suffix so it can still match a plain source_ip/destination_ip column.
        v = _PORT_SUFFIX_RE.sub('', (r['pattern'] or '').strip())
        if v:
            values.add(v)
    if not values:
        # An empty `field: []` is invalid Sigma/YAML (and `IN ()` is invalid SQL) — a
        # sentinel that can never appear in real traffic keeps the rule syntactically
        # valid and simply match-nothing until IOCs exist.
        return "['__NO_IOCS_YET__']"
    escaped = sorted(v.replace("'", "''") for v in values)
    return '[' + ', '.join(f"'{v}'" for v in escaped) + ']'

def _substitute_ioc_placeholder(rule_yaml_text, cursor, cache):
    if IOC_IP_PLACEHOLDER not in rule_yaml_text:
        return rule_yaml_text
    if 'value' not in cache:
        # Computed at most once per detection cycle (cached across every rule that
        # references it), not once per rule — this is the only place the query runs.
        cache['value'] = _get_ioc_ip_list_yaml(cursor)
    return rule_yaml_text.replace(IOC_IP_PLACEHOLDER, cache['value'])

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

    # Evaluate every rule and only collect what needs writing — the actual INSERTs
    # happen afterward in one short batch, rather than interleaved with rule
    # evaluation across the whole cycle. sqlite3 auto-opens a write transaction on the
    # first INSERT and holds the exclusive write lock until commit(), so writing
    # per-match here used to keep that lock held for as long as the entire sweep took
    # (potentially hundreds of rules against however many new log rows) instead of
    # just the brief moment actually spent writing — blocking every other writer,
    # including agent check-ins, for the whole duration. Reads (rule queries against
    # recent_events) don't need the write lock at all under WAL mode, so deferring
    # only the writes shrinks the lock-held window to milliseconds without changing
    # anything about which alerts get created.
    pending_alerts = []
    ioc_ip_cache = {}
    for r in rules:
        try:
            rule_exclusions = exclusions_by_rule.get(r['id'], [])
            severity = (r['severity_override'] or '').capitalize() or _extract_level(r['rule_yaml']) or 'High'
            rule_yaml_text = _substitute_ioc_placeholder(_normalize_rule_dates(r['rule_yaml']), cursor, ioc_ip_cache)
            for q in backend.convert(SigmaCollection.from_yaml(rule_yaml_text)):
                for m in cursor.execute(q).fetchall():
                    if any(_exclusion_matches(e, m) for e in rule_exclusions):
                        continue
                    # host/message/username/source_ip/log_event_id/log_app are duplicated onto
                    # the alert row itself (not just left as a join back to the triggering
                    # live_logs row) so Log Search can list alerts without joining against the
                    # multi-million-row live_logs table on every query. log_event_id/log_app
                    # preserve the original event's own Windows Event ID and channel, distinct
                    # from the rule that fired — both shown in the alert's detail view.
                    m_keys = m.keys()
                    pending_alerts.append((
                        r['id'], m['id'], severity, m['host'], m['message'],
                        m['username'] if 'username' in m_keys else None,
                        m['source_ip'] if 'source_ip' in m_keys else None,
                        m['destination_ip'] if 'destination_ip' in m_keys else None,
                        m['event_id'] if 'event_id' in m_keys else None,
                        m['app'] if 'app' in m_keys else None
                    ))
                    try:
                        if soar_api_key:
                            requests.post("http://127.0.0.1:8000/webhook/alert", json={"rule_title": r['title'], "severity": severity, "hostname": m['host'], "agent_id": m['host'], "raw_log": m['message']}, headers={"Authorization": f"Bearer {soar_api_key}"}, timeout=2)
                    except Exception as e:
                        print(f"[-] SOAR webhook failed for rule '{r['title']}': {e}")
        except Exception as e:
            print(f"[-] Rule '{r['title']}' failed to convert/execute: {e}")

    if pending_alerts:
        cursor.executemany(
            "INSERT INTO alerts (rule_id, event_id, severity, host, message, username, source_ip, destination_ip, log_event_id, log_app) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            pending_alerts
        )
    conn.commit(); conn.close()
    json.dump({"last_id": current_max}, open(STATE_FILE, 'w'))

# Same piggyback rationale as sync_due_feeds() below: automatic log retention has no
# UI-configured value by default (log_retention_days is blank/unset), so this is a
# no-op SELECT on every cycle for anyone who hasn't opted in via Settings -> System,
# and runs at most once a day (tracked via log_retention_last_purge) once they have.
def run_due_log_purge():
    if not os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    days_row = cursor.execute("SELECT value FROM settings WHERE key = 'log_retention_days'").fetchone()
    try:
        retention_days = int(days_row['value']) if days_row and days_row['value'] else 0
    except (TypeError, ValueError):
        retention_days = 0
    if retention_days < 1:
        conn.close()
        return  # automatic purge not enabled

    now = datetime.datetime.now()
    last_row = cursor.execute("SELECT value FROM settings WHERE key = 'log_retention_last_purge'").fetchone()
    if last_row and last_row['value']:
        try:
            last_purge = datetime.datetime.strptime(last_row['value'], '%Y-%m-%d %H:%M:%S')
            if (now - last_purge).total_seconds() < 24 * 3600:
                conn.close()
                return  # already ran within the last day
        except (ValueError, TypeError):
            pass  # unparseable timestamp -- treat as due, same as never having run

    cutoff = (now - datetime.timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("DELETE FROM live_logs WHERE timestamp < ?", (cutoff,))
    deleted = cursor.rowcount
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_last_purge', ?)", (now_str,))
    conn.commit()
    conn.close()
    if deleted:
        print(f"[+] Automatic log purge: deleted {deleted} log(s) older than {retention_days} day(s) (cutoff {cutoff}).", flush=True)

if __name__ == "__main__":
    # Threat intel feed auto-sync and automatic log purge both piggyback on this loop
    # rather than running as their own scheduler service — this is the only long-lived
    # background loop deployable through the existing update.sh pipeline without
    # hand-provisioning a new systemd unit or cron entry on the host. Both checks are
    # cheap on every cycle (a SELECT against settings/ti_feeds) unless something's
    # actually due, so running them every 30s adds negligible overhead.
    from taxii_client import sync_due_feeds
    while True:
        run_detection_cycle()
        try:
            sync_due_feeds()
        except Exception as e:
            print(f"[-] TI feed auto-sync check failed: {e}")
        try:
            run_due_log_purge()
        except Exception as e:
            print(f"[-] Automatic log purge check failed: {e}")
        time.sleep(30)
