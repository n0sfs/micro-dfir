import os, json, re, time, sqlite3, requests, datetime
from notifications import notify_if_configured
from warninglists import filter_warninglisted_ips
from geoip import lookup_country
from mitre_attack import techniques_for_tags
from dataclasses import dataclass, field as dc_field
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem

DB_PATH = "/opt/micro-dfir/siem.db"
STATE_FILE = os.path.join(os.path.dirname(DB_PATH), "sigma_state.json")

# pysigma's SQLite backend correctly translates a Sigma rule's |re field modifier into
# SQLite's `value REGEXP 'pattern'` syntax -- but SQLite only recognizes REGEXP as sugar
# for a registered function, it doesn't implement one itself, so every |re rule silently
# produced zero detections (every cycle, forever) until a REGEXP function is registered
# on the connection. SQLite calls this as regexp(pattern, value), matching X REGEXP Y.
def _sqlite_regexp(pattern, value):
    # A malformed pattern from a rule's own YAML must not abort the whole detection
    # cycle for every other rule -- fails closed (no match) instead of raising.
    try:
        return re.search(pattern, value or '') is not None
    except re.error:
        return False

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
    # IOC-match builder fields (see _prepare_ioc_correlation) map onto the same
    # source_ip/destination_ip columns as their plain counterparts — the only
    # difference is the *value* side, a lookup-table membership test instead of a
    # single typed-in value.
    'sourceipioc': 'source_ip', 'destinationipioc': 'destination_ip',
    # Process-creation fields (the single most common Sigma rule category), regex-
    # extracted from the raw message body at ingest time by _extract_process_fields()
    # in app.py -- see live_logs.process_image/command_line/parent_image/
    # parent_command_line/original_file_name. 'newprocessname' is Security-log 4688's
    # own name for the same concept as Sysmon's 'Image'; 'targetimage' covers Sysmon
    # event types where a different process is the subject (e.g. access/tamper events).
    'image': 'process_image', 'newprocessname': 'process_image', 'targetimage': 'process_image',
    'commandline': 'command_line', 'processcommandline': 'command_line',
    'parentimage': 'parent_image',
    'parentcommandline': 'parent_command_line',
    'originalfilename': 'original_file_name',
    # Canonicalized single-hash column (see app.py's _canonical_hash()) -- 'hashes' is
    # Sysmon's own field name for the raw multi-algorithm string, 'sha256/md5/sha1' cover
    # SigmaHQ rules that target one algorithm specifically; all land on the same column
    # since only one canonical hash is ever stored per row.
    'hashes': 'file_hash', 'hash': 'file_hash', 'sha256': 'file_hash', 'md5': 'file_hash', 'sha1': 'file_hash',
    # DNS query name (Sysmon Event ID 22) -- a bare hostname, not a full URL.
    'queryname': 'query_name', 'query': 'query_name',
    # IOC-match builder fields for the two correlation types this maps onto, same
    # relationship as sourceipioc/destinationipioc above.
    'filehashioc': 'file_hash', 'destinationdomainioc': 'query_name',
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

# Same tag-block regex app.py's _get_rules_cache() uses to feed the MITRE coverage
# heatmap -- duplicated here rather than imported, since that function lives in a
# Flask-app-scoped module this standalone detection-engine process doesn't otherwise
# depend on. Extracts the raw 'attack.txxxx'-style tag strings; techniques_for_tags()
# (mitre_attack.py) resolves those to real technique IDs, dropping tactic-only tags.
_TAGS_BLOCK_RE = re.compile(r'^tags:\s*\n((\s+-\s*[^\n\r]+\n?)+)', re.MULTILINE)

def _extract_mitre_technique_ids(rule_yaml):
    m = _TAGS_BLOCK_RE.search(rule_yaml or '')
    if not m:
        return ''
    tags = [t.strip().strip('- ') for t in m.group(1).split('\n') if t.strip()]
    return ','.join(t['id'] for t in techniques_for_tags(tags))

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
# __IOC_IP_LIST__`) rather than a typed-in value -- unchanged rule-authoring surface.
# Internally this used to be substituted with a literal YAML flow-sequence of every
# matching IOC value before parsing; once the real feed grew past ~100k IOCs (a real
# MISP sync did), pysigma's SQLite backend compiled that into a SQL expression tree
# deep enough to hit SQLite's own max-expression-depth limit (1000), and the rule
# silently failed to convert on every detection cycle from then on. It's now resolved
# via a lookup TABLE instead -- the same pattern most SIEMs use for this (Splunk
# lookups, Sentinel watchlists, Elastic enrich policies): the candidate values live as
# indexed table rows, and the compiled query does a cheap `IN (SELECT ...)` against
# them rather than listing every value inline. See _prepare_ioc_correlation() and
# _rewrite_ioc_lookups() below for how.
IOC_IP_PLACEHOLDER = "__IOC_IP_LIST__"
# Same mechanism, extended to the two correlation types live_logs now has real columns
# for (file_hash/query_name, see app.py's ingest-time extraction) -- "Tier 2" of the
# CTI gap analysis: automatic correlation was IP-only until this.
IOC_HASH_PLACEHOLDER = "__IOC_HASH_LIST__"
IOC_DOMAIN_PLACEHOLDER = "__IOC_DOMAIN_LIST__"
_PORT_SUFFIX_RE = re.compile(r':\d+$')
_HEX_HASH_RE = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')

def _get_ioc_ip_values(cursor):
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
    # Drop anything covered by an enabled warninglist (CDN ranges, public DNS
    # resolvers, RFC1918) before it can ever fire the IOC-IP rule -- a phishing kit
    # that transiently sits on a shared Cloudflare IP shouldn't turn ordinary CDN
    # traffic into a "known-bad IP matched" alert.
    return filter_warninglisted_ips(cursor, values)

def _get_ioc_hash_values(cursor):
    # Matched by SHAPE (hex length), the same reasoning as the IP list's substring
    # match above: ioc_type vocabulary for hashes varies just as much across feeds
    # ('md5'/'sha1'/'sha256' from CSV, 'FileHash-SHA256' from generic TAXII, whatever a
    # live feed calls it) and a 32/40/64-char hex string is unambiguously a hash
    # regardless of how the feed labeled it (see app.py's identical _get_live_ioc_*_hashes
    # helpers, which independently arrived at the same shape-based approach for the IOC
    # hash sweep agent action).
    rows = cursor.execute(
        "SELECT DISTINCT pattern FROM stix_indicators WHERE revoked = 0 AND pattern IS NOT NULL AND pattern != ''"
    ).fetchall()
    return {r['pattern'].strip().lower() for r in rows if _HEX_HASH_RE.match((r['pattern'] or '').strip())}

def _get_ioc_domain_values(cursor):
    rows = cursor.execute(
        "SELECT DISTINCT pattern FROM stix_indicators WHERE revoked = 0 "
        "AND pattern IS NOT NULL AND pattern != '' AND LOWER(ioc_type) LIKE '%domain%'"
    ).fetchall()
    return {r['pattern'].strip().lower() for r in rows if r['pattern']}

# Records one ioc_sightings row per stix_indicators IOC that actually contributed to a
# NEW alert firing via one of the __IOC_..._LIST__ correlations (IP, hash, or DNS query
# domain -- see rule_uses_ioc_placeholder below) -- the only automatic IOC-to-log
# correlation that exists today, so this is the only place a genuine "observed in our
# environment" event can currently be derived from. Only called for brand-new alerts
# (not re-occurrences within the 15-minute dedup window), mirroring the same
# once-per-burst restraint already applied to notify_if_configured() below.
def _record_ioc_sightings(cursor, rule_id, host, source_ip, destination_ip, file_hash, query_name,
                           alert_id, rule_title, rule_uses_ioc_placeholder):
    used = rule_uses_ioc_placeholder.get(rule_id)
    if not used:
        return
    # Each correlation type only ever checks its own column against its own ioc_type
    # shape -- a rule using __IOC_HASH_LIST__ must not accidentally record a sighting
    # off the same alert's source_ip, which has nothing to do with what that rule
    # actually matched on.
    candidates = []
    if used.get('ip'):
        candidates += [(v, "LOWER(ioc_type) LIKE '%ip%'") for v in (source_ip, destination_ip) if v]
    if used.get('hash') and file_hash:
        candidates.append((file_hash, "1=1"))  # hash IOCs are matched by shape (see _get_ioc_hash_list_yaml), not ioc_type
    if used.get('domain') and query_name:
        candidates.append((query_name, "LOWER(ioc_type) LIKE '%domain%'"))
    for value, type_filter in candidates:
        rows = cursor.execute(
            f"SELECT stix_id FROM stix_indicators WHERE LOWER(pattern) = LOWER(?) AND {type_filter} AND revoked = 0",
            (value,)
        ).fetchall()
        for row in rows:
            cursor.execute(
                "INSERT INTO ioc_sightings (stix_id, source, log_ref) VALUES (?, ?, ?)",
                (row['stix_id'], f"alert:{rule_title}", f"alert_id={alert_id}, host={host}")
            )

# Only called for a genuinely NEW alert row (the caller's `existing` branch above skips
# this on a re-occurrence bump within the 15-minute dedup window) -- that's the only
# dedup guard this needs. A rule that keeps re-triggering on the same host/user just
# keeps bumping occurrence_count on the one alert already linked into the one case
# already created, rather than spawning a new case every cycle.
def _auto_create_case(cursor, rule_title, host, username, alert_id, template_id):
    title = f"{rule_title} — {host}"
    detail = f"Auto-created because rule '{rule_title}' fired on {host}" + (f" (user: {username})" if username else "") + "."
    cursor.execute(
        "INSERT INTO cases (title, status, description, created_by, tlp, pap) VALUES (?, 'open', ?, 'system:auto-case', 'amber', 'amber')",
        (title, detail)
    )
    cid = cursor.lastrowid
    cursor.execute("INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, 'system', 'created', ?)", (cid, title))
    cursor.execute("INSERT INTO case_items (case_id, item_type, item_id, added_by) VALUES (?, 'alert', ?, 'system')", (cid, str(alert_id)))
    cursor.execute("INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, 'system', 'item_added', ?)", (cid, f"alert:{alert_id}"))
    if template_id:
        tpl = cursor.execute("SELECT name, tasks FROM case_templates WHERE id = ?", (template_id,)).fetchone()
        if tpl:
            tasks = json.loads(tpl['tasks'])
            cursor.executemany(
                "INSERT INTO case_tasks (case_id, title, position, created_by) VALUES (?, ?, ?, 'system')",
                [(cid, t, i) for i, t in enumerate(tasks)]
            )
            cursor.execute("INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, 'system', 'template_applied', ?)", (cid, tpl['name']))
    return cid

# kind -> (rule-facing placeholder token, internal sentinel scalar, TEMP TABLE name, value builder).
# The sentinel is deliberately alphanumeric-only (no underscores/percent) so pysigma's
# SQLite backend compiles the field comparison as a plain `column='SENTINEL'` equality
# instead of a LIKE/ESCAPE pattern (its usual handling for any string containing a
# LIKE wildcard character) -- that keeps _rewrite_ioc_lookups()'s regex simple and
# reliable regardless of pysigma version quirks. Never seen by rule authors; only ever
# exists between _prepare_ioc_correlation() and _rewrite_ioc_lookups() within one
# rule's conversion.
_IOC_KINDS = (
    ('ip', IOC_IP_PLACEHOLDER, 'IOCSENTINELIPVALUE', 'ioc_ip_lookup', _get_ioc_ip_values),
    ('hash', IOC_HASH_PLACEHOLDER, 'IOCSENTINELHASHVALUE', 'ioc_hash_lookup', _get_ioc_hash_values),
    ('domain', IOC_DOMAIN_PLACEHOLDER, 'IOCSENTINELDOMAINVALUE', 'ioc_domain_lookup', _get_ioc_domain_values),
)
_IOC_LOOKUP_SQL_RE = {kind: re.compile(r"(\w+)\s*=\s*'" + re.escape(sentinel) + r"'") for kind, _, sentinel, _, _ in _IOC_KINDS}

# Populates one small TEMP TABLE per IOC kind actually referenced by ANY rule this
# cycle/dry-run (cached in `cache` so it's built at most once regardless of how many
# rules reference it, the same restraint the old per-cycle YAML-list cache had), and
# swaps each rule's __IOC_*_LIST__ placeholder for that kind's internal sentinel
# scalar. Called BEFORE Sigma parses the rule -- see _rewrite_ioc_lookups() for the
# other half, which runs AFTER Sigma compiles it to SQL.
def _prepare_ioc_correlation(rule_yaml_text, cursor, cache):
    for kind, placeholder, sentinel, table, build_values in _IOC_KINDS:
        if placeholder not in rule_yaml_text:
            continue
        if kind not in cache:
            cursor.execute(f"DROP TABLE IF EXISTS {table}")
            cursor.execute(f"CREATE TEMP TABLE {table} (value TEXT PRIMARY KEY)")
            values = build_values(cursor)
            if values:
                cursor.executemany(f"INSERT OR IGNORE INTO {table} (value) VALUES (?)", [(v,) for v in values])
            cache[kind] = True
        rule_yaml_text = rule_yaml_text.replace(placeholder, sentinel)
    return rule_yaml_text

# Rewrites a compiled query's sentinel equality checks into a lookup-table membership
# test -- `source_ip='IOCSENTINELIPVALUE'` becomes
# `source_ip IN (SELECT value FROM ioc_ip_lookup)`. A cheap indexed subquery against
# however many IOCs actually exist, instead of every one of them appearing as literal
# SQL text (which is what overflowed SQLite's expression-tree depth limit once the
# real IOC set passed ~100k rows). A no-op (regex just won't match) for any query that
# doesn't reference one of these sentinels.
def _rewrite_ioc_lookups(sql):
    for kind, _, sentinel, table, _ in _IOC_KINDS:
        sql = _IOC_LOOKUP_SQL_RE[kind].sub(rf"\1 IN (SELECT value FROM {table})", sql)
    return sql

# Lighter than dry_run_rule() below -- checks that a rule PARSES and COMPILES to SQL
# (date normalization, IOC lookup-table correlation, Sigma YAML parsing, SQL
# generation) WITHOUT ever executing the compiled query against live_logs.
# SigmaCollection.from_yaml()/backend.convert() are pure in-memory work with no
# database access at all, so this only touches the DB for _prepare_ioc_correlation()'s
# (cheap, cached) lookup-table population -- never the live_logs table itself, which is
# what actually made a first version of this (built on dry_run_rule(), which DOES
# execute against live_logs) far too slow to run across every enabled rule in one
# request: 106 real rules each scanning live_logs took minutes, not seconds. A
# conversion-time exception -- like the expression-tree-depth bug this very lookup-
# table mechanism was built to fix -- is exactly the failure mode silently swallowed by
# run_detection_cycle()'s per-rule try/except, and is what this is checking for.
# `ioc_cache` should be shared across every rule checked in one bulk pass (the same
# restraint run_detection_cycle()'s own per-cycle cache uses), so the IOC lookup tables
# are built at most once regardless of how many rules reference them.
def check_rule_converts(conn, rule_yaml, ioc_cache):
    cursor = conn.cursor()
    rule_yaml_text = _prepare_ioc_correlation(_normalize_rule_dates(rule_yaml), cursor, ioc_cache)
    backend = _make_backend()
    for q in backend.convert(SigmaCollection.from_yaml(rule_yaml_text)):
        _rewrite_ioc_lookups(q)

DRY_RUN_PREVIEW_FIELDS = ('id', 'timestamp', 'host', 'app', 'severity', 'event_id', 'username', 'message')

# Tests a Sigma rule against a recent window of live_logs WITHOUT writing to `alerts`,
# without notifications/SOAR webhook/auto-case, and without touching sigma_state.json's
# ingest cursor. Reuses the exact same rule-to-SQL conversion path run_detection_cycle()
# uses (date normalization, IOC placeholder substitution, field-to-column mapping via
# _make_backend(), exclusions) against a time window instead of an ingest-id cursor, so
# what this reports is what a live run would actually have matched -- not a separate,
# driftable reimplementation. Called from app.py's Flask process (a different service
# than the one that runs run_detection_cycle()), against that request's own SQLite
# connection -- the TEMP VIEW this creates is connection-scoped and gone once that
# request's connection closes, so it can never collide with the live engine's own
# per-cycle `recent_events` view on its separate, long-lived connection.
def dry_run_rule(conn, rule_yaml, days=7, exclusions=None, preview_limit=20, ioc_cache=None):
    conn.create_function('REGEXP', 2, _sqlite_regexp)
    cursor = conn.cursor()

    cutoff = cursor.execute("SELECT datetime('now', ?)", (f'-{days} days',)).fetchone()[0]
    cursor.execute("DROP VIEW IF EXISTS recent_events")
    cursor.execute(f"CREATE TEMP VIEW recent_events AS SELECT * FROM live_logs WHERE timestamp >= '{cutoff}'")

    # ioc_cache defaults to a fresh dict (this call's own IOC lookup tables, built once
    # for however many kinds THIS rule references) -- a caller validating several rules
    # in one pass can instead pass one shared dict across every call, so the tables are
    # built at most once for the whole batch rather than once per rule (same restraint
    # check_rule_converts()/run_detection_cycle() apply).
    rule_yaml_text = _prepare_ioc_correlation(_normalize_rule_dates(rule_yaml), cursor, ioc_cache if ioc_cache is not None else {})
    backend = _make_backend()
    queries = backend.convert(SigmaCollection.from_yaml(rule_yaml_text))  # raises on invalid/unconvertible rule -- caller reports it

    # A rule can compile to more than one SQL query (e.g. multiple detection blocks) --
    # dedup by row id across all of them so a log line matching more than one doesn't
    # inflate the "how many events would this have caught" count.
    seen_ids, matches = set(), []
    for q in queries:
        q = _rewrite_ioc_lookups(q)
        for m in cursor.execute(q).fetchall():
            if m['id'] in seen_ids:
                continue
            if any(_exclusion_matches(e, m) for e in (exclusions or [])):
                continue
            seen_ids.add(m['id'])
            matches.append(m)
    cursor.execute("DROP VIEW IF EXISTS recent_events")

    matches.sort(key=lambda m: m['id'], reverse=True)
    total = len(matches)
    preview = [{k: m[k] for k in DRY_RUN_PREVIEW_FIELDS if k in m.keys()} for m in matches[:preview_limit]]
    return {'total_matches': total, 'preview': preview, 'preview_truncated': total > preview_limit, 'window_days': days}

def run_detection_cycle():
    if not os.path.exists(DB_PATH): return
    conn = sqlite3.connect(DB_PATH, timeout=30); conn.row_factory = sqlite3.Row
    conn.create_function('REGEXP', 2, _sqlite_regexp)
    cursor = conn.cursor()
    last_id = json.load(open(STATE_FILE)).get("last_id", 0) if os.path.exists(STATE_FILE) else 0
    soar_api_key = _get_soar_api_key(cursor)

    try: current_max = cursor.execute("SELECT MAX(id) as m FROM live_logs").fetchone()['m'] or 0
    except Exception as e:
        print(f"[-] Could not read live_logs: {e}")
        return
    if current_max <= last_id: return

    cursor.execute(f"CREATE TEMP VIEW recent_events AS SELECT * FROM live_logs WHERE id > {last_id} AND id <= {current_max}")
    rules = cursor.execute("SELECT id, title, rule_yaml, severity_override, auto_case, auto_case_template_id FROM sigma_rules WHERE enabled = 1").fetchall()
    rule_titles = {r['id']: r['title'] for r in rules}
    rule_mitre = {r['id']: _extract_mitre_technique_ids(r['rule_yaml']) for r in rules}
    rule_autocase = {r['id']: r['auto_case_template_id'] for r in rules if r['auto_case']}
    rule_uses_ioc_placeholder = {
        r['id']: {kind: placeholder in r['rule_yaml'] for kind, placeholder, *_ in _IOC_KINDS}
        for r in rules
    }
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
    ioc_cache = {}
    for r in rules:
        try:
            rule_exclusions = exclusions_by_rule.get(r['id'], [])
            severity = (r['severity_override'] or '').capitalize() or _extract_level(r['rule_yaml']) or 'High'
            rule_yaml_text = _prepare_ioc_correlation(_normalize_rule_dates(r['rule_yaml']), cursor, ioc_cache)
            for q in backend.convert(SigmaCollection.from_yaml(rule_yaml_text)):
                q = _rewrite_ioc_lookups(q)
                for m in cursor.execute(q).fetchall():
                    if any(_exclusion_matches(e, m) for e in rule_exclusions):
                        continue
                    # host/message/username/source_ip/log_event_id/log_app are duplicated onto
                    # the alert row itself (not just left as a join back to the triggering
                    # live_logs row) so Log Search can list alerts without joining against the
                    # multi-million-row live_logs table on every query. log_event_id/log_app
                    # preserve the original event's own Windows Event ID and channel, distinct
                    # from the rule that fired — both shown in the alert's detail view.
                    # file_hash/query_name aren't stored on the alert row itself (alerts has no
                    # such columns) -- they're only carried through pending_alerts far enough to
                    # feed _record_ioc_sightings() below, then discarded.
                    m_keys = m.keys()
                    pending_alerts.append((
                        r['id'], m['id'], severity, m['host'], m['message'],
                        m['username'] if 'username' in m_keys else None,
                        m['source_ip'] if 'source_ip' in m_keys else None,
                        m['destination_ip'] if 'destination_ip' in m_keys else None,
                        m['event_id'] if 'event_id' in m_keys else None,
                        m['app'] if 'app' in m_keys else None,
                        m['file_hash'] if 'file_hash' in m_keys else None,
                        m['query_name'] if 'query_name' in m_keys else None
                    ))
                    try:
                        if soar_api_key:
                            requests.post("http://127.0.0.1:8000/webhook/alert", json={"rule_title": r['title'], "severity": severity, "hostname": m['host'], "agent_id": m['host'], "raw_log": m['message']}, headers={"Authorization": f"Bearer {soar_api_key}"}, timeout=2)
                    except Exception as e:
                        print(f"[-] SOAR webhook failed for rule '{r['title']}': {e}")
        except Exception as e:
            print(f"[-] Rule '{r['title']}' failed to convert/execute: {e}")

    if pending_alerts:
        # Collapse duplicate hits within THIS cycle's own batch by (rule_id, host,
        # username) before ever touching the alerts table -- a bursty rule matching the
        # same host/user combo dozens of times in one sweep shouldn't create dozens of
        # rows or dozens of dedup lookups, just one candidate per combo (using the last
        # match's fields, since pending_alerts is populated in ascending id order so the
        # last one seen is the most recent occurrence) tagged with how many hit.
        grouped = {}
        for tup in pending_alerts:
            key = (tup[0], tup[3], tup[5])  # rule_id, host, username
            g = grouped.setdefault(key, {'count': 0, 'latest': tup})
            g['count'] += 1
            g['latest'] = tup

        # One SELECT + one INSERT/UPDATE per distinct (rule, host, user) combo this
        # cycle -- bounded by how many DISTINCT things fired, not how many times they
        # fired, so this stays a brief final write phase rather than reopening the
        # long-write-lock problem the pending_alerts batching above exists to avoid.
        for (rule_id, host, username), g in grouped.items():
            (_, event_id, severity, _, message, _, source_ip, destination_ip, log_event_id, log_app,
             file_hash, query_name) = g['latest']
            existing = cursor.execute(
                "SELECT id, occurrence_count FROM alerts WHERE rule_id IS ? AND host = ? AND username IS ? "
                "AND COALESCE(last_seen, timestamp) >= datetime('now', '-15 minutes') ORDER BY id DESC LIMIT 1",
                (rule_id, host, username)
            ).fetchone()
            if existing:
                cursor.execute(
                    "UPDATE alerts SET occurrence_count = occurrence_count + ?, last_seen = datetime('now'), "
                    "event_id = ?, message = ?, source_ip = ?, destination_ip = ?, log_event_id = ?, log_app = ?, severity = ? "
                    "WHERE id = ?",
                    (g['count'], event_id, message, source_ip, destination_ip, log_event_id, log_app, severity, existing['id'])
                )
            else:
                country_code, country_name = lookup_country(source_ip)
                cursor.execute(
                    "INSERT INTO alerts (rule_id, event_id, severity, host, message, username, source_ip, destination_ip, log_event_id, log_app, occurrence_count, last_seen, country_code, country_name, mitre_techniques) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?)",
                    (rule_id, event_id, severity, host, message, username, source_ip, destination_ip, log_event_id, log_app, g['count'], country_code, country_name, rule_mitre.get(rule_id, ''))
                )
                new_alert_id = cursor.lastrowid
                _record_ioc_sightings(cursor, rule_id, host, source_ip, destination_ip, file_hash, query_name,
                                       new_alert_id, rule_titles.get(rule_id, 'Custom/YARA Rule'), rule_uses_ioc_placeholder)
                if rule_id in rule_autocase:
                    try:
                        _auto_create_case(cursor, rule_titles.get(rule_id, 'Custom/YARA Rule'), host, username,
                                           new_alert_id, rule_autocase[rule_id])
                    except Exception as e:
                        print(f"[-] Auto-case creation failed for rule '{rule_titles.get(rule_id)}': {e}")
                # Only a brand-new alert notifies, not a re-occurrence within the same
                # 15-minute dedup window (the `existing` branch above) -- otherwise a noisy
                # rule would re-notify every cycle it keeps matching instead of once per burst.
                notify_if_configured(cursor, {
                    'rule_title': rule_titles.get(rule_id, 'Custom/YARA Rule'),
                    'severity': severity, 'host': host, 'username': username,
                    'source_ip': source_ip, 'message': message,
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                })
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

# stix_indicators has no natural TTL of its own -- ThreatFox/URLhaus/Feodo Tracker's
# "recent" endpoints are rolling windows, so an indicator that ages out of the feed just
# stops being re-synced (see migrate_stix_indicators's INSERT OR REPLACE, and
# `inserted_at DEFAULT CURRENT_TIMESTAMP` in schema.sql -- a resync refreshes it, so an
# unchanged inserted_at genuinely means "not seen in any feed export since"). Left
# unchecked this grows unbounded -- confirmed at 135k+ rows in production, which is what
# originally blew SQLite's expression-tree-depth limit on IOC-correlation rules (see
# _IOC_KINDS above). Unlike log retention, this defaults to ON: an aged-out IOC just
# re-syncs if its feed still carries it, and the actual "this was observed in our
# environment" evidence lives in ioc_sightings (untouched -- see _record_ioc_sightings),
# so purging stix_indicators here is low-risk cache cleanup, not evidence destruction.
DEFAULT_IOC_RETENTION_DAYS = 30

def run_due_ioc_purge():
    if not os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    days_row = cursor.execute("SELECT value FROM settings WHERE key = 'ioc_retention_days'").fetchone()
    try:
        retention_days = int(days_row['value']) if days_row and days_row['value'] else DEFAULT_IOC_RETENTION_DAYS
    except (TypeError, ValueError):
        retention_days = DEFAULT_IOC_RETENTION_DAYS
    if retention_days < 1:
        conn.close()
        return  # admin explicitly disabled automatic purge (stored '0', not just unset)

    now = datetime.datetime.now()
    last_row = cursor.execute("SELECT value FROM settings WHERE key = 'ioc_retention_last_purge'").fetchone()
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
    cursor.execute("DELETE FROM stix_indicators WHERE inserted_at < ?", (cutoff,))
    deleted = cursor.rowcount
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ioc_retention_last_purge', ?)", (now_str,))
    conn.commit()
    conn.close()
    if deleted:
        print(f"[+] Automatic IOC purge: deleted {deleted} stale indicator(s) older than {retention_days} day(s) (cutoff {cutoff}).", flush=True)

if __name__ == "__main__":
    # Threat intel feed auto-sync, automatic log purge, and automatic IOC purge all
    # piggyback on this loop rather than running as their own scheduler service — this
    # is the only long-lived background loop deployable through the existing update.sh
    # pipeline without hand-provisioning a new systemd unit or cron entry on the host.
    # All three checks are cheap on every cycle (a SELECT against settings/ti_feeds)
    # unless something's actually due, so running them every 30s adds negligible
    # overhead.
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
        try:
            run_due_ioc_purge()
        except Exception as e:
            print(f"[-] Automatic IOC purge check failed: {e}")
        time.sleep(30)
