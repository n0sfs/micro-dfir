import copy, os, json, sqlite3, duckdb
DB_PATH = "/opt/micro-dfir/siem.db"
UEBA_DEFAULTS = {
    'ueba_lookback_days': 30, 'ueba_stddev_multiplier': 3.0, 'ueba_min_baseline': 50.0,
    'ueba_min_days_observed': 4, 'ueba_new_ip_enabled': 1,
}

# Point values an admin can retune without a schema change -- one JSON settings blob
# rather than ~15 individual keys the way UEBA_DEFAULTS above does it, since that
# one-key-per-value shape doesn't scale cleanly to this many tunables and a new
# indicator's weight shouldn't need a migration to add. Deep-merged over a POSTed
# partial config (see get_risk_score_config) so adding a new indicator later doesn't
# break an already-saved config that predates it.
RISK_SCORE_DEFAULTS = {
    'window_days': 7,
    'points': {
        'alert_critical': 40, 'alert_high': 25, 'alert_medium': 10, 'alert_low': 5, 'alert_informational': 1,
        'sweep_hit': 35,
        'failed_login': 10,
        'volume_anomaly_critical': 30, 'volume_anomaly_high': 20, 'volume_anomaly_medium': 10,
        'new_source_ip': 15,
        'first_time_bonus': 15,
    },
    'tiers': {'low': 0, 'medium': 20, 'high': 50, 'critical': 100},
}

# Which columns an anomaly_rules row is allowed to reference for each source table --
# enforced again here (not just at rule-CRUD time in app.py) because entity_field ends
# up interpolated into a raw SQL column reference below, so a stored value must be
# re-validated against this allowlist before it's ever trusted, defense in depth.
# Sigma alerts only for now -- audit_log-sourced rules were pulled back out shortly
# after shipping; may return as a source later.
ANOMALY_RULE_SOURCES = {
    'alerts': {'fields': ('severity', 'rule_name', 'host', 'username', 'source_ip', 'destination_ip'), 'entity_fields': ('host', 'username')},
}

def _rule_matches(rule, row):
    if rule['field'] not in row.keys():
        return False
    row_value = row[rule['field']]
    row_value = '' if row_value is None else str(row_value)
    target = rule['value'] or ''
    op = rule['operator']
    if op == 'equals':
        return row_value == target
    if op == 'not_equals':
        return row_value != target
    if op == 'contains':
        return target.lower() in row_value.lower()
    return False

def _load_anomaly_rules(conn, source):
    allowed = ANOMALY_RULE_SOURCES.get(source)
    if not allowed:
        return []
    rows = conn.execute(
        "SELECT id, name, field, operator, value, entity_field, entity_type, points, first_time_bonus_points "
        "FROM anomaly_rules WHERE source = ? AND enabled = 1",
        (source,)
    ).fetchall()
    return [r for r in rows if r['field'] in allowed['fields'] and r['entity_field'] in allowed['entity_fields']]

# "Is this normal for THIS entity" for a custom rule: has this exact rule ever matched
# for this entity before (anywhere in the source table's history, not just the current
# scoring window)? Generalizes the old fixed "same username + same action" check to any
# rule condition, so a first occurrence -- not just a first-time action -- earns the bonus.
def _rule_ever_matched_before(conn, table, rule, entity_id, before_id):
    prior_rows = conn.execute(
        f"SELECT * FROM {table} WHERE {rule['entity_field']} = ? AND id < ?", (entity_id, before_id)
    ).fetchall()
    return any(_rule_matches(rule, pr) for pr in prior_rows)

def _deep_merge(base, override):
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base

def get_risk_score_config():
    cfg = copy.deepcopy(RISK_SCORE_DEFAULTS)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        row = conn.execute("SELECT value FROM settings WHERE key = 'risk_score_config'").fetchone()
        conn.close()
        if row and row[0]:
            _deep_merge(cfg, json.loads(row[0]))
    except Exception:
        pass
    return cfg
# 0.6745 is the standard consistency constant that scales MAD to be comparable to a
# stddev for a normal distribution, so the existing stddev_multiplier setting keeps its
# original meaning now that baselines use median/MAD instead of mean/stddev.
MAD_TO_STDDEV = 0.6745

def get_ueba_config():
    cfg = dict(UEBA_DEFAULTS)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        keys = tuple(UEBA_DEFAULTS.keys())
        rows = conn.execute(f"SELECT key, value FROM settings WHERE key IN ({','.join('?' for _ in keys)})", keys).fetchall()
        conn.close()
        for k, v in rows:
            cfg[k] = v
    except Exception:
        pass
    return {
        'lookback_days': max(1, min(365, int(cfg['ueba_lookback_days']))),
        'stddev_multiplier': max(0.5, min(10.0, float(cfg['ueba_stddev_multiplier']))),
        'min_baseline': max(0.0, float(cfg['ueba_min_baseline'])),
        'min_days_observed': max(1, min(52, int(cfg['ueba_min_days_observed']))),
        'new_ip_enabled': str(cfg['ueba_new_ip_enabled']) not in ('0', 'false', 'False'),
    }

def _get_exclusions():
    excluded = set()
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        for entity_type, entity_id in conn.execute("SELECT entity_type, entity_id FROM ueba_exclusions WHERE enabled = 1").fetchall():
            excluded.add((entity_type, entity_id))
        conn.close()
    except Exception:
        pass
    return excluded

# UEBA models two entity types — host and user — with the same technique: daily
# event-volume vs. a rolling per-entity baseline. This is a flat activity-count model,
# not the richer multi-signal behavioral profile a full UEBA platform builds — that
# would need new structured fields we don't currently ingest. Placeholder values
# (missing host, '-'/blank username used when ingest has no user context) are filtered
# out so they don't get modeled as if they were a real entity.
ENTITY_MODELS = [
    {'entity_type': 'host', 'column': 'host', 'extra_filter': "host IS NOT NULL AND host NOT IN ('', 'UNKNOWN')"},
    {'entity_type': 'user', 'column': 'username', 'extra_filter': "username IS NOT NULL AND username NOT IN ('', '-')"},
]

# `spread` is already scaled to be comparable to a stddev (MAD / 0.6745). Alerts are
# only ever raised at cur_c > center + (multiplier * spread), so this ratio is always
# >= 1 for anything considered anomalous — it buckets how far past that threshold the
# spike is into Critical/High/Medium instead of a single flat severity.
def _severity_for(cur_c, center, spread, multiplier):
    if spread and spread > 0:
        ratio = (cur_c - center) / (spread * multiplier)
    else:
        ratio = cur_c / max(center, 1)
    if ratio >= 3: return 'Critical'
    if ratio >= 2: return 'High'
    return 'Medium'

def _run_model(con, model, cfg):
    entity_type, col, extra_filter = model['entity_type'], model['column'], model['extra_filter']
    # Baselines are computed per day-of-week (today's Friday count is only compared
    # against this entity's historical Fridays, not blended with its weekends), using
    # median/MAD instead of mean/stddev so a single past spike day doesn't drag the
    # baseline up for weeks afterward. Splitting by weekday thins the historical sample
    # to roughly lookback_days/7 per entity, so an entity needs min_days_observed
    # same-weekday samples before the weekday-specific stats are trusted — until then it
    # falls back to a flat all-history median/MAD (the old behavior) so newly-seen
    # entities and freshly-deployed instances still get modeled instead of going dark
    # for weeks while weekday history accumulates.
    query = (
        f"WITH daily AS (SELECT {col} as entity_id, date_trunc('day', CAST(timestamp AS TIMESTAMP)) as day, count(*) as c "
        f"FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY AND {extra_filter} GROUP BY 1, 2), "
        "hist AS (SELECT entity_id, c, CAST(date_part('dow', day) AS INTEGER) as dow FROM daily WHERE day < CURRENT_DATE), "
        "flat_stats AS (SELECT entity_id, median(c) as med_c, count(*) as days_seen FROM hist GROUP BY 1), "
        "flat_mad AS (SELECT h.entity_id, median(abs(h.c - s.med_c)) as mad_c "
        "             FROM hist h JOIN flat_stats s ON h.entity_id = s.entity_id GROUP BY 1), "
        "wd_stats AS (SELECT entity_id, dow, median(c) as med_c, count(*) as days_seen FROM hist GROUP BY 1, 2), "
        "wd_mad AS (SELECT h.entity_id, h.dow, median(abs(h.c - s.med_c)) as mad_c "
        "           FROM hist h JOIN wd_stats s ON h.entity_id = s.entity_id AND h.dow = s.dow GROUP BY 1, 2), "
        "picked AS (SELECT fs.entity_id, "
        f"    CASE WHEN ws.days_seen >= {cfg['min_days_observed']} THEN ws.med_c ELSE fs.med_c END as med_c, "
        f"    CASE WHEN ws.days_seen >= {cfg['min_days_observed']} THEN wm.mad_c ELSE fm.mad_c END as mad_c, "
        f"    CASE WHEN ws.days_seen >= {cfg['min_days_observed']} THEN ws.days_seen ELSE fs.days_seen END as days_seen, "
        f"    CASE WHEN ws.days_seen >= {cfg['min_days_observed']} THEN 'weekday' ELSE 'flat' END as baseline_mode "
        "    FROM flat_stats fs "
        "    LEFT JOIN wd_stats ws ON fs.entity_id = ws.entity_id AND ws.dow = CAST(date_part('dow', CURRENT_DATE) AS INTEGER) "
        "    LEFT JOIN wd_mad wm ON ws.entity_id = wm.entity_id AND ws.dow = wm.dow "
        "    LEFT JOIN flat_mad fm ON fs.entity_id = fm.entity_id), "
        f"today AS (SELECT {col} as entity_id, count(*) as cur_c FROM siem.live_logs "
        f"          WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE AND {extra_filter} GROUP BY 1) "
        "SELECT p.entity_id, COALESCE(t.cur_c, 0) as cur_c, p.med_c, p.mad_c, p.days_seen, p.baseline_mode "
        "FROM picked p LEFT JOIN today t ON p.entity_id = t.entity_id "
        f"WHERE p.med_c > {cfg['min_baseline']} "
        "ORDER BY (COALESCE(t.cur_c, 0) / GREATEST(p.med_c, 1)) DESC LIMIT 200"
    )
    rows = []
    for entity_id, cur_c, med_c, mad_c, days_seen, baseline_mode in con.execute(query).fetchall():
        spread = (mad_c or 0) / MAD_TO_STDDEV
        threshold = med_c + (cfg['stddev_multiplier'] * spread)
        rows.append({
            'entity_type': entity_type, 'entity_id': entity_id, 'current_count': cur_c,
            'baseline_avg': round(med_c, 1) if med_c is not None else None,
            'baseline_stddev': round(spread, 1),
            'threshold': round(threshold, 1), 'is_anomalous': cur_c > threshold,
            'days_seen': days_seen, 'baseline_mode': baseline_mode,
        })
    return rows

# A second, non-volume signal: a user active today from a source IP that's never been
# associated with them in the lookback window before. Cheap classic UEBA "new location"
# check using data we already capture — no new ingestion needed.
def _run_new_source_ip_model(con, cfg):
    if not cfg['new_ip_enabled']:
        return []
    query = (
        "WITH known AS (SELECT DISTINCT username, source_ip FROM siem.live_logs "
        f"    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND username IS NOT NULL AND username NOT IN ('', '-') "
        "      AND source_ip IS NOT NULL AND source_ip NOT IN ('', '-')), "
        "today_pairs AS (SELECT username, source_ip, count(*) as c FROM siem.live_logs "
        "    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE "
        "      AND username IS NOT NULL AND username NOT IN ('', '-') "
        "      AND source_ip IS NOT NULL AND source_ip NOT IN ('', '-') GROUP BY 1, 2) "
        "SELECT tp.username, tp.source_ip, tp.c FROM today_pairs tp "
        "LEFT JOIN known k ON tp.username = k.username AND tp.source_ip = k.source_ip "
        "WHERE k.username IS NULL LIMIT 200"
    )
    return [{'username': u, 'source_ip': ip, 'count': c} for u, ip, c in con.execute(query).fetchall()]

def run_ueba_models():
    try:
        cfg = get_ueba_config()
        risk_cfg = get_risk_score_config()
        excluded = _get_exclusions()
        con = duckdb.connect(database=':memory:'); con.execute("INSTALL sqlite; LOAD sqlite;")
        con.execute(f"ATTACH '{DB_PATH}' AS siem (TYPE SQLITE);")
        all_rows = []
        for model in ENTITY_MODELS:
            all_rows.extend(_run_model(con, model, cfg))
        new_ip_hits = _run_new_source_ip_model(con, cfg)
        con.close()
    except Exception as e:
        print(f"[-] UEBA model run failed: {e}")
        return

    for r in all_rows:
        r['excluded'] = (r['entity_type'], r['entity_id']) in excluded
    new_ip_hits = [h for h in new_ip_hits if ('user', h['username']) not in excluded]

    conn = sqlite3.connect(DB_PATH, timeout=30)

    # Snapshot every modeled entity (not just the ones currently anomalous) so the
    # baseline-visibility view can show what "normal" looks like — best-effort: an
    # older DB that hasn't run this migration yet just skips the snapshot.
    try:
        conn.execute("DELETE FROM ueba_entity_baselines")
        conn.executemany(
            "INSERT INTO ueba_entity_baselines (entity_type, entity_id, current_count, baseline_avg, baseline_stddev, threshold, is_anomalous, excluded, days_seen, baseline_mode, computed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
            [(r['entity_type'], r['entity_id'], r['current_count'], r['baseline_avg'], r['baseline_stddev'],
              r['threshold'], r['is_anomalous'], r['excluded'], r['days_seen'], r['baseline_mode']) for r in all_rows]
        )
        conn.commit()
    except Exception as e:
        print(f"[-] UEBA baseline snapshot failed (non-fatal): {e}")

    try:
        for r in all_rows:
            if not r['is_anomalous'] or r['excluded']:
                continue
            severity = _severity_for(r['current_count'], r['baseline_avg'], r['baseline_stddev'], cfg['stddev_multiplier'])
            label = 'host' if r['entity_type'] == 'host' else 'user'
            basis = f"same-weekday baseline of {r['baseline_avg']} (±{r['baseline_stddev']}, {r['days_seen']} weeks observed)" \
                if r['baseline_mode'] == 'weekday' else \
                f"baseline of {r['baseline_avg']} (±{r['baseline_stddev']}, {r['days_seen']} days observed — not enough same-weekday history yet)"
            message = f"{r['entity_id']} ({label}) generated {r['current_count']} events today, exceeding its {basis}."
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, ?, 'duckdb_ueba', ?, ?, ?)",
                (r['entity_id'], r['entity_type'], severity, message, json.dumps({**r, 'detection_type': 'volume_baseline'}))
            )
            # This statistical anomaly is one of six risk-score indicators (see
            # run_risk_scoring below for the fact-based ones) -- scored right here from
            # the same computation rather than re-deriving it from raw_json later.
            pts = risk_cfg['points'].get(f'volume_anomaly_{severity.lower()}', risk_cfg['points']['volume_anomaly_medium'])
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id) VALUES (?,?,?,?,?,?,?)",
                (r['entity_type'], r['entity_id'], 'volume_anomaly', pts, message, 'ueba_entity_baselines', None)
            )
        for h in new_ip_hits:
            message = (f"{h['username']} (user) was active from a source IP not seen for this user in the past "
                       f"{cfg['lookback_days']} days: {h['source_ip']} ({h['count']} events today).")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, 'user', 'duckdb_ueba', 'Medium', ?, ?)",
                (h['username'], message, json.dumps({**h, 'detection_type': 'new_source_ip'}))
            )
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id) VALUES (?,?,?,?,?,?,?)",
                ('user', h['username'], 'new_source_ip', risk_cfg['points']['new_source_ip'], message, 'events', None)
            )
        conn.commit()
    except Exception as e:
        print(f"[-] UEBA failed to persist anomalies: {e}")
    finally:
        conn.close()

# ---- Composite risk scoring (fact-based indicators) ----
# Sigma alerts / audit actions / sweep hits are scanned incrementally -- each source
# never gets re-scored twice -- via a high-water-mark id per source stored in the
# settings table, the same pattern sigma_engine.py already uses (STATE_FILE's last_id)
# for its own incremental live_logs scan.
_RISK_MARK_KEYS = {
    'alert': 'risk_scoring_last_alert_id',
    'audit': 'risk_scoring_last_audit_id',
    'sweep': 'risk_scoring_last_sweep_cmd_id',
}

def _get_risk_marks(conn):
    marks = {}
    for name, key in _RISK_MARK_KEYS.items():
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        try:
            marks[name] = int(row['value']) if row and row['value'] else 0
        except (TypeError, ValueError):
            marks[name] = 0
    return marks

def _save_risk_marks(conn, marks):
    for name, key in _RISK_MARK_KEYS.items():
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(marks[name])))

# Both host and username get scored independently from the same alert -- an alert is
# relevant to both entities' risk posture, the same way the existing volume-baseline
# model already treats host and user as independently-modeled entity types from the
# same live_logs stream.
def _score_alerts(conn, cfg, last_id):
    rows = conn.execute("SELECT id, host, username, severity, rule_name, source_ip, destination_ip FROM alerts WHERE id > ?", (last_id,)).fetchall()
    events, max_id = [], last_id
    if not rows:
        return events, max_id
    rules = _load_anomaly_rules(conn, 'alerts')
    for r in rows:
        max_id = max(max_id, r['id'])
        pts = cfg['points'].get(f"alert_{(r['severity'] or '').lower()}", cfg['points']['alert_medium'])
        detail = f"{r['rule_name'] or 'Sigma alert'} ({r['severity'] or 'unknown'})"
        for entity_type, entity_id in (('host', r['host']), ('user', r['username'])):
            if not entity_id or entity_id in ('', '-', 'UNKNOWN'):
                continue
            events.append((entity_type, entity_id, 'sigma_alert', pts, detail, 'alerts', str(r['id'])))
        # Custom alert rules add on top of the flat severity score above rather than
        # replace it -- a noteworthy pattern (e.g. a specific rule_name) can be weighted
        # heavier without changing how every other alert of the same severity scores.
        for rule in rules:
            if not _rule_matches(rule, r):
                continue
            entity_id = r[rule['entity_field']]
            if not entity_id:
                continue
            events.append((rule['entity_type'], entity_id, 'custom_alert_rule', rule['points'],
                           f"Matched rule '{rule['name']}'", 'alerts', str(r['id'])))
            if rule['first_time_bonus_points'] and not _rule_ever_matched_before(conn, 'alerts', rule, entity_id, r['id']):
                events.append((rule['entity_type'], entity_id, 'first_time_action', rule['first_time_bonus_points'],
                               f"First match of rule '{rule['name']}' by this entity", 'alerts', str(r['id'])))
    return events, max_id

# Anomaly rules don't cover audit_log for now (Sigma alerts only) -- this indicator
# stays a flat, hardcoded failed-login counter rather than a rule-engine consumer.
def _score_audit(conn, cfg, last_id):
    rows = conn.execute("SELECT id, action, target_id FROM audit_log WHERE id > ? AND action = 'login_failed'", (last_id,)).fetchall()
    events, max_id = [], last_id
    for r in rows:
        max_id = max(max_id, r['id'])
        actor = r['target_id'] or '(unknown)'
        events.append(('user', actor, 'failed_login', cfg['points']['failed_login'], 'Failed login attempt', 'audit_log', str(r['id'])))
    return events, max_id

def _score_sweeps(conn, cfg, last_id):
    rows = conn.execute(
        "SELECT id, hostname, stdout FROM agent_commands WHERE id > ? AND label IN ('ioc_sweep','string_sweep') AND status = 'done'",
        (last_id,)
    ).fetchall()
    events, max_id = [], last_id
    for r in rows:
        max_id = max(max_id, r['id'])
        try:
            hits = (json.loads(r['stdout'] or '{}') or {}).get('hits') or []
        except (json.JSONDecodeError, TypeError):
            hits = []
        if not hits:
            continue
        events.append(('host', r['hostname'], 'ioc_sweep_hit', cfg['points']['sweep_hit'],
                       f"{len(hits)} IOC match(es) found in a sweep", 'agent_commands', str(r['id'])))
    return events, max_id

def run_risk_scoring():
    cfg = get_risk_score_config()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        marks = _get_risk_marks(conn)
        alert_events, marks['alert'] = _score_alerts(conn, cfg, marks['alert'])
        audit_events, marks['audit'] = _score_audit(conn, cfg, marks['audit'])
        sweep_events, marks['sweep'] = _score_sweeps(conn, cfg, marks['sweep'])
        all_events = alert_events + audit_events + sweep_events
        if all_events:
            conn.executemany(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id) VALUES (?,?,?,?,?,?,?)",
                all_events
            )
        _save_risk_marks(conn, marks)
        conn.commit()
    except Exception as e:
        print(f"[-] Risk scoring run failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    run_ueba_models()
    run_risk_scoring()
