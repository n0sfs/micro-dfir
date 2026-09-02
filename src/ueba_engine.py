import copy, os, json, sqlite3, duckdb, math
DB_PATH = "/opt/micro-dfir/siem.db"
# Mirrors app.py's _PRIORITY_TIERS['critical'] (0-10 normalized priority_score scale,
# fixed by construction, not admin-configurable) -- duplicated here since this standalone
# cron script has no shared import with app.py, same as UEBA_DEFAULTS below. Used only to
# let run_autocase_check() also trigger on priority_score reaching Critical, independent
# of the raw-sum threshold.
_PRIORITY_TIER_CRITICAL = 7.5
UEBA_DEFAULTS = {
    'ueba_lookback_days': 30, 'ueba_stddev_multiplier': 3.0, 'ueba_min_baseline': 50.0,
    'ueba_min_days_observed': 4, 'ueba_new_ip_enabled': 1,
    'ueba_new_process_enabled': 1, 'ueba_new_dest_ip_enabled': 1,
    'ueba_process_lineage_enabled': 1, 'ueba_off_hours_enabled': 1,
    'ueba_rare_process_enabled': 1, 'ueba_rare_process_max_hosts': 2,
    'ueba_convergence_enabled': 1, 'ueba_convergence_min_indicators': 3,
    'ueba_convergence_window_hours': 24,
    'ueba_sequence_chain_enabled': 1, 'ueba_sequence_chain_window_hours': 24,
    'ueba_priority_enabled': 1, 'ueba_priority_window_days': 30, 'ueba_priority_half_life_hours': 24,
    'ueba_autocase_enabled': 0, 'ueba_autocase_threshold': 80, 'ueba_autocase_template_id': None,
    'ueba_autocase_cooldown_hours': 24,
}

# The 3-way blend weights and normalization caps below are a scoring heuristic, not a
# per-admin tunable -- unlike the flat UEBA_DEFAULTS keys above, exposing 6 more knobs
# for a blended score most admins will never want to hand-tune wasn't worth the added
# Settings-UI surface. PRIORITY_PEAK_CAP matches RISK_SCORE_DEFAULTS['points']['alert_critical']
# (the highest point value any single indicator can carry) so a lone critical alert
# alone maxes out the peak-severity component.
PRIORITY_PEAK_CAP = 40
PRIORITY_BREADTH_CAP = 5
PRIORITY_DECAY_CAP = 80
PRIORITY_WEIGHT_PEAK = 0.4
PRIORITY_WEIGHT_BREADTH = 0.3
PRIORITY_WEIGHT_DECAY = 0.3
# decay_score sums points*exp(-hours_ago/half_life) per event -- each individual old
# event's weight goes to ~0, but summed over enough of them a large-enough historical
# volume (a since-resolved alert-storm incident, days later) can still add up to more
# than PRIORITY_DECAY_CAP, saturating decay_norm at 10 -- fully "current" -- purely from
# stale volume, defeating the whole point of decay. Capping how many events feed the sum
# (the MOST RECENT N, not a random/arbitrary subset) bounds worst-case stale-volume
# contribution to a negligible amount while a genuine current incident -- which by
# definition produces its alerts recently -- still has its full recent event set well
# under this cap and reaches the same decay_norm ceiling it always would.
PRIORITY_DECAY_EVENT_CAP = 200

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
        'new_process': 20, 'new_destination_ip': 15, 'process_lineage': 25, 'off_hours_activity': 10,
        'rare_process_population': 18,
        'multi_signal_convergence': 30,
        'sequence_chain_progression': 15,
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

def _condition_matches(condition, row):
    if condition['field'] not in row.keys():
        return False
    row_value = row[condition['field']]
    row_value = '' if row_value is None else str(row_value)
    target = condition['value'] or ''
    op = condition['operator']
    if op == 'equals':
        return row_value == target
    if op == 'not_equals':
        return row_value != target
    if op == 'contains':
        return target.lower() in row_value.lower()
    if op == 'starts_with':
        return row_value.lower().startswith(target.lower())
    if op == 'ends_with':
        return row_value.lower().endswith(target.lower())
    return False

# Conditions combine left-to-right via each condition's own logic (AND/OR) -- e.g.
# "severity equals Critical" + "rule_name contains Mimikatz" (logic=AND) requires both;
# swapping that second condition's logic to OR means either alone is enough. There is
# no operator precedence or parenthesized grouping: each condition folds strictly onto
# the running result of everything before it, left to right (A AND B OR C means
# (A AND B) OR C, not A AND (B OR C)). The first condition's own logic value is stored
# but ignored -- nothing precedes it to combine with. A rule with no conditions at all
# never matches (safe default, not "matches everything").
def _rule_matches_all(conditions, row):
    if not conditions:
        return False
    result = _condition_matches(conditions[0], row)
    for c in conditions[1:]:
        if (c.get('logic') or 'AND').upper() == 'OR':
            result = result or _condition_matches(c, row)
        else:
            result = result and _condition_matches(c, row)
    return result

def _load_anomaly_rules(conn, source):
    allowed = ANOMALY_RULE_SOURCES.get(source)
    if not allowed:
        return []
    rows = conn.execute(
        "SELECT id, name, entity_field, entity_type, points, first_time_bonus_points, sequence_name, sequence_stage "
        "FROM anomaly_rules WHERE source = ? AND enabled = 1",
        (source,)
    ).fetchall()
    rules = []
    for r in rows:
        if r['entity_field'] not in allowed['entity_fields']:
            continue
        cond_rows = conn.execute(
            "SELECT field, operator, value, logic FROM anomaly_rule_conditions WHERE rule_id = ?", (r['id'],)
        ).fetchall()
        conditions = [dict(c) for c in cond_rows]
        # Defense in depth: every condition's field must be in this source's allowlist.
        # A rule with any invalid condition is excluded entirely rather than silently
        # dropping just that one condition, which would weaken an AND into something
        # looser than what was actually configured (and, for entity_field elsewhere,
        # is exactly the check that keeps a stored value safe to interpolate into SQL).
        if not conditions or any(c['field'] not in allowed['fields'] for c in conditions):
            continue
        rule = dict(r)
        rule['conditions'] = conditions
        rules.append(rule)
    return rules

# "Is this normal for THIS entity" for a custom rule: has this exact rule (all of its
# conditions, AND-combined) ever matched for this entity before (anywhere in the source
# table's history, not just the current scoring window)? Generalizes the old fixed
# "same username + same action" check to any rule condition, so a first occurrence --
# not just a first-time action -- earns the bonus.
def _rule_ever_matched_before(conn, table, rule, entity_id, before_id):
    prior_rows = conn.execute(
        f"SELECT * FROM {table} WHERE {rule['entity_field']} = ? AND id < ?", (entity_id, before_id)
    ).fetchall()
    return any(_rule_matches_all(rule['conditions'], pr) for pr in prior_rows)

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
        'new_process_enabled': str(cfg['ueba_new_process_enabled']) not in ('0', 'false', 'False'),
        'new_dest_ip_enabled': str(cfg['ueba_new_dest_ip_enabled']) not in ('0', 'false', 'False'),
        'process_lineage_enabled': str(cfg['ueba_process_lineage_enabled']) not in ('0', 'false', 'False'),
        'off_hours_enabled': str(cfg['ueba_off_hours_enabled']) not in ('0', 'false', 'False'),
        'rare_process_enabled': str(cfg['ueba_rare_process_enabled']) not in ('0', 'false', 'False'),
        'rare_process_max_hosts': max(1, min(50, int(cfg['ueba_rare_process_max_hosts']))),
        'convergence_enabled': str(cfg['ueba_convergence_enabled']) not in ('0', 'false', 'False'),
        'convergence_min_indicators': max(2, min(10, int(cfg['ueba_convergence_min_indicators']))),
        'convergence_window_hours': max(1, min(168, int(cfg['ueba_convergence_window_hours']))),
        'sequence_chain_enabled': str(cfg['ueba_sequence_chain_enabled']) not in ('0', 'false', 'False'),
        'sequence_chain_window_hours': max(1, min(168, int(cfg['ueba_sequence_chain_window_hours']))),
        'priority_enabled': str(cfg['ueba_priority_enabled']) not in ('0', 'false', 'False'),
        'priority_window_days': max(1, min(365, int(cfg['ueba_priority_window_days']))),
        'priority_half_life_hours': max(1.0, float(cfg['ueba_priority_half_life_hours'])),
        'autocase_enabled': str(cfg['ueba_autocase_enabled']) not in ('0', 'false', 'False'),
        'autocase_threshold': max(1, int(cfg['ueba_autocase_threshold'])),
        'autocase_template_id': int(cfg['ueba_autocase_template_id']) if str(cfg.get('ueba_autocase_template_id') or '') not in ('', 'None') else None,
        'autocase_cooldown_hours': max(1, int(cfg['ueba_autocase_cooldown_hours'])),
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
#
# entity_days gates this on cfg['min_days_observed'] -- the same confidence threshold
# the volume model already uses -- so a user with only 1-2 days of any history doesn't
# get every one of their early source IPs flagged as "new" just because their own
# baseline is still too thin to know what's actually normal for them yet.
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
        "      AND source_ip IS NOT NULL AND source_ip NOT IN ('', '-') GROUP BY 1, 2), "
        "entity_days AS (SELECT username as entity_id, COUNT(DISTINCT date_trunc('day', CAST(timestamp AS TIMESTAMP))) as days_seen "
        f"    FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND username IS NOT NULL AND username NOT IN ('', '-') GROUP BY 1) "
        "SELECT tp.username, tp.source_ip, tp.c FROM today_pairs tp "
        "LEFT JOIN known k ON tp.username = k.username AND tp.source_ip = k.source_ip "
        "JOIN entity_days ed ON tp.username = ed.entity_id "
        f"WHERE k.username IS NULL AND ed.days_seen >= {cfg['min_days_observed']} LIMIT 200"
    )
    return [{'username': u, 'source_ip': ip, 'count': c} for u, ip, c in con.execute(query).fetchall()]

# Same "known pair vs today's pairs" shape as _run_new_source_ip_model above, just keyed
# on (host, process_image) instead of (username, source_ip) -- flags a host running a
# process it's never run before in the lookback window. Host-only (not per-user) since
# process_image comes from live_logs, which agent-sourced rows populate reliably but
# syslog-sourced rows never do at all.
def _run_new_process_model(con, cfg):
    if not cfg['new_process_enabled']:
        return []
    query = (
        "WITH known AS (SELECT DISTINCT host, process_image FROM siem.live_logs "
        f"    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') "
        "      AND process_image IS NOT NULL AND process_image != ''), "
        "today_pairs AS (SELECT host, process_image, count(*) as c, any_value(command_line) as command_line FROM siem.live_logs "
        "    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') "
        "      AND process_image IS NOT NULL AND process_image != '' GROUP BY 1, 2), "
        "entity_days AS (SELECT host as entity_id, COUNT(DISTINCT date_trunc('day', CAST(timestamp AS TIMESTAMP))) as days_seen "
        f"    FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') GROUP BY 1) "
        "SELECT tp.host, tp.process_image, tp.c, tp.command_line FROM today_pairs tp "
        "LEFT JOIN known k ON tp.host = k.host AND tp.process_image = k.process_image "
        "JOIN entity_days ed ON tp.host = ed.entity_id "
        f"WHERE k.host IS NULL AND ed.days_seen >= {cfg['min_days_observed']} LIMIT 200"
    )
    return [{'host': h, 'process_image': p, 'count': c, 'command_line': cl} for h, p, c, cl in con.execute(query).fetchall()]

# Same shape again, keyed on (host, destination_ip) -- a host reaching a destination it
# has never contacted before in the lookback window (first-contact / lateral-movement
# signal), independent of and complementary to the source-IP model above.
def _run_new_destination_ip_model(con, cfg):
    if not cfg['new_dest_ip_enabled']:
        return []
    query = (
        "WITH known AS (SELECT DISTINCT host, destination_ip FROM siem.live_logs "
        f"    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') "
        "      AND destination_ip IS NOT NULL AND destination_ip NOT IN ('', '-')), "
        "today_pairs AS (SELECT host, destination_ip, count(*) as c FROM siem.live_logs "
        "    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') "
        "      AND destination_ip IS NOT NULL AND destination_ip NOT IN ('', '-') GROUP BY 1, 2), "
        "entity_days AS (SELECT host as entity_id, COUNT(DISTINCT date_trunc('day', CAST(timestamp AS TIMESTAMP))) as days_seen "
        f"    FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') GROUP BY 1) "
        "SELECT tp.host, tp.destination_ip, tp.c FROM today_pairs tp "
        "LEFT JOIN known k ON tp.host = k.host AND tp.destination_ip = k.destination_ip "
        "JOIN entity_days ed ON tp.host = ed.entity_id "
        f"WHERE k.host IS NULL AND ed.days_seen >= {cfg['min_days_observed']} LIMIT 200"
    )
    return [{'host': h, 'destination_ip': ip, 'count': c} for h, ip, c in con.execute(query).fetchall()]

# Same shape a third time, keyed on the (host, parent_image, process_image) triple -- a
# process-ancestry pairing never seen on that host before (e.g. winword.exe spawning
# powershell.exe for the first time). A well-known DFIR pattern; only buildable now that
# both process_image and parent_image are captured (see last session's ingest work).
def _run_process_lineage_model(con, cfg):
    if not cfg['process_lineage_enabled']:
        return []
    query = (
        "WITH known AS (SELECT DISTINCT host, parent_image, process_image FROM siem.live_logs "
        f"    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') "
        "      AND parent_image IS NOT NULL AND parent_image != '' "
        "      AND process_image IS NOT NULL AND process_image != ''), "
        "today_pairs AS (SELECT host, parent_image, process_image, count(*) as c, any_value(command_line) as command_line, "
        "    any_value(parent_command_line) as parent_command_line FROM siem.live_logs "
        "    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') "
        "      AND parent_image IS NOT NULL AND parent_image != '' "
        "      AND process_image IS NOT NULL AND process_image != '' GROUP BY 1, 2, 3), "
        "entity_days AS (SELECT host as entity_id, COUNT(DISTINCT date_trunc('day', CAST(timestamp AS TIMESTAMP))) as days_seen "
        f"    FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') GROUP BY 1) "
        "SELECT tp.host, tp.parent_image, tp.process_image, tp.c, tp.command_line, tp.parent_command_line FROM today_pairs tp "
        "LEFT JOIN known k ON tp.host = k.host AND tp.parent_image = k.parent_image AND tp.process_image = k.process_image "
        "JOIN entity_days ed ON tp.host = ed.entity_id "
        f"WHERE k.host IS NULL AND ed.days_seen >= {cfg['min_days_observed']} LIMIT 200"
    )
    return [{'host': h, 'parent_image': pi, 'process_image': p, 'count': c, 'command_line': cl, 'parent_command_line': pcl}
            for h, pi, p, c, cl, pcl in con.execute(query).fetchall()]

# A different shape from the 3 pair-based models above: per entity (host/user, reusing
# ENTITY_MODELS), a 24-hour x 7-day-of-week histogram baseline per (entity, dow, hr)
# cell -- median/MAD over that cell's own history, same statistic _run_model already
# uses for the daily-volume signal, just one dimension finer. Replaced the original
# binary "seen this hour before, yes/no" version: that check collapsed day-of-week
# entirely (an hour's first-ever occurrence, on ANY day, permanently whitelisted it for
# the rest of the lookback window), so it under-detected genuinely day-specific anomalies
# -- e.g. a user's first-ever weekend activity at an hour that's completely normal on
# weekdays was invisible to it.
#
# A cell with fewer than min_days_observed same-(dow,hr) samples -- including a cell
# with ZERO samples, i.e. an hour this entity has truly never been active in on this
# day of week -- falls back to a flat per-entity baseline (typical hourly count,
# pooling every (day, hour) sample regardless of which day or hour) rather than either
# always-flagging (a hair-trigger on any first-time hour) or never-flagging (silently
# accepting it). A genuinely novel hour still gets compared against something -- just a
# coarser something -- instead of an automatic pass/fail.
def _run_off_hours_model(con, cfg):
    if not cfg['off_hours_enabled']:
        return []
    out = []
    for model in ENTITY_MODELS:
        entity_type, col, extra_filter = model['entity_type'], model['column'], model['extra_filter']
        query = (
            f"WITH cell AS (SELECT {col} as entity_id, "
            f"    CAST(date_part('dow', CAST(timestamp AS TIMESTAMP)) AS INTEGER) as dow, "
            f"    CAST(date_part('hour', CAST(timestamp AS TIMESTAMP)) AS INTEGER) as hr, "
            f"    date_trunc('day', CAST(timestamp AS TIMESTAMP)) as day, count(*) as c "
            f"    FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
            f"      AND CAST(timestamp AS TIMESTAMP) < CURRENT_DATE AND {extra_filter} GROUP BY 1, 2, 3, 4), "
            "cell_stats AS (SELECT entity_id, dow, hr, median(c) as med_c, count(*) as days_seen FROM cell GROUP BY 1, 2, 3), "
            "cell_mad AS (SELECT c.entity_id, c.dow, c.hr, median(abs(c.c - s.med_c)) as mad_c "
            "    FROM cell c JOIN cell_stats s ON c.entity_id = s.entity_id AND c.dow = s.dow AND c.hr = s.hr GROUP BY 1, 2, 3), "
            "flat_stats AS (SELECT entity_id, median(c) as med_c, count(*) as days_seen FROM cell GROUP BY 1), "
            "flat_mad AS (SELECT c.entity_id, median(abs(c.c - s.med_c)) as mad_c "
            "    FROM cell c JOIN flat_stats s ON c.entity_id = s.entity_id GROUP BY 1), "
            f"today AS (SELECT {col} as entity_id, "
            f"    CAST(date_part('hour', CAST(timestamp AS TIMESTAMP)) AS INTEGER) as hr, count(*) as cur_c "
            f"    FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE AND {extra_filter} GROUP BY 1, 2) "
            "SELECT t.entity_id, t.hr, t.cur_c, "
            f"    COALESCE(CASE WHEN cs.days_seen >= {cfg['min_days_observed']} THEN cs.med_c END, fs.med_c) as med_c, "
            f"    COALESCE(CASE WHEN cs.days_seen >= {cfg['min_days_observed']} THEN cm.mad_c END, fm.mad_c) as mad_c, "
            f"    COALESCE(CASE WHEN cs.days_seen >= {cfg['min_days_observed']} THEN cs.days_seen END, fs.days_seen, 0) as days_seen, "
            f"    CASE WHEN cs.days_seen >= {cfg['min_days_observed']} THEN 'cell' ELSE 'flat' END as baseline_mode "
            "FROM today t "
            f"LEFT JOIN cell_stats cs ON t.entity_id = cs.entity_id AND t.hr = cs.hr AND cs.dow = CAST(date_part('dow', CURRENT_DATE) AS INTEGER) "
            "LEFT JOIN cell_mad cm ON cs.entity_id = cm.entity_id AND cs.dow = cm.dow AND cs.hr = cm.hr "
            "LEFT JOIN flat_stats fs ON t.entity_id = fs.entity_id "
            "LEFT JOIN flat_mad fm ON t.entity_id = fm.entity_id "
            "LIMIT 2000"
        )
        # Threshold comparison happens here rather than in SQL: it needs med_c/mad_c,
        # which are only resolved after the cell-vs-flat fallback above, and doing that
        # CASE logic a second time in a WHERE clause would just duplicate it verbatim.
        for entity_id, hr, cur_c, med_c, mad_c, days_seen, baseline_mode in con.execute(query).fetchall():
            if med_c is None or days_seen < cfg['min_days_observed']:
                continue
            spread = (mad_c or 0) / MAD_TO_STDDEV
            threshold = med_c + (cfg['stddev_multiplier'] * spread)
            if cur_c <= threshold:
                continue
            out.append({
                'entity_type': entity_type, 'entity_id': entity_id, 'hour': hr, 'count': cur_c,
                'baseline_avg': round(med_c, 1), 'baseline_stddev': round(spread, 1),
                'days_seen': days_seen, 'baseline_mode': baseline_mode,
            })
    return out

# Complements _run_new_process_model above rather than duplicating it: that model
# asks "has THIS HOST ever run this process before" (needs the host's own history to
# have built up first); this one asks "how many hosts fleet-wide ever run this process
# at all" -- catches something rare across the whole environment even on a host with
# plenty of its own baseline (e.g. a well-established host quietly running a tool that
# no other host touches). host_counts intentionally includes today's activity in the
# denominator -- this is a population-rarity measure, not a first-time-seen check, so
# there's no known-vs-today split the way the pair-based models above have.
#
# Grouped/joined on lower(process_image) rather than the raw path -- confirmed in
# production that the exact same binary gets logged with different drive-letter casing
# depending on source (e.g. "C:\Windows\..." from one channel vs "C:\WINDOWS\..." from
# another), which without normalization silently split one real file into two separate
# "rare process" hits. The displayed process_image still comes from today_hosts (the
# actual casing seen on that host today), so this only affects grouping, not display.
def _run_rare_process_population_model(con, cfg):
    if not cfg['rare_process_enabled']:
        return []
    # "Rare" only means something relative to a real population to be a minority
    # within. With too few hosts reporting at all, host_count <= rare_process_max_hosts
    # is trivially true for EVERY process on EVERY host (there's no larger population
    # to contrast against), so a 1-2-host lab/small-fleet deployment would otherwise
    # get flooded with meaningless "rare process" noise for completely ordinary system
    # processes (svchost.exe, conhost.exe, ...) instead of real outlier signal. Require
    # the total population to actually exceed the rarity cutoff before flagging anyone
    # as a minority within it.
    total_hosts = con.execute(
        "SELECT COUNT(DISTINCT host) FROM siem.live_logs "
        f"WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "  AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN')"
    ).fetchone()[0]
    if total_hosts <= cfg['rare_process_max_hosts']:
        return []
    query = (
        "WITH host_counts AS (SELECT lower(process_image) as process_key, COUNT(DISTINCT host) as host_count FROM siem.live_logs "
        f"    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY "
        "      AND process_image IS NOT NULL AND process_image != '' "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') GROUP BY 1), "
        "today_hosts AS (SELECT host, process_image, lower(process_image) as process_key, any_value(command_line) as command_line "
        "    FROM siem.live_logs "
        "    WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE "
        "      AND process_image IS NOT NULL AND process_image != '' "
        "      AND host IS NOT NULL AND host NOT IN ('', 'UNKNOWN') GROUP BY 1, 2, 3) "
        "SELECT th.host, th.process_image, hc.host_count, th.command_line FROM today_hosts th "
        "JOIN host_counts hc ON th.process_key = hc.process_key "
        f"WHERE hc.host_count <= {cfg['rare_process_max_hosts']} LIMIT 200"
    )
    return [{'host': h, 'process_image': p, 'host_count': hc, 'command_line': cl} for h, p, hc, cl in con.execute(query).fetchall()]

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
        new_process_hits = _run_new_process_model(con, cfg)
        new_dest_ip_hits = _run_new_destination_ip_model(con, cfg)
        lineage_hits = _run_process_lineage_model(con, cfg)
        off_hours_hits = _run_off_hours_model(con, cfg)
        rare_process_hits = _run_rare_process_population_model(con, cfg)
        con.close()
    except Exception as e:
        print(f"[-] UEBA model run failed: {e}")
        return

    for r in all_rows:
        r['excluded'] = (r['entity_type'], r['entity_id']) in excluded
    new_ip_hits = [h for h in new_ip_hits if ('user', h['username']) not in excluded]
    new_process_hits = [h for h in new_process_hits if ('host', h['host']) not in excluded]
    new_dest_ip_hits = [h for h in new_dest_ip_hits if ('host', h['host']) not in excluded]
    lineage_hits = [h for h in lineage_hits if ('host', h['host']) not in excluded]
    off_hours_hits = [h for h in off_hours_hits if (h['entity_type'], h['entity_id']) not in excluded]
    rare_process_hits = [h for h in rare_process_hits if ('host', h['host']) not in excluded]

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
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                (r['entity_type'], r['entity_id'], 'volume_anomaly', pts, message, 'ueba_entity_baselines', None, None)
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
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                ('user', h['username'], 'new_source_ip', risk_cfg['points']['new_source_ip'], message, 'events', None, None)
            )
        for h in new_process_hits:
            cmd_note = f" Command line: {h['command_line']}" if h.get('command_line') else ""
            message = (f"{h['host']} (host) executed a process never seen on this host before in the past "
                       f"{cfg['lookback_days']} days: {h['process_image']} ({h['count']} times today).{cmd_note}")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, 'host', 'duckdb_ueba', 'Medium', ?, ?)",
                (h['host'], message, json.dumps({**h, 'detection_type': 'new_process'}))
            )
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                ('host', h['host'], 'new_process', risk_cfg['points']['new_process'], message, 'events', None, None)
            )
        for h in new_dest_ip_hits:
            message = (f"{h['host']} (host) connected to a destination IP never seen from this host before in the past "
                       f"{cfg['lookback_days']} days: {h['destination_ip']} ({h['count']} events today).")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, 'host', 'duckdb_ueba', 'Medium', ?, ?)",
                (h['host'], message, json.dumps({**h, 'detection_type': 'new_destination_ip'}))
            )
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                ('host', h['host'], 'new_destination_ip', risk_cfg['points']['new_destination_ip'], message, 'events', None, None)
            )
        for h in lineage_hits:
            cmd_note = f" Command line: {h['command_line']}" if h.get('command_line') else ""
            message = (f"{h['host']} (host) had a process relationship never seen before in the past {cfg['lookback_days']} days: "
                       f"{h['parent_image']} spawned {h['process_image']} ({h['count']} times today).{cmd_note}")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, 'host', 'duckdb_ueba', 'High', ?, ?)",
                (h['host'], message, json.dumps({**h, 'detection_type': 'process_lineage'}))
            )
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                ('host', h['host'], 'process_lineage', risk_cfg['points']['process_lineage'], message, 'events', None, None)
            )
        for h in off_hours_hits:
            label = 'host' if h['entity_type'] == 'host' else 'user'
            basis = f"same-hour-of-week baseline of {h['baseline_avg']} (±{h['baseline_stddev']}, {h['days_seen']} weeks observed)" \
                if h['baseline_mode'] == 'cell' else \
                f"overall hourly baseline of {h['baseline_avg']} (±{h['baseline_stddev']}, {h['days_seen']} days observed — not enough same-hour-of-week history yet)"
            message = (f"{h['entity_id']} ({label}) was active at {h['hour']:02d}:00 with {h['count']} event(s), "
                       f"exceeding its {basis}.")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, ?, 'duckdb_ueba', 'Medium', ?, ?)",
                (h['entity_id'], h['entity_type'], message, json.dumps({**h, 'detection_type': 'off_hours_activity'}))
            )
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                (h['entity_type'], h['entity_id'], 'off_hours_activity', risk_cfg['points']['off_hours_activity'], message, 'events', None, None)
            )
        for h in rare_process_hits:
            cmd_note = f" Command line: {h['command_line']}" if h.get('command_line') else ""
            message = (f"{h['host']} (host) is running a process rare across the whole fleet -- seen on only "
                       f"{h['host_count']} host(s) in the past {cfg['lookback_days']} days: {h['process_image']}.{cmd_note}")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, 'host', 'duckdb_ueba', 'Medium', ?, ?)",
                (h['host'], message, json.dumps({**h, 'detection_type': 'rare_process_population'}))
            )
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                ('host', h['host'], 'rare_process_population', risk_cfg['points']['rare_process_population'], message, 'events', None, None)
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

# A sequence-aware sibling to run_convergence_scoring() below: that one rewards ANY N
# distinct signal types converging, order-blind. This rewards a SPECIFIC admin-defined
# ordered progression -- two or more anomaly_rules sharing a sequence_name, each at a
# distinct sequence_stage -- escalating rather than flat, since reaching stage 3 of a
# real attack chain is a stronger signal than reaching stage 2. Only fires once per
# (entity, rule) thanks to the rule_id dedup check below, so re-matching the same stage
# repeatedly doesn't restack the bonus.
def _sequence_chain_bonus_event(conn, risk_cfg, ueba_cfg, rule, entity_type, entity_id, alert_id):
    if not ueba_cfg['sequence_chain_enabled'] or not rule.get('sequence_name') or not rule.get('sequence_stage'):
        return None
    stage = rule['sequence_stage']
    if stage <= 1:
        return None  # stage 1 is the entry point into the chain, nothing earlier to progress from
    window = f"-{ueba_cfg['sequence_chain_window_hours']} hours"
    earlier_stage = conn.execute(
        "SELECT MAX(ar.sequence_stage) as max_stage FROM risk_score_events rse "
        "JOIN anomaly_rules ar ON ar.id = rse.rule_id "
        "WHERE rse.entity_type = ? AND rse.entity_id = ? AND ar.sequence_name = ? "
        "AND ar.sequence_stage < ? AND rse.computed_at >= datetime('now', ?)",
        (entity_type, entity_id, rule['sequence_name'], stage, window)
    ).fetchone()
    if not earlier_stage or earlier_stage['max_stage'] is None:
        return None
    already = conn.execute(
        "SELECT COUNT(*) FROM risk_score_events WHERE entity_type = ? AND entity_id = ? "
        "AND indicator = 'sequence_chain_progression' AND rule_id = ? AND computed_at >= datetime('now', ?)",
        (entity_type, entity_id, rule['id'], window)
    ).fetchone()[0]
    if already:
        return None
    bonus = risk_cfg['points']['sequence_chain_progression'] * (stage - 1)
    detail = f"Sequence '{rule['sequence_name']}' progressed to stage {stage} ('{rule['name']}') within {ueba_cfg['sequence_chain_window_hours']}h"
    return (entity_type, entity_id, 'sequence_chain_progression', bonus, detail, 'alerts', str(alert_id), rule['id'])

# Both host and username get scored independently from the same alert -- an alert is
# relevant to both entities' risk posture, the same way the existing volume-baseline
# model already treats host and user as independently-modeled entity types from the
# same live_logs stream.
def _score_alerts(conn, cfg, ueba_cfg, last_id):
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
            events.append((entity_type, entity_id, 'sigma_alert', pts, detail, 'alerts', str(r['id']), None))
        # Custom alert rules add on top of the flat severity score above rather than
        # replace it -- a noteworthy pattern (e.g. a specific rule_name) can be weighted
        # heavier without changing how every other alert of the same severity scores.
        for rule in rules:
            if not _rule_matches_all(rule['conditions'], r):
                continue
            entity_id = r[rule['entity_field']]
            if not entity_id:
                continue
            events.append((rule['entity_type'], entity_id, 'custom_alert_rule', rule['points'],
                           f"Matched rule '{rule['name']}'", 'alerts', str(r['id']), rule['id']))
            if rule['first_time_bonus_points'] and not _rule_ever_matched_before(conn, 'alerts', rule, entity_id, r['id']):
                events.append((rule['entity_type'], entity_id, 'first_time_action', rule['first_time_bonus_points'],
                               f"First match of rule '{rule['name']}' by this entity", 'alerts', str(r['id']), rule['id']))
            chain_event = _sequence_chain_bonus_event(conn, cfg, ueba_cfg, rule, rule['entity_type'], entity_id, r['id'])
            if chain_event:
                events.append(chain_event)
    return events, max_id

# Anomaly rules don't cover audit_log for now (Sigma alerts only) -- this indicator
# stays a flat, hardcoded failed-login counter rather than a rule-engine consumer.
def _score_audit(conn, cfg, last_id):
    rows = conn.execute("SELECT id, action, target_id FROM audit_log WHERE id > ? AND action = 'login_failed'", (last_id,)).fetchall()
    events, max_id = [], last_id
    for r in rows:
        max_id = max(max_id, r['id'])
        actor = r['target_id'] or '(unknown)'
        events.append(('user', actor, 'failed_login', cfg['points']['failed_login'], 'Failed login attempt', 'audit_log', str(r['id']), None))
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
                       f"{len(hits)} IOC match(es) found in a sweep", 'agent_commands', str(r['id']), None))
    return events, max_id

def run_risk_scoring():
    cfg = get_risk_score_config()
    ueba_cfg = get_ueba_config()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        marks = _get_risk_marks(conn)
        alert_events, marks['alert'] = _score_alerts(conn, cfg, ueba_cfg, marks['alert'])
        audit_events, marks['audit'] = _score_audit(conn, cfg, marks['audit'])
        sweep_events, marks['sweep'] = _score_sweeps(conn, cfg, marks['sweep'])
        all_events = alert_events + audit_events + sweep_events
        if all_events:
            conn.executemany(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                all_events
            )
        _save_risk_marks(conn, marks)
        conn.commit()
    except Exception as e:
        print(f"[-] Risk scoring run failed: {e}")
    finally:
        conn.close()

# One slightly abnormal event alone shouldn't read as high-confidence -- but an entity
# that trips several genuinely DIFFERENT detection mechanisms close together (a Sigma
# alert AND a new-process hit AND an off-hours flag, say) is a materially stronger
# signal than any one of those alone. This runs last, after both run_ueba_models() and
# run_risk_scoring() have written this cycle's indicators, since it needs the full
# picture across both alert-based and model-based risk_score_events to see a
# convergence at all. Inspired by Splunk's risk-based-alerting (many low-weight "risk
# events" promoted to one high-fidelity "risk notable") and Exabeam's model-confidence
# gating -- see this session's architecture research.
def run_convergence_scoring():
    cfg = get_ueba_config()
    if not cfg['convergence_enabled']:
        return
    risk_cfg = get_risk_score_config()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        window = f"-{cfg['convergence_window_hours']} hours"
        rows = conn.execute(
            "SELECT entity_type, entity_id, COUNT(DISTINCT indicator) as distinct_indicators, "
            "GROUP_CONCAT(DISTINCT indicator) as indicators FROM risk_score_events "
            "WHERE computed_at >= datetime('now', ?) AND indicator != 'multi_signal_convergence' "
            "GROUP BY entity_type, entity_id HAVING distinct_indicators >= ?",
            (window, cfg['convergence_min_indicators'])
        ).fetchall()
        for r in rows:
            # Dedup: don't stack a second convergence bonus for the same entity while
            # an earlier one from this same window is still standing.
            already = conn.execute(
                "SELECT COUNT(*) FROM risk_score_events WHERE entity_type = ? AND entity_id = ? "
                "AND indicator = 'multi_signal_convergence' AND computed_at >= datetime('now', ?)",
                (r['entity_type'], r['entity_id'], window)
            ).fetchone()[0]
            if already:
                continue
            detail = (f"{r['distinct_indicators']} distinct signal types converged within "
                      f"{cfg['convergence_window_hours']}h: {r['indicators']}")
            conn.execute(
                "INSERT INTO risk_score_events (entity_type, entity_id, indicator, points, detail, source_table, source_id, rule_id) VALUES (?,?,?,?,?,?,?,?)",
                (r['entity_type'], r['entity_id'], 'multi_signal_convergence',
                 risk_cfg['points']['multi_signal_convergence'], detail, 'risk_score_events', None, None)
            )
        conn.commit()
    except Exception as e:
        print(f"[-] Convergence scoring run failed: {e}")
    finally:
        conn.close()

# A second, separate read model over risk_score_events -- not a replacement for the
# Risk Scoring tab's raw cumulative sum, which stays exactly as-is. This blends three
# components into one 0-10 "what to look at first" number: how severe the worst single
# thing was (peak), how many genuinely different detection mechanisms tripped (breadth),
# and how fresh the activity is (exponential decay, half-life below) -- so a diffuse,
# recent, multi-signal entity can outrank a single loud-but-stale alert from weeks ago,
# which the raw sum alone can't express. Runs last, truncate-and-reinsert each cycle
# (same disposable-snapshot pattern as ueba_entity_baselines), over a longer window than
# the Risk Scoring tab's own (30 days here vs. 7) specifically so genuinely old activity
# has room to decay toward zero instead of falling out of the window entirely.
def run_priority_scoring():
    cfg = get_ueba_config()
    if not cfg['priority_enabled']:
        return
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        window = f"-{cfg['priority_window_days']} days"
        rows = conn.execute(
            "SELECT entity_type, entity_id, indicator, points, "
            "(julianday('now') - julianday(computed_at)) * 24 as hours_ago "
            "FROM risk_score_events WHERE computed_at >= datetime('now', ?)",
            (window,)
        ).fetchall()

        by_entity = {}
        for r in rows:
            by_entity.setdefault((r['entity_type'], r['entity_id']), []).append(r)

        half_life = cfg['priority_half_life_hours']
        results = []
        for (entity_type, entity_id), events in by_entity.items():
            distinct_indicators = len({e['indicator'] for e in events})
            peak_points = max(e['points'] for e in events)
            # max(hours_ago, 0) guards against a slightly-in-the-future computed_at
            # (clock skew, or a row inserted mid-transaction) blowing up into a negative
            # exponent, which would make a "future" event dominate the decay sum instead
            # of just contributing full weight like any other very-recent event.
            # Only the most-recent PRIORITY_DECAY_EVENT_CAP events feed the sum -- see
            # the constant's own comment above for why an uncapped sum lets stale volume
            # saturate this score regardless of true recency. peak_points/
            # distinct_indicators intentionally still use the FULL event set: MAX and
            # set-cardinality aren't subject to the same volume-scaling problem a SUM is.
            decay_events = sorted(events, key=lambda e: e['hours_ago'])[:PRIORITY_DECAY_EVENT_CAP]
            decay_score = sum(e['points'] * math.exp(-max(e['hours_ago'], 0) / half_life) for e in decay_events)

            peak_norm = min(peak_points, PRIORITY_PEAK_CAP) / PRIORITY_PEAK_CAP * 10
            breadth_norm = min(distinct_indicators, PRIORITY_BREADTH_CAP) / PRIORITY_BREADTH_CAP * 10
            decay_norm = min(decay_score, PRIORITY_DECAY_CAP) / PRIORITY_DECAY_CAP * 10
            priority = round(
                PRIORITY_WEIGHT_PEAK * peak_norm + PRIORITY_WEIGHT_BREADTH * breadth_norm + PRIORITY_WEIGHT_DECAY * decay_norm, 1
            )
            results.append((entity_type, entity_id, priority, distinct_indicators, peak_points, round(decay_score, 1)))

        conn.execute("DELETE FROM ueba_priority_scores")
        if results:
            conn.executemany(
                "INSERT INTO ueba_priority_scores (entity_type, entity_id, priority_score, distinct_indicators, peak_points, decay_score, computed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                results
            )
        conn.commit()
    except Exception as e:
        print(f"[-] Priority scoring run failed: {e}")
    finally:
        conn.close()

# Unlike sigma_engine.py's alert-triggered auto-case (one clean alert_id to link as a
# case_item), a UEBA risk score is an aggregate over many risk_score_events rows with no
# single natural item to attach -- so the top contributing indicators go straight into
# the case description instead, giving an analyst the same "why did this fire" context
# without forcing a case_items link that doesn't really fit the data shape.
def _auto_create_ueba_case(conn, entity_type, entity_id, score, top_indicators, template_id):
    label = 'Host' if entity_type == 'host' else 'User'
    title = f"High UEBA Risk Score — {entity_id}"
    breakdown = ', '.join(f"{t['indicator']} ({t['pts']} pts)" for t in top_indicators) if top_indicators else 'no breakdown available'
    detail = f"Auto-created because {label.lower()} '{entity_id}' crossed the UEBA auto-case risk threshold (score: {score}). Top contributing signals: {breakdown}."
    conn.execute(
        "INSERT INTO cases (title, status, description, created_by, tlp, pap) VALUES (?, 'open', ?, 'system:auto-case', 'amber', 'amber')",
        (title, detail)
    )
    cid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, 'system', 'created', ?)", (cid, title))
    if template_id:
        tpl = conn.execute("SELECT name, tasks FROM case_templates WHERE id = ?", (template_id,)).fetchone()
        if tpl:
            tasks = json.loads(tpl['tasks'])
            conn.executemany(
                "INSERT INTO case_tasks (case_id, title, position, created_by) VALUES (?, ?, ?, 'system')",
                [(cid, t, i) for i, t in enumerate(tasks)]
            )
            conn.execute("INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, 'system', 'template_applied', ?)", (cid, tpl['name']))
    return cid

# Uses the SAME weighted-score SQL as /api/ueba/risk-scores (app.py) so the number an
# admin sets the threshold against on screen is exactly the number this checks -- see
# that endpoint's comment for why the criticality/privileged multiplier is applied
# inside the query rather than in Python. A ueba_autocase_log row per entity is the only
# dedup guard: an entity that stays above threshold every cycle only gets one case per
# cooldown window, not one every run.
def run_autocase_check():
    cfg = get_ueba_config()
    if not cfg['autocase_enabled']:
        return
    risk_cfg = get_risk_score_config()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        window = f"-{risk_cfg['window_days']} days"
        # Additive OR, not a replacement: the raw-sum threshold stays exactly as it was
        # (every case that already triggers today still triggers, unchanged), with a new
        # condition so an entity whose decay-aware priority_score has independently
        # reached Critical also qualifies -- even if its flat windowed sum hasn't crossed
        # the admin's numeric threshold yet. Same wiring api_ueba_risk_scores/the
        # dashboard's top-risk-entities widget already use for the tier badge itself.
        rows = conn.execute(
            "SELECT rse.entity_type as entity_type, rse.entity_id as entity_id, "
            "ROUND(SUM(rse.points) * COALESCE("
            "    CASE WHEN rse.entity_type = 'host' THEN "
            "        CASE a.criticality WHEN 'critical' THEN 2.0 WHEN 'important' THEN 1.5 ELSE 1.0 END "
            "    WHEN rse.entity_type = 'user' THEN "
            "        CASE WHEN i.privileged = 1 THEN 1.5 ELSE 1.0 END "
            "    END, 1.0), 1) as score, "
            "ps.priority_score as priority_score "
            "FROM risk_score_events rse "
            "LEFT JOIN assets a ON rse.entity_type = 'host' AND rse.entity_id = a.host "
            "LEFT JOIN identities i ON rse.entity_type = 'user' AND rse.entity_id = i.username "
            "LEFT JOIN ueba_priority_scores ps ON rse.entity_type = ps.entity_type AND rse.entity_id = ps.entity_id "
            "WHERE rse.computed_at >= datetime('now', ?) "
            "GROUP BY rse.entity_type, rse.entity_id "
            "HAVING score >= ? OR (ps.priority_score IS NOT NULL AND ps.priority_score >= ?)",
            (window, cfg['autocase_threshold'], _PRIORITY_TIER_CRITICAL)
        ).fetchall()

        cooldown_window = f"-{cfg['autocase_cooldown_hours']} hours"
        for r in rows:
            entity_type, entity_id, score = r['entity_type'], r['entity_id'], r['score']
            recent = conn.execute(
                "SELECT 1 FROM ueba_autocase_log WHERE entity_type = ? AND entity_id = ? AND last_triggered_at >= datetime('now', ?)",
                (entity_type, entity_id, cooldown_window)
            ).fetchone()
            if recent:
                continue
            top = conn.execute(
                "SELECT indicator, SUM(points) as pts FROM risk_score_events WHERE entity_type = ? AND entity_id = ? "
                "AND computed_at >= datetime('now', ?) GROUP BY indicator ORDER BY pts DESC LIMIT 5",
                (entity_type, entity_id, window)
            ).fetchall()
            cid = _auto_create_ueba_case(conn, entity_type, entity_id, score, top, cfg['autocase_template_id'])
            conn.execute(
                "INSERT INTO ueba_autocase_log (entity_type, entity_id, last_triggered_at, case_id) VALUES (?, ?, datetime('now'), ?) "
                "ON CONFLICT(entity_type, entity_id) DO UPDATE SET last_triggered_at = excluded.last_triggered_at, case_id = excluded.case_id",
                (entity_type, entity_id, cid)
            )
        conn.commit()
    except Exception as e:
        print(f"[-] UEBA auto-case check failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    run_ueba_models()
    run_risk_scoring()
    run_convergence_scoring()
    run_priority_scoring()
    run_autocase_check()
