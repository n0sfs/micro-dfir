import os, json, sqlite3, duckdb
DB_PATH = "/opt/micro-dfir/siem.db"
UEBA_DEFAULTS = {
    'ueba_lookback_days': 30, 'ueba_stddev_multiplier': 3.0, 'ueba_min_baseline': 50.0,
    'ueba_min_days_observed': 4, 'ueba_new_ip_enabled': 1,
}
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
        for h in new_ip_hits:
            message = (f"{h['username']} (user) was active from a source IP not seen for this user in the past "
                       f"{cfg['lookback_days']} days: {h['source_ip']} ({h['count']} events today).")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, 'user', 'duckdb_ueba', 'Medium', ?, ?)",
                (h['username'], message, json.dumps({**h, 'detection_type': 'new_source_ip'}))
            )
        conn.commit()
    except Exception as e:
        print(f"[-] UEBA failed to persist anomalies: {e}")
    finally:
        conn.close()

if __name__ == "__main__": run_ueba_models()
