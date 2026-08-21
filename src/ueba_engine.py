import os, json, sqlite3, duckdb
DB_PATH = "/opt/micro-dfir/siem.db"
UEBA_DEFAULTS = {'ueba_lookback_days': 30, 'ueba_stddev_multiplier': 3.0, 'ueba_min_baseline': 50.0}

def get_ueba_config():
    cfg = dict(UEBA_DEFAULTS)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        rows = conn.execute("SELECT key, value FROM settings WHERE key IN (?, ?, ?)", tuple(UEBA_DEFAULTS.keys())).fetchall()
        conn.close()
        for k, v in rows:
            cfg[k] = v
    except Exception:
        pass
    return {
        'lookback_days': max(1, min(365, int(cfg['ueba_lookback_days']))),
        'stddev_multiplier': max(0.5, min(10.0, float(cfg['ueba_stddev_multiplier']))),
        'min_baseline': max(0.0, float(cfg['ueba_min_baseline'])),
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
# event-volume vs. a rolling per-entity baseline (mean + N*stddev). This is a flat
# activity-count model, not the richer multi-signal behavioral profile a full UEBA
# platform builds (login geography, peer-group deviation, resource access patterns,
# etc.) — that would need new structured fields we don't currently ingest. Placeholder
# values (missing host, '-'/blank username used when ingest has no user context) are
# filtered out so they don't get modeled as if they were a real entity.
ENTITY_MODELS = [
    {'entity_type': 'host', 'column': 'host', 'extra_filter': "host IS NOT NULL AND host NOT IN ('', 'UNKNOWN')"},
    {'entity_type': 'user', 'column': 'username', 'extra_filter': "username IS NOT NULL AND username NOT IN ('', '-')"},
]

# Alerts are only ever raised at cur_c > avg_c + (multiplier * sd_c), so the ratio below
# is always >= 1 for anything considered anomalous — it buckets how far past that
# threshold the spike is into Critical/High/Medium instead of a single flat severity.
def _severity_for(cur_c, avg_c, sd_c, multiplier):
    if sd_c and sd_c > 0:
        ratio = (cur_c - avg_c) / (sd_c * multiplier)
    else:
        ratio = cur_c / max(avg_c, 1)
    if ratio >= 3: return 'Critical'
    if ratio >= 2: return 'High'
    return 'Medium'

def _run_model(con, model, cfg):
    entity_type, col, extra_filter = model['entity_type'], model['column'], model['extra_filter']
    query = (
        f"WITH daily AS (SELECT {col} as entity_id, date_trunc('day', CAST(timestamp AS TIMESTAMP)) as day, count(*) as c "
        f"FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL {cfg['lookback_days']} DAY AND {extra_filter} GROUP BY 1, 2), "
        "stats AS (SELECT entity_id, avg(c) as avg_c, stddev_pop(c) as sd_c FROM daily WHERE day < CURRENT_DATE GROUP BY 1), "
        f"today AS (SELECT {col} as entity_id, count(*) as cur_c FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE AND {extra_filter} GROUP BY 1) "
        "SELECT s.entity_id, COALESCE(t.cur_c, 0) as cur_c, s.avg_c, s.sd_c "
        "FROM stats s LEFT JOIN today t ON s.entity_id = t.entity_id "
        f"WHERE s.avg_c > {cfg['min_baseline']} "
        "ORDER BY (COALESCE(t.cur_c, 0) / GREATEST(s.avg_c, 1)) DESC LIMIT 200"
    )
    rows = []
    for entity_id, cur_c, avg_c, sd_c in con.execute(query).fetchall():
        threshold = avg_c + (cfg['stddev_multiplier'] * (sd_c or 0))
        rows.append({
            'entity_type': entity_type, 'entity_id': entity_id, 'current_count': cur_c,
            'baseline_avg': round(avg_c, 1) if avg_c is not None else None,
            'baseline_stddev': round(sd_c, 1) if sd_c is not None else 0,
            'threshold': round(threshold, 1), 'is_anomalous': cur_c > threshold,
        })
    return rows

def run_ueba_models():
    try:
        cfg = get_ueba_config()
        excluded = _get_exclusions()
        con = duckdb.connect(database=':memory:'); con.execute("INSTALL sqlite; LOAD sqlite;")
        con.execute(f"ATTACH '{DB_PATH}' AS siem (TYPE SQLITE);")
        all_rows = []
        for model in ENTITY_MODELS:
            all_rows.extend(_run_model(con, model, cfg))
        con.close()
    except Exception as e:
        print(f"[-] UEBA model run failed: {e}")
        return

    for r in all_rows:
        r['excluded'] = (r['entity_type'], r['entity_id']) in excluded

    conn = sqlite3.connect(DB_PATH, timeout=30)

    # Snapshot every modeled entity (not just the ones currently anomalous) so the
    # baseline-visibility view can show what "normal" looks like — best-effort: an
    # older DB that hasn't run this migration yet just skips the snapshot.
    try:
        conn.execute("DELETE FROM ueba_entity_baselines")
        conn.executemany(
            "INSERT INTO ueba_entity_baselines (entity_type, entity_id, current_count, baseline_avg, baseline_stddev, threshold, is_anomalous, excluded, computed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
            [(r['entity_type'], r['entity_id'], r['current_count'], r['baseline_avg'], r['baseline_stddev'],
              r['threshold'], r['is_anomalous'], r['excluded']) for r in all_rows]
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
            message = (f"{r['entity_id']} ({label}) generated {r['current_count']} events today, exceeding its "
                       f"{cfg['lookback_days']}-day baseline of {r['baseline_avg']} (±{r['baseline_stddev']}).")
            conn.execute(
                "INSERT INTO events (timestamp, hostname, entity_type, app_name, severity, message, raw_json) "
                "VALUES (datetime('now'), ?, ?, 'duckdb_ueba', ?, ?, ?)",
                (r['entity_id'], r['entity_type'], severity, message, json.dumps(r))
            )
        conn.commit()
    except Exception as e:
        print(f"[-] UEBA failed to persist anomalies: {e}")
    finally:
        conn.close()

if __name__ == "__main__": run_ueba_models()
