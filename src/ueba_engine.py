import os, json, sqlite3, duckdb
DB_PATH = "/opt/micro-dfir/siem.db"
def run_ueba_models():
    anomalies = []
    try:
        con = duckdb.connect(database=':memory:'); con.execute("INSTALL sqlite; LOAD sqlite;")
        con.execute(f"ATTACH '{DB_PATH}' AS siem (TYPE SQLITE);")
        query = "WITH daily AS (SELECT host, date_trunc('day', CAST(timestamp AS TIMESTAMP)) as day, count(*) as c FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL 30 DAY GROUP BY 1, 2), stats AS (SELECT host, avg(c) as avg_c, stddev_pop(c) as sd_c FROM daily WHERE day < CURRENT_DATE GROUP BY 1), today AS (SELECT host, count(*) as cur_c FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE GROUP BY 1) SELECT t.host, t.cur_c, s.avg_c, s.sd_c FROM today t JOIN stats s ON t.host = s.host WHERE t.cur_c > (s.avg_c + (3 * COALESCE(s.sd_c, 0))) AND s.avg_c > 50"
        for r in con.execute(query).fetchall():
            host, cur_c, avg_c, sd_c = r[0], r[1], r[2], r[3]
            anomalies.append({
                "host": host,
                "current_count": cur_c,
                "baseline_avg": round(avg_c, 1) if avg_c is not None else None,
                "baseline_stddev": round(sd_c, 1) if sd_c is not None else 0,
                "severity": "HIGH",
                "message": f"{host} generated {cur_c} events today, exceeding its 30-day baseline of {round(avg_c, 1)} (±{round(sd_c or 0, 1)})."
            })
        con.close()
    except Exception as e:
        print(f"[-] UEBA model run failed: {e}")
        return

    if anomalies:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            for a in anomalies: conn.execute("INSERT INTO events (timestamp, hostname, app_name, severity, message, raw_json) VALUES (datetime('now'), ?, 'duckdb_ueba', ?, ?, ?)", (a['host'], a['severity'], a['message'], json.dumps(a)))
            conn.commit(); conn.close()
        except Exception as e:
            print(f"[-] UEBA failed to persist anomalies: {e}")
if __name__ == "__main__": run_ueba_models()
