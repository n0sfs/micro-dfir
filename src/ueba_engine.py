import os, json, sqlite3, duckdb
DB_PATH = "/opt/micro-dfir/siem.db"
def run_ueba_models():
    anomalies = []
    try:
        con = duckdb.connect(database=':memory:'); con.execute("INSTALL sqlite; LOAD sqlite;")
        con.execute(f"ATTACH '{DB_PATH}' AS siem (TYPE SQLITE);")
        query = "WITH daily AS (SELECT host, date_trunc('day', CAST(timestamp AS TIMESTAMP)) as day, count(*) as c FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE - INTERVAL 30 DAY GROUP BY 1, 2), stats AS (SELECT host, avg(c) as avg_c, stddev_pop(c) as sd_c FROM daily WHERE day < CURRENT_DATE GROUP BY 1), today AS (SELECT host, count(*) as cur_c FROM siem.live_logs WHERE CAST(timestamp AS TIMESTAMP) >= CURRENT_DATE GROUP BY 1) SELECT t.host, t.cur_c, s.avg_c, s.sd_c FROM today t JOIN stats s ON t.host = s.host WHERE t.cur_c > (s.avg_c + (3 * COALESCE(s.sd_c, 0))) AND s.avg_c > 50"
        for r in con.execute(query).fetchall(): anomalies.append({"severity": "err", "message": f"UEBA: {r[0]} generated {r[1]} events today. Baseline {int(r[2])}."})
        con.close()
    except Exception as e:
        print(f"[-] UEBA model run failed: {e}")
        return

    if anomalies:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            for a in anomalies: conn.execute("INSERT INTO events (timestamp, hostname, app_name, severity, message, raw_json) VALUES (datetime('now'), 'microsoc-engine', 'duckdb_ueba', ?, ?, ?)", (a['severity'], a['message'], json.dumps(a)))
            conn.commit(); conn.close()
        except Exception as e:
            print(f"[-] UEBA failed to persist anomalies: {e}")
if __name__ == "__main__": run_ueba_models()
