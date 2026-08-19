import os, yara, sqlite3
DB_PATH = os.path.abspath("siem.db")
def scan_file(file_path):
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    try: rules = conn.cursor().execute("SELECT id, title, rule_text FROM yara_rules WHERE enabled = 1").fetchall()
    except: rules = []
    finally: conn.close()
    if not rules: return {"status": "error", "message": "No YARA rules enabled."}
    compiled = yara.compile(sources={f"r_{r['id']}": r['rule_text'] for r in rules})
    try:
        matches = compiled.match(file_path)
        return {"status": "success", "matches": [{"rule_name": m.rule} for m in matches]}
    except Exception as e: return {"status": "error", "message": str(e)}
