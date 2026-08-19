import os, sqlite3, urllib.request, zipfile, yaml, tempfile, shutil
def import_sigmahq_rules():
    t = tempfile.mkdtemp(); zp = os.path.join(t, "sigma.zip")
    try:
        urllib.request.urlretrieve("https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip", zp)
        with zipfile.ZipFile(zp, 'r') as z: z.extractall(t)
        conn = sqlite3.connect(os.path.abspath("siem.db")); cursor = conn.cursor()
        for root, _, files in os.walk(os.path.join(t, "sigma-master", "rules")):
            for f in files:
                if f.endswith(".yml"):
                    with open(os.path.join(root, f), 'r', encoding='utf-8') as file: ry = file.read()
                    try:
                        p = yaml.safe_load(ry)
                        if p and 'title' in p: cursor.execute("INSERT INTO sigma_rules (title, rule_yaml, enabled) VALUES (?, ?, 0)", (p['title'], ry))
                    except: pass
        conn.commit(); conn.close()
    finally: shutil.rmtree(t, ignore_errors=True)
if __name__ == "__main__": import_sigmahq_rules()
