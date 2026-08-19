import sqlite3, requests, json
DB_PATH = "/opt/micro-dfir/siem.db"
def sync_taxii_feed():
    try:
        res = requests.get("https://limo.anomali.com/api/v1/taxii2/feeds/collections/107/objects/", headers={"Accept": "application/taxii+json;version=2.1"}, auth=("guest", "guest"), timeout=15)
        res.raise_for_status()
        objects = res.json().get("objects", [])
        conn = sqlite3.connect(DB_PATH); cursor = conn.cursor(); c = 0
        for obj in objects:
            if obj.get("type") == "indicator":
                cursor.execute("INSERT OR REPLACE INTO stix_indicators (stix_id, type, name, description, pattern, valid_from, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)", (obj.get("id"), "indicator", obj.get("name", ""), obj.get("description", ""), obj.get("pattern", ""), obj.get("valid_from", ""), 1 if obj.get("revoked", False) else 0))
                c += 1
        conn.commit(); conn.close(); print(f"[+] Sync'd {c} STIX indicators.")
    except Exception as e: print(f"[-] TAXII Sync Failed: {e}")
if __name__ == "__main__": sync_taxii_feed()
