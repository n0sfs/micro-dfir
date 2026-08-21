import sqlite3, requests, datetime
DB_PATH = "/opt/micro-dfir/siem.db"

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def sync_taxii(feed):
    headers = {"Accept": "application/taxii+json;version=2.1"}
    auth = (feed["username"], feed["password"]) if feed["username"] else None
    url = feed["discovery_url"].rstrip("/") + f"/collections/{feed['collection_id']}/objects/"
    res = requests.get(url, headers=headers, auth=auth, timeout=20)
    res.raise_for_status()
    objects = res.json().get("objects", [])
    conn = _connect(); c = 0
    for obj in objects:
        if obj.get("type") == "indicator":
            conn.execute(
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, name, description, pattern, valid_from, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (obj.get("id"), "indicator", obj.get("name", ""), obj.get("description", ""), obj.get("pattern", ""), obj.get("valid_from", ""), 1 if obj.get("revoked", False) else 0)
            )
            c += 1
    conn.commit(); conn.close()
    return c

def sync_threatfox(feed):
    res = requests.get("https://threatfox.abuse.ch/export/json/recent/", timeout=20)
    res.raise_for_status()
    data = res.json()
    conn = _connect(); c = 0
    items = data.items() if isinstance(data, dict) else []
    for ioc_id, group in items:
        for e in group:
            stix_id = f"threatfox--{ioc_id}"
            malware = e.get('malware_printable') or e.get('malware') or 'Unknown'
            name = f"{malware} ({e.get('threat_type', 'ioc')})"
            desc = f"ioc_type={e.get('ioc_type')}, confidence={e.get('confidence_level')}"
            conn.execute(
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, name, description, pattern, valid_from, revoked) VALUES (?, ?, ?, ?, ?, ?, 0)",
                (stix_id, "indicator", name, desc, e.get("ioc_value", ""), e.get("first_seen_utc", ""))
            )
            c += 1
    conn.commit(); conn.close()
    return c

def sync_feed(feed):
    if feed["feed_type"] == "taxii":
        return sync_taxii(feed)
    elif feed["feed_type"] == "threatfox":
        return sync_threatfox(feed)
    raise ValueError(f"Unknown feed_type: {feed['feed_type']}")

def sync_one(feed_id):
    conn = _connect()
    feed = conn.execute("SELECT * FROM ti_feeds WHERE id = ?", (feed_id,)).fetchone()
    if not feed:
        conn.close()
        return {"status": "error", "message": "Feed not found"}
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        count = sync_feed(feed)
        conn.execute("UPDATE ti_feeds SET last_sync = ?, last_status = 'success', last_count = ? WHERE id = ?", (now, count, feed_id))
        conn.commit(); conn.close()
        print(f"[+] Synced feed '{feed['name']}': {count} indicators.")
        return {"status": "success", "count": count}
    except Exception as e:
        conn.execute("UPDATE ti_feeds SET last_sync = ?, last_status = ? WHERE id = ?", (now, f"error: {e}", feed_id))
        conn.commit(); conn.close()
        print(f"[-] Feed '{feed['name']}' sync failed: {e}")
        return {"status": "error", "message": str(e)}

def sync_all_feeds():
    conn = _connect()
    feeds = conn.execute("SELECT id FROM ti_feeds WHERE enabled = 1").fetchall()
    conn.close()
    for feed in feeds:
        sync_one(feed["id"])

if __name__ == "__main__":
    sync_all_feeds()
