import sqlite3, requests, datetime
DB_PATH = "/opt/micro-dfir/siem.db"

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def sync_taxii(feed):
    headers = {"Accept": "application/taxii+json;version=2.1"}
    auth = None
    # A TAXII server can require either basic auth (username/password) or a bearer
    # token (api_key) depending on how it's deployed — an API key takes precedence
    # when both happen to be set, since it's the more explicit choice.
    api_key = feed["api_key"] if "api_key" in feed.keys() else None
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    elif feed["username"]:
        auth = (feed["username"], feed["password"])
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

# Response shape confirmed live against https://urlhaus.abuse.ch/downloads/json_recent/ :
# a JSON object keyed by url_id, each value a one-element list of
# {dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter}.
def sync_urlhaus(feed):
    res = requests.get("https://urlhaus.abuse.ch/downloads/json_recent/", timeout=20)
    res.raise_for_status()
    data = res.json()
    conn = _connect(); c = 0
    items = data.items() if isinstance(data, dict) else []
    for url_id, group in items:
        for e in group:
            stix_id = f"urlhaus--{url_id}"
            tags = ", ".join(e.get("tags") or [])
            name = e.get("threat") or "malware_download"
            desc = f"reporter={e.get('reporter', '')}" + (f", tags={tags}" if tags else "")
            conn.execute(
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, name, description, pattern, valid_from, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (stix_id, "indicator", name, desc, e.get("url", ""), e.get("dateadded", ""), 1 if e.get("url_status") == "offline" else 0)
            )
            c += 1
    conn.commit(); conn.close()
    return c

# Response shape confirmed live against https://feodotracker.abuse.ch/downloads/ipblocklist.json :
# a JSON array of {ip_address, port, status, hostname, as_number, as_name, country,
# first_seen, last_online, malware}.
def sync_feodotracker(feed):
    res = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=20)
    res.raise_for_status()
    data = res.json()
    conn = _connect(); c = 0
    items = data if isinstance(data, list) else []
    for e in items:
        ip = e.get("ip_address", "")
        port = e.get("port", "")
        stix_id = f"feodotracker--{ip}--{port}"
        name = f"{e.get('malware') or 'Unknown'} C2"
        desc = f"port={port}, status={e.get('status', '')}, country={e.get('country', '')}, as_name={e.get('as_name', '')}"
        conn.execute(
            "INSERT OR REPLACE INTO stix_indicators (stix_id, type, name, description, pattern, valid_from, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (stix_id, "indicator", name, desc, ip, e.get("first_seen", ""), 1 if e.get("status") == "offline" else 0)
        )
        c += 1
    conn.commit(); conn.close()
    return c

# AlienVault OTX — GET /api/v1/pulses/subscribed, auth via X-OTX-API-KEY header
# (confirmed against the official OTX Python SDK). Response is {"results": [...],
# "next": <url or null>}; each pulse has id/name/description and an indicators list
# of {indicator, type, description, created, is_active, ...}. Only the first page is
# pulled per sync — same "recent slice, not full history" scope as the other feeds.
def sync_otx(feed):
    api_key = feed["api_key"] if "api_key" in feed.keys() else None
    if not api_key:
        raise ValueError("OTX feed requires an API key")
    headers = {"X-OTX-API-KEY": api_key}
    res = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20", headers=headers, timeout=20)
    res.raise_for_status()
    pulses = res.json().get("results", [])
    conn = _connect(); c = 0
    for pulse in pulses:
        pulse_id = pulse.get("id", "")
        pulse_name = pulse.get("name") or "OTX Pulse"
        for ind in pulse.get("indicators", []):
            stix_id = f"otx--{pulse_id}--{ind.get('id', '')}"
            conn.execute(
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, name, description, pattern, valid_from, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (stix_id, "indicator", f"{pulse_name} ({ind.get('type', '')})",
                 ind.get("description") or pulse.get("description", ""), ind.get("indicator", ""),
                 ind.get("created", ""), 0 if ind.get("is_active", True) else 1)
            )
            c += 1
    conn.commit(); conn.close()
    return c

def sync_feed(feed):
    if feed["feed_type"] == "taxii":
        return sync_taxii(feed)
    elif feed["feed_type"] == "threatfox":
        return sync_threatfox(feed)
    elif feed["feed_type"] == "urlhaus":
        return sync_urlhaus(feed)
    elif feed["feed_type"] == "feodotracker":
        return sync_feodotracker(feed)
    elif feed["feed_type"] == "otx":
        return sync_otx(feed)
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

# Only feeds with a configured sync_interval_minutes get auto-synced — a feed left on
# "Manual only" (NULL/0) is never touched here, same as before this existed. Called
# from sigma_engine.py's already-running background loop (see the comment there for
# why) rather than a dedicated scheduler process.
def sync_due_feeds():
    conn = _connect()
    feeds = conn.execute(
        "SELECT id, last_sync, sync_interval_minutes FROM ti_feeds "
        "WHERE enabled = 1 AND sync_interval_minutes IS NOT NULL AND sync_interval_minutes > 0"
    ).fetchall()
    conn.close()
    now = datetime.datetime.now()
    for feed in feeds:
        due = True
        if feed["last_sync"]:
            try:
                last = datetime.datetime.strptime(feed["last_sync"], '%Y-%m-%d %H:%M:%S')
                due = (now - last).total_seconds() >= feed["sync_interval_minutes"] * 60
            except (ValueError, TypeError):
                due = True
        if due:
            sync_one(feed["id"])

if __name__ == "__main__":
    sync_all_feeds()
