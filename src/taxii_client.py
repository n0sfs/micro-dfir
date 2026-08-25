import sqlite3, requests, datetime, re, os, shutil, tempfile, zipfile, time
DB_PATH = "/opt/micro-dfir/siem.db"
# Duplicated from app.py's YARA_RULES_DIR rather than imported from it -- this module
# is deliberately standalone (app.py imports FROM here), same reasoning as DB_PATH
# above being its own local constant instead of importing app.py's DB path.
YARA_RULES_DIR = "/opt/micro-dfir/rules/yara_imported"
# Confirmed live: this specific bulk-download endpoint needs no Auth-Key at all (the
# YARAify API docs' own "download all rules" section shows a plain unauthenticated
# curl example, and its "Download all YARA rules" link resolves here) -- unlike every
# other YARAify endpoint (hash lookups, rule submission, etc.), which do require one.
YARAIFY_ZIP_URL = "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"
_YARAIFY_MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024   # refuse an implausibly large download up front
_YARAIFY_MAX_EXTRACTED_BYTES = 500 * 1024 * 1024  # zip-bomb guard: cap total decompressed size

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

# STIX patterns look like "[ipv4-addr:value = '1.2.3.4']" or
# "[domain-name:value = 'evil.com' AND file:hashes.SHA256 = '...']" — pulling the
# first object-type token out of the pattern is a best-effort classification (a
# generic TAXII feed doesn't otherwise expose a clean "this is an IP/domain/hash"
# field the way the other feeds do), not a full STIX pattern parse.
_STIX_PATTERN_TYPE_RE = re.compile(r'\[\s*([a-zA-Z0-9\-]+):')

def _guess_stix_pattern_type(pattern):
    m = _STIX_PATTERN_TYPE_RE.match(pattern or '')
    return m.group(1) if m else 'stix-pattern'

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
            pattern = obj.get("pattern", "")
            conn.execute(
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (obj.get("id"), "indicator", _guess_stix_pattern_type(pattern), obj.get("name", ""), obj.get("description", ""),
                 pattern, obj.get("valid_from", ""), 1 if obj.get("revoked", False) else 0, feed["id"])
            )
            c += 1
    conn.commit(); conn.close()
    return c

# ThreatFox/URLhaus/Feodo Tracker's legacy "export"/"downloads" endpoints (used below)
# stay public even without a key -- an Auth-Key here is optional, not required, and
# only buys a higher rate limit / requests counted against your own abuse.ch account
# instead of anonymous access. Same abuse.ch Auth-Key as the YARAify feed accepts.
def _abuse_ch_headers(feed):
    api_key = feed["api_key"] if "api_key" in feed.keys() else None
    return {"Auth-Key": api_key} if api_key else {}

def sync_threatfox(feed):
    res = requests.get("https://threatfox.abuse.ch/export/json/recent/", headers=_abuse_ch_headers(feed), timeout=20)
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
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (stix_id, "indicator", e.get("ioc_type", "") or "unknown", name, desc, e.get("ioc_value", ""), e.get("first_seen_utc", ""), feed["id"])
            )
            c += 1
    conn.commit(); conn.close()
    return c

# Response shape confirmed live against https://urlhaus.abuse.ch/downloads/json_recent/ :
# a JSON object keyed by url_id, each value a one-element list of
# {dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter}.
def sync_urlhaus(feed):
    res = requests.get("https://urlhaus.abuse.ch/downloads/json_recent/", headers=_abuse_ch_headers(feed), timeout=20)
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
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, ?, 'url', ?, ?, ?, ?, ?, ?)",
                (stix_id, "indicator", name, desc, e.get("url", ""), e.get("dateadded", ""), 1 if e.get("url_status") == "offline" else 0, feed["id"])
            )
            c += 1
    conn.commit(); conn.close()
    return c

# Response shape confirmed live against https://feodotracker.abuse.ch/downloads/ipblocklist.json :
# a JSON array of {ip_address, port, status, hostname, as_number, as_name, country,
# first_seen, last_online, malware}.
def sync_feodotracker(feed):
    res = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=_abuse_ch_headers(feed), timeout=20)
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
            "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, ?, 'ip', ?, ?, ?, ?, ?, ?)",
            (stix_id, "indicator", name, desc, ip, e.get("first_seen", ""), 1 if e.get("status") == "offline" else 0, feed["id"])
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
            ind_type = ind.get("type", "") or "unknown"
            conn.execute(
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (stix_id, "indicator", ind_type, f"{pulse_name} ({ind_type})",
                 ind.get("description") or pulse.get("description", ""), ind.get("indicator", ""),
                 ind.get("created", ""), 0 if ind.get("is_active", True) else 1, feed["id"])
            )
            c += 1
    conn.commit(); conn.close()
    return c

# A generic MISP-format feed: a directory of static files (no MISP instance, no auth)
# served over plain HTTP -- manifest.json keyed by event UUID (metadata: info/date/Tag),
# plus one <uuid>.json per event holding the full Attribute list. This is exactly how
# MISP's own free default feeds (CIRCL OSINT, Botvrij.eu, and the ~50 others at
# misp-project.org/feeds/) are published; consuming one needs nothing but requests+json.
# Confirmed live against https://www.circl.lu/doc/misp/feed-osint/ -- manifest.json is
# ~1.4MB for ~1700 events, too much to refetch every event file each sync, so (mirroring
# OTX's "most recent slice, not full history" precedent above) only the N most-recently-
# updated events are pulled per sync; re-running periodically cycles through the rest.
#
# Bounded by an OVERALL WALL-CLOCK BUDGET (manifest fetch + every event fetch
# combined), not just event count: this whole sync runs inside one gunicorn worker
# request, and microsoc-web.service has no --timeout override, so gunicorn's default
# 30s worker-kill applies -- confirmed live that an earlier 50-event/30s-per-request
# design could hang past 2 minutes with no client-visible error, since a killed
# worker's connection doesn't reliably surface as a clean failure to the browser.
# _MISP_FEED_TIME_BUDGET_SECONDS leaves a comfortable ~10s margin under that 30s
# cutoff for DB writes and response serialization; _MISP_FEED_MAX_EVENTS_PER_SYNC is
# now just an outer sanity cap, rarely the thing that actually stops the loop. A
# shared Session reuses the TLS connection across every event fetch instead of paying
# a fresh handshake each time.
_MISP_FEED_MAX_EVENTS_PER_SYNC = 50
_MISP_FEED_TIME_BUDGET_SECONDS = 20
_MISP_FEED_EVENT_REQUEST_TIMEOUT = 5

def sync_misp_feed(feed):
    start = time.time()
    base = feed["discovery_url"].rstrip("/") + "/"
    headers = _abuse_ch_headers(feed)  # harmless no-op for feeds that don't use one
    session = requests.Session()
    # manifest.json is a single request but can run ~1.4MB (e.g. CIRCL's OSINT feed) --
    # capped at what's left of the overall budget rather than its own fixed timeout,
    # since it counts against the same 20s ceiling as everything else in this sync.
    res = session.get(base + "manifest.json", headers=headers, timeout=max(5, _MISP_FEED_TIME_BUDGET_SECONDS - (time.time() - start)))
    res.raise_for_status()
    manifest = res.json()
    if not isinstance(manifest, dict):
        raise ValueError("manifest.json did not contain the expected {event_uuid: {...}} object")

    entries = sorted(manifest.items(), key=lambda kv: kv[1].get("timestamp", 0), reverse=True)
    entries = entries[:_MISP_FEED_MAX_EVENTS_PER_SYNC]

    conn = _connect(); c = 0
    for event_uuid, meta in entries:
        if time.time() - start > _MISP_FEED_TIME_BUDGET_SECONDS:
            break  # out of time for this cycle -- whatever's synced so far still commits below;
                   # the next sync (this feed re-sorts by timestamp) picks up from the most recent again
        try:
            ev_res = session.get(base + f"{event_uuid}.json", headers=headers, timeout=_MISP_FEED_EVENT_REQUEST_TIMEOUT)
            ev_res.raise_for_status()
            raw = ev_res.json()
        except Exception:
            continue  # one bad/missing/slow event file shouldn't abort the whole sync
        event = raw.get("Event", raw) if isinstance(raw, dict) else {}
        info = event.get("info") or meta.get("info") or "MISP Event"
        event_date = event.get("date") or meta.get("date") or ""
        tags = ", ".join(t.get("name", "") for t in (event.get("Tag") or meta.get("Tag") or []) if t.get("name"))
        for attr in (event.get("Attribute") or []):
            # to_ids=false attributes are context (a report link, a comment) rather than
            # something MISP itself considers detection-worthy -- same filter MISP's own
            # IDS export applies. Deleted attributes are tombstones, not live IOCs.
            if attr.get("deleted") or not attr.get("to_ids", False):
                continue
            value = (attr.get("value") or "").strip()
            if not value:
                continue
            stix_id = f"misp--{event_uuid}--{attr.get('uuid') or value}"
            desc_parts = [f"category={attr.get('category', '')}"]
            if tags:
                desc_parts.append(f"tags={tags}")
            if attr.get("comment"):
                desc_parts.append(f"comment={attr['comment']}")
            conn.execute(
                "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (stix_id, "indicator", (attr.get("type") or "unknown").lower(), info, ", ".join(desc_parts), value, event_date, feed["id"])
            )
            c += 1
    conn.commit(); conn.close()
    return c

# abuse.ch SSLBL's malicious TLS certificate blacklist (SHA1 fingerprints) -- their IP
# blacklist (sslipblacklist.csv) was deprecated 2025-01-03 and is permanently empty now,
# confirmed live, so this deliberately targets the still-active certificate list instead.
# Format confirmed live: "Listingdate,SHA1,Listingreason" CSV with a '#'-commented banner.
def sync_sslbl(feed):
    res = requests.get("https://sslbl.abuse.ch/blacklist/sslblacklist.csv", headers=_abuse_ch_headers(feed), timeout=20)
    res.raise_for_status()
    conn = _connect(); c = 0
    for line in res.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 3:
            continue
        listing_date, sha1, reason = parts[0], parts[1], ','.join(parts[2:])
        stix_id = f"sslbl--{sha1}"
        conn.execute(
            "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, 'indicator', 'tls-cert-sha1', ?, ?, ?, ?, 0, ?)",
            (stix_id, reason, "source=SSLBL certificate blacklist", sha1, listing_date, feed["id"])
        )
        c += 1
    conn.commit(); conn.close()
    return c

# Spamhaus DROP ("Don't Route Or Peer") -- hijacked/criminal-controlled netblocks, plain
# text, no auth, no API key. EDROP was merged into drop.txt itself (confirmed live: the
# edrop.txt endpoint now just says so) so this single list already covers both.
_DROP_LINE_RE = re.compile(r'^([0-9./]+)\s*;\s*(\S+)')

def sync_spamhaus_drop(feed):
    res = requests.get("https://www.spamhaus.org/drop/drop.txt", timeout=20)
    res.raise_for_status()
    conn = _connect(); c = 0
    for line in res.text.splitlines():
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        m = _DROP_LINE_RE.match(line)
        if not m:
            continue
        cidr, sbl_ref = m.group(1), m.group(2)
        stix_id = f"spamhaus-drop--{cidr}"
        conn.execute(
            "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, 'indicator', 'ip-cidr', ?, ?, ?, '', 0, ?)",
            (stix_id, f"Spamhaus DROP ({sbl_ref})", "source=Spamhaus DROP", cidr, feed["id"])
        )
        c += 1
    conn.commit(); conn.close()
    return c

# Tor Project's official bulk exit-node list -- one IP per line, plain text, no auth.
# Not inherently malicious, but a source IP that's a known Tor exit node is useful
# context on an alert regardless (anonymized/likely-adversarial traffic origin).
def sync_tor_exit(feed):
    res = requests.get("https://check.torproject.org/torbulkexitlist", timeout=20)
    res.raise_for_status()
    conn = _connect(); c = 0
    for line in res.text.splitlines():
        ip = line.strip()
        if not ip or ip.startswith('#'):
            continue
        stix_id = f"tor-exit--{ip}"
        conn.execute(
            "INSERT OR REPLACE INTO stix_indicators (stix_id, type, ioc_type, name, description, pattern, valid_from, revoked, feed_id) VALUES (?, 'indicator', 'ip', 'Tor Exit Node', 'source=Tor Project bulk exit list', ?, '', 0, ?)",
            (stix_id, ip, feed["id"])
        )
        c += 1
    conn.commit(); conn.close()
    return c

def _extract_zip_safely(zip_path, dest_dir, max_total_bytes=_YARAIFY_MAX_EXTRACTED_BYTES):
    # dest_dir must already exist and be empty. Returns the number of files written.
    # Two defenses zipfile.extractall() alone doesn't give you, even for a zip from a
    # reputable source (it could still be tampered with or corrupted in transit):
    #  - zip-slip: an entry name like '../../etc/cron.d/evil' escaping dest_dir.
    #  - zip bomb: checked against the REAL decompressed byte count as it streams out,
    #    not the zip's own declared file_size, which is attacker-controllable metadata.
    dest_dir = os.path.realpath(dest_dir)
    written = 0
    total = 0
    chunk_size = 1024 * 1024
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = os.path.realpath(os.path.join(dest_dir, info.filename))
            if target != dest_dir and not target.startswith(dest_dir + os.sep):
                raise ValueError(f"Refusing to extract unsafe zip entry: {info.filename!r}")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, 'wb') as dst:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_total_bytes:
                        raise ValueError(f"Zip extracts to more than {max_total_bytes} bytes -- refusing (possible zip bomb)")
                    dst.write(chunk)
            written += 1
    return written

def sync_yaraify(feed):
    # Unlike the other sync_* functions, this writes files to disk rather than rows
    # into stix_indicators -- it's the YARA rule content that File Scan and String
    # Sweep both read from rules/yara_imported/, kept fresh from abuse.ch's YARAify
    # bulk rule-pack export instead of only whatever's been manually vendored in.
    os.makedirs(YARA_RULES_DIR, exist_ok=True)
    fd, tmp_zip_path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    extract_dir = None
    try:
        # No auth required for this endpoint, but sending one if configured is
        # harmless and matches every other abuse.ch feed's optional-Auth-Key pattern.
        with requests.get(YARAIFY_ZIP_URL, headers=_abuse_ch_headers(feed), timeout=60, stream=True) as res:
            res.raise_for_status()
            content_length = res.headers.get("Content-Length")
            if content_length and int(content_length) > _YARAIFY_MAX_DOWNLOAD_BYTES:
                raise ValueError(f"YARAify rule pack is larger than expected ({content_length} bytes) — refusing to download")
            downloaded = 0
            with open(tmp_zip_path, "wb") as f:
                for chunk in res.iter_content(chunk_size=1024 * 1024):
                    downloaded += len(chunk)
                    if downloaded > _YARAIFY_MAX_DOWNLOAD_BYTES:
                        raise ValueError("YARAify rule pack exceeded the maximum expected download size — refusing")
                    f.write(chunk)

        # Extracted into a temp dir on the SAME filesystem as the final target
        # (dir=YARA_RULES_DIR) so the swap below is a real atomic os.rename, not a
        # cross-device copy that could fail or leave a partial directory behind.
        extract_dir = tempfile.mkdtemp(prefix=".yaraify_extract_", dir=YARA_RULES_DIR)
        count = _extract_zip_safely(tmp_zip_path, extract_dir)
        if count == 0:
            raise ValueError("YARAify rule pack contained no rule files")

        final_dir = os.path.join(YARA_RULES_DIR, "yaraify_synced")
        stale_dir = final_dir + ".stale"
        if os.path.isdir(stale_dir):
            shutil.rmtree(stale_dir)
        if os.path.isdir(final_dir):
            os.rename(final_dir, stale_dir)
        os.rename(extract_dir, final_dir)
        extract_dir = None
        if os.path.isdir(stale_dir):
            shutil.rmtree(stale_dir)
        return count
    finally:
        if extract_dir and os.path.isdir(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
        try:
            os.remove(tmp_zip_path)
        except OSError:
            pass

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
    elif feed["feed_type"] == "yaraify":
        return sync_yaraify(feed)
    elif feed["feed_type"] == "misp":
        return sync_misp_feed(feed)
    elif feed["feed_type"] == "sslbl":
        return sync_sslbl(feed)
    elif feed["feed_type"] == "spamhaus_drop":
        return sync_spamhaus_drop(feed)
    elif feed["feed_type"] == "tor_exit":
        return sync_tor_exit(feed)
    elif feed["feed_type"] == "csv":
        # CSV feeds are a one-time snapshot uploaded through /api/ti/feeds/upload_csv —
        # there's no remote source to re-fetch from, so "Sync Now" / sync_all_feeds()
        # can't do anything for one. Re-upload a fresh CSV (as a new feed) to update it.
        raise ValueError("CSV feeds can't be re-synced — upload a new CSV to refresh the list")
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
