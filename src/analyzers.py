"""Lightweight on-demand IOC enrichment (Cortex's analyzer pattern, minimal version): a
small registry of independent functions, each taking an IOC value and returning a
normalized {ok, verdict, summary, raw} result. Run synchronously on demand -- no queue,
no separate service, just a direct API call with a short timeout -- since this is a
one-shot "check this value" action, not a bulk pipeline. Callers cache results (see
app.py's enrichment_results table) so repeat lookups don't re-hit free-tier rate limits.
"""
import base64
import datetime
import json
import requests

ENRICHMENT_CACHE_TTL_HOURS = 24


def _shodan_internetdb(value, api_key=None, ioc_type=None):
    # Free, keyless, no rate-limit auth -- https://internetdb.shodan.io/<ip>. A 404
    # means Shodan has no data for this IP (not an error), same as any other IP.
    try:
        res = requests.get(f"https://internetdb.shodan.io/{value}", timeout=8)
        if res.status_code == 404:
            return {'ok': True, 'verdict': 'clean', 'summary': 'No data on record in Shodan InternetDB.', 'raw': {}}
        res.raise_for_status()
        data = res.json()
        ports = data.get('ports') or []
        vulns = data.get('vulns') or []
        tags = data.get('tags') or []
        verdict = 'suspicious' if vulns else ('info' if ports else 'clean')
        parts = []
        if ports:
            shown = ', '.join(str(p) for p in ports[:10])
            parts.append(f"{len(ports)} open port(s): {shown}" + ('...' if len(ports) > 10 else ''))
        if vulns:
            parts.append(f"{len(vulns)} known CVE(s) on record")
        if tags:
            parts.append(f"tags: {', '.join(tags)}")
        return {'ok': True, 'verdict': verdict, 'summary': '; '.join(parts) or 'No open ports or CVEs on record.', 'raw': data}
    except Exception as e:
        return {'ok': False, 'verdict': 'error', 'summary': str(e), 'raw': {}}


def _abuseipdb(value, api_key=None, ioc_type=None):
    if not api_key:
        return {'ok': False, 'verdict': 'unconfigured', 'summary': 'No AbuseIPDB API key configured.', 'raw': {}}
    try:
        res = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={'ipAddress': value, 'maxAgeInDays': 90},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=8
        )
        res.raise_for_status()
        data = (res.json() or {}).get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        verdict = 'malicious' if score >= 75 else ('suspicious' if score >= 25 else 'clean')
        summary = (f"Abuse confidence: {score}%, {data.get('totalReports', 0)} report(s), "
                   f"country: {data.get('countryCode') or '?'}, ISP: {data.get('isp') or '?'}")
        return {'ok': True, 'verdict': verdict, 'summary': summary, 'raw': data}
    except Exception as e:
        return {'ok': False, 'verdict': 'error', 'summary': str(e), 'raw': {}}


# VirusTotal v3 uses a different URL shape per observable type -- ioc_type tells us
# which one to hit. 'hash' covers md5/sha1/sha256 all the same way (VT's /files/
# endpoint accepts any of them directly, no algorithm needed). A url must be looked up
# by its urlsafe-base64, no-padding "url id", not the raw string -- see VT's own API
# docs for /urls/{id}.
def _virustotal(value, api_key=None, ioc_type=None):
    if not api_key:
        return {'ok': False, 'verdict': 'unconfigured', 'summary': 'No VirusTotal API key configured.', 'raw': {}}
    t = (ioc_type or '').lower()
    if 'hash' in t or t in ('md5', 'sha1', 'sha256'):
        path = f"files/{value}"
    elif 'domain' in t:
        path = f"domains/{value}"
    elif 'url' in t:
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip('=')
        path = f"urls/{url_id}"
    else:
        path = f"ip_addresses/{value}"
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/{path}", headers={'x-apikey': api_key}, timeout=8)
        if res.status_code == 404:
            return {'ok': True, 'verdict': 'clean', 'summary': "Not found in VirusTotal's dataset.", 'raw': {}}
        res.raise_for_status()
        attrs = (res.json().get('data') or {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats') or {}
        malicious, suspicious = stats.get('malicious', 0), stats.get('suspicious', 0)
        verdict = 'malicious' if malicious else ('suspicious' if suspicious else 'clean')
        summary = (f"{malicious} malicious, {suspicious} suspicious, {stats.get('harmless', 0)} harmless "
                   f"of {sum(stats.values()) or '?'} engines")
        return {'ok': True, 'verdict': verdict, 'summary': summary, 'raw': attrs}
    except Exception as e:
        return {'ok': False, 'verdict': 'error', 'summary': str(e), 'raw': {}}


# URLhaus (abuse.ch) -- free, but as of abuse.ch's 2025 policy change every API call
# needs a free "Auth-Key" (registered at https://auth.abuse.ch/, no payment/account
# approval), sent as an Auth-Key header -- confirmed live against production (a keyless
# call returns 401). Separate endpoints for a full URL vs. just a host/domain;
# case_iocs already distinguishes 'url' from 'domain', so no guessing needed here.
def _urlhaus(value, api_key=None, ioc_type=None):
    if not api_key:
        return {'ok': False, 'verdict': 'unconfigured', 'summary': 'No URLhaus Auth-Key configured.', 'raw': {}}
    endpoint, field = ('url', 'url') if 'url' in (ioc_type or '').lower() else ('host', 'host')
    try:
        res = requests.post(f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", data={field: value},
                             headers={'Auth-Key': api_key}, timeout=8)
        res.raise_for_status()
        data = res.json()
        if data.get('query_status') != 'ok':
            return {'ok': True, 'verdict': 'clean', 'summary': 'No record in URLhaus.', 'raw': data}
        urls = data.get('urls') or ([data] if endpoint == 'url' else [])
        threats = sorted({u.get('threat') for u in urls if u.get('threat')})
        online = sum(1 for u in urls if u.get('url_status') == 'online')
        summary = f"{len(urls)} URLhaus record(s), {online} still online" + (f"; threat(s): {', '.join(threats)}" if threats else '')
        return {'ok': True, 'verdict': 'malicious', 'summary': summary, 'raw': data}
    except Exception as e:
        return {'ok': False, 'verdict': 'error', 'summary': str(e), 'raw': {}}


# MalwareBazaar -- same abuse.ch family/Auth-Key convention as URLhaus above, but a
# genuinely different capability: this is an on-demand "is this ONE specific hash a
# known malware sample" lookup against MalwareBazaar's full database, complementing
# (not duplicating) the app's existing MalwareBazaar *feed*
# (taxii_client.sync_malwarebazaar), which only ever pulls the last N "recent samples"
# into the local IOC set -- a hash from an older sample, or one a triage/memory capture
# just surfaced, won't be in that feed's slice but is still reachable here. Confirmed
# live against bazaar.abuse.ch/api/'s own current docs (base URL, query=get_info,
# Auth-Key header, and the query_status vocabulary below), not from memory.
def _malwarebazaar(value, api_key=None, ioc_type=None):
    if not api_key:
        return {'ok': False, 'verdict': 'unconfigured', 'summary': 'No MalwareBazaar Auth-Key configured.', 'raw': {}}
    try:
        res = requests.post("https://mb-api.abuse.ch/api/v1/", data={'query': 'get_info', 'hash': value},
                             headers={'Auth-Key': api_key}, timeout=8)
        res.raise_for_status()
        result = res.json() or {}
        status = result.get('query_status')
        if status == 'hash_not_found':
            return {'ok': True, 'verdict': 'clean', 'summary': 'No record in MalwareBazaar.', 'raw': result}
        if status != 'ok':
            return {'ok': True, 'verdict': 'info', 'summary': f'MalwareBazaar query status: {status}', 'raw': result}
        # MalwareBazaar's own docs describe the match as a 'data' array with one entry
        # per queried hash -- defensively handled as either a list or a bare dict in
        # case that shape has drifted since, rather than assuming one or the other.
        entries = result.get('data')
        entry = (entries[0] if isinstance(entries, list) and entries else entries) or {}
        signature = entry.get('signature') or 'Unknown malware family'
        file_type = entry.get('file_type') or '?'
        tags = entry.get('tags') or []
        summary = f"Known malware sample: {signature} ({file_type})" + (f"; tags: {', '.join(tags[:5])}" if tags else '')
        return {'ok': True, 'verdict': 'malicious', 'summary': summary, 'raw': result}
    except Exception as e:
        return {'ok': False, 'verdict': 'error', 'summary': str(e), 'raw': {}}


# IPQualityScore -- proxy/VPN/Tor + fraud-score IP reputation, genuinely complementary
# to AbuseIPDB (community-reported abuse) and Shodan InternetDB (exposed ports/CVEs):
# neither of those does anonymization-infrastructure detection. Free tier is small
# (35 lookups/day per IPQS's own pricing page) -- see this file's ANALYZERS entry below,
# `auto_enrich_eligible: False` keeps it out of the automatic Critical/High sweep so it's
# never burned on the first few alerts of the day, on-demand lookups only.
def _ipqualityscore(value, api_key=None, ioc_type=None):
    if not api_key:
        return {'ok': False, 'verdict': 'unconfigured', 'summary': 'No IPQualityScore API key configured.', 'raw': {}}
    try:
        res = requests.get(f"https://www.ipqualityscore.com/api/json/ip/{api_key}/{value}", timeout=8)
        res.raise_for_status()
        data = res.json() or {}
        if not data.get('success', True) and data.get('message'):
            return {'ok': False, 'verdict': 'error', 'summary': data['message'], 'raw': data}
        score = data.get('fraud_score', 0)
        verdict = 'malicious' if score >= 90 else ('suspicious' if score >= 75 else 'clean')
        flags = [f for f, on in (('proxy', data.get('proxy')), ('VPN', data.get('vpn')), ('Tor', data.get('tor')),
                                  ('recent abuse', data.get('recent_abuse'))) if on]
        summary = (f"Fraud score: {score}/100" + (f"; {', '.join(flags)}" if flags else '') +
                   f"; ISP: {data.get('ISP') or '?'}, org: {data.get('organization') or '?'}")
        return {'ok': True, 'verdict': verdict, 'summary': summary, 'raw': data}
    except Exception as e:
        return {'ok': False, 'verdict': 'error', 'summary': str(e), 'raw': {}}


# Censys -- an internet-wide host/certificate scanning search engine like Shodan, but
# with real TLS certificate detail and ASN/org attribution InternetDB doesn't have.
# Genuinely complementary to Shodan InternetDB (free/keyless, ports+CVEs only), not
# redundant with it. Auth note, honestly flagged: Censys's v2 Search API uses HTTP
# Basic Auth (API ID as username, API Secret as password) -- to fit this file's
# established one-settings-key-per-analyzer convention without a schema change, both
# are stored as one "API_ID:API_SECRET" string in the censys_api_key settings field and
# split here, rather than adding a second settings key just for this one analyzer. This
# hasn't been verified against a real Censys account yet (the platform's docs describe
# a newer unified auth model that may differ) -- confirm against a real key before
# trusting it in production, same "verify before shipping" discipline this session
# already applied elsewhere.
def _censys(value, api_key=None, ioc_type=None):
    if not api_key or ':' not in api_key:
        return {'ok': False, 'verdict': 'unconfigured', 'summary': 'No Censys API ID:Secret configured (format: "API_ID:API_SECRET").', 'raw': {}}
    api_id, api_secret = api_key.split(':', 1)
    try:
        res = requests.get(f"https://search.censys.io/api/v2/hosts/{value}", auth=(api_id, api_secret), timeout=8)
        if res.status_code == 404:
            return {'ok': True, 'verdict': 'clean', 'summary': 'No data on record in Censys.', 'raw': {}}
        res.raise_for_status()
        result = (res.json() or {}).get('result', {})
        services = result.get('services') or []
        ports = sorted({s.get('port') for s in services if s.get('port')})
        autonomous_system = result.get('autonomous_system') or {}
        # Censys doesn't itself score maliciousness the way AbuseIPDB/IPQS do -- this is
        # exposure/attribution data (like Shodan InternetDB), so verdict stays 'info' at
        # most, never 'malicious'/'suspicious' on its own.
        verdict = 'info' if ports else 'clean'
        summary = ((f"{len(ports)} open port(s): {', '.join(str(p) for p in ports[:10])}" if ports else 'No open services on record.') +
                   f"; ASN: {autonomous_system.get('asn') or '?'} ({autonomous_system.get('name') or '?'})")
        return {'ok': True, 'verdict': verdict, 'summary': summary, 'raw': result}
    except Exception as e:
        return {'ok': False, 'verdict': 'error', 'summary': str(e), 'raw': {}}


# 'settings_key' is the key each requires_key=True analyzer's API key is stored under
# in the enrichment_api_keys settings blob (see app.py's api_ti_enrichment_settings).
# 'auto_enrich_eligible' (default True when absent) gates whether auto_enrich_and_score_
# alert's automatic Critical/High sweep may call this analyzer -- False for anything
# with a free-tier quota too small to spend on automatic enrichment (see _enrich_value).
ANALYZERS = [
    {'key': 'shodan_internetdb', 'label': 'Shodan InternetDB', 'ioc_types': ('ip',),
     'requires_key': False, 'settings_key': None, 'run': _shodan_internetdb},
    {'key': 'abuseipdb', 'label': 'AbuseIPDB', 'ioc_types': ('ip',),
     'requires_key': True, 'settings_key': 'abuseipdb_api_key', 'run': _abuseipdb},
    {'key': 'virustotal', 'label': 'VirusTotal', 'ioc_types': ('ip', 'hash', 'domain', 'url'),
     'requires_key': True, 'settings_key': 'virustotal_api_key', 'run': _virustotal},
    {'key': 'urlhaus', 'label': 'URLhaus', 'ioc_types': ('domain', 'url'),
     'requires_key': True, 'settings_key': 'urlhaus_api_key', 'run': _urlhaus},
    {'key': 'malwarebazaar', 'label': 'MalwareBazaar', 'ioc_types': ('hash',),
     'requires_key': True, 'settings_key': 'malwarebazaar_api_key', 'run': _malwarebazaar},
    {'key': 'ipqualityscore', 'label': 'IPQualityScore', 'ioc_types': ('ip',),
     'requires_key': True, 'settings_key': 'ipqualityscore_api_key', 'run': _ipqualityscore,
     'auto_enrich_eligible': False},
    {'key': 'censys', 'label': 'Censys', 'ioc_types': ('ip',),
     'requires_key': True, 'settings_key': 'censys_api_key', 'run': _censys,
     'auto_enrich_eligible': False},
]


def applicable_analyzers(ioc_type):
    """Which registered analyzers apply to a given ioc_type string. ioc_type vocabulary
    varies by feed ('ip', 'ipv4-addr', 'ip-src', 'ip-dst', 'hash', 'md5', 'sha256',
    'domain', 'domain-name', 'url', ...) -- substring match per family, same reasoning
    as the other ioc_type-shape checks elsewhere in this codebase."""
    t = (ioc_type or '').lower()
    matched_types = set()
    if 'ip' in t:
        matched_types.add('ip')
    if 'hash' in t or t in ('md5', 'sha1', 'sha256'):
        matched_types.add('hash')
    if 'domain' in t:
        matched_types.add('domain')
    if 'url' in t:
        matched_types.add('url')
    if not matched_types:
        return []
    return [a for a in ANALYZERS if matched_types & set(a['ioc_types'])]


# ---------------------------------------------------------------------------
# Auto-enrichment + per-alert composite confidence scoring.
#
# Closes a real gap a DFIR-SME-style review of this app's alert-to-verdict pipeline
# found: the curated-feed IOC-correlation Sigma rule already runs automatically on
# every alert (an exact match is a DEFINITE signal), but VT/AbuseIPDB/URLhaus
# reputation lookups above were on-demand only -- an analyst had to manually paste a
# hash/IP into Quick IOC Lookup. Everything below is called once, right after a NEW
# alert is inserted, from both sigma_engine.py (a separate process) and app.py's
# heuristic ingest path -- this module is the natural shared home since its functions
# are already plain (value, api_key, ioc_type) -> dict with no Flask coupling, so both
# processes can import it directly. `conn` is a plain sqlite3 Connection or Cursor
# (both support .execute()); nothing here ever calls .commit() -- that stays the
# caller's responsibility, matching sigma_engine.py's own established convention of
# passing a bare cursor through helper functions.
# ---------------------------------------------------------------------------

# Auto-enrichment only fires for Critical/High severity -- keeps external API spend
# proportional to what's actually worth spending it on. Lower-cased for comparison
# since severity casing genuinely differs between the two alert-creation paths that
# call this (sigma_engine.py's Title-Case 'Critical'/'High' vs. api_ingest's heuristic
# path, which uses ALL-CAPS 'CRITICAL'/'HIGH' -- confirmed directly, not assumed).
AUTO_ENRICH_SEVERITIES = ('critical', 'high')
AUTO_ENRICH_DAILY_MAX_DEFAULT = 100

# Composite-confidence point values -- deliberately small and explainable, not a real
# ML model, matching this codebase's own established heuristic-scoring style (e.g.
# agent_scripts.capture_top_suspicious_memory's process-suspicion heuristic).
_CONFIDENCE_POINTS_IOC_SIGHTING = 40
_CONFIDENCE_POINTS_DEFINITE_MALICIOUS = 35
_CONFIDENCE_POINTS_HEURISTIC_MALICIOUS = 20
_CONFIDENCE_POINTS_SUSPICIOUS = 10


def _tier_for(source, ioc_type, verdict):
    """Distinguishes a curated-feed exact match ('definite') from a reputation-score
    heuristic ('heuristic') -- the crux of the "suspicious vs definitively malicious"
    question this whole feature answers. URLhaus is always a literal blocklist hit when
    it returns anything at all; a VirusTotal HASH lookup with verdict='malicious' means
    real independent AV engines flagged this exact file, a materially stronger signal
    than VT's own IP/domain reputation (which drifts, gets shared across tenants, etc).
    Returns None (no tier) for a verdict that isn't itself a finding worth tiering
    (clean/unconfigured/error) -- NULL there is more honest than inventing a category
    for "nothing to report"."""
    if source in ('urlhaus', 'malwarebazaar'):
        return 'definite'
    if source == 'virustotal' and (ioc_type or '').lower() in ('hash', 'md5', 'sha1', 'sha256') and verdict == 'malicious':
        return 'definite'
    if verdict in ('malicious', 'suspicious', 'info'):
        return 'heuristic'
    return None


def _auto_enrich_budget_ok(conn, daily_max):
    """A plain settings-row JSON counter {date, count}, reset when the date rolls over
    -- the one thing this app's own review flagged as missing (no throttle beyond the
    24h cache, and VT's free tier is famously rate-limited). Soft budget, not a hard
    security boundary: a small race between concurrent callers (e.g. two gunicorn
    workers auto-enriching at once) is acceptable here, the same tradeoff this codebase
    already takes for other once-ish-per-day counters elsewhere."""
    today = datetime.date.today().isoformat()
    row = conn.execute("SELECT value FROM settings WHERE key = 'auto_enrich_daily_budget'").fetchone()
    try:
        state = json.loads(row['value']) if row and row['value'] else {}
    except (TypeError, ValueError):
        state = {}
    if state.get('date') != today:
        state = {'date': today, 'count': 0}
    if state['count'] >= daily_max:
        return False
    state['count'] += 1
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_enrich_daily_budget', ?)", (json.dumps(state),))
    return True


def _enrich_value(conn, api_keys, value, ioc_type):
    """One value through applicable_analyzers(), cache-then-run-then-write -- the same
    shape app.py's /api/ti/enrich and _run_case_analysis already use, factored out here
    so this module owns the pattern once rather than a third near-duplicate appearing.
    This is exclusively the automatic-enrichment path's own helper (only called from
    auto_enrich_and_score_alert below) -- the plain on-demand routes in app.py have
    their own separate loops and are NOT filtered by auto_enrich_eligible, since a human
    explicitly asking for a lookup should always reach every configured analyzer."""
    for a in applicable_analyzers(ioc_type):
        if not a.get('auto_enrich_eligible', True):
            continue
        cached = conn.execute(
            "SELECT 1 FROM enrichment_results WHERE value = ? AND source = ? AND fetched_at >= datetime('now', ?)",
            (value, a['key'], f'-{ENRICHMENT_CACHE_TTL_HOURS} hours')
        ).fetchone()
        if cached:
            continue
        api_key = api_keys.get(a['settings_key']) if a.get('requires_key') else None
        out = a['run'](value, api_key, ioc_type)
        tier = _tier_for(a['key'], ioc_type, out['verdict'])
        conn.execute(
            "INSERT INTO enrichment_results (value, source, verdict, summary, raw_json, tier, fetched_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(value, source) DO UPDATE SET verdict=excluded.verdict, summary=excluded.summary, raw_json=excluded.raw_json, tier=excluded.tier, fetched_at=excluded.fetched_at",
            (value, a['key'], out['verdict'], out['summary'], json.dumps(out.get('raw') or {}), tier)
        )


def _score_alert_confidence(conn, alert_id, values):
    """Cheap, local-only -- runs for every alert regardless of severity, using whatever
    enrichment_results data exists (freshly fetched above, or already cached from an
    earlier unrelated lookup). `values` are the source_ip/destination_ip/file_hash
    strings actually present on this alert (any may be None)."""
    points = 0
    if conn.execute("SELECT 1 FROM ioc_sightings WHERE alert_id = ?", (alert_id,)).fetchone():
        points += _CONFIDENCE_POINTS_IOC_SIGHTING
    values = [v for v in values if v]
    if values:
        placeholders = ','.join('?' for _ in values)
        rows = conn.execute(
            f"SELECT verdict, tier FROM enrichment_results WHERE value IN ({placeholders}) "
            f"AND fetched_at >= datetime('now', ?)",
            (*values, f'-{ENRICHMENT_CACHE_TTL_HOURS} hours')
        ).fetchall()
        best = 0
        for r in rows:
            if r['tier'] == 'definite' and r['verdict'] == 'malicious':
                best = max(best, _CONFIDENCE_POINTS_DEFINITE_MALICIOUS)
            elif r['tier'] == 'heuristic' and r['verdict'] == 'malicious':
                best = max(best, _CONFIDENCE_POINTS_HEURISTIC_MALICIOUS)
            elif r['verdict'] == 'suspicious':
                best = max(best, _CONFIDENCE_POINTS_SUSPICIOUS)
        points += best
    if points >= 40:
        tier = 'confirmed'
    elif points >= 20:
        tier = 'high'
    elif points >= 10:
        tier = 'medium'
    elif points > 0:
        tier = 'low'
    else:
        return  # no signal at all -- leave confidence_score/tier NULL, not zero-and-'low'
    conn.execute("UPDATE alerts SET confidence_score = ?, confidence_tier = ? WHERE id = ?", (points, tier, alert_id))


def auto_enrich_and_score_alert(conn, alert_id, host, source_ip, destination_ip, file_hash, severity, daily_max=AUTO_ENRICH_DAILY_MAX_DEFAULT):
    """Called once, right after a NEW alert is inserted. The two halves are
    independent: enrichment is severity+budget gated since it spends real external API
    quota; scoring is not, since it's local-only and cheap -- it runs even for a
    Low/Medium alert, using whatever enrichment data already exists from an earlier,
    unrelated lookup. Never raises: every analyzer function already degrades to
    {'ok': False, 'verdict': 'error', ...} rather than throwing, and this wraps its own
    SQL too, so one bad alert can never abort the caller's whole detection cycle or
    ingest request."""
    try:
        key_row = conn.execute("SELECT value FROM settings WHERE key = 'enrichment_api_keys'").fetchone()
        api_keys = json.loads(key_row['value']) if key_row and key_row['value'] else {}
        if (severity or '').strip().lower() in AUTO_ENRICH_SEVERITIES and _auto_enrich_budget_ok(conn, daily_max):
            if source_ip:
                _enrich_value(conn, api_keys, source_ip, 'ip')
            if destination_ip and destination_ip != source_ip:
                _enrich_value(conn, api_keys, destination_ip, 'ip')
            if file_hash:
                _enrich_value(conn, api_keys, file_hash, 'hash')
        _score_alert_confidence(conn, alert_id, [source_ip, destination_ip, file_hash])
    except Exception:
        pass
