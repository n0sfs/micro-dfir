"""Lightweight on-demand IOC enrichment (Cortex's analyzer pattern, minimal version): a
small registry of independent functions, each taking an IOC value and returning a
normalized {ok, verdict, summary, raw} result. Run synchronously on demand -- no queue,
no separate service, just a direct API call with a short timeout -- since this is a
one-shot "check this value" action, not a bulk pipeline. Callers cache results (see
app.py's enrichment_results table) so repeat lookups don't re-hit free-tier rate limits.
"""
import base64
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


# 'settings_key' is the key each requires_key=True analyzer's API key is stored under
# in the enrichment_api_keys settings blob (see app.py's api_ti_enrichment_settings).
ANALYZERS = [
    {'key': 'shodan_internetdb', 'label': 'Shodan InternetDB', 'ioc_types': ('ip',),
     'requires_key': False, 'settings_key': None, 'run': _shodan_internetdb},
    {'key': 'abuseipdb', 'label': 'AbuseIPDB', 'ioc_types': ('ip',),
     'requires_key': True, 'settings_key': 'abuseipdb_api_key', 'run': _abuseipdb},
    {'key': 'virustotal', 'label': 'VirusTotal', 'ioc_types': ('ip', 'hash', 'domain', 'url'),
     'requires_key': True, 'settings_key': 'virustotal_api_key', 'run': _virustotal},
    {'key': 'urlhaus', 'label': 'URLhaus', 'ioc_types': ('domain', 'url'),
     'requires_key': True, 'settings_key': 'urlhaus_api_key', 'run': _urlhaus},
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
