"""Lightweight on-demand IOC enrichment (Cortex's analyzer pattern, minimal version): a
small registry of independent functions, each taking an IOC value and returning a
normalized {ok, verdict, summary, raw} result. Run synchronously on demand -- no queue,
no separate service, just a direct API call with a short timeout -- since this is a
one-shot "check this value" action, not a bulk pipeline. Callers cache results (see
app.py's enrichment_results table) so repeat lookups don't re-hit free-tier rate limits.
"""
import requests

ENRICHMENT_CACHE_TTL_HOURS = 24


def _shodan_internetdb(value, api_key=None):
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


def _abuseipdb(value, api_key=None):
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


# 'settings_key' is the key each requires_key=True analyzer's API key is stored under
# in the enrichment_api_keys settings blob (see app.py's api_ti_enrichment_settings).
ANALYZERS = [
    {'key': 'shodan_internetdb', 'label': 'Shodan InternetDB', 'ioc_types': ('ip',),
     'requires_key': False, 'settings_key': None, 'run': _shodan_internetdb},
    {'key': 'abuseipdb', 'label': 'AbuseIPDB', 'ioc_types': ('ip',),
     'requires_key': True, 'settings_key': 'abuseipdb_api_key', 'run': _abuseipdb},
]


def applicable_analyzers(ioc_type):
    """Which registered analyzers apply to a given ioc_type string. ioc_type vocabulary
    varies by feed ('ip', 'ipv4-addr', 'ip-src', 'ip-dst', ...) -- substring match on
    'ip', same reasoning as the other ioc_type-shape checks elsewhere in this codebase."""
    t = (ioc_type or '').lower()
    if 'ip' in t:
        return [a for a in ANALYZERS if 'ip' in a['ioc_types']]
    return []
