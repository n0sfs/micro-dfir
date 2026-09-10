"""Submit-then-poll sandbox/detonation clients -- a genuinely different shape from
analyzers.py's single-call synchronous lookups, so this is a sibling module, not an
addition to that file. Same house style as analyzers.py (short timeout, never raise,
plain dict return) even though the two-step submit/poll flow itself is new territory
for this codebase.

urlscan.io is the only source implemented here -- a real free sandboxed-browser visit
(screenshot, DOM, every network request, TLS cert chain, a verdict), confirmed via
urlscan's own current API docs (https://urlscan.io/docs/api/) before building this, not
from memory. filescan.io and a self-hosted CAPE Sandbox client are deliberately NOT
built here (see the DFIR SME review plan this pass follows): filescan.io's docs are
JS-rendered and unverifiable without a live API key, and CAPE needs its own separate
host with a hypervisor + guest VM(s) this appliance doesn't have. Both would land in
this same module, as new functions, when that infrastructure/verification exists --
nothing about this module's shape is urlscan-specific.
"""
import requests

URLSCAN_POLL_TIMEOUT = 10


def urlscan_submit(url, api_key, visibility='private'):
    """POST https://urlscan.io/api/v1/scan/ -- returns {'ok': True, 'job_id': uuid,
    'report_url': ...} on success, {'ok': False, 'error': ...} otherwise. Never raises.
    visibility: 'private' (default -- not indexed/searchable, 50/day free quota) or
    'public' (indexed and searchable by anyone on urlscan.io, 5,000/day free quota) --
    the caller decides per-submission, this function has no opinion beyond the default."""
    if not api_key:
        return {'ok': False, 'error': 'No urlscan.io API key configured.'}
    if visibility not in ('private', 'public', 'unlisted'):
        visibility = 'private'
    try:
        res = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={'API-Key': api_key, 'Content-Type': 'application/json'},
            json={'url': url, 'visibility': visibility},
            timeout=URLSCAN_POLL_TIMEOUT
        )
        if res.status_code == 400:
            # A malformed/blocklisted URL, or a duplicate-within-a-few-minutes
            # resubmission -- urlscan's own 400 body carries a real message field.
            try:
                msg = res.json().get('message', 'Rejected by urlscan.io.')
            except ValueError:
                msg = 'Rejected by urlscan.io.'
            return {'ok': False, 'error': msg}
        res.raise_for_status()
        data = res.json() or {}
        job_id = data.get('uuid')
        if not job_id:
            return {'ok': False, 'error': 'urlscan.io accepted the submission but returned no scan id.'}
        return {'ok': True, 'job_id': job_id, 'report_url': data.get('result'), 'visibility': visibility}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def urlscan_poll(job_id, api_key):
    """GET https://urlscan.io/api/v1/result/{uuid}/ -- 404 while still scanning (mapped
    to {'ok': True, 'status': 'pending'}), 200 once ready. Extracts a normalized verdict
    from result.verdicts.overall (malicious/score), a human summary, the report/
    screenshot URLs, and the full raw result for storage. Never raises -- a genuine
    error (not "still pending") maps to {'ok': True, 'status': 'error', ...} so a
    caller's polling loop always has a status to act on rather than an exception to
    catch.

    Field names below (verdicts.overall.malicious/score, task.reportURL,
    task.screenshotURL) match urlscan.io's documented result shape as of this writing --
    confirm against one real completed scan during live-verification before trusting
    this in production, same discipline this session already applied to Censys."""
    try:
        res = requests.get(
            f"https://urlscan.io/api/v1/result/{job_id}/",
            headers={'API-Key': api_key} if api_key else {},
            timeout=URLSCAN_POLL_TIMEOUT
        )
        if res.status_code == 404:
            return {'ok': True, 'status': 'pending'}
        res.raise_for_status()
        data = res.json() or {}
        verdicts = (data.get('verdicts') or {}).get('overall', {})
        task = data.get('task') or {}
        page = data.get('page') or {}
        malicious = bool(verdicts.get('malicious'))
        score = verdicts.get('score')
        verdict = 'malicious' if malicious else ('suspicious' if (score or 0) > 0 else 'clean')
        summary = (f"Verdict score {score if score is not None else '?'}/100"
                   + (f"; domain: {page.get('domain')}" if page.get('domain') else '')
                   + (f"; IP: {page.get('ip')}" if page.get('ip') else ''))
        return {
            'ok': True, 'status': 'complete', 'verdict': verdict, 'summary': summary,
            'report_url': task.get('reportURL'), 'screenshot_url': task.get('screenshotURL'),
            'raw': data,
        }
    except Exception as e:
        return {'ok': True, 'status': 'error', 'error': str(e)}
