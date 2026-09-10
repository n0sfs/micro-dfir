"""Submit-then-poll sandbox/detonation clients -- a genuinely different shape from
analyzers.py's single-call synchronous lookups, so this is a sibling module, not an
addition to that file. Same house style as analyzers.py (short timeout, never raise,
plain dict return) even though the two-step submit/poll flow itself is new territory
for this codebase.

Three sources are implemented here:

- **urlscan.io** -- a real free sandboxed-browser visit (screenshot, DOM, every network
  request, TLS cert chain, a verdict), URL-only, confirmed via urlscan's own current API
  docs (https://urlscan.io/docs/api/).
- **filescan.io** -- file AND URL detonation. Its own docs page (filescan.io/api/docs)
  is JS-rendered and unfetchable (still true as of this writing), so this was verified
  a different way: against filescanio/fsio-cli, OPSWAT's own open-source reference
  Python client (github.com/filescanio/fsio-cli), reading its
  filescan_cli/service/{endpoints,headers,scan}.py source directly. The free community
  tier is confirmed PUBLIC-ONLY (OPSWAT's own tier-comparison docs: "Free Triage with
  public reports", no private option) -- unlike urlscan, there is no free private tier
  here at all. The `is_private` parameter below is sent regardless (harmless if the
  service ignores it) but must not be trusted to actually keep a submission private on
  the free tier without live confirmation against a real key.
- **Hybrid Analysis** (Falcon Sandbox, CrowdStrike) -- file AND URL detonation, a real
  free community API, verified against dark0pcodes/hybrid_analysis_api (an open-source
  client whose source shows the exact endpoints/headers) and independently corroborated
  by Hybrid Analysis's own curl examples for the required `user-agent: Falcon Sandbox`
  header. A NEW API key starts at 'restricted' privilege (search-only) -- submitting
  files/URLs requires a one-time manual vetting request in Hybrid Analysis's own UI to
  reach 'default' privilege, an out-of-band admin action this module can't do anything
  about, only surface a clear error for.

A self-hosted CAPE Sandbox client is still deliberately NOT built here (see the DFIR
SME review plan this pass follows): CAPE needs its own separate host with a hypervisor
+ guest VM(s) this appliance doesn't have. It would land in this same module, as a new
function, when that infrastructure exists -- nothing about this module's shape is
source-specific.
"""
import json
import requests

URLSCAN_POLL_TIMEOUT = 10
FILESCAN_BASE_URL = "https://www.filescan.io"
FILESCAN_TIMEOUT = 20  # file uploads are slower than a URL-only POST
HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
HYBRID_ANALYSIS_TIMEOUT = 20
# Windows 10 64-bit -- the most broadly-applicable default environment for an
# unattended submission where the caller has no reason to pick a specific OS/arch.
# A future per-submission environment picker is real but not built here (see the
# sandbox tab's UI plan) -- confirm this id is still current against a real key's
# GET system/environments response before trusting it long-term.
HYBRID_ANALYSIS_DEFAULT_ENVIRONMENT_ID = 160


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


def filescan_submit(api_key, file_path=None, file_name=None, url=None, is_private=True):
    """POST {FILESCAN_BASE_URL}/api/scan/file -- one endpoint handles BOTH a file
    upload (multipart 'file' field) and a URL submission (multipart 'link' field),
    unlike urlscan's URL-only API. Exactly one of file_path or url must be given.
    Returns {'ok': True, 'scan_id': ..., 'flow_id': ...} or {'ok': False, 'error': ...}.
    Never raises.

    Auth: 'X-Api-Key' header (confirmed via fsio-cli's filescan_cli/service/headers.py).
    Endpoint path and the file/link field names are confirmed via fsio-cli's
    filescan_cli/service/{endpoints,scan}.py. The exact wire shape of the 'extra'
    options object (description/tags/is_private/password) that fsio-cli's own flow
    layer builds could NOT be independently confirmed from the client source alone
    (conflicting signals on whether it travels as a form field or a header) -- sent
    here as a JSON-encoded 'extra' form field, the more conventional REST shape, but
    flag this specifically for live confirmation against a real API key before
    trusting is_private to actually restrict visibility on the free tier (which
    OPSWAT's own docs say is public-only regardless -- see this module's docstring)."""
    if not api_key:
        return {'ok': False, 'error': 'No filescan.io API key configured.'}
    if not file_path and not url:
        return {'ok': False, 'error': 'filescan_submit requires either a file or a URL.'}
    opened_file = None
    try:
        headers = {'X-Api-Key': api_key, 'accept': 'application/json'}
        data = {'extra': json.dumps({'is_private': bool(is_private)})}
        files = None
        if file_path:
            opened_file = open(file_path, 'rb')
            files = {'file': (file_name or 'sample', opened_file, 'application/octet-stream')}
        else:
            data['link'] = url
        res = requests.post(
            f"{FILESCAN_BASE_URL}/api/scan/file",
            headers=headers, data=data, files=files, timeout=FILESCAN_TIMEOUT
        )
        if res.status_code in (400, 401, 403):
            try:
                msg = res.json().get('message') or res.json().get('error') or 'Rejected by filescan.io.'
            except ValueError:
                msg = 'Rejected by filescan.io.'
            return {'ok': False, 'error': msg}
        res.raise_for_status()
        result = res.json() or {}
        scan_id = result.get('flow_id') or result.get('id') or result.get('scan_id')
        if not scan_id:
            return {'ok': False, 'error': 'filescan.io accepted the submission but returned no scan id.'}
        return {'ok': True, 'scan_id': str(scan_id), 'report_url': f"{FILESCAN_BASE_URL}/uploads/{scan_id}"}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    finally:
        if opened_file:
            opened_file.close()


def filescan_poll(scan_id, api_key):
    """GET {FILESCAN_BASE_URL}/api/scan/{scan_id}/report -- polled the same
    submit-then-poll way as urlscan_poll. fsio-cli's own polling loop (confirmed
    directly from filescan_cli/flow/scan.py) checks report['overallState'] ('success'
    / 'failed') and report['allFinished'] (True once every sub-analysis has completed)
    to decide when to stop -- mirrored here. Never raises; a genuine error maps to
    {'ok': True, 'status': 'error', ...} matching urlscan_poll's own contract so both
    sources' results are interchangeable to a caller's polling loop."""
    try:
        res = requests.get(
            f"{FILESCAN_BASE_URL}/api/scan/{scan_id}/report",
            headers={'X-Api-Key': api_key, 'accept': 'application/json'} if api_key else {'accept': 'application/json'},
            timeout=FILESCAN_TIMEOUT
        )
        if res.status_code == 404:
            return {'ok': True, 'status': 'pending'}
        res.raise_for_status()
        data = res.json() or {}
        if not data.get('allFinished'):
            return {'ok': True, 'status': 'pending'}
        overall_state = (data.get('overallState') or '').lower()
        if overall_state == 'failed':
            return {'ok': True, 'status': 'error', 'error': data.get('error') or 'filescan.io analysis failed.'}
        # filescan.io's own verdict vocabulary isn't independently confirmed here (no
        # live key to check a real completed report against) -- 'verdict'/'malicious'
        # are the most commonly documented top-level fields in third-party client
        # code, with a safe 'unknown' fallback rather than guessing further.
        verdict_raw = (data.get('verdict') or ('malicious' if data.get('malicious') else None) or 'unknown')
        verdict = verdict_raw if verdict_raw in ('malicious', 'suspicious', 'clean') else 'unknown'
        summary = f"filescan.io analysis complete (overallState: {data.get('overallState')})"
        return {
            'ok': True, 'status': 'complete', 'verdict': verdict, 'summary': summary,
            'report_url': f"{FILESCAN_BASE_URL}/uploads/{scan_id}", 'raw': data,
        }
    except Exception as e:
        return {'ok': True, 'status': 'error', 'error': str(e)}


def hybrid_analysis_submit(api_key, file_path=None, file_name=None, url=None, is_private=True,
                            environment_id=HYBRID_ANALYSIS_DEFAULT_ENVIRONMENT_ID):
    """POST {HYBRID_ANALYSIS_BASE_URL}/submit/file (multipart 'file' field) or
    /submit/url-for-analysis ('url' form field) -- both require environment_id (which
    sandbox VM image to run in; 160 = Windows 10 64-bit, the default here). Confirmed
    against dark0pcodes/hybrid_analysis_api's open-source client source
    (hybrid_analysis_api/__init__.py) for endpoint paths/methods, and independently
    corroborated by Hybrid Analysis's own published curl examples for the required
    headers. Returns {'ok': True, 'job_id': ...} or {'ok': False, 'error': ...}.

    A brand-new API key starts at 'restricted' privilege (search-only) -- submitting
    files/URLs needs a one-time manual vetting request in Hybrid Analysis's own UI to
    reach 'default' privilege first; a 403 here most likely means that hasn't happened
    yet, surfaced as a specific error rather than a generic failure.

    is_private maps to the 'no_share_third_party' submission option (confirmed as a
    real parameter in Hybrid Analysis's own extra_params) -- this keeps the analysis
    out of Hybrid Analysis's third-party intel-sharing partners, NOT off the platform
    entirely; unlike urlscan.io there is no fully-private submission tier here, a real
    difference worth the analyst knowing before treating this as equivalent."""
    if not api_key:
        return {'ok': False, 'error': 'No Hybrid Analysis API key configured.'}
    if not file_path and not url:
        return {'ok': False, 'error': 'hybrid_analysis_submit requires either a file or a URL.'}
    opened_file = None
    try:
        headers = {'api-key': api_key, 'user-agent': 'Falcon Sandbox', 'accept': 'application/json'}
        if file_path:
            opened_file = open(file_path, 'rb')
            data = {'environment_id': environment_id, 'no_share_third_party': '1' if is_private else '0'}
            files = {'file': (file_name or 'sample', opened_file, 'application/octet-stream')}
            res = requests.post(f"{HYBRID_ANALYSIS_BASE_URL}/submit/file", headers=headers,
                                 data=data, files=files, timeout=HYBRID_ANALYSIS_TIMEOUT)
        else:
            data = {'environment_id': environment_id, 'url': url, 'no_share_third_party': '1' if is_private else '0'}
            res = requests.post(f"{HYBRID_ANALYSIS_BASE_URL}/submit/url-for-analysis", headers=headers,
                                 data=data, timeout=HYBRID_ANALYSIS_TIMEOUT)
        if res.status_code == 403:
            return {'ok': False, 'error': 'Hybrid Analysis rejected this (HTTP 403) -- this API key may still be at '
                                           '"restricted" privilege. Submitting files/URLs needs a one-time vetting '
                                           'request approved in your Hybrid Analysis account first.'}
        if res.status_code == 429:
            return {'ok': False, 'error': 'Hybrid Analysis rate limit reached -- try again later.'}
        res.raise_for_status()
        result = res.json() or {}
        job_id = result.get('job_id') or result.get('id')
        if not job_id:
            return {'ok': False, 'error': 'Hybrid Analysis accepted the submission but returned no job id.'}
        return {'ok': True, 'job_id': job_id, 'report_url': f"https://www.hybrid-analysis.com/sample/{job_id}"}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    finally:
        if opened_file:
            opened_file.close()


def hybrid_analysis_poll(job_id, api_key):
    """GET {HYBRID_ANALYSIS_BASE_URL}/report/{job_id}/state, then (once state is
    terminal) GET .../report/{job_id}/summary for the verdict/threat score. State
    values and the verdict vocabulary ('whitelisted'/'no verdict'/'no specific
    threat'/'suspicious'/'malicious') are confirmed via Hybrid Analysis's own public
    knowledge-base/FAQ pages, not the client source (which doesn't parse them itself
    -- the caller does) -- still worth a live re-check against one real completed job
    before fully trusting the exact strings. Never raises."""
    try:
        res = requests.get(
            f"{HYBRID_ANALYSIS_BASE_URL}/report/{job_id}/state",
            headers={'api-key': api_key, 'user-agent': 'Falcon Sandbox', 'accept': 'application/json'},
            timeout=HYBRID_ANALYSIS_TIMEOUT
        )
        if res.status_code == 404:
            return {'ok': True, 'status': 'pending'}
        res.raise_for_status()
        state = ((res.json() or {}).get('state') or '').upper()
        if state in ('IN_QUEUE', 'IN_PROGRESS', ''):
            return {'ok': True, 'status': 'pending'}
        if state == 'ERROR':
            return {'ok': True, 'status': 'error', 'error': 'Hybrid Analysis reported an analysis error.'}
        # state == 'SUCCESS' (or any other terminal-but-unrecognized value) -- fetch
        # the actual verdict from the summary endpoint rather than assuming success.
        summary_res = requests.get(
            f"{HYBRID_ANALYSIS_BASE_URL}/report/{job_id}/summary",
            headers={'api-key': api_key, 'user-agent': 'Falcon Sandbox', 'accept': 'application/json'},
            timeout=HYBRID_ANALYSIS_TIMEOUT
        )
        summary_res.raise_for_status()
        data = summary_res.json() or {}
        verdict_raw = (data.get('verdict') or 'no verdict').lower()
        verdict = 'malicious' if verdict_raw == 'malicious' else ('suspicious' if verdict_raw == 'suspicious' else
                  ('clean' if verdict_raw in ('whitelisted', 'no specific threat') else 'unknown'))
        threat_score = data.get('threat_score')
        summary = f"Verdict: {verdict_raw}" + (f" (threat score: {threat_score}/100)" if threat_score is not None else "")
        return {
            'ok': True, 'status': 'complete', 'verdict': verdict, 'summary': summary,
            'report_url': f"https://www.hybrid-analysis.com/sample/{job_id}", 'raw': data,
        }
    except Exception as e:
        return {'ok': True, 'status': 'error', 'error': str(e)}
