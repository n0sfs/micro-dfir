# Shared vulnerability-matching engine -- imported directly by both src/app.py (the
# live per-host lookup, Flask context) and src/generate_report.py (the Vulnerability
# Report and cron-scheduled generation, no Flask context), same plain-module-with-no-
# Flask-dependency shape src/agent_scripts.py already uses for the same reason. A real
# matching *algorithm* duplicated across two files would be a correctness hazard (two
# copies to keep in sync, easy to silently drift) -- unlike the small, rarely-changing
# constant dicts (COMPLIANCE_FRAMEWORK_LABELS, SCA_CHECK_FRAMEWORKS) this codebase does
# deliberately duplicate elsewhere, this is real logic, so it lives in exactly one place.
import re

_SOFTWARE_NAME_JUNK_RE = re.compile(r'\s*\((?:x86|x64|32-bit|64-bit)\)\s*', re.IGNORECASE)
_SOFTWARE_NAME_NONALNUM_RE = re.compile(r'[^a-z0-9]+')

def normalize_software_name(name):
    n = _SOFTWARE_NAME_JUNK_RE.sub(' ', (name or '').lower())
    return _SOFTWARE_NAME_NONALNUM_RE.sub(' ', n).strip()

_VERSION_EPOCH_RE = re.compile(r'^\d+:')
_VERSION_SPLIT_RE = re.compile(r'[.\-_~+]')

def _parse_version_loose(v):
    # Deliberately lenient/best-effort, not a real semver or Debian-policy parser --
    # installed-version strings span Windows' free-text DisplayVersion (whatever the
    # installer author typed), Debian's "epoch:upstream-revision" (dpkg -W's ${Version}),
    # and RPM's "version-release" (rpm -qa's %{VERSION}-%{RELEASE}), none of which are
    # true semver and none of which share a format with the other two. Each segment is
    # tagged (0, int) if numeric or (1, str) if not, so numeric segments always compare
    # numerically (not "10" < "9" as strings) and a numeric/non-numeric pair at the same
    # position still compares deterministically instead of raising.
    if not v:
        return []
    s = _VERSION_EPOCH_RE.sub('', str(v).strip())
    parts = [p for p in _VERSION_SPLIT_RE.split(s) if p != '']
    out = []
    for p in parts:
        if p.isdigit():
            out.append((0, int(p)))
        else:
            out.append((1, p.lower()))
    return out

def _compare_versions(a, b):
    # -1/0/1. A shorter parsed sequence sorts as "less" at the first missing segment
    # (so "1.2" < "1.2.1"), via a fillvalue that sorts below every real segment tag.
    pa, pb = _parse_version_loose(a), _parse_version_loose(b)
    from itertools import zip_longest
    for x, y in zip_longest(pa, pb, fillvalue=(-1, 0)):
        if x < y:
            return -1
        if x > y:
            return 1
    return 0

def version_matches_range(installed, flat_version, start_inc=None, start_exc=None, end_inc=None, end_exc=None):
    # No range fields at all -- today's pre-existing behavior, unchanged: an empty or
    # '*' flat_version (NVD's CPE match wasn't pinned to one exact version) means "no
    # constraint", otherwise it's an exact-version match.
    if not any([start_inc, start_exc, end_inc, end_exc]):
        if not flat_version or flat_version == '*':
            return True
        return _compare_versions(installed, flat_version) == 0
    if start_inc and _compare_versions(installed, start_inc) < 0:
        return False
    if start_exc and _compare_versions(installed, start_exc) <= 0:
        return False
    if end_inc and _compare_versions(installed, end_inc) > 0:
        return False
    if end_exc and _compare_versions(installed, end_exc) >= 0:
        return False
    return True

def correlate_software_vulnerabilities(db, apps):
    # Explicitly approximate on the NAME side, same caveat this codebase already
    # documents elsewhere: NVD's own CPE product names rarely match a vendor's
    # installer-reported DisplayName exactly ("Google Chrome" vs CPE product "chrome"),
    # so this checks whether the CPE product name appears as a whole word/phrase in the
    # app's normalized name -- catches the common vendor-prefixed-name case without
    # falling back to raw substring matching, which would flag almost anything against
    # short/generic CPE product names and bury real findings in noise. A short (<4 char)
    # CPE product name is skipped entirely for the same reason. The VERSION side is now
    # real range matching (version_matches_range), not the flat string-equality this
    # used to do.
    #
    # Pulling the full cve_affected_products table into Python rather than pushing this
    # matching into SQL is deliberate: word-boundary matching isn't expressible cleanly
    # in a LIKE clause, and at this table's real size (a rolling ~7-day CVE window, a
    # few thousand affected-product rows at most) a full in-memory pass per correlation
    # call (not a hot path -- triggered on demand per host, or once per host for a
    # fleet-wide report/widget) is cheap.
    candidates = db.execute(
        "SELECT cap.cve_id, cap.vendor, cap.product, cap.version, "
        "cap.version_start_including, cap.version_start_excluding, "
        "cap.version_end_including, cap.version_end_excluding, "
        "cr.severity, cr.cvss_score, cr.description "
        "FROM cve_affected_products cap JOIN cve_records cr ON cr.cve_id = cap.cve_id "
        "WHERE LENGTH(cap.product) >= 4"
    ).fetchall()

    matches = []
    seen = set()
    for app in apps:
        name_norm = normalize_software_name(app.get('name', ''))
        if not name_norm:
            continue
        version = (app.get('version') or '').strip()
        for c in candidates:
            product_norm = normalize_software_name(c['product'])
            if not product_norm:
                continue
            # Whole-word/whole-phrase containment, not `in name_words` (a set of single
            # words can never contain a multi-word product like "7 zip") and not raw
            # substring containment either (that would let a short product name match
            # as part of an unrelated longer word). Padding both sides with spaces turns
            # "is product_norm one of the space-separated tokens/phrases in name_norm"
            # into a plain substring check.
            if f' {product_norm} ' not in f' {name_norm} ':
                continue
            if not version_matches_range(
                version, c['version'],
                c['version_start_including'], c['version_start_excluding'],
                c['version_end_including'], c['version_end_excluding'],
            ):
                continue
            key = (app.get('name'), c['cve_id'])
            if key in seen:
                continue
            seen.add(key)
            matches.append({
                'installed_name': app.get('name'), 'installed_version': app.get('version'),
                'cve_id': c['cve_id'], 'severity': c['severity'], 'cvss_score': c['cvss_score'],
                'matched_product': c['product'], 'description': c['description'],
            })
    matches.sort(key=lambda m: (m['cvss_score'] or 0), reverse=True)
    return matches

def latest_software_inventory(db):
    # Same "latest agent_commands row per hostname" shape as generate_report.py's own
    # _latest_sca_results, applied to collect_software_inventory instead of sca_check.
    # Returns [{hostname, apps: [...]}], skipping a row whose stdout isn't valid JSON
    # rather than raising.
    import json
    rows = db.execute(
        "SELECT hostname, stdout FROM agent_commands WHERE label = 'collect_software_inventory' AND status = 'done' "
        "AND id IN (SELECT MAX(id) FROM agent_commands WHERE label = 'collect_software_inventory' AND status = 'done' GROUP BY hostname)"
    ).fetchall()
    results = []
    for row in rows:
        try:
            parsed = json.loads(row['stdout']) if row['stdout'] else None
        except (ValueError, TypeError):
            parsed = None
        apps = parsed.get('apps') if isinstance(parsed, dict) else None
        if isinstance(apps, list):
            results.append({'hostname': row['hostname'], 'apps': apps})
    return results
