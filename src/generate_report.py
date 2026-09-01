import base64, json, mimetypes, os, re, sqlite3
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import vuln_matching

BASE_DIR = "/opt/micro-dfir"
DB_PATH = os.path.join(BASE_DIR, "siem.db")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
REPORT_OUTPUT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

# Kept in sync with app.py's COMPLIANCE_FRAMEWORKS -- both need the same key set, and
# this is also the one place the human-readable label lives (previously duplicated a
# second time in dashboard.html's JS as its own separate list).
COMPLIANCE_FRAMEWORK_LABELS = {
    'pci_dss': 'PCI DSS', 'hipaa': 'HIPAA', 'nist_800_53': 'NIST 800-53',
    'nist_csf': 'NIST CSF', 'iso_27001': 'ISO 27001', 'soc2': 'SOC 2',
    'cis_controls': 'CIS Controls', 'gdpr': 'GDPR',
}

# Kept in sync with app.py's SCA_CHECK_FRAMEWORKS -- same reasoning as
# COMPLIANCE_FRAMEWORK_LABELS above (this module runs its own sqlite3 connection, not
# Flask's get_db(), so the mapping is duplicated rather than imported).
SCA_CHECK_FRAMEWORKS = {
    'firewall_enabled': ['pci_dss', 'cis_controls', 'nist_800_53', 'nist_csf', 'iso_27001', 'soc2'],
    'smb1_disabled': ['cis_controls', 'nist_800_53', 'pci_dss'],
    'rdp_nla': ['cis_controls', 'nist_800_53', 'pci_dss', 'soc2'],
    'defender_realtime': ['cis_controls', 'nist_800_53', 'hipaa', 'pci_dss', 'soc2'],
    'guest_disabled': ['cis_controls', 'nist_800_53', 'pci_dss', 'iso_27001'],
    'uac_enabled': ['cis_controls', 'nist_800_53'],
    'lm_hash_disabled': ['cis_controls', 'pci_dss', 'nist_800_53'],
    'autorun_disabled': ['cis_controls', 'nist_800_53'],
    'ps_execution_policy': ['cis_controls', 'nist_800_53'],
    'bitlocker_enabled': ['hipaa', 'pci_dss', 'nist_800_53', 'gdpr', 'iso_27001', 'soc2'],
    'windows_update_service': ['cis_controls', 'nist_800_53', 'pci_dss'],
    'account_lockout': ['pci_dss', 'hipaa', 'nist_800_53', 'cis_controls', 'iso_27001', 'soc2', 'gdpr'],
    'ssh_root_login': ['cis_controls', 'nist_800_53', 'pci_dss', 'soc2'],
    'ssh_password_auth': ['cis_controls', 'nist_800_53', 'pci_dss', 'soc2'],
    'firewall_active': ['pci_dss', 'cis_controls', 'nist_800_53', 'nist_csf', 'iso_27001', 'soc2'],
    'passwd_perms': ['cis_controls', 'nist_800_53'],
    'shadow_perms': ['cis_controls', 'nist_800_53', 'pci_dss'],
    'no_empty_passwords': ['pci_dss', 'hipaa', 'cis_controls', 'nist_800_53', 'soc2'],
    'password_min_len': ['pci_dss', 'hipaa', 'cis_controls', 'nist_800_53', 'soc2', 'iso_27001'],
    'password_max_days': ['pci_dss', 'cis_controls', 'nist_800_53'],
    'core_dumps_restricted': ['cis_controls', 'nist_800_53'],
    'aslr_enabled': ['cis_controls', 'nist_800_53'],
    'time_sync_active': ['cis_controls', 'nist_800_53', 'pci_dss'],
}

# Kept in sync with app.py's SIGMA_LOGSOURCE_INGESTED_APPS/_extract_yaml_field -- same
# no-Flask-context reasoning as the two catalogs above. Used only by
# _framework_relevant_apps() below, to answer "which live_logs.app values does this
# framework's own tagged-rule set actually depend on" for the Log Volume report section.
def _extract_yaml_field(key, text):
    m = re.search(rf'^\s*{key}:\s*([^\n\r#]+)', text, re.MULTILINE)
    return m.group(1).strip().strip("'\"") if m else None

SIGMA_LOGSOURCE_INGESTED_APPS = {
    ('windows', 'sysmon'): {'sysmon'},
    ('windows', 'security'): {'security'},
    ('windows', 'system'): {'system'},
    ('windows', 'application'): {'application'},
    ('windows', 'powershell'): {'powershell'},
    ('windows', 'powershell-classic'): {'powershell'},
    ('windows', 'windefend'): {'windows defender'},
    ('windows', None): {'sysmon', 'security', 'system', 'application', 'powershell', 'windows defender'},
    ('linux', 'auditd'): {'auditd'},
    ('linux', 'syslog'): set(),
    ('linux', None): {'systemd', 'sshd', 'kernel', 'cron', 'dbus-daemon', 'systemd-logind', 'wpa_supplicant', 'fwupd'},
    ('aws', None): set(),
    ('azure', None): set(),
    ('gcp', None): set(),
    ('okta', None): set(),
    ('m365', None): set(),
    ('github', None): set(),
}

def _latest_sca_results(cursor):
    rows = cursor.execute(
        "SELECT hostname, stdout FROM agent_commands WHERE label = 'sca_check' AND status = 'done' "
        "AND id IN (SELECT MAX(id) FROM agent_commands WHERE label = 'sca_check' AND status = 'done' GROUP BY hostname)"
    ).fetchall()
    results = []
    for row in rows:
        try:
            parsed = json.loads(row['stdout']) if row['stdout'] else None
        except (ValueError, TypeError):
            parsed = None
        checks = parsed.get('checks') if isinstance(parsed, dict) else None
        if isinstance(checks, list):
            results.append({'hostname': row['hostname'], 'checks': checks})
    return results

def _sca_framework_aggregate(sca_results):
    agg = {key: {'total': 0, 'passed': 0, 'failed': 0, 'errored': 0} for key in COMPLIANCE_FRAMEWORK_LABELS}
    failing = []
    for host in sca_results:
        for check in host['checks']:
            frameworks = SCA_CHECK_FRAMEWORKS.get(check.get('id'))
            if not frameworks:
                continue
            status = check.get('status')
            for fw in frameworks:
                if fw not in agg:
                    continue
                agg[fw]['total'] += 1
                if status == 'pass':
                    agg[fw]['passed'] += 1
                elif status == 'fail':
                    agg[fw]['failed'] += 1
                elif status == 'error':
                    agg[fw]['errored'] += 1
            if status == 'fail':
                failing.append({
                    'hostname': host['hostname'], 'title': check.get('title', check.get('id')),
                    'detail': check.get('detail', ''),
                    'frameworks': ', '.join(COMPLIANCE_FRAMEWORK_LABELS.get(f, f) for f in frameworks),
                })
    failing.sort(key=lambda f: (f['title'], f['hostname']))
    return agg, failing

# Action categories a compliance reviewer would specifically want called out, not
# buried in a full activity list -- user management, credential/cert changes, and
# anything that alters what gets retained.
AUDIT_SENSITIVE_ACTIONS = (
    'user_create', 'user_password_reset', 'user_delete',
    'soc_token_change', 'network_config_change', 'tls_cert_upload',
    'retention_policy_change', 'manual_log_purge', 'db_vacuum',
)
AUDIT_REPORT_ROW_CAP = 200

# Mirrors app.py's REPORT_BRANDING_DEFAULTS/REPORT_BRANDING_DIR exactly -- this script
# has no Flask app context (cron invokes it directly), so it can't import app.py's
# copy and keeps its own, same reasoning as RISK_SCORE_DEFAULTS/DB_PATH being
# duplicated across this codebase's standalone scripts rather than cross-imported.
REPORT_BRANDING_DIR = "/opt/micro-dfir/data/branding"
REPORT_BRANDING_DEFAULTS = {
    "company_name": "Micro DFIR", "logo_filename": None,
    "footer_text": "Generated by Micro DFIR SOAR Engine", "accent_color": "#0d6efd",
}

def _branding_context(conn):
    import json
    cfg = dict(REPORT_BRANDING_DEFAULTS)
    row = conn.execute("SELECT value FROM settings WHERE key = 'report_branding_config'").fetchone()
    if row and row[0]:
        try:
            cfg.update(json.loads(row[0]))
        except (ValueError, TypeError):
            pass
    cfg['logo_data_uri'] = None
    if cfg.get('logo_filename'):
        path = os.path.join(REPORT_BRANDING_DIR, cfg['logo_filename'])
        if os.path.exists(path):
            mime = mimetypes.guess_type(path)[0] or 'image/png'
            with open(path, 'rb') as f:
                cfg['logo_data_uri'] = f"data:{mime};base64,{base64.b64encode(f.read()).decode()}"
    return cfg

def _report_filename(label):
    # Was month-only ({label}_{YYYY_MM}.pdf) -- a second generation of the same report
    # type in the same month silently overwrote the first with no warning. Full
    # timestamp makes every generation its own file, which is what makes a real
    # history table (one row per file) meaningful instead of misleading.
    return f"{label}_Report_{datetime.now().strftime('%Y_%m_%d_%H%M%S')}.pdf"

def _render_and_write(template_name, context, output_name):
    html_out = Environment(loader=FileSystemLoader(TEMPLATE_DIR)).get_template(template_name).render(context)
    HTML(string=html_out).write_pdf(os.path.join(REPORT_OUTPUT_DIR, output_name))
    return output_name

def generate_security_report():
    conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
    thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
    total_events = cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (thirty_days_ago,)).fetchone()[0]
    total_alerts = cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (thirty_days_ago,)).fetchone()[0]
    top_alerts = [{"title": r[0], "severity": r[1], "count": r[2]} for r in cursor.execute(
        "SELECT sr.title, a.severity, COUNT(a.id) as hit_count FROM alerts a JOIN sigma_rules sr ON a.rule_id = sr.id "
        "WHERE a.timestamp >= ? GROUP BY sr.title, a.severity ORDER BY hit_count DESC LIMIT 5", (thirty_days_ago,)
    ).fetchall()]

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "report_title": "Managed Security Report",
        "branding": _branding_context(conn),
        "total_events": f"{total_events:,}", "total_alerts": f"{total_alerts:,}",
        "top_alerts": top_alerts,
    }
    conn.close()
    return _render_and_write('report_template.html', context, _report_filename('Security'))

# Mirrors app.py's COMPLIANCE_AUDIT_ACTIONS -- this script has no Flask app context, same
# duplication reasoning as COMPLIANCE_FRAMEWORK_LABELS/SCA_CHECK_FRAMEWORKS above.
COMPLIANCE_AUDIT_ACTIONS = ('rule_compliance_tag', 'rule_toggle', 'rule_bulk_toggle')

# "Relevant" here means: this framework's own tagged rules (enabled AND disabled -- a
# disabled rule still represents detection intent for the framework, so its log-source
# dependency still counts as evidence of what monitoring the framework's story rests on)
# have a Sigma logsource that resolves to one or more real live_logs.app values. Answers
# "is the underlying data even being collected", independent of whether any rule has
# fired on it -- the same (product,service)->apps resolution _rule_log_source_ingestible()
# uses in app.py, just walking rule_yaml directly since this script has no _get_rules_cache.
def _framework_relevant_apps(cursor, framework_key):
    like_pattern = f'%{framework_key}%'
    apps = set()
    for row in cursor.execute(
        "SELECT rule_yaml FROM sigma_rules WHERE compliance_tags LIKE ?", (like_pattern,)
    ).fetchall():
        product = _extract_yaml_field('product', row['rule_yaml'])
        service = _extract_yaml_field('service', row['rule_yaml'])
        if not product:
            continue
        product = product.strip().lower()
        service = service.strip().lower() if service else None
        expected = SIGMA_LOGSOURCE_INGESTED_APPS.get((product, service))
        if expected is None:
            expected = SIGMA_LOGSOURCE_INGESTED_APPS.get((product, None))
        if expected:
            apps |= expected
    return apps

def _framework_focused_context(conn, cursor, framework_key):
    label = COMPLIANCE_FRAMEWORK_LABELS.get(framework_key, framework_key)
    like_pattern = f'%{framework_key}%'
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

    # Rule coverage, scoped to this framework, with real fired-alert evidence per rule --
    # not just enabled=1. Same alerts-JOIN-sigma_rules shape already used by
    # generate_security_report()'s top_alerts query above, extended with the
    # compliance_tags LIKE filter this module already uses for the all-frameworks report.
    rule_rows = cursor.execute(
        "SELECT sr.id, sr.title, sr.enabled, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.rule_id = sr.id AND a.timestamp >= ?) as alert_count "
        "FROM sigma_rules sr WHERE sr.compliance_tags LIKE ? ORDER BY sr.enabled DESC, alert_count DESC, sr.title",
        (thirty_days_ago, like_pattern)
    ).fetchall()
    rules = [dict(r) for r in rule_rows]
    rules_enabled_count = sum(1 for r in rules if r['enabled'])

    # Endpoint hardening (SCA), scoped to this one framework -- same aggregation the
    # all-frameworks report uses, just read out for a single key instead of looped.
    sca_agg, sca_failing_all = _sca_framework_aggregate(_latest_sca_results(cursor))
    sca = sca_agg.get(framework_key, {'total': 0, 'passed': 0, 'failed': 0, 'errored': 0})
    sca_failing = [f for f in sca_failing_all if label in f['frameworks'].split(', ')]

    # Fleet coverage -- how much of the enrolled estate this hardening picture actually
    # reflects, not just its pass rate. agent_tokens is the hostname-native enrollment
    # table (see migrate_agent_groups()'s own comment in app.py).
    # agent_tokens looked like the hostname-native enrollment table on paper, but in
    # practice most already-deployed agents authenticate via the older shared-secret
    # path and never bind a row there (confirmed live: production had 5 agent_tokens
    # rows, all with hostname=NULL, while every real host was only visible via
    # agent_polls) -- agent_polls.user_agent (the hostname agents report themselves as)
    # is what's actually populated for every host that has ever checked in, so that's
    # the real "total known hosts" denominator, not agent_tokens.
    total_hosts = cursor.execute(
        "SELECT COUNT(DISTINCT user_agent) FROM agent_polls"
    ).fetchone()[0]
    assessed_hosts = len(_latest_sca_results(cursor))

    # Recent detections -- real alert rows, not just the count above, so this reads as
    # evidence rather than a bare statistic. Same 200-row cap generate_audit_report()
    # already establishes as this report set's convention.
    detection_rows = cursor.execute(
        "SELECT a.timestamp, a.host, sr.title as rule_title, a.severity FROM alerts a "
        "JOIN sigma_rules sr ON a.rule_id = sr.id "
        "WHERE sr.compliance_tags LIKE ? AND a.timestamp >= ? ORDER BY a.timestamp DESC LIMIT ?",
        (like_pattern, thirty_days_ago, AUDIT_REPORT_ROW_CAP)
    ).fetchall()
    detections = [dict(r) for r in detection_rows]
    total_detections = cursor.execute(
        "SELECT COUNT(*) FROM alerts a JOIN sigma_rules sr ON a.rule_id = sr.id "
        "WHERE sr.compliance_tags LIKE ? AND a.timestamp >= ?",
        (like_pattern, thirty_days_ago)
    ).fetchone()[0]

    # Audit trail, scoped to changes on rules CURRENTLY tagged with this framework --
    # a rule detagged since the change was made won't show here, same "current state"
    # framing the rest of this report uses.
    placeholders = ','.join('?' for _ in COMPLIANCE_AUDIT_ACTIONS)
    audit_rows = cursor.execute(
        f"SELECT al.timestamp, al.username, al.action, al.target_id, al.details FROM audit_log al "
        f"JOIN sigma_rules sr ON al.target_id = CAST(sr.id AS TEXT) "
        f"WHERE al.action IN ({placeholders}) AND sr.compliance_tags LIKE ? ORDER BY al.id DESC LIMIT ?",
        (*COMPLIANCE_AUDIT_ACTIONS, like_pattern, AUDIT_REPORT_ROW_CAP)
    ).fetchall()
    audit_trail = [dict(r) for r in audit_rows]

    # Raw log-volume evidence -- distinct from everything above, which is all
    # post-detection (alerts) or config-state (sigma_rules/SCA). Answers "is the data
    # this framework's detections would need actually being collected" independent of
    # whether anything has fired on it yet. Empty relevant_apps (no tagged rules, or
    # every tagged rule's logsource resolves to a confirmed non-ingestible combo) means
    # an empty IN (...) clause, so the queries are skipped entirely rather than issued.
    relevant_apps = _framework_relevant_apps(cursor, framework_key)
    log_volume_total = 0
    log_volume_by_app = []
    if relevant_apps:
        app_placeholders = ','.join('?' for _ in relevant_apps)
        # LOWER(app) -- SIGMA_LOGSOURCE_INGESTED_APPS values are lowercase (matching
        # app.py's _get_ingested_apps convention), but live_logs.app is stored in
        # whatever case the source sent (e.g. 'Sysmon'); a bare `app IN (...)` silently
        # matches nothing. GROUP BY app (not LOWER(app)) so the report displays the
        # real casing as ingested.
        log_volume_total = cursor.execute(
            f"SELECT COUNT(*) FROM live_logs WHERE LOWER(app) IN ({app_placeholders}) AND timestamp >= ?",
            (*relevant_apps, thirty_days_ago)
        ).fetchone()[0]
        log_volume_by_app = [dict(r) for r in cursor.execute(
            f"SELECT app, COUNT(*) as count FROM live_logs WHERE LOWER(app) IN ({app_placeholders}) AND timestamp >= ? "
            f"GROUP BY app ORDER BY count DESC",
            (*relevant_apps, thirty_days_ago)
        ).fetchall()]

    return {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "report_title": f"Compliance Report — {label}",
        "report_subtitle": "Detection rules, endpoint hardening, and audit evidence for this framework",
        "branding": _branding_context(conn),
        "framework_label": label,
        "rules": rules,
        "rules_total": len(rules),
        "rules_enabled_count": rules_enabled_count,
        "sca": sca,
        "sca_failing_checks": sca_failing,
        "total_hosts": total_hosts,
        "assessed_hosts": assessed_hosts,
        "detections": detections,
        "total_detections": total_detections,
        "detections_truncated": total_detections > AUDIT_REPORT_ROW_CAP,
        "audit_trail": audit_trail,
        "row_cap": AUDIT_REPORT_ROW_CAP,
        "log_volume_total": log_volume_total,
        "log_volume_by_app": log_volume_by_app,
        "log_volume_apps": sorted(relevant_apps),
    }

def generate_compliance_report(framework_key=None):
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; cursor = conn.cursor()

    if framework_key:
        context = _framework_focused_context(conn, cursor, framework_key)
        conn.close()
        return _render_and_write('report_template_compliance_framework.html', context, _report_filename(f"Compliance_{framework_key}"))

    rows = cursor.execute(
        "SELECT compliance_tags, enabled FROM sigma_rules WHERE compliance_tags IS NOT NULL AND compliance_tags != ''"
    ).fetchall()

    coverage = {key: {'key': key, 'label': label, 'total': 0, 'enabled': 0} for key, label in COMPLIANCE_FRAMEWORK_LABELS.items()}
    for row in rows:
        # A rule can be tagged for more than one framework -- it counts toward each.
        for tag in (row['compliance_tags'] or '').split(','):
            if tag in coverage:
                coverage[tag]['total'] += 1
                if row['enabled']:
                    coverage[tag]['enabled'] += 1

    # Second, deliberately separate metric per framework -- fleet-wide SCA hardening
    # check pass rate, not blended into the rule-coverage total/enabled above. See
    # _sca_framework_aggregate's own docstring-equivalent comment for why.
    sca_agg, sca_failing = _sca_framework_aggregate(_latest_sca_results(cursor))
    for key, sca in sca_agg.items():
        coverage[key]['sca'] = sca

    frameworks = sorted(coverage.values(), key=lambda f: f['label'])
    full_coverage_count = sum(1 for f in frameworks if f['total'] > 0 and f['enabled'] == f['total'])

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "report_title": "Compliance Report",
        "branding": _branding_context(conn),
        "frameworks": frameworks,
        "full_coverage_count": full_coverage_count,
        "total_frameworks": len(frameworks),
        "sca_failing_checks": sca_failing,
    }
    conn.close()
    return _render_and_write('report_template_compliance.html', context, _report_filename('Compliance'))

def generate_audit_report():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

    action_counts = [dict(r) for r in cursor.execute(
        "SELECT action, COUNT(*) as count FROM audit_log WHERE timestamp >= ? GROUP BY action ORDER BY count DESC",
        (thirty_days_ago,)
    ).fetchall()]

    placeholders = ','.join('?' for _ in AUDIT_SENSITIVE_ACTIONS)
    sensitive_events = [dict(r) for r in cursor.execute(
        f"SELECT timestamp, username, action, target_type, target_id, details FROM audit_log "
        f"WHERE timestamp >= ? AND action IN ({placeholders}) ORDER BY id DESC",
        (thirty_days_ago, *AUDIT_SENSITIVE_ACTIONS)
    ).fetchall()]

    total_events_count = cursor.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?", (thirty_days_ago,)).fetchone()[0]
    recent_events = [dict(r) for r in cursor.execute(
        "SELECT timestamp, username, action, target_type, target_id FROM audit_log WHERE timestamp >= ? ORDER BY id DESC LIMIT ?",
        (thirty_days_ago, AUDIT_REPORT_ROW_CAP)
    ).fetchall()]

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "report_title": "Audit Trail Report",
        "report_subtitle": "Last 30 days",
        "branding": _branding_context(conn),
        "action_counts": action_counts,
        "sensitive_events": sensitive_events,
        "recent_events": recent_events,
        "total_events_count": total_events_count,
        "truncated": total_events_count > AUDIT_REPORT_ROW_CAP,
        "row_cap": AUDIT_REPORT_ROW_CAP,
    }
    conn.close()
    return _render_and_write('report_template_audit.html', context, _report_filename('Audit'))

# Distinct from CASE_SEVERITY_COLORS below (which collapses CRITICAL/HIGH into the
# same red) -- CVE severity has 4 real tiers worth telling apart at a glance, matching
# templates/threat_intel.html's own cveSeverityBadge color scheme (CRITICAL/HIGH/MEDIUM/
# LOW -> danger/warning/info/secondary), just as hex for this PDF's inline-styled badges.
CVE_SEVERITY_COLORS = {
    'CRITICAL': '#dc3545', 'HIGH': '#e0a800', 'MEDIUM': '#0dcaf0', 'LOW': '#6c757d',
}

def generate_vulnerability_report():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; cursor = conn.cursor()

    inventory = vuln_matching.latest_software_inventory(cursor)
    findings = []  # one row per (host, match) -- real evidence, not just a count
    host_summaries = []
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    unique_cves = set()
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    for host in inventory:
        matches = vuln_matching.correlate_software_vulnerabilities(cursor, host['apps'])
        host_highest = None
        for m in matches:
            sev = (m['severity'] or '').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            unique_cves.add(m['cve_id'])
            if host_highest is None or severity_order.get(sev, 9) < severity_order.get(host_highest, 9):
                host_highest = sev
            findings.append({
                'hostname': host['hostname'], 'cve_id': m['cve_id'], 'severity': m['severity'],
                'cvss_score': m['cvss_score'], 'installed_name': m['installed_name'],
                'installed_version': m['installed_version'], 'description': m['description'],
            })
        host_summaries.append({
            'hostname': host['hostname'], 'apps_scanned': len(host['apps']),
            'match_count': len(matches), 'highest_severity': host_highest,
        })

    findings.sort(key=lambda f: (severity_order.get((f['severity'] or '').upper(), 9), -(f['cvss_score'] or 0)))
    findings_total = len(findings)
    findings = findings[:AUDIT_REPORT_ROW_CAP]
    host_summaries.sort(key=lambda h: (severity_order.get(h['highest_severity'], 9), -h['match_count']))

    # Same "last CVE sync" freshness signal the Threat Intel tab's own sync-status
    # button already surfaces -- carried into the report so a reader isn't left
    # assuming this reflects today's CVE landscape when it might be a week stale.
    last_sync = None
    sync_row = cursor.execute("SELECT value FROM settings WHERE key = 'cve_feed_status'").fetchone()
    if sync_row and sync_row['value']:
        try:
            last_sync = json.loads(sync_row['value']).get('last_sync')
        except (ValueError, TypeError):
            pass

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "report_title": "Vulnerability Report",
        "branding": _branding_context(conn),
        "hosts_assessed": len(inventory),
        "unique_cve_count": len(unique_cves),
        "severity_counts": severity_counts,
        "findings": findings,
        "findings_truncated": findings_total > AUDIT_REPORT_ROW_CAP,
        "findings_total": findings_total,
        "row_cap": AUDIT_REPORT_ROW_CAP,
        "host_summaries": host_summaries,
        "last_cve_sync": last_sync,
        "severity_colors": CVE_SEVERITY_COLORS,
    }
    conn.close()
    return _render_and_write('report_template_vulnerability.html', context, _report_filename('Vulnerability'))

CASE_TLP_PAP_COLORS = {
    'clear': '#6c757d', 'green': '#198754', 'amber': '#e0a800',
    'amber-strict': '#e0a800', 'red': '#dc3545',
}
CASE_SEVERITY_COLORS = {
    'CRITICAL': '#dc3545', 'HIGH': '#dc3545', 'ALERT': '#dc3545',
    'MEDIUM': '#e0a800', 'WARN': '#e0a800', 'LOW': '#6c757d', 'INFO': '#0dcaf0',
}

# Plain-text mirror of cases.html's caseEventLabel() JS function -- same event types,
# same phrasing, minus the HTML markup (this renders into a PDF table cell, not a DOM
# node). Keep the two in sync if a new case_event type is ever added.
def _case_event_label(event_type, detail):
    detail = detail or ''
    labels = {
        'created': 'Case created',
        'status_change': f'Status changed to {detail}',
        'assignee_change': f'Assignee changed to {detail}',
        'tlp_change': f'TLP changed to {detail.upper()}',
        'pap_change': f'PAP changed to {detail.upper()}',
        'queue_change': f'Queue changed to {detail}',
        'item_added': f'Item added: {detail}',
        'item_removed': f'Item removed: {detail}',
        'task_added': f'Task added: "{detail}"',
        'task_done': f'Task completed: "{detail}"',
        'task_reopened': f'Task reopened: "{detail}"',
        'task_removed': f'Task removed: "{detail}"',
        'template_applied': f'Template applied: {detail}',
        'note': detail,
        'analysis': (detail.split('\n')[0] if detail else 'Analysis'),
        'playbook_run': detail,
    }
    return labels.get(event_type, event_type)

# Same shape as app.py's _case_item_summary() -- duplicated rather than imported since
# this script runs standalone with no Flask app context (see the module-level comment
# on REPORT_BRANDING_DEFAULTS above for why that pattern is already established here).
def _case_item_summary(conn, item_type, item_id):
    if item_type == 'alert':
        r = conn.execute(
            "SELECT a.timestamp, a.severity, a.host, a.username, COALESCE(s.title, a.rule_name, 'Custom/YARA Rule') as label, a.message "
            "FROM alerts a LEFT JOIN sigma_rules s ON a.rule_id = s.id WHERE a.id = ?", (item_id,)
        ).fetchone()
    elif item_type == 'command_result':
        r = conn.execute(
            "SELECT queued_at as timestamp, hostname as host, NULL as username, label, status, exit_code FROM agent_commands WHERE id = ?",
            (item_id,)
        ).fetchone()
        if not r:
            return None
        r = dict(r)
        if r['status'] != 'done':
            r['severity'], r['message'] = 'INFO', f"Status: {r['status']}"
        elif r['exit_code'] not in (0, None):
            r['severity'], r['message'] = 'HIGH', f"Completed with a non-zero exit code ({r['exit_code']})"
        else:
            r['severity'], r['message'] = 'INFO', "Completed successfully"
        del r['status'], r['exit_code']
    else:
        r = conn.execute(
            "SELECT timestamp, severity, hostname as host, NULL as username, 'UEBA Anomaly' as label, message FROM events WHERE id = ?", (item_id,)
        ).fetchone()
    return dict(r) if r else None

def generate_case_report(case_id):
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    case = conn.execute("SELECT c.*, q.name as queue_name FROM cases c LEFT JOIN case_queues q ON q.id = c.queue_id WHERE c.id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        raise ValueError(f"Case {case_id} not found")
    case = dict(case)

    tasks = [dict(t) for t in conn.execute(
        "SELECT title, status, assignee FROM case_tasks WHERE case_id = ? ORDER BY position, id", (case_id,)
    ).fetchall()]

    items_rows = conn.execute(
        "SELECT item_type, item_id FROM case_items WHERE case_id = ? ORDER BY added_at", (case_id,)
    ).fetchall()
    items = []
    for it in items_rows:
        summary = _case_item_summary(conn, it['item_type'], it['item_id'])
        if summary:
            summary['item_type'] = it['item_type']
            items.append(summary)

    events_rows = [dict(e) for e in conn.execute(
        "SELECT ts, actor, event_type, detail FROM case_events WHERE case_id = ? ORDER BY ts, id", (case_id,)
    ).fetchall()]
    timeline, analyses = [], []
    for e in events_rows:
        if e['event_type'] == 'analysis':
            analyses.append({'ts': e['ts'], 'actor': e['actor'], 'text': e['detail'] or ''})
        timeline.append({'ts': e['ts'], 'actor': e['actor'] or '', 'label': _case_event_label(e['event_type'], e['detail'])})

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "report_title": "Case Report",
        "report_subtitle": case['title'],
        "branding": _branding_context(conn),
        "case": case,
        "tlp_pap_colors": CASE_TLP_PAP_COLORS,
        "severity_colors": CASE_SEVERITY_COLORS,
        "tasks": tasks,
        "tasks_done": sum(1 for t in tasks if t['status'] == 'done'),
        "items": items,
        "timeline": timeline,
        "analyses": analyses,
    }
    conn.close()
    safe_title = ''.join(c if c.isalnum() or c in ' -_' else '' for c in case['title'])[:60].strip() or f"Case_{case_id}"
    return _render_and_write('report_template_case.html', context, f"{safe_title.replace(' ', '_')}_{_report_filename('Case')}")

REPORT_GENERATORS = {
    'security': generate_security_report,
    # 'compliance' is handled by its own explicit branch in run_report() (needs to pass
    # framework_key through), same as 'case' -- not listed here to avoid two dispatch
    # paths for the same type.
    'audit': generate_audit_report,
    'vulnerability': generate_vulnerability_report,
}

def _record_history(conn, report_type, filename, status, started_at, completed_at,
                     triggered_by, trigger_source, error_message=None, case_id=None, case_title=None,
                     framework_key=None, framework_label=None):
    file_size = None
    if status == 'success' and filename:
        try:
            file_size = os.path.getsize(os.path.join(REPORT_OUTPUT_DIR, filename))
        except OSError:
            pass
    conn.execute(
        "INSERT INTO report_history (report_type, filename, status, triggered_by, trigger_source, "
        "started_at, completed_at, file_size_bytes, error_message, case_id, case_title, framework_key, framework_label) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (report_type, filename, status, triggered_by, trigger_source, started_at, completed_at, file_size, error_message,
         case_id, case_title, framework_key, framework_label)
    )
    conn.commit()

# Single chokepoint for both triggering paths: cron calls this script directly with no
# Flask context (trigger_source='scheduled', triggered_by=None), the Reports tab's
# /reports/generate route shells out to it the same way with --user/--source=manual.
# History recording lives here (not in app.py) so both paths get a row without either
# duplicating the insert or a cron run silently having no record at all. A case report
# (report_type == 'case') is the one path that needs case_id -- looked up here so a
# failed generation still records which case it was for, not just that something failed.
def run_report(report_type, triggered_by=None, trigger_source='manual', case_id=None, framework_key=None):
    started_at = datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    case_title = None
    framework_label = COMPLIANCE_FRAMEWORK_LABELS.get(framework_key) if framework_key else None
    try:
        # Defensive create -- mirrors _get_or_create_secret_key()'s own pattern in
        # app.py, in case this runs before migrate_report_history()/
        # migrate_report_history_case_id()/migrate_report_history_framework() have (e.g.
        # cron fires between a code deploy and the next app restart that runs migrations).
        conn.execute('''CREATE TABLE IF NOT EXISTS report_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, report_type TEXT NOT NULL, filename TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'success', triggered_by TEXT, trigger_source TEXT NOT NULL DEFAULT 'manual',
            started_at DATETIME, completed_at DATETIME, file_size_bytes INTEGER, error_message TEXT,
            case_id INTEGER, case_title TEXT, framework_key TEXT, framework_label TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        if report_type == 'case':
            if case_id is None:
                raise ValueError("case report requires a case_id")
            row = conn.execute("SELECT title FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not row:
                raise ValueError(f"Case {case_id} not found")
            case_title = row[0]
            filename = generate_case_report(case_id)
        elif report_type == 'compliance':
            filename = generate_compliance_report(framework_key)
        else:
            filename = REPORT_GENERATORS.get(report_type, generate_security_report)()
        _record_history(conn, report_type, filename, 'success', started_at,
                         datetime.now().isoformat(), triggered_by, trigger_source, case_id=case_id, case_title=case_title,
                         framework_key=framework_key, framework_label=framework_label)
    except Exception as e:
        _record_history(conn, report_type, '', 'failed', started_at,
                         datetime.now().isoformat(), triggered_by, trigger_source, str(e), case_id=case_id, case_title=case_title,
                         framework_key=framework_key, framework_label=framework_label)
        conn.close()
        raise
    conn.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('report_type', nargs='?', default='security')
    parser.add_argument('--user', default=None)
    parser.add_argument('--source', default='scheduled', choices=('manual', 'scheduled'))
    parser.add_argument('--case-id', type=int, default=None)
    parser.add_argument('--framework', default=None)
    args = parser.parse_args()
    run_report(args.report_type, triggered_by=args.user, trigger_source=args.source, case_id=args.case_id, framework_key=args.framework)
