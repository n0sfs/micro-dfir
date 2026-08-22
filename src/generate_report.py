import os, sqlite3, sys
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

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

# Action categories a compliance reviewer would specifically want called out, not
# buried in a full activity list -- user management, credential/cert changes, and
# anything that alters what gets retained.
AUDIT_SENSITIVE_ACTIONS = (
    'user_create', 'user_password_reset', 'user_delete',
    'soc_token_change', 'network_config_change', 'tls_cert_upload',
    'retention_policy_change', 'manual_log_purge', 'db_vacuum',
)
AUDIT_REPORT_ROW_CAP = 200

def _render_and_write(template_name, context, output_name):
    html_out = Environment(loader=FileSystemLoader(TEMPLATE_DIR)).get_template(template_name).render(context)
    HTML(string=html_out).write_pdf(os.path.join(REPORT_OUTPUT_DIR, output_name))

def generate_security_report():
    conn = sqlite3.connect(DB_PATH); cursor = conn.cursor()
    thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
    total_events = cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (thirty_days_ago,)).fetchone()[0]
    total_alerts = cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (thirty_days_ago,)).fetchone()[0]
    top_alerts = [{"title": r[0], "severity": r[1], "count": r[2]} for r in cursor.execute(
        "SELECT sr.title, a.severity, COUNT(a.id) as hit_count FROM alerts a JOIN sigma_rules sr ON a.rule_id = sr.id "
        "WHERE a.timestamp >= ? GROUP BY sr.title, a.severity ORDER BY hit_count DESC LIMIT 5", (thirty_days_ago,)
    ).fetchall()]
    conn.close()

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "total_events": f"{total_events:,}", "total_alerts": f"{total_alerts:,}",
        "top_alerts": top_alerts,
    }
    _render_and_write('report_template.html', context, f"Security_Report_{datetime.now().strftime('%Y_%m')}.pdf")

def generate_compliance_report():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT compliance_tags, enabled FROM sigma_rules WHERE compliance_tags IS NOT NULL AND compliance_tags != ''"
    ).fetchall()
    conn.close()

    coverage = {key: {'key': key, 'label': label, 'total': 0, 'enabled': 0} for key, label in COMPLIANCE_FRAMEWORK_LABELS.items()}
    for row in rows:
        # A rule can be tagged for more than one framework -- it counts toward each.
        for tag in (row['compliance_tags'] or '').split(','):
            if tag in coverage:
                coverage[tag]['total'] += 1
                if row['enabled']:
                    coverage[tag]['enabled'] += 1

    frameworks = sorted(coverage.values(), key=lambda f: f['label'])
    full_coverage_count = sum(1 for f in frameworks if f['total'] > 0 and f['enabled'] == f['total'])

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "frameworks": frameworks,
        "full_coverage_count": full_coverage_count,
        "total_frameworks": len(frameworks),
    }
    _render_and_write('report_template_compliance.html', context, f"Compliance_Report_{datetime.now().strftime('%Y_%m')}.pdf")

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
    conn.close()

    context = {
        "date_generated": datetime.now().strftime("%B %d, %Y"),
        "action_counts": action_counts,
        "sensitive_events": sensitive_events,
        "recent_events": recent_events,
        "total_events_count": total_events_count,
        "truncated": total_events_count > AUDIT_REPORT_ROW_CAP,
        "row_cap": AUDIT_REPORT_ROW_CAP,
    }
    _render_and_write('report_template_audit.html', context, f"Audit_Report_{datetime.now().strftime('%Y_%m')}.pdf")

REPORT_GENERATORS = {
    'security': generate_security_report,
    'compliance': generate_compliance_report,
    'audit': generate_audit_report,
}

if __name__ == "__main__":
    report_type = sys.argv[1] if len(sys.argv) > 1 else 'security'
    REPORT_GENERATORS.get(report_type, generate_security_report)()
