# Alert-triggered SOAR automation -- mirrors notifications.py's DB-connection-agnostic
# contract (an already-open `db`, either app.py's Flask sqlite3.Connection or
# sigma_engine.py's raw sqlite3.Cursor, is passed in; this module never calls
# get_db()/current_user) since it's the one place both alert-creation paths route
# through, replacing the old notify_if_configured().
#
# Playbooks are otherwise entirely case-scoped (every action operates on a case_id
# that doesn't exist yet at alert-creation time) -- this module adds a small, distinct
# alert-native action set instead of forcing alert triggers through case-shaped
# actions. create_case is the deliberate bridge: it creates a case, links the alert,
# and (when the caller supplies run_case_playbooks_fn) lets the existing case_created
# playbook cascade take over from there, so the full case-scoped action arsenal
# (isolate_host, the other EDR actions, etc.) is reachable without duplicating any of
# it here. None of the 4 action types here are destructive/physical, so unlike
# case-scoped playbooks, alert-scoped playbooks have no approval-gate machinery --
# anyone who wants a gated EDR response from an alert uses create_case to bridge into
# the case-scoped world where that gating already exists.
import json

from notifications import get_alert_notification_config, _SEVERITY_ORDER

PLAYBOOK_ALERT_ACTION_TYPES = ('send_email', 'send_webhook', 'send_slack', 'create_case')


def _fill_alert_template(text, alert):
    if not text:
        return text
    values = {
        '{{severity}}': alert.get('severity') or '',
        '{{host}}': alert.get('host') or '',
        '{{rule_title}}': alert.get('rule_title') or '',
        '{{message}}': alert.get('message') or '',
        '{{username}}': alert.get('username') or '',
        '{{source_ip}}': alert.get('source_ip') or '',
        '{{timestamp}}': alert.get('timestamp') or '',
    }
    for k, v in values.items():
        text = text.replace(k, v)
    return text


def _create_case_from_alert(db, alert, run_case_playbooks_fn):
    # Mirrors sigma_engine.py's _auto_create_case() shape/defaults (title format,
    # amber/amber TLP/PAP for a system-generated case with no analyst review yet) --
    # that's the existing precedent for "an alert auto-created a case" (there, driven
    # by a rule's own auto_case checkbox); this is the same idea, driven by a playbook
    # instead, and stays consistent with it rather than the general TLP/PAP
    # "leave unset" convention that applies to analyst-initiated case creation.
    title = f"{alert.get('rule_title') or 'Alert'} — {alert.get('host') or 'unknown host'}"
    severity = (alert.get('severity') or 'medium').lower()
    if severity not in ('critical', 'high', 'medium', 'low'):
        severity = 'medium'
    cur = db.execute(
        "INSERT INTO cases (title, status, description, created_by, tlp, pap, severity) VALUES (?, 'open', ?, 'playbook', 'amber', 'amber', ?)",
        (title, f"Auto-created by a SOAR playbook because an alert fired on {alert.get('host') or 'an unknown host'}.", severity)
    )
    cid = cur.lastrowid
    db.execute("INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, 'playbook', 'created', ?)", (cid, title))
    if alert.get('id'):
        db.execute("INSERT INTO case_items (case_id, item_type, item_id, added_by) VALUES (?, 'alert', ?, 'playbook')", (cid, str(alert['id'])))
        db.execute("INSERT INTO case_events (case_id, actor, event_type, detail) VALUES (?, 'playbook', 'item_added', ?)", (cid, f"alert:{alert['id']}"))
    if run_case_playbooks_fn:
        try:
            run_case_playbooks_fn(cid, None, '', 'open', severity)
        except Exception as e:
            print(f"[-] case_created playbook cascade failed after alert-triggered create_case: {e}")
    return cid


# One action's execution against a raw alert dict (not a case). Same dry_run contract
# as app.py's _run_playbook_action: every lookup/validation runs normally, but returns
# before the one mutating statement/network call in each branch.
def run_playbook_action_for_alert(db, alert, action_type, params, run_case_playbooks_fn=None, dry_run=False):
    params = params or {}

    if action_type == 'create_case':
        if dry_run:
            return f"would create a case from this alert on {alert.get('host') or 'unknown host'}"
        cid = _create_case_from_alert(db, alert, run_case_playbooks_fn)
        return f"created case #{cid} and linked this alert"

    if action_type == 'send_email':
        config = get_alert_notification_config(db)
        if not config.get('smtp_enabled') or not config.get('smtp_host'):
            return "email channel not configured/enabled, skipped"
        to_raw = (params.get('to') or '').strip() or config.get('smtp_to') or ''
        to_addrs = [a.strip() for a in to_raw.split(',') if a.strip()]
        if not to_addrs:
            return "no recipient configured (and no default To on the Email channel), skipped"
        subject = _fill_alert_template(params.get('subject') or '[{{severity}}] {{rule_title}} on {{host}}', alert)
        body = _fill_alert_template(params.get('body') or '{{rule_title}} fired on {{host}} ({{severity}}).\n\n{{message}}', alert)
        if dry_run:
            return f"would email {', '.join(to_addrs)}: \"{subject}\""
        from email.mime.text import MIMEText
        import smtplib
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = config.get('smtp_from') or config.get('smtp_user') or 'micro-dfir@localhost'
        msg['To'] = ', '.join(to_addrs)
        with smtplib.SMTP(config['smtp_host'], int(config.get('smtp_port') or 587), timeout=10) as server:
            if config.get('smtp_use_tls', True):
                server.starttls()
            if config.get('smtp_user') and config.get('smtp_pass'):
                server.login(config['smtp_user'], config['smtp_pass'])
            server.sendmail(msg['From'], to_addrs, msg.as_string())
        return f"emailed {', '.join(to_addrs)}"

    if action_type == 'send_webhook':
        secret_name = (params.get('url_secret') or '').strip()
        if secret_name:
            row = db.execute("SELECT value FROM playbook_secrets WHERE name = ?", (secret_name,)).fetchone()
            if not row:
                return f"secret '{secret_name}' not found, skipped"
            url, url_display = row['value'], f"[secret: {secret_name}]"
        else:
            url = url_display = (params.get('url') or '').strip()
        if not url:
            return "no URL configured, skipped"
        if dry_run:
            return f"would POST alert data to {url_display}"
        import requests
        requests.post(url, json=alert, timeout=8)
        return f"posted webhook to {url_display}"

    if action_type == 'send_slack':
        secret_name = (params.get('webhook_url_secret') or '').strip()
        if secret_name:
            row = db.execute("SELECT value FROM playbook_secrets WHERE name = ?", (secret_name,)).fetchone()
            if not row:
                return f"secret '{secret_name}' not found, skipped"
            webhook_url, url_display = row['value'], f"[secret: {secret_name}]"
        else:
            webhook_url = url_display = (params.get('webhook_url') or '').strip()
        if not webhook_url:
            return "no Slack webhook URL configured, skipped"
        message = _fill_alert_template(params.get('message') or '[{{severity}}] {{rule_title}} on {{host}}: {{message}}', alert)
        if dry_run:
            return f'would send Slack message via {url_display}: "{message}"'
        import requests
        requests.post(webhook_url, json={'text': message}, timeout=8)
        return f"sent Slack message via {url_display}"

    return f"unknown action type '{action_type}', skipped"


# Same CAS trip-disable pattern as app.py's _check_playbook_rate_limit, scoped to
# playbook_alert_runs instead of playbook_runs -- kept separate rather than shared
# since the two tables/scopes don't overlap and app.py's version is already relied on
# elsewhere; duplicating this ~10 line check is cheaper than the coupling a shared
# version would need across the module boundary.
def _check_alert_playbook_rate_limit(db, pb, alert):
    if not pb['max_runs_per_hour']:
        return True
    recent = db.execute(
        "SELECT COUNT(*) FROM playbook_alert_runs WHERE playbook_id = ? AND triggered_at >= datetime('now', '-1 hour')",
        (pb['id'],)
    ).fetchone()[0]
    if recent < pb['max_runs_per_hour']:
        return True
    tripped = db.execute("UPDATE playbooks SET enabled = 0 WHERE id = ? AND enabled = 1", (pb['id'],))
    if tripped.rowcount:
        detail = f"rate limit tripped ({recent}/{pb['max_runs_per_hour']} runs in the last hour) -- playbook auto-disabled"
        db.execute(
            "INSERT INTO playbook_alert_runs (playbook_id, alert_id, status, detail) VALUES (?, ?, 'rate_limited', ?)",
            (pb['id'], alert.get('id'), detail)
        )
    return False


def run_playbooks_for_alert(db, alert, run_case_playbooks_fn=None):
    """The one call site both alert-creation paths (app.py's inline-heuristic ingest,
    sigma_engine.py's Sigma-rule loop) route through. Swallows its own errors per
    playbook (one misconfigured playbook never blocks another) and overall (this must
    never be the reason an alert fails to record) -- matches notify_if_configured's own
    error-swallowing contract. Does NOT call db.commit() itself: both callers already
    commit once after their own larger per-cycle/per-request loop, and this only ever
    runs from inside that loop."""
    try:
        severity = (alert.get('severity') or '').upper()
        playbooks = db.execute(
            "SELECT * FROM playbooks WHERE enabled = 1 AND trigger_event = 'alert_created'"
        ).fetchall()
        for pb in playbooks:
            if pb['condition_severity']:
                threshold = _SEVERITY_ORDER.get(pb['condition_severity'].upper(), 0)
                if _SEVERITY_ORDER.get(severity, 0) < threshold:
                    continue
            if not _check_alert_playbook_rate_limit(db, pb, alert):
                continue
            actions = db.execute(
                "SELECT action_type, params FROM playbook_actions WHERE playbook_id = ? ORDER BY position", (pb['id'],)
            ).fetchall()
            results, overall_status = [], 'success'
            for a in actions:
                try:
                    action_params = json.loads(a['params']) if a['params'] else {}
                    result = run_playbook_action_for_alert(db, alert, a['action_type'], action_params, run_case_playbooks_fn)
                    results.append(f"{a['action_type']}: {result}")
                except Exception as e:
                    results.append(f"{a['action_type']}: FAILED ({e})")
                    overall_status = 'partial'
            detail = '; '.join(results) if results else 'no actions configured'
            db.execute(
                "INSERT INTO playbook_alert_runs (playbook_id, alert_id, status, detail) VALUES (?, ?, ?, ?)",
                (pb['id'], alert.get('id'), overall_status, detail)
            )
    except Exception as e:
        print(f"[-] Alert-triggered playbook dispatch failed: {e}")
