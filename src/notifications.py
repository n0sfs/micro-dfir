# Alert notification delivery (email + generic webhook) -- shared by both places an alert
# gets created: sigma_engine.py's standalone detection loop (a raw sqlite3 connection, no
# Flask context) and app.py's inline-heuristic ingest path (a Flask request context). This
# module is intentionally DB-connection-agnostic: every function here takes an already-open
# `db` (anything exposing .execute(...).fetchone(), which both sqlite3.Connection and
# sqlite3.Cursor satisfy identically) or a plain config dict -- it never calls get_db()/
# current_user itself, so it works unmodified in either caller's context.
import copy
import json
import smtplib
from email.mime.text import MIMEText

import requests

ALERT_NOTIFICATION_DEFAULTS = {
    'smtp_enabled': False, 'smtp_host': '', 'smtp_port': 587, 'smtp_user': '', 'smtp_pass': '',
    'smtp_from': '', 'smtp_to': '', 'smtp_use_tls': True,
    'webhook_enabled': False, 'webhook_url': '',
    # Only alerts at or above this severity trigger a notification -- defaults to High so
    # enabling notifications for the first time doesn't immediately flood an inbox with
    # every Low/Info hit.
    'min_severity': 'High',
}

_SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}


def get_alert_notification_config(db):
    cfg = copy.deepcopy(ALERT_NOTIFICATION_DEFAULTS)
    row = db.execute("SELECT value FROM settings WHERE key = 'alert_notification_config'").fetchone()
    if row and row['value']:
        try:
            saved = json.loads(row['value'])
            cfg.update({k: v for k, v in saved.items() if k in cfg})
        except (ValueError, TypeError):
            pass
    return cfg


def should_notify(config, severity):
    threshold = _SEVERITY_ORDER.get((config.get('min_severity') or 'High').upper(), 3)
    return _SEVERITY_ORDER.get((severity or '').upper(), 0) >= threshold


def _send_email(config, alert):
    try:
        to_addrs = [a.strip() for a in (config.get('smtp_to') or '').split(',') if a.strip()]
        if not to_addrs:
            return False, 'no recipient configured'
        body = (
            f"Severity: {alert.get('severity', '')}\n"
            f"Host: {alert.get('host', '')}\n"
            f"User: {alert.get('username') or '-'}\n"
            f"Source IP: {alert.get('source_ip') or '-'}\n"
            f"Time: {alert.get('timestamp', '')}\n\n"
            f"{alert.get('message', '')}\n"
        )
        msg = MIMEText(body)
        msg['Subject'] = f"[{alert.get('severity', '')}] {alert.get('rule_title', 'Alert')} on {alert.get('host', '')}"
        msg['From'] = config.get('smtp_from') or config.get('smtp_user') or 'micro-dfir@localhost'
        msg['To'] = ', '.join(to_addrs)
        with smtplib.SMTP(config['smtp_host'], int(config.get('smtp_port') or 587), timeout=10) as server:
            if config.get('smtp_use_tls', True):
                server.starttls()
            if config.get('smtp_user') and config.get('smtp_pass'):
                server.login(config['smtp_user'], config['smtp_pass'])
            server.sendmail(msg['From'], to_addrs, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


def _send_webhook(config, alert):
    try:
        requests.post(config['webhook_url'], json=alert, timeout=5)
        return True, None
    except Exception as e:
        return False, str(e)


def send_alert_notification(config, alert):
    """config: a parsed alert_notification_config dict (get_alert_notification_config()'s
    return, or ALERT_NOTIFICATION_DEFAULTS for a test send). alert: dict with rule_title/
    severity/host/username/source_ip/message/timestamp. Best-effort per channel -- a failed
    email never blocks the webhook and vice versa, and neither ever raises (mirrors this
    codebase's existing outbound-HTTP convention: explicit timeout, try/except, never let a
    notification failure abort the caller's larger operation)."""
    results = {}
    if config.get('smtp_enabled') and config.get('smtp_host') and config.get('smtp_to'):
        ok, err = _send_email(config, alert)
        results['email'] = {'ok': ok, 'error': err}
    if config.get('webhook_enabled') and config.get('webhook_url'):
        ok, err = _send_webhook(config, alert)
        results['webhook'] = {'ok': ok, 'error': err}
    return results


def notify_if_configured(db, alert):
    """The one call site both alert-creation paths use: reads config, checks the severity
    threshold, sends if warranted. Swallows its own errors -- notification delivery must
    never be the reason an alert fails to record."""
    try:
        config = get_alert_notification_config(db)
        if not should_notify(config, alert.get('severity')):
            return None
        return send_alert_notification(config, alert)
    except Exception as e:
        print(f"[-] Alert notification dispatch failed: {e}")
        return None
