# The shared Email(SMTP)/Webhook "Notification Channels" config and low-level senders,
# now surfaced in the SOAR page instead of Settings. Auto-dispatch on every new alert
# used to live here (notify_if_configured/should_notify) but has moved to
# soar_alerts.run_playbooks_for_alert, driven by real alert_created playbooks instead of
# one hardcoded rule -- see the seeded "Legacy Alert Notifications" playbook
# (migrate_seed_legacy_notification_playbook in app.py) for the reproduced default
# behavior. What's left here backs the Test Send button (api_alert_notification_test)
# and get_alert_notification_config()/_SEVERITY_ORDER, which soar_alerts.py's send_email
# action and severity-threshold check both still read. Still DB-connection-agnostic
# (every function takes an already-open `db` -- sqlite3.Connection or sqlite3.Cursor --
# or a plain config dict; never calls get_db()/current_user) since soar_alerts.py needs
# that same property.
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
# Still used by soar_alerts.py's threshold comparison for alert_created playbooks (the
# severity-ordering logic itself outlived the hardcoded dispatch this module used to do).


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
