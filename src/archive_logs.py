# Moves live_logs rows older than the configured archive window into
# live_logs_archive (same schema, same database file -- no second .db, no ATTACH)
# so Log Search's default query stays fast on the hot table while older data isn't
# lost outright. Mirrors geoip_update.py's pattern: a standalone script driven by
# cron, not a service, importable for the Settings "Archive Now" button too.
#
# Independent of the separate Settings > System "Log Retention" purge
# (sigma_engine.py's run_due_log_purge(), which hard-deletes from live_logs with no
# archiving). If both are enabled, keep log_retention_days LONGER than
# log_archive_days -- otherwise retention purge deletes rows before this script
# ever gets a chance to archive them.
import sqlite3, sys
from datetime import datetime, timedelta

DB_PATH = '/opt/micro-dfir/siem.db'
DEFAULT_ARCHIVE_DAYS = 90

ARCHIVE_COLUMNS = [
    'id', 'timestamp', 'host', 'app', 'severity', 'event_id', 'username',
    'source_ip', 'destination_ip', 'message', 'process_image', 'command_line',
    'parent_image', 'parent_command_line', 'original_file_name', 'raw_xml',
    'file_hash', 'query_name'
]

def archive_old_logs(days_override=None):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if days_override is not None:
        # Settings > System's "Archive Now" button passes whatever is currently typed
        # into the days field, even if it hasn't been saved yet -- mirrors how "Purge
        # Now" for retention works, so a manual run always reflects what's on screen.
        archive_days = days_override
    else:
        days_row = cursor.execute("SELECT value FROM settings WHERE key = 'log_archive_days'").fetchone()
        try:
            archive_days = int(days_row['value']) if days_row and days_row['value'] else DEFAULT_ARCHIVE_DAYS
        except (TypeError, ValueError):
            archive_days = DEFAULT_ARCHIVE_DAYS
    if archive_days < 1:
        conn.close()
        return {'archived': 0, 'cutoff': None, 'enabled': False}

    now = datetime.now()
    cutoff = (now - timedelta(days=archive_days)).strftime('%Y-%m-%d %H:%M:%S')
    cols = ', '.join(ARCHIVE_COLUMNS)

    # Copy and delete run as one transaction (single connection, one commit at the
    # end) so a crash never leaves live_logs missing rows that didn't make it into
    # the archive -- either both statements land or neither does.
    cursor.execute(f"INSERT OR IGNORE INTO live_logs_archive ({cols}) SELECT {cols} FROM live_logs WHERE timestamp < ?", (cutoff,))
    archived = cursor.rowcount
    cursor.execute("DELETE FROM live_logs WHERE timestamp < ?", (cutoff,))
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('log_archive_last_run', ?)", (now.strftime('%Y-%m-%d %H:%M:%S'),))
    conn.commit()
    conn.close()
    if archived:
        print(f"[+] Log archiving: moved {archived} log(s) older than {archive_days} day(s) into live_logs_archive (cutoff {cutoff}).", flush=True)
    return {'archived': archived, 'cutoff': cutoff, 'enabled': True}

if __name__ == "__main__":
    try:
        archive_old_logs()
    except Exception as e:
        print(f"[-] Log archiving failed: {e}")
        sys.exit(1)
