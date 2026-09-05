# Nightly consistent snapshot of siem.db, gzip-compressed with rotation. Mirrors
# archive_logs.py's shape: a standalone script driven by cron, importable for the
# Settings "Backup Now" button too.
#
# Uses SQLite's own VACUUM INTO to take the snapshot -- it acquires a read lock the
# same way a normal query does and is safe to run against a live, actively-written
# database. A plain file copy (cp / shutil.copy) is NOT safe here: it can copy the
# file mid-write and produce a torn, corrupted copy -- this feature exists specifically
# because that's the closest guess anyone has for what caused the 2026-09-04 siem.db
# corruption incident (see CHANGELOG.md), which had no backup to recover from.
import sqlite3, os, sys, gzip, shutil, time
from datetime import datetime, timedelta

DB_PATH = '/opt/micro-dfir/siem.db'
BACKUP_DIR = '/opt/micro-dfir/backups'
DEFAULT_RETENTION_DAYS = 7

def run_backup(retention_override=None):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if retention_override is not None:
        # Settings > System's "Backup Now" button passes whatever is currently typed
        # into the retention field, even if it hasn't been saved yet -- mirrors how
        # "Archive Now"/"Purge Now" already work elsewhere in this same settings page.
        retention_days = retention_override
    else:
        row = cursor.execute("SELECT value FROM settings WHERE key = 'db_backup_retention_days'").fetchone()
        try:
            retention_days = int(row['value']) if row and row['value'] else DEFAULT_RETENTION_DAYS
        except (TypeError, ValueError):
            retention_days = DEFAULT_RETENTION_DAYS

    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    snapshot_path = os.path.join(BACKUP_DIR, f'siem_{timestamp}.db')
    gz_path = snapshot_path + '.gz'

    start = time.time()
    cursor.execute("VACUUM INTO ?", (snapshot_path,))
    conn.close()

    with open(snapshot_path, 'rb') as f_in, gzip.open(gz_path, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(snapshot_path)
    duration = time.time() - start
    size_bytes = os.path.getsize(gz_path)

    removed = 0
    if retention_days > 0:
        cutoff = datetime.now() - timedelta(days=retention_days)
        for fname in os.listdir(BACKUP_DIR):
            if not (fname.startswith('siem_') and fname.endswith('.db.gz')):
                continue
            fpath = os.path.join(BACKUP_DIR, fname)
            if datetime.fromtimestamp(os.path.getmtime(fpath)) < cutoff:
                os.remove(fpath)
                removed += 1

    conn2 = sqlite3.connect(DB_PATH, timeout=30)
    conn2.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('db_backup_last_run', ?)",
                  (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),))
    conn2.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('db_backup_last_size_bytes', ?)",
                  (str(size_bytes),))
    conn2.commit()
    conn2.close()

    print(f"[+] Database backup: {gz_path} ({size_bytes / 1024 / 1024:.1f} MB) in {duration:.1f}s; "
          f"removed {removed} backup(s) older than {retention_days}d.", flush=True)
    return {'path': gz_path, 'filename': os.path.basename(gz_path), 'size_bytes': size_bytes,
            'duration_seconds': round(duration, 1), 'removed': removed, 'retention_days': retention_days}

if __name__ == "__main__":
    try:
        run_backup()
    except Exception as e:
        print(f"[-] Database backup failed: {e}")
        sys.exit(1)
