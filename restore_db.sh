#!/bin/bash
# Restores /opt/micro-dfir/siem.db from a backup produced by src/backup_db.py
# (Settings > System > Database Backups, or the nightly 2 AM cron job).
#
# Deliberately NOT wired into update.sh or any web UI button: restoring a database is
# rare, destructive if pointed at the wrong file, and needs to stop/start services and
# swap the live database file out from under the running app -- exactly the kind of
# action this repo's own conventions (CLAUDE.md) say should stay a manual, confirmed
# step, not something automated silently. Requires real (not the passwordless
# update.sh-scoped) sudo, since it does more than that one pinned script.
#
# Usage:
#   sudo bash /opt/micro-dfir/restore_db.sh /opt/micro-dfir/backups/siem_20260905_020000.db.gz
#
# Run with no argument to list available backups.
set -e

DB_PATH="/opt/micro-dfir/siem.db"
BACKUP_DIR="/opt/micro-dfir/backups"
BACKUP_FILE="$1"
SERVICES="microsoc-web microsoc-sigma microsoc-soar"

if [ "$EUID" -ne 0 ]; then
    echo "[-] This script must be run as root: sudo bash restore_db.sh <backup-file>"
    exit 1
fi

if [ -z "$BACKUP_FILE" ] || [ ! -f "$BACKUP_FILE" ]; then
    echo "Usage: sudo bash restore_db.sh <path-to-backup.db.gz>"
    echo ""
    echo "Available backups in $BACKUP_DIR:"
    ls -lh "$BACKUP_DIR"/siem_*.db.gz 2>/dev/null || echo "  (none found)"
    exit 1
fi

# gzip -t verifies the archive's internal checksum without extracting it anywhere --
# catches a truncated download, a non-gzip file, or disk corruption before this script
# ever touches the live DB, instead of failing mid-restore with services already down.
echo "[*] Verifying backup archive integrity..."
if ! gzip -t "$BACKUP_FILE" 2>/dev/null; then
    echo "[-] '$BACKUP_FILE' is not a valid gzip archive -- aborting before touching the live database."
    exit 1
fi

echo "[*] About to restore siem.db from: $BACKUP_FILE"
echo "[*] This will stop microsoc-web, microsoc-sigma, and microsoc-soar briefly."
read -p "Continue? [y/N] " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "[*] Aborted, nothing changed."
    exit 0
fi

echo "[*] Stopping Micro-DFIR services..."
systemctl stop $SERVICES

# Restart the services on ANY exit from this point on -- success, an integrity-check
# failure below, or set -e tripping on a mid-restore failure (disk full during gunzip,
# a permission error, etc.). Without this trap, that last case left the whole appliance
# down indefinitely with no automatic recovery.
SERVICES_RESTARTED=0
restart_services() {
    if [ "$SERVICES_RESTARTED" -eq 0 ]; then
        echo "[*] Restarting Micro-DFIR services..."
        systemctl start $SERVICES
        SERVICES_RESTARTED=1
    fi
}
trap restart_services EXIT

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PRE_RESTORE_PATH="${DB_PATH}.pre_restore_${TIMESTAMP}"
if [ -f "$DB_PATH" ]; then
    echo "[*] Preserving the current (pre-restore) database at ${PRE_RESTORE_PATH}..."
    cp "$DB_PATH" "$PRE_RESTORE_PATH"
else
    echo "[!] No existing database found at $DB_PATH -- nothing to preserve."
fi

echo "[*] Decompressing and restoring $BACKUP_FILE..."
gunzip -c "$BACKUP_FILE" > "${DB_PATH}.restoring"
mv "${DB_PATH}.restoring" "$DB_PATH"
chown root:root "$DB_PATH"
chmod 664 "$DB_PATH"

echo "[*] Verifying integrity of the restored database..."
INTEGRITY_RESULT=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;")
echo "$INTEGRITY_RESULT"
if [ "$INTEGRITY_RESULT" != "ok" ]; then
    echo "[-] Integrity check FAILED -- the restored database is corrupt."
    if [ -f "$PRE_RESTORE_PATH" ]; then
        echo "[-] Rolling back to the pre-restore database..."
        cp "$PRE_RESTORE_PATH" "$DB_PATH"
        chown root:root "$DB_PATH"
        chmod 664 "$DB_PATH"
        echo "[-] Rolled back -- the bad backup was NOT applied. Investigate $BACKUP_FILE before retrying."
    else
        echo "[-] No pre-restore copy existed to roll back to -- $DB_PATH is left in its corrupt, restored state. Restore a different backup immediately."
    fi
    exit 1
fi

echo "[+] Restore complete."
if [ -f "$PRE_RESTORE_PATH" ]; then
    echo "[+] The pre-restore database is preserved at: $PRE_RESTORE_PATH"
    echo "    (delete it manually once you've confirmed the restore is good)"
fi
