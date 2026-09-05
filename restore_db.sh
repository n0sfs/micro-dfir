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

echo "[*] About to restore siem.db from: $BACKUP_FILE"
echo "[*] This will stop microsoc-web, microsoc-sigma, and microsoc-soar briefly."
read -p "Continue? [y/N] " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "[*] Aborted, nothing changed."
    exit 0
fi

echo "[*] Stopping Micro-DFIR services..."
systemctl stop microsoc-web microsoc-sigma microsoc-soar

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -f "$DB_PATH" ]; then
    echo "[*] Preserving the current (pre-restore) database at ${DB_PATH}.pre_restore_${TIMESTAMP}..."
    cp "$DB_PATH" "${DB_PATH}.pre_restore_${TIMESTAMP}"
else
    echo "[!] No existing database found at $DB_PATH -- nothing to preserve."
fi

echo "[*] Decompressing and restoring $BACKUP_FILE..."
gunzip -c "$BACKUP_FILE" > "${DB_PATH}.restoring"
mv "${DB_PATH}.restoring" "$DB_PATH"
chown root:root "$DB_PATH"
chmod 664 "$DB_PATH"

echo "[*] Verifying integrity of the restored database..."
sqlite3 "$DB_PATH" "PRAGMA integrity_check;"

echo "[*] Restarting Micro-DFIR services..."
systemctl start microsoc-web microsoc-sigma microsoc-soar

echo "[+] Restore complete."
if [ -f "${DB_PATH}.pre_restore_${TIMESTAMP}" ]; then
    echo "[+] The pre-restore database is preserved at: ${DB_PATH}.pre_restore_${TIMESTAMP}"
    echo "    (delete it manually once you've confirmed the restore is good)"
fi
