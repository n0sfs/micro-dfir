#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "Please run as root (sudo bash update.sh)"; exit 1; fi

SOC_DIR="/opt/micro-dfir"
echo "[*] Pulling latest updates from GitHub..."
cd "$(dirname "$0")"
git config --global --add safe.directory "$(pwd)"
if ! git pull origin main; then
    echo "[-] git pull failed — aborting update. No files were changed."
    exit 1
fi

echo "[*] Syncing updated files to production environment..."
rsync -av --exclude='siem.db' \
          --exclude='venv' \
          --exclude='.git' \
          --exclude='agent_config.json' \
          --exclude='*.log' \
          ./ $SOC_DIR/

echo "[*] Checking for any new Python dependencies..."
cd $SOC_DIR
source venv/bin/activate
pip install -r requirements.txt

# install.sh sets up cron jobs at first-install time only -- update.sh never touches
# crontab otherwise, so an existing host would never pick up a cron entry added after
# its original install without this. Idempotent (matches install.sh's own pattern):
# safe to re-run on every future deploy, always ends with exactly one matching line.
echo "[*] Ensuring the GeoIP database cron job is scheduled..."
(crontab -l 2>/dev/null | grep -v "geoip_update.py"; echo "0 3 1 * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/geoip_update.py >> /var/log/microdfir-geoip.log 2>&1") | crontab -
if [ ! -f "$SOC_DIR/data/geoip/dbip-country-lite.mmdb" ]; then
    echo "[*] No GeoIP database found yet -- downloading now instead of waiting for the monthly cron run..."
    venv/bin/python src/geoip_update.py
fi

# Report scheduling moved from this script's own hardcoded crontab line to a
# Settings-page-configurable one (Settings > Reports > Schedule), applied live by
# app.py whenever an admin saves it. An existing host's crontab still has the OLD
# hardcoded line from a prior install.sh run, though -- this one-shot sync replaces it
# with whatever the saved schedule config says (defaulting to the same "security only,
# monthly" behavior if nothing's been saved yet), so it doesn't linger alongside the
# app-managed lines and double-generate the security report.
echo "[*] Syncing the report generation schedule to crontab..."
venv/bin/python src/sync_report_schedule.py

echo "[*] Restarting Micro-SOC services to apply changes..."
systemctl restart microsoc-web
systemctl restart microsoc-soar
systemctl restart microsoc-sigma

echo "[+] In-place update complete! Your database and settings were preserved."
