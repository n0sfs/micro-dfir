#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "Please run as root (sudo bash update.sh)"; exit 1; fi

SOC_DIR="/opt/micro-dfir"
echo "[*] Pulling latest updates from GitHub..."
cd "$(dirname "$0")"
sudo -u $SUDO_USER git pull origin main

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

echo "[*] Restarting Micro-SOC services to apply changes..."
systemctl restart microsoc-web
systemctl restart microsoc-soar

echo "[+] In-place update complete! Your database and settings were preserved."
