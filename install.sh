#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "Please run as root (sudo bash install.sh)"; exit 1; fi

SOC_DIR="/opt/micro-dfir"
echo "[*] Deploying Micro DFIR Architecture..."

if [ ! -d "src" ] || [ ! -d "config" ] || [ ! -f "requirements.txt" ]; then
  echo "[-] Error: Run this script from the root of your cloned 'micro-dfir' repository folder!"
  echo "    (Current directory: $(pwd))"
  exit 1
fi

systemctl stop rsyslog 2>/dev/null
systemctl disable rsyslog 2>/dev/null

echo "[*] Installing System Dependencies..."
apt-get update
apt-get install -y python3-venv python3-pip sqlite3 curl openssl libpango-1.0-0 libpangoft2-1.0-0 build-essential libssl-dev pkg-config

echo "[*] Installing Vector Ingestion Engine..."
curl -1sLf 'https://repositories.timber.io/public/vector/cfg/setup/bash.deb.sh' | bash
apt-get install -y vector

echo "[*] Copying application files to $SOC_DIR..."
mkdir -p $SOC_DIR
cp -r ./* $SOC_DIR/
cd $SOC_DIR

echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Generating self-signed TLS certificate for the web dashboard and ingestion API..."
if [ ! -f "config/cert.pem" ] || [ ! -f "config/key.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout config/key.pem -out config/cert.pem -days 3650 -subj "/CN=micro-dfir"
fi

echo "[*] Configuring Vector..."
cp config/vector.toml /etc/vector/vector.toml
rm -f /etc/vector/vector.yaml
echo 'VECTOR_CONFIG="/etc/vector/vector.toml"' > /etc/default/vector
mkdir -p /etc/systemd/system/vector.service.d
echo -e "[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE" > /etc/systemd/system/vector.service.d/override.conf
chown -R vector:vector /etc/vector/

echo "[*] Initializing Database & Administrator..."
venv/bin/python -c "import sys; sys.path.append('src'); from app import init_db; init_db()"
venv/bin/python src/setup_admin.py
venv/bin/python src/import_sigmahq.py
venv/bin/python src/geoip_update.py

echo "[*] Setting up Automation Cron Jobs..."
(crontab -l 2>/dev/null | grep -v "ueba_engine.py"; echo "0 * * * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/ueba_engine.py >> /var/log/microdfir-ueba.log 2>&1") | crontab -
(crontab -l 2>/dev/null | grep -v "taxii_client.py"; echo "0 2 * * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/taxii_client.py >> /var/log/microdfir-taxii.log 2>&1") | crontab -
(crontab -l 2>/dev/null | grep -v "generate_report.py"; echo "0 1 1 * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/generate_report.py >> /var/log/microdfir-report.log 2>&1") | crontab -
(crontab -l 2>/dev/null | grep -v "geoip_update.py"; echo "0 3 1 * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/geoip_update.py >> /var/log/microdfir-geoip.log 2>&1") | crontab -

echo "[*] Installing Systemd Services..."
cp config/microsoc-web.service /etc/systemd/system/
cp config/microsoc-sigma.service /etc/systemd/system/
cp config/microsoc-soar.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now vector.service
systemctl enable --now microsoc-web.service
systemctl enable --now microsoc-sigma.service
systemctl enable --now microsoc-soar.service

echo "[+] Deployment Complete!"
echo "[+] Micro DFIR Dashboard: https://<nuc-ip>:5001"