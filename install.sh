cat << 'EOF' > install.sh
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
apt-get install -y python3-venv python3-pip sqlite3 curl libpango-1.0-0 libpangoft2-1.0-0 build-essential libssl-dev pkg-config

echo "[*] Installing Vector Ingestion Engine..."
curl -1sLf 'https://repositories.timber.io/public/vector/cfg/setup/bash.deb.sh' | bash
apt-get install -y vector

echo "[*] Downloading Velociraptor Server Binary..."
mkdir -p $SOC_DIR/bin
curl -L -o $SOC_DIR/bin/velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-linux-amd64
chmod +x $SOC_DIR/bin/velociraptor

echo "[*] Copying application files to $SOC_DIR..."
mkdir -p $SOC_DIR
cp -r ./* $SOC_DIR/
cd $SOC_DIR

echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Configuring Vector..."
cp config/vector.toml /etc/vector/vector.toml
rm -f /etc/vector/vector.yaml
echo 'VECTOR_CONFIG="/etc/vector/vector.toml"' > /etc/default/vector
mkdir -p /etc/systemd/system/vector.service.d
echo -e "[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE" > /etc/systemd/system/vector.service.d/override.conf
chown -R vector:vector /etc/vector/

echo "[*] Configuring Velociraptor..."
$SOC_DIR/bin/velociraptor config generate > $SOC_DIR/config/server.config.yaml
sed -i 's/bind_address: 127.0.0.1/bind_address: 0.0.0.0/g' $SOC_DIR/config/server.config.yaml
$SOC_DIR/bin/velociraptor --config $SOC_DIR/config/server.config.yaml user add admin "Admin123!" --role administrator

echo "[*] Initializing Database & Administrator..."
venv/bin/python -c "import sys; sys.path.append('src'); from app import init_db; init_db()"
venv/bin/python src/setup_admin.py
venv/bin/python src/import_sigmahq.py

echo "[*] Setting up Automation Cron Jobs..."
(crontab -l 2>/dev/null | grep -v "ueba_engine.py"; echo "0 * * * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/ueba_engine.py >> /var/log/microdfir-ueba.log 2>&1") | crontab -
(crontab -l 2>/dev/null | grep -v "taxii_client.py"; echo "0 2 * * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/taxii_client.py >> /var/log/microdfir-taxii.log 2>&1") | crontab -
(crontab -l 2>/dev/null | grep -v "generate_report.py"; echo "0 1 1 * * $SOC_DIR/venv/bin/python3 $SOC_DIR/src/generate_report.py >> /var/log/microdfir-report.log 2>&1") | crontab -

echo "[*] Installing Systemd Services..."
cp config/microsoc-web.service /etc/systemd/system/
cp config/microsoc-sigma.service /etc/systemd/system/
cp config/microsoc-soar.service /etc/systemd/system/
cp config/velociraptor.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now vector.service
systemctl enable --now microsoc-web.service
systemctl enable --now microsoc-sigma.service
systemctl enable --now microsoc-soar.service
systemctl enable --now velociraptor.service

echo "[+] Deployment Complete!"
echo "[+] Micro DFIR Dashboard: http://<nuc-ip>:5001"
echo "[+] Velociraptor GUI:      https://<nuc-ip>:8889"
EOF