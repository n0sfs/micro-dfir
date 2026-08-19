import time, json, urllib.request, os, sys

SOC_IP = "MICRO_SOC_IP_PLACEHOLDER"
SECRET_KEY = "YOUR_SECRET_MICRO_SOC_KEY"

def send_log(message):
    payload = json.dumps({
        "secret": SECRET_KEY, 
        "message": message, 
        "host": os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'Unknown'))
    }).encode('utf-8')
    req = urllib.request.Request(f"http://{SOC_IP}:514", data=payload, headers={'Content-Type': 'application/json'})
    try: urllib.request.urlopen(req, timeout=3)
    except: pass # Fail silently if SOC is unreachable

if __name__ == "__main__":
    print(f"[*] Micro-DFIR Agent Deployed. Target SOC: {SOC_IP}")
    send_log("Agent successfully installed and checked in.")
