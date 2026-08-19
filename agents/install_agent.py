import time, json, urllib.request, os, sys

SOC_IP = "MICRO_SOC_IP_PLACEHOLDER"
SECRET_KEY = "YOUR_SECRET_MICRO_SOC_KEY"

def send_log(message, app_name="windows_agent", severity="info"):
    payload = json.dumps({
        "hostname": os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'Unknown')),
        "app_name": app_name,
        "severity": severity,
        "message": message
    }).encode('utf-8')
    
    req = urllib.request.Request(
        f"http://{SOC_IP}:5001/api/ingest", 
        data=payload, 
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {SECRET_KEY}'
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status == 201
    except Exception as e:
        pass # Fail silently if SOC is unreachable

if __name__ == "__main__":
    print(f"[*] Micro-DFIR Agent Deployed. Target SOC: {SOC_IP}:5001")
    send_log("Windows agent started and checked in successfully.")
    
    # Keep the agent running in the background and sending heartbeats
    while True:
        try:
            send_log("Agent heartbeat - system operational.")
            time.sleep(60) # Report every 60 seconds
        except KeyboardInterrupt:
            print("\n[*] Agent stopped by user.")
            break