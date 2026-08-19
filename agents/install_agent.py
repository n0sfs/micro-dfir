import time, json, urllib.request, os, sys, subprocess

SOC_IP = "MICRO_SOC_IP_PLACEHOLDER"
SECRET_KEY = "YOUR_SECRET_MICRO_SOC_KEY"
TASK_NAME = "MicroDFIRAgent"

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
    except Exception:
        pass

def get_windows_events():
    try:
        cmd = [
            "powershell", "-NoProfile", "-Command", 
            "Get-WinEvent -FilterHashtable @{LogName='Security','System'; ID=4624,4625,4688,7045} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LogName, Message | ConvertTo-Json -Compress"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            return data
    except Exception:
        pass
    return []

def install_service():
    script_path = os.path.abspath(__file__)
    python_w_path = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(python_w_path):
        python_w_path = sys.executable # Fallback

    # Create a Windows Scheduled Task that runs at system startup under SYSTEM privileges
    cmd = [
        "schtasks", "/create", "/tn", TASK_NAME,
        "/tr", f'"{python_w_path}" "{script_path}"',
        "/sc", "ONSTART", "/ru", "SYSTEM", "/f"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Micro-DFIR Agent successfully installed as a background service!")
            print("[+] It will now run automatically on system boot. Starting it now...")
            subprocess.run(["schtasks", "/run", "/tn", TASK_NAME])
        else:
            print(f"[-] Failed to install service: {result.stderr}")
            print("[*] Try running your PowerShell terminal as Administrator.")
    except Exception as e:
        print(f"[-] Error: {e}")

def uninstall_service():
    cmd = ["schtasks", "/delete", "/tn", TASK_NAME, "/f"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Micro-DFIR Agent background service successfully stopped and removed.")
        else:
            print("[-] Service not found or already removed.")
    except Exception as e:
        print(f"[-] Error: {e}")

def run_agent():
    print(f"[*] Micro-DFIR Windows Log Forwarder Running. Target SOC: {SOC_IP}:5001")
    send_log("Windows log forwarder background service started.")
    sent_events = set()
    
    while True:
        try:
            events = get_windows_events()
            for ev in events:
                time_created = str(ev.get('TimeCreated', ''))
                ev_id = str(ev.get('Id', ''))
                msg_body = str(ev.get('Message', ''))
                clean_msg = msg_body.replace("\r\n", " ").replace("\n", " ")
                event_sig = f"{time_created}_{ev_id}_{clean_msg[:40]}"
                
                if event_sig not in sent_events:
                    sent_events.add(event_sig.strip())
                    if len(sent_events) > 300:
                        sent_events.pop()
                        
                    log_text = f"[{ev.get('LogName')} ID:{ev_id}] {clean_msg}"
                    severity = "warning" if ev_id == "4625" else "info"
                    send_log(log_text, app_name=f"win_{ev.get('LogName').lower()}", severity=severity)
            
            time.sleep(30)
        except Exception:
            time.sleep(30)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "install":
            install_service()
        elif arg == "uninstall":
            uninstall_service()
        else:
            print("Unknown argument. Use 'install' or 'uninstall'.")
    else:
        run_agent()