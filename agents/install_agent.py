import time, json, urllib.request, os, sys, subprocess

SOC_IP = "MICRO_SOC_IP_PLACEHOLDER"
SECRET_KEY = "YOUR_SECRET_MICRO_SOC_KEY"
TASK_NAME = "MicroDFIRAgent"
DEBUG_LOG = "C:\\Windows\\Temp\\micro_agent_debug.log"

def log_debug(text):
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
    except:
        pass

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
        log_debug(f"Failed to send log: {e}")
        return False

def get_windows_events():
    try:
        cmd = [
            "powershell", "-NoProfile", "-Command", 
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security','System'; ID=4624,4625,4688,7045} -MaxEvents 5 -ErrorAction SilentlyContinue; "
            "if ($events) { $events | Select-Object @{Name='TimeCreated';Expression={ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}, Id, LogName, Message | ConvertTo-Json -Compress }"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            return data
    except Exception as e:
        log_debug(f"Event query error: {e}")
    return []

def find_system_python():
    candidates = [
        r"C:\Program Files\Python312\pythonw.exe",
        r"C:\Program Files\Python311\pythonw.exe",
        r"C:\Program Files\Python310\pythonw.exe",
        r"C:\Python312\pythonw.exe",
        r"C:\Python311\pythonw.exe",
        r"C:\Python310\pythonw.exe"
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    if "Users" not in sys.executable:
        return sys.executable.replace("python.exe", "pythonw.exe")
    return None

def install_service():
    script_path = os.path.abspath(__file__)
    python_path = find_system_python()
    
    if not python_path:
        print("[-] ERROR: A system-wide Python installation was not found.")
        print("[-] Please install Python for 'All Users' or use a global path.")
        return

    cmd = [
        "schtasks", "/create", "/tn", TASK_NAME,
        "/tr", f'"{python_path}" "{script_path}"',
        "/sc", "ONSTART", "/ru", "SYSTEM", "/f"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Micro-DFIR Agent successfully installed as a system-wide service!")
        subprocess.run(["schtasks", "/run", "/tn", TASK_NAME])
    else:
        print(f"[-] Failed to install service: {result.stderr}")

def uninstall_service():
    subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"], capture_output=True)
    print("[+] Micro-DFIR Agent background service removed.")

def run_agent():
    log_debug("System-wide agent started.")
    send_log("Windows system-wide log forwarder started.")
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
        except Exception as e:
            log_debug(f"Loop error: {e}")
            time.sleep(30)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "install":
            install_service()
        elif arg == "uninstall":
            uninstall_service()
    else:
        run_agent()