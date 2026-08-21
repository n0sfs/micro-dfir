import requests, urllib3
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = FastAPI(title="Micro DFIR SOAR")

SOAR_API_KEY = "SUPER_SECRET_SOAR_KEY_123"
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

WAZUH_API_URL = "https://127.0.0.1:55000" 
WAZUH_USER = "wazuh-wui"; WAZUH_PASS = "YourWazuhPassword"

class SIEMAlert(BaseModel):
    rule_title: str; severity: str; hostname: str; agent_id: str; raw_log: str

def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header != f"Bearer {SOAR_API_KEY}": raise HTTPException(status_code=403, detail="Unauthorized")
    return api_key_header

def get_wazuh_token():
    res = requests.get(f"{WAZUH_API_URL}/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=False)
    if res.status_code == 200: return res.json()['data']['token']
    raise Exception("Wazuh Auth Failed")

def playbook_isolate_host(agent_id: str):
    try:
        token = get_wazuh_token()
        payload = {"command": "firewall-drop", "agents_list": [agent_id], "arguments": ["-", "any"]}
        res = requests.put(f"{WAZUH_API_URL}/active-response", headers={"Authorization": f"Bearer {token}"}, json=payload, verify=False)
        return res.status_code == 200
    except: return False

@app.post("/webhook/alert")
async def receive_alert(alert: SIEMAlert, api_key: str = Depends(get_api_key)):
    if alert.severity.lower() in ["high", "critical"]:
        if alert.agent_id != "unknown": playbook_isolate_host(alert.agent_id)
        return {"status": "Automated Response Executed"}
    return {"status": "Logged"}

if __name__ == "__main__":
    import uvicorn; uvicorn.run(app, host="0.0.0.0", port=8000)
