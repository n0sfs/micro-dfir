import sqlite3
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

app = FastAPI(title="Micro DFIR SOAR")

DB_PATH = "/opt/micro-dfir/siem.db"
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

class SIEMAlert(BaseModel):
    rule_title: str; severity: str; hostname: str; agent_id: str; raw_log: str

def get_soar_api_key():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        row = conn.execute("SELECT value FROM settings WHERE key = 'soar_api_key'").fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception:
        return None

def get_api_key(api_key_header: str = Security(api_key_header)):
    expected = get_soar_api_key()
    if not expected or api_key_header != f"Bearer {expected}":
        raise HTTPException(status_code=403, detail="Unauthorized")
    return api_key_header

# No automated playbook is wired up here. The previous one authenticated to a Wazuh
# instance that was never actually deployed alongside this app (hardcoded placeholder
# credentials, an API URL nothing was listening on) — it silently failed on every
# high/critical alert since this service went live. Every alert is accepted and
# acknowledged; nothing acts on it until a real playbook is deliberately wired in
# (e.g. driven by the EDR agents' own isolate_host response action).
@app.post("/webhook/alert")
async def receive_alert(alert: SIEMAlert, api_key: str = Depends(get_api_key)):
    return {"status": "Logged"}

if __name__ == "__main__":
    # Loopback only. This bound 0.0.0.0:8000 -- an authenticated-but-inert webhook
    # receiver listening on every interface. Nothing calls it: a repo-wide search for
    # port 8000 or /webhook/alert finds exactly one hit, the route definition itself.
    # Every playbook and notification path in this product runs inside the web app
    # (soar_alerts.py, _run_playbook_action) and has never gone near this service.
    # An open port with no client is pure surface area.
    #
    # If a genuine off-box integration ever needs this, that is a deliberate decision that
    # comes with a bind setting and a reason, not a default nobody chose.
    import uvicorn; uvicorn.run(app, host="127.0.0.1", port=8000)
