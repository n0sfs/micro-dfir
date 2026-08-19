import requests
def lookup_ioc(ioc_value):
    try:
        res = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ioc_value}, timeout=3)
        if res.status_code == 200:
            d = res.json()
            if d.get("query_status") == "ok":
                h = d["data"][0]
                return {"status": "malicious", "threat_type": h.get("threat_type"), "malware": h.get("malware_printable"), "confidence": h.get("confidence_level"), "tags": h.get("tags")}
            elif d.get("query_status") == "no_result": return {"status": "clean", "message": "No known threats."}
        return {"status": "error", "message": "CTI query failed."}
    except Exception as e: return {"status": "error", "message": str(e)}
