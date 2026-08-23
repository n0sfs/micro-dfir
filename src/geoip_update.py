# Monthly refresh of the DB-IP Lite country database (see src/geoip.py for the reader
# side). Run once at install time and via a monthly cron entry (install.sh), mirroring
# generate_report.py's cadence rather than adding a new systemd timer.
import os, sys, gzip, shutil, tempfile
from datetime import date, timedelta
import requests

from geoip import GEOIP_DIR, GEOIP_DB_PATH

_DBIP_URL_TEMPLATE = "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz"
# The real file is ~4MB gzipped; refuse anything wildly larger than that could ever
# plausibly be, matching the size-cap pattern used for the YARAify rule pack download.
_DBIP_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024

def _download_month(month, dest_path):
    url = _DBIP_URL_TEMPLATE.format(month=month)
    with requests.get(url, timeout=60, stream=True) as res:
        if res.status_code == 404:
            return False
        res.raise_for_status()
        content_length = res.headers.get("Content-Length")
        if content_length and int(content_length) > _DBIP_MAX_DOWNLOAD_BYTES:
            raise ValueError(f"DB-IP country database is larger than expected ({content_length} bytes) — refusing to download")
        downloaded = 0
        with open(dest_path, "wb") as f:
            for chunk in res.iter_content(chunk_size=1024 * 1024):
                downloaded += len(chunk)
                if downloaded > _DBIP_MAX_DOWNLOAD_BYTES:
                    raise ValueError("DB-IP country database exceeded the maximum expected download size — refusing")
                f.write(chunk)
    return True

def update_geoip_database():
    os.makedirs(GEOIP_DIR, exist_ok=True)
    today = date.today()
    # DB-IP publishes on the 1st of each month, but this job may run before that
    # month's file has actually landed -- fall back one month if so. Only one fallback
    # step; if both are missing something is genuinely wrong upstream, not just early.
    this_month = today.strftime("%Y-%m")
    prev_month = (today.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    candidates = [this_month, prev_month]

    fd, tmp_gz_path = tempfile.mkstemp(suffix=".mmdb.gz", dir=GEOIP_DIR)
    os.close(fd)
    tmp_mmdb_path = None
    try:
        fetched_month = None
        for month in candidates:
            if _download_month(month, tmp_gz_path):
                fetched_month = month
                break
        if not fetched_month:
            raise RuntimeError(f"no DB-IP country database found for any of {candidates}")

        fd2, tmp_mmdb_path = tempfile.mkstemp(suffix=".mmdb", dir=GEOIP_DIR)
        os.close(fd2)
        with gzip.open(tmp_gz_path, "rb") as f_in, open(tmp_mmdb_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        # Sanity-check it's a real, readable mmdb before ever swapping it into place --
        # a truncated or corrupt download must never replace a working database.
        import maxminddb
        reader = maxminddb.open_database(tmp_mmdb_path)
        reader.close()

        os.replace(tmp_mmdb_path, GEOIP_DB_PATH)  # same filesystem -> atomic
        tmp_mmdb_path = None
        print(f"[+] GeoIP country database updated ({fetched_month})")
        return True
    finally:
        if os.path.exists(tmp_gz_path):
            os.remove(tmp_gz_path)
        if tmp_mmdb_path and os.path.exists(tmp_mmdb_path):
            os.remove(tmp_mmdb_path)

if __name__ == "__main__":
    try:
        update_geoip_database()
    except Exception as e:
        print(f"[-] GeoIP database update failed: {e}")
        sys.exit(1)
