# Country-level IP geolocation, backed by the DB-IP Lite "IP to Country" database
# (kept fresh by geoip_update.py, a monthly cron job -- see install.sh). DB-IP Lite
# publishes in the same MaxMind DB (.mmdb) binary format GeoLite2 uses, so the generic
# maxminddb reader works for either without any DB-IP/MaxMind-specific client library.
# No API key, no account, no per-lookup network call -- everything is a local file read.
GEOIP_DIR = "/opt/micro-dfir/data/geoip"
GEOIP_DB_PATH = f"{GEOIP_DIR}/dbip-country-lite.mmdb"

import os

_reader = None
_reader_mtime = None

# Reopens the reader only when the underlying file's mtime changes (i.e. once a month,
# right after geoip_update.py swaps in a fresh database) -- everything in between is a
# cheap in-memory lookup, not a fresh file open per call.
def _get_reader():
    global _reader, _reader_mtime
    try:
        mtime = os.path.getmtime(GEOIP_DB_PATH)
    except OSError:
        return None
    if _reader is None or mtime != _reader_mtime:
        import maxminddb
        if _reader is not None:
            _reader.close()
        _reader = maxminddb.open_database(GEOIP_DB_PATH)
        _reader_mtime = mtime
    return _reader

def lookup_country(ip):
    """Resolve a source IP to (iso_code, country_name). Returns (None, None) for a
    private/reserved/invalid IP, an IP the database has no entry for, or if the
    database hasn't been downloaded yet (e.g. before geoip_update.py's first run)."""
    if not ip:
        return None, None
    reader = _get_reader()
    if reader is None:
        return None, None
    try:
        result = reader.get(ip)
    except ValueError:
        return None, None
    country = (result or {}).get('country')
    if not country:
        return None, None
    return country.get('iso_code'), (country.get('names') or {}).get('en')
