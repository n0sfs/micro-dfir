"""Curated warninglist-style suppression data (MISP's misp-warninglists pattern) and
the matcher that applies it. These vendored lists are seeded once into the warninglists/
warninglist_entries tables by app.py's migrate_warninglists() -- this module holds only
the static data + the pure matching logic, so it's importable from both app.py (Flask
db) and sigma_engine.py (raw sqlite3), same DB-connection-agnostic shape as
notifications.py.

Kept deliberately small and hand-picked rather than mirroring MISP's full ~150-list
set (some of which, like public-dns-v4, run to 60,000+ CIDR entries) -- these three
cover the highest-value, lowest-risk false-positive sources for a single appliance
without needing a live warninglist-repo sync.
"""
import ipaddress

# Confirmed live against github.com/MISP/misp-warninglists/blob/main/lists/rfc1918/list.json
RFC1918_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

# Confirmed live against github.com/MISP/misp-warninglists/blob/main/lists/cloudflare/list.json
CLOUDFLARE_CIDRS = [
    '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/13', '104.24.0.0/14',
    '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15', '172.64.0.0/13',
    '173.245.48.0/20', '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '2400:cb00::/32', '2405:8100::/32', '2405:b500::/32', '2606:4700::/32', '2803:f800::/32',
    '2a06:98c0::/29', '2c0f:f248::/32',
]

# Hand-curated, not vendored from misp-warninglists (its public-dns-v4 list runs to
# ~63,000 aggregated CIDR entries) -- just the well-known, stable anycast addresses of
# the major public resolvers themselves.
PUBLIC_DNS_RESOLVERS = [
    '8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844',       # Google
    '1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001',       # Cloudflare
    '9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9',                  # Quad9
    '208.67.222.222', '208.67.220.220',                                        # OpenDNS
]

SEED_WARNINGLISTS = [
    {
        'name': 'RFC 1918 Private IP Ranges', 'type': 'cidr', 'entries': RFC1918_CIDRS,
        'description': 'Private, non-routable address space -- never a legitimate external IOC.',
    },
    {
        'name': 'Cloudflare CDN Ranges', 'type': 'cidr', 'entries': CLOUDFLARE_CIDRS,
        'description': 'Shared CDN infrastructure -- a malicious host fronted by Cloudflare shows up as one of these IPs to every visitor, not just this environment.',
    },
    {
        'name': 'Major Public DNS Resolvers', 'type': 'ip', 'entries': PUBLIC_DNS_RESOLVERS,
        'description': 'Google/Cloudflare/Quad9/OpenDNS resolver addresses -- normal DNS traffic, not C2.',
    },
]


def _ip_matches(ip_str, entry_value, entry_type):
    try:
        if entry_type == 'cidr':
            return ipaddress.ip_address(ip_str) in ipaddress.ip_network(entry_value, strict=False)
        return ip_str == entry_value
    except ValueError:
        return False


def filter_warninglisted_ips(cursor, ips):
    """Given an iterable of IP strings, returns the subset NOT matched by any
    currently-enabled warninglist entry. `cursor` is anything with a sqlite-shaped
    .execute(...).fetchall() -- sqlite3.Connection/Cursor or Flask's get_db()."""
    ips = list(ips)
    if not ips:
        return []
    entries = cursor.execute(
        "SELECT e.value, w.type FROM warninglist_entries e "
        "JOIN warninglists w ON w.id = e.warninglist_id WHERE w.enabled = 1"
    ).fetchall()
    if not entries:
        return ips
    return [ip for ip in ips if not any(_ip_matches(ip, val, typ) for val, typ in entries)]
