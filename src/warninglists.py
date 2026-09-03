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
import bisect
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


def _merge_intervals(intervals):
    """Sorts and merges overlapping/nested (start_int, end_int) ranges into the minimal
    disjoint set, so containment can later be answered with one bisect instead of a
    linear scan across every original (possibly nested, e.g. a /8 containing many /16s)
    CIDR range."""
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged = [intervals[0]]
    for start, end in intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    return merged


def _build_ip_matcher(cursor):
    """Builds a reusable matcher from every currently-enabled warninglist entry: an
    exact-match set for 'ip'-type entries, plus merged/sorted (start_int, end_int)
    ranges per address family for 'cidr'-type entries -- kept separate per family since
    plain integer comparison alone can't distinguish a v4 address's int value from a v6
    range's. This replaces the old O(ips * entries) scan that constructed a fresh
    ipaddress object for every (ip, entry) pair: a single large vendored CIDR list
    (e.g. a full AWS-ranges warninglist, ~3,900 entries) crossed against a few thousand
    IOC IPs meant tens of millions of object constructions per detection cycle -- this
    parses every entry exactly once, then answers each IP with a single bisect.
    Returns (exact_set, {4: (starts, merged), 6: (starts, merged)})."""
    entries = cursor.execute(
        "SELECT e.value, w.type FROM warninglist_entries e "
        "JOIN warninglists w ON w.id = e.warninglist_id WHERE w.enabled = 1"
    ).fetchall()
    exact = set()
    raw_intervals = {4: [], 6: []}
    for val, typ in entries:
        try:
            if typ == 'cidr':
                net = ipaddress.ip_network(val, strict=False)
                raw_intervals[net.version].append((int(net.network_address), int(net.broadcast_address)))
            else:
                exact.add(val)
        except ValueError:
            continue
    by_version = {}
    for version, intervals in raw_intervals.items():
        merged = _merge_intervals(intervals)
        by_version[version] = ([iv[0] for iv in merged], merged)
    return exact, by_version


def _ip_matches_matcher(ip_str, exact, by_version):
    if ip_str in exact:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    starts, merged = by_version.get(addr.version, ([], []))
    if not merged:
        return False
    addr_int = int(addr)
    idx = bisect.bisect_right(starts, addr_int) - 1
    return idx >= 0 and addr_int <= merged[idx][1]


def filter_warninglisted_ips(cursor, ips):
    """Given an iterable of IP strings, returns the subset NOT matched by any
    currently-enabled warninglist entry. `cursor` is anything with a sqlite-shaped
    .execute(...).fetchall() -- sqlite3.Connection/Cursor or Flask's get_db()."""
    ips = list(ips)
    if not ips:
        return []
    exact, by_version = _build_ip_matcher(cursor)
    if not exact and not any(merged for _, merged in by_version.values()):
        return ips
    return [ip for ip in ips if not _ip_matches_matcher(ip, exact, by_version)]
