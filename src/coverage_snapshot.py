# Daily cron job (see update.sh) that snapshots today's MITRE ATT&CK coverage tier
# counts into coverage_snapshots, so the Coverage tab (templates/dashboard.html,
# ?tab=coverage) can show a trend over time instead of only ever-live numbers.
# Mirrors archive_logs.py's pattern: a standalone script driven by cron, not a service.
#
# Deliberately self-contained rather than importing from app.py (which sets up
# Flask/login-manager/DB-path resources on import) -- duplicates the same minimal
# tag-extraction regex already independently duplicated between app.py's
# _get_rules_cache() and sigma_engine.py's alert-tagging path (see CLAUDE.md's
# "Dual-definition config dicts" note -- this is the same established tradeoff, not a
# new one). Only imports mitre_attack, which has zero Flask dependencies (same way
# sigma_engine.py already imports it, run from the same src/ directory).
import sqlite3, sys, re
from datetime import date

from mitre_attack import TECHNIQUES, _display_id, techniques_for_tags

DB_PATH = '/opt/micro-dfir/siem.db'
VALIDATED_WINDOW_DAYS = 30  # matches the Coverage tab's default range selector

_TAGS_RE = re.compile(r'^tags:\s*\n((\s+-\s*[^\n\r]+\n?)+)', re.MULTILINE)

def _extract_tags(rule_yaml):
    m = _TAGS_RE.search(rule_yaml)
    if not m:
        return []
    return [t.strip().strip('- ') for t in m.group(1).split('\n') if t.strip()]

def snapshot_coverage():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row

    enabled_counts = {}
    disabled_counts = {}
    for row in conn.execute("SELECT rule_yaml, enabled FROM sigma_rules").fetchall():
        tags = _extract_tags(row['rule_yaml'] or '')
        for tech in techniques_for_tags(tags):
            if tech['tactic'] == 'unmapped':
                continue
            key = (tech['tactic'], tech['id'])
            if row['enabled']:
                enabled_counts[key] = enabled_counts.get(key, 0) + 1
            else:
                disabled_counts[key] = disabled_counts.get(key, 0) + 1

    validated = {}
    for row in conn.execute(
        "SELECT mitre_techniques FROM alerts WHERE timestamp >= datetime('now', ?) "
        "AND mitre_techniques IS NOT NULL AND mitre_techniques != ''",
        (f'-{VALIDATED_WINDOW_DAYS} days',)
    ).fetchall():
        for tid in (row['mitre_techniques'] or '').split(','):
            tid = tid.strip()
            if tid:
                validated[tid] = validated.get(tid, 0) + 1

    # Same 4-tier classification as app.py's _build_mitre_coverage, collapsed to
    # global totals only -- the daily snapshot doesn't need a per-tactic breakdown.
    tiers = {'gap': 0, 'inactive': 0, 'active': 0, 'validated': 0}
    seen_ids = set()
    for key, (name, tactic) in TECHNIQUES.items():
        tid = _display_id(key)
        if tid in seen_ids:
            continue
        seen_ids.add(tid)
        enabled_n = enabled_counts.get((tactic, tid), 0)
        disabled_n = disabled_counts.get((tactic, tid), 0)
        validated_n = validated.get(tid, 0)
        if enabled_n == 0 and disabled_n == 0:
            tier = 'gap'
        elif enabled_n == 0:
            tier = 'inactive'
        elif validated_n == 0:
            tier = 'active'
        else:
            tier = 'validated'
        tiers[tier] += 1

    total = len(seen_ids)
    coverage_pct = ((tiers['active'] + tiers['validated']) / total * 100) if total else 0.0
    today = date.today().isoformat()

    # UNIQUE(snapshot_date) + INSERT OR REPLACE: a same-day re-run (manual trigger, or
    # the one-time run update.sh does right after scheduling the cron) updates that
    # day's row instead of creating a duplicate.
    conn.execute(
        "INSERT OR REPLACE INTO coverage_snapshots "
        "(snapshot_date, techniques_total, gap_count, inactive_count, active_count, validated_count, coverage_pct) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (today, total, tiers['gap'], tiers['inactive'], tiers['active'], tiers['validated'], coverage_pct)
    )
    conn.commit()
    conn.close()
    return {'snapshot_date': today, 'coverage_pct': coverage_pct, 'tiers': tiers, 'total': total}

if __name__ == "__main__":
    try:
        result = snapshot_coverage()
        print(f"[+] Coverage snapshot recorded for {result['snapshot_date']}: "
              f"{result['coverage_pct']:.1f}% covered ({result['tiers']}) of {result['total']} techniques.", flush=True)
    except Exception as e:
        print(f"[-] Coverage snapshot failed: {e}")
        sys.exit(1)
