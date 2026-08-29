# Enterprise Micro DFIR

A Complete Edge Security Appliance integrating:
1.  **SIEM:** Vector + SQLite + Log Pipeline UI
2.  **EDR:** Custom Windows/Linux agents (remote response actions, live triage)
3.  **UEBA:** DuckDB Behavioral Models
4.  **SOAR:** Automated response playbooks, chained actions triggered by case lifecycle events (create/status/queue/assignee changes)
5.  **Threat Intel:** TAXII 2.1 STIX Caching & ThreatFox Integration

## Deployment
`sudo bash install.sh`

## Access control

Every user account has one role, ranked as a strict escalation ladder (each tier
inherits everything below it) rather than independent capability grants:

| Role | Tier | Can do |
|---|---|---|
| `analyst` | Tier 1/2 | Triage, investigate, and respond: alerts, cases, log search, threat lookups, and the 4 safe EDR actions (isolate host, restore network, triage collection, kill process). |
| `senior_analyst` | Tier 3 | Everything above, plus hunting (YARA/IOC/string sweeps), detection rule tuning, UEBA model config, threat intel feed/entity management, SOAR playbook authoring, case deletion, and the full EDR response console (including free-text commands). |
| `admin` | Admin | Everything above, plus user management, network/TLS/system settings, backups, retention, playbook secrets, and the audit log. |

Enforcement is server-side (`require_role()` in `src/app.py`, checked against
`ROLE_RANK`) on every mutating/sensitive route; the UI's `roleAtLeast()` helper
(`templates/base.html`) mirrors those checks only to hide controls a lower tier
couldn't use anyway.
