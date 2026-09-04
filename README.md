# Enterprise Micro DFIR

A Complete Edge Security Appliance integrating:
1.  **SIEM:** Vector + SQLite + Log Pipeline UI
2.  **EDR:** Custom Windows/Linux agents (remote response actions, live triage)
3.  **UEBA:** DuckDB Behavioral Models
4.  **SOAR:** Automated response playbooks, chained actions triggered by case lifecycle events (create/status/queue/assignee changes)
5.  **Threat Intel:** TAXII 2.1 STIX Caching & ThreatFox Integration
6.  **Coverage:** MITRE ATT&CK, compliance framework, and fleet vulnerability coverage in one place — a shared gap/inactive/active/validated tier model applied across all three

## Deployment
`sudo bash install.sh`

## Access control

Access is governed by named permissions, not a fixed rank ladder — a role is
just a set of permission keys drawn from a ~21-key registry spanning every
gated app area (Cases, Log Search, Detection Rules, UEBA, Threat Intel,
EDR/Agents, SOAR, Settings). Admins manage roles from Settings > Security >
User Groups: view what each role can access, edit any role's permissions, or
create an entirely new custom role (e.g. a "Threat Intel Analyst" role scoped
to only `threatintel.manage`).

Three built-in roles ship out of the box and can't be deleted, though their
permissions can still be edited:

| Role | Tier | Can do |
|---|---|---|
| `analyst` | Tier 1/2 | Triage, investigate, and respond: alerts, cases, log search, threat lookups, and the 4 safe EDR actions (isolate host, restore network, triage collection, kill process). |
| `senior_analyst` | Tier 3 | Everything above, plus hunting (YARA/IOC/string sweeps), detection rule tuning, UEBA model config, threat intel feed/entity management, SOAR playbook authoring, case deletion, and the full EDR response console (including free-text commands). |
| `admin` | Admin | Everything above, plus user management, network/TLS/system settings, backups, retention, playbook secrets, and the audit log. |

The built-in `admin` role can never lose the two permissions that manage
users and roles themselves, so the system can't be locked out of its own
administration.

Enforcement is server-side (`require_permission(key)` in `src/app.py`,
checked against each role's row in `role_permissions`) on every
mutating/sensitive route; the UI's `hasPermission(key)` helper
(`templates/base.html`) mirrors those checks only to hide controls a user's
role couldn't use anyway.

## License

[MIT](LICENSE)
