# Changelog

A dated, narrative record of what's been built and why — kept because memory notes and
plan files are ephemeral, but this file lives in the repo and travels with the code.

**Convention**: add an entry here for anything a future reader would want to know about —
a new feature, a real architectural decision, an incident and its fix. Routine polish/typo
fixes don't need their own line; group them into the feature they support. Newest first.
Full commit-level detail is always available via `git log`.

## 2026-09-05

### Production incident: `siem.db` corruption and recovery

Around 16:43 on 2026-09-04, `/opt/micro-dfir/siem.db`'s first page (the 4096-byte header +
schema catalog) was overwritten with unrelated Sysmon log text, right at a service restart.
Root cause was never conclusively identified (the corrupted bytes looked like real log
content, not random garbage). Recovery, done live against production with no prior backup
to fall back on:

- Used `sqlite3`'s `.recover` command (from an official precompiled build with
  `sqlite_dbpage` support — the system package lacked it) to salvage the database
  page-by-page after grafting a fresh, valid page 1 onto a working copy.
- `.recover` also turned up several old, orphaned `sqlite_master` schema snapshots still
  sitting in freed space — the *authoritative* real column layout for every table, which
  turned out to differ from `schema.sql` in several places (ALTER TABLE-added columns
  land wherever they were historically appended, not wherever `schema.sql` shows them
  today — a real, generalizable gap in trusting `schema.sql` as ground truth for an
  existing, long-migrated database).
- Mapped every recovered data fragment back to its real table by content (not just
  column-count guessing — verified failed more than once, e.g. `stix_indicators`'
  `ioc_type` column position, and a rootpage-reuse false match for `agent_tokens`).
  Rebuilt a fresh database and restored ~7.4M rows across every core table (`live_logs`,
  `alerts`, `sigma_rules`, `stix_indicators`, `cases`, `users`, `settings`, `roles`, etc).
- `PRAGMA integrity_check` clean; referential integrity (`alerts.rule_id`/`event_id`
  against `sigma_rules`/`live_logs`) verified with zero orphans.
- Known, accepted gaps (empty, either genuinely never-populated or truly unrecoverable):
  `assets`, `identities`, `rule_exclusions`, `saved_searches`, `live_logs_archive` (this
  instance was too young to have archived anything yet), `coverage_snapshots` (regenerates
  nightly), several SOAR/UEBA working-state tables, one custom role's display label
  (its permission grants survived).
- **Found and fixed a real, separate pre-existing bug while verifying the recovery**:
  `generate_vector_config()`'s `microsoc_out` sink was hardcoded to
  `https://127.0.0.1:{ingest_port}/api/ingest` regardless of the configured
  `ingest_bind_ip`. A gunicorn bind to `0.0.0.0` accepts loopback fine, but Settings >
  Network's dual-bind flow binds to one specific IP instead — which never accepts
  `127.0.0.1`. This silently broke syslog-sourced ingestion (dnsmasq DNS queries, any real
  syslog device) independent of tonight's incident. Fixed to target whichever address
  will actually be listening.
- **Agent tokens**: `agent_tokens` (per-agent auth bindings) came back empty — recovered
  the raw token hash values from the table's own surviving index page and reinserted them
  unbound (`hostname=NULL`), letting `_validate_agent_auth`'s existing trust-on-first-use
  logic re-bind them to the real agents on their next check-in. Both fleet agents
  (`LAPTOP-KKPV777T`, `DESKTOP-C3LBEGL`) re-authenticated successfully with no re-enrollment
  needed.
- The corrupted original is preserved at `/opt/micro-dfir/siem.db.corrupted.bak` on the
  production host.

**Follow-up this incident directly motivated**: automated backup scheduling + a documented
restore procedure (see below / next entries), since there was no backup to restore from.

### Add a Category filter and Select-Visible-for-delete to File Scan

Deleting a whole unwanted community-rule category (e.g. all 64 ANDROID rules) required
hand-checking every individual rule's delete-box one by one. Added a Category dropdown
alongside the existing Source filter (both real fields, combine as AND), plus "Select
Visible"/"Clear" buttons scoped to whatever the current filters show.

### Fix Vector's ingest sink targeting 127.0.0.1 when bound to a specific IP

See the incident writeup above — this is that fix's own commit.

## 2026-09-04

- **Atomic Testing**: tag alerts triggered by a deliberate Atomic Red Team run
  (`is_atomic_test`), and for a "not detected" run, auto-diagnose *why* — pull the raw
  logs from the exact host/window and dry-run every technique-matching Sigma rule against
  them to tell syntax/logic problems apart from a genuine detection gap. Fixed a stuck-on-
  "Pending" bug (UTC vs local time comparison) and a `dry_run_rule_scoped` crash (SQLite
  views can't take bound parameters) along the way. Catalog sync cadence is now
  configurable instead of fixed.
- **IOC feeds**: added a column picker (Category/Confidence/TLP/Tags, toggle what you see,
  persisted per-browser), removed YARAify from IOC-context dropdowns (it only ever
  produces YARA rules, never IOC rows), and added OpenPhish + blocklist.de as two new
  public feed sources. Fixed the Add Feed modal's type dropdown not actually filtering by
  IOC-vs-rule context in every browser.
- **YARA File Scanner rebuild**: a raw-content viewer (click a rule to see its actual
  `.yar` source, with copy), filtering out index-only wrapper files that have no real
  `rule{}` block (was cluttering the picker with ~13 uncompilable stub files), a Source
  filter, per-rule and bulk delete, and a guided custom YARA rule builder (meta fields,
  repeatable string definitions, any/all/custom condition) that validates via a real
  `yara.compile()` before saving.
- **EDR command timeline**: `agent_commands` (isolate_host, sweeps, etc.) is now a 4th
  branch in the unified Log Search / UEBA Timeline query, so EDR response actions show up
  in the same per-entity investigation view as alerts/anomalies/logs — completing the
  "Collect Evidence" stage of the Timeline's own Signal → Collect → Reconstruct →
  Understand design.
- Also: MITRE ATT&CK entity sync + YARA Forge feed sync, CISA KEV/EPSS enrichment on the
  Vulnerabilities tab (with a stub-record backfill for KEV-only CVEs), a real MIT license,
  dual-network deployment docs, and a fix for a VRL type-checker bug that had silently
  blocked every Vector config reload for about two weeks.

## 2026-09-03

- **Atomic Red Team**: full import/run/validate loop — import the public technique
  catalog, queue a real technique execution on an agent, and automatically check whether
  the expected Sigma rule fired within a validation window.
- **Windows agent**: a real installer (bundled Python, no prerequisites), auto-configured
  Windows audit logging + auto-installed Sysmon, host-detail and heartbeat-history popups,
  real OS version/build reporting, and independently configurable config/log check-in
  intervals. Fixed several real bugs found live: agent download/upgrade producing a
  syntactically broken script, `/api/ingest` only accepting the shared secret (never a
  valid per-agent token), and silent log-shipping failures now redirect to a file instead
  of swallowing errors.
- **SOAR/Cases**: pin raw Log Search rows to a case (not just alerts/anomalies), a Related
  Cases panel (shares a host/IOC/threat entity), a `case_stale` proactive-nudge trigger,
  task assignee/due-date editing, per-column filters on Threat Entities, a pending-
  approvals badge on the SOAR nav item.
- Opt-in DNS query logging (dnsmasq) with read-only pipeline visibility; a "log source
  went silent" alarm distinct from "never ingested at all."

## 2026-09-02

- Technical Maturity Roadmap **Phases 3–5**: UEBA peer-tier-aware rare-process scoring +
  threat-intel IOC fusion; Windows agent watchdog + Agent Offline SOAR trigger + legacy
  shared-secret auth surfacing; Sigma single-rule aggregation-condition support
  (`count() by field > N`, stripped pre-parse and enforced by a second windowed pass —
  pySigma itself hard-rejects the syntax at the grammar level).
- Insider threat watchlist (track people under sustained watch, independent of score);
  fixed a real detection-cycle performance collapse (O(n·m) warninglist matching,
  unbounded batch window, unindexed alert dedup lookup); fixed case-reopen data loss.

## 2026-09-01

- Technical Maturity Roadmap **Phases 1–2**: cross-signal correlation (Related Items
  panel on cases, cross-rule escalation into an auto-case, UEBA priority score wired into
  tier badges); closing feedback loops (false-positive → exclusion suggestion, SLA-breach
  playbook trigger, MTTA + playbook success-rate metrics).
- Business Readiness Phase 1: forced password change on first login, a real login page
  (shared theme, responsive, label fixes), a global fetch-failure toast covering all 271
  `fetch()` call sites.
- SOAR starter playbook + creatable/editable custom webhook actions; selective SigmaHQ
  rule import (browse and pick individual rules instead of only whole-pack import).
- Unified Coverage nav item (MITRE ATT&CK + Compliance + Vulnerability, later + an
  Intelligence tab fusing threat entities with coverage tiers); an executive-narrative
  pass on the Security Summary report; raw log-volume evidence in the per-framework
  compliance report.
- Fixed a real O(872) linear scan in `mitre_attack.lookup()` that was causing
  `/api/mitre/coverage`'s 13–15s latency.

## 2026-08-31

- Stopped exposing the shared SOC secret to every logged-in user; closed 3 more read-route
  permission gaps found by a full-app audit.
- New EDR response actions: network connections, DNS/ARP, process-injection indicators,
  quarantine_file (contain, not just collect), registry key collection, scheduled-task
  removal, name/path-matching `kill_process_by_name`.
- A macOS agent (check-in, FIM, log ingestion, core response actions) — the third
  supported OS alongside Windows and Linux.
- Split MITRE Coverage into a broader Coverage % and a stricter, validated-only Detection
  Score; SOAR reorganized into tabs (4 phases); Case Templates with typed custom fields;
  a per-framework Compliance Report (rules + detections + hardening + fleet); real
  version-range vulnerability matching.
- Fixed `rare_process_population` flooding small fleets with meaningless noise; fixed
  priority-score decay saturating from stale volume instead of recency.

## 2026-08-30

- Detection Coverage: a 4-tier MITRE ATT&CK model (gap/inactive/active/validated),
  expanded `mitre_attack.py` from ~190 curated techniques to the full ATT&CK matrix, NIST
  800-53 control coverage derived from existing ATT&CK data, a live Compliance Framework
  Coverage dashboard widget.
- CVE database feed + real vulnerability detection (software inventory + CVE
  correlation); SCA-lite hardening checks; agent groups with group-scoped response-action
  dispatch.
- Threat Entities: entity-to-entity relationships, confidence/attribution fields, external
  references, a "last seen active" indicator. Detection Rules: edit Sigma-sourced rules
  in place with Revert to Default, a "SigmaHQ upstream updated" indicator.
- `CLAUDE.md` added, documenting architecture/deploy flow/conventions (this session's own
  operating manual).

## 2026-08-29

- Multi-dashboard system with a draggable/resizable widget grid, 5 more live-app widgets,
  a user-buildable Custom Chart widget.
- Replaced the flat analyst/admin split with a 3-tier SOC access model, then replaced
  *that* with dynamic named-permission roles (the RBAC model still in use today — a role
  is a set of permission keys, not a fixed rank ladder).
- SOAR approval gate + Run Now for gated actions; structured case IOCs; GeoIP resolved at
  alert-creation time, not just display time.

## 2026-08-28

- Sigma rule dry-run/backtest against real historical logs; a bulk "Validate Rules"
  health check for every enabled rule (then made it fast enough to actually use); per-case
  asset compromise tracking.

## 2026-08-27

- Per-case PDF report export; playbook dry-run/test mode; a case metrics/SLA dashboard;
  named secrets for playbook webhook/Slack actions (credentials never appear in playbook
  config directly).

## 2026-08-26

- Case queues; alert/UEBA-score-triggered auto-case creation (the 3-part
  alert-to-case-automation arc); lightweight SOAR playbooks; in-case host/user analysis.

## 2026-08-25

This was the single biggest day of the project — 8 numbered UEBA "batches" plus a Tier-1/
Tier-2/Tier-3 CTI (threat intel) gap-analysis pass, largely in parallel:

- **UEBA**: model confidence gating, rare-process population model, multi-signal
  convergence bonus, alert deduplication/grouping, asset/identity criticality weighting,
  a cyclical 24×7 off-hours histogram (replacing a binary day/night model), an
  Investigation Priority Rollup, and a Timeline tab (later merged with Anomaly
  Detections into one global filterable event stream — the same Timeline this session
  later extended with EDR commands as a 4th type).
- **Response actions**: a Persistence Sweep ("Autoruns-lite") with baseline diffing, a
  Live Forensic Triage action (with output-size caps added after a real overrun),
  lightweight FIM and auditd exec auditing.
- **Case management**: introduced from scratch — tasks, TLP/PAP marking, timeline,
  templates.
- **Threat intel**: MISP feed, warninglists (misp-warninglist-style suppression),
  sightings tracking, actor context, real STIX pattern parsing (replacing best-effort
  regex), hash/DNS IOC correlation wired into detections, cross-feed confidence merging,
  on-demand enrichment ("mini-Cortex"), DB-backed threat entities with manual
  relationship linking.
- **SIEM**: a real Log Search query language, saved searches, cursor-based pagination,
  MITRE ATT&CK coverage (technique extraction + tactic heatmap) — this tab's very first
  version, long before the later 4-tier Coverage rebuild.
- Also: hot/cold log tiering, a server-configurable FIM check interval, an on-demand
  artifact-preset library.

## 2026-08-24

- Raw-XML capture, custom channels, event-ID filters (removed message truncation); TCP as
  an opt-in syslog transport; a column picker on Log Search results; 15 starter UEBA
  anomaly rules seeded by default.

## 2026-08-23

- Reporting/dashboards, built in 3 phases: report history + PDF branding, a Dashboards tab
  with 6 analytics widgets, configurable per-report-type scheduling.
- A light/dark theme toggle (defaulting to dark) — and the contrast bugs that followed
  from every place white text or `btn-outline-light` had been hardcoded.
- Multi-condition (AND/OR) anomaly rules with starts_with/ends_with operators.

## 2026-08-22

- IOC hash sweep (proactive endpoint scanning against threat intel) and a lightweight
  String Sweep, both surfaced on a redesigned YARA Scanning tab; MD5/SHA1 matching added
  alongside SHA256.
- YARAify added as an auto-syncing YARA rule feed (with real bugs found and fixed live:
  wrong URL, the bulk endpoint needing no auth despite every other YARAify endpoint
  requiring one).
- Composite point-based UEBA risk scoring, a Data Insights tab (per-entity/per-model
  histograms), an Anomaly Rules page generalizing the sensitive-action scoring into a
  real rule engine, GeoIP country lookup, configurable log retention.

## 2026-08-21

The second-biggest day — the app's core shape mostly solidified here:

- Fixed the Sigma detection engine to actually match anything (it never had); rotated
  hardcoded secrets and added CSRF protection.
- A guided fact-based rule builder; Sigma/Custom rule provenance, cloning, edit history;
  Detection Tuning (exclusions, severity overrides, noise stats) split into its own page.
- Unified Log Search across raw logs, rule alerts, and UEBA anomalies for the first time
  (the same unified query this session later extended with EDR commands).
- A real EDR response console (verified actions, a CLIXML output-leak fix, remote
  upgrade), a Linux agent alongside the original Windows one, TLS verification and
  shared-token spoofing fixes.
- More threat intel feeds with API-key auth and auto-sync intervals; per-column IOC
  filters; IOC-match conditions in the rule builder.
- UI: collapsible sidebar, consolidated tabbed pages (UEBA + Threat Intel, then SIEM's 5
  sub-tabs), a redesigned Agents page.

## 2026-08-20

- Removed an earlier Velociraptor integration and fixed critical auth/data bugs it had
  introduced; a full dark-theme UI redesign; a real Sigma rule editor; UEBA detection
  tuning; Threat Intelligence with configurable IOC feeds; a lightweight EDR
  response-action system — most of these subsystems' very first versions.

## 2026-08-18 – 2026-08-19

Project start. Initial SOAR/Velociraptor integration attempt (later removed), the
install/update script, the base Flask app layout, sidebar navigation, settings UI, and
the first YARA/Sigma rule handling.
