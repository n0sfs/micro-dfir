# Changelog

A dated, narrative record of what's been built and why — kept because memory notes and
plan files are ephemeral, but this file lives in the repo and travels with the code.

**Convention**: add an entry here for anything a future reader would want to know about —
a new feature, a real architectural decision, an incident and its fix. Routine polish/typo
fixes don't need their own line; group them into the feature they support. Newest first.
Full commit-level detail is always available via `git log`.

## 2026-09-06

### Fixed the two review findings flagged for judgment

Closed out the two items the third review pass surfaced but didn't auto-fix:

- **Channel-template GET routes now require `edr.agent.manage`** (`src/app.py`,
  `/api/agent/channels` and `/api/agent/linux-channels`) — previously gated on
  POST/DELETE only, leaving GET readable by any authenticated user despite the label on
  this exact permission being "Manage agents (upgrade/uninstall/enroll/channels)" and
  `edr.agent.manage` being a Tier 3+/Admin-only permission, not granted to the base
  Tier 1/2 analyst role. Also hid the Windows/Linux Log Channels tabs in Log Pipeline
  behind the same permission (`{% if has_permission(...) %}`, matching the existing SOAR
  Automation tab precedent) rather than leaving a now-broken-looking tab visible, and
  hardened `switchLogPipelineTab()` with the same missing-element fallback
  `switchSoarTab()` already uses, so a hidden tab can't throw when the shared
  `LOG_PIPELINE_TABS` list still names it.
- **Silent-host detection no longer collapses every hostless log source into one shared
  "UNKNOWN" bucket** (`_run_due_log_source_silent_alerts`) — a source that never reports
  its own hostname (a raw syslog sender, a misconfigured device) previously landed in a
  single group that never looked silent as long as *any* such source kept sending,
  masking a real individual outage among them. Now sub-groups by `app` for that one
  fallback value only; real hostnames are unaffected and still group purely by host.

Verified with 25 new fixture/vm tests (permission-check ordering, tab-fallback
behavior, and three UNKNOWN-host grouping/cooldown scenarios) plus the full existing
regression suite (89 tests total across today's work), all passing.

### Third code review pass — 6 fixes from reviewing today's own sweeps

Ran the same 8-angle review process against everything shipped today since the second
review pass (the YARA/channel-template/macOS fixes, the Silent Host rework, and the two
sweeps). Caught a second instance of the exact widget-recovery regression fixed earlier
today (`loadCaseStatsInto` in Dashboards' Case Metrics widget was replacing its whole
container on failure, destroying the SLA-edit controls) — same root cause, same fix
pattern, missed by manual review the first time because it's called from three sites,
not obviously all vulnerable to a naive glance. Also fixed: a colspan mismatch on the
Detection Rules table's new error row (12 vs. the table's real 11 columns); the one
loader in the Silent Hosts sweep that got missed (`loadSilentSourceAlerts` had no `r.ok`
check); a subtle edge case where a network blip during the YARA tag-sync fix's own
refetch could let the Tag filter dropdown rebuild itself from stale row data; a missing
null-guard in Coverage's history-load error handler; and extracted Dashboards' 20
inline-duplicated widget-failure messages into one shared `renderWidgetLoadError()`
helper (restoring the "Reload" retry link every sibling template's equivalent helper
already had). Two findings flagged but not auto-fixed, left for the user's judgment: a
pre-existing (not introduced today) missing permission gate on the Windows/Linux channel
GET routes — the Log Pipeline UI itself has no client-side view-gating on these tabs
either, so this may be an intentional "read is open, write is gated" design rather than
an oversight; and an edge case where multiple hostless log sources collapse into one
shared "UNKNOWN" bucket for silent-host detection, carried forward from an analogous
pre-existing weakness in the old per-app grouping. Verified via Jinja + `node --check`
on every touched file, 10 new/updated frontend tests, and a direct script confirming the
colspan fix against the table's real header count.

### Accessibility sweep: label/`for=` associations across every static form

The last deferred item from the Business Readiness pass: ~190 `<label>` elements across
the app had no programmatic association with their form control (missing `for=`), a real
WCAG gap and screen-reader usability issue — only the login page got this fix at the time.
Swept the remaining 9 templates (`agents.html`, `cases.html`, `dashboard.html`,
`dashboards.html`, `log_pipeline.html`, `settings.html`, `soar.html`,
`threat_intel.html`, `ueba.html`; `change_password.html` was already fully covered), 158
labels fixed total. Every fix reused a control's already-existing `id` (this app's JS is
full of `getElementById` calls, so nearly every control already had one) — a small number
of genuinely id-less controls (Settings' Network IP/port fields, report-schedule
selects, the branding logo file input) got a new id, each verified unique before use.
Deliberately left alone: labels nested around their control (already valid, no `for=`
needed), labels with no single associated control (section headings over checkbox groups
or dynamic lists), and labels inside JS template literals (dynamically-stamped rows,
often already using a per-instance dynamic id scheme of their own). Verified via Jinja +
`node --check` on every touched file and a repo-wide scan confirming zero duplicate `id=`
attributes were introduced — a real risk given how much of this app's JS resolves
elements by id.

### Loading-state sweep: the rest of the "stuck on Loading forever" fetch sites

From the earlier Business Readiness pass: only 5 representative `fetch()` call sites got
a real "failed to load, click to retry" treatment at the time; the other ~65+ sites
across every remaining template were deliberately deferred as a follow-up sweep. Did
that sweep now, file by file (`agents.html`, `cases.html`, `coverage.html`,
`dashboard.html`, `dashboards.html`, `log_pipeline.html`, `settings.html`, `soar.html`,
`threat_intel.html`, `ueba.html`) — every loader that populates a visible table/widget
now gets a `res.ok` check and an explicit, retriable failure message (a `renderLoadError`
table row or an equivalent widget-level failure `<div>`) instead of either an unhandled
rejection or a silent `console.error` that leaves "Loading…" on screen forever. A few
real, previously-uncaught bugs turned up along the way: `loadUniqueEndpoints()` (Agents
page fleet table) and `ld()` (Detection Rules table) had **no error handling at all** —
a failure there threw unhandled and left the table permanently blank/stuck; `loadExclusions()`
(Tune modal) could silently leave a *different* rule's stale exclusions displayed as if
they belonged to whichever rule's modal was currently open. Caught and fixed one
regression the sweep itself introduced during review: `renderVulnerabilitySummaryWidget`
(Dashboards) re-polls every 60s, but its first-draft failure handler replaced the whole
widget container — destroying the `canvas`/list/note elements a later successful poll's
closure still referenced, which would have left the widget stuck on the error message
forever even after the API recovered. Fixed to write into the already-captured
sub-elements instead, matching the other three auto-refreshing widgets' (already-correct)
pattern. Verified via compile checks (Jinja + `node --check`) on every touched file plus
targeted regression tests for the widget-recovery fix and colspan correctness.

### Silent Log Source alert reworked to per-host (was per-app)

The Log Pipeline > Silent Hosts tab (built earlier this session as "Silent Log Sources")
alerted per individual log channel — a single host going dark (agent crash, network
drop, ingestion break) fired several redundant "silent" alerts at once (Sysmon,
Security, PowerShell, ...) for one real incident, and none of them said which endpoint
was actually the problem. Reworked to group by `live_logs.host` instead of `app`: the
baseline/threshold is still computed adaptively from each host's own combined recent
history (across every log source it sends), but now produces one alert per host, with
a real `alerts.host` value set (not just mentioned in the message text) so it
participates in host-scoped features (Related Items, Agents page, etc.) like every
other host-keyed alert. Renamed the alert to "Host Silent" (the fired-alert history
route still matches the old "Log Source Silent" name too, so pre-rework alerts stay
visible). Added a `host` column to `log_source_silent_alerts` (cooldown is now
per-host) and to the tab's fired-alerts table. Verified with 10 new fixture tests
(including a same-host-multiple-sources case proving one alert fires, not three, and
an independent-hosts case proving a chatty host and a quiet host each get their own
correctly-scoped threshold) and 6 frontend vm-context tests.

### Deferred round-2 review items + macOS remote-upgrade bug

Closed out the two items deliberately deferred from the second review pass, plus a
third small real bug spotted during Phase 4 research and flagged for later:

- **YARA tag UI desync** (`templates/threat_intel.html`): adding/removing a manual tag
  via the rule viewer only ever refreshed the viewer panel — the rule-list row's inline
  tag badges, its `data-tags`/`data-search` attributes (used by the Tag filter), and the
  Tag filter dropdown's own option list all stayed stale until a full page reload. Added
  `syncYaraRuleRowDisplay()` (always runs after any rule-content fetch, keeps one row's
  badges/attributes current) and `syncYaraTagFilterDropdown()` (runs after an actual
  add/remove, rebuilds the dropdown from what's really tagged across the rendered list —
  adds a brand-new tag, drops one nothing uses anymore).
- **Windows/Linux channel-template duplication** (`src/app.py`): the per-group
  JSON-file storage pattern (read file, treat a legacy flat dict as `'__default__'`,
  normalize each group, persist only if an existing file actually changed) plus the
  group-key-resolution/reserved-name-rejection and GET/DELETE route logic were
  hand-duplicated between the Windows Event Log channel routes and the Linux auditd
  channel routes. Extracted into shared `_load_grouped_channel_config()`,
  `_resolve_channel_group_key()`, `_channel_group_get_response()`, and
  `_delete_channel_group()` — the genuinely different per-channel value shapes (Windows:
  rich enabled/capture_xml/filter_mode dict; Linux: plain on/off) stay in each side's own
  normalize function, only the plumbing around them is shared now. Behavior-preserving:
  verified via 21 fixture tests porting the exact old vs. new logic side by side.
- **Remote agent upgrade silently sent Windows source to macOS hosts** (`src/app.py`,
  `agent_config()`): the `agent_filename` picker only branched on `'linux'` vs.
  everything-else, even though `agent_os` can genuinely be `'macos'` (a real, reported
  value going back to when OS-detail reporting shipped). A macOS host clicking "upgrade"
  would have received `micro_agent_windows.py`. Fixed to map all three OSes explicitly.

### Second code review pass — the first half of 2026-09-05's work, 15 fixes

Ran the same 10-angle + sweep review process against the half of yesterday's commits
the prior review pass hadn't covered yet (Vector ingest-sink fix, Log Pipeline's move
out of SIEM and split into sub-tabs, YARA rule tagging, nightly DB backup/restore, 4
settings blocks relocated out of Settings, MITRE Coverage fixes, per-agent-group
Windows Log Channel templates). Verified every candidate directly against source,
including a real functional test of the fixed `restore_db.sh` against mocked
`systemctl`/`sqlite3` (three scenarios: an invalid backup file rejected before touching
anything, a corrupted restore rolling back to the pre-restore copy while still
restarting services, and a clean successful restore). Fixed 15 findings:

- `reconcile_linux_audit_channels()` (`micro_agent_linux.py`) called `augenrules --load`
  without checking its exit code -- a rejected rule file (bad syntax, permission error)
  exited non-zero but raised nothing, so the reconcile silently marked itself successful
  and never retried. Added `check=True` so a real failure is now caught, logged, and
  retried on the next poll instead of vanishing.
- `agent_config()`'s new per-group channel lookup had no `ORDER BY`/non-empty filter on
  `agent_tokens`, unlike the Agents-page listing that already documents and handles the
  "stale leftover row from re-enrollment" hazard -- could silently resolve the wrong
  group (and wrong channel template) for a re-enrolled host.
- A Linux/Windows agent group literally named `__default__` or `custom_channels`
  silently aliased onto (and could corrupt) the real fleet-wide default/custom-channel
  catalog -- rejected at the one place group names actually get set
  (`/api/agent/<hostname>/group`), plus a defensive re-check at both channel routes.
- `get_linux_channels_all()` was missing the `file_existed` guard its Windows
  counterpart has, writing `agent_linux_channels.json` to disk on every single GET
  (even a fresh install's very first one) instead of only when something changed.
- Settings > Network's `ingest_bind_ip`/`ui_bind_ip`/port fields used
  `request.form.get(key, default)`, which only falls back on a genuinely *absent* field
  -- clearing the text box and saving stored `''`, which broke Vector's ingest sink URI
  (`https://:{port}/...`). Switched to `.get(key) or default` for all four fields.
- `sigma_engine.py`'s internal scheduled-playbooks poll still hardcoded
  `127.0.0.1:5001` -- the exact sibling bug the Vector ingest-sink fix addressed for
  `ingest_bind_ip`, left unfixed for `ui_bind_ip`. Now resolves both from settings the
  same way.
- The 4 settings blocks relocated out of Settings earlier (Alert Escalation, Case
  Stale Nudge, Agent Offline Alert, Log Source Silent Alert) lost the page-level
  permission gate their old home always had -- visible read-only to any authenticated
  user. Re-gated each at the block/pane level (not just the inputs), matching the
  still-gated Case Templates tab precedent; added a matching JS guard so the settings
  fetch itself doesn't fire for a non-admin either.
- `restore_db.sh`: the `PRAGMA integrity_check` result was printed but never enforced: a
  corrupted restore proceeded as if it succeeded. Now checks the result, automatically
  rolls back to the pre-restore copy on failure, and adds a `trap` so services restart
  on ANY exit path (not just success) plus a `gzip -t` check on the backup file before
  touching anything.
- `backup_db.py`: a compression failure left the full uncompressed VACUUM snapshot
  (multiple GB) behind forever (the retention loop only ever matches `.db.gz`). Wrapped
  in `try/finally`. Also wired up the `retention_override` parameter for real -- its own
  comment already claimed "Backup Now" passed the unsaved retention field, but neither
  the route nor the JS ever actually sent it.
- The MITRE Coverage alert deep-link force-checked the Advanced Query box but never
  called the visibility-update function, so the query box stayed hidden (Basic Filter
  shown instead, with no query visible) for anyone whose saved search-mode preference
  was Basic.
- A YARA tag containing a comma broke the Tag filter dropdown (tags are comma-joined/
  split with no escaping) -- rejected at the point of entry instead.
- Log Pipeline wrote its active sub-tab to `localStorage` on every switch but never
  read it back, unlike every other tabbed page in the app -- always reset to Drop Rules
  on a fresh visit.
- Two stale strings: SIEM's subtitle still said "manage ingestion pipelines" after Log
  Pipeline moved out to its own page; a JS comment said "3 panes" when there are 5.

Left two lower-confidence/larger-scope items unfixed and documented rather than rushed:
YARA tag add/remove not refreshing the rule-list row or Tag filter dropdown until a full
reload (real, but a moderate frontend change); and the substantial backend+frontend code
duplication between the Windows and Linux per-group channel-template features (the
*reason* the `file_existed`-guard divergence above happened) -- a genuine refactor
opportunity, not a quick fix, and risky to rush inside a review-driven fix pass. 35 new
tests added, all against the real fixed source.

## 2026-09-05

### Log Pipeline: move Log Source Silent Alert into its own tab, list real fired alerts

The "Log Source Silent Alert" settings card lived inside the Drop Rules tab, and had no
way to see whether it had actually fired for any log source short of digging through the
general Alerts view. Moved it into a new "Silent Log Sources" tab and added a real fired-
alert history at the bottom (`GET /api/log-pipeline/silent-source-alerts`, scoped to
`rule_name = 'Log Source Silent'` rather than reusing the general alerts list, which
defaults to the 30 most recent alerts of any type and could silently push these out of
view on a busy instance) -- most recent first, with occurrence count and
acknowledged/status shown per row.

### Multi-angle code review of this session's work — 12 fixes, 2 of them live production bugs

Ran a 10-angle + sweep-pass review over everything shipped this session (`git diff` since
session start), then personally verified every candidate against the live source (plus one
live production test that disproved a well-reasoned but incorrect finding about URLhaus
feed sync). Fixed all 12 confirmed findings:

- **Two were live, active production bugs** at review time: a custom Linux channel whose
  slugified label collided at exactly 40 characters made the id-uniquifying loop
  regenerate the same string forever, hanging the Flask worker (any two channels with the
  same 40+ char label, or a double-submit, triggered it); and the Sysmon config-hash
  compare stored the agent's own *full* 64-char hash against the server's *truncated*
  16-char one, so they could never match — every enrolled Windows endpoint re-downloaded
  and reloaded its Sysmon config on every single poll (~8s) since that feature shipped
  earlier this session, not only when the config actually changed.
- A Linux agent group literally named `custom_channels` (the exact label of that feature's
  own UI section) silently corrupted or wiped the fleet-wide custom-channel catalog and
  could 500 `agent_config()` for every other group with a now-corrupted channel enabled —
  fixed with an explicit reserved-key guard, not a schema change.
- Two new GET routes (`/api/settings/sysmon-config`, `/api/agent/linux-channels/custom`)
  shipped with only `@login_required`, letting any authenticated user of any role read
  fleet-wide Sysmon config / custom auditd definitions their write counterparts already
  gated behind `edr.agent.manage` — added the matching permission check to both.
- The aggregated enrichment verdict badge (added earlier this session) excluded Shodan
  InternetDB's legitimate `'info'` verdict from its rank table, so a real "open ports, no
  CVEs" finding displayed as "Unknown" instead — added `'info'` to the rank table.
- The new custom-channel path/id validators used `$` instead of `\Z`, so a value ending in
  one trailing newline bypassed validation built specifically to block rule-injection into
  the auditd rules file.
- The Timeline `?host=` deep-link (added earlier this session) fired two racing fetches on
  first load — one unfiltered (before the host param was applied), one filtered — with no
  ordering guard; reordered the init so the filter is set before either fetch fires, and
  switched the three link-emission sites to the query DSL's `host:` field syntax instead of
  a bare hostname, narrowing a 5-column substring search down to one precise field.
- The curated Security channel's Event ID filter advertised 4698/4702 (scheduled task
  created/updated) without the "Other Object Access Events" audit subcategory that
  actually generates them — added it to the enabled-subcategory list.
- A stale "Checking external sources..." message on the IOC catalog's enrich button was
  never cleared (it wrote into the wrong element); an inconsistent escaping gap on a case
  Indicator's onclick handler; and duplicated custom-channel validation logic between the
  create/update routes, refactored into one shared helper matching this codebase's
  existing `_validate_X()` convention.

Left two lower-confidence findings unfixed and documented: whether `/api/settings/
enrichment`'s audit-log entry should be unconditional or only-on-change is a judgment
call, not a clear regression; and detecting live Windows Advanced Audit Policy drift
against a domain GPO refresh would need a new live-policy-read capability, out of scope
for a review-driven fix pass. 37 new fixture/vm-context tests added, all against the real
fixed source (not reimplementations). `CLAUDE.md` gained 4 new lessons from this review:
permission-gate parity as a required check, the reserved-key/free-text-namespace
collision pattern, Python's `$`-before-trailing-newline regex gotcha, and hash-truncation
consistency across the server/agent boundary.

### EDR: fix collect_file truncation bug, add Linux live forensics, deep-link into the UEBA Timeline

Research comparing against Heimdall-DFIR (a real, active offline-artifact/timeline DFIR
tool) found Micro DFIR's EDR agents already cover most of that ground -- the real,
narrowly-scoped gaps were: (1) a genuine bug where `collect_file`'s advertised 4MB limit
produces base64 output that blows straight through the server's 60,000-char stdout
truncation (`api_agent_result`), silently corrupting the JSON mid-string for anything
over ~44KB raw -- fixed by lowering the real, honest limit to 40KB on all three platforms
(Windows/Linux/macOS), verified by executing the actual generated collector code against
real temp files at the boundary; (2) Linux had no `collect_live_forensics` action at all
(Windows-only) -- added a Linux equivalent covering the genuinely-missing pieces (recent
USB/removable-media kernel events via journalctl with a dmesg fallback, recent
auth activity, a general recent-file-changes scan, a current-mounts snapshot), without
duplicating shell history/authorized_keys/known_hosts already covered by
Collect-SSH-Artifacts; (3) the existing UEBA Timeline (already a real unified per-host
chronological view merging anomalies/alerts/EDR results/logs -- not purely UEBA-scoped
as assumed) had no entry point from Agents or Cases, so an analyst had to manually type
a hostname into it -- added `?host=` deep-link support plus "View Timeline" links from
the Agents context menu, the Host Detail modal, and each Case Asset row. Explicitly not
pursued: Plaso-style super-timelines or Volatility memory-forensics integration -- both
would be shallow, infrastructure-incompatible imitations of Heimdall's much heavier
stack (distributed job queue, object storage) rather than real capability gains on a
single-box Flask+SQLite appliance.

### Aggregated enrichment verdict badge + external check on the IOC catalog table

Closed out the remaining IntelOwl-inspired ideas from the enrichment work above. Added
an `overall_verdict` (worst-case-wins across every source that returned a real signal,
excluding unconfigured/error sources so a badly-configured analyzer can't quietly read
as "clean") to `/api/ti/enrich`'s response, shown as one summary badge above the
per-source breakdown in both the case Indicators check and Quick IOC Lookup. Also
extended the Threat Intel IOC catalog table with its own "Check External Sources"
button per row (reusing Quick IOC Lookup's existing enrich machinery rather than adding
a second results area) and fixed a real gap this surfaced: Quick IOC Lookup's own
Enrich button only ever appeared for IP-shaped values (a leftover from before
VirusTotal/URLhaus added hash/domain/url coverage) -- it now recognizes all four shapes
client-side. (Cross-case IOC correlation, the other item on the IntelOwl list, turned
out to already exist via the Related Cases card built earlier this session -- no new
work needed there.)

### Add VirusTotal + URLhaus enrichment analyzers, wire external lookup into case Indicators

Research into IntelOwl surfaced a live outbound IOC enrichment mechanism this app
already had (`/api/ti/enrich`, `analyzers.py`'s `ANALYZERS` registry, 24h-TTL cached
results) but that was scoped to IP-only (Shodan InternetDB, AbuseIPDB) and reachable
only from a standalone "Quick IOC Lookup" tool on the Threat Intel page — an analyst
investigating a hash/domain/URL already sitting in a case's Indicators list had no way
to check it externally without re-typing the value elsewhere. Added two more analyzers
(VirusTotal, keyed, covering ip/hash/domain/url; URLhaus, covering domain/url —
live-caught during testing that abuse.ch now requires a free Auth-Key for every
URLhaus call, not the fully keyless access its docs implied when this was scoped),
generalized `applicable_analyzers()`'s dispatch and the `/api/settings/enrichment`
key-storage route (previously hardcoded to one key) to support more than one keyed
analyzer, and added a "Check External Sources" button directly on each case Indicator
row (next to the existing local Threat-Intel-set check) that calls the same
`/api/ti/enrich` endpoint the Quick Lookup tool already uses — no new backend
mechanism, just wider analyzer coverage and a second UI call site.

### Add 12 custom Sigma rules for the new Linux Log Channels

Community SigmaHQ auditd rules were confirmed (via direct research against pySigma's
field-mapping code) to silently degrade to dead `message LIKE` clauses against this
app's schema rather than erroring, so they wouldn't reliably detect anything if
imported as-is. Instead, wrote 12 rules by hand — one per new Linux Log Channel plus two
process-execution content rules (reverse-shell one-liners, base64-encoded command
execution) — using the `category: custom, product: custom` pattern this app's own
field-mapped fields already support, each keyed to the new `[channel=<key>]` message tag
added in the prior entry below. Each carries an honest `status: experimental` (none have
fired against real production traffic yet — no monitored Linux endpoint in this fleet
today) and a MITRE ATT&CK tag; 13 of 14 tags correctly surface on the Coverage page as
"active" (the 14th, T1070.002, isn't in this app's own curated technique table — a
pre-existing curation gap, not a rule defect). All 12 compiled and executed cleanly
against production's real pySigma pipeline via Validate Selected (0 matches, as
expected with no Linux endpoint currently reporting).

### Push Windows Advanced Audit Policy, fix Sysmon config reload, curate Security defaults

Windows had the exact gap just closed for Linux auditd: turning on the Security
channel's Event ID filter is meaningless for several high-value events (4688 with
command line, account/group management, Kerberos/NTLM auth) unless the endpoint's own
Advanced Audit Policy has the matching subcategory enabled — confirmed zero `auditpol`
usage existed anywhere. `reconcile_windows_audit_policy()` now pushes the standard
CIS/NSA-aligned subcategory set plus the process-creation-command-line and PowerShell-
script-block-logging registry keys, tied directly to whether the Security/PowerShell
channels are enabled — symmetric, so disabling a channel unwinds its policy too.
Deliberately targets Advanced Audit Policy only, never Basic (Microsoft's own guidance:
mixing the two via policy causes "unexpected results").

Also fixed a real, separate bug: `_ensure_sysmon_installed()` only ever applied
`sysmon_config.xml` on a host's *first* install — editing the config afterward silently
never reached an already-enrolled endpoint. `agent_config()` now sends a content hash;
the agent reloads live via Sysmon's own `-c` flag whenever it changes. New "Sysmon
Configuration (Advanced)" section in Log Pipeline lets an admin view/edit the raw XML
directly, stored as an override file outside the git tree so it survives future deploys.

Security channel's default Event ID filter is now a curated ~28-ID baseline instead of
collecting every Security event unfiltered — scoped to fresh installs/new channels
only; confirmed live that production's existing saved template was left untouched.
The Sysmon editor also gained an "Import Config" file picker (loads a `.xml` file into
the textarea client-side for review before saving — e.g. starting from a downloaded
SwiftOnSecurity or Olaf Hartong config) and an always-available "Revert to Default"
button (previously hidden unless a custom override already existed).

Separately: every Linux channel audit event now carries a `[channel=<key>]` tag in its
message. `event_id` alone can't tell channels apart — several are pure `-w` watch rules
and all land on `event_id='file_watch'` (identity_changes, ssh_config_changes,
cron_changes, pam_changes, login_session_tamper, and even file_deletion's unlink/rename
syscalls, which carry a PATH record) — so this is what makes it possible to write a
Sigma rule (or anything else) that reliably targets one specific channel's events
instead of guessing from watched-path text alone.

### Expand Linux Log Channels to 11 CIS/STIG-aligned channels + custom channels

Grew the curated auditd catalog from 2 to 11 channels, researched against current
CIS Benchmark/NSA auditd baseline guidance: file deletion, privilege escalation
(setuid/setgid), kernel module load/unload, system time tampering, SSH/PAM/cron
config changes, network config changes, and login-record tampering, alongside the
existing process execution and identity file changes.

Also adds admin-defined custom channels — a label + path + which accesses
(read/write/execute/attribute-change) to watch, defined once and enabled per group
exactly like a built-in channel. Required a real refactor: the server now resolves
every enabled channel's full rule text (fixed or custom) and sends it directly to
the agent on each poll, so `micro_agent_linux.py` carries no local channel catalog
of its own anymore — a custom channel needs zero agent-side code to work. Custom
channel paths are validated against a strict single-line, no-whitespace charset
before being written into the generated rules file, closing off a rule-injection
route a raw multi-line path value could otherwise open — confirmed live against
production (`\n-a always,exit ... -k pwned` correctly rejected with a 400). Full
add/edit/delete lifecycle live-verified against production, including confirming a
deleted custom channel's enable-state is cleaned out of every group with no stale
leftover key.

### Add Linux Log Channels: per-group auditd policy that actually pushes and pulls

New Log Pipeline tab mirroring Windows Log Channels' per-group shape, but built for how
Linux logging actually works: journald already captures almost everything unfiltered
(kept unconditional, no regression to existing hosts), so the real gap is process-
execution and sensitive-file-change visibility, neither of which the kernel surfaces at
all without auditd rules loaded. Two curated, opt-in-by-default channels — Process
Execution, User/Group/Sudoers File Changes. Enabling one both pushes the required
auditd rule onto the endpoint and pulls its own tagged `ausearch` log stream, mirroring
per-group resolution exactly like Windows Log Channels (own override, or inherit a
`__default__` template) but stored in a fully separate file so it carries zero risk to
that already-working migration. A real bug was caught and fixed before deploy: the
audit-record parser initially mislabeled a file-watch hit as a process-execution event
whenever its `type=SYSCALL` line happened to carry an `exe=` field (which nearly every
audit record does, regardless of syscall) — fixed to key off an actual `type=EXECVE`
record instead, caught by a real parser fixture test before this ever reached
production. Live-verified full isolation against the real "Test" group.

### Add per-agent-group Windows Log Channel templates

Previously one global channel template applied to every Windows agent fleet-wide —
no way to give Servers a different collection profile than Workstations/Laptops.
`agent_config.json`'s shape now nests per-group templates under the existing
free-text `agent_tokens.group_name` (admin-assigned per host on the EDR Agents page),
falling back to a `__default__` template for any host whose group has no override —
migrated non-destructively from every existing single-template file (verified live:
production's real single template came through byte-identical after migration). The
Log Pipeline Channels tab gets a group selector, shows whether the selected group has
its own override or is inheriting the default, and can remove an override to revert
a group to the default. Live-verified full isolation against production's real "Test"
group (the one real group in use, assigned to `DESKTOP-C3LBEGL`): saving an override
changed only that group's template, left the default and other groups untouched, and
removing it cleanly reverted to inheritance — cleaned up afterward, no leftover
override left in the file.

### Move the light/dark theme toggle into the sidebar

It was a fixed top-right floating button that overlapped page content on some panels.
Now a normal sidebar nav-link right below Settings, matching every other nav item.

### MITRE Coverage: enabled-first rule sort, collapsible disabled rules, alert links

Technique drilldown modal now lists enabled rules first, collapsing disabled ones into
a `<details>` section — a technique with dozens of rules no longer buries the handful
that can actually fire under a long scroll of disabled ones. Fixed a real, previously-
silent bug found in the same pass: the 25-rule-per-technique cap was applied in
insertion order during accumulation, so a technique with many disabled rules could
crowd an enabled rule out of the kept set before any sorting ever happened. The cap now
applies after sorting.

The Validated tier popup (click the "Validated" chip on the MITRE tab) now shows last
seen + a "View Alert" link per technique, deep-linking into Log Search scoped to that
exact alert. Required a new `item_id:` exact-match field-scoped query (Log Search's
existing `field:value` syntax only ever did substring `LIKE`, which would have made
`item_id:5` also match 15/25/51). Two real bugs caught live during verification and
fixed same-session: the unified log/alert/anomaly view's id column is actually named
`item_id`, not `id` (first attempt hit a real `no such column` SQL error), and the
deep link's query was silently ignored the first time because Advanced Query mode can
be toggled off by a saved preference — fixed by forcing it on for this one code path.

### Move 4 settings blocks out of Settings into their own contextual pages

Agent Offline Alert → EDR Agents page (fleet-health config, not a general system
setting). Log Source Silent Alert → Log Pipeline's Drop Rules tab (pipeline health
monitoring). Alert Escalation + Case Stale Nudge → SOAR, new "Automation" tab (both
create/annotate cases or fire a playbook trigger event — genuinely SOAR concerns).
Same backend routes/permissions throughout; only the UI moved, following the exact
precedent already set when Notification Channels moved from Settings into SOAR.

### Add nightly database backup scheduling + a documented restore script

Directly motivated by the `siem.db` corruption incident earlier the same day, which had
no backup to recover from. `src/backup_db.py` takes a nightly (2 AM) consistent snapshot
via SQLite's own `VACUUM INTO` — safe against a live, actively-written database, unlike a
plain file copy (the likeliest suspect for that corruption) — gzips it, and rotates old
backups past a configurable retention window (default 7 days). Wired into `update.sh`'s
existing cron-scheduling pattern; surfaced in Settings > System with a manual "Backup Now"
button. Restore is deliberately a manual, documented script (`restore_db.sh`, repo root)
run via SSH with real sudo — not a UI button or part of `update.sh`'s passwordless scope —
since it stops services and swaps the live database file, which should stay a confirmed,
human-run step.

**Real production tuning during live-verification**: the default gzip compression level
(6) took over 20 minutes against this appliance's actual ~8.3GB database — long enough to
fail the "Backup Now" button's request and risk overlapping the next scheduled maintenance
job. Switched to `compresslevel=1`: a real backup of the full production database
completed in ~5 minutes, 662MB compressed. Disk space was never the real constraint here
(hundreds of GB free) — a job that reliably finishes was.

### Add YARA rule tagging (auto-derived + manual) to File Scan

Derives real filter tags from each rule's own content, following the yarGen/Neo23x0
community convention (reference: github.com/Neo23x0/yarGen-Go) instead of inventing a new
taxonomy: underscore-segmented rule names (`MAL_APT_Loader_WIN_...` → Category/Intent/
Type/OS/Arch/Tech/Modifier tags), real YARA `rule X : tag1 tag2 {` syntax, and known
actor/malware-family names (reusing `threat_actors.ACTORS`, the same curated list Threat
Intel entity matching already uses) found in a rule's name or description. Admins can
also add/remove manual tags per rule (`yara_rule_tags` table). A new Tag filter in File
Scan combines with the existing Source/Category filters. Live-verified against the real
signature-base corpus (748 rules): 104 distinct tags derived with no code changes needed,
including several genuine YARA `tags:` values (e.g. `cve_2021_27065`) the taxonomy/actor
list never anticipated.

### Move Log Pipeline out of SIEM into its own top-level nav page

Drop rules, DNS query logging, and Windows log channel config used to live as a SIEM
sub-tab; moved to `/log-pipeline`, a standalone page in the sidebar positioned just above
SIEM. Old `/siem?tab=pipeline` bookmarks redirect cleanly instead of rendering a dead tab.
The 3 cards were then split into their own sub-tabs (Drop Rules / DNS Query Logging /
Windows Log Channels) so more Log Pipeline tabs can be added later without the page
becoming an ever-growing scroll.

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
