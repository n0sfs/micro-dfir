# Changelog

A dated, narrative record of what's been built and why — kept because memory notes and
plan files are ephemeral, but this file lives in the repo and travels with the code.

**Convention**: add an entry here for anything a future reader would want to know about —
a new feature, a real architectural decision, an incident and its fix. Routine polish/typo
fixes don't need their own line; group them into the feature they support. Newest first.
Full commit-level detail is always available via `git log`.

## 2026-09-11

### Export Cases to CSV

Third item from the same Exabeam-docs review: Case Manager's "export a filtered incident
list to CSV for auditing/external sharing" had no equivalent here — the only case export
was a single-case PDF report, nothing for the list view.

- New "Export CSV" button on the Cases list, next to the All/Open/Closed filter. Pure
  client-side (the case list is already fully loaded and filtered in the browser, no new
  route needed) — downloads exactly the rows currently on screen, honoring every active
  filter (status, queue, My queues only, and the column filters on severity/TLP/assignee).
  `getFilteredCases()` is now the one shared filtering implementation both the table and
  the export use, so the two can't silently drift apart.
- Standard RFC 4180 CSV (comma-separated, `\r\n` line endings, fields quoted only when
  they contain a comma/quote/newline) — Case Number, ID, Title, Severity, Status, Queue,
  TLP, Assignee, Items, Tasks Done, Tasks Total, Created At.

### SOAR "New from Template" playbook gallery

Direct request: reviewed Exabeam's Case Manager and Incident Responder docs
(docs.exabeam.com) for ideas worth borrowing. Most of what those pages describe is
already matched or exceeded here (entities/artifacts ~ case assets/IOCs, incident types
~ case templates with custom fields, phases ~ workflow_state, workbench ~ EDR Response
tab + case timeline, KPI dashboards/watchlists ~ existing dashboards/UEBA watchlisting).
The one genuine, concretely buildable gap: Incident Responder ships 16 out-of-box
"turnkey" playbook templates so a new admin isn't starting from a blank canvas — this
app's SOAR had no equivalent.

- New **"New from Template"** button (SOAR > Playbooks) opens a small gallery of 5
  starting points, each built entirely from this app's own existing action types (no new
  backend capability): **Phishing Triage**, **Malware Containment**, **Critical Alert
  Escalation**, **Threat Intel Enrichment**, **SLA Breach Notification**. Picking one
  opens the regular playbook editor pre-filled with a name/trigger/action sequence —
  nothing saves until the admin reviews and clicks Save, same as building one by hand.
- `apply_template`'s `template_id` (used by Phishing Triage) is auto-resolved by a
  case-insensitive substring match against this instance's own real Case Templates (e.g.
  "Phishing Investigation") — if nothing matches, the action row is added with no
  template selected rather than guessing wrong.
- Gated actions (`isolate_host`, `collect_triage` in Malware Containment) come in
  pre-flagged "Requires approval", matching how every other gated action in this app
  already works.

### Severity classification helper + rationale on cases

Second item from the same IR-lifecycle gap-finding pass: `cases.severity` has always
been a free-pick enum with no record of *why* an analyst chose Critical vs. Medium —
undermining consistency across the SLA tiers, escalation rules, and metrics that already
key off it. Adds a lightweight, optional rubric rather than a rigid enforced matrix.

- **New `cases.severity_rationale` TEXT column** (nullable, free text) on both the New
  Case modal and case detail's edit form, next to the Severity select.
- **"Severity helper" inline panel** — 4 quick-pick factors (scope of compromise, data
  sensitivity, business impact, confidence) each worth 0-4 points, summed to a 0-14
  score mapped to a suggested tier (`>=12` Critical, `>=8` High, `>=4` Medium, else Low).
  "Apply" sets the Severity select and writes a readable breakdown into the rationale
  field (`"Scope of compromise: Multiple hosts, same segment (2); ... = 10 -> High"`) —
  purely a suggestion the analyst can freely override afterward, never enforced
  server-side or blocking manual entry.
- `PUT /api/cases/<id>` logs a `severity_rationale_updated` case-timeline event only when
  the rationale text actually changes (including an explicit clear, logged as
  `(cleared)`), matching the existing "only log real changes" convention the rest of this
  route already follows.

### Explicit, durable case-to-case links (duplicate/child/related/same-campaign)

IR lifecycle gap-finding pass: Related Cases has only ever been a read-only
auto-suggestion feed (cases sharing a host/indicator/threat entity) — it recomputes on
every load and disappears the moment the shared data changes, and there was no way for
an analyst to durably assert "case 142 is a duplicate of case 140" or track a
multi-incident campaign across cases that don't happen to share any single IOC.

- **New `case_links` table** (`case_id`, `related_case_id`, `relationship_type`,
  `created_by`, `created_at`) — one row per asserted link. `relationship_type` is one of
  `duplicate_of` / `child_of` / `related_to` / `same_campaign`.
- **`GET /api/cases/<id>/links`** returns links from BOTH directions with the label
  flipped correctly on each side — a `child_of` link declared as "140 is child_of 142"
  reads as "Child of #142" on case 140's page and "Parent of #140" on case 142's page
  (symmetric types like `same_campaign` read identically both ways). `POST`/`DELETE`
  check for an existing link in *either* direction before inserting (a pair is one fact
  regardless of which case it's declared from) and log a `case_linked`/`case_unlinked`
  timeline event on both cases.
- **Case detail's Related Cases tab** now shows a new "Linked Cases" card (add-link form
  + list with remove buttons, hidden/read-only on a closed case) above the existing
  auto-suggested feed, now relabeled "Suggested Related Cases" for clarity between the
  two.

### Per-template case number prefixes (e.g. INC-2026-014)

Direct request: cases only ever showed the raw `#<id>` primary key, and case templates
only carried a task checklist even though the underlying schema already has room for
more (custom typed fields exist there too). This adds an optional, per-template
"Prefix" (e.g. `INC`, `PHISH`) that drives a real formatted case number on any case
created from that template — a genuinely bigger scope than a plain title prefix, chosen
directly over the simpler options after asking.

- **`case_templates.prefix`** (nullable `TEXT`) — set in the same modal (SOAR > Case
  Templates) that already edits Name/Description/Tasks/Custom Fields, validated as
  1-10 uppercase letters/digits/hyphens (`CASE_TEMPLATE_PREFIX_RE`).
- **`cases.case_number`** (nullable `TEXT`) + new `case_number_counters(prefix, year)`
  table — `_generate_case_number()` atomically allocates the next sequence via one
  `INSERT ... ON CONFLICT(prefix, year) DO UPDATE SET next_seq = next_seq + 1`
  statement (safe against two concurrent case-creation requests racing into the same
  number), formatted `PREFIX-YYYY-NNN`. The counter is scoped to `(prefix, year)`, so
  it resets to 1 automatically each new calendar year with no separate reset job, and
  multiple templates sharing a prefix correctly share one numbering series.
- A case created from a template **without** a prefix set gets no `case_number` — it
  keeps showing the existing plain `#<id>` exactly as before; a case created with no
  template at all is unaffected either way. Nothing retroactive: existing cases stay
  `#<id>` forever unless manually re-triaged under a template (not built — case number
  is stamped once, at creation, matching how template application itself already works).
- Case list rows and the case detail header now show `case_number` when present (via a
  small `caseNumberLabel()` fallback helper), and the New Case modal's template picker
  shows the prefix inline (`"Phishing Investigation (7 tasks, PHISH-#)"`).

**Follow-up, same day**: added a second numbering mode, **year-only** (`2026-014`, no
template-specific text at all) — a new `ctNumberMode` selector in the Case Template
editor, listed above the prefix field with "Year only" as the first option. Picking it
hides the prefix input entirely (nothing to type) and ignores any prefix text the
template previously had.
- **`case_templates.number_mode`** (nullable `TEXT`, `'custom'` or `'year'`) — `NULL`
  (every row saved before this column existed, including the real "Phishing
  Investigation" template already configured with a `PHISH` prefix during this same
  day's live-verification) is normalized to `'custom'` everywhere it's read, so existing
  configured prefixes kept working unchanged with zero manual re-save needed.
- `_generate_case_number()` gained a `year_only` flag — format becomes `YYYY-NNN`. Its
  counter-table key is namespaced (`year:2026`, lowercase+colon) rather than the bare
  year string: `CASE_TEMPLATE_PREFIX_RE` happens to allow an all-digit custom prefix
  like `'2026'`, and without this namespacing a template literally prefixed `2026`
  would silently share (and corrupt) the same counter series as every year-only
  template in that same calendar year.

### Second/third sandbox sources (filescan.io, Hybrid Analysis) + MalwareBazaar hash analyzer

Follow-up to a "what else is out there" research pass (filescan.io, VirusTotal, and
other free tools). Two real findings changed scope from the original plan: filescan.io's
docs page is still JS-rendered/unfetchable, but its official open-source Python client
(`filescanio/fsio-cli`) has real endpoint/header code that's directly readable — no live
key needed to verify the wire shape, unlike the earlier deferral assumed. And OTX Pulses
+ MalwareBazaar were already both fully-built threat-intel *feeds* in this codebase
(bulk "recent samples" sync) — nothing to add there. What *was* a real gap: an on-demand
"check this one specific hash" lookup, which a bulk feed's recent-only slice can't cover.

- **`src/sandbox.py`** gains `filescan_submit`/`filescan_poll` and
  `hybrid_analysis_submit`/`hybrid_analysis_poll`, both file- and URL-capable (unlike
  urlscan.io, URL-only) — endpoints/auth verified against each service's own open-source
  reference client source (`filescanio/fsio-cli`, `dark0pcodes/hybrid_analysis_api`), not
  from memory. Real, documented tradeoffs worth knowing before using either: filescan.io's
  free community tier is confirmed **public-only** (no private option at all, unlike
  urlscan's 50/day private quota); a brand-new Hybrid Analysis API key starts at
  "restricted" privilege and needs a one-time manual vetting request (in Hybrid
  Analysis's own UI) before it can submit anything — surfaced as a specific error on a
  403, not a generic failure.
- **`/api/sandbox/submit`/`/api/sandbox/<id>/status`** now dispatch through a
  `SANDBOX_SOURCE_CATALOG` keyed by source (urlscan/filescan/hybrid_analysis), each
  declaring whether it supports URL and/or file submissions — rejects a URL-only source
  asked to detonate a file (or vice versa) with a clear error instead of a confusing one.
  File submissions always reference an *existing* case attachment (`attachment_id`) —
  reuses `case_attachments`' own upload/validation/hashing rather than adding a second
  upload path.
- **Case detail's Attachments tab** gets a per-file "Detonate" action (source picker:
  filescan.io or Hybrid Analysis — urlscan.io is excluded, URL-only) with the same
  client-driven poll-until-done pattern already used for URL indicators.
- **Threat Intel's Sandbox tab** gets a 3-row API-key table (one per source) and a
  Source dropdown on the submit form; Recent Submissions gets a Source column.
- **New `analyzers._malwarebazaar`** — an on-demand hash lookup against MalwareBazaar's
  full database (`query=get_info`, same `Auth-Key` convention as the already-integrated
  URLhaus), registered with `ioc_types=('hash',)` and tiered `'definite'` in
  `_tier_for()` (same curated-abuse.ch-database confidence as a URLhaus hit) — genuinely
  complements the existing MalwareBazaar *feed* rather than duplicating it.
### Sandbox/detonation: urlscan.io URL sandboxing, IPQualityScore + Censys enrichment

Follow-up to the verdict-signals work above: this app could say a URL/IP *looked* bad
via reputation lookups, but never actually detonated anything. Researched VirusTotal
file-behavior (Premium-only, dead end on the free tier), urlscan.io, filescan.io,
IPQualityScore, Censys, and self-hosted Cuckoo/CAPE against their current docs before
building — Cuckoo is confirmed abandoned (archived 2021), CAPE needs a second host with
a hypervisor/guest VM this single-box appliance doesn't have, and filescan.io's docs are
JS-rendered/unverifiable without a live key. urlscan.io is the one genuinely free,
capable option (a real sandboxed-browser visit — screenshot, DOM, network requests,
verdict) via a plain submit-then-poll REST API:

- **New `src/sandbox.py`** — `urlscan_submit`/`urlscan_poll`, a sibling module to
  `analyzers.py` rather than an addition to it, since submit-then-poll is a genuinely
  different shape than that file's single-call synchronous lookups. Same house style
  (short timeout, never raises, plain dict return).
- **New `sandbox_submissions` table + 4 routes** (`/api/sandbox/submit`, `/<id>/status`,
  list, delete) — source-agnostic schema (`source`/`submission_type` columns) so a
  future filescan.io or CAPE client can plug in later without a redesign, per explicit
  scope decision not to build those now. Polling follows the exact client-driven
  repeated-fetch pattern Log Import's chunked normalize/commit already established —
  this app has no background-job mechanism anywhere, so a still-pending scan is checked
  again a few seconds later from the browser, not a server-side job queue.
- **Private by default, explicit opt-in to Public** — urlscan's free quota is much
  larger for Public scans (5,000/day vs. 50/day private), but Public scans are indexed
  and searchable by anyone on urlscan's own site — a real wrong default for a URL
  pulled from an actual phishing email. Visibility is a per-submission toggle, defaulting
  Private.
- **Three integration points, all sharing the same submit/poll mechanism**: a new
  Sandbox tab on Threat Intel (submit form + polling Recent Submissions table +
  screenshot/report-link detail), a "Detonate" button next to Quick IOC Lookup's Enrich
  button (shown only for a URL-shaped value), and a per-IOC "Detonate in Sandbox" button
  on case detail's URL-type indicators (submits with `case_id` set so the result surfaces
  in that case's own context).
- **`analyzers.py` gains IPQualityScore (proxy/VPN/Tor + fraud-score IP reputation) and
  Censys (host/cert data, Shodan-like)** — both on-demand only (Quick IOC Lookup / Case
  Analyze), explicitly excluded from the automatic Critical/High auto-enrichment sweep
  via a new `auto_enrich_eligible: False` flag, since both have small free quotas (35/day,
  ~100 credits/month) that automatic enrichment would burn through on the first few
  alerts of the day.

- **Fixed live, caught by a direct question about whether enrichment items needed to
  "move over" to Sandbox**: the Indicator Browser catalog's per-row "Enrich" action
  (`enrichCatalogIoc`) jumped straight to `runIocEnrich()`, which never touches the
  Detonate button — only the manual "Check" flow (`runIocLookup`) did. A genuine
  url-type indicator's row-level Enrich button never surfaced Detonate as a result.
  Also fixed a smaller instance of the same gap inside `runIocLookup` itself: a
  confirmed local match can refine the guessed ioc_type past the client's initial
  shape guess (e.g. a bare domain STIX has tagged `url`), and the Enrich button was
  re-synced to the refined type but Detonate wasn't.

Explicitly deferred: file-sandbox submission (`type: 'file'` returns a clear
not-yet-available error rather than silently no-op-ing — the schema is ready, no client
exists yet), filescan.io and CAPE clients (real follow-ups once a live key/second host
exists to verify against), and automatic sandbox submission on alert creation (detonation
stays analyst-initiated — urlscan's private quota is small and "detonate every URL
automatically" is a much bigger action than a passive reputation lookup).

### Suspicious-to-malicious verdict signals: auto-enrichment, YARA evidence, confidence tiering, per-alert score

Follow-up to a direct question: when an alert fires, what actually says "definitively
malicious" vs. "just suspicious"? A code-grounded review found the curated-feed IOC
Sigma rule and URLhaus already gave a real DEFINITE signal automatically, but VT/
AbuseIPDB lookups were on-demand only, YARA matches showed only a rule name, and there
was no per-alert confidence distinct from UEBA's entity-level risk score. Closes all
four gaps, reusing `src/analyzers.py`'s existing VT/AbuseIPDB/URLhaus/Shodan pipeline
rather than a new detection engine:

- **Auto-enrichment on new Critical/High alerts** — `analyzers.auto_enrich_and_score_alert()`
  runs once, right after a new alert is inserted (both `sigma_engine.py`'s detection
  cycle and `app.py`'s heuristic ingest path), checking source/destination IP and file
  hash (new `alerts.file_hash` column — previously computed but discarded before the
  INSERT) against whichever of VT/AbuseIPDB/URLhaus are configured. Gated to Critical/
  High severity plus a new daily API-call budget (`settings` counter, resets daily) --
  the one real gap the review flagged: no throttle beyond the existing 24h cache, and
  VT's free tier is rate-limited. Severity casing genuinely differs between the two
  call sites (sigma_engine.py's Title-Case vs. api_ingest's ALL-CAPS) — the gate
  compares case-insensitively.
- **Confidence/evidence tier on `enrichment_results`** — new `tier` column
  distinguishing a curated-feed exact match ('definite': URLhaus, or a VirusTotal HASH
  lookup where real AV engines flagged the exact file) from a reputation-score
  heuristic ('heuristic': AbuseIPDB's community score, VT's own IP/domain reputation).
  Quick IOC Lookup and Case Analyze now show a "Confirmed" vs "Heuristic" badge
  alongside the verdict badge.
- **YARA match evidence** — File Scan (the live match-producing path;
  `yara_scanner.py`'s separate `/api/yara/scan` route was confirmed dead/unused) now
  surfaces each match's real tags and up to 5 matched-string identifiers with byte
  offset + a readable preview, not just the rule name. Verified against a real
  `yara.compile()`/`match()` run, not just eyeballed.
- **Per-alert composite confidence score** — new `alerts.confidence_score`/
  `confidence_tier` columns, computed once at alert-creation time: +40 for a linked
  `ioc_sightings` row (already alert-linked, no new plumbing), +35 for a definite-tier
  malicious enrichment match, +20 heuristic-malicious, +10 suspicious — mapped to
  confirmed/high/medium/low. Runs for every alert regardless of severity (cheap,
  local-only) using whatever enrichment data already exists, even from an unrelated
  earlier lookup. A new badge renders next to severity in Log Search/alert views, and
  a new opt-in "Confidence" column joins the existing Status/Assignee ones.
- Fixed a real Windows-only encoding bug in `tools/check_template.py` hit live while
  verifying this pass: `node --check`'s stdin write defaulted to the OS locale codepage
  (cp1252), which can't encode genuine non-ASCII characters some templates contain —
  now explicit `encoding='utf-8'`.

### New EDR actions: targeted firewall block, Windows Defender scans

Follow-up to a direct question about EDR coverage: neither a Defender scan nor any
firewall policy beyond the existing all-or-nothing `isolate_host` toggle was available
to trigger. Four new canned actions close that gap, all dispatched through the existing
generic `/api/agent/commands` mechanism (no new routes needed):

- **`block_ip`/`unblock_ip`** (`src/agent_scripts.py`, Tier1/`edr.command.basic`,
  matching `isolate_host`/`restore_network`'s own gate) — a lighter-touch containment
  than full isolation: two new Windows Firewall deny rules (inbound + outbound) for one
  specific IP, host stays otherwise fully usable. `unblock_ip` removes them by the same
  shared rule name. **Real bug caught by actually running the generated script without
  admin rights**: the original version had no `-ErrorAction Stop` around
  `New-NetFirewallRule`, so a permission failure printed the hardcoded success message
  anyway -- a false-positive an analyst could act on believing a host was contained when
  it wasn't. Fixed with a proper try/catch that reports a real failure as one.
- **`defender_quick_scan`** (`edr.command.advanced`) — runs `Start-MpScan -ScanType
  QuickScan` inline and returns real results (last scan time, signature age, recent
  threat detections); typically finishes well inside the agent's 180s script timeout,
  though a slow/loaded host can still exceed it (reported as a clean timeout, not a
  crash or hang).
- **`defender_full_scan`** (`edr.command.advanced`) — a full scan can take hours, so
  this launches detached in the background (the same write-a-child-script/
  `Start-Process`/self-delete pattern `beacon_simulator` already established) and
  returns immediately; it does not wait for or report the result, same accepted
  limitation as `beacon_simulator`'s own detached work.

All four are Windows-only (no Linux/macOS equivalent exists for either mechanism),
queueable from both Case detail's EDR Response tab and the Agents console.

### DFIR SME review, part 3: bulk suspicious-process memory capture (skipped dual-control)

Last of the DFIR SME review findings. Dual-control on destructive approvals (#3) was
deliberately not built this pass -- a second-approver requirement adds delay, and during
an active incident that delay is itself a real risk (further lateral movement/
exfiltration while the analyst waits on a second reviewer). Building #7 instead:
`capture_process_memory`'s real gap was needing an already-identified PID, which an
analyst doing first triage on a newly-flagged host usually doesn't have yet.

- **New EDR action, `capture_top_suspicious_memory`** (`src/agent_scripts.py`,
  Windows-only, matching `capture_process_memory`'s own scope) — ranks running processes
  with a small, explainable heuristic (non-standard install path, invalid/missing
  Authenticode signature, an active connection to a non-private IP -- weighted highest,
  since that's the strongest signal available here for ongoing C2/exfil) and
  memory-dumps the top 3 automatically via the same comsvcs.dll MiniDump mechanism/
  metadata-only-result shape as the existing single-PID action. A handful of core OS
  processes are excluded outright (stability risk on a host already under investigation,
  no real triage benefit). Queueable from both Case detail's EDR Response tab and the
  Agents console, same as every other canned action.
- **Real bug caught by actually running the generated script**, not just parse-checking
  it: an unconditional `Get-AuthenticodeSignature` call for every running process took
  60s+ against a normal process count, which would have risked the agent's own 180s
  script timeout on a real host. Fixed by only signature-checking processes the cheap
  checks (path/connection) already flagged, deduplicated by executable path -- confirmed
  down to ~21s on a real re-run.

### DFIR SME review, part 2: structured post-incident review, cross-host forensic timeline

Follow-up to the same DFIR SME review's two larger findings, planned separately and now
built: a post-incident review that produces tracked outcomes, and a chronological
reconstruction of case activity across every tracked host (not just an audit log of
changes to the case itself).

- **Structured post-incident review** — `cases.pir_notes` (new JSON column) backs 3
  fixed, NIST-800-61-Post-Incident-Activity-inspired sections (Detection & Response
  Effectiveness / Gaps Identified / Recommended Improvements) rendered alongside the
  existing Root Cause / Lessons Learned fields — both untouched, nothing an analyst
  already wrote is hidden or migrated. A "Follow-up Actions" composer posts straight to
  the existing case-tasks route, so a follow-up action is a real, trackable task from the
  moment it's added, not more prose. Edits to any of the three retrospective fields now
  log a `pir_updated` case-timeline event — previously silent.
- **Cross-host forensic timeline** — new `GET /api/cases/<cid>/forensic-timeline` route
  and case-detail tab, distinct from the existing Timeline (case_events audit log) and
  Related Items (a 24h "what's new to add" suggestion feed that excludes anything already
  linked). Merges alerts/UEBA/FIM activity across every host the case tracks (any
  compromise status, not just confirmed) into one chronological list, defaulting to the
  case's own lifetime with an optional `hours_before` to pull in pre-incident context,
  paginated via a `before_ts` cursor.

### DFIR SME review: order-of-volatility, legal hold, evidence access logging

Reviewed the actual EDR/case workflow against NIST 800-61 / SANS PICERL practice
(chain of custody, order of volatility, dual control, post-incident review) rather
than app UI/navigation. Three findings addressed this pass; a structured
post-incident-review artifact and a cross-host case timeline are larger items,
planned separately.

- **Order of volatility**: `isolate_host` playbook actions can now optionally
  queue a `collect_triage` bundle for each targeted host immediately ahead of the
  isolation command (`_run_playbook_action`, `src/app.py`) — `agent_commands` is a
  strict per-host FIFO queue, so this guarantees the triage capture is dispatched
  before containment cuts off the volatile process/network state it would capture.
  Opt-in checkbox on the `isolate_host` action editor (`templates/soar.html`);
  off by default, so no existing playbook's behavior changes.
- **Legal hold on log retention**: the automatic log-retention purge
  (`run_due_log_purge`, `src/sigma_engine.py`) no longer deletes a `live_logs` row
  that's linked into an *open* case as a `fim_event` item — age-based retention was
  previously blind to whether a row was an active case's evidence. A case's hold
  releases once it's closed.
- **Evidence access logging**: case attachment downloads are now logged to the
  case timeline (`attachment_downloaded`, every download, not just the first) —
  closes the other half of chain-of-custody (who added evidence was already
  logged; who accessed it wasn't).

### Workflow consolidation pass: SOAR Settings tab, vulnerability cross-links, dev tooling

Follow-up to the previous day's nav cleanup — reviewed the app's remaining tab
structure, the alert-to-case-to-response analyst workflow, and this session's own
dev/test/deploy process for further consolidation. Most of the app held up fine on
inspection (nav is already lean, the core analyst workflow is already linear with no
redundant screen-bouncing); three concrete items came out of it:

- **SOAR: folded Queues, Notifications, and Automation into one "Settings" tab**
  (`templates/soar.html`) — those three were thin config screens next to the two real
  work surfaces (Playbooks, Actions). SOAR's tab strip goes from 6 tabs to 4
  (Playbooks, Case Templates, Actions, Settings), with the three merged sections
  separated by `<h6>`/`<hr>` inside one pane. Automation's whole-section
  `has_permission('settings.system.manage')` gate is preserved (not weakened to
  per-input `disabled` attributes) so its inputs still never reach a non-admin's DOM.
- **Cross-linked the two vulnerability views** — Threat Intel & Hunting's
  "Vulnerabilities" tab (raw CVE/EPSS/KEV browsing, not host-correlated) and
  Coverage's "Vulnerability" tab (per-host coverage-score rollup) cover genuinely
  different ground, so they weren't merged, but nothing pointed from one to the other.
  Added a one-line link each way.
- **New `tools/` directory**: `check_template.py` (Jinja compile-check + extract/stub/
  `node --check` an inline `<script>` block, in one command) and `vm_test_harness.js`
  (shared `extractFn`/`makeChecker` helpers for Node vm-context tests). Collapses
  boilerplate that had been getting hand-rewritten from scratch in scratchpad every
  phase this session — dev-only tooling, no production-path changes.

## 2026-09-09

### Nav cleanup: fold IR Runbooks into Cases as a sibling tab

The left sidebar had grown to 11 top-level items; IR Runbooks (added earlier this
session) was Cases-adjacent content sitting in its own slot for no strong reason, unlike
every other item (SIEM, EDR, UEBA, Threat Intel, SOAR, Log Pipeline), which represents a
genuinely distinct workflow this app has deliberately kept separate. Folded IR Runbooks
into Cases as a flattened 3-tab page (Cases | Runbook Library | Tabletop Exercises) —
`templates/runbooks.html` deleted, its markup/JS merged into `templates/cases.html`
(duplicate `escHtml`/`renderLoadError` dropped in favor of Cases' own copies,
`switchRunbookTab` replaced by a unified `switchCasesTab`). `cases_page()` now accepts
`?tab=`; the old `/runbooks` route redirects to `/cases?tab=library` (or `?tab=exercises`)
so existing bookmarks/links keep working instead of hitting a dead page. Sidebar is back
to 10 items.

### New: Click-through drill-down on the two dashboard trend charts

Closes the gap explicitly left open when 3 other dashboard charts got click-through
earlier this session: "there's no precise date-range deep-link into Log Search yet to
click through to, and landing on an approximate day would be worse than no drill-down."
Alert Volume Trend and Risk Score Trend now both have a real `Chart.js` `onClick` handler
(neither had one at all before — the 3 already-shipped charts are a doughnut and two bar
charts, this is the first time a `line`-type widget got one) that deep-links to Log
Search scoped to exactly the clicked bucket's time window via a new `range=custom&start=
&end=` query string, rather than a categorical `field:value` filter like the existing
`pivotToLogSearch()` pivot uses.

New shared `pivotToLogSearchBucket()` (`base.html`) handles a real, easy-to-get-wrong
correctness trap: both trend charts' bucket labels (`t_bucket`/`day`) are computed via a
plain `strftime()` against a UTC-native timestamp column (`alerts.timestamp`/
`risk_score_events.computed_at`, both SQLite's own UTC `CURRENT_TIMESTAMP` default) with
no `'localtime'` conversion — so the label itself is a UTC-clock string, while Log
Search's `range=custom&start=/end=` are documented as LOCAL time
(`_build_log_time_condition`, matching the existing custom-range date picker's own
convention). Treating the UTC label as if it were already local would silently shift the
deep-linked window by the server's UTC offset — exactly the mixed-clock bug class this
session already fixed elsewhere in Log Search. Fixed by parsing the label as UTC (`Z`
suffix) and reading it back via JS `Date`'s plain (non-UTC) getters, which naturally
return browser-local time.

Bucket width is read from the label itself (hourly `"YYYY-MM-DD HH:00"` vs daily
`"YYYY-MM-DD"`, detected by a colon) rather than assumed from the dashboard's currently-
selected range — `api_dashboard_alert_trend`'s own bucket switches to hourly only when
the selected range is ≤7 days, so a click needs to reflect what the chart actually drew,
not what range happens to be selected right now.

`initSearchTab()` (`dashboard.html`) now reads `range=custom&start=&end=` from the
incoming URL and applies it via the page's existing `timeRangeState`/custom-range-picker
mechanism — previously only `alert_id`/`q` were ever read, and a `q` deep-link
unconditionally reset the window to "All Time" (correct for a categorical pivot, wrong
for a time-bucket click, which needs the *opposite*: the precise window, not the whole
history). A plain page load with no deep-link params is completely unaffected.

Verified: 22 Node vm-context tests (the UTC→local conversion independently re-derived
and cross-checked rather than hardcoded to one timezone, hourly/daily bucket width math,
both widgets' `onClick` wiring, `initSearchTab()`'s new branch including that a bare page
load stays untouched) + 2 tests round-tripping the exact emitted timestamp format through
the real, unmodified `_parse_datetime_local()` backend function.

### New: Windows Advanced Audit Policy drift detection

Closes the gap a review pass explicitly left unfixed earlier this session ("would need a
new live-policy-read capability, out of scope for a review-driven fix pass"). This app's
agent has always been able to *push* Advanced Audit Policy (`reconcile_windows_audit_policy()`
in `micro_agent_windows.py`, 12 CIS/NSA-aligned subcategories set to Success+Failure via
`auditpol /set`) but had zero read-back path — `auditpol /get` was never called anywhere
in the codebase, so a domain GPO refresh silently overriding the pushed policy (or a
subcategory drifting/being tampered with) had no way to surface.

New `audit_policy_compliance` check folded directly into the existing `sca_check()`
hardening-check action (Windows only) rather than a new mechanism: runs
`auditpol /get /category:* /r`, parses the CSV, and compares the same 12 subcategories
against the expected `Success and Failure` baseline — reusing the entire existing
SCA pipeline (`SCA_CHECK_FRAMEWORKS` mapping, `_sca_framework_aggregate()`'s Hardening-
score rollup, the "View SCA Results" table) with zero new routes, tables, or UI code.
Domain-joined status (`Win32_ComputerSystem.PartOfDomain`) is included in the detail text
as a diagnostic hint, not a gate — drift is worth flagging even on a non-domain host
(e.g. a failed local push), the domain-joined note just helps an analyst tell GPO
interference apart from other causes.

**Real bug caught by actually running the script, not just reading it**: `auditpol` is a
native console exe, not a cmdlet — it never throws a PowerShell exception on failure
(e.g. insufficient privilege), it just writes an error to its own output and returns a
non-zero exit code. The first draft's `auditpol /get ... | ConvertFrom-Csv` silently
parsed a failed call's empty output as zero matching rows, which the comparison loop then
misreported as "all 12 subcategories drifted" (status `fail`) instead of "could not
determine" (status `error`) — confirmed live by running the check unelevated on a real
Windows box and watching it produce exactly that false-fail. Fixed by checking
`$LASTEXITCODE` and the parsed row count explicitly before ever comparing.

Verified: 12 real PowerShell tests against the actual comparison logic (all-enabled →
pass, a single drifted subcategory named correctly in the detail, "Success" without
"Failure" correctly treated as drift, a subcategory missing from auditpol's own output
entirely, unrelated extra subcategories in the real output ignored, domain-joined/
non-domain/unknown all reported honestly) + 15 Python tests (the dual-definition
`SCA_CHECK_FRAMEWORKS` copy in `app.py`/`generate_report.py` byte-for-byte identical,
`_sca_framework_aggregate()`'s rollup exercised directly, and — the regression guard that
actually matters here — the new check's 12-subcategory list cross-checked against
`micro_agent_windows.py`'s own push-side list to prove there's no silent mismatch between
what's enforced and what's verified). Both the outer script and this specific addition
were parsed with PowerShell's own AST parser and genuinely executed on a real Windows
host (unelevated, which is exactly what surfaced the bug above).

### New: Replay Detection (Log Import's deferred Phase 2)

Closes the Phase 2 gap explicitly deferred when Log Import Phase 1 shipped: an opt-in
"Replay Detection" action on a completed import, running every enabled Sigma rule
against just that import's `imported_logs` rows and creating real alerts for new
matches — without ever touching the live detection cursor (`sigma_state.json`) or firing
SOAR playbooks/auto-case for what could be months of historical data. New
`sigma_engine.replay_import_chunk()` scopes the same `recent_events` TEMP VIEW mechanism
`dry_run_rule()`/`dry_run_rule_scoped()` already use to `imported_logs WHERE import_id =
?` instead of `live_logs` — `imported_logs` deliberately mirrors `live_logs`' column
shape (a Phase 1 decision made specifically to leave this open), so `_make_backend()`'s
field-to-column mapping needed zero changes.

Chunked by rule (not by row), same "no async/background-job mechanism, drive a slow
operation as a client-driven loop" convention Log Import's own normalize/commit phases
already use — new `POST /api/logs/import/<id>/replay` route, optimistic-concurrency
conditional UPDATE on `imports.replay_rule_offset` mirroring `commit_offset`'s own
shape. Idempotent by design: re-replaying the same import (e.g. after enabling a new
rule) never duplicates an alert for a rule/host/user combo already alerted from that
import — it bumps `occurrence_count` instead, checked via a new `alerts.import_id`
column.

Deliberately scoped down, each a real trade-off rather than an oversight: aggregation-
condition rules are skipped (their per-cycle accumulate-then-threshold design has no
one-shot translation for a fixed dataset — same limitation `dry_run_rule()` already has);
SOAR playbooks and auto-case creation never fire for a replay alert (an admin clicking
Replay wants to see the alerts, not retroactively spam every live automation against a
historical backlog); UEBA baselining is entirely untouched (no view-indirection exists
there at all — ~15+ query strings hardcode `siem.live_logs` directly, and baselines are
shared global state a replay run must never pollute — a materially larger, separately-
scoped gap, not attempted here).

**Real bug found and fixed while wiring this up**: `alerts.event_id` is compared against
`live_logs.id` in two places (the Home dashboard's recent-alerts widget, and the MTTD
calculation) — but `imported_logs` and `live_logs` have **independent AUTOINCREMENT
sequences**, so a replay alert's `event_id` (pointing at an `imported_logs.id`) could
silently collide with an unrelated `live_logs` row sharing the same numeric id, corrupting
both the widget's displayed host/message and the MTTD average with garbage from a
decade-old row. Both joins now guard on the new `import_id IS NULL` marker.

Verified: 84 tests across 5 real fixture suites — 27 against the actual
`sigma_engine.replay_import_chunk()` function with the real installed pySigma 0.11.23
(real matches scoped correctly to one import and never touching a colliding `live_logs`
row with the same pattern, idempotent re-replay verified by bumping `occurrence_count`
not duplicating, aggregation rules genuinely skipped, exclusions honored, disabled rules
never evaluated, chunked pagination math correct across multiple calls); 18 for the
route's own offset/reset/optimistic-concurrency bookkeeping including a simulated
concurrent-request race; 9 directly proving the `event_id` collision fix by deliberately
constructing the exact same-id collision between the two independent tables; 8 for
migration idempotency; 22 Node vm-context tests for the console's confirm-gate, chunked
polling loop, and progress/completion UI. Commit + push + deploy via `update.sh`.

### New: Beacon Simulator EDR test action (Beaconing Detection's deferred Phase 2)

Closes the Phase 2 gap explicitly deferred when Beaconing Detection shipped: a way to
validate the UEBA regularity model against a real, controlled beacon instead of trusting
it on faith. New Windows-only `beacon_simulator` EDR console action (Agents page,
`edr.command.advanced`): admin supplies a target IP/port, interval, jitter, and
connection count; the agent writes a small detached child `.ps1` to
`C:\ProgramData\MicroDFIR\BeaconSim\` and launches it via `Start-Process` (a real
independent OS process, not a `Start-Job` pipe tied to the invoking script's lifetime),
so a realistic multi-minute beacon run survives well past the agent's own 180s
per-command timeout. Each iteration is a real `TcpClient.ConnectAsync` — the same signal
Sysmon Event ID 3 (Network Connection) actually observes, which is the only data source
`_run_beaconing_model` ever reads. The outer command returns immediately with the
target/cadence and an estimated finish time; the child self-deletes when its loop
completes. Bounds-validated server-side (port 1-65535, interval 5-3600s, jitter
0-interval, count 3-100, and a hard interval×count ≤ 24h cap) so a typo can't leave an
orphaned background process running for days.

Deliberately Windows-only, not a Linux/macOS gap: the beaconing model itself only ever
reads Sysmon data (a Windows-only source), so a Linux/macOS version would generate
connections the detector can never see — it would validate nothing.

Verified: 27 real Python fixture tests (every bounds rejection, the 24h-cap and
jitter-equals-interval boundaries, script content, WINDOWS_TEMPLATES registration,
confirmed absent from LINUX_TEMPLATES) + 11 Node vm-context tests for the console form's
client-side validation and exact params shape. Both the outer and the generated inner
script were parsed with PowerShell's own AST parser (`[Parser]::ParseFile`, zero errors)
and then genuinely *executed* on a real Windows host: the outer command returned in
under a second with valid JSON, the detached child was confirmed written to disk, and 15
seconds later the child had completed its full 3-connection loop against `1.1.1.1:443`
and self-deleted — real, observed, end-to-end behavior, not just a code read.

### New: IR Runbooks & Tabletop Exercise tracking

Closed the last item on the DFIR-lifecycle gap list: this app had no place to document
incident-response procedures or record whether they'd ever actually been rehearsed — the
Post-Incident Activity / Preparation phases had zero coverage. New top-level "IR Runbooks"
nav item with two tabs. **Runbook Library**: a growable-seeded catalog of narrative IR
procedures (distinct from the existing case-template task checklists — a runbook is
reference documentation with real step-by-step instructions, read during an incident, not
applied onto a case as tasks), seeded with three real starter runbooks (Ransomware
Response, Business Email Compromise, Insider Threat Response), each with substantive
step content. **Tabletop Exercises**: a log of practice drills — title, scenario, linked
runbook, status (planned/completed/cancelled), facilitator/participants, and a
findings/action-items retrospective (same free-text-pair shape as the case Retrospective
fields shipped earlier this session). The exercises tab surfaces a live "Runbooks Never
Tested" count so an untested procedure doesn't stay invisible.

New `cases.runbooks.manage` permission (backfilled onto any role that already had
`cases.templates.manage`, same pattern used for every prior permission-key addition); read
access is ungated, matching the existing case-templates precedent, since this is
operational documentation every analyst should be able to read. Deleting a runbook nulls
out `tabletop_exercises.runbook_id` rather than cascading — a completed exercise's findings
stay meaningful even after the runbook it tested is retired.

New fifth report type: **Tabletop Exercise Report** (Reports page — type dropdown,
schedule tab, all fully generic over `REPORT_TYPES` so no other code needed to change).
Summarizes exercise activity in the selected window plus a current-state runbook coverage
table (times tested / last tested, highlighting anything never rehearsed).

### New: Readiness Scorecard dashboard widget

The last lifecycle-audit item for now: a first-time evaluator (or an admin checking in
periodically) had no single place to answer "are we actually ready" — EDR enrollment,
detection rules, MITRE coverage, backup, retention, and asset inventory each already live
on their own page, with nothing tying them into one checklist. New `chart_readiness_scorecard`
widget (Dashboards, same registry every other widget uses) pulls seven already-existing
facts into a green/amber checklist: agents active in the last 24h vs. total ever enrolled,
enabled detection rules, the latest MITRE coverage snapshot, whether the DB backup ran in
the last 48h, whether retention/archiving are configured, how many assets carry a real
criticality, and how many real user accounts exist beyond the seed admin. Deliberately no
new computation or tables — every number is read from where it already lives
(`agent_polls`, `sigma_rules`, `coverage_snapshots`, `settings`, `assets`, `users`), same
pure-aggregation spirit as the existing Compliance Coverage widget.

### New: cross-rule escalation now keys on username too, not just host

`_escalate_host` (sigma_engine.py) already auto-cases a host when N distinct rules fire
against it in a window; the lifecycle audit flagged that this had no equivalent for a
username — several different rules firing against the same account across multiple hosts
(exactly a credential-abuse or lateral-movement pattern) went completely uncorrelated.
New `_escalate_user`, same signal keyed on `username` instead: SYSTEM/service-account
values are excluded in the SQL itself (a shared account triggering rules across many
hosts is noise, not a real single-user signal), and cooldown reuses the same
`alert_escalations` table (a new nullable `username` column; `host` stays `''` for a
user-type row rather than relaxing its `NOT NULL`, which SQLite can't do without a full
table rebuild). `case_assets` has no username column, so unlike the host path this can't
attach an asset row — "already tracked by an open case" is instead derived from a case's
linked alerts' own username field, the same bridge `_case_implicated_usernames` uses.

Found and fixed a real, unrelated pre-existing bug while wiring this up: `caseEventLabel`
(cases.html) had no entry for the `'escalation'` event type at all, so a host-escalation
note was silently rendering as the bare word "escalation" with its actual detail text
dropped — fixed for both the host and username paths at once, since they share the type.

### New: urgency chips (fired-ago / unacknowledged) on the alert triage panel

The last of today's smaller lifecycle-audit items: cases show "6.5d open, SLA breached"
right at the top, but the alert triage panel — where triage actually happens — showed no
urgency signal at all. Alerts have no formal SLA target the way cases do (`case_sla_hours`
doesn't apply here), so this doesn't invent a breach threshold; it shows the same two
honest, always-computable facts the case header already leads with: how long ago the
alert fired (`hoursLabel`/`elapsedHours`, duplicated from cases.html's own implementation)
and whether it's still unacknowledged. Refreshes in place immediately after a save — the
save itself is what acknowledges the alert, so the modal's own "Not yet acknowledged" chip
would otherwise keep showing stale until it's closed and reopened.

### New: bulk alert triage in Log Search

An alert storm previously had to be worked one detail-modal click at a time — no way to
select several alerts and apply one triage action to all of them. Log Search's results
table gains a checkbox column (alert-type rows only; log/anomaly/command/import rows get
a blank cell, since bulk triage only makes sense for something with triage semantics) and
a select-all header checkbox. Selecting 1+ shows a bulk-action bar with Mark False
Positive / Mark Resolved / Mark Investigating, each firing a parallel fan-out to the
existing single-alert `PUT /api/alerts/<id>` route (no new backend endpoint — each alert
is its own independent update, so a client-side `Promise.all` is exactly as safe as a
server-side loop would be, without adding new surface). Selection is keyed by real alert
id so it survives an in-place row re-render, but clears on a genuinely fresh search.

### New: remediation status tracking on Coverage > Vulnerability findings

Another small item from the lifecycle audit: Vulnerability Coverage was pure read-only
reporting — no "mark patched," no way to record an analyst's call on a finding at all.
Vulnerability findings themselves are never stored as rows (they're recomputed fresh
every request from live software-inventory + CVE-feed matching), so this adds a small
`vulnerability_remediation` table storing just a status override keyed on the same
`(hostname, cve_id, installed_name)` identity `correlate_software_vulnerabilities`
already dedups findings on internally — `GET /api/vulnerabilities/coverage` looks it up
and merges it into each freshly-computed finding, defaulting to "Open" when no row
exists.

Five statuses: Open, Acknowledged, Patched, Accepted Risk, False Positive. If the
software is genuinely upgraded, the finding stops matching on its own on the next scan
(the new version falls outside the vulnerable range) and just disappears — this table
exists for the interim before a rescan confirms it, and for the two outcomes (accepted
risk, false positive) a rescan could never resolve by itself. The Coverage page's
Vulnerability tab gets a Status column (inline select, saves immediately, same posture
as alert triage — no extra permission gate) plus a new "Still Open" hero tile counting
findings not yet marked patched/accepted/false-positive.

### New: real session revocation, a case-linked credential-revoke playbook action, and incident-triggered watchlisting

Two more items from the lifecycle audit's Containment/Recovery findings, both real
gaps closed by one shared piece of new infrastructure.

**The infrastructure**: this app's session cookie (Flask-Login) carried only a user id
— `load_user()` never re-checked anything password-derived on each request, so
changing a `password_hash` never actually invalidated an already-logged-in browser
session. The "Force password reset and revoke active sessions" line on the
Compromised Account case template was, until now, only ever half-true. Fixed with a
new `users.session_version` column: stamped into the session cookie at login, compared
on every request in `load_user()`. Bumping it (admin reset, self-service change, or the
new revoke action below) makes every *other* outstanding session fail that check on its
very next request — a real, working "log out everywhere else." Self-service password
change re-stamps its own session so that one tab stays logged in; every other session
for that account does not.

**⚠️ One-time effect of this deploy**: every session active *before* this update has no
`session_version` stamped in its cookie at all, which the new check treats as a
mismatch — expect to have to log back in once, on every open tab, right after this
deploys. A one-time inconvenience, not a bug.

**New `revoke_user_credentials` playbook action** (always-approval-gated, like
`isolate_host`): targets every username implicated by a case's linked alerts that
matches a real app account — most endpoint usernames won't (they're Windows/Linux
account names, not app logins), which is the expected common case, not an error. Sets a
random password (never returned, logged, or stored anywhere — recovery is the existing,
separate admin reset flow once the account owner is ready), forces a change, and bumps
`session_version`. New shared helper `_case_implicated_usernames()` (also used to
de-duplicate `related-items`' own username derivation) is the only bridge from a case to
a real identity today, since `case_assets` is host-only and `identities` has no host
column.

**Incident-triggered watchlisting**: closing a case that has at least one Case Asset
marked `confirmed` compromised now auto-adds its implicated usernames to the existing
insider-threat watchlist (`identities.watched`) — logged to the case timeline
(`user_watchlisted`), never fabricating a new `identities` row for a username with no
existing entry. Closes "nothing connects a resolved incident back to heightened
monitoring," the same real, previously-manual gap `_case_coverage_gaps` closed for
detection tuning earlier today.

### New: triage-scoped process memory capture (Windows), closing part of the DFIR audit's Forensic Evidence Collection gap

The lifecycle audit flagged zero volatile-data acquisition anywhere in the app as a
first-order gap against NIST's "capture volatile data first" step. Full RAM/disk
imaging was explicitly scoped out (already declined once for Volatility integration,
per CHANGELOG history, as infrastructure-incompatible with a single-box SQLite
appliance) in favor of something that actually fits: a new `capture_process_memory`
EDR action dumps ONE process's memory (a PID an analyst already has, same as
`kill_process`), via `comsvcs.dll`'s built-in `MiniDump` export — no third-party tool
to bundle or download, since it's already on every Windows box. It's the same
OS-native mechanism real credential-dumping TTPs use against `lsass.exe` (this app's
own `_is_suspicious_lsass_process_access` heuristic exists because of it), so expect it
to be flagged/blocked by the endpoint's own AV/EDR when targeting a protected process —
a correct, expected outcome, not a bug.

The dump itself (routinely 100s of MB) deliberately stays on the endpoint's own disk
rather than trying to squeeze it through the agent command channel's 60,000-char stdout
cap (`collect_file`'s own 40KB limit exists for exactly this reason) — what comes back
is metadata only (path, size, SHA-256, process identity), hashed immediately for chain
of custody. An analyst retrieves the actual `.dmp` out-of-band and can upload it as a
case attachment, where it now hashes on upload and re-verifies on every download (see
the case-attachment-hashing entry above) to cross-check against the hash recorded here
at capture time. Windows-only for this pass — an honest scope cut, not an oversight;
Linux/macOS equivalents (`gcore`, etc.) would need different mechanisms entirely.

### New: case Retrospective fields (Root Cause / Lessons Learned) + a case→Coverage gap link

Two more items from the DFIR lifecycle audit's Post-Incident Activity findings, both
real: every quantitative post-incident metric already existed (MTTD/MTTA/MTTI/MTTC/MTTR,
FP rate, etc.) but nothing ever captured the qualitative half, and nothing connected "we
just handled an incident" back to "did Coverage already know about the techniques
involved."

`cases` gains two nullable free-text columns, `root_cause`/`lessons_learned`, editable
alongside Description and disabled once a case is closed (same as every other field —
closing a case is meant to be the point where the record freezes). Since that means a
retrospective note has to be written *before* closing or not through the UI at all,
`saveCaseDetail()` adds a soft, dismissable prompt ("You're closing this case without a
root cause or lessons learned note — continue anyway?") rather than a hard block — a
false positive or a trivial case shouldn't be stuck on a mandatory write-up.

New `_case_coverage_gaps()` (`app.py`) gathers the MITRE techniques implicated by a
case's linked alerts (`alerts.mitre_techniques`, already stamped on every fired alert)
and checks each one's current Coverage tier — reusing the exact same
`_build_mitre_coverage`/`_technique_tier_lookup` the Coverage page itself uses, not a
separate approximation. When any of them sit at `gap`/`inactive`/`unmapped`, the case
detail page shows a small warning card naming them with a link straight to Coverage's
MITRE tab — the case→gap-review link that was previously entirely manual.

### Settings > Database Backups now lists actual backup files, not just a count

Started as a "backup has no restore path" item on the DFIR lifecycle audit — turned out
to be wrong. `restore_db.sh` already exists at the repo root and is genuinely
well-built: gzip integrity check before touching the live DB, a confirmation prompt, a
pre-restore safety copy, and a post-restore `PRAGMA integrity_check` with automatic
rollback if it fails. It's deliberately kept CLI/root-only rather than a Settings
button (documented in its own header, and already referenced in Settings' own copy) —
restoring a database is exactly the kind of rare, destructive action that should stay a
manual, confirmed step. What was real and worth fixing: an admin had no way to see
*which* backups actually exist without SSHing in first. `GET /api/settings/db-backup`
now returns the real file list (name/size/timestamp, newest first), rendered as a small
table with a ready-to-copy restore command for the most recent one. Also closed a
pre-existing permission-gate gap while touching this route: the GET branch had no
server-side check even though POST did and the UI panel is admin-only — any logged-in
user could previously read backup existence/count directly via the API.

### New: SHA-256 hashing + integrity verification for case attachments

From a DFIR-lifecycle gap audit: every EDR-collected artifact (`collect_file`,
`quarantine_file`) is hashed at collection time, but the one place an analyst
*deliberately* attaches evidence to a case — `case_attachments` — wasn't, making it the
single biggest chain-of-custody gap in the app. Fixed: `api_case_attachments`'s upload
route now hashes the file stream once (chunked, before it's saved, not a second read
after) and stores the digest in a new nullable `sha256` column; the case Attachments
table shows it (truncated, full value on hover). Nullable so a pre-existing attachment
uploaded before this shipped reads as "not recorded," never as a false mismatch.

Hashing something nobody ever re-checks isn't really a custody control, so
`api_case_attachment_download` now re-hashes the on-disk file against the stored digest
on *every* download and logs a new `attachment_integrity_mismatch` case-timeline event
(red, distinct from routine notes) if they no longer match — corruption or tampering
leaves a real, visible trail instead of silently going unnoticed. Non-blocking: a
mismatch never prevents the download itself, since a false positive here shouldn't lock
an analyst out of evidence they need right now.

### DNS query logs now carry a real host, not just a source IP

`dns_server.py` deliberately never attempted host attribution — DNS itself carries no
identity, only a source IP — leaving every query in Log Search and the DNS Activity view
attributed to an IP alone. A best-effort correlation helper (`_resolve_dns_client_context`)
already existed for the dedicated DNS Activity view, but its only data source
(`live_logs.source_ip` from some other log type) was essentially unpopulated, since
nothing extracts a host's own local IP from Sysmon — only `destination_ip` ever gets
extracted from Event ID 3.

Fixed by adding a second, much denser correlation source that already exists and was
going unused for this: `agent_polls`, which records an enrolled EDR agent's real source
IP + hostname on every check-in (~8s cadence). `dns_server.py` now resolves host at
*ingest* time (new `_resolve_dns_host()`, tried against other already-ingested logs from
the same IP first, then `agent_polls` within a tight 15-minute window to avoid a stale
DHCP-lease reassignment misattributing a query) and writes it straight into
`live_logs.host` — meaning general Log Search picks it up for free through its existing
generic SQL union, no query-time enrichment or template changes needed anywhere.
`_resolve_dns_client_context` (app.py) gained the same `agent_polls` fallback, now used
only to backfill host on pre-existing rows and to resolve username (still deliberately
never attempted at ingest — a logged-in user at query time is a weaker inference than the
device itself).

### UEBA Timeline: compact-by-default Filters column with expand/collapse

The Timeline tab's Filters sidebar (Event Types, Time Range, Search, Apply/Refresh)
now ships collapsed by default — a narrow strip with just a filter icon and a toggle
button, giving the results table the room instead. Same collapse/expand mechanism
`base.html`'s sidebar toggle already uses (a body/column class swap + `localStorage`
persistence, restored before the rest of the page's init logic runs to avoid a
flash-of-wrong-state), scoped to just this one column via `#tlFiltersCol`/
`toggleTimelineFilters()` in `templates/ueba.html`.

## 2026-09-08

### New: Beaconing Detection (UEBA) — network C2-callback regularity scoring

Follow-up to reviewing Black Hills InfoSec's and Active Countermeasures' free tool
catalogs. Active Countermeasures' RITA scores C2 beaconing by how *regular* repeated
network connections are; this adds the same core idea — a new, standalone UEBA model,
not a RITA/Zeek dependency — as `_run_beaconing_model()` in `src/ueba_engine.py`. For
each `(host, destination_ip)` pair seen in Sysmon Event ID 3 (Network Connection) rows
within a lookback window, excluding private/reserved destinations (a beacon calls
*out*, by definition) and CDN/public-DNS ranges (reusing `warninglists.py`'s existing
suppression utility, already used by the IOC-IP correlation rule), a DuckDB window
function computes the coefficient of variation of inter-connection intervals — low
variance is the signature of automated callback timing versus organic traffic.
Confirmed real, meaningful data exists to build on: 46,390 Sysmon Event ID 3 rows/day
in this instance alone.

A real bug was caught by the fixture tests, not assumed: same-wall-clock-second
duplicate timestamps (Sysmon's own ingestion timestamp is second-precision only) were
initially dropping out of the *displayed* connection count, not just the variance
calculation — fixed by decoupling `conn_count` (every real connection) from the CV
computation (which correctly excludes zero-delta pairs as noise). A second issue caught
during design review: a flat 40-point/High-severity score would have tied this
purely-statistical, admittedly-imperfect indicator with `alert_critical` — the single
highest-weighted signal in the whole priority-scoring system. Rebalanced to a
20-point base tier (25 for an especially tight or high-volume pattern), calibrated
against the closest real analogues (`new_destination_ip`=15, `process_lineage`=25).

New per-destination-IP exclusion type (`ueba_exclusions.entity_type` now also accepts
`'destination_ip'`, alongside the existing `host`/`user`) so an admin can suppress a
specific known-legitimate regular destination (a VPN concentrator, a SaaS heartbeat)
without suppressing all beaconing detection for the host that talks to it. New
`ueba_beaconing_*` config (enabled/lookback hours/min connections/CV threshold) in the
usual dual-definition shape (`app.py` + `ueba_engine.py`), with real bounds validation.

**Also reviewed this session**: our existing Atomic Testing feature turned out to
already be well ahead of Active Countermeasures' "Threat Simulator" (which is actually
just a single jittered beacon-generator tool, not a broad technique library) — ours
live-fetches the real upstream Atomic Red Team repo, executes real techniques via the
EDR agent queue, and auto-validates against Sigma/alerts with a documented distinction
from Coverage's weaker "any alert fired" tier. Their beacon-generator's own
interval+jitter parameterization is a good reference for the deferred Phase 2 —
a companion EDR-agent-queued "Beacon Simulator" to validate this detector against a
real, controlled, known-beacon pattern, not started here. Threat-intel feed coverage
was also checked against BHIS's OSINT tooling: this app already supports 17 feed types
(ThreatFox, URLhaus, MISP, OTX, SSLBL, Spamhaus DROP, and more) plus a generic TAXII 2.x
client, well ahead of what BHIS's recon-focused tools (which target an org's *own*
exposure, not attacker infrastructure) would add.

### New: Log Import (Phase 1) — CSV/NDJSON/JSON-array import from other SIEMs

Customers migrating off another SIEM (Splunk, QRadar, Elastic, Sentinel, etc.) can now
bring their historical logs into a new "Import" tab on the Log Pipeline page. Scoped
deliberately to a pure historical-search feature: imported rows land in a new
`imported_logs` table (never `live_logs`, which detection/UEBA/retention are all tuned
around) and never feed live Sigma detection or UEBA baselining — an opt-in "Replay
Detection" action against a specific import is a documented, explicitly deferred Phase 2,
not started until this phase ships and gets real use.

**Wizard**: Upload → (chunked) Normalize → Map Fields → Preview → (chunked) Commit →
Done. Field mapping is auto-suggested via a new `IMPORT_FIELD_ALIASES` table (the same
"many vendor names, one canonical column" idea `sigma_engine.py`'s `_FIELD_COLUMN_ALIASES`
already uses for Sigma field resolution) — a Splunk/Elastic/QRadar export needs near-zero
manual remapping for the common fields. Timestamp timezone is a required, explicit choice
(UTC / this server's local time / a custom fixed offset) — never inferred — matching the
whole timezone-discipline thread from the two Log Search fixes earlier this same day. A
lightweight per-value Severity rename (distinct values found → optional rename, defaults
to pass-through) covers the "every vendor uses a different severity vocabulary" problem
without a full value-normalization system.

**No async job queue** (none exists anywhere in this codebase — confirmed zero
`threading` usage in `app.py`, and gunicorn runs with no explicit `--timeout`, so a
250MB file parsed synchronously in one request would risk the same worker-kill failure
mode a large SQL insert already has to avoid). Instead both slow phases are
client-driven and chunked: the browser calls `/normalize` and `/commit` repeatedly,
each call bounded and comfortably inside any reasonable timeout, with the loop itself
driving a real progress bar and getting a resumable operation for free. Both loops guard
against two tabs racing the same import via an optimistic-concurrency conditional
`UPDATE ... WHERE offset = ?` — a losing race gets a clean 409, never a silent
double-insert.

**A real bug caught by testing, not assumed**: the original design chunked CSV parsing
the same way as NDJSON (a resumable byte-offset cookie via `f.tell()`/`f.seek()`). The
very first fixture test against it raised a genuine `OSError: telling position disabled
by next() call` — Python's io module explicitly disables `tell()` on a text file once
its own `next()`/for-loop iteration has been used, which is exactly what
`csv.reader`/`csv.DictReader` do internally. CSV (and JSON-array, which has the same
"can't resume without a real streaming decoder" problem) are parsed in one single pass
instead, with their own smaller upload-time size caps (50MB / 25MB) — NDJSON is the one
format that gets true chunked resume, at a more generous 250MB cap.

**Log Search integration reused, not rebuilt**: a new `import` branch slots directly
into the `LOG_TYPE_BRANCHES` union architecture built for the Log Search timezone fixes
above — since `imported_logs.timestamp` is normalized to UTC at insert time (Python
`timedelta` arithmetic, never a client-influenced SQL expression — closes off a
SQL-injection-adjacent surface the field-mapping step would otherwise open, since a
mapping target has to be validated server-side against a fixed column whitelist before
it can be interpolated into an `INSERT`'s column list), it needs **zero changes** to
`_build_optimized_log_query`/`_build_normalized_log_union`/`_count_log_rows` — those
functions already treat any non-`'log'` branch as UTC-native. A new `import_id` column
threaded through `_UNIFIED_LOG_COLUMNS` and every existing branch (one line each) lets
the wizard's "Done" screen deep-link Log Search filtered to exactly the rows from one
import batch, with an explicit `range=all` so historical data — which by definition
usually predates Log Search's default 24h window — doesn't land on an apparently-empty
results page that reads as "the import silently failed."

**Permission**: new `logsearch.import.manage` key, gated on every route including GETs
(import history can carry sensitive customer-migration context in its labels/filenames
— this repo has hit the "GET route shipping with only `@login_required`" bug class
multiple times before, documented below). A new backfill migration grants it to any
role that already holds the sibling `logsearch.droprules.manage` permission — adding a
key to the permission registry alone does nothing for an *existing* production install,
since the default-role seed only runs once, on a fresh install with an empty `roles`
table.

**Abandoned imports are reaped automatically**: a new `_cleanup_stale_imports` sweep
(wired into the existing 30s scheduled-sweep endpoint, no new cron job) deletes any
import still stuck mid-wizard more than 48 hours after creation — otherwise a closed
browser tab mid-upload leaves an orphaned file on disk and a stuck history row forever.

### Log Search: fixed the mixed-clock `UNIFIED_LOGS_SQL` gap flagged below, plus a UTC/Local display toggle

Follow-up to the "Bigger, deliberately NOT fixed" gap flagged right below this entry
earlier the same day: `live_logs.timestamp` (local server clock) was being merged into
the same unified `timestamp` column as `alerts`/`events`/`agent_commands.queued_at`
(all UTC) across Log Search's 4 branches, corrupting chronological sort order and
date-range filtering whenever branches mixed.

**Backend** (`src/app.py`): split time-range filtering, cursor pagination, and row
counting into clock-aware variants — a local-clock version for the `log`/`log_archive`
branches, a UTC version (`datetime(?, 'utc')`, wrapping the bound *parameter*, never
the indexed column) for `alert`/`anomaly`/`command`. The `log`/`log_archive` branches'
final output is then converted to UTC in a cheap post-limit wrapper
(`datetime(timestamp, 'utc')`), so every row leaving `_build_optimized_log_query`
carries a genuinely comparable UTC `timestamp` regardless of source branch — sort,
range filters, and CSV/JSON export are all correct across mixed-branch results now.
Verified via a real `EXPLAIN QUERY PLAN` comparison that `live_logs`' index
(`idx_live_logs_timestamp`) is still used (`SEARCH ... USING INDEX`, not a full
`SCAN`) — wrapping the parameter instead of the column was the deciding factor, since
`live_logs` is by far the largest table (~150K rows/day in this instance, vs. the other
three branches' combined ~5,100/day). Cursor ("Load More") pagination got the same
clock-aware treatment so paging still doesn't drop or duplicate rows across branches —
7 real fixture tests cover chronological ordering, range filtering, row counts, and
2-page pagination with no drops/dupes.

**Frontend** (`templates/dashboard.html`): a UTC/Local toggle button next to the export
row (matching the existing "Log scale/Linear scale" toggle-label convention from the
Dashboards page), persisted per-viewer in `localStorage`. Since the backend now
guarantees every `log.time` value is real UTC, the Local mode conversion is a pure
client-side `Date` parse-and-reformat — no second server round-trip. The Time column's
header label reflects whichever mode is active. CSV/JSON export deliberately stays
UTC-only regardless of the toggle — exports are meant to be an unambiguous, canonical
record for another tool to consume, not a per-viewer display preference.

**Originally left out of scope, closed the same day** (see the entry above this one):
`api_logs_timeline` (the "Log Volume Over Time" chart) still queried the flat, unconverted
`UNIFIED_LOGS_SQL` constant directly, so its `GROUP BY` buckets could still silently mix
`live_logs`' local clock with the UTC branches. Fixed by a new `_build_normalized_log_union()`
helper (`src/app.py`) — the same per-branch clock-aware filtering + UTC normalization
`_build_optimized_log_query` already does, minus the LIMIT/cursor machinery a full
aggregate query doesn't need (a bucket has to see *every* matching row, not a top-K
subset). `UNIFIED_LOGS_SQL`/`UNIFIED_LOGS_SQL_WITH_ARCHIVE` (now genuinely dead — nothing
calls them any more) were deleted rather than left as an unused, misleading landmine.
The chart's card title now reads "(UTC buckets)" so the axis labels aren't a mystery.
5 new fixture tests cover: a log event and an alert 4 minutes apart landing in the
correct, adjacent UTC-hour buckets (plus a negative control proving the old flat union
really did misplace them, on a host with a non-UTC local clock); time-range filtering;
branch exclusion; and the shared app/severity/field filters still applying inside the
normalized union.

### Real pre-existing bug, found while live-verifying the timeline fix: `agent_commands.queued_at` is UTC, not local

Caught by generating a real Case Report PDF right after deploying the round-2 timeline
fix below and noticing two related timeline rows sitting ~4 hours apart. The fix
itself had assumed `command_result` items (`agent_commands.queued_at`) were local,
copying an existing-but-wrong comment from `api_agent_commands`'s GET handler. Checked
directly against `schema.sql` and every real `INSERT INTO agent_commands` call site:
`queued_at DATETIME DEFAULT CURRENT_TIMESTAMP` is never overridden anywhere, so it's
always SQLite's own UTC default — genuinely different from `completed_at`, which *is*
set via local `datetime.now()` in `api_agent_result`. Two real, live consequences of
the wrong assumption, both fixed:
- The Case Report timeline fix (below) needed `command_result` added to its UTC list —
  fixed before this ever reached production.
- `GET /api/agent/commands`'s `since_days` filter and `agent_checkins()`'s "requeue a
  command stuck on 'sent' for >5 minutes" safety net both compared a **local** cutoff
  against the UTC `queued_at` column. On this EDT (UTC-4) host, the `since_days` filter
  silently returned a wider window than requested (~28h for "1 day"), and the stale-
  command requeue effectively never fired within any reasonable time — a command stuck
  after a dropped connection could sit `sent` for ~4+ hours before ever being retried,
  not the intended 5 minutes. Both switched to `datetime.utcnow()`, verified with a
  real fixture reproducing the exact failure this runner's own non-UTC clock exhibited
  (the old cutoff logic missed a genuinely-10-minutes-stale row; the fixed one caught it).

**Bigger, deliberately NOT fixed in this pass**: this same investigation found that
`UNIFIED_LOGS_SQL` (the Log Search / unified-timeline view backing `_LOG_BRANCH_SQL` /
`_ALERT_BRANCH_SQL` / `_ANOMALY_BRANCH_SQL` / `_COMMAND_BRANCH_SQL`) merges `timestamp`
columns on two different clocks across its branches: `live_logs.timestamp` (local) sits
in the same unified `timestamp` column as `alerts.timestamp`, `events.timestamp`, and
`agent_commands.queued_at` (all UTC). This is a real, pre-existing architectural gap —
likely affecting Log Search's chronological ordering and date-range filtering whenever
log rows are merged with alert/anomaly/command rows — but Log Search is this
appliance's most heavily-used feature, and fixing it properly means auditing every
consumer of that unified `timestamp` column (sort order, range filters, exports), not
a quick swap. Flagged for a dedicated follow-up rather than a hasty fix in the middle
of an unrelated pass.

### Bug-hunt pass, round 2: the lower-priority findings from the earlier review

Follow-up to the previous day's 8-angle review — went through the findings that were
triaged as real but lower-severity, fixing the ones that held up and explicitly
declining the ones that turned out to already match this codebase's own established
conventions on closer look:

- **`generate_case_report`'s Incident Timeline sorted UTC and local timestamps
  together as raw strings.** Alert/UEBA-anomaly items and `case_events.ts` are UTC
  (SQLite `CURRENT_TIMESTAMP`-style columns — confirmed `events.timestamp` is UTC too,
  even though `ueba_engine.py`'s INSERT runs through a DuckDB connection: DuckDB has no
  native `datetime()` function, so that specific write is forwarded to SQLite's own
  engine on the attached table); EDR command-result and FIM-event items are local
  (Python `datetime.now()` at write time) — the same recurring mismatch documented
  elsewhere in this codebase. Normalized the UTC-sourced timestamps to local before the
  merge+sort, verified with a timezone-agnostic fixture test reproducing a real
  alert→FIM→containment→note→anomaly sequence.
- **A real forensic-accuracy bug** in the browser-artifacts SQLite parser
  (`agent_scripts.py`'s `Read-Record`): the overflow-payload-length formula substituted
  `X` (max local payload) where the SQLite file format spec calls for `M` (min local
  payload, a different, smaller value) — for a typical 4096-byte page this overestimated
  how many bytes are genuinely stored locally by roughly 2-3x (908 correct vs. 3153
  computed), risking misreading trailing overflow-pointer/adjacent-cell bytes as
  genuine URL/title text instead of correctly falling through to the existing
  `Overflowed=$true`/null safety path. Fixed to match the spec exactly (`M =
  ((usableSize-12)*32/255)-23`, `K = M + ((P-M) % (usableSize-4))`, clamped to `M` when
  `K > X`) — caught a second real bug fixing the first: PowerShell's `[int64]` cast
  *rounds* rather than truncates, so the initial fix needed `[math]::Floor` too.
  Verified directly in real PowerShell (not just Python simulation) against 5 cases
  including the `K > X` clamp branch, a zero-error AST parse of the actual deployed
  script, and a real end-to-end run against a genuine SQLite file with byte-perfect
  extraction of non-overflowing values.
- **`_run_due_log_source_silent_alerts`'s UNKNOWN-host grouping** could still collapse
  two genuinely different, both-unidentifiable sources (`host='UNKNOWN'` and a blank/
  NULL `app`) into one shared cooldown bucket, letting one mask the other going silent
  — the same masking risk the existing per-app disambiguation already guards against,
  one level deeper. Such rows are now excluded from the sweep entirely rather than
  merged.
- **`case_assets.confirmed_at`'s "stamp once, on first confirmation" rule** was
  duplicated across the create and update routes (the create path's copy was added
  later, in the same pass that first noticed it was missing). Consolidated into one
  `_confirmed_at_value()` both routes call.
- **`notifications.py`'s two email senders** (`_send_email` for alerts,
  `send_report_email` for report delivery) each had their own copy of the SMTP connect/
  TLS/auth/sendmail sequence. Extracted into a shared `_smtp_send()`; verified end-to-
  end against a real local SMTP listener (not mocked), confirming an actual message
  crosses an actual socket correctly.
- **Two redundant-query cleanups**: the DNS Activity dashboard widget's `total_queries`
  was a second full scan of the same filtered `live_logs` rows the volume-bucket query
  already covered (now derived as `sum(bucket counts)`); `api_dashboard_case_stats`'
  `closed_in_range` count and `avg_close_hours`/MTTR average were two separate scans of
  the identical `WHERE` clause (now one query, `COUNT(*)` + `AVG(...)` together).
- **The PDF case report's "Incident Timeline" header** lost its standalone linked-item
  count when Linked Items and Timeline were merged into one chronological list a few
  phases back. Restored as a breakdown alongside the combined total ("N total — N
  linked items, N analyst actions"), computed in the template from the merged list's
  own `kind` field — no new data needed.

**Explicitly left as-is, with reasoning**: the SLA-breach/-compliance loops in
`api_dashboard_case_stats` (and the pre-existing `_run_due_sla_breach_playbooks`) call
`_case_sla_hours_for` once per case rather than batching — a real N+1 shape, but this
codebase already has a standing, documented decision (the comment right above
`_run_due_sla_breach_playbooks`) that case-table volume on a single appliance is always
small enough for this not to matter; adding a batching resolver would be solving a
problem that doesn't exist here. `REPORT_TYPE_EMAIL_LABELS` being duplicated between
`app.py` and `generate_report.py` matches this exact file's own established, documented
"dual-definition config dict" convention (see `COMPLIANCE_FRAMEWORK_LABELS`/
`SCA_CHECK_FRAMEWORKS` two lines away) — not a bug, just the same pattern already
chosen deliberately for small catalogs shared between the Flask app and a standalone,
no-Flask-dependency script. The DNS server's thread-per-datagram design and
`generate_report.py`'s currently-unreachable (both real callers already clamp) `days`
parameter validation gap were left alone as genuine but out-of-scope architecture/
defense-in-depth questions, not live bugs.

## 2026-09-07

### Changelog rendering: bulleted list items that wrap across multiple source lines

Self-caught via this very entry, live, right after deploying the bug-hunt pass below:
`renderChangelogBody()`'s earlier paragraph-reflow fix (see the "own DNS server" entry
further down) only handled hard-wrapped *prose* paragraphs — a bulleted item that ALSO
wraps across multiple 2-space-indented source lines (CHANGELOG.md uses this pattern for
bullets too) had its continuation lines fall through to the plain-paragraph branch,
rendering as a stray unbulleted `<p>` disconnected from its own bullet. Fixed by giving
list items the same line-buffering treatment paragraphs already had. Verified against
the exact real bullet that exposed this, plus a regression guard for a real paragraph
correctly following a blank-line-separated list.

### Bug-hunt pass: stored XSS, 3 missing permission gates, and 3 smaller correctness fixes

An 8-angle multi-agent code review of this session's cumulative diff (everything since
the last reviewed commit — DNS server, case IDs, EDR custom commands, SOC metrics, the
changelog reflow and Vector race fixes) surfaced several real, independently-confirmed
issues, all fixed in this same pass:

- **Stored XSS** in the Dashboards DNS Activity widget's top-domains badges
  (`templates/dashboards.html`, `renderDnsActivityWidget`): a DNS query name — fully
  attacker-controlled, `src/dns_server.py` logs it verbatim with no label validation —
  was interpolated into a double-quoted `onclick` attribute with only the single quote
  escaped. A query name like `evil.com" onmouseover="alert(document.cookie)` (any
  device on the monitored network can trigger one just by resolving it) broke out of
  the attribute and injected arbitrary JS into an analyst's session on page view. Fixed
  with a proper two-stage escape (JS-string-escape, then HTML-attribute-escape) and
  verified end-to-end against the real function with the exact payload above.
- **Three GET routes missing the permission check their own POST/PUT sibling already
  had** — `/api/settings/dns-server`, `/api/settings/dns-server/interfaces`, and
  `/api/custom-parsers` — the exact recurring bug class this repo has hit before (a
  mutating route gated, its read-only sibling quietly shipped `@login_required`-only).
  Any authenticated low-privilege role could read fleet-wide DNS forwarder config,
  enumerate the appliance's network interfaces, or read every custom parser's regex
  pattern. All three now require `logsearch.droprules.manage`, matching their siblings.
- `src/dns_server.py`'s `_forward_query`: `sock` was referenced in a `finally` block
  before being guaranteed bound — if `socket.socket()` itself raised (fd exhaustion
  under load), the `finally` threw `NameError`, masking the real error and killing the
  per-query worker thread instead of falling through to the next forwarder.
- `templates/cases.html`'s `deleteCaseAttachment`: didn't check the response status, so
  deleting an attachment on a case someone else had just closed (a real 403) silently
  re-rendered the case as if nothing happened, attachment still present, no error shown.
- `templates/agents.html`: the endpoints table's error-state colspan was hardcoded to
  10 for an 11-column table (one column short) — cosmetic, but a real leftover mismatch
  from an earlier column addition.

### Four more SOC metrics: False Positive Rate, SLA Compliance, Reopen Rate, Escalation Rate, Dwell Time

Follow-up to the MTTD/MTTA/MTTI/MTTC/MTTR work below — added to the same "Case Metrics
& SLA" dashboard widget as a second "Additional SOC Metrics" row, all backed by data
already in the schema, no new columns needed:
- **False Positive Rate**: of alerts an analyst has actually triaged (`status` moved off
  the `'new'` default), the share marked `false_positive`. Untriaged alerts excluded
  from the denominator on purpose — counting an unlooked-at backlog as "not false
  positive" would understate the real rate.
- **SLA Compliance Rate**: of cases closed in the selected range, the share that closed
  within their own per-queue/per-severity SLA target — the historical complement to the
  existing `sla_breached_count` (a live snapshot of currently-open cases only).
- **Reopen Rate**: of cases ever closed at least once, the share ever reopened
  afterward. `cases.reopened_count` was added a few phases back specifically "for a
  future reopen-rate metric" (its own code comment) — this is that metric, finally built.
- **Escalation Rate**: of alerts fired in the range, the share ever linked into a case
  (`case_items` with `item_type='alert'`) — how often an alert actually becomes a real
  investigation instead of being triaged and closed at the alert level alone.
- **Dwell Time**: MTTD + MTTC summed client-side from the two already-fetched values —
  only shown when both have real data, since treating a missing one as zero would
  understate it rather than honestly showing "—".

Also fixed a real gap found while seeding demo data for these: adding a case asset as
already-`'confirmed'` (the one-step path, vs. transitioning an existing `'suspected'`
asset) never stamped `confirmed_at` — MTTC could never fire for that path. Fixed in the
same pass. Live-verified end-to-end with a real (labeled) test case: added a confirmed
asset, created a harmless throwaway file via a custom EDR command, quarantined it, then
closed the case — all 5 lifecycle tiles and this round's False Positive/SLA/Reopen/
Escalation/Dwell tiles populated with genuinely-computed (not fabricated) numbers.

### Case numbers, custom EDR commands from a case, and SOC lifecycle metrics (MTTD/MTTA/MTTI/MTTC/MTTR)

Three small-to-medium fixes/additions in one pass. **Case numbers**: cases only ever
showed a title, never their `id` — added a `#{id}` badge next to the title in the case
list, the case detail header, and the PDF case report's subtitle
(`generate_case_report`). Deliberately reused the existing raw autoincrement id rather
than inventing a formatted `CASE-2026-00147`-style scheme — there's no existing
convention in this app for that, and it's a bigger, separate decision if wanted later.

**Custom EDR command from a case**: the case detail "EDR Response" tab only offered the
canned action catalog (Isolate Host, Kill Process, etc.) — no free-text command like the
main EDR page's console has. Added a "Custom Command" entry that routes the typed value
into the request's `script` field (not `params`), matching exactly how the standalone
EDR console's free-text box already talks to `/api/agent/commands` — no backend changes
needed, since `_queue_agent_command`'s `'custom'` branch and the case tab's existing
result-linking (`case_items` → `agent_commands`) both already work generically.

**SOC lifecycle metrics**: added MTTD, MTTI, and MTTC to `/api/dashboards/case-stats`,
joining the already-shipped MTTA (`avg_tta_hours`) and MTTR (`avg_close_hours`) into one
"SOC Lifecycle Metrics" row on the Case Metrics & SLA dashboard widget.
- **MTTD** (detect): `alerts.timestamp` (UTC, sigma-engine insert path) vs. the
  triggering `live_logs.timestamp` (local) via the `event_id` FK — the two columns are on
  different clocks (the same recurring UTC-vs-local mismatch documented elsewhere in this
  codebase), so the query converts `alerts.timestamp` to localtime before diffing, and
  filters against a Python-computed local cutoff rather than SQL's own UTC `'now'`.
  Heuristic-path alerts (no `event_id`) are excluded — their alert/log timestamps are the
  same value, which would silently report ~0 latency instead of a real number.
- **MTTI** (investigate): first `case_events` `workflow_state_change → 'resolved'` row
  minus `acknowledged_at` — "time spent actively investigating, once started," using
  data this app was already recording.
- **MTTC** (contain): new `case_assets.confirmed_at` column, stamped once on the first
  `compromise_status → 'confirmed'` transition (same "local `datetime.now()`, set once"
  convention as `agent_commands.completed_at`, so the two compare directly with no
  timezone correction), against the first completed containment-flavored EDR action
  (isolate/kill/quarantine) linked into that *same case* for that *same host*.
- Real fixture-tested: correct averaging, correct exclusion of the heuristic MTTD path,
  correct "first event wins" semantics for MTTI/MTTC (a later duplicate doesn't skew the
  result), and a cross-case leakage guard for MTTC (a containment result linked into a
  *different* case must not count toward this case's confirmed asset).

### Micro DFIR's own DNS server, replacing the earlier dnsmasq/Technitium plans

After scoping a Technitium DNS Server integration (built, then removed once we decided
against it -- it needs a separate DNS App plugin just for query logging, a separate
service to run, and its own API to guess at), built our own small DNS forwarder +
query logger directly in this codebase instead (`src/dns_server.py`, using `dnslib` for
wire-format parsing so nothing hand-rolls DNS packet handling): a real UDP+TCP proxy to
real upstream resolvers (default 1.1.1.1/1.0.0.1), logging every query (client IP,
domain, record type, response code) straight into `live_logs` as `app='dns_server'` via
a batched background flush -- no external service, no separate API, no port/interface
guessing. Verified with a genuine end-to-end test: real UDP and TCP round trips through
the actual running proxy to real public resolvers, correct transaction-ID handling,
graceful survival of a malformed packet, and real rows landing in a real database.

Same opt-in safety philosophy as the dnsmasq tap it replaces (never binds `0.0.0.0`,
only enabled+configured explicitly) but config lives in Settings now (Log Pipeline > DNS
Query Logging), including a bind-IP dropdown built from the host's own real network
interfaces -- this appliance's main IP turned out to be on wifi, not ethernet, which is
exactly the kind of surprise that dropdown exists to prevent. A new DNS Activity view
shows recent queries with a best-effort host/user match against other recent activity
from the same IP (DNS itself carries no such identity, so this is an honest correlation,
not a guarantee), and a new Dashboards widget charts query volume over time, top queried
domains, and a real threat-intel-match count -- reusing the existing "Known-Bad IOC
Matched" Sigma rule's own `ioc_sightings` records rather than re-implementing detection.
`update.sh` now self-installs the new systemd unit on deploy (safe here since it's our
own code shipped through the already-sanctioned deploy script, not new third-party
software) -- no manual systemd setup needed. dnsmasq stays in place, untouched, as a
still-working fallback.

Fully live-verified on real production traffic after fixing two real bugs the rollout
itself surfaced: a `NameError` (`timedelta` used without its own local import -- this
file only imports `datetime` at module level, `timedelta` needs importing per-function,
per its own established convention) that 500'd the new dashboard route, and a missing
entry in the backend's own separate `WIDGET_TYPES` validation dict (distinct from the
frontend's `WIDGET_REGISTRY`) that silently reverted the widget on every page reload
even though it appeared to render fine. Real queries sent from an external client
resolved correctly through the live proxy, appeared in DNS Activity with a correctly
resolved host (matched against this same appliance's own EDR data), and the dashboard
widget's volume/top-domains data persisted and rendered correctly after a fresh reload.

### Cases: tabbed case detail view + metric tiles on the list page

The case detail view's right column had grown to 11 stacked cards (Items,
Related Items, Related Cases, Threat Intel, Assets, EDR Response,
Indicators, Attachments, Analyze, Report, Timeline) plus Tasks on the
left -- too much on one side, too much scrolling. Case info now sits
full-width at top; everything else is a tab below it. Same element IDs,
same load/init calls, purely a layout move. The Cases list page also
gained 4 metric tiles at top (Open Cases, SLA Breaches, Closed (30d), Avg
Time to Close), reusing the existing `/api/dashboards/case-stats`
endpoint the Dashboards page's own Case Stats widget already calls.

### Technitium DNS Server integration (opt-in, alongside dnsmasq for now)

Polls Technitium's HTTP API (once its "Query Logs (Sqlite)" DNS App is
installed) every ~30s from sigma_engine.py's existing loop and writes new
query rows directly into `live_logs` as `app='technitium'` -- richer than
dnsmasq's single regex-parsed line (client IP, qname, qtype, protocol,
rcode, response type, RTT). Bypasses Vector entirely since Technitium's
API is JSON+pagination, not a flat file to tail. Config (API URL/token/
app name/class path) lives in Log Pipeline > DNS Query Logging, with a
Test Connection action that shows the raw API response -- this appliance
had never run a live Technitium instance when this was built, so the
poller parses defensively and records a clear diagnostic status rather
than guessing at an unconfirmed response shape. dnsmasq is untouched and
still active until Technitium is confirmed working end-to-end.

### Settings > Changelog: two-column layout + search

Redesigned from a single scrolling column of markdown headers into a
table: a narrow left column (date + entry title) aligned against a wide
right column (the entry's body), plus a search box that filters entries
and highlights matches. Also fixed a real rendering bug found along the
way -- `escHtml`'s `innerText`/`innerHTML` round-trip silently converts
every newline into a `<br>`, so escaping the whole file before splitting
on `'\n'` found no newlines at all and collapsed the entire changelog
into one mis-classified heading.

### Custom Parsers editor: live extraction preview + pull a sample from Log Search

The pattern editor (Log Pipeline > Parsers) now shows which fields a regex
would extract, live, as an admin types it — against a "Sample Log" box
that can be hand-pasted or pulled from a real recent log via a new small
picker (`GET /api/custom-parsers/sample-logs`). The live check runs
through the same server-side Python `re` engine production uses (a new
`sample_text` option on `POST /api/custom-parsers/preview`), deliberately
not a client-side JS-regex approximation — Python's `(?P<name>...)` named-
group syntax has no safe 1:1 JS equivalent, and this app's own convention
is a preview should never risk "lying" about what production would
actually do. "Test against recent logs" and Add Parser are unchanged.

### Real Chrome/Edge browser-history parsing in `collect_browser_artifacts`

The EDR "Collect Browser Artifacts" action used to only hash and
timestamp `History`/`places.sqlite` files, never read what was
actually inside them. It now parses Chrome/Edge's `History` SQLite
file for real — url/title/visit_count/last_visit_time — via a
from-scratch, dependency-free SQLite B-tree/record-format reader
written in PowerShell (no `System.Data.SQLite`/ODBC provider exists
on a vanilla Windows endpoint). The file is copied first to avoid the
browser's exclusive lock, and the scan reads the most-recently-created
600 rows per file (a performance cap — byte-level decoding in
interpreted PowerShell runs ~0.03s/row, so an uncapped scan of a large
real-world History file would blow past the agent's 180s command
timeout) walked from the highest rowids down, since insertion order
(not last-visit time) is what on-disk row order actually reflects —
reading low-to-high would surface the *oldest* URLs first. The 100
most recent of those are returned. Firefox's `places.sqlite` uses a
different schema and stays metadata-only (hash + timestamp) as
before — collect the file directly for offline analysis. Verified
against a real 45MB production-scale History file (not just a
synthetic fixture): full run across 2 users' Chrome/Edge/Firefox
profiles completed in ~40s, and the parsed output correctly showed
genuinely recent real browsing activity in the right order.

### Reports page reorganization: PDF Report Branding + Report Schedule moved out of Settings

Both used to live in Settings > Reports, the one settings tab visible
to every role regardless of permissions (since it had no gate of its
own). Moved to two new tabs on the Reports page itself (Reports /
Branding / Schedule), which is where an admin actually goes to work
with reports. Settings no longer has a Reports tab; a role with none
of the remaining tab permissions (e.g. the base Analyst role) now sees
an explicit "no accessible settings" message instead of a blank card.

### EDR response-action history filters + fleet version-compliance note

Response Actions history was a flat, hard-capped last-50-rows list
with no status or date filter. Added status/since_days params to
`GET /api/agent/commands` and matching dropdowns on the Agents page;
the 3 stat tiles stay fleet-wide totals even while the table is
filtered. Also surfaces a "N of M hosts behind the newest agent
version" note directly on the Agents page, reusing the Dashboards
"Agent Fleet Health Trend" widget's own data (no new backend logic).
While wiring that endpoint into a new surface, fixed the same local-
time-vs-UTC drift bug already caught in `_run_due_log_source_silent_alerts`
— `agent_polls.timestamp` is local server time, but the query compared
it against SQLite's UTC `'now'`. Live-verified the status filter
against 6 real failed actions across the real fleet.

### Click-through drill-down on 3 dashboard charts

None of the 24 dashboard widget types had any click-through from the
chart itself into the underlying data. Added it to the 3 widgets with
a clean categorical dimension: Severity Breakdown → Log Search filtered
by that severity; Top-Firing Anomaly Rules → a free-text Log Search
pivot on the rule name; Open Cases by Queue → the Cases page filtered
to that queue (new `?queue=<id>` deep-link, mirroring the existing
`?case=<id>` one). Time-bucketed trend charts (Alert Volume, Risk
Score, etc.) were left alone — there's no precise date-range deep-link
into Log Search yet to click through to, and landing on an approximate
day would be worse than no drill-down. Live-verified all 3 against
real production data, including confirming the Cases page's queue
filter dropdown and table both correctly apply from the URL param.

### Dashboard widget edits now protected on shared role-default dashboards

Adding/removing/rearranging dashboard widgets was deliberately open to
any logged-in user (matching how case items/tasks work), but that
design predates per-role default dashboards — once a dashboard is
assigned as an entire role's default view (`roles.default_dashboard_id`),
any click there silently changes what everyone with that role sees, not
just the editor's own. Narrowed precisely: only gated when the target
dashboard IS currently a role's default, same creator-or-admin rule the
dashboard's own rename/delete already enforced — an ordinary personal/
team dashboard stays exactly as open as before. Frontend mirrors this
proactively (Add Widget/Edit Layout hidden with a "Shared default —
read-only" note) instead of letting a non-owner drag widgets around and
hit a 403 on save.

### Report email delivery + daily schedule option

SOAR playbooks and alert notifications have had real, working SMTP
infrastructure (`src/notifications.py`) for a while, but generated
reports had zero delivery mechanism beyond logging in and downloading —
a scheduled report just sat on disk with nobody notified. Added
`notifications.send_report_email()` (the first sender in this codebase
to build a `MIMEMultipart` message with a PDF attachment — the existing
senders only ever built plain text), a global "Email Recipients" field
next to the existing per-report-type schedule dropdowns (Settings >
Reports), auto-email on every scheduled (not manual) report completion,
and an on-demand "Email" button next to Download in the Reports history
table for sending any already-generated report regardless of the
schedule. Also added `daily` as a third schedule frequency (05:00)
alongside weekly/monthly. Live-verified the full pipeline end to end
(recipients config → send route → SMTP attempt); a real delivery
couldn't be confirmed since this appliance has no SMTP server
configured, but the failure surfaced the exact expected, correctly
worded error rather than failing silently or opaquely.

### EDR response actions from within a case

An analyst had to leave a case, go run something from the separate
Agents page, then manually remember to come back and note what they
did — the existing per-row Isolate/Kill icons on Case Assets only
dropped a plain text note, not the actual command output. Now:
`queueCaseAssetCommand` links the resulting `agent_commands` row into
the case as a real `command_result` item instead of a static note (no
backend change needed — `CASE_ITEM_TYPES`/`_case_item_summary` already
fully supported this item type, including a live status/severity
summary and a "View Full Result" button; it just wasn't wired up from
this call site). New "EDR Response" card in the case detail view: host
picker scoped to the case's own tracked assets, and a much fuller
action catalog (isolate/restore, kill process by PID or name,
quarantine/collect a file, registry key, scheduled task, triage
collection, persistence sweep, network connections, live forensics,
etc.) mirroring the Agents page's own console dropdown, filtered by OS
and by the same `edr.command.basic`/`edr.command.advanced` permissions
already enforced there — no new permission key, no new approval gate
(the existing manual Agents-page path is itself immediate/ungated, so
this matches it rather than introducing an inconsistent new flow).
Live-verified end to end against a real enrolled agent: queued
`list_processes` from a case, watched the item go from "pending" to
"Completed successfully" after the agent's real next check-in, and
confirmed the actual process-list output rendered in the case's
existing Response Action Result modal.

### Case attachments

Cases had no way to attach a file — a screenshot, an exported log bundle,
a memory-dump excerpt, a signed acknowledgement doc — flagged as the
biggest genuine feature gap in the DFIR-lifecycle audit below. New
`case_attachments` table + upload/list/download/delete routes, following
the same `_require_open_case` + `_log_case_event` pattern every other
case sub-resource already uses (no new permission key — ordinary case
mutations carry none today). Uploads are stored under a random on-disk
name, never the client-supplied one, and always served back with
`as_attachment=True` — deliberately not extension-restricted, since a
case attachment may legitimately BE a malware sample or suspicious
script kept as evidence; forcing a download instead of an inline render
is what neutralizes that risk. 25MB per-file cap (no existing precedent
in this codebase to match against). Two real bugs caught during live
verification and fixed same-session: upload/delete only refreshed the
attachments list, so the resulting Timeline entries never appeared until
the analyst navigated away and back; and those entries rendered as a raw
`attachment_added`/`attachment_removed` string instead of a formatted
label with the filename, unlike every other case event type.

## 2026-09-06

### Full-lifecycle DFIR audit: triage, case reports, and SOAR automation gaps

Audited the actual analyst workflow end to end (ingest → analyze → investigate
→ automate → report) for real friction, not speculative features, then fixed
the highest-value findings:

- **Triage didn't acknowledge** — the primary alert-triage form (`saveTriage`)
  never sent `acknowledged`, unlike the Home widget's quick-ack button. Every
  alert an analyst properly triaged through the actual triage UI stayed stuck
  in the "unacknowledged" count forever and kept resurfacing on the dashboard's
  unacknowledged-alerts widget. Now any explicit triage save acknowledges.
- **No way to search/sort/see alert status or assignee** — both were selected
  in every Log Search branch but absent from the query-language field list and
  the results table entirely. Added `status`/`assignee` to the searchable
  field allowlist (`status:new`, `assignee:alice` now work) and as real,
  opt-in, sortable columns in the results table.
- **Case reports were missing Assets and IOCs, and had two disconnected
  timelines** — `generate_case_report()` never queried `case_assets`/
  `case_iocs` (the two most actionable deliverables in a DFIR handoff,
  despite both being fully queryable already), and "Linked Items" (ordered by
  when added to the case) and "Timeline" (analyst actions only) never told
  the actual story of what happened, in order. Added both missing sections
  and merged items+events into one real chronological Incident Timeline.
- **`alert_created` playbooks could only condition on severity** — made
  "notify the team when Impossible Travel fires" impossible without also
  catching every other same-severity alert, including pipeline-health noise
  (Host Silent, Agent Offline). Added an exact-match rule-name condition,
  composable with the existing severity threshold, backed by a real
  ground-truth dropdown of rules that have actually fired.
- **No lightweight way to auto-suppress or auto-assign an alert** — the only
  path to touching an alert's status/assignee from a playbook was the
  heavyweight `create_case`. Added `set_alert_status` (also marks the alert
  acknowledged) and `assign_alert` as alert-scoped actions, composing with
  the new rule-name condition above.
- **No way to pivot from a host/user/IP/IOC into "show me everything else this
  did"** — the URL-prefill machinery only existed for one hardcoded case
  (MITRE Coverage's alert deep link); an analyst had to copy a value out and
  build the search by hand. Generalized to a plain `?q=` param any page can
  use, added a global `pivotToLogSearch()` helper, and wired it into the
  alert detail modal (Host/User/Src IP/Dest IP are now clickable) and case
  assets/IOCs (a "Search logs" button per row, type-aware for IOCs — hash
  searches `file_hash`, an IP searches both `source_ip` and
  `destination_ip`, a domain searches `query_name` and `message`).
- **Log Pipeline's stat tiles showed config counts, not ingestion health** —
  "Active/Total Drop Rules" and a hardcoded "6" for total channels, zero
  volume/source-count/last-event-received. An admin landing here to answer
  "is ingestion actually working" got a different question answered. New
  `/api/log-pipeline/ingestion-health` gives real Sources Ingesting /
  Events-per-Hour / Last Event Received tiles. Caught and fixed a real
  performance bug before it shipped for good: the first rowid-bounded design
  (`ORDER BY id DESC LIMIT 1 OFFSET N`) measured **20 seconds** live on this
  app's real 6.2M-row table — OFFSET reads and discards N full rows (some
  carrying large uncapped TEXT blobs) before returning the target one. Fixed
  by computing the boundary row's id directly and looking it up with
  `WHERE id <= ?` (a single B-tree seek reading exactly one row regardless of
  N) — confirmed live afterward at ~400ms on cache-hit.
- **Reports had no discoverable home** — 17 real generated PDFs sat behind a
  SIEM sub-tab an evaluator would never think to check. First attempt only
  added a second nav entry point into the same SIEM tab strip, which the
  user correctly flagged as not a real fix — reworked into a genuine
  extraction (`templates/reports.html` + `/reports` route), the same
  pattern already used to split Coverage out of SIEM earlier this session.
  SIEM's tab strip is now just Log Search / Detection Rules / Detection
  Tuning; old `?tab=reports` bookmarks redirect to the new page.
- **Agent heartbeat and log ingestion were indistinguishable** — the Agents
  page could only show "checking in fine" (`agent_polls`); an agent whose
  log shipping silently broke (bad channel config, EDR service crashed)
  looked identical to a healthy one. Added a "Last Log Received" column
  sourced from `live_logs`, with a warning when a checked-in host has never
  sent a single log. Point-lookup per visible host (`ORDER BY id DESC LIMIT
  1` riding the host index's rowid ordering, confirmed via `EXPLAIN QUERY
  PLAN`) rather than `MAX(timestamp)`, which would force a full scan of
  every row for that host on this app's 6.2M-row table.
- **An analyst had to separately check Threat Intel, EDR Agents, and UEBA**
  to tell whether a given alert's host/IP was actually notable. Added an
  enrichment card to the alert detail modal: threat-intel verdict for
  source/destination IP, asset criticality above standard, and UEBA risk
  tier/score for host and user — each shown only when there's a real signal
  (a "Low" risk tier is the server's always-on default for a zero score,
  suppressed rather than shown as noise on every alert).
- **A specific log channel going dark on an otherwise-healthy host was
  invisible** — "Host Silent" only ever detected a host going completely
  dark; one channel stopping (EDR service crashes, Sysmon service stops)
  while the rest of the host kept logging fine went unnoticed. Added "Log
  Channel Silent", reusing the identical adaptive per-source threshold
  math, scoped to (host, app) pairs and gated on the host having logged
  something from another source very recently — proof it's a real
  per-channel gap, not a duplicate of a host-wide outage the existing check
  already catches. While writing the fixture test, found and fixed a real,
  already-shipped bug in the existing check: `live_logs.timestamp` is local
  server time, but the query compared it against SQLite's own UTC `'now'`
  literal — on this appliance's `America/New_York` server that silently
  inflated every silence figure by ~4-5 hours, firing alerts prematurely.
  Verified directly: a real 5-hour gap computed as 9 hours by the old
  query, 5 hours by the fixed one.
- **Reports had no discoverable, real lookback control** — Security
  Summary, Audit Trail, and the per-framework Compliance report all
  hardcoded a 30-day window. Added a Lookback select (7/30/90/180 days) on
  the Reports page, threaded through `generate_report.py`'s `run_report()`
  into every windowed query and PDF narrative section; the Vulnerability
  Report (a live snapshot, not a rolling window) hides the control rather
  than pretending to accept it. Caught and fixed a real falsy-zero bug
  while writing the fixture test: `days or 30` would silently treat an
  explicit `days=0` as "unset" instead of clamping to 1.

### Closed the standing gap-list: SLA tiers, password strength, agent recovery, revert cancel

Worked through the 5 items flagged in an earlier gap-analysis pass but not yet built:

- **Sigma/UEBA auto-case → SOAR playbook wiring** — turned out to already be fixed (the
  `case_playbook_outbox` bridge table), no work needed. Verified directly against source
  before crossing it off rather than trusting the stale gap list.
- **Per-severity/per-queue SLA tiers** — `case_sla_hours` was one global threshold; a
  queue can now set its own `sla_hours` override (wins if set), and a
  `case_sla_hours_by_severity` JSON setting adds per-severity tiers, both falling back to
  the existing global default. `_case_sla_hours_for(db, queue_id, severity)` is the one
  place this resolves; the SLA-breach sweep and dashboard widget both switched from a
  shared SQL threshold to resolving each case's own. Caught a real regression risk before
  shipping: the dashboard widget's existing Save button only ever sends `{sla_hours}`
  with no knowledge of tiers, so a naive "empty means clear" rule would have silently
  wiped out tiers on every ordinary save — fixed by checking the *key's presence*, not
  its truthiness, the same convention already used for TLP elsewhere in this app.
- **Admin password-strength validation** — `api_settings_users()`'s create/reset routes
  had zero validation; an empty or 1-character password silently became a working login.
  Now enforces the same 8-char minimum the self-service `/change-password` route already
  had, via a shared `MIN_PASSWORD_LENGTH` constant.
- **Agent "back online" recovery notice** — `agent_offline_alerts` was append-only, so a
  recovered host left no signal in the alert feed. Added a nullable `resolved_at` column;
  when a previously-alerted host's check-in age drops back under the online threshold, an
  "Agent Back Online" (INFO) alert fires and every outstanding unresolved row for that
  host is resolved together.
- **isolate_host auto-revert manual-cancel** — a scheduled network restore
  (`playbook_pending_reverts`) had no visibility or cancel path until it came due; the
  only existing cancel was rejecting the approval *after* the timer expired. Added a
  "Scheduled Reverts" card on the SOAR page with a Cancel button, backed by a
  TOCTOU-safe `WHERE status='pending'` compare-and-swap.

### Log Pipeline: Parsers tab (Vector reload safety + custom field extraction)

Built out the Log Pipeline page with a parser manager, in the spirit of Exabeam's Parser
Manager / Cribl-style enrichment, after research established that Vector does almost no
parsing (a near-pure syslog/dnsmasq pass-through) while Python's `api_ingest()` does
nearly all real field extraction, and that EDR agents bypass Vector entirely — so new
custom parsing belongs server-side in Python, not in Vector/VRL.

- **`generate_vector_config()` now validates before applying** (`vector validate` against
  a candidate file, only writes/reloads the live config on success, verifies
  `systemctl is-active` afterward, records status to `settings`) instead of writing
  straight to `/etc/vector/vector.toml` and reloading blind — closes a real incident
  class where a bad config left Vector silently serving its stale previous config.
- **New `custom_parsers` table + CRUD/dry-run routes**: admin-defined Python regex field
  extraction, scoped by app, tested against real recent logs before saving.
- **New "Parsers" tab**: Parser Catalog (4 built-ins + custom parsers, with a
  recent-sample extraction rate each), Custom Parsers CRUD, Pipeline Health (Vector
  config status).
- **`destination_ip` finally populated** — the column existed since an earlier migration
  but nothing ever wrote to it; Sysmon Event ID 3's `DestinationIp:` label is now parsed
  the same way `Image:`/`CommandLine:` already were.
- **Two real bugs caught live, in production, before this was called done**:
  1. The Parser Catalog's health query filtered on `timestamp >= now() - 24h`, which took
     **93 seconds** on this instance's real 6.2M-row `live_logs` table (confirmed via
     direct timing) — neither the app nor timestamp index alone avoids a large scan once
     combined. Fixed by bounding every query to `id > (MAX(id) - 50000)` instead (a cheap
     rowid range) — the same query dropped to 1.5s, independent of table size.
  2. A custom parser targeting `username`/`severity`/`event_id`/`source_ip` was silently
     inert — `api_ingest()`'s INSERT never read those 4 keys back out of the gap-filled
     extraction dict, only the process/XML fields. A first fix attempt (gap-fill only
     when the built-in value was a placeholder) was *also* wrong: Windows Security 4688
     events always resolve their top-level username to a real-but-generic value
     ("SYSTEM"), never the placeholder, even though the actual acting user is in the
     message body (`Creator Subject: Account Name: ...`). Since these 4 fields have no
     genuine built-in *extractor* to protect (unlike `process_image`/`command_line`,
     which Sysmon/auditd parsing actually derives from content), a matching custom parser
     now unconditionally overrides them — verified live: a real "Security 4688 acting
     user" parser now correctly overrides "SYSTEM" with the real actor ("noslo") while
     correctly leaving distinct machine-account/local-service events alone. Kept in
     production as a genuinely useful parser, not deleted as test data.

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
