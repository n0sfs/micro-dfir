# Micro DFIR

A single-box SOC appliance: SIEM + EDR + UEBA + SOAR + Threat Intel + Case
Management, running on one Linux host (production hostname `n0snuc`,
`192.168.86.100:5001`). See [README.md](README.md) for the feature summary
and RBAC role table.

## Architecture

- **`src/app.py`** is the Flask monolith (~8,700 lines) serving every page
  and API route. `DB_PATH = /opt/micro-dfir/siem.db` — one SQLite database
  for everything (cases, alerts, UEBA, SOAR, threat intel, settings).
- Two more long-running processes, each its own systemd unit
  (`config/microsoc-*.service`):
  - `src/sigma_engine.py` (`microsoc-sigma`) — Sigma rule matching against
    incoming logs, plus a background loop that polls
    `POST /api/internal/run-scheduled-playbooks` every ~30s for SOAR's
    scheduled-trigger playbooks.
  - `src/soar_engine.py` (`microsoc-soar`).
  - `microsoc-web` runs the Flask app itself (gunicorn).
- `src/ueba_engine.py` is a standalone cron-invoked scoring engine, not a
  long-running service.
- Vector (`config/vector.toml`) handles log ingestion into SQLite.
- `templates/*.html` are server-rendered Jinja2 pages, each a large
  self-contained file (HTML + inline `<script>` with the page's JS — no
  frontend build step, no cross-template JS imports). Small catalogs/consts
  (e.g. column lists, badge-color maps) are deliberately duplicated per file
  rather than shared, matching the existing pattern — don't introduce a
  shared-import mechanism to "fix" this.
- `agents/` holds the Windows/Linux EDR agent scripts the appliance manages
  remotely.

## Deployment

Production only updates via the pinned deploy script — there is no other
sanctioned path to ship a change:

```bash
git push
ssh n0s@192.168.86.100 "sudo /bin/bash /opt/micro-dfir/update.sh"
```

`n0s` has passwordless sudo scoped to that exact command only. `update.sh`
pulls `main`, rsyncs to the production path, installs any new Python deps,
and restarts the three services. Always commit + push + deploy after a
change lands — don't wait to be asked. Never attempt other sudo commands on
that host; if something needs more than `update.sh` covers, ask the user.

## Testing standard for this repo

There's no CI here — verification is manual but real, every time:

1. **Compile-check every touched template** through a real Jinja2
   `Environment` before deploy.
2. **Syntax-check every touched `<script>` block**: extract inline scripts,
   stub `{{ }}`/`{% %}` Jinja tags with harmless placeholders, run
   `node --check` on the result.
3. **Write real SQLite fixture tests for backend logic** — an in-memory or
   tempfile `sqlite3` connection with the actual table schema, a faithful
   line-for-line port of the route/function logic under test (Flask route
   code usually can't be imported standalone), and assertions against real
   query results. Not mocks.
4. **Write isolated Node `vm`-context tests for frontend JS logic** — extract
   the function/template-literal source out of the `.html` file with a
   regex, run it in a `vm.createContext` sandbox with stubbed
   `document`/`fetch`/etc., assert on behavior. Note: a top-level
   `const`/`let` evaluated via `vm.runInContext(code, sandbox)` does **not**
   attach as an enumerable property on `sandbox` — read it back with a
   second `vm.runInContext('CONST_NAME', sandbox)` call.
5. **Live-verify on production** after every deploy, using the browser
   session already logged into `https://192.168.86.100:5001` — exercise the
   actual golden path and edge cases, then clean up any test data created
   (test cases, feeds, playbooks, etc.) before finishing.

Known browser-automation quirk (not a product bug): a cached element
reference can silently no-op if the DOM re-rendered since it was captured
(e.g. a `<select>`'s `onchange` handler swaps out a sibling element). If a
click via `ref` doesn't produce the expected network request, retake a
screenshot and click by coordinate instead of assuming the app is broken.

## Domain conventions

- **RBAC is permission-based, not a tier ladder** — a role is a set of
  permission keys (`role_permissions` table) checked server-side via
  `require_permission(key)` in `src/app.py`; `hasPermission(key)` in
  `templates/base.html` only mirrors this to hide UI, never to enforce it.
  Three built-in roles (`analyst`, `senior_analyst`, `admin`) ship by default
  and can't be deleted, but their permissions can be edited; `admin` can
  never lose the two user/role-management permissions.
- **UI-only merges over schema merges**: when two fields look redundant in
  the UI (e.g. case `status` open/closed next to `workflow_state`
  new/investigating/awaiting_input/resolved) but one is wired into
  automations/queries elsewhere (SLA breach queries, SOAR
  `condition_status` filters, dashboard sorts), default to merging them
  **visually in the UI only** and leave the backend schema/fields untouched.
  A real schema merge is higher-risk for what's usually a cosmetic
  complaint.
- **Case Resolved vs Closed** (DFIR-standard, informs any future
  case-lifecycle work): *Resolved* = the technical investigation/remediation
  is done (investigator-determined; case may still be open administratively).
  *Closed* = the formal administrative closing of the case file (often
  read-only in mature platforms; can typically still be reopened if new
  evidence surfaces). Today, closing a case (`status='closed'`) auto-sets
  `workflow_state='resolved'` unless the caller explicitly specified one —
  directionally correct, but `closed` carries no extra semantics yet (no
  read-only enforcement, no distinct reopen flow). Not scoped to build.
- **TLP/PAP are optional, not defaulted**: both fields store `''` (empty
  string, not NULL — schema stays `NOT NULL`) to mean "not assessed yet",
  distinct from an explicit `'clear'` classification. Validation treats
  empty as a pass-through exception (`if tlp and tlp not in
  CASE_TLP_VALUES`). When touching this validation, preserve the
  key-presence check (`'tlp' in data`) over a truthiness check (`data['tlp']`)
  — the latter silently drops an explicit "clear this field" submission.
- **Dual-definition config dicts**: some tunables (`UEBA_DEFAULTS`/
  `UEBA_CONFIG_DEFAULTS`, `RISK_SCORE_DEFAULTS`) are independently
  maintained in both `src/app.py` (Flask routes) and `src/ueba_engine.py`
  (standalone cron script, no shared import). Adding a new tunable means
  updating both.
- **Data-driven UEBA points editor**: `templates/ueba.html`'s
  `DYNAMIC_SCORING_FIELDS` array drives the whole points-editing UI and its
  JSON sync — add a new scoring key as one array entry, not new rendering
  code.

## What not to do

- Don't add a frontend build step, bundler, or cross-template JS import —
  the codebase is deliberately server-rendered, per-file self-contained
  templates.
- Don't run destructive git operations or sudo commands beyond
  `update.sh` on the production host without explicit confirmation.
- Don't skip the live-verification step for UI changes — type-checking and
  fixture tests confirm the code is correct, not that the feature works.
