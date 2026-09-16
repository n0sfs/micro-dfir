# Changelog

A dated, narrative record of what's been built and why — kept because memory notes and
plan files are ephemeral, but this file lives in the repo and travels with the code.

**Convention**: add an entry here for anything a future reader would want to know about —
a new feature, a real architectural decision, an incident and its fix. Routine polish/typo
fixes don't need their own line; group them into the feature they support. Newest first.
Full commit-level detail is always available via `git log`.

## 2026-09-16

### The manual log purge could never have worked at the size it was needed

`/api/settings/purge` was one unbounded `DELETE FROM live_logs WHERE timestamp < ?`.
gunicorn runs here with **no `--timeout`**, so the 30-second default applies, and `live_logs`
has reached ~6.5M rows. A purge covering millions of them cannot finish in that window: the
worker is killed mid-statement, the entire transaction rolls back so **nothing is deleted**,
and the exclusive write lock it held throughout blocked live ingest for no benefit. The
failure mode scales with how much there is to delete — it breaks precisely when it's needed.

Now bounded per call (100k rows, `done` flag) with the button driving a loop and showing a
running count — the same chunked-endpoint shape Log Import already uses, and the one
CLAUDE.md prescribes for work too slow for one request.

Worth recording alongside it: **the database is 21.8 GB across ~6.5M rows — about 3.4 KB per
row.** Volume is flat at 270k–420k logs/day across the whole retention window; there is no
historical spike to blame. The per-row size is the actual driver, and `raw_xml` capture is
most of it. Deleting history buys a one-off reduction; reducing what's stored per event is
what changes the trajectory.

### Closing the "never matches" list: anchor unmapped fields to their rendered label

**30 of 119 enabled rules → 2.** The 30 came from the review below: `live_logs` is a flat
table, so a Sigma field with no column falls back to the free-text `message`, and an *exact*
comparison compiled to `message = '0x1410'` — a test against the entire rendered event body,
never true.

Those comparisons are now anchored to the field's own rendered label. Windows and Sysmon
both render an event as one `Label: value` pair per line — the same convention this app's
ingest-time extractors already rely on — so `GrantedAccess: 0x1410` becomes
`message LIKE '%GrantedAccess:_0x1410%'`, scoped to that field's own line instead of hunting
the value anywhere in the event. Both label spellings are emitted, unsplit and space-split,
so Sysmon's `GrantedAccess:` and Security's `Logon Type:` are both covered without a
per-field table of which renderer does which.

**The separator is a bounded run of single-character wildcards, not an open `*`, and that
distinction is load-bearing.** The first version used `%Logon Type:%3%`, which matched a
Logon Type **10** event — because a Logon ID of `0x3E7` appears further down the same
message. Caught by testing against a real 4624 body rather than a convenient one. With the
bounded gap, `LogonType: 10` matches and 3, 9 and 2 do not.

Limited to exact literals on purpose. A value that already carries a wildcard
(`|contains`/`|startswith`/`|endswith`) is untouched — those rules *do* match text today, and
re-anchoring could silently stop one firing on a channel that doesn't use the label
convention. This only ever touches comparisons that currently match nothing, so it cannot
take a working detection away.

The two rules still reported as never-matching are a different shape entirely: `SidHistory:
null` and `LogonId: null` are *field-absence* tests, which become `message IS NULL` against a
NOT NULL column. No field mapping fixes that; it needs a real column. The rest are now
reported as **text-matched**, with the honest caveat that a rule whose log source isn't
ingested at all still cannot fire — the Coverage page reports those separately.

### The alert dedup window never worked on the heuristic path — a timezone bug

Found by watching the appliance immediately after deploying the review below: **30+
identical "System Discovery Commands" alerts inside a single minute, every one with
`occurrence_count: 1`**.

(An earlier draft of this entry said the alerts table had "reached ~882,000 rows". That was
wrong — 882,000 was the maximum `id`, and `alerts.id` is `AUTOINCREMENT`, which never reuses
a value after a delete. The table actually holds ~33,000 rows. The bug and its fix are
unaffected; the size claim was not.)

The inline heuristic path stamped a new alert's `last_seen` with the event's own `ts` —
which for Windows is the agent's `TimeCreated`, the **endpoint's local time** — and then
deduped against `effective_seen >= datetime('now', '-15 minutes')`, which SQLite evaluates
in **UTC**. At UTC-4 every alert was born already looking four hours old, so the 15-minute
window could never contain it, and every single heuristic match inserted a new row instead
of bumping a counter. It also quietly cut heuristic alerts out of the cross-rule escalation
sweep, which selects on that same window.

`last_seen` is now `datetime('now')` on insert — the SOC's own clock, which is what this
path's own UPDATE branch and `sigma_engine.py`'s alert path always used, and exactly why
only these rows multiplied. `timestamp` still carries the event's reported time.

Verified live: in the five minutes after the deploy the maximum alert id **did not move at
all**, while two rows (one per host) climbed from 18 to 156 and 159 occurrences. The same
315 events would previously have been 315 new rows. Existing rows were left alone —
they're real alert history, and collapsing them is a data decision, not a code fix.

### Detection review: six silent failures in the SIEM rule engine

A two-pass review of the Sigma engine and the ingest-side detection path. Everything here
shares one property, which is why none of it had ever been noticed: **nothing threw**. A
rule showed as enabled, ran on every cycle, counted toward MITRE coverage, and detected
nothing. `run_detection_cycle()` only logs rules that raise, so a rule that compiles to
SQL which simply can't match is invisible by construction.

**Keyword rules could never match.** A fieldless Sigma search — `keywords: ['whoami
/priv']` — means "this text appears somewhere in the event". The field mapping correctly
sent it to the `message` column but left the value a bare literal, so it compiled to
`message = 'whoami /priv'`: an exact comparison against the *entire* rendered event text,
which is never true for a real log line. Every keyword-style rule in the catalogue was
structurally incapable of firing. Fieldless values are now wildcarded, giving the
`message LIKE '%…%'` the spec actually calls for. Deliberately narrow: only fieldless
items, only strings, only values that aren't already wildcarded — a bare number would
become `%3%` and match everything.

**MITRE tags were dropped from two of the three ways a rule can write them.** The
extraction regex only understood indented block sequences with no trailing comment, so
`tags: [attack.t1059.001]` and `- attack.t1003.001  # lsass` both yielded *no* techniques.
Alerts from those rules were written with an empty `mitre_techniques` column, so the
Coverage page's Validated tier counted the technique as never having fired. The same regex
existed as **five byte-identical copies** — the engine, the rules cache, the log-source gap
summary, the coverage snapshot, and the compliance report — all sharing both blind spots.
Consolidated into `mitre_attack.tags_from_rule_yaml()`, beside the `techniques_for_tags()`
it feeds; that module is already the shared Flask-free home for tag semantics, so this adds
no new sharing mechanism, it just stops one bug from having five addresses. Zero-indent and
CRLF rules now parse too.

**Alert dedup wasn't null-safe on host.** The lookup keyed on `rule_id IS ? AND host = ?
AND username IS ?`. Since `NULL = NULL` is never true and the host column is nullable, a
rule matching events whose host never got parsed found nothing to merge into and created a
brand-new alert *every cycle* instead of bumping one row's occurrence count — precisely the
runaway the 15-minute dedup window exists to prevent. Fixed on the import-replay path too.

**Aggregation bookkeeping was never deleted by anything.** Every raw per-event match of an
aggregation rule writes a row that exists only so the threshold check can count it inside
the rule's timeframe — typically 300 seconds — and every one of those rows was kept
forever. On a rule like "failed logons `count() by user > 5`" against real authentication
noise that's an unbounded write-only table. `run_due_aggregation_prune()` now runs on the
same once-a-day, settings-tracked cadence as the log and IOC purges, with retention derived
from the longest timeframe any rule actually configures, so a `timeframe: 7d` rule keeps
counting correctly instead of being quietly broken by a fixed short window.

**Windows Security 4688 process fields were never extracted.** The parsers only knew
Sysmon's `Image:` / `CommandLine:` / `ParentImage:` spellings. The Security log renders the
identical concepts as `New Process Name:`, `Process Command Line:` and `Creator Process
Name:`, and matched none of them — so those columns stayed NULL on every Security-channel
process event, and every rule keyed on Image/CommandLine/NewProcessName (the single largest
rule category there is) compared against an empty column. Added to both the rendered-message
patterns and the XML-capture map. This is what a host without Sysmon reports process
creation with.

**Two inline heuristics fired on any event that merely mentioned a word.** `"-enc" in
message` also matches `-Encoding` — an entirely ordinary PowerShell parameter — so routine
scripting like `Out-File -Encoding utf8` raised a HIGH "Suspicious PowerShell Execution"
alert. Likewise `"ipconfig" in message` fired on any log line containing the word, in any
channel, for any reason. Both now match anchored patterns against the *parsed* process
image and command line when the event is a real execution, falling back to the message only
for channels this appliance can't structure — the same treatment the LSASS heuristic already
got for the same reason.

### Making the remaining gap visible instead of silent

`live_logs` is a flat table, so a Sigma field with no column falls back to `message`. With a
wildcard that genuinely works (`message LIKE '%mimikatz%'`); with an exact comparison it
silently becomes `message = 3`, which nothing can satisfy. That distinction decides whether
a rule works imprecisely or not at all, and it was invisible either way.

**Validate Rules** now reports it. Alongside genuine conversion failures it lists rules that
can *never* match (an exact comparison on a field with no column) and, separately, rules
that fall back to searching raw event text. The counts are the point: a few thousand
imported rules can look like coverage while a meaningful share of them are structurally
dead. Under-reports rather than over-reports by design — a field is only called dead when
every value for it is an exact literal.

### Permission gate on the rule-authoring preview

`/api/rules/dry-run` compiles caller-supplied Sigma YAML into SQL and executes it against
`live_logs`, and shipped with `@login_required` alone — so a role without permission to
create a rule could still run one it invented. It and the two validate endpoints now require
`rules.manage`, which every other rule-authoring route already did. Same recurring
read-side-gate class noted in CLAUDE.md.

### What Validate Rules actually reported

First real run, on 119 enabled rules: **0 failed to convert, 30 can never match, 17 more
match imprecisely.** A quarter of the enabled ruleset was doing nothing, and the old check —
which only catches rules that throw — called all 119 healthy.

Some of the 30 are honestly unreachable (`eventName`/`eventSource` on AWS rules, `c-uri` on
proxy rules — there's no ingest path for those sources, which the log-source gap summary
already reports separately). The rest are Windows data this appliance *does* collect and
just has no column for, and they are not minor rules: LSASS credential-dumping detections on
`GrantedAccess`/`CallTrace`, pass-the-hash on `LogonType`/`LogonProcessName`, Defender
tamper detection on `Provider_Name`/`param1`. Closing those is the highest-value follow-up
in the detection area, and it's now a measured list rather than a guess.

### Log Search UI

Chart legend keys are round dots in each line's own colour rather than filled rectangles;
Export CSV and Export JSON merged into one Export dropdown; Saved Searches moved up beside
the Search button, since loading a saved search and running the current one are the same
action on the same controls. Service Health moved off Log Pipeline → Parsers to Settings →
System — it reports systemd unit state and the engine heartbeat, which has nothing to do
with parsing; it was only there because it had been added next to Pipeline Health, which
genuinely belongs in that tab.

## 2026-09-15

### A PyInstaller bundle build for the Windows agent, and frozen-awareness

`installer/build_agent_exe.ps1` produces a single-file `MicroDFIRAgent.exe` and
Authenticode-signs it when `MICRODFIR_SIGN_THUMBPRINT` is set. It still builds unsigned,
with a warning, because the signature is the part that carries the real value — tamper
detection by the OS, and allowlisting. A onefile bundle extracts to temp at runtime and
its PYZ is readable with ordinary tools; **this is not obfuscation** and the script says so
rather than letting bundling feel more protective than it is.

The larger half of the work was making the agent *correct* when frozen, because three
paths fail silently otherwise and every one would have been an unpleasant surprise in
production:

- the watchdog matched `IMAGENAME eq python.exe`. A bundle runs under its own image name,
  so the watchdog would never find the live agent, conclude it had died, and relaunch it
  every five minutes — **one extra agent per tick, forever**.
- self-upgrade writes Python source to `micro_agent_windows.py`. Nothing executes that
  file in a bundled install, so every upgrade would report success and change nothing. It
  refuses loudly now.
- `_kill_other_agent_instances` matched the `.py` name in the command line, which a
  bundle's command line never contains — so reinstall would quietly stop de-duplicating
  at exactly the moment it matters.

**Bundling costs remote source self-upgrade**, which is why the built exe is gitignored
rather than checked in like the NSIS installer: switching a fleet to bundled agents should
be a decision, not something stumbled into because a binary was sitting in the repo.

So the trade-off is visible rather than mysterious, agents now report `X-Agent-Packaging`
on check-in and the server stores it per poll (`agent_polls.packaging`, backfilling every
pre-existing row to `source` — which they all are). Without it, a bundled fleet ignoring
Upgrade Agent would look identical to a successful upgrade that changed nothing, a
confusion this product has already produced once for a different reason.

The build refuses to ship a bundle that fails its own self-check, and that check
deliberately exercises the agent's two **lazy** imports — `winreg` and `ctypes`/`wintypes`.
Every other import is module-level and therefore already proven by the interpreter
reaching that line, but those two are imported on first use: a bundle missing `ctypes`
would build fine, start fine, and then be unable to read its own stored credential on a
real endpoint.

### The endpoint enrollment token is no longer plaintext on disk

The token authorises remote script execution on the endpoint it belongs to, and it sat in
plaintext in up to two places there: baked into the agent's own `.py` source at download
time, and again in `agent_config.json` on installer-based deployments. Measured on a real
endpoint rather than assumed — the installed source carries `BUILTIN\Users:
ReadAndExecute`, so **any local user could read a fleet credential out of it with no
privilege at all**.

Each platform now uses what it actually has:

- **Windows** — DPAPI through `ctypes` (no pywin32; this agent has no third-party
  dependencies and must keep it that way). **User** scope deliberately, not
  `LOCAL_MACHINE`: verified live that the agent runs under the installing account via a
  `RunLevel=Highest` scheduled task, *not* SYSTEM, so user scope binds the blob to that
  one account. Machine scope would be strictly worse here — it lets every local user
  decrypt. The blob's inherited ACEs are stripped too.
- **macOS** — the System keychain via `/usr/bin/security`, reachable because the agent
  runs as root from a LaunchDaemon (a login keychain would be locked on a headless boot).
  Falls back to a 0600 file if `security` refuses, because losing the credential is worse.
- **Linux** — a root-owned 0600 file, and that is the honest answer rather than a keyring.
  The agent runs as root, where the kernel keyring offers root nothing it does not already
  have; what matters is that *non-root* users cannot read it, which the mode gives
  directly. libsecret needs D-Bus and a desktop login, neither of which a headless
  endpoint has.

What this buys is stated plainly in the code as well: it stops any *other* local user
reading the token and makes a copied file useless elsewhere. It does not stop the account
the agent runs as — nothing file-based can.

Three ordering details carry the safety. The bootstrap copy is scrubbed **only after** the
store is written *and read back correctly*, because an unverified store plus an
irreversible scrub would de-enroll the endpoint permanently. A POSIX store whose mode has
drifted world-readable is refused and rewritten rather than trusted. And if the store ever
becomes unreadable after the scrub, the agent cannot report it — reporting needs the
credential — so it writes a FATAL line to the local `agent.log` naming the fix.

The self-upgrade path still ships the token inline, because an older agent has nowhere
else to get it; the new agent migrates and scrubs on its first startup, so that window is
one startup rather than forever.

**Verified on a real endpoint after upgrading it:** the DPAPI store exists (294 bytes,
correct blob header — the same length the local DPAPI test produced for a 64-char token),
its ACL is SYSTEM / Administrators / the agent's own account with **no `BUILTIN\Users`**,
`soc_token` is gone from `agent_config.json` while its other keys survive, no 64-hex
literal remains anywhere in the source, the placeholder is back in its place exactly once
— and the host kept checking in and shipping logs throughout, which is the part that
proves the stored credential actually works.

### Containment that reported success without containing (ISO-01 → ISO-04)

All four isolation findings from the security assessment. Three of the four share one
shape: the console said a host was contained and it was not.

- **ISO-01, Windows — pre-existing Allow rules survived "isolation".**
  `Set-NetFirewallProfile -DefaultOutboundAction Block` only changes what happens to
  traffic matching *no rule*. Windows Firewall evaluates Block rules, then Allow rules,
  then the default — so every one of the host's enabled Allow rules still matched first
  and still permitted its traffic. A stock install ships with dozens (Core Networking,
  mDNS, network discovery, RDP) and every application adds more; malware that registered
  its own Allow rule kept its channel open through an isolation that came back green.
  Fixed with explicit **Block** rules, because Block outranks Allow. Windows has no
  "everywhere except X" address syntax, so the exception is the arithmetic complement of
  the SOC addresses — as inclusive ranges, which needs 3 entries where CIDR needs 31 and
  says plainly what it covers. IPv6 is blocked wholesale: the SOC is reached over IPv4,
  and leaving v6 open hands anyone on a v6-capable network an untouched path out.
- **ISO-02, macOS — the whole thing was a no-op.** It loaded rules into a pf anchor and
  stopped. Loading an anchor does not make pf evaluate it; an anchor is only reached
  through an `anchor` rule in the main ruleset, and macOS's stock `/etc/pf.conf`
  references `com.apple/*` and nothing else. The rules loaded, `pfctl` exited 0, the
  script printed "Host isolated", and every packet flowed as before. The anchor is now
  referenced from `pf.conf` (between markers, so restore removes exactly what was added),
  the script has `set -e` and a fail path like the other two platforms, and it asserts all
  three conditions that must hold: pf enabled, anchor referenced, rules present inside it.
  Also fixed `pfctl -e 2>&1 | grep -v 'already enabled'`, which made the pipeline's exit
  status grep's and hid both outcomes. **Still untested on real hardware** — there is no
  Mac here. That is precisely why the self-checks matter: on an untested platform the
  honest failure mode is "says it failed", never "says it worked".
- **ISO-03 — a reboot silently un-isolated Linux and macOS hosts.** iptables rules live in
  kernel memory and nothing on a stock host writes them back at boot; macOS ships pf
  disabled and its boot job loads `pf.conf` without ever running `pfctl -e`. Rebooting is
  not an exotic evasion — it is the first thing a person does when their machine "stops
  working", which is exactly how an isolated machine looks to whoever is sitting at it.
  Linux gets a systemd oneshot, macOS a LaunchDaemon; both removed by restore, which now
  fails loudly if the boot job is still installed (otherwise a host restores now and
  re-isolates itself at the next reboot with nothing in its history to explain why).
  Windows needed nothing — its rules and profile defaults are already persistent.
- **ISO-04 — containment was asserted once and never re-checked.** The Isolated badge is
  derived from the newest completed `isolate_host` with no later `restore_network`: a
  record of what was *asked for*, not of what is true now. Between those two commands
  containment quietly dies (firewall cleared, GPO refresh, image rollback, malware with
  local admin). A new read-only `verify_isolation` action returns a JSON verdict from the
  endpoint, and the server asks every believed-isolated host every 15 minutes. A "no"
  raises a HIGH **Isolation Not Holding** alert through the normal alert path, SOAR
  included — "the host you believe is contained is not" is an incident and belongs in the
  queue. An unparseable or failed probe is deliberately *not* read as "not isolated": a
  broken probe crying containment failure every cycle would train analysts to ignore the
  one alert that matters.

**Live-verified end to end on a real Windows endpoint**, with a before/after egress probe:

| | baseline | isolated | restored |
|---|---|---|---|
| TCP to an external host | reachable | **blocked** | reachable |
| External DNS over UDP/53 | works | **blocked** | works |
| TCP to the SOC | reachable | reachable | reachable |
| Isolation rules enabled | 0 | 6 | 0 |
| Profiles defaulting to Block | 0 | 3 | 0 (back to `NotConfigured`) |

The DNS row is the ISO-01 proof specifically: outbound DNS is covered by the stock
"Core Networking - DNS (UDP-Out)" **Allow** rule, so under the old code it kept working
straight through an "isolation" that reported success. ISO-04 proved itself unprompted in
the same window — the server's own 15-minute check queued a `verify_isolation` nobody
asked for and the endpoint answered `isolated: true, rules_enabled: 6`.

**The first attempt failed, and that is worth recording**, because it is the behaviour all
of this was for. `-RemoteAddress ::/0` is rejected by `New-NetFirewallRule` (`::` is the
unspecified address and cannot be the base of a prefix), and since every rule uses
`-ErrorAction Stop`, one bad entry failed the whole isolate: the command went red, the
error named the cause, and the host was left **not contained** rather than half-contained
and reported green. The pre-ISO-01 code would have reported success. Settled by probing
the host with every candidate address form rather than guessing — all of `0.0.0.0-x`,
`x-255.255.255.255`, `0.0.0.0/1`, `::/1`, `8000::/1` and the explicit full IPv6 range are
accepted and stored verbatim; `::/0` and `::1/128` are not.

Found while testing ISO-01: the IPv4 validation in `agent_scripts` was shape-only
(`\d{1,3}` per octet), so `192.0.2.999` passed and became a malformed firewall rule.
On the isolate path, a rule the firewall rejects or silently skips means a host reported
as contained that isn't. All five call sites now range-check through `ipaddress`.

### Agent tokens are no longer stored in the clear (AUTH-04)

`agent_tokens` kept the token itself as its primary key. Anything able to read `siem.db` —
a stolen backup, the world-readable file this appliance shipped with until the hardening
pass, a SQL-injection read, anyone with shell access — walked away with a working
credential for every enrolled endpoint, and those credentials authorise remote script
execution across the fleet. Now SHA-256: the right primitive here rather than
bcrypt/PBKDF2, because these are 256-bit `secrets.token_hex(32)` values, not human-chosen
passwords, so there is no dictionary to stretch against.

A table rebuild rather than an ALTER — the plaintext column had to actually go, and it
couldn't be blanked in place because it was the primary key and every row would collide on
`''`. Existing agents kept working across it: tokens are hashed in flight, so binding,
group assignment and last-seen history all survive. Verified live — both agents stayed
Online through the migration and their group assignment came out the other side intact,
which is the real proof rows were carried rather than recreated. `_mint_agent_token`'s
return value is now the only moment the plaintext exists server-side; nothing ever needs
to read one back, because the self-upgrade path reuses the token the agent presents.

Alongside it: **`soar_engine.py` bound `0.0.0.0:8000`** — an authenticated-but-inert
webhook receiver listening on every interface. A repo-wide search for port 8000 or
`/webhook/alert` finds exactly one hit, the route definition. Nothing has ever called it;
every playbook and notification path runs inside the web app. Bound to loopback.

### The appliance couldn't recognise its own requests — and nothing could have told us

Host hardening (HOST-01 phase 1) went looking for proof that the Sigma engine was running
under its new systemd confinement, and found there was no way to ask. That absence turned
out to be hiding a live outage.

- **`/api/internal/run-scheduled-playbooks` was answering the detection engine with 403 on
  every 30-second cycle.** The endpoint is deliberately restricted to this host, and it
  tested `remote_addr in ('127.0.0.1', '::1')`. That test does not hold on an appliance
  with a real binding: Settings > Network binds gunicorn to specific interface addresses,
  a socket bound that way never accepts a loopback connection, so the engine must dial an
  interface address — and that request arrives carrying that interface IP, not loopback.
  `requests.post` does not raise on a 403 and nothing checked the status code, so it failed
  in total silence. **Scheduled playbooks, agent sweeps, isolation auto-reverts, SLA-breach
  / offline-agent / case-created / case-stale notifications and stale-import cleanup had
  all stopped running** from the moment the appliance was given a binding.
- **The same wrong test, in a second place.** `api_ingest`'s `source_ip` fallback used it
  to avoid stamping the SOC's own address onto relayed syslog — and, being loopback-only,
  did exactly what its comment said it existed to prevent, because the Vector sink is
  pointed at `ingest_bind_ip` for that same socket reason. Both now share
  `_is_own_host_request()`: loopback or either configured bind address. Not a widening of
  trust — a request from anywhere else carries *its* source address, never the server's.
- **Fixing the 403 immediately exposed the next problem.** The silent-log-source check is
  the one thing on that poll that isn't cheap — three `GROUP BY` scans over `live_logs`
  across 7 days, the query shape already measured at 93 seconds on this box. It had been
  harmless only because it never ran. Within a minute of deploying the fix the engine's
  poll was timing out on every cycle. It now runs on a 15-minute cadence of its own,
  claimed with a conditional `UPDATE` *before* the work starts — three gunicorn workers
  plus a check that outlasts the poll interval is otherwise two concurrent passes racing
  the same cooldown check and double-firing one alert.
- **Service Health** (Log Pipeline > Parsers) is the missing instrument: `systemctl
  is-active` for all five units, plus the detection engine's own per-cycle heartbeat and
  the outcome of its scheduled-task call. Two signals because they fail differently — a
  unit can be perfectly "active" while every request it makes is rejected, which is
  precisely what was happening. It is also the canary the confinement work needed: until
  now, a hardened unit that refused to start looked exactly like a quiet day with no rule
  matches.

### Host hardening, phase 1 — systemd units, file permissions, Sigma confinement

- **Four of the five `config/*.service` files were dead config.** `update.sh` only ever
  installed `microsoc-dns.service`; systemd reads `/etc/systemd/system/`, which
  `install.sh` wrote once at first install and nothing updated since. Editing any of the
  others *looked* deployed and was not. `update.sh` now syncs them (only when changed,
  then one `daemon-reload`).
- **Two units are deliberately excluded, for different reasons.** `microsoc-dnsmasq`
  serves DNS to whatever has opted in, and a routine app deploy must never interrupt that.
  `microsoc-web` is **live state, not deployable config** — Settings > Network rewrites
  the installed unit in place to set the bind addresses, and the repo copy carries the
  generic `--bind 0.0.0.0:5001`. Learned the hard way: the first version of the loop
  included it and silently discarded the admin's deliberate per-interface binding,
  re-exposing the UI on every interface. Nothing broke, which is exactly why it would have
  gone unnoticed; restored by re-saving the Network form. The template now carries a
  header saying so.
- **`update.sh` self-update lag**, worth knowing before trusting any deploy that changes
  the script itself: the running copy is the old one, so an edit to `update.sh` only takes
  effect on the *next* run.
- **Secrets were world-readable.** `config/key.pem` is the TLS key every agent pins;
  `siem.db` holds agent tokens, the shared secret and every password hash. `install.sh`
  created both with the default umask. Now `chmod 600` (plus the WAL/SHM sidecars, which
  carry the same data mid-transaction) and `chmod 700` on `case_attachments`, applied on
  every deploy so existing hosts pick it up without anyone knowing to go and do it.
- **Confinement starts with the Sigma engine on purpose** — nine directives
  (`NoNewPrivileges`, `ProtectHome`, the `ProtectKernel*`/`Restrict*` set). It is the least
  disruptive service to lose: if a directive is wrong, detection matching stops while the
  UI and the deploy path keep working, which is what makes the failure diagnosable.
  `ProtectSystem` and `PrivateTmp` are deliberately absent with the reasons recorded in the
  unit — the web app writes `/etc/vector/` and `/etc/systemd/system/`, and the update lock
  file is created inside the app but removed from outside it.

## 2026-09-14

### Insider threat workflow review — making the identity scoring actually work

Asked to walk the investigative workflow as an insider threat analyst. Three parallel
code reviews plus a live walkthrough. The scaffolding turned out to be better than
expected — an Identities model with Privileged/Departing/Watch multipliers, asset
criticality, a seeded Insider Threat queue, a genuinely well-written Insider Threat
runbook and a dedicated dashboard. Two things were wrong with it: it was completely
inert, and the user-centric views were led by accounts that aren't people.

- **Machine and service accounts were scored as people.** Measured on the live fleet: of
  five `user` entities, exactly **one was a human**, and `SYSTEM` outranked them **12×** —
  so "Top Risky Entities", the headline widget of the Insider Threat dashboard, led with a
  machine account. `classify_account()` now labels AD computer accounts (`HOST$`) and the
  built-in service principals across the bare / `DOMAIN\name` / `name@domain` forms, and
  the Risk Scoring table defaults to **People only**. Deliberately a classification rather
  than an exclusion — `SYSTEM` behaving oddly is a real intrusion signal, so nothing is
  dropped, it is one click away. The classifier is biased toward *human* on purpose:
  hiding the subject of a case is a far worse failure than showing a service account, so
  `svc_backup` and `system_admin` both classify as people.
- **`departing` is now a timestamped transition**, like `watched` already was. It was a
  bare boolean, so the date lived by convention inside the free-text note where nothing
  could query it — and the entire premise of the flag is that exfiltration risk spikes in
  a *window*, which cannot be measured or charted if nothing records when it opened.
  Stamped on the 0→1 transition, cleared on 1→0, shown as an elapsed day count
  ("day 9") since that is the number an analyst reasons with. An unrelated edit cannot
  reset it and move the goalposts on an investigation already measuring against it.
- **CSV import for identities.** These flags are the only insider-specific scoring in the
  product, and the sole way to populate them was a form, one user at a time — so on any
  real fleet the table stays empty and none of it ever fires. It was empty here. Paste an
  HR export or `Get-ADUser | Export-Csv`; upsert, so re-running the same export daily is
  the joiner/mover/leaver path. Deliberately a paste box, not a directory connector: no
  credentials to store and no scheduled sync to go stale.
- The identity flags are surfaced on the risk table, so an analyst can see **why** a user
  is weighted up rather than only that they are.

**`watched` deliberately still does not multiply the score**, despite the obvious symmetry
with privileged and departing, and despite that being the shape of the original request.
Inflating someone's risk score *because* an investigation was opened into them is circular,
and in the HR or legal proceeding these cases end in it is prejudicial — "we watchlisted
them, which raised their score, which justified the case" does not survive contact with a
defence. It surfaces them instead, via the badge and the standing watchlist widget. There
is a test pinning this so it is not "fixed" by accident later.

19 tests, including a reproduction from the real fleet entity list and the re-import trap
where a nightly feed silently resets a departure window. Live-verified end to end:
`SYSTEM` and `HOST$` now label correctly and People-only leaves the one human while
preserving every host; a two-row import created 2, a re-import updated 2 with no
duplicates and the original `departing_at` intact. Test identities removed afterwards.

**The watchlist is now restricted** (follow-up pass). `GET /api/identities` and
`GET /api/dashboards/watchlist` both served the rows that name who is under investigation,
who put them there and the free-text reason why — and both were `@login_required` only, so
any account could read them. They now require `assets.manage`, exactly the key the write
side of `/api/identities` already used: the GET/POST parity rule this project documents as
a recurring gap, not a new permission model. Closing only one would have moved the leak to
the Insider Threat dashboard, which is more visible. The role split lands correctly — the
built-in Tier 1 `analyst` loses it, `senior_analyst` and the custom `insider_threat` role
both hold the key and keep it. Both surfaces degrade to a lock and an explanation rather
than a red "failed to load", because for some roles a refusal here is an expected outcome
rather than a failure. 6 tests; verified live that a privileged account is unaffected.

**Case-level confidentiality** (the finding that mattered most, now closed). Every case
was readable by every logged-in account — no visibility flag, no ACL, and the seeded
"Insider Threat" queue restricted nothing because `queue_members` is never consulted by
any read path. Added `cases.visibility` (`normal` | `restricted`) plus a `case_acl` table:
a restricted case is visible to admins, its creator, its current assignee and anyone on
its ACL, and returns **404 to everyone else — not 403**, because a 403 confirms the case
exists, which for *"is there an investigation into me?"* is most of the answer.

Enforced through a single decorator across all 24 case routes rather than 24 hand-edits.
They all carry `<int:cid>` and share no other chokepoint (unlike `_require_open_case`,
which every mutation already calls), and hand-editing each is exactly how a surface gets
missed — a confidentiality control with a hole in it is worse than none, because it
invites trust it hasn't earned. The list route filters in SQL, so counts and ordering are
computed over the visible set. `/reports/download/<history_id>` is checked too: a case PDF
is the whole case in one file and that route is keyed on the report id, so it reached
straight past every guard on the case routes, addressable by guessing a small integer.

Ships inert — `visibility` defaults to `normal` and a normal case behaves exactly as
before, so nothing changes until a case is deliberately restricted. Admins, the creator
and the assignee always retain access, so restricting cannot orphan a case from the people
already working it. Restricting is deliberately *not* admin-only: the analyst who realises
mid-triage that this is an insider matter is exactly who needs to act. A visibility change
is written to the case's own append-only timeline as well as the audit log.

**The UI** puts it on the case rather than leaving it API-only: a visibility row at the
top of the case detail, above the fields, because "who can see this" is something you want
to know before you start reading. A restricted case gets a red border, a shield badge and
the access list inline — including the creator, assignee and admins, who retain access
whatever the list says; leaving those implicit would give "who can see this?" a second,
invisible answer. The case list carries the same shield.

The editor is a dedicated modal rather than `confirmDialog()`: that helper renders its
body with `innerText` and binds Enter to confirm — both correct for a confirmation and
wrong for a form, since every newline typed into the access list would have submitted it.
Retrofitting it would have weakened a correct behaviour for every other caller. The access
list disables itself when the case isn't restricted; a rejected username reports inside the
dialog with the offending value still on screen rather than as a toast over a closed form;
and on a closed case the button becomes "Reopen the case to change this" rather than
vanishing, since the API rejects the write anyway.

24 tests (15 backend, 9 UI). Live-verified end to end on a real case: restricted it
through the dialog, saw the red panel and the list shield, confirmed an unknown ACL name is
refused inline without closing the form, then set it back to normal — all four transitions
remain on the case timeline, which is the point.

**Deployment note worth keeping.** The first deploy of this took the web service down:
the `/api/cases/<int:cid>/reports` route sits ~700 lines above where the helpers were
added, so `@requires_case_access` was evaluated at import before the name existed.
`py_compile` passes on that — it is a name-resolution failure, not a syntax one — so the
usual pre-deploy check could not catch it. Fixed by moving the block above its first use,
and the suite now walks the AST asserting no decorator is used above its own `def`, so the
class cannot recur silently.

**Evidence integrity, insider templates and an honest runbook** (third pass):

- **Deleting a case destroyed its evidentiary record with no trace.** The delete removed
  `case_events` — the append-only timeline, the one table with no UPDATE path anywhere
  precisely so it can be trusted — and wrote **no audit entry at all**. A case, its notes,
  its analyst actions and the record that any of it existed could be erased leaving nothing
  behind. For an insider case ending in an employment or legal proceeding that is the
  difference between a defensible file and an unexplained gap. It now snapshots the case
  identity and per-table counts *before* destroying anything and audits what went.
- **It also orphaned evidence.** `case_attachments` rows and the files under
  `CASE_ATTACHMENTS_DIR` were never touched, so uploaded evidence outlived the case that
  explained it — files nobody can account for, with no chain back to why they were
  collected. Now removed along with `case_acl` rows and `case_links` pointing at the case
  from either direction; a file that cannot be unlinked is named in the audit detail rather
  than aborting the delete half-way and leaving the case in pieces.
- **Four insider case templates.** All four shipped templates are intrusion-shaped, and the
  nearest neighbour — "Compromised Account" — opens with *"Force password reset and revoke
  active sessions"*, correct for a compromised account and exactly what you must not do
  first against an insider. Added Departing Employee Review, Data Exfiltration (Insider),
  Privilege Misuse and Acceptable Use Violation, with the HR/Legal gate ahead of any
  investigative step. Acceptable Use deliberately scopes *first* and engages HR second: it
  is the lowest-severity and most common outcome, and escalating before anyone has
  established which policy is in scope is its own harm to the person. A test pins that
  asymmetry so it reads as a decision rather than an oversight.
- **The Insider Threat runbook stopped promising telemetry that doesn't exist.** It told
  analysts to review "DLP/file-access logs" and a "cloud/USB audit trail" — the product
  collects none of it. It now names the limits plainly and points at what *is* collected
  and what has to be switched on first. A coverage gap is survivable; discovering
  mid-investigation that the runbook described a product you don't have is not.

One process note: the runbook fix initially shipped **inert**. `IR_RUNBOOKS_SEED` uses
`INSERT OR IGNORE` on a unique name, so editing a seed entry only ever reaches a fresh
install — the same "only applies on first seed" trap the Windows channel filters hit.
Caught in live verification, then retrofitted by a migration that matches on the old
wording so a runbook someone has edited themselves is left alone.

**Found and not yet addressed** — the seeded "Insider Threat" queue still restricts
nothing on its own (`queue_members` is never consulted by any read path), though a case in
it can now be restricted individually; and TLP remains a badge, not a control. Also open: no person as a first-class case entity
(the subject is inferred from `alerts.username`); deleting a case wipes its append-only
timeline with no audit entry and orphans the attachment files; no chain of custody, no
legal hold; the four shipped case templates are all intrusion-shaped and the nearest one
starts by resetting the subject's password, which tips them off; and the shipped Insider
Threat runbook tells analysts to review "DLP/file-access logs" and a "cloud/USB audit
trail" that the product does not collect — no file-read auditing, no USB copy visibility,
no printing, no byte counts, with Sysmon and all 11 Linux auditd channels off by default.

### Security assessment of the EDR agent, isolation and appliance posture

Asked whether the EDR agent deployment, its security and firewall features, and the
overall posture could be bypassed. Four parallel code reviews — agent authentication and
identity, endpoint tamper resistance, the server-side API surface, isolation internals —
produced 36 findings. Every one relayed was re-checked by hand against the cited lines;
two reviewer claims were wrong on the facts and were dropped rather than passed on (a
"unpinned HTTP" Sysmon download that actually uses full system-CA verification, and an
installer-path bug framed as remote code execution when the resulting agent cannot
resolve its server at all and simply never connects). Full report published separately.

Three structural themes account for most of it:

1. **"Isolated" means "a command exited 0", not "this host is contained."** Every success
   criterion in the containment feature is an exit code. Nothing compares intended state
   against endpoint state — not at apply time, not periodically. Containment that
   evaporated on reboot, was never applied, or was removed locally all present
   identically: a green badge.
2. **The lowest EDR tier could reach root on an endpoint**, collapsing the
   Tier-1/Tier-3 boundary the permission model exists to enforce.
3. **Agent identity is asserted by the client** and rarely checked against the credential.
   One route does this correctly; the other three trust a header.

Worth recording as a genuine strength: the per-agent token model is sound — 256-bit,
minted per download, hostname-bound with replay rejection — and `/api/agent/result`
derives identity from the command row rather than a header, which is the pattern the
other routes need. A live probe of the auth boundary returned 401 for both an absent and
an incorrect token with no state written.

**Fixed in this pass** (the highest-severity finding, plus three regressions introduced
hours earlier by the isolation-incident fix — all four reproduced before and after):

- **A Tier-1 analyst could execute arbitrary code as root on any Linux/macOS endpoint.**
  Six builders embedded a caller-supplied path or pattern in a `python3 - <<'PYEOF'`
  heredoc, escaped with Python string-literal rules that do not cover newlines. A path
  containing a line reading `PYEOF` closed the heredoc early and bash ran the rest as
  root. `quarantine_file` is a Tier-1 label, so this required only `edr.command.basic` —
  while that same account cannot queue a `custom` script, which needs
  `edr.command.advanced`. The quoting flaw inverted the permission model it sat behind.
  Now `_py_literal()`: `repr()` (the pattern `string_sweep_linux` already used) plus
  outright rejection of control characters, so the next builder added here fails loudly
  rather than depending on `repr()` being remembered.
- **Isolation had become impossible on any appliance reached by hostname.** This
  morning's fix folded `request.host` into the allowlist unconditionally, and the
  validator rejects the whole set on one non-IPv4 entry. A DNS-name or reverse-proxied
  console could not contain a host at all; in the playbook path the exception was
  swallowed, so automated containment silently did not happen. This box is reached by IP,
  which is exactly why the testing missed it.
- **An attacker-controlled `Host` header punched a hole in the allowlist.** A caller with
  `edr.command.basic` sending `Host: <their-address>` got it written into the isolated
  endpoint's firewall as an Allow rule — and the endpoint-side probe then *passes*,
  because their address answers. `request.host` is now a last resort used only when the
  bind settings yield nothing, validated through `ipaddress` so octets are range-checked
  too. The allowlist is also computed server-side unconditionally: a client-supplied
  `soc_ip` no longer overrides it.
- **`unblock_ip` reported success on failure** — the `exit 1` fix its sibling `block_ip`
  received in Pass A was never carried across.
- **The rollback asserted the opposite of what may have happened.** Every teardown
  command is failure-tolerant, and the script then claimed *"the firewall has been
  returned to its previous state and the host is NOT isolated"* regardless. A failed
  rollback therefore told the analyst the host was fine while leaving it isolated and
  unable to reach the SOC — the same false-success class the self-check exists to remove,
  surviving in the branch that handles the worst case. Both platforms now verify their
  own teardown and pick the message from the result.

17 tests, including a reproduction of the heredoc escape under the old quoting,
round-trip checks for awkward-but-legitimate paths (apostrophes, quotes, backslashes,
unicode), and an assertion that `repr()` alone would hold if the control-character guard
were ever removed. Full regression green across all nine suites.

**Fixed in a second pass** — the permission side doors and one destructive action:

- **Log Search handed EDR command output to any logged-in account.** The unified search
  union projects response-action stdout/stderr into its message column, and its three
  consumers (search, CSV export, timeline) carry only `@login_required`. `types=command`
  narrows the union to that branch alone, so any account — including a custom role holding
  no permissions at all — could request a clean dump of every response-action result
  across the fleet. `api_agent_commands`' GET refuses exactly that data without
  `edr.command.basic` and its comment explains why; this was a side door around that
  decision. `_log_branches_for_user()` now drops the branch for users without the
  permission. Filtering rather than refusing keeps log search working normally for
  everyone, and every consumer already short-circuits on an empty branch list.
- **The SOAR approval queue gated one of seven actions.** It re-checked the EDR permission
  only for `isolate_host`, while the always-gated set holds six more — so
  `soar.playbooks.manage` alone could **un-isolate a contained host**, quarantine files,
  kill processes fleet-wide and revoke credentials. Approving executes the action for
  real, so it now demands the same permission the direct route does, *derived* from
  `AGENT_COMMAND_TIER1_LABELS` rather than restated, so the two cannot drift apart again —
  which is exactly how the queue ended up covering one label and not the rest.
- **`block_ip` could sever the appliance's own control channel.** Nothing compared the
  target against the SOC addresses, and a Block rule beats an Allow rule in the Windows
  filtering engine — so blocking a SOC address also overrides the isolation allowlist, the
  agent can never poll again, and the unblock can never be delivered. One mistyped IOC
  from a feed was enough. Refused at queue time now, reusing the same allowlist isolation
  computes.
- **Queuing a command had no audit record** — the highest-impact action in the product,
  where a `custom` label is arbitrary code as SYSTEM/root and the group branch runs it on
  every host in a group from one request, while cancelling a command and changing a host's
  group both wrote audit rows. Both paths now do; the script body is deliberately not
  logged, since it can be large and already lives on the row.

18 further tests. Live-verified: an account holding the permission still sees command rows
(the gate filters, it does not break search), blocking the appliance's own address is
refused with an explanation, and blocking an ordinary indicator still works.

**Fixed in a third pass** — binding identity to the credential:

- **Any endpoint could forge logs for any host.** `/api/ingest` authenticated
  `logs[0]['host']` while the write loop read `log.get('host')` per entry, so an endpoint
  holding its own valid token could name itself first and any other host in the rest,
  with arbitrary timestamps and severities. Every deployed endpoint holds a valid token,
  so this was the fleet's normal state rather than a stolen-credential scenario. It
  reached the alert dedup branch too, which `UPDATE`s an existing alert's message and
  severity — letting an attacker who had just tripped a heuristic overwrite the stored
  message of the real alert inside the window.
- **The fix is deliberately scoped, and it corrected the assessment.** Vector
  authenticates with the shared secret and relays syslog for *every* device on the
  network, each entry carrying its own self-reported hostname
  (`generate_vector_config` sets `.host = .hostname`). Requiring one identity per batch
  would have silently broken all syslog and dnsmasq ingestion. So the shared secret is
  **load-bearing for the appliance's own log relay**, not merely legacy-agent
  compatibility — retiring it, as the assessment suggested, needs Vector moved to its own
  credential first. `_agent_token_bound_host()` makes the distinction: a per-agent token
  bound to a hostname may only write that hostname, and a mismatched batch is refused with
  a 403 and an audit record rather than having foreign entries silently dropped.
- **Authentication now fails closed.** `if not expected_secret: return True` meant a
  missing secret row left every agent route accepting anyone with no token at all. It now
  rejects, and seeds a fresh secret so the closed state heals itself.
- **The fleet-wide secret was generated with `Math.random()`** — V8's xorshift128+, state
  recoverable from a modest run of outputs, for the credential that authenticates to every
  agent route with no hostname binding. Now `crypto.getRandomValues`, 128 bits. The save
  endpoint also accepted any non-empty string, so `test` was a valid fleet key; added a
  length and repetition floor that every generated value clears.
- **Tokens are revoked when an uninstall is delivered.** There was no revocation path
  anywhere, so removing an endpoint left its token valid forever and a decommissioned
  machine could re-enroll by polling. Revoked at hand-over, deliberately *not* in
  `delete_agent()` — the agent must authenticate once more to collect that very command,
  so revoking earlier would leave it running forever and invisible. Only `uninstall`
  revokes; an `upgrade` leaves the credential intact because that agent keeps running.

15 further tests, including a reproduction of the forgery and an explicit regression test
that a shared-secret caller can still relay many hosts. Live-verified after deploy: both
agents kept polling and shipping logs across the change. The Vector path could **not** be
live-verified — this appliance currently has no active syslog sources, so there is no
traffic on it to observe; that direction rests on the test and the code path.

**Known and not yet addressed** — Windows isolation leaves pre-existing Allow rules
intact so an "isolated" host keeps DNS egress; the macOS pf anchor is never evaluated;
Linux and macOS containment does not survive a reboot while the console keeps claiming
it does; tokens are still stored in plaintext and there is no revocation for a host that
never returns; the agent has no tamper resistance and a killed agent is indistinguishable
from a sleeping laptop; the self-upgrade executes unsigned server-supplied source; and
every appliance service runs as root with no systemd confinement.

### Incident: host isolation was irreversible on a dual-homed appliance

Running the first real end-to-end containment test (a genuine `isolate_host` on the one
endpoint authorised for disruptive testing) turned up the most serious defect this
codebase has had.

Settings > Network offers **separate bind addresses for the UI and for ingestion**, and
the deployed appliance uses both — UI on `…100:5001`, ingestion on `…101:5000`. The agent
does not treat them interchangeably: it checks in and receives commands on the **UI**
address (`/api/agent/config`, `/api/agent/result`) and ships logs to the **ingest**
address (`/api/ingest`). But `soc_ip` for the isolation firewall rule was a single value
read from `ingest_bind_ip`.

So isolation allowlisted the ingest address and blocked the check-in address — and the
failure mode is the worst one available. The host stayed **visibly healthy**: logs kept
arriving on the allowed path, every few seconds, for the full hour the test ran. What had
actually happened is that its command channel was severed, so it could never be handed
the `restore_network` that undoes the isolation, and the isolate's own result never came
back either. **The containment was real, complete, and unreachable by any remote means,
because the one channel recovery travels on is the one isolation cuts.** Recovery
required physical access to the endpoint.

Observed split, an hour after the isolate landed — the whole bug in two numbers:

    last log received   12:59:13   (ingest address, allowed)
    last check-in       11:59:36   (UI address, blocked)

`isolate_host` (+ the Linux and macOS variants) now take one or more addresses, and
`_soc_allowlist_ips()` assembles both bind addresses plus the request host — deduped,
with `0.0.0.0` dropped since a wildcard bind is not an address an endpoint can send to.
Both callers use it (the EDR queue route and the SOAR playbook action, which can isolate
several hosts at once) and both now **refuse to queue an isolation** rather than strand a
host when no address can be determined. Each address is validated individually, so a
payload can't ride along in the comma-separated list. A single-homed appliance collapses
to one address and is byte-for-byte unchanged.

16 tests, including a reproduction from the real production settings and an assertion
that the old rule never mentions the check-in address at all. Pass A's isolate/restore
suite still green.

Two supporting gaps this exposed, both now closed:

- **No way to cancel a queued command.** A `sent` isolate that never reported stays
  `sent`, and the 5-minute stale requeue flips it back to `pending` — so repairing the
  endpoint by hand would have brought it back online only to be **re-isolated on its next
  check-in**, the recovery undone by the queue. `POST /api/agent/commands/<id>/cancel`
  now withdraws an unfinished command (`pending`/`sent` only; `done`/`failed` is history).
  `cancelled` is terminal and no longer matches the requeue's `status = 'sent'` filter.
  This also clears the three August strays Pass B surfaced.
- **Agent status cutoffs didn't track the check-in interval.** Noticed while checking
  fleet state before the test: both hosts read "Idle" although one was checking in
  perfectly regularly. The 45s/300s cutoffs were tuned for the 8s default interval and
  never revisited when it became configurable; at this appliance's 120s the agent
  (measured 122–139s across 8 consecutive polls) sat outside the 45s window ~68% of every
  cycle. The fleet looked half-dead, the Endpoints Online tile flickered 0↔1, and the
  Offline/Idle queue warnings added in Pass C hours earlier would have fired on every
  queue against a healthy endpoint. Now `max(45, interval × 1.5 + 15)` /
  `max(300, interval × 5)`, with `generate_report.py` kept in step. The floors reproduce
  the original behaviour exactly at the 8s default. Verified live: both hosts Online,
  dashboard tile agreeing 2/2. 12 tests.

Process note worth keeping: isolation should have been proven first on a host that could
be reached physically, precisely because the failure being tested for is loss of remote
access. Testing it on a remote endpoint made the blast radius of a bad outcome the same
as the bug itself.

**Hardening, after the fact.** The allowlist bug is fixed, but two structural weaknesses
are what turned one wrong IP into an unrecoverable host, and each is worth closing on its
own merits.

*Isolation now proves it kept its own command channel, and rolls itself back if it
didn't.* After the rules are applied the script makes a real TCP connection back to each
SOC endpoint; if none answers, it tears the isolation down and exits 1. Only the endpoint
can detect this — by definition the server stops hearing from it — so this has to live in
the script, not the server. A host briefly isolated and then released beats one contained
and unreachable, and the analyst gets a red "Failed" naming the cause instead of a host
that quietly stops answering. Three rounds with a pause, so a transient failure doesn't
tear down a working isolation. All three platforms (`TcpClient` / bash `/dev/tcp` / `nc`).
Endpoints became `ip:port`; a bare address still produces a rule but no probe, and the
script says out loud that it could not verify rather than letting silence read as proof.

One trap worth recording: the Linux probe is written entirely as `if` conditions because
`[ cond ] && break` is a complete AND-list, so under `set -e` a false condition aborts the
script — which here would mean exiting *before* the rollback could run, producing exactly
the outcome the check exists to prevent. There is a test asserting no bare `test && break`
survives in that block.

*The agent now has more than one way to reach us.* gunicorn binds both the UI and ingest
addresses and serves the whole API on each, so the other bind address is a genuine
fallback rather than a separate service. Check-ins and result reports now alternate across
them (primary / fallback / primary across the three attempts). During the incident the
ingest base stayed reachable the whole time — with this in place the host would have
checked in on it, received `restore_network`, and recovered itself without anyone touching
the machine. Computed per call so zero-touch routing rewrites are picked up; single-homed
deployments collapse to one URL and make no extra requests.

26 further tests (17 isolation self-check, 9 agent failover). The isolation change is
server-side and applies to the next isolate on any agent version; the agent change reaches
endpoints only via Upgrade Agent.

**And then the upgrade looked like it did nothing.** Running Upgrade Agent left the
reported version unchanged. The upgrade had in fact worked — the command completed and the
agent restarted on schedule — but `AGENT_VERSION` was still `2026.09.05.2` despite *two*
commits changing those files (the ingest spool, then the check-in fallback). The header
comment on that constant says to bump it on every change; it wasn't.

That is not cosmetic. The version string is the only observable evidence an upgrade
reached an endpoint, so hosts running old code and hosts running new code reported
identically, the fleet's version column couldn't tell them apart, and "did it apply?" had
no answer. All three agents are now on `2026.09.14.1`, and macOS picked up the same
check-in fallback rather than being left with the single-path weakness.

The guard is an invariant checkable straight from git, so it needs no fingerprint file to
maintain: **if an agent file differs from HEAD, its `AGENT_VERSION` must differ too.** It
compares working tree against HEAD, so it fails *before* the commit that would ship the
mistake, and a companion test proves the guard isn't vacuous by constructing exactly the
change-without-bump case. Verified end-to-end afterwards: `2026.09.05.2` → `2026.09.14.1`
on a real endpoint, with check-ins and log shipping continuing across the restart.

### EDR workflow/agent review, Pass C — polish (4 of 14, review complete: 14/14)

- **Failed actions were greyed out in the host-detail popup.** That table carried its own
  inline status mapping testing for `'error'` — a status `api_agent_result` never
  produces, since it only ever writes `'done'` or `'failed'` — so every failed action
  rendered as a grey secondary badge reading "failed", visually identical to a pending
  one. The single status a responder most needs to spot in a host's history was the one
  the table greyed out. Now reuses `statusBadgeCmd()`; the duplication is what let the
  two drift apart in the first place.
- **The Queued column printed raw UTC beside local-clock values.** `queued_at` is UTC
  (schema `DEFAULT CURRENT_TIMESTAMP`), while `agent_polls.timestamp` and `completed_at`
  are local server time — both were rendered raw, side by side. Added
  `utcToLocalStr`/`relativeTimeUtc`/`queuedAtCell`; the history table and the popup both
  route through it, showing a relative time with the local conversion and the raw stored
  UTC each labelled on its own tooltip line. Measured on the live page: a value stored
  `20:19:39 UTC` now reads `16:19:39 local` on this UTC-4 host, and the old local-parse
  helper read a 30-minute-old stamp as "0s ago".
- **The history table's host column was a dead end** — plain bold text, so reading
  "isolate_host failed on X" and wanting anything about X meant scrolling back to the
  fleet table and finding the row by hand. It can't be a blanket link, though: this table
  is the one place in the app that routinely lists hosts which no longer exist (command
  history outlives enrollment), and `openHostDetailModal()` returns silently for those,
  so a link would be a click that does nothing. Enrolled hosts pivot into the modal;
  decommissioned ones are muted, explain themselves, and still link to their UEBA
  timeline — the one view that doesn't need a live agent. `openHostDetailModal()`'s own
  silent return now toasts instead.
- **Queueing against an Offline host gave the same green "will run within 120s" toast as
  an online one**, which is simply false — the row it was fired from said Offline. The
  command is still queued either way (contain-now-apply-later is the point, you isolate a
  machine that isn't awake yet); the toast and the console transcript now say which wait
  this actually is. Both status checks are written as allowlists on `Online` rather than
  "warn if Offline", so a host missing from the fleet list entirely can never fall through
  to the reassuring message — a gap the tests caught before deploy.
- `renderLoadError` on the endpoints table used `colspan 11` on a 12-column table.

22 new vm-context tests; full regression green across all seven EDR suites.
Live-verified on production: the tooltip conversion measured against the real UTC-4
offset, the pivot cells rendering correctly for both live hosts *and* the three
decommissioned ones (muted, explained, timeline link present), and all three queue
messages generated from the real fleet state — Idle for the laptop, "Last check-in 5d
ago" for the offline desktop, cautious for a host absent from the list. Previously all
three were the identical green success toast.

**Live verification caught a fifth bug.** The Queued tooltip rendered a literal `<br>`
between its two lines: `escHtml()` is `d.innerText = str; return d.innerHTML`, so a
newline passed *through* it comes back as `<br>` — correct inside element content, wrong
inside an attribute value. Fixed by escaping each line separately and joining with a raw
newline (the shape the fleet table's hostname title already used). The test had asserted
the tooltip carried both clocks but used a tidy regex-based `escHtml` stub that escaped
quotes and left newlines alone, so it passed a bug the browser renders; the stub now
matches the real `innerText`/`innerHTML` behaviour, and reverting the fix under it
reproduces the exact string seen in the browser.

**Not queued, deliberately**: there is no cancel or delete route for `agent_commands`,
so a command queued by mistake cannot be withdrawn and nothing ages one out. Rather than
add a permanent row to the stale backlog Pass B had just surfaced, the offline-toast
path was verified by generating the messages from live fleet data without the POST, and
the failed-badge rendering by driving the real popup against a stubbed response. Nothing
was created: the command count was 125 before and after.

### EDR workflow/agent review, Pass B — containment visibility & data loss (5 of 14)

- **Nothing in the app told you which hosts were currently isolated.** The only
  isolation-aware view anywhere was SOAR's scheduled auto-revert list, so the single
  piece of state a responder most needs at a glance — *is this host still contained?* —
  meant reading command history by hand. It turned out to be fully derivable with no new
  column: the newest **successfully completed** `isolate_host`/`restore_network` per host
  decides it. `/api/agent/checkins` now returns an `isolated` flag and the fleet table
  badges it. The `status = 'done'` condition is load-bearing and only became trustworthy
  because of Pass A — a failed isolate used to exit 0 and record `done`, which would have
  made this badge claim containment that never happened. It also fails safe in the other
  direction: a failed *restore* stays non-`done`, so the host keeps showing Isolated
  rather than being quietly marked reachable.
- **You couldn't isolate from the fleet list.** The per-row Respond menu offered only
  Console / Upgrade / Uninstall — every containment action required a detour through the
  Response Console. Added Isolate Host, Restore Network and Collect Triage, gated on
  `edr.command.basic` (the permission `AGENT_COMMAND_TIER1_LABELS` already maps to
  server-side). The menu swaps Isolate for Restore on an already-isolated host, so it
  only ever offers the action that would change something. All three use `rowHost(this)`
  per the file's own stated anti-injection convention — hostnames come from
  client-supplied agent headers and are never interpolated into an `onclick` body.
  `queueCommand()` also picked up Pass A's host-naming fix for its confirm dialog.
- **The fleet list deduped by IP and capped at 20.** Grouping the check-in query by
  `ip_address` meant one host rendered as *two* rows the moment its DHCP lease changed,
  and two hosts behind one NAT collapsed into one — the second silently vanishing from
  the table, the console's host picker and bulk selection. This turned out to be
  systemic rather than a single site: five queries in `app.py` and two in
  `generate_report.py`, all now grouping by hostname. Separately, this one query carried
  a `LIMIT 20` its three siblings didn't, so on a fleet above 20 hosts the Agents page
  and the dashboard tile disagreed with no indication which was right.
- **Agents silently lost logs on every deploy.** An event was added to the
  already-sent set at *collection* time, then shipped with a single POST and a 5s
  timeout — no retry, no spool. So one failed ingest meant that batch was gone for good:
  never retried, never re-collected, nothing server-side to notice the gap. The window
  that matters isn't exotic — `update.sh` restarts gunicorn on every deploy, so every
  agent in the fleet dropped whatever it had collected during that restart. Command
  *results* already got three attempts with backoff; logs got one. Both agents now retry
  3× and hold a failed batch in a bounded spool (5000 entries) that's prepended to the
  next cycle, so a transient outage costs latency rather than data. On overflow the
  oldest entries go and the drop is *printed* — silent loss is the exact failure this
  exists to remove.
- **The stat tiles were labelled fleet-wide but counted a 50-row page.** They were
  derived client-side from the same most-recent-50 history the table renders, so on any
  fleet past that they always summed to exactly 50, and a burst of queued work could
  push every completed action out of the window and read as `0 Completed`. Replaced with
  a real `/api/agent/commands/summary` (`COUNT(*)`s; Pending all-time since a command
  queued for a host that's been offline a week is still outstanding, Completed/Failed
  windowed to 7 days and now *saying so* on the tile face). Tiles are also clickable
  into exactly the rows they counted — which needed a new "Pending or Sent" history
  filter, since the existing `pending` option would have shown fewer rows than the
  Pending tile's own number.

Verified with 42 tests: 15 SQLite fixture tests (the DHCP-duplicate and NAT-collapse
bugs are **reproduced** against `GROUP BY ip_address` before being fixed; likewise the
old tile derivation summing to 50 and reading 0-completed under a queue burst), 6 tests
exercising the extracted spool helper from both agent sources, 18 vm-context tests that
run the real `renderEndpoints()` against a stubbed DOM and assert on rendered HTML, and
3 for the race below.

**Live verification found a fourth bug and a stale-command backlog.** Clicking the
Pending tile applied the filter to the select but left 50 unfiltered rows in the table:
the history table auto-refreshes every 8s, so a periodic *unfiltered* request is often
already in flight when the user changes a filter, both write the tbody unconditionally,
and the stale one lands last. Pre-existing — it affects the filter dropdowns too, the
tiles just made it easy to hit. `loadCommandHistory()` now stamps each request with a
monotonic sequence number and discards any superseded response. Re-verified on
production with the refresh running: all three tiles now match their filtered row counts
exactly (3/3 pending, 19/19 completed, 0/0 failed).

Production numbers made the tile bug concrete: on real data the *old* derivation would
have read **Pending 0**, Completed 49, Failed 1 — summing to exactly 50 — while three
commands were genuinely outstanding (two `list_processes` from decommissioned QA hosts,
a `persistence_sweep` queued against `soc-appliance` on 2026-08-31). The new tiles report
Pending 3 and Completed 19 (7d), against 125 total history rows. Those three stale
commands had been invisible the entire time.

The `isolated` flag came back present and `false` for both live hosts (correct — neither
is contained). The badge and the Isolate→Restore menu swap were verified by re-rendering
the real table with the flag flipped client-side — nothing queued, no host touched — and
the badge confirmed genuinely visible (non-zero box, computed `display` not `none`),
which is the check the recurring `d-flex`/`!important` class demands. The Isolate confirm
was opened for real on `WORKSTATION-B` and **cancelled**: title "Confirm action on
WORKSTATION-B", body naming the host and spelling out the user-facing impact, and zero
`isolate_host` commands queued afterwards. Per standing instruction `WORKSTATION-A` was
never a target of any action.

### EDR workflow/agent review, Pass A — response-action correctness (5 of 14 findings)

Asked to run through the EDR workflow and agent again. A live walkthrough plus a
background Explore agent's code research produced 14 findings — notably more *real
bugs* than the three prior review areas. User approved safety/correctness first.

- **Commands could execute repeatedly on an endpoint.** The 5-minute "sent but never
  reported a result" requeue aged off `queued_at` because there was no dispatch
  timestamp at all. So a command queued while its host was offline — the normal
  containment case, you isolate a machine that isn't awake yet — was already older than
  the cutoff the instant it was finally sent, got flipped straight back to `pending`,
  and was re-dispatched on the very next check-in ~8s later, looping until some result
  happened to land. For a non-idempotent action (`kill_process`, `quarantine_file`,
  `collect_triage`) that meant real repeated execution on the endpoint. Added a
  `sent_at` column (`migrate_agent_commands_sent_at()` + schema), stamped at dispatch
  **in UTC** to match the UTC cutoff — writing local there would have recreated the
  exact mixed-clock bug the surrounding comment already documents, except worse (on a
  UTC-4 host every fresh dispatch would look 4h old and requeue immediately) — and aged
  the requeue off `COALESCE(sent_at, queued_at)` so pre-migration rows aren't stranded
  as permanently-`sent` with no way to retry.
- **`isolate_host` reported success even when it silently failed.** No
  `-ErrorAction Stop`, no try/catch, an unconditional success string, exit 0 — and
  `api_agent_result` decides done-vs-failed purely from the exit code, so a host that
  was never contained showed a green "Done". The Linux variant had the same shape (no
  `set -e`, so the final `echo` ran regardless of whether `iptables` worked). Both now
  fail loudly and `exit 1`; Linux additionally verifies the isolation chain is actually
  referenced from INPUT *and* OUTPUT rather than assuming, and tolerates first-run
  teardown of a chain that doesn't exist yet. `block_ip` already had the try/catch (it
  documents this exact false-positive class as fixed *for itself only*) but never
  exited non-zero, so its error also landed as a green Done — completed that fix too.
- **`restore_network` left Windows more open than it found it.** It forced
  `-DefaultInboundAction Allow`, but Windows' stock default is *Block* inbound, so
  every isolate→restore cycle permanently weakened that host's firewall — a security
  regression caused by the containment tooling itself. Now restores `NotConfigured`,
  handing the decision back to Windows/GPO instead of guessing, which errs *closed* in
  the one case it can't know (a prior explicitly-set Allow). It also verifies the
  isolation rules are gone and warns loudly if the host may still be cut off — a
  silently-failed restore is worse than a failed isolate.
- **The bulk action bar never hid** — `class="d-flex"` alongside a `style.display`
  toggle, so Bootstrap's `!important` kept it permanently visible reading "0 selected".
  Confirmed live before the fix (inline `none`, computed `flex`) and after (computed
  `none`, not visible). Fourth instance of this exact bug class in this codebase; only
  a live browser check ever catches it.
- Response-action confirms never named the host ("Isolate this host from the network?")
  even though the target is a dropdown well away from the button being clicked — they
  now name it in both dialog title and body. Separately, the action buttons relied on a
  container's `pointer-events:none` for their "no host selected" state rather than a
  real `disabled` attribute, which keyboard activation bypasses; they now carry the
  attribute and are initialized at page load instead of only after the first change
  event. (Note: the original walkthrough characterized these buttons as having *no*
  guard — that was wrong. Two guards existed, the CSS one and an early-return in
  `consoleRun`; this change hardens a working guard rather than adding a missing one.)

Verified with 26 tests: a SQLite fixture that **reproduces** the re-dispatch loop
(5 of 5 consecutive check-ins re-send the same command under the old `queued_at` logic,
exactly 1 under the new `sent_at` logic) and covers the genuine-retry, recent-dispatch,
legacy-NULL, result-ends-cycle and queue-ordering paths; 12 assertions on the generated
PowerShell/bash for every isolate/restore/block_ip failure path; 7 vm-context tests for
the UI changes. Live-verified on production: the bulk bar is now genuinely hidden, all
8 action buttons report `disabled` at load and enable on host selection, and the confirm
renders "Confirm action on WORKSTATION-B" / "Target host: WORKSTATION-B" — cancelled
without queueing anything (Pending Actions stayed 0). The requeue fix runs on *every*
agent check-in, so `WORKSTATION-A` returning to **Online** after the deploy is itself
proof the migration applied and the new SQL executes cleanly against the production
database — a missing `sent_at` column would have errored every check-in.

Per explicit user instruction, `WORKSTATION-A` was never isolated; `WORKSTATION-B`
was the authorized test host and was Offline throughout, so no live end-to-end
containment test was possible — hence the generated-script assertions.

### Reporting/Coverage usability review, Pass B (4 of 4, review complete: 9/9 findings)

- **Biggest UX win**: "Generate Report" was a synchronous form POST that froze the
  whole page for up to 120s with zero feedback (`subprocess.run(..., timeout=120)`
  inside the request handler). Extracted the shared generation logic into
  `_generate_report_now()` (used by both the original form route, kept intact for
  anything still hitting it directly, and a new `/api/reports/generate` JSON route).
  reports.html now calls the new route with the button showing a spinner while
  disabled, then refreshes the history table in place via the same `loadReports()` the
  initial page load already uses — no more frozen unresponsive page, even though
  generation itself is still synchronous server-side (this app has no background-job
  mechanism, per its own documented convention).
- Coverage's gap analysis had no click-through to build a rule. Added
  `buildRuleUrlForGap()`, reusing the exact same `?new_rule=1&mitre=&title=&
  description=` deep link Atomic Testing's own "Create Detection Rule" button already
  uses — wired into both the Prioritized Gaps table (a new "Build a rule" column) and
  the drilldown modal's "No rules are mapped" message.
- Report history had no type/status filter despite 28+ real reports already in
  production. Added two dropdown filters (`getFilteredReportHistory()`), with a
  filter-aware empty state distinct from the genuine "no reports yet" one.
- No visibility into whether the report schedule was actually running — saving
  rewrote the crontab with no persisted trace of success. Added a `last_applied_at`
  timestamp (stamped only on a confirmed-successful crontab rewrite, survives a later
  failed save, read back via `get_report_schedule_config()`) shown on the Schedule tab:
  a green confirmation with the timestamp, or a warning if a schedule is active but has
  never been confirmed applied.

Verified with 33 tests across 5 files: 10 fixture tests for `_generate_report_now()`'s
validation/branching (param clamping, successful/timeout/generic-error paths, the form
route and JSON route sharing identical results by construction); 5 fixture tests for
the schedule's `last_applied_at` persistence (fresh install has none, a successful
apply stamps it and it survives a reload, a failed apply neither stamps it nor erases a
prior successful stamp); 3 JS vm-context tests for `buildRuleUrlForGap()` and the
Prioritized Gaps table's new column; 6 JS vm-context tests for the report history
filters (type/status/combined AND semantics, filtered-empty vs. genuinely-empty
messaging); 9 JS vm-context tests for `submitGenerateReport()`'s spinner/disable
lifecycle, payload shape, and success/failure/network-error toast handling, plus the
schedule note's three states. Live-verified on production: clicked Generate Report and
watched the button show "Generating…" while the rest of the page — sidebar, filters,
the existing table — stayed fully interactive (no page freeze), then confirmed a real
new "Security Summary (30d)" row appeared in place (29→30 total) with no navigation;
turned on Security Summary's daily schedule, saved, and confirmed "✅ Crontab last
confirmed applied: 2026-09-14 08:41:53" appeared, then turned it back off (restored to
original all-off state); opened the real gap-tier technique T1589.001 (Credentials, 0
rules mapped) and confirmed its new "Build a rule" button correctly deep-linked into a
fully pre-filled New Custom Rule builder (title, description, and `attack.t1589.001`
MITRE tag all populated) — canceled without saving.

**Pass B complete (4/4). Reporting/Coverage usability review complete (9/9 findings) —
this closes out the user's full multi-part request across UEBA, Cases/SOAR, and
Reporting/Coverage.**

### Reporting/Coverage usability review, Pass A (5 of 9 findings)

Started the final pass of the user's original multi-part request — Reporting and
Coverage tabs, after UEBA and Cases/SOAR. Checked CHANGELOG first (two Reports passes
already happened this session: SOC lifecycle metrics/content additions, then a UX pass
on Branding/Email/Schedule) so these are genuinely new gaps, not re-flags. A live
walkthrough plus a background Explore agent produced 9 findings, split into two passes;
user approved "Pass A now, Pass B next."

- Coverage-by-Tactic grid technique names were truncated with ellipsis and no hover
  tooltip — confirmed live via DOM inspection (`<span class="cov-cell-name">Gather
  Victim Identity Information</span>` rendered as "Gather Vi..." with `title: null`).
  Added a `title` attribute carrying the full name.
- Vulnerability tab's 5 stat tiles were a Bootstrap grid bug: `col-6 col-md-3` × 5 = 15
  of 12 columns at the `md` breakpoint, wrapping "Still Open" — the most actionable
  number — onto its own row. Switched to `row-cols-md-5`, the correct Bootstrap idiom
  for N equal tiles when N doesn't factor into 12 (same recurring grid-math bug class
  fixed 3× elsewhere this session, this time the fix reaches for the right primitive
  instead of hand-balancing column counts).
- Vulnerability severity chips shared `.cov-chip`'s cursor-pointer/hover styling with
  the genuine filter chips elsewhere on the same page, but had no `onclick` — implying
  a filter that didn't exist. Wired them to actually filter the Findings table, with a
  filter-aware empty state ("No Critical findings. Clear filter") instead of the
  generic "no CVEs at all" message.
- The per-row Email button on the Reports tab was shown to everyone in JS, but
  `/api/reports/<id>/email` requires `settings.reports.manage` — every other
  permission-gated control on the same page (Branding inputs, Schedule selects) is
  properly hidden/disabled server-side via `has_permission()`; this was the one
  exception, only failing with a toast after a click. Gated it the same way using the
  existing client-side `hasPermission()` mirror (base.html).
- `report_history` had no column recording which lookback window (7/30/90/180 days) a
  report was generated with, even though the Reports tab lets an analyst pick one per
  generation — two same-day same-type rows were indistinguishable. Added
  `migrate_report_history_days()` (exact mirror of the existing
  `migrate_report_history_framework()`), threaded `report_days` through
  `_record_history()`/`run_report()` (NULL for `vulnerability`/`case` report types,
  which genuinely aren't day-windowed — a live inventory snapshot and a
  not-time-bounded case summary respectively), and surfaced it next to the type/
  framework label ("Security Summary (7d)").

Verified with 18 tests across 3 files: 6 SQLite fixture tests for the days-persistence
logic (security/compliance reports persist their window, vulnerability/case reports
correctly store NULL even when a days value was resolved, a failed generation still
records its attempted window, the migration is idempotent across two runs); 6 JS
vm-context tests for `covCellHtml()`'s title attribute and the severity-chip filter
(real filtering, toggle-off, the filter-aware empty state); 6 JS vm-context tests for
`renderReportHistory()`'s Email-button permission gating and the report_days display
(shown when present, omitted when null, shown alongside a framework label). Live-
verified on production: the real "Gather Victim Identity Information" technique cell
carries its full name in `title`; the Vulnerability tab's 5 tiles now sit on one row;
clicking the real "Critical" chip (0 findings currently) shows the active state and the
filter-aware empty message; generated a real 7-day Security Summary report and
confirmed it landed in history as "Security Summary (7d)" with the Email button present
for the admin account. That real report (`report_history` id for 2026-09-14 08:13:41,
29 total reports now) stays in history — no delete route exists for reports (permanent
audit trail by design, same as flagged for earlier test reports this session).

**Pass A complete (5/5). Pass B (4 items, including the biggest UX win — async report
generation with progress feedback) next.**

### Cases/SOAR usability review, Pass B (5 of 5, review complete: 10/10 findings)

- Case list showed SLA breach status only as one aggregate stat tile — `api_cases()`
  now computes `sla_breached` per row (reusing `_case_sla_hours_for`'s own
  queue/severity-tier precedence), rendered as a red "SLA Breached" badge next to
  Status. Clicking the SLA Breaches tile now filters the list down to just those
  cases; click again to clear it.
- **Safety-relevant**: Pending Approvals showed a raw JSON params dump instead of a
  human-readable description, right when an analyst decides whether to approve a
  potentially destructive action (`quarantine_file`, `kill_process_by_name`).
  `api_playbook_approvals` now computes the same dry-run preview text the Test modal
  already shows, by calling the existing `_run_playbook_action(..., dry_run=True)` per
  row (read-only for every action type) — falls back to the raw dump only if that
  computation itself fails.
- A real playbook run's outcome landed in the case Timeline as one flat
  semicolon-joined string, unlike the dry-run preview's clean per-step cards for the
  exact same actions. `_execute_playbook_actions` now also returns a structured
  per-action list; the 3 real-run call sites log a JSON `{label, flat, actions}` blob
  instead of plain text (`playbook_runs.detail` and the Recent Runs modal are
  untouched — still the flat string). `caseEventLabel`'s `playbook_run` handler
  renders per-action cards when the detail parses as that JSON shape, and falls back
  to plain text for the still-flat rate-limit-tripped event and any pre-existing row
  written before this change.
- Alert-triggered playbook runs showed plain text with no click-through, unlike
  case-triggered runs which already link to the case. Wrapped in the same
  `?item_id=&item_type=alert` deep link already used elsewhere (Log Search's existing
  single-row resolution).
- Playbook actions had no reorder control — fixing an out-of-order step meant deleting
  and re-adding every action after it. Added move-up/move-down buttons;
  `savePlaybook()` already derives each action's position purely from DOM order, so
  this is just a DOM-node swap, no other state to keep in sync.

Verified with 15 tests across 3 files: 6 SQLite fixture tests for `sla_breached`
(open-past-default, open-within-SLA, closed-never-breached, queue override wins over
default, severity tier applies with no queue override, multiple cases evaluated
independently); 4 fixture tests for the Pending Approvals preview computation (success,
exception swallowed to null, null-params handling, one row's failure doesn't affect
others); 5 fixture tests for `_execute_playbook_actions`'s structured output (all
succeed, gated action queued not run, failure marks partial, pending_approval beats
partial, the JSON blob shape); JS vm-context tests for the SLA-filter toggle, the
Pending Approvals frontend fallback, `playbookRunLabel()` (structured cards, status
colors, the still-plain-text rate-limit event, a pre-existing flat-string row), and
`movePlaybookActionRow()` (swap up/down, no-op at either end, repeated moves walking a
row to the top).

Live-verified on production: all 5 real open cases correctly show "SLA Breached"
badges matching the aggregate count of 5; clicking the tile filters the list to those 5
and back; the playbook action-reorder buttons correctly swapped two real rows in the
Edit Playbook modal; ran the real "New Case Checklist" playbook against the disposable
`TEST: SOC Metrics Demo Data` case via Run Now and confirmed its case Timeline rendered
a clean "Apply Template" card instead of flat text; added a temporary `add_note`
approval-gated action, ran it, and confirmed Pending Approvals showed the actual note
text ("would add a note: ...") instead of raw JSON — then rejected it and removed the
temporary action, restoring the playbook to its original single step. Test data (the
temporary playbook action, the approval, and 10 duplicate tasks from two verification
runs) all cleaned up afterward; the test case was briefly reopened to remove the
duplicate tasks (its own deletion endpoint correctly 403s on a closed/read-only case)
and closed again to its original state.

### Cases/SOAR usability review, Pass A (5 of 10 findings)

Asked to run through Cases/Investigations and SOAR for simplification/
analyst-friendliness, same as the UEBA passes. A live walkthrough plus a background
Explore agent's code research (52 tool calls) produced 10 findings, split into two
passes by risk/depth; user approved "Pass A now, Pass B next." Pass A covers the
lower-risk labeling/visibility fixes plus one confirmed bug:

- **Confirmed live bug**: the "Link Case" form on the case-detail Case Links tab
  stayed visible and enabled on a closed, read-only case. Same `d-flex` + inline
  `style="display:none"` Bootstrap bug already fixed once this session (the Related
  Items bulk bar) — Bootstrap's `!important` utility class was permanently winning
  over the plain inline toggle `renderCaseLinks()` does. Dropped `d-flex` from the
  static class list; the toggle now sets `display:flex`/`none` directly. Caught by
  the research pass, confirmed live on the real closed case #9 (Delete/Link form was
  fully interactive there before the fix).
- The case list showed only binary Open/Closed, hiding the New/Investigating/Awaiting
  Input/Resolved `workflow_state` the case-detail view treats as primary — added the
  already-existing `workflowStateBadge()` next to Status in both the list table and
  the CSV export.
- Timeline entries for `case_linked`/`case_unlinked` events showed raw internal
  event-type strings ("case_unlinked") instead of human-readable text, inconsistent
  with every other Timeline entry type. Added both to `caseEventLabel()`'s map.
- "Related Items" and "Case Links" case-detail tabs showed no count badge unlike
  their siblings (Tasks/Linked Items/Assets/Indicators), even though both are fetched
  before the tab is ever opened — added `setCaseTabCount()` to update each tab's
  label once its own data loads, e.g. "Related Items (4809)" on a real noisy case.
- SOAR's "Status changed" trigger was labeled ambiguously — it only fires on Status
  (Open/Closed), never on the `workflow_state` moves (New/Investigating/Resolved) the
  case-detail edit UI visually presents as one merged "Status" dropdown. Relabeled to
  "Status changed (Open/Closed only — not New/Investigating/Resolved)" so an admin
  building a workflow-state trigger doesn't reach for this one and get nothing.

Verified with 11 JS vm-context tests across two files: `workflowStateBadge()`'s
label/color per state and null fallback; `case_linked`/`case_unlinked` render human-
readable text while an unmapped event type still falls back to its raw name unaffected;
`setCaseTabCount()` updates the right label span and no-ops safely when the element
isn't found; `renderCaseLinks()`'s display toggle is `flex` on an open case and `none`
on a closed one (the actual bug-fix assertion); the CSV export gains a Workflow State
column with the humanized label and a null-safe "New" fallback. Live-verified on
production against real cases: the list now shows both badges per row; case #9's Link
Case form is correctly hidden now (previously always visible); its tabs read "Related
Items (4809)" and "Case Links (0)"; case #8's Timeline shows "🔗 Case link added:
Related to case #5" / "🔗 Case link removed: case #5" instead of the old raw strings;
and the SOAR trigger dropdown shows the corrected label.

**Pass A complete (5/5). Pass B (5 items, including a safety-relevant Pending Approvals
fix) next.**

## 2026-09-13

### UEBA ideas from Exabeam screenshots (1/2): departing-employee risk signal

User shared Exabeam UEBA screenshots and asked what's learnable/adaptable. One
screenshot showed an actual scored risk reason: "HR Risk: Gary Hardin gave notice." —
a real, well-known insider-threat pattern (data exfiltration risk spikes on the way
out) with no equivalent here. Confirmed via research: `identities` had no
termination/offboarding field at all, and the demo case title "Potential data
exfiltration by departing employee jdoe" had nothing behind it.

Added `identities.departing` (boolean) + `departing_note` (free text, e.g. "2 weeks'
notice given"), migrated the same one-column-at-a-time way `watched`/`watch_reason`
were. Weighted the same way `privileged` already is — a ×1.5 multiplier — and
*compounds* with privileged rather than replacing it (×2.25 for a departing privileged
account, exactly the highest-risk case this exists for). Updated all three places that
independently compute this multiplier (`app.py`'s `_run_case_analysis` and
`api_ueba_risk_scores`, `ueba_engine.py`'s `run_autocase_check`) to keep them in sync,
matching this codebase's existing dual-definition-config convention. Surfaced as a
checkbox + note field on the Asset & Identity tab (same pattern as Privileged/Watch)
and as a read-only "Departing" badge in the risk detail modal's identity panel (added
last pass) and the Risk Scoring table's multiplier tooltip.

Verified with a real SQLite fixture test (12 cases): create/update correctly
store/toggle the flag and note without clobbering unrelated fields, un-flagging keeps
the note (same convention as `watch_reason` surviving unwatch), and the multiplier
expression itself correctly computes 1.0x/1.5x/1.5x/2.25x for
neither/departing-only/privileged-only/both — including the LEFT JOIN case where a
user has no `identities` row at all. Plus a JS vm-context test (3 cases) for the badge
rendering in the identity quick-actions panel. Live-verified on production against the
real `analyst-a` user: flagged privileged+departing, confirmed `/api/ueba/risk-scores`
returned `multiplier: 2.25` and `score: 15754.5` (exactly `7002 raw × 2.25`), confirmed
the Risk Scoring table rendered "15754.5 ×2.25" with the updated tooltip wording, and
confirmed the risk detail modal's identity panel showed both real badges — test
identity deleted afterward, restoring the table to its original empty state.

### UEBA ideas from Exabeam screenshots (2/2): rule rationale shown to analysts

A second screenshot (a case's Threat Timeline) showed each fired detection's own
descriptive rationale text, not just its rule name. Confirmed via research: Micro
DFIR's custom UEBA rules (`anomaly_rules`) had no `description` field at all — the risk
detail modal only ever showed "Matched rule 'X'", never why an admin built it.

Added `anomaly_rules.description` (optional free text), a textarea in the rule
create/edit modal, and a JOIN in `api_ueba_risk_score_detail` (via the already-existing
`risk_score_events.rule_id` — the plumbing to look up which specific rule produced an
event already existed for the Scoring & Rules tab's match-count columns) so the
detail modal can show an info icon carrying the rule's rationale as a tooltip next to
the indicator name. Only ever appears for rule-derived indicators
(`custom_alert_rule`/`first_time_action`/`sequence_chain_progression`) — every built-in
behavioral model (`sigma_alert`, `off_hours_activity`, etc.) has no matching rule and
correctly shows nothing. A grouped row spanning more than one distinct custom rule
(the grouping key is indicator+timestamp, not `rule_id`) takes the first description
seen rather than trying to show several — same simplify-the-display tradeoff the
existing 2-sample detail truncation already makes.

Verified with a real SQLite fixture test (3 of the 12 total cases in this pass): a
rule's description is stored on create, the detail query's LEFT JOIN correctly
resolves a rule-derived event's description via `rule_id`, and a built-in indicator
(no `rule_id`) correctly comes back with `rule_description = NULL` rather than an
error. Plus a JS vm-context test (5 cases): the info icon appears with the right
tooltip for a rule-derived event, no icon for a built-in one, first-non-null-wins
across grouped events, and the rule modal correctly prefills/clears the description
field on open for an existing vs. brand-new rule. Live-verified on production: wrote a
real rationale for the actual "Named-User Alert Sourced from Internal Network" rule
(125 real historical matches), confirmed every `custom_alert_rule` row in `analyst-a`'s
real risk breakdown now carries the ⓘ info icon with that text — left in place
afterward as genuinely useful documentation, not reverted like the session's usual
disposable test data.

### UEBA usability pass 2 (item 2 of 3, pass complete): Timeline severity filter, pivots, and DSL discoverability

Three related gaps in the same tab, fixed together:

- No severity filter existed in the sidebar despite `/api/logs/search` already
  supporting a `severity` param server-side (`_build_log_other_filters`) — added
  Critical/High/Medium/Low/Info checkboxes (none checked = no filter, preserving
  today's default) and wired `getTimelineSeverities()` into `loadTimeline()`'s query
  params.
- Host and username in the Entity column were plain text — generalized the existing
  process-only pivot helper into `fieldPivotLink()` and used it for host/username too,
  matching `dashboard.html`'s `pivotLinkHtml` convention (host/username are both
  already `PIVOT_COLUMNS` there).
- Each row had no way to reach its own full detail/triage/add-to-case/link-to-entity
  view — that already exists in Log Search (`dashboard.html`'s `showLogDetail` modal),
  so rather than duplicating it in a second template, added a deep link using the same
  `?item_id=&item_type=` mechanism MITRE Coverage's Validated popup already uses to
  jump straight to one exact row. No entry for EDR command rows — those already have
  their own view in `cases.html`, not Log Search, matching that deep link's existing
  carve-out.
- The Search box's query DSL (field:value, quoted phrases, -exclude, wildcards) had no
  discoverability — added the same click-to-insert "Try:" hint row Log Search's own
  Advanced Query box already uses, as `insertTimelineQueryHint()` scoped to this tab's
  own search box.

Verified with a JS vm-context test (10 cases): severity checkbox selection state maps
correctly to the query param (including the "none checked = no filter" default); the
DSL hint buttons insert into an empty vs. non-empty search box correctly; host/username
render as pivot links while a missing host falls back to plain "UNKNOWN" text with no
link and a placeholder "-" username is suppressed entirely; the item_type mapping is
correct per row type (alert/anomaly/log → alert/ueba_event/fim_event) and a command row
or a row with no id correctly gets no deep link at all. Live-verified on production
against real `WORKSTATION-A` data: checking Medium severity correctly narrowed 5244
matching events down to 3923; clicking a "host:WIN-A" DSL hint button correctly
inserted it and re-searched; clicking the real host link navigated to
`/siem?tab=search&q=host:WORKSTATION-A` with results loading; and following a real
row's deep link (`item_id=98212&item_type=ueba_event`) landed on Log Search with
exactly 1 matching result, which opened the actual existing Log Detail modal (Add to
Case, full process/message detail) for that exact rare-process anomaly.

**Pass 2 complete (3/3 — 1 pivots item, this Timeline item covering the originally
separate 6/7).**

### UEBA usability pass 2 (item 1 of 3): Data Insights histograms are now click-through

Started Pass 2, the second of two approved UEBA usability passes. Every histogram row
in Data Insights (By Entity's Top Alerts/Related Entities/Top Source & Destination
IPs/Admin Activity, and By Model's Top Entities) rendered as plain text — an analyst
spotting something worth chasing had to retype the value into Log Search or the entity
search box by hand rather than clicking straight there.

Added an optional `linkFn` to `renderTableHistogram()`: Top Alerts and Admin Activity
rows do a raw-text Log Search pivot (matching the existing Top-Firing Anomaly Rules
chart convention already in `dashboards.html`); Top Source/Destination IP rows pivot
field-scoped to `source_ip`/`destination_ip`; Related Entities and Top Entities (By
Model) rows open that entity's own risk detail modal in place (the modal lives outside
any tab-pane, so it opens regardless of which UEBA tab is active). Risk Contributions
rows get no link — they're already the selected entity's own breakdown, nothing
external to jump to.

Added `escJs()` (this file's own copy of the helper already duplicated per-file
elsewhere, e.g. `cases.html`) because the existing `escHtml`-only pattern used
elsewhere in this file is actually unsafe for building an onclick's JS-string argument:
`escHtml` turns a literal `'` into the HTML entity `&#39;`, which the browser decodes
back to a literal `'` *before* the onclick body is compiled as JS — still closing the
string early for any value containing an apostrophe (e.g. a rule or alert name).

Verified with a JS vm-context test (6 cases): `escJs` itself neutralizes apostrophes
and backslashes; a Top Alerts row (including one with an apostrophe in its name) links
to an escaped raw-text pivot; a Related Entities row links to that entity's risk detail
modal; IP rows link field-scoped; Risk Contributions rows get no link; a Top Entities
(By Model) row pivots using the raw entity id, not the emoji-prefixed display text.
Live-verified on production against the real `analyst-a` user: clicked the real
`WORKSTATION-A` row under Related Hosts and confirmed its own risk detail modal
opened with real data (Priority 10/10, `rare_process_population`/`process_lineage`/
`new_destination_ip` events), then clicked the real "Suspicious PowerShell Execution"
row under Top Alerts and confirmed it landed on Log Search with that exact query
pre-filled and loading.

### UEBA usability pass 1 (item 4 of 4): description info-icon + Never Matched badge on Scoring & Rules

The Scoring & Rules list table had no indicator for a rule's `description` field
(invisible until the Edit modal was opened, even though the risk detail modal already
shows it as an info-icon tooltip via a JOIN on the same field) and no in-table "Never
Matched" signal, despite `matches_total` already being computed server-side
(`_ANOMALY_RULES_TUNING_SQL`) and a "Never Matched" quick-filter chip already sitting
above the table — an analyst had to apply that filter to discover which rules never
fire, rather than seeing it at a glance per row.

Added the same info-icon convention next to the rule name in `arRenderTable()`, and a
"Never Matched" badge in the Last Matched column when `matches_total` is 0 (falls back
to a plain dash if a rule somehow has matches but no resolved `last_matched` — avoids a
false claim). Pure frontend change; the backend already selected everything needed.

Verified with a JS vm-context test (5 cases): a rule with a description shows the info
icon with that exact text as its tooltip, one without shows no icon, a rule with zero
total matches shows the Never Matched badge, a matched rule shows its timestamp
instead, and a matches_total>0-but-no-last_matched edge case still avoids the false
badge. Live-verified on production against real data: 6 of the real 15 rules
("Critical/High-Severity Alert with Internal Lateral Movement," host and user variants,
etc.) correctly show the Never Matched badge, and the real "Named-User Alert Sourced
from Internal Network" rule's info icon carries its actual rationale text (added last
pass) — confirmed by reading the `title` attribute directly.

**Pass 1 complete (4/4).**

### UEBA usability pass 1 (item 3 of 4): Departing status on the Insider Threat Watchlist widget

`/api/dashboards/watchlist` selected everything about a watched identity except
`departing`/`departing_note` — exactly the signal this widget exists to surface (the
whole reason `departing` was added last pass was the classic "risk spikes on the way
out" insider-threat window). Added both to the SELECT and a "Departing" badge (note as
its tooltip) next to the username in `renderWatchlistWidget()`, matching the same badge
convention already used in the risk detail modal and the Asset & Identity table.

Verified with a real SQLite fixture test (3 cases): a departing watched user carries
the flag and note through the watchlist query, a non-departing one shows a falsy flag,
and an unwatched departing user is still excluded regardless. Plus a JS vm-context test
(3 cases) for the badge rendering, including the pre-existing empty-state row staying
unaffected. Live-verified on production: added a real test identity
(`qa_test_departing_user`) flagged both departing and watched with a note, confirmed
the Insider Threat dashboard's Watchlist widget rendered the red "Departing" badge with
the note as its tooltip (`title` attribute read directly via devtools), then deleted
the test identity, restoring the table to its original empty state.

### UEBA usability pass 1 (items 1-2 of 4): Add Identity grid overflow, inaccurate Rare Process label

Asked to run two more usability passes over UEBA. A live walkthrough plus a background
research pass surfaced 7 findings; user approved doing 4 now (this entry covers the
first 2) and 3 next.

Fixed a Bootstrap grid overflow in the Asset & Identity "Add Identity" form: a prior
pass added the Departing checkbox as `col-md-2` without rebalancing Username/Department
(each `col-md-3`), pushing the row to 14 of 12 grid columns and wrapping the Add button
onto its own line below the fields on every md+ screen. Rebalanced all six fields to
`col-md-2` (12 total). Pure CSS grid math, no JS logic involved — verified live in the
browser rather than with a fixture/vm test, same as the earlier `d-flex`/`!important`
bug this session.

Also corrected the "Rare Process" Model Tuning label, which said "Flag processes rare
across the whole fleet" — factually wrong. The underlying model
(`_run_rare_process_population_model` in `ueba_engine.py`) is tier-aware: it compares a
host's process rarity against its own `assets.criticality`-tier peers first, only
falling back to fleet-wide when that tier doesn't have enough hosts to compare against.
The Dynamic Scoring config field for this same model already described it accurately
("Rare Process (Peer-Tier or Fleet-Wide)") — the admin-facing tuning control just hadn't
been updated to match. Corrected that label plus the two other "(Fleet-Wide)"-only
labels (Data Insights model dropdown, `INSIGHTS_MODEL_LABELS`) for consistency.
Live-verified all three on production.

### Insider threat workflow review (1/2): quick "Watch This User" from the risk detail modal

Asked to run through the insider-threat process specifically. Live-verified current
state: the `identities` table is completely empty on this deployment (the Insider
Threat dashboard's Watchlist widget literally says so), but the same dashboard's Top
Risky Entities widget shows real live data — including the real user `analyst-a` at a
genuine 9.4/10 Critical priority score. Investigating that gap surfaced the actual
friction: UEBA's Risk Scoring detail modal (`viewRiskScoreDetail`) shows a full score
breakdown for any entity, including users, but had zero identity/watchlist context or
actions — the *only* place to flag someone as watched was the separate Asset & Identity
tab, and that tab's Add Identity form is entirely blank with no prefill, forcing an
analyst who just spotted a risky user to retype the exact username from memory on a
different screen.

Added `renderIdentityQuickActions()` to the risk detail modal — for `entity_type ===
'user'` only (identities are username-only, no host column; a host's equivalent is
Asset criticality, unaffected). Fetches the existing identity list (already used by the
Asset & Identity tab) and shows real Privileged/Watched badges plus a single
context-appropriate action: "Watch This User" (creates the identity as watched in one
step if none exists yet, or flips the flag if one does) or "Remove from Watchlist".
Gated to `assets.manage` for the button, same as the Asset & Identity tab's own
controls — a non-admin still sees the real badges (informational, matching that tab's
own read-only-for-non-admins convention and the already-ungated `GET /api/identities`),
just no button. Keeps the Asset & Identity tab's own table in sync afterward if it's
already been loaded this session.

Verified with a JS vm-context test (9 cases): renders nothing for a host entity, an
untracked user shows "Watch This User" with the username prefilled via a data
attribute (no raw-string interpolation into the onclick), an existing unwatched
identity shows its real Privileged badge and a Watch button keyed to its real id, an
already-watched one shows Remove instead, a non-admin sees badges but no buttons,
creating a new watched identity in one step succeeds and toasts, a create failure
(e.g. a race where the identity already exists) surfaces the real server error, and a
toggle failure shows an error toast rather than a false success. Live-verified on
production against the real `analyst-a` user (9.4/10 Critical): opened their risk detail,
clicked "Watch This User", and confirmed `/api/dashboards/watchlist` immediately
returned them with the real priority score and `watched_by: "admin"` — then clicked
"Remove from Watchlist" and deleted the test identity row, restoring the table to its
original empty state.

### Insider threat workflow review (2/2): drill-down from the Insider Threat dashboard, plus a real display bug found along the way

Second finding from the same review: the Insider Threat dashboard's two flagship
widgets — Watchlist and Top Risky Entities — were fully static, confirmed via source
(neither `renderTopRiskWidget()` nor `renderWatchlistWidget()` in `dashboards.html` had
an `onclick` anywhere). An analyst scanning the dashboard for who's risky (it showed
the real user `analyst-a` at a genuine 9.4/10 Critical) had no way to click through — they
had to separately open UEBA and search for that exact entity by hand.

Added `pivotToRiskDetail(entityType, entityId)` and wired it to both widgets' rows,
navigating to `/ueba?tab=risk&entity_type=&entity_id=` — a new pair of params
`ueba.html`'s existing `?tab=` deep-link init code now resolves straight to that
entity's risk detail modal (opening the same "Watch This User" panel added in 1/2).
`loadRiskScores()` now returns (and stashes in `_riskScoresLoadPromise`) its fetch
chain so the deep-link handler can await whichever load `switchUebaTab('risk')` itself
already triggered, instead of firing a second redundant fetch just to know when it's
safe to open the modal.

**Bug found and fixed along the way, unrelated to the drill-down feature itself**: the
risk detail modal's contributing-events table was showing the literal text `&middot;`
instead of a bullet separator between grouped detail samples — a real display bug an
analyst pointed out directly from a screenshot during this work. Root cause: `viewRiskScoreDetail()`
joined multiple detail strings with the literal `&middot;` HTML entity *before* passing
the combined string through `escHtml()`, which escaped the entity's own `&` into
`&amp;middot;` — every other `&middot;`/`&times;` use in this codebase is written as
raw literal HTML outside any `escHtml()` call for exactly this reason. Fixed by
escaping each detail piece individually first, then joining with the raw (correctly
unescaped) entity.

Verified with a JS vm-context test (6 cases across both files): the pivot link builds
the correct deep-link URL and URI-encodes the entity id, the fixed `&middot;` join
renders as a real entity (not literal text) while still HTML-escaping each piece
individually (XSS safety unchanged), and a regression-baseline test confirms the old
join-then-escape expression really did double-escape. Source-inspection checks confirm
the `?entity_type=&entity_id=` deep link correctly switches to the risk tab, awaits the
right load promise without double-fetching, and the plain `?tab=` path is unaffected
when no entity is specified. Live-verified on production: clicking the real `analyst-a` row
in Top Risky Entities navigated straight to `/ueba?tab=risk&entity_type=user&entity_id=
analyst-a` and auto-opened the detail modal with the `&middot;` fix visible as a real
bullet between grouped rule-match details; separately watched `analyst-a` to verify the
Watchlist widget's own row pivots identically and lands on the modal already showing
"Watched" — test identity deleted afterward both times.

### Cross-screen triage friction, round 3 (1/3): EDR quick actions for UEBA anomalies too

Asked to run the triage-workflow review through once more. First finding: the EDR
quick-actions panel added in round 2 (Isolate Host/Kill Process) only ever rendered for
`type === 'alert'` — a UEBA anomaly never got it, even though an anomaly carries a real
host just as much as a Sigma alert does. Verified live against a real anomaly on
`WORKSTATION-A` (which has an active EDR agent): the triage modal showed "Add to
case"/"Link to entity" but nothing for containment.

The gap was structural, not deliberate: `alertEdrWrap`'s `<div>` lived nested inside
the alert-only "Triage" block (Status/Assignee/Save — genuinely alert-specific, UEBA
anomalies have no triage-lifecycle columns), so it never even existed in the DOM for an
anomaly. Moved the div out to render for `alert` or `anomaly` alike, right after the
enrichment panel, and widened the `renderAlertEdrActions()` call site to match. "Fired
before"/"Noisy" stay alert-only on purpose — both are `rule_id`-driven and don't map to
an anomaly.

Verified by confirming (via source inspection, since `renderAlertEdrActions()` itself
was already fully covered by round 2's 10-case vm-context test) that the wrap div and
call site both now gate on `alert || anomaly`, the old combined alert-only call site is
gone, and `alertEdrWrap` no longer sits inside the alert-only Triage block.
Live-verified on production against the same real rare-process anomaly on
`WORKSTATION-A`: the modal now shows UEBA Risk *and* EDR Agent (Idle) with working
Isolate Host/Kill Process buttons, and clicking Isolate Host triggered the real confirm
dialog — declined, confirmed via `agent_commands`'s unchanged latest row id that
nothing was queued against the real host.

### Cross-screen triage friction, round 3 (2/3): "Run Playbook" directly from a case

Second finding from the same review: a working manual "Run Now" playbook-execution
control already existed, but only on the standalone SOAR page, where it asks which
*case* to run against via a dropdown. An analyst already looking at a case who wants to
fire an existing playbook against it (e.g. "run the containment playbook now") had to
leave the case, go to SOAR, find the playbook's row, then re-select the exact case they
just left.

Added a "Run Playbook" card to a case's Timeline tab (`cases.html`) — the natural
pairing, since `playbook_run` events already surface there — with a playbook picker and
the same Test (dry-run, no changes) / Run Now (real, confirmed) split soar.html's own
control offers, reusing the identical `POST /api/playbooks/<id>/dry-run` and
`/run` endpoints, just scoped to `activeCaseId` instead of a re-picked one. Gated by
the same `soar.playbooks.manage` permission those endpoints already require
server-side (and soar.html's own control already requires client-side), so this never
shows to someone who'd just get a 403. A successful "Run Now" refreshes the case (same
convention every other case mutation here already uses) to show the new Timeline entry.

Verified with a JS vm-context test (8 cases): the card is hidden (and fetches nothing)
without permission, populates real playbooks with disabled ones labeled, Test requires
a selection first, a dry-run correctly reports would-fire/would-not-fire with the real
skip reason, Run Now names the selected playbook in its confirm dialog and does nothing
if declined, a real run executes against `activeCaseId` (not a re-picked case) and
refreshes to show the result, and a `pending_approval` run status is styled distinctly
from a plain success. Live-verified on production against a disposable test case:
"Test" against the real (only existing) "New Case Checklist" playbook correctly showed
"Would fire on trigger 'case_created'"; "Run Now" (confirmed) really executed it,
adding the real "Generic Investigation" template's 5 tasks and logging a
`playbook_run` Timeline event tagged "(run manually)" to distinguish it from the same
playbook's earlier automatic case_created run — test case deleted afterward.

### Cross-screen triage friction, round 3 (3/3): bulk-add in the case's own Related Items tab

Third finding, and the same one flagged (but not actually fixed for this specific
screen) back in round 1 item 5: a case's Related Items tab surfaces other alerts/UEBA
anomalies/FIM events on the case's own hosts that aren't linked yet, capped to 20 rows
per category with a "(showing X of Y)" note — but still only a single "+" button per
row. Round 1's fix only added bulk-select to the SIEM alert list's own toolbar, a
different screen entirely. Verified live: real case #8 currently shows "20 of 676"
alert candidates and 6,041 UEBA anomaly candidates.

Added a checkbox to each `relatedItemRow` (alongside its existing single-item Add
button, not replacing it) plus a "Add Selected to Case" bar that only appears once
something's checked. Reuses the same `Promise.all` fan-out pattern the SIEM bulk
toolbar's `bulkAddToCase()` already uses, POSTing to the same generic
`/api/cases/<id>/items` route — but with one `openCaseDetail()` refresh at the end
instead of `addRelatedItem()`'s own per-row full-case-reload, which is what actually
makes bulk-adding N items faster than clicking Add N times rather than just more
convenient.

Verified with a JS vm-context test (7 cases): each row keeps its existing single-add
button and gains a working checkbox, a fresh render shows the real candidate scale and
starts with the bulk bar hidden/selection cleared, checking/unchecking rows correctly
shows/updates the bar and count, a mixed-type bulk add (alert + ueba_event + fim_event)
fans out one POST per item and refreshes exactly once, a `"ueba_event:42"` selection
key splits correctly on the first colon (not the type's own underscore), and a
declined confirm or an empty selection makes zero network calls.

**Caught live, fixed before shipping**: the bulk bar's initial class list included
Bootstrap's `d-flex`, whose `display:flex !important` permanently overrode the plain
inline `display:none`/`flex` toggle `toggleRelatedItemSelect()` sets at runtime — the
bar rendered visibly ("0 selected") even with nothing checked. The exact same class of
bug dashboard.html's own `bulkTriageBar` already had to avoid, just missed here since
a `vm`-context test has no real CSS cascade to catch a `!important` conflict. Removed
`d-flex` from the class list; live-verified afterward on production with a real
disposable test case against real alert candidates on `WORKSTATION-A`: the bar now
starts hidden, correctly shows "1 selected" / "2 selected" as real checkboxes are
checked, and a real 2-item bulk add correctly linked both selected alerts — test case
deleted afterward.

### Cross-screen triage friction, round 2 (1/4): EDR quick actions in the alert triage modal

Asked to run the alert/case triage workflow through again looking for anything missed,
this time specifically hunting for places an analyst has to jump to a different screen
to do something. Found the sharpest example: the alert triage modal (Log Search's Log
Detail view) had zero EDR response capability at all — verified live against a real
Critical alert on `WORKSTATION-A` (which has an active, online enrolled agent) that
containing the host meant closing the modal and either navigating to the standalone EDR
page, or escalating to a case first just to reach its EDR Response tab.

Added a small quick-actions panel (`renderAlertEdrActions()`) to the triage modal,
offering only the two Tier 1 (`edr.command.basic`) actions — Isolate Host and Kill
Process — matching the same two quick-shortcut icons cases.html's own Case Assets rows
already expose (not the fuller response-console catalog, which stays reserved for a
case already in progress). Reuses the exact same `POST /api/agent/commands` endpoint
and `/api/agent/checkins` host-resolution `cases.html`'s `queueCaseAssetCommand()`/
`knownAgentsByHost` already use — same confirm-dialog wording, same permission gate,
same "no agent found" / "Offline disables the buttons" behavior — just without the
case-linking step, since there may be no case yet. Renders nothing for a host with no
matching enrolled agent, and nothing at all for a user without `edr.command.basic`
(skips the fetch entirely rather than showing disabled buttons).

Verified with a JS vm-context test (10 cases): renders enabled actions for a known
non-offline agent, disables both for an Offline one, renders nothing for an unknown
host or a user without permission, Isolate Host uses the exact cases.html confirm
wording, a declined confirm or cancelled PID prompt makes zero network calls, Kill
Process validates the PID is numeric and trims whitespace, and a server-side queueing
failure surfaces its real error message. Live-verified on production against the real
`WORKSTATION-A` alert: the panel rendered correctly with its real "Idle" agent
status, and clicking both real buttons triggered the right confirm/prompt dialog with
the right host — deliberately declining/cancelling each time (never actually isolating
or killing anything on the user's real active laptop) and confirming via
`agent_commands`'s latest row id that nothing was queued either time.

### Cross-screen triage friction, round 2 (2/4): "Go to case" after escalating

Second fix from this same follow-up pass: escalating an alert to a case (single-item
"Add to Case" and the bulk toolbar's "Add to Case" from the last pass) only ever said
"Added to case." — no link back to it. An analyst who just escalated a Critical alert
had to close the modal, go to the Cases page, and find the case by title/scrolling to
keep working it.

`addToCase()` (dashboard.html) now shows a "Go to case" link alongside the success
message, pointing at `/cases?case=<id>` — the exact deep-link param format
`cases.html` already reads on load — opened `target="_blank"` (same convention as the
"View Rule" button) so the current Log Search view stays open rather than navigating
away from it. `bulkAddToCase()` gets the equivalent via `toast()`'s existing
`actionLabel`/`onAction` mechanism (already established in `threat_intel.html`'s
sweep-hit toast) instead of a link, since `toast()` has no HTML support. Both correctly
target the *actual* case used — the just-created case's own id when "+ New Case" was
picked, not whatever was in the dropdown before creation.

Verified with a JS vm-context test (5 cases): the link/action targets the right
existing case, targets a brand-new case's own id (not the stale `__new__` select
value), a failed add shows the plain error with no case link, and the bulk toast's
action opens the right case in a new tab for both the existing-case and new-case paths.
Live-verified on production: escalated the same real Critical alert via "+ New Case",
clicked the resulting "Go to case" link, and confirmed it opened case #20 in a new tab
(SIEM tab stayed put) with the right title, Critical severity, the alert already
linked, and its host already tracked as an Asset — test case cleaned up afterward.

### Cross-screen triage friction, round 2 (3/4): "View Full Detail" on a case's linked items

Third fix from the same follow-up pass: a case's linked `command_result` items already
got a "View Full Result" button opening a rich inline modal, but the other 3 item
types (`alert`/`ueba_event`/`fim_event`) were a dead end — only a 200-char message
excerpt, no way to see the full triage view (raw message, process details, enrichment)
without leaving the case to search Log Search by hand for a record with no obvious
search terms to find it by.

Generalized the existing `?alert_id=` Log Search deep link (previously hardcoded to
MITRE Coverage's "View Alert" popup, alert-only) into a `?item_id=&item_type=` pair
that also resolves `ueba_event` → the `anomaly` type checkbox and `fim_event` → the
`log` type checkbox (matching the already-documented "fim_event is really just a raw
live_logs row" naming quirk) — `?alert_id=` keeps working exactly as before for its
existing caller, unchanged. `itemSummaryLine()` (cases.html) now shows a "View Full
Detail" link using this deep link for the 3 item types that don't already have their
own modal, opened `target="_blank"` so the case stays open behind it.

Verified with a JS vm-context test (9 cases): the existing `alert_id` path is
unaffected, `item_id`+`item_type` resolves both new types to the right checkbox, an
unrecognized item_type falls back to `alert` rather than checking nothing, a normal
page load resolves to nothing, an alert/ueba_event item gets the right link,
command_result keeps only its existing modal button (no duplicate link), and a
deleted-underlying-record item shows no dead link. Live-verified on production: linked
a real Critical alert into a fresh test case, clicked its new "View Full Detail"
button, and confirmed the new tab landed on `/siem?item_id=855588&item_type=alert`
correctly resolved to `item_id:855588`, Type=Alerts, "All Time" — "Total Matches: 1"
showing exactly that one alert — test case cleaned up afterward.

### Cross-screen triage friction, round 2 (4/4, minor): entity info after "Link to Entity"

Fourth and last fix from this follow-up pass: linking an alert to a threat entity
(actor/malware family) only ever said "Linked to entity." — nothing about who or what
that entity actually is. Understanding it still meant a trip to Threat Intel's
Entities tab. Lower priority than the other 3 since entity-linking is a rarer action
than escalating or containing.

`renderLinkToEntityControl()` already fetches the full entity list to build the
`<select>` options — `linkToEntity()` now reuses that same in-memory list (no second
fetch) to show a compact summary card on success: the entity type badge (reusing
`threat_intel.html`'s own `entityTypeBadge()` styling), name, aliases, associated
technique count, and a truncated description. Falls back to the old plain text if the
linked id somehow isn't in the cached list, so this never renders blank.

Verified with a JS vm-context test (5 cases): the full summary renders correctly,
singular "technique" grammar at a count of 1 with no aliases line when there are none,
a cache-miss falls back to plain text, a failed link shows the plain server error with
no summary card, and hostile entity field values are HTML-escaped before being
inlined. Live-verified on production: linked the same real Critical alert to the real
seeded `APT28` entity and confirmed the card correctly showed the actor badge, name,
"(aka Fancy Bear, Sofacy)", "3 associated techniques", and its real description — then
deleted the test relationship (`ti_relationships` id 1) via its DELETE route.

### Analyst triage/investigation workflow improvements (1/7): severity inheritance on escalation

Live-walked the full alert-fires → triage → escalate → investigate scenario end to end
(a real recurring Critical alert, already flagged "Noisy" in Detection Tuning, on
`LAPTOP-1`) to find friction worth smoothing out. First fix: escalating an alert to a
**new** case (both the manual "Add to Case → New Case" UI flow and the single-rule
auto-case automation in `sigma_engine.py`) always created the case with `severity`
defaulting to the schema's `'medium'`, regardless of the triggering alert's real
severity — a Critical alert silently became a Medium case, understating its SLA
urgency (case SLA targets are tiered by severity). The backend's `POST /api/cases`
already accepted an optional `severity` param; nothing populated it from context.

Mapped alerts' Title-Case severity to cases' lowercase severity tier in both places,
matching the convention a *third*, already-correct case-creation path
(`soar_alerts.py`'s playbook-driven `_create_case_from_alert()`) already used —
`'Informational'`/unrecognized falls back to `'medium'`, same as that existing
precedent, rather than inventing a fourth convention. Adding evidence to an *existing*
case is untouched; this only affects what a brand-new case is created with.

Verified with a Python fixture test (function extracted and exec'd in isolation, since
`sigma_engine.py`'s `pysigma` dependency isn't installed in this dev environment) and a
JS vm-context test. Live-verified the manual escalation path on production: called the
real deployed `addToCase()` against an actual Critical alert and confirmed the
resulting case's `severity` came back `"critical"`, not the old default `"medium"`.

### Analyst triage/investigation workflow improvements (2/7): auto-track the host as a Case Asset

Second fix from the same walkthrough: the case's "EDR Response" tab is unusable
("Add a Case Asset above to run a response action against it") until a host is
manually re-added as a Case Asset — even though every alert linked into the case
already carries `hostname`. Real duplicate-data-entry friction on every one of 3
case-creation/item-linking paths (`app.py`'s `api_case_add_item`, `sigma_engine.py`'s
single-rule auto-case, `soar_alerts.py`'s playbook-driven case creation). A 4th,
pre-existing path (`sigma_engine.py`'s multi-rule host-escalation case creation)
already did this correctly — these 3 now match it.

`api_case_add_item` reuses `_case_item_summary`'s existing per-item-type host
resolution (alerts/agent_commands/live_logs/events each keep the hostname in a
differently-named column) instead of re-deriving it. All 3 rely on `case_assets`'
`UNIQUE(case_id, host)` via `INSERT OR IGNORE`, so linking a second item for an
already-tracked host is a safe no-op — no duplicate asset row, no duplicate
`asset_added` timeline event.

Verified with real SQLite fixture tests: `soar_alerts.py` imported directly (light
dependencies, unlike `sigma_engine.py`'s `pysigma` chain), `sigma_engine.py`'s function
extracted/exec'd, and `api_case_add_item` ported line-for-line (a Flask route) —
covering the auto-add itself, a no-host case that mustn't crash, and a second
same-host item not duplicating anything. Live-verified on production: linking a real
alert to a fresh test case immediately added `LAPTOP-1` as a tracked asset with no
manual step.

### Analyst triage/investigation workflow improvements (3/7): surface "fired before" at triage time

Third fix from the same walkthrough: the real recurring Critical alert used for this
whole pass had fired 5 separate times (once an hour) on `LAPTOP-1`, but opening any one
of those 5 alerts to triage it showed zero cross-reference to the other 4 — only
`occurrence_count`/`last_seen`, which only track repeats collapsed into that *one* alert
row within `sigma_engine.py`'s dedup window, not separate alert records. An analyst
triaging alert #5 had no way to see, from the triage modal itself, that this exact
rule+host combination had already fired (and been dispositioned) 4 other times without
navigating away to search for it manually.

Added `GET /api/alerts/history` (`rule_id` + `host` + optional `exclude_id`), returning
a count of other alert rows sharing that rule+host plus a breakdown by disposition
(`false_positive`/`resolved`/`investigating`/still-`new`). Wired into the triage modal
(`dashboard.html`) as a new async panel (`renderAlertHistory`), following the same
independent-fetch-into-its-own-DOM-slot pattern as the existing enrichment/add-to-case
panels — e.g. "4 other alerts for this rule on this host (2 False Positive, 1 Resolved,
1 Investigating)". Renders nothing for a genuinely first-time alert or one with no
`rule_id` (legacy built-in heuristic alerts predate Sigma rules), rather than an empty
placeholder panel.

Verified with a Python fixture test (SQLite, grouping/exclusion logic) and a JS
vm-context test (including a stale-response race: a slow lookup for an alert the
analyst has already clicked past must not overwrite the panel for the alert they're
now looking at — same guard pattern as `renderAlertEnrichment`'s existing token check).
Live-verified on production against a real recurring rule+host pair (`WORKSTATION-A`,
111 other alert rows for the same rule): the triage modal's new panel correctly showed
"Fired before: 111 other alerts for this rule on this host (111 still New)".

### Analyst triage/investigation workflow improvements (4/7): surface a rule's "Noisy" status + a tuning shortcut at triage time

Fourth fix from the same walkthrough: the real recurring Critical alert this whole pass
is based on was already flagged "Noisy" in Detection Tuning (72 alerts/7d against a
50-alert threshold) — but nothing on the alert's own triage view said so. An analyst
had to already know to check Detection Tuning, then search for the rule there by name,
before discovering the alert they were triaging was a known-noisy one worth tuning
rather than investigating fresh each time.

Added `renderAlertNoiseStatus()` to the triage modal (`dashboard.html`), reusing the
existing `/api/rules/tuning` endpoint and `classifyNoise()` threshold logic Detection
Tuning's own table already uses — no new backend route, no second noise-threshold
definition. Only renders for a rule that's actually crossed the Noisy threshold (a
Normal/Quiet/Never-Triggered rule shows nothing, so this stays informative rather than
cluttering every alert), showing the badge, the 7-day count, and a "Tune This Rule"
button that opens the same Detection Tuning modal analysts already use for severity
overrides and exclusions — reachable directly from the alert instead of a separate
navigate-and-search. `openTuneModal()` reads from the `allTuning` global that Detection
Tuning's own tab lazily populates on its first render; the new code back-fills it from
the same fetch if still empty, so the shortcut works even when an analyst opens this
straight from Log Search/Home and has never visited that tab this session.

Verified with a JS vm-context test covering: a Noisy rule renders the badge/shortcut, a
Normal rule renders nothing, a legacy alert with no `rule_id` skips the fetch entirely,
the `allTuning` back-fill only happens when it's actually empty (never clobbering a
fresher fetch Detection Tuning already made), and the shortcut hides the triage modal
before opening the tuning modal (avoiding Bootstrap's stacked-modal glitches, the same
pattern the existing `openRuleFromTuneModal()` uses). Live-verified on production
against the same real Noisy rule used for item 3 (73 alerts/7d, well over the 50
threshold): the triage modal correctly showed the Noisy badge and count, and clicking
"Tune This Rule" opened the real Detection Tuning modal for that exact rule with no
stacked-modal glitches.

### Analyst triage/investigation workflow improvements (5/7): bulk "add to case"

Fifth fix from the same walkthrough: the alert list's bulk triage bar already supported
Mark False Positive/Resolved/Investigating across a multi-select, but a case's Related
Items tab only ever linked one alert at a time — even browsing "20 of 319" untriaged
candidates for the same incident. Escalating a batch of related alerts (e.g. every
occurrence of the same Noisy rule an analyst just decided to investigate together)
meant opening each one's own triage modal individually just to link it.

Added an "Add to Case…" picker + button to the existing bulk triage bar
(`dashboard.html`), reusing the single-item `/api/cases/<id>/items` route with the same
fan-out-via-`Promise.all` pattern `bulkUpdateAlerts()` already uses — no new backend
route. The case picker lazily loads open cases once per session (memoized like
`loadAssetsCached()`/`loadTuningCached()`), same `+ New Case` flow as the single-item
Add-to-Case control. For a brand-new case, extended item 1's severity-inheritance
precedent to pick the *highest* severity among every alert in the batch
(`highestCaseSeverityAmong()`) rather than defaulting to Medium just because
severity-picking got ambiguous with multiple alerts involved.

Verified with a JS vm-context test (8 cases): highest-severity selection logic, the
cases picker loading exactly once despite repeated calls, a required-case guard, the
existing-case fan-out clearing selection on success, new-case creation using the
batch's worst severity, a cancelled prompt making zero network calls, and Clear
resetting both the checkbox selection and the picker's stale value. Live-verified on
production: bulk-selected 2 real Critical alerts, created a new case via the bulk
picker, and confirmed the resulting case had `item_count: 2` and `severity: "critical"`
— then deleted the test case and confirmed neither alert's own status/acknowledged
state had been touched by the link.

### Analyst triage/investigation workflow improvements (6/7): human-readable Timeline entries

Sixth fix from the same walkthrough: a case's Timeline tab logged item links as the raw
internal join key it's stored as — `"Item added: alert:855164"` — across all 4 places
that write it (`app.py`'s `api_case_add_item`, `sigma_engine.py`'s two auto-case paths,
`soar_alerts.py`). Meant nothing to an analyst reading the case history without cross-
referencing the Items tab by hand.

`caseEventLabel()` (`cases.html`) now resolves `item_added`/`item_removed` details
through a new `itemLookup` map — built once per case render from `c.items` (already
loaded in the same payload as `c.events`, no extra fetch) keyed the identical
`"item_type:item_id"` way the backend already writes `case_events.detail`. A still-linked
item now shows its real label (e.g. "Alert — Antivirus - Exploitation Framework
Signature") reusing `ITEM_KIND_LABELS`, the same catalog the Items tab itself uses — no
second type-name mapping. Falls back to a plain `"Kind #id"` (never the fully raw
string) when the item's since been removed or isn't in this render's lookup, and passes
an unrecognized detail shape through untouched, so nothing renders blank or throws.
Historical rows written before this change render exactly the same way — no backfill
needed, no schema change made.

Verified with a JS vm-context test (6 cases): resolves to a real label when still
linked, falls back to "Kind #id" when not in the lookup or the underlying record's
summary is gone, an unrecognized item_type still renders using the raw type name, a
non-matching detail shape passes through untouched, and an item label containing HTML
is properly escaped before being inlined into the Timeline row. Live-verified on
production against a real case's actual history: a still-linked EDR response action
now shows "Item added: Response Action — **collect_browser_artifacts**", while an item
added and later removed from the same case correctly falls back to "Item added/removed:
Response Action #113" instead of the old raw `command_result:113`.

### Analyst triage/investigation workflow improvements (7/7, minor): normalized UEBA risk score in the triage modal

Seventh and last fix from the same walkthrough: the alert triage modal's UEBA Risk
enrichment panel showed a raw, unbounded cumulative point sum — e.g. "Critical (861,106
pts)" for a busy real host in this deployment — with no sense of scale. `ueba.html`'s
own risk detail modal had already solved exactly this: it leads with the normalized
0-10 `priority_score` (a peak-severity/signal-breadth/recency blend, comparable across
entities) and demotes the raw sum to "supporting detail, not the headline," with an
explicit comment explaining why. The triage modal's enrichment panel just never got the
same treatment.

Added `riskScoreDisplay()` to `dashboard.html`, applying that exact same precedent:
shows `priority_score/10` when a priority row exists for the entity, falling back to the
raw `N pts` only when it doesn't yet (new entities before `ueba_engine.py`'s next scoring
pass) — mirroring `api_ueba_risk_score_detail`'s own priority-first-with-fallback tier
logic server-side. No backend change: the `/api/ueba/risk-scores/<type>/<id>` route
already returned `priority` in its response; the frontend just wasn't using it here.

Verified with a JS vm-context test (4 cases): uses the normalized score when available,
falls back to raw pts when no priority row exists yet, correctly treats a real
`priority_score` of exactly `0` as a value (not "missing"), and escapes values before
inlining. Live-verified on production against the same real Noisy-rule alert used for
items 3-4: the enrichment panel now reads "UEBA Risk: Host Critical (10/10) User
Critical (9.4/10)" instead of the old "Critical (879,728 pts)".

This closes out all 7 findings from the alert-fires → triage → escalate → investigate
walkthrough that started this pass — see the 2026-09-13 entries above for the full set.

## 2026-09-12

### Report content improvements (1/7): SOC effectiveness metrics in the Security Summary

Research pass into what would make the generated reports more useful, working through
7 findings in order. First: `api_dashboard_case_stats` (app.py:11119) already computes
MTTD/MTTA/MTTI/MTTC/MTTR, false-positive rate, SLA compliance, reopen rate, and
escalation rate — the same numbers the Home dashboard's "Case Metrics & SLA" widget
shows — but the Security Summary report only ever ported the basic open/closed case
counts, leaving out the metrics a periodic report's reader would want most. Ported the
full query set into `generate_report.py`, which also fixed the report's SLA-breach
count to resolve each case's own per-queue/per-severity SLA threshold instead of a
single global one (matching the dashboard widget's existing accuracy). Added a "SOC
Effectiveness Metrics" section to `report_template.html`.

Verified with a real SQLite fixture test covering all 9 metrics, SLA precedence, and
the `hoursLabel`/`secondsLabel`/`pctLabel` formatting helpers ported from
`dashboards.html`. Live-generated a real Security Summary report on production and
confirmed every new metric matches what the Home dashboard shows for the same window
(12m MTTD, 39.3h MTTA, 18m MTTC, 16.7% false-positive rate, 100% SLA compliance, etc.).

### Report content improvements (2/7): failed logins in the Audit Trail report

`login_failed` (app.py:449) was missing from `AUDIT_SENSITIVE_ACTIONS`, so
brute-force/credential-stuffing activity was invisible in the Audit Trail report unless
it survived the 200-row-capped generic activity list — exactly the kind of event PCI
DSS/HIPAA/SOC 2 expect an audit trail to call out. Added it, and added `ip_address` to
the Sensitive Actions table (audit_log already stores the source IP on every row, but
no report surfaced it — the one detail that turns "a login failed" into "this IP is
trying multiple accounts"). Live-generated a real Audit Trail report and it surfaced a
genuine, previously-invisible pattern on this deployment: 5 failed logins against
`admin` from `10.0.0.49` within 3 minutes on 2026-09-01, now visible with its
source IP instead of buried in nearly 2,000 other audit events.

### Report content improvements (3/7): Endpoint & Infrastructure Health section

Agent Fleet Health, Agent Status (idle/offline), File Integrity Monitoring activity,
and DNS query/threat-intel-match activity all have dedicated Home dashboard widgets
but appeared in zero reports — a periodic security report previously said nothing
about endpoint or infrastructure health at all. Added a new "Endpoint & Infrastructure
Health" section to the Security Summary, ported from the same underlying queries
(`api_dashboard_agent_status`/`_fim_activity`/`_dns_activity`). Agent status is
explicitly labeled a point-in-time snapshot as of report generation, not a days-window
trend like everything else in the report — matching how the dashboard widget it
mirrors is itself labeled "Live".

Verified with a real SQLite fixture (status-threshold boundaries, the MAX(id)-per-host
resolution, and an empty-deployment case). Live-generated a Security Summary report and
confirmed it matches the Home dashboard exactly: 2 agents (1 idle, 1 offline), 2 File
Integrity changes on `LAPTOP-1`, and 6,956 DNS queries with no threat-intel
matches.

### Report content improvements (4/7): Threat Intelligence Matches section

`ioc_sightings` (real correlations between synced threat-intel indicators and actual
traffic/alerts) is fully queryable but was never surfaced in any report. Added a
"Threat Intelligence Matches" section to the Security Summary, grouping sightings per
indicator (type/pattern/feed name, sighting count, last seen) rather than one row per
raw sighting — mirrors the join shape `_attach_actor_sightings` (app.py:2256) already
uses. Verified with a real SQLite fixture (grouping/ranking, days-window filtering, and
an empty-deployment case). Live-generated a Security Summary report: this deployment
genuinely has zero threat-intel sightings (consistent with the DNS section's own "none
matching known threat intelligence" from item 3), so the new section's honest empty
state — "No sightings of a synced threat-intelligence indicator in the last 30 days" —
is exactly what should render, and does.

### Report content improvements (5/7): SOAR Automation section

SOAR execution history (`playbook_runs` for case-scoped runs, `playbook_alert_runs` for
alert-triggered ones) was never surfaced in any report — no report said anything about
automation activity at all. Added `_soar_automation_context()`, combining both tables
the same way `api_playbooks` (app.py:9295) already does for its own per-playbook
counts, and a "SOAR Automation" section (total runs, success rate, top playbooks) to
the Security Summary. Verified with a real SQLite fixture (combines both run tables
correctly, ranks by run count, respects the days window, no division-by-zero on an
empty deployment). Live-generated a report and confirmed it matches this deployment's
real automation history exactly: 9 "New Case Checklist" runs, 100% success rate.

### Report content improvements (6/7): Detection Validation Evidence in Compliance reports

`atomic_test_runs` already proves a technique's detection genuinely fired against a
real Atomic Red Team simulation — stronger evidence than "a rule is configured and
enabled" — but no compliance report surfaced it, so an auditor had no way to see which
techniques were actually *tested* versus merely covered on paper. Added
`_framework_technique_ids()` (resolves a framework's tagged rules to their MITRE
techniques via `mitre_attack.techniques_for_tags()`, the same tags-parsing
`_get_rules_cache()` already does) and `_detection_validation_context()` (matches
those techniques against `detected` atomic-test runs), plus a new "Detection
Validation Evidence" section and executive-summary metric on the per-framework
Compliance report. Reads the stored `validation_status` rather than triggering the
live on-read recompute the interactive Atomic Testing page performs — appropriate
there, not for a point-in-time report snapshot.

Verified with a real SQLite fixture covering all 3 branches: a validated technique
correctly surfaces as evidence, a `pending` (not-yet-detected) run and an unrelated
framework are both excluded, and a framework with no tagged rules degrades to zero.
Live-generated a PCI DSS compliance report: this deployment currently has zero rules
tagged for any framework, so the new section correctly renders "No rules are tagged
... yet, so no techniques are known to validate" — consistent with every other section
of that same report reaching the identical conclusion.

### Report content improvements (7/7): Appliance Operational Health section

`api_dashboard_readiness` (app.py:11359) already computes a compact operational-health
scorecard (fleet enrollment, rule enablement, backup recency, retention/archiving
configured) for the Home dashboard's Readiness widget, but it never made it into a
report — useful context for how much to trust everything else in the report (a stale
backup or unconfigured retention matters to a reader deciding how seriously to take
the rest of the numbers). Ported the same queries into `_appliance_health_context()`
and added a closing "Appliance Operational Health" section to the Security Summary.

Verified with a real SQLite fixture: an empty deployment degrades to honest
zeros/False/None, a populated one computes fleet/rule/backup/asset/user figures
correctly (an asset with no criticality value set correctly doesn't count as
"tracked"), and a backup older than 48h is correctly flagged stale. Live-generated a
Security Summary report and confirmed every figure matches `/api/dashboards/readiness`
exactly: 1/2 agents active, 119/4062 rules enabled, backup from 02:13:54 (not flagged
stale), retention configured, archiving not, 0 assets tracked, 2 users.

**This closes out all 7 report-content improvements identified in the research pass** —
every one implemented, fixture-tested, and live-verified against real production data.

### Reports improvement pass: Branding tab undersold its own scope

Live-tested Reports end to end: generated a real Compliance Report (PCI DSS, Last 7
days) and confirmed the resulting PDF downloads correctly (valid `%PDF-1.7` header,
size matching the list). Checked `src/generate_report.py` against the Branding tab's
description — every one of the 6 report generators (security, compliance, audit,
vulnerability, case, tabletop) passes a `branding` context into its template via the
shared `_report_branding_header.html` partial, but the tab's own description text only
named 3 of them ("Security, Compliance, Audit Trail"), understating what company
name/footer/accent-color/logo actually gets applied to. Corrected the description to
list all 6. Schedule tab reviewed and confirmed correct (all cadences default Off, the
email-recipients field held only its placeholder text, not real data) — left
unexercised since toggling it on would need a configured SMTP server to verify
meaningfully. Confirmed live: the Branding tab now lists all 6 report types. Note: the
test Compliance/PCI DSS report generated during this pass was left in place —
`report_history` has no delete route (reports are treated as a permanent audit trail,
same as every other report on this page), so removing it would mean a direct DB/file
edit on production outside `update.sh`, which is out of scope for a UX pass.
### Home (Dashboards) pass, continued: fractional axis ticks on small-integer bar charts

Continuing the Home/Dashboards pass below the fold. `baseHBarOptions()` — the shared
Chart.js options used by every horizontal bar widget (Analyst Workload, Agent Status,
Open Cases by Queue, Case Workload/Backlog, Top-Firing Anomaly Rules) — never set an
axis tick precision, so Chart.js's auto-scaling picked fractional steps (0, 0.2, 0.4,
0.6, 0.8, 1.0) whenever every bar's value was a small integer. Live on this deployment,
**Open Cases by Queue** (5 queues, 1 open case each) rendered a 0–1.0 axis in 0.2
increments, and **Analyst Workload** (3 unassigned, 2 assigned to admin) rendered a
0–3.0 axis with half-integer gridlines — both technically correct but confusing for a
chart of whole-number case counts. Added `ticks.precision: 0` to the shared x-axis
config, forcing whole-number ticks everywhere this helper is used; charts with larger
integer ranges (e.g. the thousands-scale Anomaly Rules chart) already picked round
numbers and are unaffected. Confirmed live on production: Analyst Workload now shows
0/1/2/3 and Open Cases by Queue shows 0/1, both previously fractional.

The same missing precision existed in `baseLineOptions()` (9 trend-line widgets: Alert
Volume, FIM Activity, DNS Activity, Agent Health, Risk Score, Cases Closed, plus the
user-built Custom Chart widget's trend type) — every one of them plots an integer count
or points total, never a continuous value. Live on this deployment, **Cases Closed
Trend** (a single day with 1 closed case) rendered a 0–1.0 y-axis in 0.2 increments.
Applied the identical `ticks.precision: 0` fix to the shared y-axis. Confirmed live:
Cases Closed Trend, File Integrity Activity, and Agent Fleet Health all now show clean
whole-number y-axes.

### Home (Dashboards) improvement pass: Top Source Countries looked broken when empty

"Home" in the sidebar is just a label for the Dashboards page (`dashboards_page`) — Home
was retired as its own template a while back and merged into Dashboards, with each
role defaulting into its own dashboard (confirmed in `base.html`; no `templates/
home.html` exists). Live-tested the `admin` role's default "Overview" dashboard with
real production data.

- **Top Source Countries rendered an empty bar chart with a meaningless 0–1.0 axis**
  instead of any indication why. Root cause: `/api/dashboards/top-countries` deliberately
  excludes private/reserved IPs from its GeoIP aggregation (`_aggregate_country_counts`'s
  own comment: "private/reserved/unresolvable IPs excluded, not bucketed as 'Unknown'")
  — correct behavior, but on this real deployment nearly every alert's `source_ip` is
  internal (192.168.x/10.x), so the widget is *always* going to render this way here,
  not just on a rare cold-start. `renderCountriesWidget` was the only chart widget in
  `dashboards.html` not following the `.widget-empty` pattern three other widgets
  (Agent Status, MITRE Coverage, Actor Summary) already use for exactly this situation.
  Added the same pattern: hide the canvas and show "No public-IP alert sources in this
  window — private/internal source IPs have no country to show" instead.
- **Investigated and deliberately left alone**: the Severity Breakdown and Vulnerability
  Summary donut charts render "High" and "Critical" in the identical color
  (`severityColor()` maps both to `c.danger`). Looked like a bug at first glance, but
  it's a consistent, deliberate convention repeated at 3+ call sites across this file
  (including a separate case-severity badge helper) — top two severities share one
  "urgent" red, only Medium/Low get distinct colors. Changing the shared helper would
  make this one dashboard inconsistent with every other severity display in the app for
  a cosmetic preference, not a confirmed bug — left as-is.
- Verified with a `vm`-context test (empty countries hides the canvas and shows the
  message; real data shows the canvas and hides the message, matching the established
  pattern), then live on production: the widget now shows the message with the canvas
  hidden, matching this deployment's actual (all-private-IP) alert data.

### Help & Reference updated to match the current app

Reviewed every section against the actual app after this session's run of improvement
passes through most of it. Found three gaps:

- **No "Threat Intel & Hunting" section existed at all** — the page's own left-nav TOC
  skipped straight from UEBA to SOAR, even though Threat Intel & Hunting is a full
  top-level sidebar item with 6 sub-tabs. Added one covering IOCs (feed sync, the
  local-only Quick Lookup vs. the external Enrich, and the new duplicate-feed guard),
  Threat Entities, YARA Scanning (File Scan/Hash Sweep/String Sweep), Sandbox, and
  Atomic Testing — including calling out the real distinction between this page's
  Vulnerabilities tab (the raw CVE/KEV/EPSS database) and Coverage's own Vulnerability
  tab (that same CVE data matched against actual installed software), since the two
  easily get confused by name alone.
- **Log Pipeline's list of sub-tabs was missing Import** — the CSV/NDJSON/JSON-array
  historical log import wizard has its own tab on the real page but no entry here.
  Added one.
- **EDR's copy said response actions land "usually within 15 seconds" — the exact
  hardcoded claim already fixed in the Agents page itself** (EDR pass 6, this
  deployment's real interval was 120s, 8x that number) had never been corrected here,
  so the documentation was repeating the same stale claim the code fix already
  addressed. Reworded to describe the interval as admin-configurable and always shown
  live on the Agents page, instead of naming a number that can drift out of sync again.

Pure content/documentation change — no logic to fixture-test, verified with a Jinja
compile-check and `node --check` on the (unchanged) scroll-spy script, then live on
production: the new TOC link correctly scrolls to and highlights the new section, and
both corrected sections (Log Pipeline, EDR) render as intended.

### Settings improvement pass 2: Roles table's Member count went stale

Pass 1 deliberately avoided exercising the actual create/delete lifecycle for real
users and roles (too risky to test on Settings' real config live). Pass 2 tested it
properly with disposable throwaway data instead: created a `claude_test_role` role
(confirmed it starts with zero permissions checked — the safe-by-default behavior the
opposite bug in pass 1 was missing), created a `claude_test_verify_user` account
against it, then a real user against `Tier 1/2 Analyst` — cleaned both up via their own
delete-with-confirmation flow afterward, verified via the Audit Log that both the
creates and deletes were logged correctly.

- **Creating or deleting a user left the Roles table's Member column stale until the
  next full page load.** Confirmed live: after creating `claude_test_verify_user`
  under Tier 1/2 Analyst, the Users table above correctly showed the new row
  immediately, but the Roles table below still read "1" member for Tier 1/2 Analyst
  instead of 2 — the same page, no reload, no re-navigation. Root cause:
  `submitUserForm()` and `deleteUser()` both call `loadUsers()` on success, but the
  Member count comes from a completely separate cache (`ROLES_CACHE`) that only
  `loadRoles()` populates — nothing on the user-management path ever called it.
- Both functions now also call `loadRoles()` on success, so the Roles table's counts
  stay accurate without a reload. Verified with a `vm`-context test (both functions
  call `loadRoles()`, not just `loadUsers()`, after a successful create/delete) and
  live on production (member counts updated immediately after both the create and the
  delete, no reload needed).
- Also verified the password-length validation (`< 8 chars` correctly rejected with a
  clear toast) and the delete-user confirmation dialog (names the real username, not a
  generic message) along the way — both already correct.

### Settings improvement pass 1: "Add New User" defaulted to Admin

Live-tested Security (Users & Roles). The "Add New User" modal's Role/Group dropdown
opened with **Admin — Adds users, certs, backups, system settings** pre-selected — the
single most privileged role on the platform, ahead of Tier 1/2 Analyst, Tier 3 Senior
Analyst, and Insider Threat Analyst. Confirmed via the live DOM (`selectedIndex: 0`,
`value: "admin"`), not assumed from a screenshot.

- **Root cause: `populateManageRoleSelect()` never explicitly set a default — a plain
  `<select>` just selects whatever option ends up first**, and Admin (role id 1, the
  first role this table has ever had) is first in `ROLES_CACHE`'s natural DB order.
  The backend (`api_settings_users()`) already has the *correct* safe default —
  `data.get('role', 'analyst')` — but a `<select>` always sends some value, so that
  fallback never actually had a chance to fire; the frontend silently overrode it every
  time. An admin quickly filling in username + password without noticing the
  pre-selected role (easy to miss — it reads like normal placeholder text, not a
  warning) would create a brand-new full-admin account by accident.
- Now explicitly defaults the dropdown to `analyst` when present, matching the
  backend's own intended fallback instead of leaving it to option order. Preserves an
  already-selected value if one exists (e.g. a future re-population mid-edit), and
  fails safe (falls back to native first-option behavior, not a crash) on a deployment
  that renamed or removed the `analyst` role entirely.
- Verified with a `vm`-context test (defaults to `analyst` over Admin; an
  already-selected valid role survives a re-population; a deployment with no `analyst`
  role doesn't crash) and live on production: opening Add New User now shows "Tier 1/2
  Analyst — Triage, cases, incident response" pre-selected.
- **Caught and corrected my own mistake mid-pass**: clicking the "Insider Threat
  Analyst" role's delete icon (its edit and delete buttons sit right next to each
  other) opened a real "Delete the 'Insider Threat Analyst' group?" confirmation —
  caught it before confirming and cancelled, no role was actually deleted. Mentioning
  it because Settings is exactly the area where a live-testing mistake could do real
  damage; this one didn't.

Also live-tested the role permission editor (well-organized by category — Cases, Log
Search, Detection Rules, UEBA, Threat Intel, EDR/Agents, etc.), Audit Log's filters
(Action/Username/date-range all correctly narrow the real log — confirmed my own
`anomaly_rule_delete`/`epss_sync`/`cisa_kev_sync` entries from earlier passes are all
present and accurate), and Changelog's search (correctly filters to only matching
entries, not just highlighting — a memory note flagged this tab as one the user has
raised before, but the multi-line-list-item and paragraph-joining fixes already in
place render every entry from this session's own passes correctly). **Network and
System were deliberately observed read-only, not exercised** — both host exactly the
kind of action a live-testing mistake could turn into real damage (rebinding the UI's
own IP/port, uploading a bad TLS cert, `Purge Now` on log retention, `Vacuum` on a
17GB live database) — confirmed the displayed state is internally consistent (Network's
bind IPs/ports match production reality; System's backup history, retention, and
archive settings all show real, plausible, steadily-growing data) without touching any
of their write actions.

### Threat Intel & Hunting improvement pass 1: duplicate feed guard

Live-tested the IOCs tab with real production data (49,844 synced indicators across 6
feed rows). Noticed two separate "Tor Exit Nodes (Public)" rows in Feed Sources — same
name, same type, same source URL, both enabled and status OK, each independently
holding its own synced copy of the same 1339 Tor exit IPs. `migrate_ti_feeds()`'s own
seeding is already guarded against creating this (`if not conn.execute("SELECT 1 FROM
ti_feeds WHERE feed_type = 'tor_exit'")...`), so this wasn't the seed migration
double-running — the gap is that `POST /api/ti/feeds` (the "+ Add Feed" button) never
checked for an existing feed of the same type before inserting another one.

- For most feed types this is fine — `taxii`/`misp` take a user-supplied
  `discovery_url` (a different server each time), `csv` is inherently a one-off upload,
  `otx`'s `api_key` ties to a specific account's pulse subscription, and `yara_forge`
  has its own `collection_id` package selector — all genuinely support multiple
  legitimate instances. But `threatfox`/`urlhaus`/`feodotracker`/`sslbl`/`yaraify`/
  `yara_rules_project`/`signature_base`/`spamhaus_drop`/`tor_exit`/`openphish`/
  `blocklist_de`/`malwarebazaar` are all single fixed public sources with zero
  configurable content (confirmed in `threat_intel.html`'s own `FEED_TYPES_WITH_URL`/
  `FEED_TYPES_WITH_OPTIONAL_API_KEY` comments — an optional API key on these only raises
  the rate limit, it never changes what's fetched) — a second feed of one of these types
  can never be a *different* feed, only a duplicate of the same one.
- Added a `TI_FEED_SINGLETON_TYPES` check to the feed-creation route: attempting to add
  a second feed of one of those 12 fixed-source types is now rejected with a clear error
  naming the existing feed (id + name) instead of silently creating a duplicate that
  double-syncs and double-counts the same indicators.
- **Did not delete the existing duplicate Tor Exit feed** — flagged to the user rather
  than removing configuration unilaterally, same as the earlier `TEST-REPLAY-VERIFY-2`
  and `pivotToLogSearch` findings. Deleting it would drop the duplicated 1339 IOCs from
  the Total IOCs count with no loss of real coverage (both rows hold identical content).
- Verified with a fixture test covering all 12 singleton types (each rejects a second
  instance) and the two real differentiated types (`taxii` with different
  `discovery_url`s, `yara_forge` with different `collection_id` packages both still
  allowed) — a naive "one feed_type, period" rule would have wrongly broken those. Live
  on production: opening Add Feed defaulted to ThreatFox (already existing) and
  attempting to save surfaced the exact rejection message naming the real id/name of
  the existing feed, no test row left behind.

Also live-tested Threat Entities (APT28/APT29/etc. detail modal, MITRE technique badges,
manual relationships — all solid) and Atomic Testing, where a second real bug turned up:

- **"Browse & Import Atomic Red Team Tests" showed "? test(s) cached" instead of a real
  number**, even though `last_synced` right next to it correctly showed a real date.
  Root cause: `cached_test_count` only ever read `_ATOMIC_LIST_CACHE['data']`, an
  in-memory dict that's per-gunicorn-worker-process, not shared. `_list_atomic_tests_
  available()` (the function that actually serves the test list) already has a comment
  documenting this exact multi-worker gotcha and falls back to a DB-persisted copy
  (`atomic_test_catalog_cache` in `settings`) for that reason — but the status endpoint
  never got the same fallback, so a GET landing on any of the 2 workers that didn't
  personally run the last sync showed "?" forever, even seconds after a real sync had
  completed on a different worker. Added the same DB fallback here, mirroring the
  established pattern instead of inventing a new one. Verified with a fixture test (a
  worker with its own in-memory copy reports it directly; a worker with none falls back
  to the DB-persisted count; a genuinely-never-synced appliance still reports `None`
  cleanly; a corrupted cache value fails safe instead of crashing). Live on production
  (fresh workers after deploy, so definitely no in-memory copy yet): "Browse & Import"
  now reads "1821 test(s) cached — last synced 2026-09-04 10:55:50" instead of "?".

Live-tested YARA Scanning's IOC Hash Sweep and String Sweep (existing real sweep results
from both real EDR hosts — 20 alerts on DESKTOP-1, 90 on LAPTOP-1 — render
correctly with matched-pattern detail; did not trigger a new sweep, since that dispatches
a real command to real agents) and Sandbox's URL detonation form (correctly rejects a
submission with "No urlscan.io API key configured." — no keys are set on this
deployment, and nothing was actually submitted externally). Also synced the two
previously-never-synced Vulnerability feeds (CISA KEV: 1709 records; FIRST.org EPSS:
2092 scored) — both worked correctly on the first real trigger, confirming they just
hadn't been run yet rather than being broken.

**Not investigated further, flagged for the user's own awareness, not this pass's
concern**: one YARA Hash Sweep hit on DESKTOP-1 matched `AHK_DarkGate_Payload_
April_2024` and `APT_Bitter_Almond_RAT` (146 total patterns) against `C:\Users\<user>\
AppData\Local\Temp\tmp7e_ljju5.ps1` — the matched strings shown (`#NoTrayIcon`,
`A_ScriptDir`, `DllCall("VirtualAlloc", ...)`) look like ordinary AutoHotkey script
syntax, so this reads like a plausible false positive from a broad community
signature-base rule, not a confirmed detection — but it's real security-relevant data
on a real host, worth a look regardless of this UX pass's scope.

### Log Pipeline improvement pass 1: Drop Rule preview hung on real log volume

Live-tested Drop Rules with real production data. Typing `App Name equals FIM` and
clicking Preview left "Checking recent logs…" spinning for 2+ minutes with no result,
confirmed by leaving the request running rather than assuming a slow screenshot.

- **`/api/droprules/preview` wrapped the matched column in `COALESCE(field, '')` for
  the 'equals' operator, which made it an unindexable expression** — `EXPLAIN QUERY
  PLAN` on the exact query (fixture-tested, not guessed) showed SQLite falling back to
  `SEARCH ... USING INDEX idx_live_logs_timestamp (timestamp>?)`, i.e. scanning every
  row in the whole 7-day preview window (millions on this deployment's real hosts) to
  test the COALESCE condition on each one, instead of seeking directly to matching rows
  via `idx_live_logs_app`/`idx_live_logs_host`/`idx_live_logs_event_id`. The COALESCE
  was there to mirror Vector's VRL `?? ""` null-coalescing semantics exactly (a real,
  deliberate design decision, not an oversight — see the comment above the route), but
  since the preview form always requires a non-empty match value, `field = ?` and
  `COALESCE(field, '') = ?` are equivalent for every input the form can ever send:
  `NULL = <non-empty>` is falsy either way. Dropped the COALESCE for 'equals' only —
  behaviorally identical, but now indexable. Left 'contains' (`INSTR`) as-is: substring
  search isn't index-friendly in SQLite regardless of COALESCE, so that operator was
  never the bug and gets no benefit from this change.
- First deploy attempt deliberately skipped adding a new index — the UEBA Data Insights
  pass earlier today already showed that a `CREATE INDEX` migration on this deployment's
  7.6M-row `live_logs` can itself cause a multi-minute outage while it builds, and
  `host`/`event_id` previews already benefit from indexes that exist today (`host` even
  gets the composite `idx_live_logs_host_timestamp` added in that same UEBA pass).
  **Live-testing `App Name equals Sysmon` immediately after deploy showed this wasn't
  enough**: `Sysmon` (4.47M rows) and `PowerShell` (3.07M rows) are ~99% of this
  deployment's entire `live_logs` table between them, confirmed via a direct read-only
  query — a single-column `idx_live_logs_app` index still forces a rowid lookup per
  matching row across that app's *entire* history to test the timestamp condition, the
  same shape of problem the UEBA pass hit. Drop Rules exists specifically to filter
  noisy/common apps, so previewing exactly those two values is the *typical* case, not
  an edge case — added `idx_live_logs_app_timestamp` (folded into the existing
  `migrate_ueba_insights_indexes()` migration rather than a new one, since it's the same
  composite-index-for-a-time-boxed-entity-filter pattern) to make it a covering-index
  seek instead. Flagged the known outage risk to the user before this second deploy,
  given the UEBA pass's `CREATE INDEX` had caused one minutes earlier in the same
  session — this one recovered faster (~3 minutes vs. ~15), monitored the same way
  (polling curl + read-only `ps`/`journalctl` over SSH, no direct intervention).
- Verified with a SQLite fixture test (NULL-app and out-of-window rows correctly
  excluded from the count; a simulated "common app with a long history" scenario
  confirms a covering-index seek via `idx_live_logs_app_timestamp`, not a full-history
  scan; 'contains' behavior unchanged) and live on production: `FIM` — zero matches,
  instant; `Sysmon` — **1,221,186 matching logs in the last 7 days, resolved instantly**
  (previously the request this same query represents had been left running for 2+
  minutes with nothing back).

Also live-tested the other 6 tabs — DNS Query Logging (both the DNS server config and
DNS Activity's domain filter, which already uses a bare `app = 'dns_server'` column plus
`ORDER BY timestamp DESC LIMIT`, so it was never exposed to this bug), Windows/Linux Log
Channels (including switching the per-group template selector to the real "Test" agent
group), Silent Hosts, and Parsers (Pipeline Health, Parser Catalog's fixed-row-count
sampling, and the Custom Parsers live-preview/test flow, including its "pattern matched
but no named group maps to a recognized field" warning working correctly). All confirmed
solid — no further fixes needed this pass. Import's wizard was reviewed structurally but
not exercised end-to-end (would need a real file upload + cleanup) — worth a dedicated
look if the user wants that depth.

### UEBA improvement pass 3/3: Clone Rule on Scoring & Rules

Live-tested Model Tuning (Baseline Model Parameters, Entity Baselines table, Exclusions)
and Scoring & Rules (Dynamic Scoring, the anomaly-rules table). Model Tuning's
"Exclude" button prefill + scroll-into-view already works correctly (confirmed after
initially misreading a mid-animation screenshot as a bug — it just needed more time for
the `smooth` scroll to finish). Toggle rows whose numeric/select fields stay fully
interactive regardless of the toggle's own on/off state (Beaconing, Sequence Chain,
Priority, Autocase) were investigated but left alone — no other toggle+field row
anywhere in this codebase disables its siblings on toggle-off either, so this isn't a
regression from an established pattern, just a possible future enhancement.

- **Building one of the rule set's many near-duplicate rules meant re-entering the whole
  condition set from scratch.** The seeded 15 rules already include 4 "Lateral
  Movement" variants (Critical/High × Host/User) and several other Host/User pairs that
  differ only by entity type or a severity keyword — a real, observed pattern, not a
  hypothetical one. Added a **Clone** button (copy icon, next to Edit/Delete) that
  pre-fills the Add Rule modal from an existing rule with a `(copy)`-suffixed name,
  saving as a new rule (not overwriting the original) — cuts building the next variant
  down to editing 2-3 fields instead of re-entering every condition. Verified with a
  `vm`-context test (clone passes `id: null` + the suffixed name to the shared modal
  opener with every other field preserved; cloning an unknown id no-ops rather than
  throwing) and live on production (cloned "Critical Alert Sourced from Internal Network
  (Host)" — all 3 conditions, points, and first-time bonus came through correctly, saved
  as a new 16th rule with the original's 47/226 match counts untouched, then deleted the
  test rule to clean up).

Also live-tested Asset & Identity — confirmed solid (clean validation, no crash on an
empty submit). Worth flagging to the user: it's currently empty on this deployment, so
the criticality (×2) and privileged (×1.5) score multipliers it drives are a no-op for
every entity right now, including the two real EDR hosts.

## 2026-09-11

### UEBA improvement pass 2/3: Data Insights entity search hung indefinitely

Live-tested the Data Insights tab's "By Entity" search against real production data
(searched a genuinely busy host). The request never came back — still `pending` after
75+ seconds with nothing on screen but a static "Loading…" (no spinner, no timeout, no
error path), confirmed via network-request inspection rather than assumed from a slow
screenshot.

- **`/api/ueba/insights/entity/<type>/<id>` scanned an entity's entire history across
  every table it touches, with no time bound at all** — unlike every other UEBA view
  (Timeline, and Risk Scoring's own `api_ueba_risk_score_detail`, both always time-box by
  `cfg['window_days']`), this endpoint's 6 queries ran unbounded. First fix attempt only
  bounded the 4 `live_logs`-derived ones (activity pattern, last-seen, top source/
  destination IPs, related entities — `live_logs` only carries single-column indexes on
  `host`/`username`, so each matching row needs a separate rowid lookup, which compounds
  badly on a busy host's full history); live-testing that fix against the same real host
  still hung 20s+, because `top_alerts` (`alerts`) and especially `risk_contributions`
  (`risk_score_events`) were *also* unbounded, and an entity scored repeatedly over
  months can rack up hundreds of thousands of `risk_score_events` rows on its own — this
  turned out to be the larger of the two costs, not `live_logs`.
- All 6 queries are now bounded to the last 90 days, and the window is surfaced in the
  response (`window_days`) so the UI labels every affected card honestly — "(last 90d)"
  on Activity Pattern, Top Source/Destination IPs, Related Entities, Top Alerts, Risk
  Contributions, and Admin Activity — instead of silently truncating history the analyst
  would otherwise assume was complete.
- Verified with a SQLite fixture test covering all 6 queries (a host with recent rows
  plus rows/events well outside the 90-day window in `live_logs`, `risk_score_events`,
  and `alerts`: each query includes only the in-window data; an entity with zero
  in-window activity returns empty, not an error) and a `vm`-context test of the
  window-label rendering (defaults to 90d when the field is absent, shows the real value
  otherwise). Caught the incompleteness of the first fix by re-testing live against
  production after deploying it, rather than assuming a plausible-looking fix was done.
- **Second live-test, same host: still hung 30s+ even with all 6 queries time-bounded.**
  `EXPLAIN QUERY PLAN` on the exact query (fixture-tested, not guessed) showed why: the
  existing single-column `idx_live_logs_host`/`idx_live_logs_username`/`idx_alerts_host`
  indexes only narrow rows to "this entity" — `SEARCH live_logs USING INDEX
  idx_live_logs_host (host=?)`, with the `timestamp >= ...` bound applied only as a
  residual filter *after* the index search, not pushed into it. SQLite still visited
  every row that host had ever produced regardless of the WHERE clause, so the 90-day
  bound changed nothing for a host with a long history. Added a new migration,
  `migrate_ueba_insights_indexes()`, creating composite `(host, timestamp)` /
  `(username, timestamp)` indexes on `live_logs` and `(host, timestamp)` on `alerts` (
  `risk_score_events` already had a usable composite index, `idx_risk_score_events_entity
  (entity_type, entity_id, computed_at)`, so it didn't need one). Re-ran the same
  `EXPLAIN QUERY PLAN` fixture test after adding the index: `SEARCH live_logs USING
  COVERING INDEX idx_live_logs_host_timestamp (host=? AND timestamp>?)` — a covering
  index seek straight to the in-window rows, confirmed against a plan with vs. without
  the index rather than assumed from the index existing.
- **Deploying the composite-index migration caused a real, if brief, production outage**
  — `live_logs` turned out to hold 7.6M rows, and building 3 new indexes over it on
  first startup took long enough that gunicorn's 3 worker processes (which each
  independently re-run every `migrate_*()` at boot) piled up on SQLite's single-writer
  lock; one worker crashed on `database is locked` and had to be respawned, and the site
  was unreachable for roughly 5 minutes. Verified recovery live (`EXPLAIN QUERY PLAN`
  against the real database, not just the fixture) rather than assuming the fix was done
  once the deploy script exited.
- **Root cause of the original hang, once the dust settled: `LAPTOP-1` and
  `DESKTOP-1` between them account for 7.6M of the database's 7.62M `live_logs`
  rows** — 6.88M rows over 24 days for the first, 722K over 6 days for the second
  (confirmed via direct read-only queries against the production DB, not inferred).
  **Correction**: these are the user's own two real EDR-monitored laptops, not test
  data — initially misread as synthetic/stress-test traffic given the volume (~287K and
  ~120K events/day respectively); the user corrected this. Every one of those rows
  already falls inside a 90-day window, so no time bound can make Data Insights fast for
  these two specific hosts while their logging stays this verbose — that's a real,
  ongoing volume characteristic to design around, not a one-time cleanup. Verified the
  fix is otherwise correct and fast against a lower-volume real entity (`soc-appliance`, 6528
  events, loads instantly with proper "(last 90d)" labels throughout).

### UEBA improvement pass 1/3: process pivot link, unbounded risk-detail text

Live-tested Timeline and Risk Scoring with real production data (a genuinely
high-volume UEBA deployment — 6487 matching events, one entity scored 757161 raw points
at Priority 10/10 Critical). Noticed a `TEST-REPLAY-VERIFY-2` host sitting in Risk
Scoring with a real score — looks like leftover test data from a prior session's replay
verification, flagged to the user rather than touched (out of scope for this pass, not
a code bug).

- **Timeline's process name was another instance of the styled-like-a-link-but-inert
  bug** (same pattern as the SIEM Detection Rules title fixed earlier) — `<code
  class="text-info">` with zero interactivity, even though `process_image` is already
  an established Log Search pivot field elsewhere in the app (dashboard.html's own
  `PIVOT_COLUMNS`/`pivotLinkHtml`). Now pivots to Log Search filtered on the full
  process path (not just the displayed basename, since that's what Log Search's own
  `process_image` column actually stores), reusing the genuinely-global
  `pivotToLogSearch()` from base.html. Verified with a `vm`-context test (pivots on the
  full path, no link when there's nothing to pivot on, no throw on an event with
  neither `process_image` nor `command_line`).
- **A Risk Scoring breakdown row's detail text had no length cap at all** — unlike
  Timeline's own `timelineDetailCell()` (already truncates to 160 chars), a single
  `rare_process_population` indicator's detail (a full command line with embedded JSON
  config, several KB long) blew out the entire modal's layout. Each sample is now
  truncated to 200 chars individually (before joining multiple samples, so the ellipsis
  lands per-detail) with the full untruncated text kept in a `title` tooltip. Verified
  with a targeted test of the truncation boundary math (short text unchanged, a 5000-char
  string cut to exactly 200 + ellipsis, no off-by-one at the exact 200-char boundary).

Live-tested MITRE ATT&CK (technique drill-down popover, the disabled-rule links inside
it correctly deep-link to `/siem?tab=rules&rule_id=N` — already solid), Compliance, and
Vulnerability (clean, matches EDR's own "Check for Vulnerabilities" snapshot — already
solid). Compliance's "Recent Changes" audit trail was the one real gap.

- **"Recent Changes" showed bare rule IDs** — `admin toggled rule #3338` — telling an
  analyst nothing without leaving the page to look up what that rule actually is, on a
  page where every other rule reference in the app shows its title. `target_id` is
  always a `sigma_rules.id` for the two actions that use it (`rule_toggle`,
  `rule_compliance_tag` — confirmed against `api_r_tog`/`api_rule_compliance`);
  `/api/compliance/audit-trail` now LEFT JOINs `sigma_rules` to resolve the real title,
  falling back to `#id` only if the rule has since been deleted (a LEFT JOIN keeps that
  row in the trail instead of an INNER JOIN silently dropping it). `rule_bulk_toggle`'s
  target_id isn't a rule id at all and rides along as harmless NULL, unchanged.
  Verified with a SQLite fixture test (title resolves correctly, a deleted rule's row
  survives with a NULL title rather than vanishing, bulk-toggle unaffected) and a
  `vm`-context test for the frontend fallback logic.

### EDR improvement pass 6: "usually within 15s" was a lie on this deployment's real config

Exercised the File Integrity Monitoring add/delete flow live (both clean — add clears
the form and inserts the row in place, delete has its own confirmation dialog) and
noticed the "Agent Poll Interval" section showing Command/config check-in = **120
seconds** on this real appliance.

- **Four separate places hardcoded "usually within 15s"** for how long a queued command
  takes to reach an endpoint — the Response Actions console's own hint text, the FIM
  interval note, and two toast messages (single-host queue, bulk Upgrade Selected) —
  none of them reading the actual admin-configurable `config_interval_seconds` setting
  (5-3600s range) that this exact number is about. On this deployment that setting is
  120s, 8x the claimed 15s, which reads as "the command is stuck" during exactly the
  kind of live troubleshooting where trust in the UI matters most. All four now read
  from one shared `agentConfigIntervalSecondsValue`, refreshed whenever the real value
  loads or is saved, falling back to the old 15s only until the real value has actually
  loaded. Verified with a `vm`-context test (fallback text before load, both notes
  updating in lockstep once the real value loads, and no throw when a target element
  isn't in the DOM for this permission level).

### EDR improvement pass 5: confirmation dialog on "Run on Group"

More live-testing through EDR beyond the original 4 passes. Exercised areas not yet
touched: View SCA Results / Check for Vulnerabilities (already solid — clean tables,
honest caveat text, nothing to fix), the "All Response Action History" table's rich
JSON-to-table result modal (already solid, confirms pass 1's console fix wasn't
redundant with it — two genuinely separate rendering paths), the right-click host
context menu and Heartbeat History modal (both already solid), and PID/path param-form
validation on Kill Process/Collect File (already solid — numeric-only PID check,
confirmation dialog, no risk of submitting the `1234` placeholder by accident).

- **"Run on a Group" had no confirmation dialog at all** — every single-host action of
  comparable or lesser risk (including the exact same "Upgrade Agent" action from the
  per-row Respond menu) already confirms via `confirmDialog()` before queuing, but this
  is the one dispatch path whose blast radius is an entire group of hosts, not one, and
  it fired immediately on click. Added a confirmation naming both the action and the
  actual member count of the selected group (`allEndpoints.filter(...)`, no extra
  request), so a wrong-group-selected misclick is caught before dispatch instead of
  being invisible until it's already gone out.

### EDR improvement pass 4/4 (cross-EDR): "/" to search Agents, host details from the console

- **"/" now focuses the Agents tab's hostname/IP search box** — same convention as
  SIEM's three tabs. Deliberately scoped to only fire when the Agents pane is actually
  visible: Response Actions has a live PowerShell command input where '/' is an
  entirely normal character (paths, flags), and there's no search box on either
  Response Actions or Deployment to send it to — stealing it there would do nothing
  useful and risk yanking focus off an in-progress command.
- **Response Actions had no way to see a host's full details without switching tabs.**
  Mid-response, checking a host's OS/group/agent version/recent actions meant leaving
  the console, finding the row on the Agents tab, clicking it, then switching back.
  Added a small "Details" link next to Target Host that opens the exact same host-detail
  modal the Agents tab's hostname click already uses, without leaving the console.

### EDR improvement pass 3/4 (Deployment): click-to-copy on every install command

Deployment's entire job is handing an analyst a command to paste into a remote shell —
the install/uninstall commands for Windows/Linux/macOS (6 total) and the SOC ingestion
token itself were all plain, unselectable-by-click text with no copy affordance,
meaning every install started with a manual click-drag-select. Added a shared
`copyCommandToClipboard()` (click the block, icon briefly swaps to a checkmark to
confirm) wired to all 6 command blocks plus a dedicated copy button next to the SOC
token field.

### EDR improvement pass 2/4 (Agents): Alerts (24h) surfaced on the fleet table

The host-detail modal (click a hostname) already showed a striking, red-highlighted
"Alerts (24h)" count — 1403 for the one real online host in this appliance — but seeing
it meant clicking into each host individually, one at a time, to notice. Added as its
own column on the main Agents table instead, so a host generating unusual alert volume
is visible at a glance across the whole fleet.

- `/api/agent/checkins` now also bulk-queries `alerts_24h` per visible host (one
  `GROUP BY host` query alongside the existing bulk group/version-history lookups it
  already does this way, not a query per row) using the exact same
  `COALESCE(last_seen, timestamp) >= datetime('now', '-1 day')` UTC-timestamp
  convention the host-detail modal's own `alerts_24h` calculation already used, so the
  two never drift apart. Verified with a SQLite fixture test (counts a repeat-alert
  correctly via its bumped `last_seen` even though its original `timestamp` is outside
  the window, respects the 24h boundary, and omits a host with zero alerts from the
  aggregate rather than erroring — the frontend defaults that case to 0).

### EDR improvement pass 1/4 (Response Actions): structured command output as a table

Same live-testing methodology as the SIEM passes, this time through EDR (Agents /
Response Actions / Deployment). Ran a real "List Processes" against the one online
Windows agent to see actual output, not synthetic data.

- **Canned actions that return JSON (List Processes and anything else shaped like it)
  dumped raw, unbroken JSON into the terminal** — a single unwrapped line like
  `{"Id":1992,"ProcessName":"msedgewebview2","Path":"C:\...` per process, effectively
  unreadable past a couple of entries. Added `formatCommandOutput()`: if the whole
  stdout string parses as JSON, an array of flat objects renders as a table (column
  union across all rows, not just the first row's keys — a later row can have an extra
  field the first doesn't); a bare JSON object pretty-prints with indentation instead.
  Typed ad-hoc PowerShell output that ISN'T JSON falls straight through to the exact
  same plain-text rendering as before, unchanged. Verified with a `vm`-context test
  (escapes cell values against injection, handles a column only present on a later row,
  stringifies a nested-object cell instead of leaking `[object Object]`, and an empty
  array shows a literal `[]` rather than a blank table) plus live verification against
  the real agent's actual process list.

### SIEM improvement pass 4/4 (cross-SIEM): "/" to search, jump from Tune to the rule editor

- **Assessing a problematic rule in the Tune modal (noisy, never fired, piling up
  exclusions) very often ends in "I need to actually look at its definition"** — that
  meant closing the modal, switching to Detection Rules, and searching for the same
  rule by name all over again. Added a small edit-pencil button next to the Tune modal's
  title that closes it and opens the same rule editor Detection Rules' own row-title/
  Edit menu use, keyed off the same rule id (handles both Sigma and Custom rules, same
  as that existing path already does).
- **"/" now focuses whichever tab's own search box is on screen** (Advanced Query or
  Basic Field Filter's Value box on Log Search — whichever mode is actually active —
  the title-search box on Detection Rules/Detection Tuning) — a standard convention
  (GitHub, Gmail, Splunk...) this page had none of, so every search on every tab started
  with a mouse click. Never steals '/' while an input/textarea/contenteditable already
  has focus, so typing a literal '/' into a query still works normally.

### SIEM improvement pass 3/4 (Detection Tuning): inline enable toggle + noise-mix bar

- **Disabling a noisy rule from Detection Tuning required a full modal round trip** —
  "Enabled" was a static badge, not a switch, so the only way to disable a rule from the
  one view built specifically for "which rules need action" was Tune → Disable This
  Rule → Close (a modal open/close for the single most common tuning action). Now an
  inline switch, matching Detection Rules' own table. Same stale-stats fix as pass 2
  applied here too: patches the row into `allTuning` and re-renders stats in place
  rather than doing nothing.
- **Added a noise-mix bar for the ENABLED subset** — same idea as pass 2's severity-mix
  bar: answering "of what's actually live, how much is well-behaved vs. flooding vs.
  dead weight that's never fired" today meant clicking each quick-filter chip in turn
  and reading its row count. Verified with a `vm`-context test (excludes disabled rules
  even when they'd otherwise look extremely noisy, classifies each bucket correctly,
  orders attention-worthy-first) plus live verification.

### SIEM improvement pass 2/4 (Detection Rules): severity-mix bar + a real stale-stats bug

- **Toggling a single rule's Enabled switch left the top stat tiles stale.** The switch
  itself flips instantly (it's a plain checkbox), and `bulkAction()` already called
  `ld()` (a full reload) to refresh everything -- but the single-row `toggleSingle()`
  path did nothing at all on success, so Total/Enabled/Disabled sat showing the
  pre-toggle counts until the next full reload, filter change, or bulk action.
  Confirmed live (toggled a rule off, watched Enabled/Disabled hold their old numbers).
  Now patches the one changed row into `allRules` in place and re-renders stats,
  instead of doing nothing or a wasteful full re-fetch.
- **Added a severity-mix bar for the ENABLED subset** — "Enabled: 119" alone doesn't say
  whether that active detection surface skews critical/high-signal or mostly
  informational; answering that today meant filtering by Level four times and reading
  the row count each time. One glance at a small stacked bar now (same flex-segment
  pattern as Coverage's own tactic bars, reused for visual consistency rather than
  inventing a new one). Verified with a Node `vm`-context test (excludes disabled rules,
  falls back a null level to 'medium' matching the row-render code's own fallback,
  orders segments by severity not insertion order, clears cleanly when nothing's
  enabled) plus live verification with real data.

### SIEM improvement pass 1/4 (Log Search): alert/anomaly volume as its own chart series

Direct follow-up request for several more usability passes through SIEM specifically,
optimizing for fewer clicks to a common task and adding visualization where an analyst
is currently reading a raw number/table that a chart would make faster to parse.

- **Log Search's volume chart couldn't show an alert/anomaly spike** — it plotted one
  undifferentiated line for total log volume, and at this appliance's real ratio
  (~8k routine logs/hour against single-digit alerts/hour on a quiet day) an alert spike
  would be invisible, flattened against the x-axis by sheer log volume. `/api/logs/timeline`
  now also returns `alert_count` per bucket (one extra `SUM(CASE WHEN log_type IN
  ('alert','anomaly')...)` in the same query, not a second round trip), plotted as its
  own line on a secondary right-hand axis so it stays legible regardless of routine
  volume. Verified with a fixture test isolating the CASE/SUM aggregation, then live
  against real data.
- Checked "View Rule" / "Add Exclusion" quick actions on alert rows and Enter-to-search
  on both query inputs — both already existed, so left untouched.

### Full-cycle UX review: Logs → Log Search → Detections → Investigations → Reporting

Fresh-eyes live walkthrough of the whole analyst workflow, cross-checking suspicious
findings against actual API responses and source before acting (one suspect — bare
"Compliance Report" rows with no framework suffix — turned out to be correct behavior,
not a bug, and was dropped; another — defaulting Detection Tuning to a different quick
filter — turned out to have no clearly-better option among the existing four chips,
given the page already default-sorts by 30-day alert volume, so left alone).

- **Reporting: raw unformatted timestamps.** `report_history.started_at`/`completed_at`
  are written server-side as Python `datetime.now().isoformat()` (used as a correlation
  key elsewhere, so the write side is untouched) while the rest of the app displays
  SQLite `datetime('now')`-style timestamps — three places rendered the raw
  `2026-09-09T17:52:54.207821` straight through: the Reports list, its "Last Generated"
  stat tile, and the per-case Report tab. Added a display-only `formatReportTimestamp()`
  helper (duplicated in both `reports.html` and `cases.html` per this codebase's
  convention) to normalize it.
- **Stat tiles couldn't distinguish loading / failed / genuinely zero.** On Log Pipeline,
  a fast-resolving loader (`loadDropRules`) was unconditionally re-rendering all 4 shared
  stat tiles on every call, stomping the other 3 tiles' "Loading..." placeholder back to
  a bare `'—'` well before their own slower fetch (`loadIngestionHealth`, e.g. events/hour)
  had actually resolved — a real, if intermittent, bug, not just a slow load. Tiles are
  now only written once their own data actually arrives. Both Log Pipeline and SIEM
  (all three tabs — Log Search, Detection Rules, Detection Tuning) also had no visible
  error state at all: a failed fetch left the tiles stuck on "Loading..." forever with
  no sign anything broke. Added a `setStatTileError()` (small warning glyph) on every
  stat-tile-owning fetch's `.catch()`.
- **Log Search defaulted to a 5-minute window.** At this appliance's real traffic volume
  that's not literally empty, but a first-time query with zero hits in 5 minutes reads as
  "nothing's flowing" rather than "the window's too narrow" — widened the default to 24h,
  matching what deep-linked/saved searches already fell back to when unspecified.

### SIEM deep-dive: two real bugs found by actually clicking through it

Direct follow-up request to specifically evaluate SIEM in depth after the full-cycle
review above. Exercised every control on Log Search, Detection Rules, and Detection
Tuning (row detail modal, pivoting, Columns picker, bulk actions, Tune modal, New Rule
builder) rather than just reading the code.

- **Detection Rules' rule title looked clickable but did nothing.** Styled identically to
  a link (`fw-bold text-info`, the same color/weight the rest of the app uses for actual
  links) but had no `onclick`/`href` at all — the only way to open a rule was the small
  `⋮` menu at the far right of its row. Now clicking the title opens the same rule editor
  the menu's "Edit" item does.
- **The Detection Rules bulk-action dropdown ("Select Rules" / "N Selected") could get
  stuck open with no way to close it.** It uses `data-bs-auto-close="outside"` so clicking
  an item inside (e.g. "Clear Selection") deliberately doesn't close it — by design, so a
  few bulk actions can be done in a row without reopening the menu. But once the selection
  count hits zero, the toggle button gets `disabled` while the menu is still open, and a
  disabled element stops participating in Bootstrap's outside-click/Escape dismiss
  handling entirely — the menu was then stuck open, floating over the table, until a full
  page reload. Now the dropdown is explicitly hidden before its toggle is disabled.

Direct request to review Case Management and SOAR for accumulated clutter after several
sessions of feature additions. A fresh-eyes audit (not code I'd just written myself)
flagged 8 real friction points; shipped the 6 that were small, safe, UI-only changes —
the two structural ones (grouping the 13-tab case-detail nav, reordering the New
Playbook form) were left for a dedicated follow-up pass rather than rushed.

- **Retrospective/PIR section is now collapsed by default** on the case-detail header
  card — Root Cause, Lessons Learned, Post-Incident Review, and Follow-up Actions sat
  fully expanded on every case regardless of age, even a 5-minute-old one with nothing
  to retrospect on yet. Now a `<details>` disclosure, auto-expanded only once the case's
  workflow state is Resolved or its status is Closed.
- **Case-detail tab count reduced from 14 to 13**: the standalone "Threat Intel" tab was
  just one dropdown+button (link this case to a known actor/entity) burning a whole tab
  slot, with a name confusingly close to the separate "Indicators" tab. Folded into
  Indicators as a second card.
- **"Items" → "Linked Items"; Attachments gets its own icon** — both tabs shared the
  identical `fa-paperclip` icon, and "Items" alone didn't distinguish "pivoted alerts/
  EDR results" from "Attachments"'s uploaded files.
- **"Related Cases" tab → "Case Links"**, and its "Suggested Related Cases" card →
  "Suggestions" — three near-identical phrases ("Related Items," "Related Cases,"
  "Suggested Related Cases") across two adjacent tabs was genuinely confusing under time
  pressure; now each tab/card name is visually distinct.
- **Cases list: "My queues only" switch merged into the queue filter `&lt;select&gt;`** as a
  top "My queues" option — one control instead of two doing overlapping jobs (a queue
  filter and a "my queues" filter were never both meaningfully active at once). Export
  CSV shrunk from a labeled button to an icon-only one (title tooltip retained) so it
  reads as secondary to the actual filter controls next to it.
- **SOAR toolbar: 3 rarely-used config buttons (Manage Secrets/Custom Actions/Email
  Templates) collapsed into one "Configure" dropdown** — these are admin setup actions,
  not the everyday "build a playbook" action, and were visually competing for attention
  with "New from Template"/"New Playbook" at the same weight. The two actual everyday
  buttons stay as direct, one-click toolbar buttons.

### Named email templates for Send Email + custom case fields usable by every playbook action

Direct follow-up request after reviewing two more Exabeam Case Manager pages (Email
Notifications, Investigate a Security Incident): (1) reusable, named email templates
instead of retyping subject/body into every `send_email` action, and (2) case custom
fields usable as template variables the way Exabeam's own "Case Manager Incident
Fields" become `{{variable}}`s in their email templates.

- **New `email_templates` table** (name, subject, body) + CRUD routes, mirroring
  `playbook_custom_actions`' exact shape/permission gate. New "Manage Email Templates"
  button on SOAR > Playbooks. `send_email`'s action editor gained a "Use a saved
  template" select — picking one hides the inline Subject/Body inputs (the template's
  own text is used instead); leaving it on "Type subject/body inline…" works exactly as
  before. Deleting a template that's still referenced by a playbook fails that one
  action cleanly (`"email template not found, skipped"`) rather than erroring the whole
  run, matching `custom_webhook`'s established behavior for a deleted custom action.
- **`_fill_playbook_template` now also substitutes custom case fields** — any
  `case_field_values` row (from a case template's custom fields, or one an analyst added
  directly) becomes a `{{field_<slug>}}` placeholder, where `<slug>` is the field's label
  lowercased with punctuation/spaces collapsed to underscores (`"Attack Vector"` →
  `{{field_attack_vector}}`). This is a change to the one shared substitution function
  every templated action already calls, so it's available for free in `send_email`,
  `send_webhook`, `send_slack`, and `custom_webhook` alike — not just the new email
  templates. A slug collision (two differently-punctuated labels landing on the same
  key) keeps the first field's value rather than silently overwriting it; an unmatched
  `{{field_*}}` placeholder is left as literal text rather than erroring, consistent
  with this function's existing plain-substitution (not a real template engine) design.
- Out of scope for this pass: the Report generator's own PDF email delivery (a
  fixed-format Jinja report, not a plain Subject+Body pair — a genuinely different
  templating shape) was left untouched.

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
     user" parser now correctly overrides "SYSTEM" with the real actor (a real Windows
     account name) while correctly leaving distinct machine-account/local-service
     events alone. Kept in
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
group (the one real group in use, assigned to `DESKTOP-1`): saving an override
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
  (`LAPTOP-1`, `DESKTOP-1`) re-authenticated successfully with no re-enrollment
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
