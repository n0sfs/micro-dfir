# Tasks

Structural progress checklist — done / in-flight / next. Checked-off items can be
deleted once a session confirms them stable in production; this is a working list, not
a history (that's [CHANGELOG.md](CHANGELOG.md)).

## In-flight

- [ ] Commit `d7792c9` ("UX simplification pass: Cases + SOAR" — the
      `cases.html`/`soar.html` work below) is **committed but not yet pushed/deployed**.
      It was landed by a concurrent session while this file was being set up (same git
      identity, `n0sfs`), including its own CHANGELOG.md entry. Not yet run through
      CLAUDE.md's testing standard (Jinja compile-check, `node --check` on inline
      scripts, live-verify on prod) as far as this session can tell — confirm before
      push+deploy, and check for another session mid-push first to avoid a race.
- [ ] `rules/yara_imported/rules-master/webshells/WShell_THOR_Webshells.yar` — **deleted**
      (8588 lines) in the working tree, still unstaged. Needs a decision: intentional
      removal (license/noise reasons?) or accidental — confirm with the user before this
      gets committed either way.

## Next

_Empty — populate from the next task the user gives._

## Done (recent, for continuity — full history is `git log` / CHANGELOG.md)

- [x] UX simplification pass on Cases + SOAR — collapsed retrospective/PIR, tab naming
      cleanup, merged "My queues only" into the queue filter, SOAR toolbar → Configure
      dropdown (`d7792c9`, committed, not yet pushed/deployed — see In-flight above)
- [x] Named email templates + `{{field_slug}}` custom-field substitution for playbook
      actions (`739117f`, `989ca9d`)
- [x] CSV export on the Cases list (`7b58aae`)
- [x] SOAR "New from Template" playbook gallery (`d8aa8e3`)
- [x] Severity-classification helper + rationale field on cases (`22720df`)

## How to use this file

- Check items off as they're verified (not just coded) — verification is what CLAUDE.md's
  testing standard requires before a task counts as done.
- Keep this short. If it's ballooning, the "Done" section is probably duplicating
  CHANGELOG.md — prune it back to just enough for a fresh session's continuity.
