# Tasks

Structural progress checklist — done / in-flight / next. Checked-off items can be
deleted once a session confirms them stable in production; this is a working list, not
a history (that's [CHANGELOG.md](CHANGELOG.md)).

## In-flight (uncommitted in working tree, undocumented)

Found at session start 2026-09-11 — pre-dates this file, not yet tied to a plan:

- [ ] `templates/cases.html` — merges the "My queues only" switch into
      `queueFilterSelect` as a `__my__` option; collapses Retrospective/PIR into a
      `<details>` that auto-expands on Resolved/Closed; tab-label tweaks (Items →
      "Linked Items", Related Cases → "Case Links", drops the standalone "Threat Intel"
      tab, Attachments icon change); Export CSV button shrunk to icon-only.
- [ ] `templates/soar.html` — collapses "Manage Secrets" / "Manage Custom Actions" /
      "Manage Email Templates" into one "Configure" dropdown.
- [ ] `rules/yara_imported/rules-master/webshells/WShell_THOR_Webshells.yar` — **deleted**
      (8588 lines). Needs a decision: intentional removal (license/noise reasons?) or
      accidental — confirm with the user before this gets committed either way.
- [ ] None of the above verified per CLAUDE.md's testing standard yet (Jinja
      compile-check, `node --check` on inline scripts, live-verify on prod) or written up
      in CHANGELOG.md.

## Next

_Empty — populate from the next task the user gives._

## Done (recent, for continuity — full history is `git log` / CHANGELOG.md)

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
