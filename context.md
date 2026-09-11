# Context

Volatile, session-to-session snapshot of "what's true right now." Stable architecture,
domain conventions, and the deploy process live in [CLAUDE.md](CLAUDE.md) — don't
duplicate those here, just link. This file is expected to go stale and get overwritten;
[CHANGELOG.md](CHANGELOG.md) is the durable, dated record that never gets rewritten.

## System state (as of 2026-09-11)

- Production: `n0snuc` / `192.168.86.100:5001`, deployed via `update.sh` (see CLAUDE.md
  Deployment section). Last deploy corresponds to commit `739117f` (Email Templates
  modal `{{case_id}}` fix).
- Working tree has uncommitted changes not yet described anywhere — see
  [tasks.md](tasks.md) for the breakdown.

## Active constraints

Nothing beyond what's already codified in CLAUDE.md's "Domain conventions" and
"What not to do" sections — that list is the actual source of truth (dual-definition
UEBA config dicts, TLP/PAP empty-string semantics, reserved-key namespacing, `$` vs `\Z`
in validation regex, chunked-endpoint optimistic concurrency, etc.). Read it before
touching `src/app.py`.

## How to use this file

- Update it when a session ends with a real architectural decision or a system-state
  fact a fresh session would need (e.g. "prod is mid-migration," "X feature is half-wired
  and deliberately paused"). Don't log routine progress here — that's tasks.md.
- If something here turns out to be durable/important beyond the current work cycle,
  promote it into CLAUDE.md or CHANGELOG.md instead of letting it live only here.
