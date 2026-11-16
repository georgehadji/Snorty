# Implementation Plan: vault-journal

Source spec: [SPEC-vault-journal.md](../SPEC-vault-journal.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)
Previous modules: alert-core, snort-adapter, sensor, rules, notify, done (their plans and tasks are in git history; notify's last at `a94c930`).

## Overview

Build `snorty.journal`: one Obsidian note per local day, regenerated from the alert
repository, with a managed block between two marker lines and your own text left alone.
Pure logic first (sanitise and render, then merge), then the note-store port with the
path-confined vault adapter, then the service (dirty days, debounced flush, start
regeneration, stop flush), then resilience and paging, then the CLI and the `--journal`
flag on the sensor CLI, then the manual real-vault check.

## Architecture Decisions

- **Functional core.** `render(day, alerts, tz, total) -> str` and `merge(existing, block, day) -> str` are pure and deterministic; every rule is tested with plain strings.
- **Repository is the source of truth.** Each flush rebuilds the whole day from `AlertRepository` (paged, 1,000 per page, 100,000 cap), so backlog, dropped events and restarts converge. Bus events only mark a day dirty.
- **One consumer task, one flush timer.** `start()` subscribes before returning, regenerates today and yesterday, then loops: wait for the interval (injected `sleep`), flush dirty days. `stop()` flushes once, cancels the task, closes the subscription. Second `start()` is a no-op.
- **`NoteStore` port** (`read(day)`, `write(day, text)`); `VaultNoteStore` confines every path to `<vault>\Security\Snort\`, writes temp file + `os.replace`, never creates the vault root. `MemoryNoteStore` for tests.
- **Failures never escape.** A failed write or conflict is logged; the day stays dirty and is retried at the next flush. Unchanged result means no write.
- **Sanitise alert text for Markdown** at the cell level so rule messages cannot add columns, links, tags, comments, HTML or our marker lines.
- **`journal` imports only `snorty.core`** plus stdlib. The sensor CLI composes it; the `sensor` package does not import `journal`.
- **Dependencies:** none. `snorty.journal.*` added to the strict mypy override.
- Test file basenames are unique across test dirs: `test_journal_render.py`, `test_journal_merge.py`, `test_journal_store.py`, `test_journal_service.py`, `test_journal_resilience.py`, `test_journal_cli.py`, `journal_fakes.py`.

## Task List

### Phase 1: Pure logic
- [x] Task 1: `sanitize_cell` and `render`
- [x] Task 2: `merge` and `NoteConflict`

### Checkpoint: Pure logic
- [x] All unit tests green; ruff and strict mypy clean on `snorty.journal`

### Phase 2: Port and service
- [ ] Task 3: `NoteStore`, `VaultNoteStore`, `MemoryNoteStore`
- [ ] Task 4: `JournalService` (dirty days, flush, start regeneration, stop flush)
- [ ] Task 5: resilience and paging (failed write retry, no-write when unchanged, cap, non-blocking publish)

### Checkpoint: Service
- [ ] Spec criteria 1-10 each covered by a passing test; unit suite under 3 s

### Phase 3: CLI and real checks
- [ ] Task 6: `python -m snorty.journal write`, `--journal` on the sensor CLI
- [ ] Task 7: manual real-vault write and real `--journal` run, close-out

### Checkpoint: Complete
- [ ] Every Success Criteria box in SPEC-vault-journal.md checked
- [ ] Then the next module spec (rule-lab or dashboard)

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rule text breaks the note or our markers | High | Cell sanitiser; hostile-text tests including an end marker in a message |
| Overwriting your own text | High | Replace only between markers; refuse on broken markers; byte-for-byte test over 10 regenerations |
| Write escapes `Security/Snort/` (`..`, symlink) | High | Resolve and check containment; escape tests |
| Half-written note read by Obsidian | Med | Temp file + `os.replace` |
| Local day boundary wrong (UTC storage) | Med | Day range computed in local zone then converted; midnight test |
| Huge day (millions of rows) | Med | Page 1,000 at a time, 100,000 cap, totals from the database |
| Obsidian sync conflict on the open note | Low | Write only when the text changes; atomic replace |

## Open Questions

None blocking. Defaults taken (approved): template summary, 5-minute flush, frontmatter `type: snort-journal`, `tags: [security, snort]`, `ai-first: true`.
