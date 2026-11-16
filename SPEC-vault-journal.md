# Spec: vault-journal — V1

Module id: `vault-journal` (package `snorty.journal`). Depends on: `alert-core`. Map: `CAPABILITY-MAP.md`.

## Objective

Write one Obsidian note per local day with that day's Snort alerts and a plain summary, in your second-brain vault. Re-running regenerates the same note. Text you write in the note is never touched.

User: you, reading `Security/Snort/YYYY-MM-DD.md` next to your other notes. Success: after a day of traffic the note shows counts, top rules, top addresses, an hourly profile and the priority-1 alerts, and your own notes in the file survive every regeneration.

## Assumptions (correct me or I proceed)

1. Vault is `C:\Users\tesse\Documents\Second Brain`, given by `--vault` or the `OBSIDIAN_VAULT_PATH` env var (already set in your Claude settings). Writes go only under `<vault>\Security\Snort\`; the folder is created if missing, the vault root never is.
2. **Summary is a plain template** (counts, top rules, top addresses, hourly profile). The Claude-API summary from the map's open question 1 is deferred: it needs an API key, costs money, and sends alert data off the machine, which breaks the "everything stays local" rule.
3. The note is ours only between two marker lines. Everything outside them (your text, anything Obsidian plugins add) is preserved byte for byte.
4. Frontmatter follows your daily notes: `date`, `type: snort-journal`, `tags`, `ai-first: true`. It is written only when the file is new and is never edited afterwards.
5. A day with no alerts gets no new note. An existing note's managed block is updated to zero.
6. Days are local calendar days (the machine's time zone). Alerts are stored in UTC.
7. Alert `msg` comes from third-party rule files, so all alert text is sanitised before it enters Markdown (see Behaviour).
8. Stdlib only. No new dependency, no network, no subprocess.
9. Flush interval 5 minutes while the sensor runs. Not a live view; the dashboard is.

## Architecture and patterns

- **Functional core, imperative shell.** `render(day, alerts, tz) -> str` is pure and deterministic: same alerts, same bytes. `merge(existing, block, day) -> str` is pure too: places the managed block into a note.
- **Port:** `NoteStore` Protocol, `read(day) -> str | None`, `write(day, text) -> None`. `VaultNoteStore(vault_root)` is the real adapter (path-confined, atomic write). `MemoryNoteStore` in tests.
- **Observer + debounce:** `JournalService(bus, repo, store, config, clock, tz)` subscribes to the bus (`AlertRaised` marks that day dirty); one consumer task flushes dirty days every `flush_interval`. `stop()` flushes once, then cancels. A failed write is logged and the day stays dirty for the next flush.
- **Idempotent regeneration:** every flush rebuilds the whole day from the repository (the source of truth), so backlog the sensor never announced, missed events and restarts all converge. On `start()` it regenerates today and yesterday.
- `publish` is never slowed (drop-oldest subscription, as in notify). Dropped events do not matter because the flush reads the database.

## Behaviour

**Note path:** `<vault>\Security\Snort\YYYY-MM-DD.md`.

**Managed block**, between these two lines:

```
<!-- snorty:begin — generated; edit outside these markers -->
...
<!-- snorty:end -->
```

**Block content**, in order:

1. `## Snort alerts` and one line: `N alerts · P1 a · P2 b · P3 c · updated HH:MM`.
2. `### Top rules`: table of the 10 most frequent rules: SID, message, count.
3. `### Top addresses`: top 10 sources and top 10 destinations with counts.
4. `### By hour`: 24-row table, hour and count.
5. `### Priority 1 alerts`: a table of up to 50 rows (time, SID, message, source → destination), newest first, then `…and N more` if cut. If none: `None.`

**Merge rules** (`merge`):

- No existing note: frontmatter + `# YYYY-MM-DD Snort journal` + block.
- Existing note with exactly one begin and one end marker in order: replace only the text between them.
- Existing note with no markers: append the block at the end after a blank line. Nothing else changes.
- Existing note with broken markers (duplicate, only one, reversed): refuse. Log an error, write nothing, leave the file as it is.
- Result identical to the existing text: no write (file mtime unchanged).

**Sanitising for Markdown:** alert text is reduced to printable characters; whitespace is collapsed; `|`, `[`, `]`, backtick, `<`, `>`, `%%` and `#` at word start are replaced with a space or escaped so that a rule message can never add a table column, a wikilink, a tag, a comment, HTML, or our own marker lines. Each cell is capped at 120 characters.

**Paging:** the day's alerts are read in pages of 1,000 (newest first) with a hard cap of 100,000 rows. Past the cap the note says `truncated: N alerts not shown in tables`; the total count still comes from the database.

**Writing:** `VaultNoteStore` resolves the target and refuses anything outside `<vault>\Security\Snort\` (including symlinks and `..`). It writes to a temp file in the same folder and `os.replace`s it, so a reader never sees half a note. A missing vault root is an error, not created.

## Commands

```
Test:   uv run pytest tests/journal -q
Lint:   uv run ruff check src tests
Types:  uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules src/snorty/notify src/snorty/journal
CLI:    uv run python -m snorty.journal write [--date YYYY-MM-DD] [--db PATH] [--vault PATH] [--dry-run]
        uv run python -m snorty.sensor --journal [--notify]       # sensor with a journal
```

`--dry-run` prints the note instead of writing it. `--journal` is composition only: the `sensor` package stays unaware of `journal`.

## Project structure

```
src/snorty/journal/
  render.py     render(), merge(), sanitize_cell() (pure)
  ports.py      NoteStore Protocol, VaultNoteStore
  service.py    JournalConfig, JournalService
  __main__.py   CLI (write command)
tests/journal/  test_render, test_merge, test_store, test_service, test_journal_cli
```

Test files get unique basenames (a repeat basename in another folder breaks collection).

## Code style

Frozen dataclasses, `Protocol` ports, injected `clock` and `tz`, strict mypy, ruff (E,F,I,B,UP, 100 cols). Pure shape:

```python
def merge(existing: str | None, block: str, day: date) -> str:
    """The note text after putting `block` in. Raises NoteConflict on broken markers."""
```

## Testing strategy

- Pure core: unit tests for `render` (golden text for a fixed alert set, empty day, ties in top lists, UTC-to-local day boundary around midnight) and `merge` (every rule above, user text and frontmatter preserved byte for byte, idempotent).
- Hostile text: pipes, brackets, backticks, `#tag`, `%% comment %%`, an end marker inside a rule message, newlines, huge input, non-ASCII.
- Store: real temp folder; path escape (`..`, absolute, symlink where the OS allows), atomic write, missing vault root, folder creation.
- Service: real `EventBus` and `AlertRepository` on a temp DB, `MemoryNoteStore`, fake clock; assertions on debounce, restart regeneration, failed write retried, stop flush.
- One manual check in the final summary: a real note appears in your vault and opens correctly in Obsidian, and a line you type outside the markers survives a regeneration.
- Coverage of `snorty.journal` at least 90% from unit tests alone.

## Boundaries

- **Always:** write only under `Security/Snort/`; sanitise all alert text; use temp file + replace; rebuild from the repository.
- **Ask first:** the AI summary (assumption 2); writing outside `Security/Snort/`; adding links from other notes to the journal; any new dependency.
- **Never:** edit text outside the markers; edit existing frontmatter; delete or rename a note; send alert data off the machine; call a subprocess; raise out of the consumer task; create the vault root.

## Success Criteria

- [ ] 1. `render` is deterministic and its output matches a golden note for a fixed alert set, including the empty day and the P1 table cut at 50.
- [ ] 2. Day boundaries use the local zone: an alert at 23:59 and one at 00:01 local land in different notes.
- [ ] 3. `merge` into no note creates frontmatter, title and block; into a note without markers appends the block and changes nothing else; with good markers replaces only between them; with broken markers raises and writes nothing.
- [ ] 4. Your text and frontmatter in an existing note survive 10 regenerations byte for byte; an unchanged result causes no write.
- [ ] 5. Hostile alert text cannot add a table column, wikilink, tag, comment, HTML or marker line.
- [ ] 6. `VaultNoteStore` refuses any path outside `<vault>\Security\Snort\` and a missing vault root; writes are atomic.
- [ ] 7. The service flushes a dirty day at most once per interval, flushes on `stop()`, retries after a failed write, and never raises out of its consumer task.
- [ ] 8. `start()` regenerates today and yesterday from the database, including alerts the sensor ingested without announcing.
- [ ] 9. A slow or failing store never slows `bus.publish`.
- [ ] 10. A day over the 100,000-row cap produces a truncation line and a correct total.
- [ ] 11. Manual: `python -m snorty.journal write` creates today's note in the vault, and a line typed outside the markers survives a second run; `python -m snorty.sensor --journal` runs and stops cleanly with no leftover `snort.exe`.
- [ ] 12. `ruff check`, strict mypy on `snorty.journal`, coverage at least 90%; `snorty.journal` imports only `snorty.core` and stdlib; no `subprocess` in our `src/snorty` outside `snort/`.

## Out of Scope (Deferred)

- AI-written summary through the Claude API: off-machine data and cost.
- "New IPs" (first seen today): needs a repository query for earlier days; add with the dashboard.
- Weekly and monthly roll-ups, per-rule notes, wikilinks to other vault notes.
- Writing through the vault MCP server or the Obsidian CLI: file write is simpler and works with Obsidian closed.
- Live note updates per alert (the dashboard is the live view).

## Open Questions

1. **Summary type:** plain template now (assumption 2). OK, or do you want the Claude-API summary despite the key, cost and off-machine data?
2. **Flush interval:** every 5 minutes while the sensor runs, plus once on stop. OK?
3. **Frontmatter:** `type: snort-journal`, `tags: [security, snort]`, `ai-first: true`. Does your vault want a different `type` or extra fields?
