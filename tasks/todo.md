# Tasks: vault-journal

Plan: [plan.md](plan.md) · Spec: [SPEC-vault-journal.md](../SPEC-vault-journal.md)
Order: 1 → 2 → 3 → 4 → 5 → 6 → 7. Each task is one TDD cycle and one commit.

## Task 1: sanitize_cell and render (M)
`src/snorty/journal/__init__.py`, `render.py`.
- [x] `sanitize_cell(text, limit=120)`: printable only, whitespace collapsed; `|`, `[`, `]`, backtick, `<`, `>`, `%%` and a word-initial `#` neutralised; capped at `limit`
- [x] `render(day, alerts, tz, total=None)` gives the managed block: begin marker, `## Snort alerts`, count line (`N alerts · P1 a · P2 b · P3 c · updated HH:MM` in `tz`), `### Top rules` (10), `### Top addresses` (10 sources, 10 destinations), `### By hour` (24 rows, local hours), `### Priority 1 alerts` (50 rows newest first, then `…and N more`, or `None.`), end marker; ties ordered by key so output is stable
- [x] `total` larger than `len(alerts)` adds `truncated: N alerts not shown in tables`
- [x] Golden-text test for a fixed alert set, empty day, 60 P1 alerts cut at 50, ties, 23:59 vs 00:01 local hour buckets
- [x] Hostile text (pipe, brackets, backtick, `#tag`, `%% x %%`, an end marker, newlines, 10,000 chars, non-ASCII) cannot add a column, link, tag, comment, HTML or marker line
- [x] Verify: `uv run pytest tests/journal/test_journal_render.py -q`
- Dependencies: none · Files: `render.py`, `tests/journal/test_journal_render.py`

## Task 2: merge and NoteConflict (S)
Same `render.py` (or `merge.py` if it grows).
- [x] `merge(existing, block, day)`: `None` gives frontmatter (`date`, `type: snort-journal`, `tags`, `ai-first: true`) + `# YYYY-MM-DD Snort journal` + block
- [x] One begin and one end marker in order: replace only between them; no markers: append after a blank line; broken markers (duplicate, one only, reversed): raise `NoteConflict`
- [x] User text and frontmatter byte for byte over 10 regenerations; identical result returns the same string
- [x] Verify: `uv run pytest tests/journal/test_journal_merge.py -q`
- Dependencies: Task 1 · Files: `render.py`, `tests/journal/test_journal_merge.py`

### Checkpoint: Tasks 1-2
- [x] Tests green; `uv run ruff check src tests`; mypy clean (add `snorty.journal.*` to the strict override in `pyproject.toml`)

## Task 3: Port and adapters (M)
`src/snorty/journal/ports.py`.
- [x] `NoteStore` Protocol: `read(day) -> str | None`, `write(day, text) -> None`
- [x] `MemoryNoteStore` (dict, records writes)
- [x] `VaultNoteStore(vault_root)`: path `<vault>/Security/Snort/YYYY-MM-DD.md`; creates `Security/Snort/` if missing; refuses a missing vault root; resolves the target and refuses anything outside the folder (`..`, absolute, symlink where the OS allows); writes a temp file in the same folder then `os.replace`; UTF-8, `\n` newlines
- [x] Tests on a real temp folder, including escape attempts, atomic write (no temp file left, old text intact if the write fails), missing root
- [x] Verify: `uv run pytest tests/journal/test_journal_store.py -q`
- Dependencies: Task 2 · Files: `ports.py`, `tests/journal/test_journal_store.py`

## Task 4: JournalService (M)
`service.py`: `JournalConfig(flush_interval=300, tz)`, `JournalService(bus, repo, store, config, *, clock, sleep)`; `journal_fakes.py`.
- [x] `start()` subscribes before returning, regenerates today and yesterday from the repository, spawns the consumer task
- [x] `AlertRaised` marks the alert's local day dirty; a flush rebuilds each dirty day (`collect` pages the repository, builds `render`, `merge`s with `store.read`, writes) and clears the flag
- [x] At most one flush per interval; `stop()` flushes once then cancels and closes the subscription; `stop()` before `start()` and twice are harmless; `start()` twice does not double-subscribe
- [x] Alerts the sensor ingested without announcing appear after `start()`
- [x] Verify: `uv run pytest tests/journal/test_journal_service.py -q` (real `EventBus`, temp `AlertRepository`, `MemoryNoteStore`, fake clock and sleep)
- Dependencies: Tasks 1-3 · Files: `service.py`, `tests/journal/journal_fakes.py`, `test_journal_service.py`

## Task 5: Resilience and paging (M)
Same `service.py`; `tests/journal/test_journal_resilience.py`.
- [x] A store that raises or a `NoteConflict` is logged, the day stays dirty and the next flush retries; nothing escapes the consumer
- [x] Unchanged merged text causes no write
- [x] A day over 100,000 rows (cap lowered by config in the test) gives the truncation line and the true total
- [x] A blocking store does not slow `bus.publish` (1,000 publishes finish quickly)
- [x] Verify: `uv run pytest tests/journal -q`
- Dependencies: Task 4 · Files: `service.py`, `test_journal_resilience.py`

### Checkpoint: Tasks 3-5
- [x] Spec criteria 1-10 each covered by a passing test; whole journal unit suite under 3 s; ruff and strict mypy clean

## Task 6: CLI and sensor wiring (M)
`src/snorty/journal/__main__.py`; `src/snorty/sensor/__main__.py`.
- [x] `python -m snorty.journal write [--date YYYY-MM-DD] [--db PATH] [--vault PATH] [--dry-run]`: vault from `--vault` or `OBSIDIAN_VAULT_PATH`, error with exit 2 if neither; writes one note (or prints it); exit 0, or 1 with the error
- [x] `python -m snorty.sensor --journal` composes a `JournalService` on the same bus and repository, started before the sensor and stopped after it; combines with `--notify`
- [x] `snorty.sensor` package modules (not `__main__`) do not import `snorty.journal` (grep-checked)
- [x] Unit tests with a temp DB and `MemoryNoteStore`; the sensor change covered by a smoke test with stubs like `test_cli_notify.py`
- [x] Verify: `uv run pytest tests/journal tests/sensor -q -m "not snort"`
- Dependencies: Tasks 3-5 · Files: `journal/__main__.py`, `sensor/__main__.py`, `tests/journal/test_journal_cli.py`, `tests/sensor/test_cli_journal.py`

## Task 7: Real checks and close-out (S)
- [ ] Manual: `uv run python -m snorty.journal write --db <db with real alerts>` creates today's note in the vault; a line typed outside the markers survives a second run (report what I saw)
- [ ] Manual: a real Snort loopback run with `JournalService` writes a note containing the alert, with no leftover `snort.exe`
- [ ] Coverage for `snorty.journal` at least 90% from unit tests alone (read from the json report)
- [ ] `grep -r subprocess src/snorty` matches only `snort/` files; `snorty.journal` imports only `snorty.core` and stdlib
- [ ] SPEC-vault-journal.md Success Criteria and deviations amended and ticked; plan and todo boxes ticked except the "next module" one
- [ ] Verify: `uv run pytest -q -m "not snort"`; `uv run ruff check src tests`; mypy as above
- Dependencies: Task 6
