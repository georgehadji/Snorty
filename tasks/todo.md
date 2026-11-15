# Tasks: alert-core

Plan: [tasks/plan.md](plan.md) · Spec: [SPEC-alert-core.md](../SPEC-alert-core.md)

Definition of done for every task: its tests pass, `uv run ruff check src tests`
and `uv run mypy src/snorty/core` are clean, and the full `uv run pytest` stays green.

## Task 1: Project scaffold

**Description:** Create the uv project with the layout from the spec, tool
configuration, and an empty `snorty.core` package with one smoke test.

**Acceptance criteria:**
- [x] `pyproject.toml`: name `snorty`, Python `>=3.12`, `src/` layout, no runtime deps; dev group: pytest, pytest-asyncio, pytest-cov, ruff, mypy
- [x] ruff (line length 100, rules `E,F,I,B,UP`), mypy (`strict` for `snorty.core`), pytest (`asyncio_mode = "auto"`, `snort` marker registered) configured in `pyproject.toml`
- [x] `.gitignore` covers `.venv/`, `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `*.db`, `snorty.toml`

**Verification:**
- [x] `uv sync` succeeds
- [x] `uv run pytest` runs 1 passing smoke test (`import snorty.core`)
- [x] `uv run ruff check src tests` and `uv run mypy src/snorty/core` clean

**Dependencies:** None

**Files likely touched:** `pyproject.toml`, `.gitignore`, `src/snorty/__init__.py`, `src/snorty/core/__init__.py`, `tests/core/test_smoke.py`

**Estimated scope:** S

## Task 2: Domain models

**Description:** Frozen, slotted `Alert` and `Suppression` dataclasses.
`Suppression.to_threshold_line()` renders the Snort 2.9 `threshold.conf` line.

**Acceptance criteria:**
- [x] `Alert` has exactly the fields in the spec; instances are immutable and hashable
- [x] `Suppression(1, 2010935).to_threshold_line() == "suppress gen_id 1, sig_id 2010935"`; with `track="by_src", ip="1.2.3.4"` → `"suppress gen_id 1, sig_id 2010935, track by_src, ip 1.2.3.4"`
- [x] `track` without `ip` (or `ip` without `track`) raises `ValueError` on construction

**Verification:**
- [x] `uv run pytest tests/core/test_models.py -q`

**Dependencies:** Task 1

**Files likely touched:** `src/snorty/core/models.py`, `tests/core/test_models.py`

**Estimated scope:** S

## Task 3: alert_fast parser

**Description:** `parse_line(line, *, default_year, tz) -> Alert | None` plus a
`__main__` entry that parses a file and prints parsed/failed counts. Fixture
file built from the real `C:\Snort\log\alert.ids` and crafted edge cases.

**Acceptance criteria:**
- [x] Parses: year/no-year timestamps; with/without classification; TCP/UDP with ports; ICMP without ports; IPv4; expanded 9-group IPv6 with port
- [x] Malformed input (empty, truncated, random text, bad date like `13/45`) returns `None` and never raises
- [x] `uv run python -m snorty.core.parser <file>` prints `parsed=N failed=M` and lists the first 5 failed lines

**Verification:**
- [x] `uv run pytest tests/core/test_parser.py -q` (parametrized over `tests/fixtures/alert_fast.txt` and malformed cases)
- [x] Manual: `uv run python -m snorty.core.parser C:\Snort\log\alert.ids` → `failed=0`

**Dependencies:** Task 2

**Files likely touched:** `src/snorty/core/parser.py`, `tests/core/test_parser.py`, `tests/fixtures/alert_fast.txt`

**Estimated scope:** M

## Checkpoint A: after Tasks 1–3
- [x] All tests green; ruff and mypy clean
- [x] Real `alert.ids` parses with 0 failures
- [x] Review with human before continuing

## Task 4: Events and EventBus

**Description:** Frozen event dataclasses (`AlertRaised`, `SensorStateChanged`,
`RulesUpdated`) and an `EventBus` with per-subscriber bounded queues.

**Acceptance criteria:**
- [x] `subscribe(maxsize=1000)` returns a `Subscription` (async iterator, `.dropped` counter, `.close()`); `publish(event)` is synchronous and never blocks
- [x] Three subscribers each receive every event published after subscribing, in order; closed subscriptions receive nothing further
- [x] On a full queue the oldest event is dropped, the new one is kept, and `dropped` increments

**Verification:**
- [x] `uv run pytest tests/core/test_bus.py -q`

**Dependencies:** Task 1 (uses `Alert` from Task 2 only in tests)

**Files likely touched:** `src/snorty/core/events.py`, `src/snorty/core/bus.py`, `tests/core/test_bus.py`

**Estimated scope:** S

## Task 5: AlertRepository

**Description:** SQLite store for alerts: schema creation, idempotent insert,
filtered queries, per-SID and per-hour counts, retention pruning.

**Acceptance criteria:**
- [x] `add(alert) -> bool` and `add_many(alerts) -> int` (new rows only); re-adding the same alert returns `False` / adds 0 rows
- [x] `query(since=, until=, sid=, min_priority=, limit=, offset=)` returns newest first; `min_priority=1` returns only priority-1 alerts
- [x] `counts_by_sid(since, until)` and `counts_by_hour(since, until, tz)`; `prune(before)` deletes rows strictly older than `before`
- [x] Opening the DB enables WAL; a second connection can read while the first writes

**Verification:**
- [x] `uv run pytest tests/core/test_repository.py -q` (uses `tmp_path`)

**Dependencies:** Task 2

**Files likely touched:** `src/snorty/core/repository.py`, `tests/core/test_repository.py`

**Estimated scope:** M

## Checkpoint B: after Tasks 4–5
- [x] `uv run pytest tests/core -q` green in under 2 s

## Task 6: Success criteria and quality gates

**Description:** Add the spec's success-criteria tests and close coverage and typing gaps.

**Acceptance criteria:**
- [x] Test: storing the same 1,000 alerts twice leaves exactly 1,000 rows
- [x] Test: publishing 10,000 events with one stalled subscriber finishes in under 1 s
- [x] Coverage for `snorty.core` ≥ 90%; `mypy src/snorty/core` strict clean

**Verification:**
- [x] `uv run pytest tests/core --cov=snorty.core --cov-report=term-missing`
- [x] `uv run ruff check src tests` and `uv run mypy src/snorty/core`

**Dependencies:** Tasks 3, 4, 5

**Files likely touched:** `tests/core/test_success_criteria.py`, any core file with uncovered branches

**Estimated scope:** S

## Checkpoint C: module complete
- [x] All Success Criteria in SPEC-alert-core.md checked
- [x] Human review; then write SPEC-snort-adapter.md
