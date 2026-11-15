# Implementation Plan: alert-core

Source spec: [SPEC-alert-core.md](../SPEC-alert-core.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)

## Overview

Build the Snorty project skeleton and the `snorty.core` package: domain types,
the `alert_fast` parser, the async event bus and the SQLite alert repository.
Stdlib only at runtime. Each task leaves `uv run pytest` green.

## Architecture Decisions

- **Repository is synchronous.** `sqlite3` is blocking; async callers (sensor,
  dashboard) will wrap calls in `asyncio.to_thread`. Keeps the core simple and
  testable without an event loop. One connection per repository instance,
  WAL mode, `check_same_thread=False` guarded by a `threading.Lock`.
- **Idempotency key = raw line.** `UNIQUE(raw)` with `INSERT OR IGNORE`. Two
  genuinely different alerts always differ in timestamp (microseconds) or
  rule/endpoints, so their lines differ.
- **Timestamps stored as UTC ISO-8601 text**, converted back to the local zone
  on read. Avoids DST ambiguity in range queries.
- **Parser is one anchored regex plus small pure helpers** (`_parse_ts`,
  `_split_endpoint`). Unknown lines return `None`; no exceptions escape.
- **EventBus:** one `asyncio.Queue(maxsize=N)` per subscriber. `publish` is a
  plain (non-async) method using `put_nowait`; on `QueueFull` it drops the
  oldest item with `get_nowait` and retries once, then increments that
  subscriber's `dropped` counter. The publisher can never await.
- **Layout and tooling** exactly as the spec's Project Structure and Commands.

## Task List

### Phase 1: Foundation and riskiest part first
- [x] Task 1: Project scaffold (uv project, tooling config, empty `snorty.core`, smoke test)
- [x] Task 2: Domain models (`Alert`, `Suppression` + threshold line)
- [x] Task 3: `alert_fast` parser + fixtures + `python -m snorty.core.parser` check script

### Checkpoint A (after Tasks 1–3)
- [x] `uv run pytest tests/core` green; ruff and mypy clean
- [x] Parsing the real `C:\Snort\log\alert.ids` reports 0 failed lines
- [x] Human review before continuing

### Phase 2: Events and storage
- [x] Task 4: Event types + `EventBus` with bounded drop-oldest queues
- [x] Task 5: `AlertRepository` (schema, idempotent add, queries, counts, prune)

### Checkpoint B (after Tasks 4–5)
- [x] All core tests green in under 2 s

### Phase 3: Spec success criteria
- [x] Task 6: Success-criteria tests (1,000 alerts stored twice; 10,000 events with a stalled subscriber), coverage ≥ 90%, strict mypy

### Checkpoint C: Module complete
- [x] Every Success Criteria box in SPEC-alert-core.md checked
- [x] Human review, then spec for `snort-adapter`

Task 4 depends only on Task 1, so it can be built in parallel with Tasks 2–3.
Task 5 depends on Task 2. In practice this runs in one session, in order.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| `alert_fast` variants not seen yet (IPv6 compressed form, odd protocols like `{PROTO:255}`, `msg` with brackets) | Med | Fixtures from the real `alert.ids`; regex keeps `msg` non-greedy up to ` [**]`; protocol group accepts any text in braces; every new failing line becomes a fixture |
| Lines without a year read across New Year | Low | Sensor runs Snort with `-y`; for old lines the caller passes the year; documented in `parse_line` docstring |
| SQLite locking on Windows when the dashboard reads while the sensor writes | Med | WAL mode, single writer connection, readers in short transactions; tested with two connections in Task 5 |
| Timezone/DST errors in hour buckets | Low | Store UTC, bucket in the caller's zone; test a DST-change day |

## Open Questions

- **Git:** initialise a git repository in `Snorty` now so each task can be committed? (Commits only when you ask.)
