# Implementation Plan: sensor

Source spec: [SPEC-sensor.md](../SPEC-sensor.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)
Previous modules: alert-core and snort-adapter, done (their plans and tasks are in git history, last at `5ed4ab5`).

## Overview

Build `snorty.sensor`: a supervisor that keeps Snort running through the adapter, tails
`alert.ids`, stores and announces alerts, restarts on crash or network change, and has a
CLI. Pure decision logic first (states, backoff, tailing), then the `Sensor` class built
up in three slices (lifecycle, ingest, supervision) against a fake port and fake clock,
then the real-Snort integration tests and CLI. Stdlib only.

## Architecture Decisions

- **Time is injected.** `Sensor` takes `clock` (monotonic seconds) and `sleep` callables, so backoff, stable-run reset and the network-check timer are tested in milliseconds with no real waiting.
- **`SnortPort` Protocol** is the only way the sensor touches Snort. `SnortAdapter` wraps `snorty.snort`. Tests use a `FakePort` that can be told to fail, exit, or change IP.
- **Stale-instance check needs a process lookup**, which must live in `snorty.snort` (subprocess containment). Task 3 adds `is_snort_running(pid, runner)` there (via `tasklist`), then exposes it on the port.
- **Tailer is polling and pure-ish:** `read_new_lines(path, state)` reads bytes from an offset and returns complete lines plus the new state; the sensor owns the loop. No file-watcher dependency.
- **Backlog = everything before the first end-of-file.** Stored via the repository; events only for rows the repository reports as new and only for live lines.
- **One supervisor task** owns all state changes (commands go through an `asyncio.Lock`); the tailer task only ingests.
- Spec's package layout and commands are used as written.

## Task List

### Phase 1: Pure logic and the port
- [ ] Task 1: states, transition table, backoff and give-up policy
- [ ] Task 2: tail reader (partial lines, CRLF, rotation, junk)
- [ ] Task 3: `SnortPort`, `SnortAdapter`, `is_snort_running` in the adapter

### Checkpoint A (after Tasks 1–3)
- [ ] All unit tests green; ruff and strict mypy clean on core, snort, sensor

### Phase 2: The Sensor class, against fakes
- [ ] Task 4: lifecycle (start, stop, state events, interface choice, pid file, stale refusal, status)
- [ ] Task 5: ingest (tailer task, backlog vs live, repository via `to_thread`, unparsed count, final drain)
- [ ] Task 6: supervision (crash restart with backoff, give-up, stable reset, network change, `restart()`)

### Checkpoint B (after Tasks 4–6)
- [ ] Every acceptance criterion 1–10 has a passing fake-port test; unit suite under 2 s

### Phase 3: Real Snort and CLI
- [ ] Task 7: `python -m snorty.sensor` CLI and `@pytest.mark.snort` integration tests (live alert, clean stop, crash restart)

### Checkpoint C (after Task 7)
- [ ] Integration tests green on this PC; manual run of the CLI shows RUNNING and a stored alert

### Phase 4: Gates
- [ ] Task 8: coverage ≥ 90%, strict mypy, containment checks, spec boxes ticked

### Checkpoint D: module complete
- [ ] Every Success Criteria box in SPEC-sensor.md checked
- [ ] Then the next module spec (rules, notify, vault-journal or rule-lab)

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Async supervision races (stop during start, crash during stop) | High | Single supervisor task, one lock, table-driven transitions, a test for each pair in the "STARTING → STOPPING" and "RUNNING → STARTING" rows |
| Fake-clock tests drift from real behaviour | Med | Integration crash/restart test uses the real clock with shortened `config` timings (backoff base 0.2 s) |
| Tailer loses or duplicates lines on rotation | High | Task 2 tests every case; repository `UNIQUE(raw)` makes duplicates harmless; lost lines covered by "shrink then re-read from 0" |
| Killing the Snort pid in the crash test affects the wrong process | Med | The test kills only the pid it got from `status()` after starting its own temp-dir instance |
| `tasklist` output differs by Windows locale | Low | Request CSV (`/FO CSV /NH`) and match the pid column, not text; unknown output means "not running" |
| Blocking the event loop with sqlite or file reads | Med | All repository and file calls via `asyncio.to_thread`; a test asserts the loop stays responsive during a large ingest |
| Orphan Snort after Snorty crashes | Med | Pid file plus refuse-to-start (approved); message names the pid |

## Open Questions

- None. Spec open questions were resolved on approval.
