# Tasks: sensor

Plan: [tasks/plan.md](plan.md) · Spec: [SPEC-sensor.md](../SPEC-sensor.md)

Definition of done for every task: its tests pass, `uv run ruff check src tests`
and `uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor` are clean, and
`uv run pytest -m "not snort"` stays green and under 2 s per package. Tasks that touch
real Snort also pass `-m snort`.

## Task 1: States and policy

**Description:** The pure parts of supervision: the state enum, the legal-transition
table, and the restart policy. Add the `snorty.sensor` package and `tests/sensor`.

**Acceptance criteria:**
- [ ] `State` enum with exactly `STOPPED, STARTING, RUNNING, STOPPING, FAILED`
- [ ] `TRANSITIONS` equals the spec's table; `check_transition(old, new)` raises `IllegalTransition` for every pair not in it (tested over all 25 pairs)
- [ ] `backoff_delay(1..)` gives 2, 4, 8, 16, 32, 60, 60 (cap 60); `should_give_up(failures, max_restarts)` is true once `failures >= max_restarts`
- [ ] `SensorConfig` (frozen dataclass with the spec's defaults) and `IllegalTransition` exist

**Verification:**
- [ ] `uv run pytest tests/sensor -q`; ruff and mypy clean

**Dependencies:** none (alert-core and snort-adapter done)

**Files likely touched:** `src/snorty/sensor/{__init__,states,policy,config}.py`, `tests/sensor/test_states.py`, `tests/sensor/test_policy.py`; `pyproject.toml` (strict mypy for `snorty.sensor.*`)

**Estimated scope:** S

## Task 2: Tail reader

**Description:** Incremental reader for `alert.ids`: returns only complete new lines
and survives rotation. Riskiest pure code, so it comes early.

**Acceptance criteria:**
- [ ] `TailState(offset, pending)` frozen; `read_new_lines(path, state) -> (list[str], TailState)`
- [ ] Missing file → `([], state)` unchanged
- [ ] Partial last line is held in `pending` and returned once its newline arrives
- [ ] CRLF and LF endings both give clean lines; invalid UTF-8 bytes are replaced, never raise
- [ ] File shorter than `offset` (truncated/rotated) → re-read from 0 and `rotated` is reported (return a third value or a flag on the state)
- [ ] Reading twice with no new data returns no lines (no duplicates)

**Verification:**
- [ ] `uv run pytest tests/sensor/test_tail.py -q` (uses `tmp_path`)

**Dependencies:** Task 1 (package exists)

**Files likely touched:** `src/snorty/sensor/tail.py`, `tests/sensor/test_tail.py`

**Estimated scope:** M

## Task 3: Port, adapter, and stale-instance lookup

**Description:** The `SnortPort` Protocol the sensor depends on, its real implementation
over `snorty.snort`, and the new adapter function that checks whether a pid is a live
`snort.exe`.

**Acceptance criteria:**
- [ ] `snorty.snort.is_snort_running(pid, runner) -> bool` runs `tasklist /FI "PID eq N" /FO CSV /NH` through the Runner; true only if the CSV row's image name is `snort.exe`; any other output or a `SnortError` → false
- [ ] `SnortPort` Protocol: `list_interfaces`, `start`, `stop`, `local_ip`, `is_snort_running`
- [ ] `SnortAdapter(paths, runner)` implements it by calling `snorty.snort` functions
- [ ] Unit tests with a fake runner for `is_snort_running` (running, other image, no task, error); `SnortAdapter` delegates correctly (checked with monkeypatched/fake runner)
- [ ] `@pytest.mark.snort`: `is_snort_running(os.getpid())` is false; a real started Snort's pid is true

**Verification:**
- [ ] `uv run pytest tests/snort tests/sensor -q` and `-m snort -k running`

**Dependencies:** Task 1

**Files likely touched:** `src/snorty/snort/{commands,service,__init__}.py`, `src/snorty/sensor/port.py`, `tests/snort/test_running.py`, `tests/sensor/test_port.py`

**Estimated scope:** M

## Checkpoint A: after Tasks 1–3
- [ ] All unit tests green; ruff and strict mypy clean on core, snort, sensor

## Task 4: Sensor lifecycle

**Description:** The `Sensor` class: state, `start`, `stop`, `status`, events, interface
choice, pid file, stale-instance refusal. No tailing and no restarts yet.

**Acceptance criteria:**
- [ ] `Sensor(config, port, repo, bus, *, clock, sleep, tz, select_interface=None)`; `state` and `status()` (frozen `SensorStatus`) work
- [ ] `start()` from STOPPED: STARTING → RUNNING, publishing `SensorStateChanged` for each step with reason; calling it again while STARTING/RUNNING starts no second process (FakePort counts starts)
- [ ] `stop()` from RUNNING: STOPPING → STOPPED; idempotent; works from FAILED (→ STOPPED) and during STARTING
- [ ] Interface choice: `config.interface_ip` first, else `port.local_ip()`; no match → FAILED with `no interface has IP x.x.x.x` and nothing started; `select_interface` overrides
- [ ] Pid file `<log_dir>/snorty-sensor.pid` written on start, removed on clean stop; a pid file naming a live Snort (`port.is_snort_running`) → FAILED `Snort already running (pid N)`; a stale pid file (not running) is overwritten
- [ ] Any illegal transition attempt raises `IllegalTransition` (internal `_transition` is the only mutator)

**Verification:**
- [ ] `uv run pytest tests/sensor/test_sensor_lifecycle.py -q`

**Dependencies:** Tasks 1, 3

**Files likely touched:** `src/snorty/sensor/sensor.py`, `tests/sensor/fakes.py` (FakePort, fake clock), `tests/sensor/test_sensor_lifecycle.py`

**Estimated scope:** M

## Task 5: Ingest

**Description:** The tailer task: read new lines, parse, store, announce.

**Acceptance criteria:**
- [ ] While RUNNING the sensor polls `alert.ids` every `poll_interval` using `read_new_lines`
- [ ] Backlog lines (before the first end-of-file) are stored, `alerts_seen` not incremented for events, and **no** `AlertRaised` published; live lines are stored and published only if `repo.add` says the row is new
- [ ] A second `start()` over the same file adds no rows and publishes no events for old lines
- [ ] Unparseable lines increment `status().unparsed` and are logged, never raise
- [ ] Repository calls run via `asyncio.to_thread`; a test shows the event loop keeps ticking during a 5,000-line ingest
- [ ] `stop()` does a final tail pass after Snort has stopped, so a last alert is ingested
- [ ] `status().last_alert_ts` and `alerts_seen` update

**Verification:**
- [ ] `uv run pytest tests/sensor/test_sensor_ingest.py -q`

**Dependencies:** Tasks 2, 4

**Files likely touched:** `src/snorty/sensor/sensor.py`, `tests/sensor/test_sensor_ingest.py`

**Estimated scope:** M

## Task 6: Supervision

**Description:** Crash recovery, backoff, network-change restart and `restart()`.

**Acceptance criteria:**
- [ ] Snort exiting while RUNNING → STARTING with reason containing the exit code; waits `backoff_delay(n)` via injected `sleep` (2, 4, 8 …), then restarts; `status().restarts` counts
- [ ] `max_restarts` consecutive failures → FAILED; a run longer than `stable_after` (injected clock) resets the counter
- [ ] A start attempt that fails (port raises) retries with backoff while counted
- [ ] Network check every `network_check_interval`: `port.local_ip()` differs from bound interface IP → restart with reason `network changed`; not performed when `interface_ip` is set
- [ ] `restart()` = stop Snort and start again via the same path, state RUNNING → STARTING → RUNNING
- [ ] `stop()` during a backoff wait cancels the wait promptly and reaches STOPPED
- [ ] The tests above run with a fake clock and fake sleep: whole file under 1 s

**Verification:**
- [ ] `uv run pytest tests/sensor/test_sensor_supervision.py -q`

**Dependencies:** Task 5

**Files likely touched:** `src/snorty/sensor/sensor.py`, `tests/sensor/fakes.py`, `tests/sensor/test_sensor_supervision.py`

**Estimated scope:** M

## Checkpoint B: after Tasks 4–6
- [ ] Spec criteria 1–10 each covered by a passing test; `uv run pytest tests/sensor -m "not snort"` under 2 s

## Task 7: CLI and real-Snort tests

**Description:** The `python -m snorty.sensor` entry point and integration tests with
real Snort on loopback in temp dirs.

**Acceptance criteria:**
- [ ] CLI: `--db PATH` (default `snorty.db`), `--interface-ip IP`; builds the real adapter, repository, bus; prints a line per state change and per live alert; Ctrl+C → clean stop → exit 0
- [ ] `@pytest.mark.snort` test: temp log dir and DB, `select_interface` = loopback; `start()`; send `uid=0(root)` payload; an `AlertRaised` for sid 1000002 arrives and the row is in the repository; `stop()` → STOPPED
- [ ] `@pytest.mark.snort` crash test with short backoff: kill the pid from `status()`; sensor returns to RUNNING and still ingests a second payload
- [ ] Manual check recorded in the final summary: run the CLI, trigger an alert, Ctrl+C, confirm no `snort.exe` is left

**Verification:**
- [ ] `uv run pytest tests/sensor -q -m snort`
- [ ] Manual: `uv run python -m snorty.sensor --db <tmp>.db`

**Dependencies:** Task 6

**Files likely touched:** `src/snorty/sensor/__main__.py`, `src/snorty/sensor/__init__.py`, `tests/sensor/test_integration.py`

**Estimated scope:** M

## Checkpoint C: after Task 7
- [ ] Integration tests green on this PC

## Task 8: Quality gates

**Description:** Close coverage and typing gaps; verify containment; tick the spec.

**Acceptance criteria:**
- [ ] Coverage for `snorty.sensor` ≥ 90% from unit tests alone
- [ ] `grep -r subprocess src/snorty` still matches only `snort/runner.py` and `snort/service.py`
- [ ] `snorty.sensor` imports only `snorty.core` and `snorty.snort`
- [ ] SPEC-sensor.md Success Criteria boxes ticked

**Verification:**
- [ ] `uv run pytest tests/sensor -m "not snort" --cov=snorty.sensor --cov-report=term-missing`
- [ ] `uv run ruff check src tests`; `uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor`

**Dependencies:** Task 7

**Files likely touched:** tests for uncovered branches, `SPEC-sensor.md`

**Estimated scope:** S

## Checkpoint D: module complete
- [ ] All Success Criteria in SPEC-sensor.md checked
