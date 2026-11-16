# Spec: sensor — V1

Status: approved 2026-11-16. Open questions resolved as proposed: (1) refuse to start when a stale Snort is running; (2) keep the network-change restart; (3) backlog is stored silently.
Module of: [CAPABILITY-MAP.md](CAPABILITY-MAP.md) · Depends on: [alert-core](SPEC-alert-core.md), [snort-adapter](SPEC-snort-adapter.md) · Used by: rules, notify, vault-journal, dashboard

## Objective

Keep Snort running and turn its output into Snorty events. The sensor:

1. picks the network interface (the one with the PC's real IP, or a configured override);
2. starts Snort through the adapter and stops it cleanly;
3. restarts Snort if it dies (with backoff), or if the PC changes network;
4. tails `alert.ids`, parses new lines, stores them, and publishes `AlertRaised`;
5. publishes `SensorStateChanged` for every state change;
6. exposes `start / stop / restart / status` for the dashboard and CLI.

It never runs a subprocess itself (that is `snorty.snort`) and never parses text itself (that is `snorty.core.parser`).

### Acceptance criteria

1. **States.** Exactly five: `STOPPED, STARTING, RUNNING, STOPPING, FAILED`. Only the transitions in the table below are legal; anything else raises `IllegalTransition`. Every change publishes `SensorStateChanged(old, new, reason)`.
2. **Start.** `start()` from `STOPPED`/`FAILED` goes `STARTING` → picks the interface → `start_live` → `RUNNING`. Calling `start()` while `STARTING`/`RUNNING` does nothing (idempotent, no second Snort).
3. **Stop.** `stop()` goes `STOPPING` → `stop_live` (Ctrl+Break, kill only on timeout) → final tail pass (so alerts written just before the stop are ingested) → `STOPPED`. Idempotent.
4. **Interface choice.** Order: `config.interface_ip` if set; else `find_local_ip()`; matched with `pick_interface`. No match → `FAILED("no interface has IP x.x.x.x")`, no Snort started.
5. **Tailing.** New lines in `alert.ids` are parsed and stored. Handles: file not there yet; a partial last line (held until its newline arrives); the file shrinking (rotation or truncation: restart from offset 0); CRLF endings. Unparseable lines are logged and counted (`status().unparsed`), never fatal.
6. **Backlog vs live.** Lines already in `alert.ids` when the sensor starts (the *backlog*) are stored silently: no `AlertRaised`. Lines that arrive after the first end-of-file are *live*. An `AlertRaised` is published only when the repository says the row is new, so a restart never re-announces old alerts.
7. **Crash recovery.** Snort exiting while `RUNNING` (not requested) → `STARTING` with the reason (exit code) and a wait of 2 s, 4 s, 8 s, … up to 60 s. After `max_restarts` (default 5) failures in a row → `FAILED`. A run that stays up 60 s resets the counter.
8. **Network change.** Every `network_check_interval` (default 30 s) the sensor compares `find_local_ip()` with the bound interface's IP; if they differ (Wi-Fi roam, Ethernet plugged in) it restarts onto the new interface with reason `"network changed"`. Not done when `interface_ip` is set.
9. **Status.** `status()` returns a frozen snapshot: state, reason, interface, pid, started_at, alerts_seen, last_alert_ts, unparsed, restarts, last_error. (Bus drops are per subscriber, `Subscription.dropped`; the bus keeps no aggregate, so the sensor does not report one.)
10. **Single instance.** `start()` refuses (→ `FAILED("Snort already running (pid N)")`) when the pid file `<log_dir>/snorty-sensor.pid` names a live `snort.exe`. The pid file is written on start and removed on a clean stop.
11. **CLI.** `uv run python -m snorty.sensor [--db PATH] [--interface-ip IP]` runs the sensor in the foreground, prints one line per state change and per live alert, and exits 0 on Ctrl+C after a clean stop.

### State table

| From | To | When |
|---|---|---|
| STOPPED | STARTING | `start()` |
| STARTING | RUNNING | Snort ready |
| STARTING | STARTING | start attempt failed, retry after backoff |
| STARTING | FAILED | no interface, stale instance, or `max_restarts` reached |
| STARTING | STOPPING | `stop()` during start |
| RUNNING | STARTING | Snort died, or network changed, or `restart()` |
| RUNNING | STOPPING | `stop()` |
| STOPPING | STOPPED | Snort stopped and tail drained |
| FAILED | STARTING | `start()` |
| FAILED | STOPPED | `stop()` |

## Design

**Paradigm: async object-oriented**, with a pure core inside it. The stateful part
(`Sensor`) is thin; the logic that decides things is plain functions tested without
asyncio or Snort:

- `states.py`: `State` enum, `TRANSITIONS`, `check_transition(old, new)`.
- `policy.py`: `backoff_delay(attempt)`, `should_give_up(failures, max_restarts)`.
- `tail.py`: `TailState`, `read_new_lines(path, state) -> (lines, state)` over bytes; pure given file contents.
- `sensor.py`: the `Sensor` class: one supervisor task, one tailer task, an `asyncio.Lock` around commands.

**Patterns:** State machine (table-driven), Supervisor (restart with backoff), Observer
(publishes on the core `EventBus`), Port/Adapter (`SnortPort` Protocol with the
`snorty.snort` functions behind it), Dependency Injection (port, repository, bus, clock,
interface selector are all constructor arguments).

**Concurrency rule:** the repository is synchronous, so every call goes through
`asyncio.to_thread`. Alerts are written in one `add_many`-style batch per tail pass.
Events are published from the event loop only.

## Types

```python
@dataclass(frozen=True, slots=True)
class SensorConfig:
    paths: SnortPaths = SnortPaths()
    interface_ip: str | None = None
    poll_interval: float = 0.5
    network_check_interval: float = 30.0
    max_restarts: int = 5
    stable_after: float = 60.0
    stop_timeout: float = 15.0

class SnortPort(Protocol):            # what the sensor needs from snorty.snort
    async def list_interfaces(self) -> list[Interface]: ...
    async def start(self, iface: Interface) -> LiveProcess: ...
    async def stop(self, proc: LiveProcess, timeout: float) -> StopResult: ...
    def local_ip(self) -> str | None: ...

@dataclass(frozen=True, slots=True)
class SensorStatus: ...               # fields listed in acceptance criterion 9
class IllegalTransition(Exception): ...
```

`Sensor(config, port, repo, bus, *, clock, tz, select_interface=None)`: the optional
`select_interface(list[Interface]) -> Interface | None` replaces criterion 4's default
choice; tests use it to pick the loopback adapter.

## Tech Stack

Python 3.12+, stdlib only (`asyncio`, `logging`, `argparse`, `os`). Uses `snorty.core`
and `snorty.snort`. No new dependency (no file-watcher library: polling every 0.5 s is
enough for one file).

## Commands

```
Unit tests:        uv run pytest tests/sensor -q -m "not snort"
Integration tests: uv run pytest tests/sensor -q -m snort
Types:             uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor
Run:               uv run python -m snorty.sensor --db snorty.db
```

## Project Structure

```
src/snorty/sensor/
  __init__.py      public API
  states.py        State, TRANSITIONS, check_transition, IllegalTransition
  policy.py        backoff_delay, should_give_up
  tail.py          TailState, read_new_lines
  port.py          SnortPort Protocol, SnortAdapter (wraps snorty.snort)
  sensor.py        Sensor, SensorConfig, SensorStatus
  __main__.py      CLI entry point
tests/sensor/      mirrors the above; test_integration.py is @pytest.mark.snort
```

Dependency rule: `snorty.sensor` imports `snorty.core` and `snorty.snort` only.

## Code Style

```python
def backoff_delay(attempt: int, *, base: float = 2.0, cap: float = 60.0) -> float:
    """Seconds to wait before restart number `attempt` (1-based): 2, 4, 8 ... cap."""
    return min(cap, base * 2 ** (attempt - 1))


TRANSITIONS: dict[State, frozenset[State]] = {
    State.STOPPED: frozenset({State.STARTING}),
    State.STARTING: frozenset({State.RUNNING, State.STARTING, State.FAILED, State.STOPPING}),
    ...
}
```

Same conventions as before (frozen slotted dataclasses, full hints, ruff, strict mypy).
Logging with `logging.getLogger("snorty.sensor")`; never `print` outside `__main__`.

## Testing Strategy

- **Pure unit tests (ms):** transition table (every legal and a sample of illegal pairs); `backoff_delay`; `should_give_up`; `read_new_lines` for: missing file, partial line, CRLF, appended data, shrink, unicode junk.
- **Sensor with a fake port and fake clock (no Snort):** start → RUNNING; idempotent start/stop; no-interface → FAILED; crash → restart with backoff (clock injected, sleeps replaced by a fake); give-up after N; stable run resets the counter; network change restarts; backlog silent, live announced, restart does not re-announce; unparseable line counted; stale pid file refuses; events carry correct `old/new/reason`.
- **Integration (`@pytest.mark.snort`):** real Snort on loopback in a temp log dir: `start()` → send a `uid=0(root)` payload → `AlertRaised` arrives, row in a temp repository → `stop()` → `STOPPED`; and a crash test: kill the Snort pid, expect a restart and `RUNNING` again.
- Coverage ≥ 90% for `snorty.sensor`; unit tests under 2 s.

## Boundaries

- **Always:** change state only through `_transition`; go through `snorty.snort` for every Snort action; wrap repository calls in `to_thread`; log every state change.
- **Ask first:** any new dependency; changing the `AlertRaised`/`SensorStateChanged` shapes (they belong to alert-core); killing processes other than the one we started.
- **Never:** publish `AlertRaised` for backlog lines; call `Process.kill()` as the normal stop path; write to the log dir of anything but our own `alert.ids`/`snort.out`/pid file; block the event loop on file or database I/O.

## Success Criteria

- [x] `uv run pytest tests/sensor -m "not snort"` passes in under 2 s.
- [x] `uv run pytest tests/sensor -m snort` passes on this PC (live alert, clean stop, crash restart).
- [x] `uv run python -m snorty.sensor` on this PC reaches RUNNING, stores a triggered alert in the SQLite file, and exits 0 on Ctrl+C with Snort gone from Task Manager.
- [x] Restarting the sensor over an existing `alert.ids` creates no duplicate rows and no `AlertRaised` for old lines.
- [x] `ruff check`, `mypy src/snorty/core src/snorty/snort src/snorty/sensor` clean; coverage ≥ 90%.

## Out of Scope (Deferred)

- Retention (`prune`) scheduling: the app shell (dashboard module) runs it with the other timed jobs.
- Rewriting `HOME_NET` or rules: `rules` module.
- Several simultaneous Snort processes or interfaces.
- Windows service / autostart at logon.
- Adopting an already-running Snort instead of refusing (see Open Questions).
- Reading `snorty.toml`: the app shell builds `SensorConfig` from it.

## Open Questions

1. **Stale Snort after a crash.** If Snorty dies, its Snort child can keep running and holds the capture. Proposed V1: refuse to start and say which pid to stop (criterion 10). Alternative: the sensor stops that stale `snort.exe` itself (needs a new adapter call and a kill of a process we did not just start, which falls under "ask first"). Refuse, or stop it automatically?
2. **Network-change restart (criterion 8).** On a laptop this restarts Snort (about 8 s gap) every time Wi-Fi roams or Ethernet is plugged in. Keep it, or leave interface changes to a manual restart in V1?
3. **Silent backlog (criterion 6).** On the very first run the existing `alert.ids` (12 lines now) is stored without notifications. OK, or do you want old alerts from the last N minutes announced?
