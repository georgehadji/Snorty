# Spec: alert-core — V1

Status: approved 2026-11-16
Module of: [CAPABILITY-MAP.md](CAPABILITY-MAP.md) · Depends on: nothing · Used by: every other module

## Objective

The domain core of Snorty: the data types every module shares, the parser that
turns Snort `alert_fast` lines into those types, the in-process event bus, and
the SQLite store for alerts. No subprocesses, no network, no Snort install
needed: everything here is testable in milliseconds.

This spec also fixes the project-wide layout, commands and code style that the
later module specs inherit.

### Acceptance criteria

1. **Parse** every line format Snort 2.9 `alert_fast` produces on this machine
   into an immutable `Alert`:
   - with or without the year in the timestamp (`11/15-23:30:13.875248` and
     `11/15/26-23:30:13.875248`; the sensor will run Snort with `-y`);
   - with or without `[Classification: ...]`;
   - TCP/UDP with ports, ICMP without ports;
   - IPv4 (`192.168.1.1:443`) and Snort's expanded IPv6 form
     (`2606:50c0:8002:0000:0000:0000:0000:0215:443`, where the 9th group is the port).
   A line that matches none of these returns `None`; it never raises.
2. **Event bus**: any number of async subscribers each get every event
   published after they subscribe, in order. A slow subscriber can never
   block the publisher: each subscriber has a bounded queue (default 1000);
   on overflow the oldest event is dropped and a per-subscriber drop counter
   increases.
3. **Repository** (SQLite, WAL mode):
   - `add` is idempotent: storing the same alert line twice keeps one row
     (re-reading `alert.ids` after a restart must not create duplicates);
   - query by time range, SID, minimum priority (1 = most severe), with limit/offset,
     newest first;
   - counts per SID and per hour for a time range (dashboard charts);
   - `prune(before)` deletes old rows (retention, default 90 days, set in config).
4. **Suppression** value object renders the exact `threshold.conf` line Snort 2.9
   accepts: `suppress gen_id 1, sig_id 2010935` and
   `suppress gen_id 1, sig_id 2010935, track by_src, ip 1.2.3.4`.

## Domain types

```python
@dataclass(frozen=True, slots=True)
class Alert:
    ts: datetime            # timezone-aware, local zone of this PC
    gid: int
    sid: int
    rev: int
    msg: str
    classification: str | None
    priority: int           # 1 = highest
    proto: str              # "TCP", "UDP", "ICMP", ...
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    raw: str                # original line, the idempotency key

@dataclass(frozen=True, slots=True)
class Suppression:
    gid: int
    sid: int
    track: Literal["by_src", "by_dst"] | None = None
    ip: str | None = None   # required when track is set

# Events (all frozen dataclasses, published on the bus)
AlertRaised(alert: Alert)
SensorStateChanged(old: str, new: str, reason: str | None)
RulesUpdated(ok: bool, rule_count: int, detail: str)
```

`SensorStateChanged` uses plain strings so this module does not depend on the
sensor's state enum.

## Tech Stack

- Python 3.12, stdlib only for this module (`dataclasses`, `re`, `sqlite3`, `asyncio`, `datetime`, `zoneinfo`).
- Project tooling: uv 0.13, pytest 8, pytest-asyncio, ruff (lint + format), mypy (strict on `src/snorty/core`).
  ruff and mypy are new dev dependencies proposed here; approving this spec approves them.

## Commands

Run from `C:\Users\tesse\Documents\Vibe Coding\Snorty`:

```
Install:  uv sync
Test:     uv run pytest
Core only: uv run pytest tests/core -q
Coverage: uv run pytest tests/core --cov=snorty.core --cov-report=term-missing
Lint:     uv run ruff check src tests
Format:   uv run ruff format src tests
Types:    uv run mypy src/snorty/core
```

(`pytest-cov` is included with the test dependencies.)

## Project Structure

Whole project, so later specs slot in without moving files:

```
Snorty/
  CAPABILITY-MAP.md, SPEC-*.md
  pyproject.toml            uv project, deps, ruff/mypy/pytest config
  snorty.example.toml       sample config (real snorty.toml is git-ignored)
  src/snorty/
    core/                   ← this spec
      models.py             Alert, Suppression
      events.py             AlertRaised, SensorStateChanged, RulesUpdated
      parser.py             parse_line()
      bus.py                EventBus
      repository.py         AlertRepository (SQLite)
    snort/                  snort-adapter
    sensor/                 sensor
    rules/                  rules
    notify/                 notify
    journal/                vault-journal
    lab/                    rule-lab
    web/                    dashboard (FastAPI app, templates/, static/)
  tests/
    core/                   mirrors src/snorty/core
    fixtures/               real alert_fast lines, sample configs
```

Dependency rule (checked in review): `snorty.core` imports nothing from other
`snorty` packages. Other packages may import `snorty.core`.

## Code Style

```python
_FAST = re.compile(
    r"^(?P<ts>\S+)\s+\[\*\*\] \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] "
    r"(?P<msg>.*?) \[\*\*\]"
    r"(?: \[Classification: (?P<cls>[^\]]*)\])?"
    r" \[Priority: (?P<prio>\d+)\] \{(?P<proto>[^}]+)\} (?P<src>\S+) -> (?P<dst>\S+)$"
)


def parse_line(line: str, *, default_year: int, tz: tzinfo) -> Alert | None:
    """Parse one alert_fast line. Returns None for anything unrecognised."""
    m = _FAST.match(line.rstrip("\r\n"))
    if m is None:
        return None
    ts = _parse_ts(m["ts"], default_year, tz)
    src_ip, src_port = _split_endpoint(m["src"])
    dst_ip, dst_port = _split_endpoint(m["dst"])
    if ts is None or src_ip is None or dst_ip is None:
        return None
    return Alert(ts=ts, gid=int(m["gid"]), sid=int(m["sid"]), ...)
```

- Pure functions take everything they need as arguments (`default_year`, `tz`):
  no clocks, globals or I/O inside `parser.py`, `models.py`, `events.py`.
- Frozen, slotted dataclasses for all domain values; no setters.
- Full type hints; `mypy --strict` clean for `snorty.core`.
- Names: modules and functions `snake_case`, classes `PascalCase`, private helpers `_leading_underscore`.
- ruff defaults plus `I` (import sort), `B` (bugbear), `UP` (pyupgrade); line length 100.
- Comments only for the why the code can't show (e.g. why the 9th IPv6 group is the port).

## Testing Strategy

- **Parser:** table-driven `pytest.mark.parametrize` over real lines saved in
  `tests/fixtures/alert_fast.txt`, including the lines captured on this machine
  on 2026-11-15, plus malformed lines (truncated, empty, random text) that must return `None`.
- **Suppression:** each rendering case checked against an exact expected string;
  `track` without `ip` raises `ValueError` at construction.
- **EventBus:** fan-out to 3 subscribers; ordering; overflow drops oldest and
  increments the counter; unsubscribing stops delivery; publisher never awaits a full queue.
- **Repository:** against a SQLite file in `tmp_path`: idempotent add, each
  query filter, counts per SID/hour, prune boundary (row exactly at `before` is kept).
- Coverage: ≥ 90% lines for `snorty.core`. All core tests together run in under 2 s.
- No `@pytest.mark.snort` tests in this module: nothing here needs Snort.

## Boundaries

- **Always:** keep `snorty.core` free of I/O except `repository.py`; run
  `pytest`, `ruff check` and `mypy` before calling a task done; add a fixture
  line for every parser bug found.
- **Ask first:** any new runtime dependency; changing the `Alert` fields or the
  SQLite schema once another module uses them.
- **Never:** import from other `snorty` packages; touch `C:\Snort` from this
  module; silently drop a field Snort provides.

## Success Criteria

- [ ] `uv sync` then `uv run pytest tests/core` passes on a clean checkout.
- [ ] Every line in `tests/fixtures/alert_fast.txt` parses to the expected `Alert`; every malformed fixture returns `None`.
- [ ] Parsing `C:\Snort\log\alert.ids` from this machine yields no `None` results (manual check script: `uv run python -m snorty.core.parser C:\Snort\log\alert.ids` prints parsed/failed counts).
- [ ] Storing the same 1,000 alerts twice leaves exactly 1,000 rows.
- [ ] A subscriber that never reads does not slow the publisher: publishing 10,000 events with one stalled subscriber finishes in under 1 s.
- [ ] `ruff check` and `mypy src/snorty/core` report no errors; coverage ≥ 90%.

## Out of Scope (Deferred)

- Reading unified2 binary output: `alert_fast` carries everything the V1 UI shows.
- Snort 3 `alert_json` parser: arrives with the deferred Snort 3 migration.
- GeoIP / reverse-DNS enrichment of IPs: needs an external database or network calls; revisit after the dashboard exists.
- Persisting events other than alerts (sensor state history): the dashboard shows current state only in V1.

## Open Questions

None blocking this module. The map's open questions (journal summary type,
autostart, lab pcaps) affect later modules only.
