# Tasks: notify

Plan: [plan.md](plan.md) · Spec: [SPEC-notify.md](../SPEC-notify.md)
Order: 1 → 2 → 3 → 4 → 5 → 6 → 7. Each task is one TDD cycle and one commit.

## Task 1: Toast, sanitize, build_toast (S)
`src/snorty/notify/toast.py`.
- [x] `Toast(title, lines)` frozen dataclass
- [x] `sanitize(text, limit)`: control characters and `" ' ` $ < > & ; | %` and backslash replaced by a space, whitespace collapsed, truncated to `limit`; non-ASCII letters kept
- [x] `build_toast(alert, same_sid=0, other=0, tz)` gives title `Snort P{priority}: {msg}` (cap 80); lines `{proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}` (ports omitted when missing), `SID {gid}:{sid}  {HH:MM:SS}` in the given zone, then `+{n} more` and `+{m} other alerts` only when non-zero; each line capped at 120
- [x] Hostile inputs in msg and addresses (`"; calc; "`, backticks, `$(...)`, `<b>`, newlines, 10,000 characters) produce sanitised, capped text
- [x] Verify: `uv run pytest tests/notify/test_toast.py -q`
- Dependencies: none · Files: `src/snorty/notify/__init__.py`, `toast.py`, `tests/notify/test_toast.py`

## Task 2: Throttle (S)
`src/snorty/notify/throttle.py`.
- [x] `Decision(show, same_sid, other)` frozen dataclass
- [x] `Throttle(window=300, cap=6, cap_window=60, max_sids=1000)`; `decide(sid, now)`:
  - SID shown less than `window` ago gives `show=False` and counts for that SID
  - else if `cap` toasts were shown in the last `cap_window` seconds gives `show=False` and counts in the "other" tally
  - else `show=True` with this SID's suppressed count and the "other" tally, then both reset
- [x] A suppressed alert never extends the window (the window runs from the last shown toast)
- [x] Expired SID entries are removed; at most `max_sids` kept, oldest dropped first (tested with 1,500 SIDs)
- [x] 500 alerts of one SID inside the window give one show; the next one after the window reports `same_sid == 499`
- [x] Verify: `uv run pytest tests/notify/test_throttle.py -q`
- Dependencies: none · Files: `throttle.py`, `tests/notify/test_throttle.py`

### Checkpoint: Tasks 1-2
- [x] Tests green; `uv run ruff check src tests`; `uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules src/snorty/notify` clean (add `snorty.notify.*` to the strict override in `pyproject.toml`)

## Task 3: Port and adapters, dependency (M)
`ports.py`; `pyproject.toml` via `uv add winotify`.
- [x] `Notifier` Protocol (`async show(toast)`)
- [x] `ConsoleNotifier(out=print)` prints title and lines
- [x] `WinotifyNotifier(app_id="Snorty", timeout=10.0, send=None)`: builds the library's `Notification` from a `Toast` and shows it in `asyncio.to_thread` under `asyncio.wait_for`; the library call is injectable (`send`) so tests never show a real toast
- [x] Read the installed `winotify` source and record in a code comment what it does with title and message text (script, XML, or escaping); if text is interpolated unescaped, the sanitiser already guards it and a test pins that no sanitised character class reaches the library
- [x] Unit tests: `send` called with the title and joined lines; timeout raises `TimeoutError`; library exception propagates (the service handles it in Task 5)
- [x] Verify: `uv run pytest tests/notify/test_ports.py -q`
- Dependencies: Task 1 · Files: `ports.py`, `pyproject.toml`, `uv.lock`, `tests/notify/test_ports.py`

## Task 4: NotifyService, filter and throttle (M)
`src/snorty/notify/service.py`: `NotifyConfig(min_priority=1, window=300, cap=6, cap_window=60, tz)`, `NotifyService(bus, notifier, config, *, clock)`.
- [x] `start()` subscribes (maxsize 1000) before returning and spawns one consumer task
- [x] Only `AlertRaised` events are considered; `alert.priority > min_priority` is ignored; changing `min_priority` changes the cut-off
- [x] A live priority-1 alert gives one toast through the notifier with the built text
- [x] Throttle integrated: 500 alerts of one SID give one toast, then `+499 more` after the window (fake clock); many SIDs hit the cap and the next toast says `+M other alerts`
- [x] Verify: `uv run pytest tests/notify/test_service.py -q` (real `EventBus`, `RecordingNotifier`, fake clock)
- Dependencies: Tasks 1-3 · Files: `service.py`, `tests/notify/notify_fakes.py`, `test_service.py`

## Task 5: Service resilience and lifecycle (M)
Same `service.py`; new tests in `tests/notify/test_service_resilience.py`.
- [x] A notifier that raises is logged; the next alert still gives a toast
- [x] A notifier that exceeds its timeout (raises `TimeoutError`) is logged; the next alert still gives a toast
- [x] A notifier that blocks forever does not slow `bus.publish` (1,000 publishes finish quickly) and the subscription queue drops oldest
- [x] `stop()` cancels the consumer, closes the subscription, and no toast is shown after it returns; `stop()` before `start()` and twice are harmless
- [x] `start()` twice does not double-subscribe (one toast per alert)
- [x] Verify: `uv run pytest tests/notify -q`
- Dependencies: Task 4 · Files: `service.py`, `test_service_resilience.py`

### Checkpoint: Tasks 3-5
- [x] Spec criteria 1-9 each covered by a passing test; whole notify unit suite under 3 s; ruff and strict mypy clean

## Task 6: CLI and sensor wiring (M)
`src/snorty/notify/__main__.py`; `src/snorty/sensor/__main__.py`.
- [x] `python -m snorty.notify test [--priority N] [--msg TEXT]` builds a sample alert and shows it through `WinotifyNotifier` (`--dry-run` uses `ConsoleNotifier`); exit 0, or 1 with the error if the toast failed
- [x] `python -m snorty.sensor --notify` creates a `NotifyService` on the same bus and starts it before the sensor, stops it after the sensor
- [x] `snorty.sensor` package modules (not `__main__`) do not import `snorty.notify` (grep-checked)
- [x] Unit tests with `--dry-run` and an injected notifier; the sensor CLI change is covered by a smoke test that builds the objects without starting Snort
- [x] Verify: `uv run pytest tests/notify tests/sensor -q -m "not snort"`
- Dependencies: Tasks 3-5 · Files: `notify/__main__.py`, `sensor/__main__.py`, `tests/notify/test_notify_cli.py`

## Task 7: Real checks and close-out (S)
- [x] Manual: `uv run python -m snorty.notify test` shows a toast on this PC (I report what appeared; Focus Assist state noted)
- [x] Manual: `uv run python -m snorty.sensor --notify --db <tmp>` runs, a loopback payload with `uid=0(root)` raises an alert and a toast, and a cancelled run leaves no `snort.exe` (same method as the sensor check)
- [x] Coverage for `snorty.notify` at least 90% from unit tests alone
- [x] `grep -r subprocess src/snorty` matches only `snort/` files; `snorty.notify` imports only `snorty.core`, stdlib and `winotify`
- [x] SPEC-notify.md Success Criteria boxes ticked; plan and todo boxes ticked except the "next module" one
- [x] Verify: `uv run pytest -q -m "not snort" --cov=snorty.notify`; `uv run ruff check src tests`; mypy as above
- Dependencies: Task 6
