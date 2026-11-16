# Spec: notify — V1

Module id: `notify` (from CAPABILITY-MAP.md). Depends on: alert-core (events, models).

## Objective

Show a Windows toast when a high-priority alert fires, without ever flooding the desktop.

- Subscribes to the in-process `EventBus` and reacts to live `AlertRaised` events (the sensor never announces backlog, so old alerts never toast).
- Priority 1 by default; threshold configurable.
- Throttled per SID, with a global cap, and suppressed alerts are counted into the next toast so nothing is silently lost.

User: the PC owner, who wants to know about serious alerts without watching a console. Success: one real attack gives one toast; 500 alerts from one noisy rule give one toast, then a "+499 more" summary later.

## Assumptions (correct me or I proceed)

1. Toasts go through `winotify` (the dependency the capability map proposed). It is the only new runtime dependency. Windows 11 Focus Assist / Do Not Disturb can still hide toasts; that is a system setting, not something Snorty overrides.
2. Muted rules never reach this module: Snort already suppresses them through `threshold.conf`.
3. Clicking a toast does nothing in V1 (the dashboard does not exist yet; click-through is deferred).
4. Everything stays local: toast text is shown on screen only and never sent anywhere.
5. `winotify` builds a PowerShell script around the toast text. Alert `msg` comes from third-party rule files, so this module sanitises all toast text itself instead of trusting the library to escape it.

## Architecture and patterns

- **Event-driven, Observer** over the bus; **Throttle/Debounce per SID** as the one non-trivial piece of logic.
- **Pure core:** `Throttle` (injected clock, returns a decision), `build_toast(alert, suppressed)` (alert to `Toast`), `sanitize(text)`. No I/O, so tests run in milliseconds.
- **Port:** `Notifier` Protocol, `async show(toast: Toast) -> None`. Real adapter `WinotifyNotifier` (runs the blocking call with `asyncio.to_thread` and a timeout). `RecordingNotifier` in tests; `ConsoleNotifier` for dry runs.
- **`NotifyService(bus, notifier, config, clock)`:** `start()` subscribes before it returns (no missed events) and spawns one consumer task; `stop()` cancels it and closes the subscription.
- Notifier errors and timeouts are logged and swallowed. One bad toast never stops later ones.
- The bus is drop-oldest, so a slow notifier can never slow the sensor.

## Behaviour

**Decision per `AlertRaised(alert)`**, in order:

1. `alert.priority > config.min_priority` (default 1): ignore.
2. Per-SID window (default 300 s): if this SID showed a toast less than a window ago, count it as suppressed for that SID and stop.
3. Global cap (default 6 toasts per rolling 60 s): if reached, count it in the "other" tally and stop.
4. Otherwise show a toast. Its text includes `+N more` (this SID's suppressed count since its last toast) and `+M other alerts` (global-cap tally), then both counters reset.

**Toast content:** title `Snort P1: <msg>`; body `<proto> <src_ip>:<src_port> -> <dst_ip>:<dst_port>`, then `SID <gid>:<sid>`, then the time `HH:MM:SS` local, then the `+N` lines when present. Missing ports are omitted.

**Sanitising:** every field is reduced to printable characters; quotes, backticks, `$`, `<`, `>`, `&`, `;`, `|`, `%` and control characters are replaced with a space; whitespace collapsed; title capped at 80 characters, body lines at 120.

**Bounded memory:** the per-SID table drops entries older than the window and holds at most 1,000 SIDs (oldest dropped first).

## Commands

```
Test:   uv run pytest tests/notify -q
Lint:   uv run ruff check src tests
Types:  uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules src/snorty/notify
CLI:    uv run python -m snorty.notify test [--priority N] [--msg TEXT]   # shows one real toast
        uv run python -m snorty.sensor --notify                         # sensor with toasts
```

`--notify` is composition only: the sensor CLI builds a `NotifyService` and starts it; the `sensor` package itself stays unaware of `notify`.

## Project structure

```
src/snorty/notify/
  toast.py      Toast dataclass, sanitize, build_toast (pure)
  throttle.py   Throttle, Decision (pure, injected clock)
  ports.py      Notifier Protocol, WinotifyNotifier, ConsoleNotifier
  service.py    NotifyConfig, NotifyService
  __main__.py   CLI (test command)
tests/notify/   test_toast, test_throttle, test_service, test_ports, test_cli
```

## Code style

Frozen dataclasses, `Protocol` ports, injected `clock`, strict mypy, ruff (E,F,I,B,UP, 100 cols). Pure decision function shape:

```python
@dataclass(frozen=True, slots=True)
class Decision:
    show: bool
    same_sid: int   # suppressed alerts for this SID since its last toast
    other: int      # alerts dropped by the global cap since the last toast

def decide(self, sid: int, now: float) -> Decision: ...
```

## Testing strategy

- Pure core: unit tests with a fake clock, including hostile text (`"; calc; "`, backticks, `$(...)`, XML, very long, control characters, non-ASCII).
- Service: real `EventBus`, `RecordingNotifier`, fake clock and sleep; assertions on toasts shown, counters and shutdown.
- `WinotifyNotifier`: unit test with the library call monkeypatched (timeout, exception); no real toast in automated tests.
- One manual check, recorded in the final summary: `python -m snorty.notify test` shows a toast on this PC.
- Coverage of `snorty.notify` at least 90% from unit tests alone.

## Boundaries

- **Always:** sanitise all toast text; log notifier failures; keep `publish` non-blocking.
- **Ask first:** the new dependency `winotify` (assumption 1); any click-through or launch URL; sounds or persistent notifications.
- **Never:** send alert data off the machine; run a subprocess from our own code (containment stays in `snort/`); raise out of the consumer task; toast backlog or non-priority-matching alerts.

## Success Criteria

- [ ] 1. A live priority-1 alert gives exactly one toast containing its message, protocol, addresses, ports and SID.
- [ ] 2. An alert with priority above `min_priority` gives no toast; changing `min_priority` changes the cut-off.
- [ ] 3. 500 alerts of one SID inside the window give one toast; the first alert after the window gives a toast with `+499 more`.
- [ ] 4. Alerts of many different SIDs never exceed the global cap per rolling 60 s; the dropped ones appear as `+M other alerts` on the next toast.
- [ ] 5. A notifier that raises or exceeds its timeout is logged; the next alert still produces a toast.
- [ ] 6. A notifier that blocks does not slow `bus.publish`; the consumer queue is bounded and drops oldest.
- [ ] 7. `stop()` cancels the consumer and closes the subscription; no toast is shown after it returns; `start()` twice does not double-subscribe.
- [ ] 8. Hostile alert text (shell and XML metacharacters, control characters, 10,000 characters) yields sanitised, length-capped toast text.
- [ ] 9. The throttle's tables stay bounded (1,000 SIDs, expired entries removed).
- [ ] 10. Manual: `python -m snorty.notify test` shows a toast on this PC; `python -m snorty.sensor --notify` runs and stops cleanly with no leftover `snort.exe`.
- [ ] 11. `ruff check`, strict mypy on `snorty.notify`, coverage at least 90%; `snorty.notify` imports only `snorty.core` and stdlib besides `winotify`; no `subprocess` in our `src/snorty` outside `snort/`.

## Out of Scope (Deferred)

- Click-through to the dashboard, action buttons ("Mute this rule"), sounds.
- Quiet hours and per-rule overrides.
- Email, phone, Slack or any off-machine notification.
- Per-network or per-IP throttling (only per-SID in V1).
- Toast history UI (the dashboard shows alerts).

## Open Questions

1. **Dependency:** approve adding `winotify`? The alternative is no toasts, or a PowerShell call from our own code, which would break the subprocess-containment rule.
2. **Throttle defaults:** 5 minutes per SID and 6 toasts per minute overall. Right for you, or tighter?
3. **Priority threshold:** priority 1 only (the map's choice). Snort ET rules rarely use 1; if you see too few toasts after a day, we can include priority 2.
