# Implementation Plan: notify

Source spec: [SPEC-notify.md](../SPEC-notify.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)
Previous modules: alert-core, snort-adapter, sensor, rules, done (their plans and tasks are in git history, rules' last at `d614f46`).

## Overview

Build `snorty.notify`: an observer on the event bus that turns live priority-1 alerts into
Windows toasts, throttled per SID with a global cap, with all toast text sanitised. Pure
logic first (sanitise and build the toast, then the throttle), then the notifier port and
the one new dependency, then the service (filtering and throttling, then resilience and
shutdown), then the CLI, the `--notify` flag on the sensor CLI, and the manual real-toast
check.

## Architecture Decisions

- **Pure core, injected clock.** `Throttle.decide(sid, now)` returns a `Decision`; the service owns the clock, so every window and cap is tested with no waiting.
- **One consumer task, one subscription.** `start()` subscribes before returning (no missed event), `stop()` cancels the task and closes the subscription. A second `start()` is a no-op.
- **Sanitise at the boundary we own.** `build_toast` sanitises every field, so no adapter (including `winotify`) ever sees raw rule text. Task 3 reads `winotify`'s source to confirm what it does with the text.
- **Bounded everything.** Bus subscription is drop-oldest (maxsize 1000); the throttle holds at most 1,000 SIDs and drops expired entries.
- **Blocking toast call off the loop.** `WinotifyNotifier.show` runs `asyncio.to_thread` under `asyncio.wait_for` with a timeout. Failures and timeouts are logged and swallowed by the service, never raised out of the consumer.
- **`notify` imports only `snorty.core`** (plus stdlib and `winotify`). The sensor CLI composes the two; the `sensor` package does not import `notify`.
- **Dependency:** `winotify` added with `uv add`. Approved with the spec.
- Test module names are distinct from other test dirs (no `__init__.py` files): `notify_fakes.py`, `test_notify_cli.py`.

## Task List

### Phase 1: Pure logic
- [x] Task 1: `Toast`, `sanitize`, `build_toast`
- [x] Task 2: `Throttle` and `Decision`

### Checkpoint: Pure logic
- [x] All unit tests green; ruff and strict mypy clean on `snorty.notify`

### Phase 2: Port and service
- [x] Task 3: `Notifier` port, `ConsoleNotifier`, `WinotifyNotifier`, add `winotify`
- [x] Task 4: `NotifyService` (filter, throttle, build, show, counters)
- [x] Task 5: service resilience (notifier errors and timeouts, blocking notifier, stop, double start)

### Checkpoint: Service
- [x] Spec criteria 1-9 each covered by a passing test; unit suite under 3 s

### Phase 3: CLI and real checks
- [x] Task 6: `python -m snorty.notify test`, `--notify` on the sensor CLI
- [ ] Task 7: manual real toast and real `--notify` run, close-out

### Checkpoint: Complete
- [ ] Every Success Criteria box in SPEC-notify.md checked
- [ ] Then the next module spec (vault-journal or rule-lab)

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `winotify` injects text into a PowerShell script | High | Sanitise everything before it gets there; hostile-text tests; read the library source in Task 3 |
| Focus Assist or notification settings hide toasts | Med | Manual check in Task 7 reports what happened; documented as a system setting |
| Toast storm from many different SIDs | Med | Global cap with `+M other alerts` tally |
| Blocking PowerShell call stalls the consumer | Med | `to_thread` plus timeout; bus is drop-oldest so the sensor never waits |
| Library unmaintained or changes API | Low | It sits behind the `Notifier` Protocol; swapping it touches one class |

## Open Questions

None blocking. Defaults taken: 5 minutes per SID, 6 toasts per minute, priority 1 only.
