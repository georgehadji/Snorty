# Implementation Plan: dashboard

Source spec: [SPEC-dashboard.md](../SPEC-dashboard.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)
Previous modules: alert-core, snort-adapter, sensor, rules, notify, vault-journal, rule-lab, all done (their plans and tasks are in git history; rule-lab's last at `32519b3`). The rule-lab plan was finished (every box ticked, its "next module spec" box satisfied by SPEC-dashboard.md) before this file replaced it.

## Overview

Build `snorty.dashboard`: the one local web app that runs Snorty. Foundations first (dependencies, config, security checks, shared service wiring), then a walking skeleton (app, base page, Overview with sensor controls), then one vertical slice per page (Alerts, live SSE, Rules, scheduled update, Journal, Lab), then the CLI, real-Snort tests, the manual browser check and close-out.

## Architecture Decisions

- **Thin controllers over services.** `Services` frozen dataclass (sensor, rules, journal, lab, repo, bus, tz, data_dir) injected with `Depends(get_services)`; tests inject fakes. All logic stays in the module services; controllers parse, call, render.
- **Pure view-models.** `views.py` turns domain objects into plain dataclasses; templates only loop and print. Unit-tested without HTTP.
- **Composition once.** The wiring in `snorty.sensor.__main__.run` moves to `snorty/compose.py` (`compose(config) -> Services`-shaped parts) and both the sensor CLI and the dashboard use it. Sensor CLI tests must stay green unchanged.
- **Security shell as middleware.** Host allow-list (`127.0.0.1:<port>`, `localhost:<port>`), per-process token header on every non-GET, Origin check, CSP and other headers on every response. No inline scripts. Autoescape on, nothing marked safe.
- **SSE over the existing bus.** One `bus.subscribe()` per tab; drop-oldest `Subscription` already bounds memory; close on disconnect; 15 s heartbeat. The generator is a plain async function tested without a server.
- **Long jobs as in-flight guards.** Rules update, lab run, restart: one in-flight per kind, a second click gets "already running"; htmx polls a fragment until done.
- **Form parsing with stdlib.** `urllib.parse.parse_qs` on the raw body; no `python-multipart`. Config with `tomllib`; no `pydantic-settings`. Lab upload is a raw body capped at 50 MB.
- **Static assets local.** `htmx.min.js` vendored once (version pinned, SHA-256 recorded in the spec deviations); `app.css` and a few lines of `app.js`.
- **Deviation noted up front:** the spec says the dashboard uses the sensor's default db path; the sensor CLI defaults to `snorty.db` in the current folder, so the dashboard uses `<data-dir>\snorty.db` and `--data-dir` can point at an existing folder. Recorded in the spec's deviations at close-out.
- **Typing and tests.** `snorty.dashboard.*` and `snorty.compose` join the strict mypy override. Test basenames unique: `test_dash_views.py`, `_security`, `_config`, `_schedule`, `_routes`, `_sse`, `_lab`, `_real`, `dash_fakes.py`. `httpx` and the TestClient are dev-only.
- **Dependencies:** `fastapi`, `uvicorn`, `jinja2` runtime; `httpx` dev (approved with the spec). Nothing else.

## Task List

### Phase 1: Foundations
- [x] Task 1: dependencies, package, `config.py` (tomllib, defaults, CLI override)
- [x] Task 2: `security.py` (validators, Host/Origin/token, headers) as pure functions plus middleware
- [x] Task 3: shared `compose.py`, `Services`, sensor CLI moved onto it

### Checkpoint: Foundations
- [x] Full unit suite green (sensor CLI included); ruff and strict mypy clean

### Phase 2: Skeleton and first pages
- [x] Task 4: `build_app`, base template, vendored htmx, `/healthz`, Overview with sensor card and Start/Stop/Restart
- [x] Task 5: Alerts page, rows fragment, filters, paging, hostile-text escaping
- [x] Task 6: live SSE (`/events`) for alert, sensor and rules fragments

### Checkpoint: Live view
- [x] Spec criteria 1-6 covered by passing tests; page works in the browser pane against fake services

### Phase 3: Remaining slices
- [x] Task 7: Rules page (status, update now, mute/unmute, HOME_NET) with in-flight guard; Alerts-row Mute button
- [x] Task 8: daily rules-update schedule
- [x] Task 9: Journal page (small read-only `status()` on journal and notify services)
- [ ] Task 10: Lab page (check, run, pcap list, upload, generate)

### Checkpoint: All pages
- [ ] Spec criteria 1-12 covered by passing tests; unit suite still fast

### Phase 4: Run and close out
- [ ] Task 11: `python -m snorty.dashboard` CLI, logging, shutdown; real Snort tests
- [ ] Task 12: manual browser check, spec amendment, final verification

### Checkpoint: Complete
- [ ] Every Success Criteria box in SPEC-dashboard.md checked
- [ ] All modules done; final summary to the user

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Another website drives the local dashboard (CSRF, DNS rebinding) | High | Loopback bind, Host and Origin checks, per-process token on non-GET, tests for each refusal |
| Third-party alert or rule text injects script into a page | High | Autoescape, nothing `|safe`, CSP without inline script; hostile-text tests on every page |
| Lab upload or name reaches outside the pcaps folder | High | Name regex, resolve-and-confine check, size cap, tests for `..`, absolute paths, junctions |
| Refactoring the sensor wiring breaks the sensor CLI | Med | Task 3 changes nothing else; sensor CLI tests run before and after |
| Sensor, rules update and lab run overlap | Med | Each service already locks; dashboard adds an in-flight guard; two-click tests |
| SSE tab leak or memory growth | Med | Close subscription in `finally`; drop-oldest bound; disconnect test |
| Scheduler double-fires or dies on a failed update | Med | Injected clock and sleep, per-day marker, try/except around the update; unit tests |
| New dependencies bring surprises | Low | Only three runtime packages, pinned by `uv.lock`; no CDN; htmx hash recorded |
| htmx download unavailable | Low | Fall back to ~60 lines of own JS (spec Q2 alternative), noted as a deviation |
| Windows event-loop quirks with uvicorn plus subprocesses | Med | Real test in Task 11 starts Snort through the dashboard; fix in `compose`/`__main__` only |

## Open Questions

None blocking. Defaults taken (approved): add `fastapi`, `uvicorn`, `jinja2`, dev `httpx`; vendor htmx; sensor starts only on the Start button; rules update daily at 03:00 local while the dashboard runs; port 8765.
