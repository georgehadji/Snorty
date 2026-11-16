# Tasks: dashboard

Plan: [plan.md](plan.md) · Spec: [SPEC-dashboard.md](../SPEC-dashboard.md)
Order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12. Each task is one TDD cycle and one commit.

## Task 1: dependencies, package, config (S)
`pyproject.toml`, `src/snorty/dashboard/__init__.py`, `config.py`, `tests/dashboard/test_dash_config.py`.
- [x] `uv add fastapi uvicorn jinja2` and `uv add --dev httpx`; add `snorty.dashboard.*` and `snorty.compose` to the strict mypy override; `uv.lock` updated
- [x] `DashConfig` frozen dataclass: `port=8765`, `interface_ip=None`, `vault=None`, `notify=True`, `journal=True`, `autostart_sensor=False`, `rules_update_at="03:00"`, `data_dir=%LOCALAPPDATA%\Snorty`
- [x] `load_config(data_dir, overrides) -> DashConfig` reads `snorty.toml` with `tomllib`; missing file gives defaults; unknown key, wrong type, port out of range, bad `HH:MM` give a clear `ConfigError`; empty `rules_update_at` disables; overrides win
- [x] Verify: `uv run pytest tests/dashboard/test_dash_config.py -q`; `uv run ruff check src tests`
- Dependencies: none · Files: `pyproject.toml`, `uv.lock`, `config.py`, test

## Task 2: security (M)
`security.py`, `tests/dashboard/test_dash_security.py`.
- [x] Pure validators raising `ValueError` with a user-safe message: `valid_sid`, `valid_priority` (1-3), `valid_range` (1h/24h/7d/all), `valid_pcap_name` (`[A-Za-z0-9._-]{1,64}`, ends `.pcap`, no leading dot), `parse_form(body: bytes) -> dict[str, str]` (`parse_qs`, size cap, one value per key)
- [x] `host_allowed(host, port)`, `origin_allowed(origin, host)`, `token_ok(given, expected)` (constant-time compare); `new_token()` random 32 bytes hex
- [x] ASGI middleware class: 400 on bad Host; 403 on non-GET without the token or with a foreign Origin; `GET /healthz` token-exempt; adds CSP (`default-src 'self'; frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` to every response, errors included
- [x] Verify: `uv run pytest tests/dashboard/test_dash_security.py -q`
- Dependencies: Task 1 · Files: `security.py`, test

## Task 3: shared wiring and Services (M)
`src/snorty/compose.py`, `src/snorty/dashboard/services.py`, `src/snorty/sensor/__main__.py`, `tests/dashboard/dash_fakes.py`.
- [x] `compose(...)` builds bus, repository, sensor, rules service, notify (optional), journal (optional), lab service and returns a `Runtime` with start/stop. Deviation: the sensor CLI is NOT moved onto it (its tests patch names inside `sensor/__main__.py`); sensor CLI left unchanged
- [x] `Services` frozen dataclass (`sensor`, `rules`, `journal`, `lab`, `repo`, `bus`, `tz`, `data_dir`, `pcap_dir`) and `get_services` dependency
- [x] `dash_fakes.py`: fake sensor (status, start/stop/restart recording), rules, journal, lab with scripted results, in-memory repo helpers
- [x] Verify: `uv run pytest -q -m "not snort"` (all earlier tests unchanged and green); mypy strict clean
- Dependencies: Task 1 · Files: `compose.py`, `services.py`, `sensor/__main__.py`, `dash_fakes.py`

### Checkpoint: Tasks 1-3
- [x] Unit suite green; `uv run ruff check src tests`; mypy on all strict modules clean; sensor CLI test file passes without edits

## Task 4: app skeleton and Overview (L)
`app.py`, `views.py`, `templates/base.html`, `overview.html`, `_sensor_card.html`, `static/htmx.min.js`, `static/app.css`, tests `test_dash_views.py`, `test_dash_routes.py`.
- [x] `build_app(services, *, token, port) -> FastAPI`: security middleware, Jinja2 env (autoescape on), static mount, `GET /healthz`, `GET /`, `POST /sensor/start|stop|restart`
- [x] htmx downloaded once from its official release, version pinned, SHA-256 recorded in a comment file `static/htmx.VERSION`; token set once on `<body hx-headers>`
- [x] `views.sensor_card(status)`: state, since, restarts, last error, which buttons are enabled per state (no `IllegalTransition` path reachable from the UI)
- [x] Overview: sensor card, counts last hour and today, top 5 rules today, last 10 alerts, placeholders for rules and journal summary
- [x] Tests: page 200 with content; each POST calls the service once; disabled buttons per state; missing token 403; bad Host 400
- [x] Verify: `uv run pytest tests/dashboard -q`
- Dependencies: Tasks 2, 3 · Files: about 8 (templates and static count as one group), tests

## Task 5: Alerts page (M)
`templates/alerts.html`, `_alert_rows.html`, `views.py`, `app.py`, `test_dash_routes.py`.
- [x] `GET /alerts` and `GET /alerts/rows` with `sid`, `priority`, `range`, `page`; results match `AlertRepository.query` (page size 50, offset); invalid values give 422 with an inline message
- [x] Rows show local time `YYYY-MM-DD HH:MM:SS`, priority badge, message, src and dst, sid; each row has a Mute button slot (wired in Task 7)
- [x] Hostile text (`<script>`, quotes, 10 000-char message, non-ASCII) is escaped or truncated with the full text in a `title`
- [x] Verify: `uv run pytest tests/dashboard/test_dash_routes.py -q`
- Dependencies: Task 4 · Files: 4-5

## Task 6: live SSE (M)
`sse.py` (or in `app.py`), `static/app.js`, `test_dash_sse.py`.
- [x] `GET /events`: one `bus.subscribe()` per client; `AlertRaised` renders a row fragment, `SensorStateChanged` renders the sensor card, `RulesUpdated` the rules card; 15 s comment heartbeat; subscription closed in `finally` on disconnect
- [x] `app.js` (CSP-clean, external file): EventSource that prepends rows to the Alerts table (cap 200 rows) and swaps cards by id; reconnects on drop
- [x] Tests on the async generator directly: publish gives fragment; disconnect closes the subscription; slow consumer keeps only the newest N and memory stays bounded; heartbeat with injected sleep
- [x] Verify: `uv run pytest tests/dashboard/test_dash_sse.py -q`
- Dependencies: Tasks 4, 5 · Files: 3-4

### Checkpoint: Tasks 4-6
- [x] Criteria 1-6 covered by tests; unit suite green; open the app against fakes in the built-in browser pane and see the Overview and Alerts pages render (screenshot, no console errors)

## Task 7: Rules page and Mute (M)
`templates/rules.html`, `_rules_card.html`, `views.py`, `app.py`, tests.
- [x] `GET /rules`: last update, rule count, last error, muted list with Unmute, HOME_NET with form
- [x] `POST /rules/update` (`force` checkbox): returns a running fragment at once and polls until done; a second click while running returns "already running" and calls the service once
- [x] `POST /rules/mute/{sid}`, `/unmute/{sid}`, `POST /rules/home-net` (set or reset): show the `EditReport` including whether Snort restarted; bad sid or bad HOME_NET gives an inline message; Mute button on Alerts rows works
- [x] Verify: `uv run pytest tests/dashboard -q`
- Dependencies: Tasks 4, 5 · Files: 4-5

## Task 8: daily rules update (S)
`schedule.py`, `test_dash_schedule.py`.
- [x] `run_daily(update, at, *, now, sleep)` fires once per local day at `HH:MM`; disabled when empty; never twice the same day (restart of the loop included); a failing update is logged and the loop continues; cancel exits cleanly
- [x] Verify: `uv run pytest tests/dashboard/test_dash_schedule.py -q`
- Dependencies: Task 1 · Files: `schedule.py`, test

## Task 9: Journal page (S)
`templates/journal.html`, small `status()` on `JournalService` and `NotifyService`, tests.
- [x] `JournalService.status()` returns frozen `JournalStatus(vault, last_flush, notes_written, error)`; `NotifyService.status()` returns on/off and toast count; both with tests in their own module test folders
- [x] `GET /journal` shows vault path (read-only) and state; `POST /journal/flush` calls flush once and shows the result; the Overview journal summary uses the same data
- [x] Verify: `uv run pytest tests/journal tests/notify tests/dashboard -q`
- Dependencies: Task 4 · Files: about 5

## Task 10: Lab page (L)
`templates/lab.html`, `_lab_result.html`, `views.py`, `app.py`, `pcaps.py`, `test_dash_lab.py`.
- [x] `pcaps.py`: `list_pcaps(dir)`, `save_pcap(dir, name, data)` (name regex, resolved path must stay inside `dir`, junction and symlink refused, 50 MB cap, atomic write), `generate_pcap(dir, name, params)` using `make_frames` and `build_pcap`
- [x] `GET /lab`: textarea, pcap picker (names only), Check and Run buttons, generator form, upload control
- [x] `POST /lab/check`, `/lab/run`: text capped at 64 KB; problems shown as "rule line N: ..."; hits table with zero-hit rules; matches list; running guard
- [x] `POST /lab/pcaps?name=` raw upload; `POST /lab/pcaps/generate`; refusals for `..`, absolute names, over 50 MB, wrong extension
- [x] Verify: `uv run pytest tests/dashboard/test_dash_lab.py -q`
- Dependencies: Task 4 · Files: 5

### Checkpoint: Tasks 7-10
- [x] Criteria 1-12 covered; full unit suite green and under 15 s; ruff and strict mypy clean

## Task 11: CLI and real tests (L)
`__main__.py`, logging setup, `tests/dashboard/test_dash_real.py` (marker `snort`), `test_dash_cli.py`.
- [ ] `python -m snorty.dashboard [--port --start-sensor --no-notify --no-journal --vault --interface-ip --data-dir]`: loads config, composes services, starts bus consumers, schedule task and `uvicorn` on `127.0.0.1` only; Ctrl+C stops sensor, journal, notify, schedule cleanly and closes the repo; exit codes 0, 1 (port in use or sensor failed), 2 (usage)
- [ ] Rotating `snorty.log` in the data folder; token never logged; startup prints the URL
- [ ] CLI tests with fake services (flag parsing, exit codes, shutdown order, a bind address other than loopback refused)
- [ ] Real: temp data dir, real services, Start, wait RUNNING, the sensor integration test's attack traffic, alert visible via `/alerts/rows`, Stop; a lab run through HTTP matches the lab result; hashes of live `snort.conf`, `rules\`, `threshold.conf` unchanged; no `snort.exe` left
- [ ] Verify: `uv run pytest tests/dashboard -q -m "not snort"`; `uv run pytest tests/dashboard -q -m snort`
- Dependencies: Tasks 1-10 · Files: about 5

## Task 12: manual check and close-out (M)
- [ ] Manual in the built-in browser pane: run the dashboard, open every page, press Start, generate traffic, watch a row appear live, mute it, update rules, run a lab rule with a generated pcap; check light and dark, phone width; network log shows no third-party request; I report with screenshots
- [ ] Coverage for `snorty.dashboard` at least 85% from unit tests alone (json report, read then delete)
- [ ] `grep -r subprocess src/snorty` matches only `snort/` files; no inline `<script>` in templates; existing module CLIs' tests pass
- [ ] SPEC-dashboard.md amended (deviations: db path under data dir, `compose.py`, status additions, htmx version and hash, anything found in real runs) and every Success Criteria box ticked; plan and todo boxes ticked
- [ ] Verify: `uv run pytest -q -m "not snort"`; `uv run pytest -q -m snort`; `uv run ruff check src tests`; `uv run mypy` on all strict modules
- Dependencies: Task 11 · Files: spec, plan, todo
