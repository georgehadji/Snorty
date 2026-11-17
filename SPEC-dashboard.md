# Spec: dashboard — V1

Module id: `dashboard` (package `snorty.dashboard`). Depends on: all other modules (`alert-core`, `snort-adapter`, `sensor`, `rules`, `notify`, `vault-journal`, `rule-lab`). Map: `CAPABILITY-MAP.md`.

## Objective

One local web page set that runs Snorty: start and stop the sensor, watch alerts arrive live, mute a noisy rule with one click, update rules, see the journal state, and try a rule against a pcap. Until now each module had only a CLI; the dashboard gives each its UI slice and becomes the single app process.

User: you, on this PC only. Success: you run `uv run python -m snorty.dashboard`, open `http://127.0.0.1:8765`, press Start, and see the sensor state change and new alerts appear in the timeline without reloading. You can mute an alert's rule from its row, update rules, and run the rule-lab from the browser. Nothing is reachable from another machine.

## Assumptions (correct me or I proceed)

1. **One process:** the dashboard is the composition root. It builds the bus, repository, sensor, notify, journal, rules and lab services exactly as `snorty.sensor.__main__.run` does, and serves the UI from the same asyncio loop. The existing module CLIs keep working unchanged.
2. **Local only:** binds `127.0.0.1`, default port 8765. No login (single user, loopback). Not exposed to the network; a different bind address is refused in V1.
3. **Stack (from the map):** FastAPI + uvicorn + Jinja2 templates, htmx for partial updates, Server-Sent Events for live alerts. No front-end build step, no SPA framework. New runtime dependencies: `fastapi`, `uvicorn`, `jinja2`. Dev: `httpx2` (Starlette's TestClient; it replaced `httpx`, which Starlette 1.10 deprecates). Not added: `pydantic-settings` (config is read with stdlib `tomllib`), `python-multipart` (form bodies are parsed with `urllib.parse.parse_qs`).
4. **htmx is vendored,** not loaded from a CDN: one file in `static/`, with its version and SHA-256 noted in the spec's deviations. The page makes no request to any third-party host.
5. **Config:** optional `snorty.toml` in the data folder (stdlib `tomllib`). Keys: `port`, `interface_ip`, `vault` (journal path), `notify` (bool), `journal` (bool), `autostart_sensor` (bool, default false), `rules_update_at` (`"HH:MM"` local, default `"03:00"`, empty string disables). Missing file means defaults. CLI flags override the file.
6. **The sensor does not start by itself** unless `autostart_sensor` is true or `--start-sensor` is given: you press Start. Closing the dashboard (Ctrl+C) stops the sensor cleanly, like the sensor CLI does today.
7. **Scheduling:** an asyncio task runs `RulesService.update()` once a day at `rules_update_at` while the dashboard is running. A missed time (PC off) is not caught up in V1. No Task Scheduler / autostart at logon in V1 (map open question 2: answered "launch it yourself" unless you say otherwise).
8. **Data folder:** `%LOCALAPPDATA%\Snorty` (database, `snorty.toml`, `pcaps\`, rotating `snorty.log`). Same db path the sensor CLI uses today; if that differs on disk, the dashboard reads the sensor's current default.
9. **Rule-lab pcaps** come from `data\pcaps\` only: you drop a file there, upload one in the page (raw body, 50 MB cap), or generate one with the page's form (the lab's `make_frames`/`build_pcap`). Names are sanitised; no path from the browser is ever opened directly.
10. **Pages (V1):** Overview, Alerts, Rules, Journal, Lab. English only, light and dark via `prefers-color-scheme`, usable at phone width but desktop-first.
11. Small additions to earlier modules are allowed where the UI needs them (e.g. a read-only `status()` on `JournalService` and `NotifyService`; `SensorStatus` already exists). Each is listed under "Built-in deviations" afterwards.

## Architecture and patterns

- **Declarative server-rendered UI (from the map):** Jinja2 templates render full pages; htmx swaps fragments (`hx-get`, `hx-post`, `hx-swap`). Pages work with JavaScript off for reading; live updates and buttons need it.
- **Facade per module:** `snorty.dashboard.services.Services` is a frozen dataclass holding the already-built application services and the repository (`sensor`, `rules`, `journal`, `lab`, `repo`, `bus`, `tz`, `data_dir`). Controllers take it through FastAPI `Depends(get_services)`; tests inject fakes. Controllers stay thin: parse input, call a service, render a template.
- **Composition root:** `snorty.dashboard.app.build_app(services, *, token) -> FastAPI` is pure wiring; `snorty.dashboard.__main__` builds the real `Services` (reusing the sensor CLI's wiring, factored into a shared `compose()` rather than copied) and runs `uvicorn`.
- **Pure view helpers:** `snorty.dashboard.views` has pure functions that turn domain objects into plain view-model dataclasses (`AlertRow`, `SensorCard`, `RulesCard`, `LabView`): priority badge class, time format, truncation, mute availability. Unit-tested without HTTP.
- **Live push (Observer):** `GET /events` is an SSE stream over one `bus.subscribe()` per browser tab. Events: `alert` (rendered table-row fragment), `sensor` (rendered status card), `rules` (rendered rules card). The existing drop-oldest `Subscription` bounds memory for a slow tab; the stream closes its subscription when the client disconnects. A comment heartbeat goes out every 15 s.
- **Long operations (Command):** rules update, lab run and restart are `POST`s that return at once with a "running" fragment where the work is more than ~1 s, and the page picks up the result (htmx polling `hx-trigger="every 1s"` on that fragment until done). One in-flight job per kind; a second request gets "already running". The lab keeps its own lock.
- **Security shell (middleware):** `Host` header must be `127.0.0.1:<port>` or `localhost:<port>` (blocks DNS rebinding); every non-GET request must carry the per-process random token in an `X-Snorty-Token` header (htmx adds it via `hx-headers` set once on `<body>`) and an `Origin` that matches the host if present (CSRF); responses carry `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. No inline scripts, so the CSP holds. Jinja2 autoescape is on; alert and rule text is third-party data and is never marked safe.

## Behaviour

**Routes**

| Route | Purpose |
|---|---|
| `GET /` | Overview: sensor card with Start / Stop / Restart, alert counts (last hour, today), top 5 rules today, last 10 alerts, rules and journal summary |
| `GET /alerts` | Table, newest first, filters `sid`, `priority` (1-3), `range` (1 h / 24 h / 7 d / all), paged 50 per page; each row has a Mute button |
| `GET /alerts/rows` | The table body fragment (for htmx filter and paging) |
| `GET /events` | SSE stream (above) |
| `POST /sensor/start`, `/stop`, `/restart` | Control the sensor; return the new sensor card |
| `GET /rules` | Rules status (last update, count, error), muted list with Unmute, HOME_NET with a form to change it |
| `POST /rules/update` | Update now (`force` checkbox) |
| `POST /rules/mute/{sid}`, `/unmute/{sid}` | Mute / unmute; the response says whether Snort was restarted |
| `POST /rules/home-net` | Set or reset HOME_NET |
| `GET /journal` | Journal state: vault path, last flush, notes written today, Flush now |
| `POST /journal/flush` | Flush now |
| `GET /lab` | Rules textarea, pcap picker, Check / Run, pcap generator form, upload |
| `POST /lab/check`, `/lab/run` | Run the lab; show problems by rule line, or the hits table and matches |
| `POST /lab/pcaps`, `/lab/pcaps/generate` | Upload (raw body, `?name=`), or build a pcap into `data\pcaps\` |
| `GET /healthz` | `{"ok": true}` for launcher scripts; token-exempt, GET only |

**Rules (data):**

- Every form value is validated at the controller: `sid` is a positive int, `priority` 1-3, `range` one of the listed values, lab text capped at 64 KB, pcap name `[A-Za-z0-9._-]{1,64}` ending `.pcap`, upload at most 50 MB. A bad value gives HTTP 422 with an inline message, not a stack trace.
- User mistakes (bad rule, missing pcap, rule already muted) are shown as messages in the fragment, status 200. Programming errors give a plain error page and a log entry; the process keeps running.
- Mute and unmute reuse the rules service, which already writes the muted block and restarts the sensor; the page shows its `EditReport`.
- The sensor card shows `SensorStatus` (state, since when, restart count, last error). Buttons disable themselves for states where the action is illegal (`IllegalTransition` is never shown to the user).
- Times are shown in local time as `YYYY-MM-DD HH:MM:SS`; no relative times that would go stale.
- The lab page never shows or accepts server paths; pcaps are chosen by name from the list.

**CLI:**

```
uv run python -m snorty.dashboard [--port N] [--start-sensor] [--no-notify] [--no-journal] [--vault PATH] [--interface-ip IP] [--data-dir PATH]
```

Exit codes: 0 clean stop, 1 sensor failed to start or port in use, 2 usage.

## Commands

```
Test:   uv run pytest tests/dashboard -q -m "not snort"
Real:   uv run pytest tests/dashboard -q -m snort          # needs C:\Snort
All:    uv run pytest -q -m "not snort"
Lint:   uv run ruff check src tests
Types:  uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules src/snorty/notify src/snorty/journal src/snorty/lab src/snorty/dashboard
Run:    uv run python -m snorty.dashboard
```

## Project structure

```
src/snorty/dashboard/
  __main__.py     CLI, compose real services, uvicorn
  app.py          build_app(): routes, middleware, template env
  services.py     Services dataclass, get_services()
  security.py     Host / Origin / token checks, security headers, input validators
  views.py        pure view-models and formatting
  schedule.py     daily rules-update loop (injected clock and sleep)
  config.py       DashConfig, load_config() (tomllib)
  templates/      base.html, overview.html, alerts.html, rules.html, journal.html, lab.html, _*.html fragments
  static/         htmx.min.js (vendored), app.css, app.js (SSE wiring, a few lines)
src/snorty/compose.py   shared wiring used by sensor CLI and dashboard (if the factoring stays small)
tests/dashboard/  test_dash_views, _security, _config, _schedule, _routes, _sse, _lab, _real, dash_fakes
```

Test file basenames are unique across test folders.

## Code style

Same as earlier modules: frozen dataclasses, `Protocol` ports, strict mypy on `snorty.dashboard.*`, ruff (E,F,I,B,UP, 100 cols). Controllers are one-liners over services:

```python
@router.post("/rules/mute/{sid}")
async def mute(sid: PositiveSid, svc: Services = Depends(get_services)) -> HTMLResponse:
    return render("_rules_card.html", rules=views.rules_card(await svc.rules.mute(sid)))
```

## Testing strategy

- **Pure:** `views` (priority badge, row building, sensor card per state, button enablement), `security` validators (sid, name, range, size caps), `config` (defaults, file, bad file, CLI override), `schedule` (fires once at the time, skips when disabled, survives a failed update, cancels cleanly).
- **Routes (TestClient + fake `Services`):** every page returns 200 with expected content; each POST calls the right service once; missing token gives 403; bad `Host` gives 400; foreign `Origin` gives 403; bad inputs give 422; alert text containing `<script>` is escaped in HTML; mute shows the restart outcome; double-click start does not break; a lab problem shows the rule line.
- **SSE:** generator tested directly (publish an `AlertRaised`, read the fragment; client disconnect closes the subscription; slow consumer drops oldest and does not grow without bound; heartbeat).
- **Real (`-m snort`):** build the app with the real services on a temp db, call start, wait for RUNNING, send the integration test's attack traffic, see the alert via `/alerts/rows`, stop, no leftover `snort.exe`; a lab run through HTTP gives the same hits as the lab test. Live Snort files untouched (hash before and after).
- **Manual in a browser (built-in browser pane):** open every page, press Start, generate traffic, watch a row appear, mute it, update rules, run a lab rule; report with screenshots; check phone width and dark mode.
- Coverage of `snorty.dashboard` at least 85% from unit tests alone (view-heavy glue, lower than the 90% of pure modules).

## Boundaries

- **Always:** bind loopback only; check Host, Origin and token on every non-GET; escape all third-party text; validate every input at the controller; reuse the module services, never duplicate their logic; stop the sensor on exit.
- **Ask first:** any new runtime dependency beyond `fastapi`, `uvicorn`, `jinja2`; vendoring any other third-party JS or CSS; binding to anything but loopback; authentication; autostart at logon; editing live Snort files from the UI beyond what the rules module already does (mute block, HOME_NET).
- **Never:** make a request to a third-party host from the browser (no CDN, fonts, analytics); `subprocess` in `dashboard`; render a server path from the browser or open a browser-supplied path; expose the token in a URL or log; inline `<script>`; leave a background task running after shutdown; `eval`/`exec`.

## Success Criteria

- [x] 1. `python -m snorty.dashboard` serves on `127.0.0.1:8765` only; `GET /healthz` returns `{"ok": true}`; a request with a foreign `Host` gets 400.
- [x] 2. Every non-GET request without the right `X-Snorty-Token`, or with a foreign `Origin`, gets 403 and changes nothing.
- [x] 3. Overview, Alerts, Rules, Journal and Lab pages render with fake services; each page's actions call exactly one service method.
- [x] 4. Sensor Start, Stop and Restart work through the UI; the card shows the real state; illegal actions are disabled, not errors.
- [x] 5. A new alert on the bus appears in an open Alerts page through `/events` without reload; a closed tab frees its subscription; a slow tab cannot grow memory.
- [x] 6. Alerts table filters (`sid`, `priority`, `range`) and paging match `AlertRepository.query`; invalid values give 422.
- [x] 7. Mute and Unmute from an alert row or the Rules page change the muted list and report whether Snort restarted.
- [x] 8. Rules page shows last update, count, error; Update now runs once even if clicked twice; HOME_NET can be changed and reset.
- [x] 9. Daily rules update runs at `rules_update_at` once, never twice for the same day, and a failed update does not stop the loop.
- [x] 10. Journal page shows state and Flush now writes the note; the vault path is shown but cannot be changed from the UI.
- [x] 11. Lab page: Check and Run show problems by rule line or the hits table and matches; pcaps come only from `data\pcaps\` by name; upload over 50 MB and bad names are refused; a generated pcap triggers a rule (real Snort).
- [x] 12. Hostile text (`<script>`, quotes, 10 000-char message, non-ASCII) in alerts, rules and pcap names is escaped or refused; CSP header present; the page makes no third-party request (checked in the browser's network log).
- [x] 13. Real: Start, traffic, alert in `/alerts/rows`, Stop; no `snort.exe` left; live `snort.conf`, `rules\`, `threshold.conf` unchanged by the lab run.
- [x] 14. Manual in the browser pane: all pages, light and dark, phone width, live row appears, mute works.
- [x] 15. `ruff check`, strict mypy on `snorty.dashboard`, full unit suite green, coverage at least 85%; `subprocess` still only in `snort/`; existing module CLIs still pass their tests.

Status: implemented. Criterion 14 was checked in the built-in browser in two parts: the live row, filters, escaping and Start button on a fake-service demo server (Live view checkpoint), and the real `python -m snorty.dashboard` (Start, Stop, Lab with a generated pcap against real Snort, all five pages, dark and light, phone width with no horizontal overflow, no third-party request, no inline script). Mute from a row was covered by route tests and the demo server, not on the real sensor.

## Deviations from the plan

- The database lives at `<data dir>\snorty.db` (the sensor CLI keeps its own `--db`). `compose.py` builds the services for the dashboard only; the sensor CLI was not moved onto it because its tests patch module-level names.
- `JournalService.status()` returns `last_written` (time of the last note write) instead of `last_flush`, plus `folder`, `notes_written`, `error`. `NotifyService.status()` returns `toasts_shown` and `min_priority`. `NoteStore` gained a `label` property.
- Extra modules: `ui.py` (render helpers), `jobs.py` (one in-flight job), `rules_routes.py`, `journal_routes.py`, `lab_routes.py`, `pcaps.py`. Alert tests are in `test_dash_alerts.py`.
- Vendored htmx 2.0.4, SHA-256 `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447`, recorded in `static/htmx.VERSION`.
- Generated pcaps are stamped with the current time (a pcap starting at epoch 0 made Snort alerts show the year 2070).
- Known gap: the CLI exit code 1 covers a port that cannot be bound or a crash, not a sensor that fails later (the card shows that). Fixed after close-out: unhandled errors now return a 500 with the security headers, and the Rules page shows a message when the Snort files cannot be read.

## Out of Scope (Deferred)

- Login, multi-user, remote access, HTTPS: single user on loopback.
- Charts beyond a simple hourly bar strip and top-rules list (a richer analytics page).
- Editing `snorty.toml` from the UI; changing the vault path from the UI.
- Autostart at logon (Task Scheduler), Windows service, system-tray icon.
- Catch-up of a missed scheduled rules update.
- Recording live traffic to pcap, downloading sample pcaps, promoting a lab rule to live `local.rules`.
- Click-through from a toast to the dashboard.
- Packet payload view, GeoIP, reverse DNS.

## Open Questions

1. **Dependencies:** approve adding `fastapi`, `uvicorn`, `jinja2` (runtime) and `httpx` (dev, for tests)? The alternative is a stdlib-only server with hand-rolled routing and SSE: no new dependencies but more code of ours to maintain and test.
2. **htmx:** approve downloading `htmx.min.js` (about 50 KB, one version pinned, hash recorded) once, to vendor it? The alternative is about 60 lines of our own JavaScript (fetch plus EventSource) with no third-party file.
3. **Autostart of the sensor:** start Snort when the dashboard starts (`autostart_sensor = true`), or only when you press Start? Spec default: only when you press Start.
4. **Rules update time:** daily at 03:00 local while the dashboard is open. Right, or another time, or manual only?
5. **Port:** 8765 fine?

## Alert retention

The dashboard deletes alerts older than `retention_days` (default 90, `0` keeps everything; set in `snorty.toml`). It runs once at startup, because the PC is often off at night, and again daily at 03:30. This is the retention job that SPEC-sensor leaves to the dashboard. A failed delete is logged and the dashboard keeps running.
