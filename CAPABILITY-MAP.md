# Capability Map: Snorty — V1

Status: approved 2026-11-16

Module specs: `SPEC-<module-id>.md` in this folder, written in build order.

Local, single-user app that wraps the existing Snort 2.9.20 install at `C:\Snort`:
live dashboard, clean process control, rule updates, alert muting, Windows
notifications, an Obsidian security journal, and a rule-writing lab.

Project root: `C:\Users\tesse\Documents\Vibe Coding\Snorty`

## Assumptions

1. Runs on this Windows 11 PC only, bound to `127.0.0.1`. No remote access, no auth.
2. Python 3.12 + uv (both installed). No Node build step.
3. Snort stays 2.9.20 at `C:\Snort`, Npcap non-admin capture (verified working).
4. Rules source is Emerging Threats Open (snort.org blocks scripted downloads).
5. Obsidian vault: `C:\Users\tesse\Documents\Second Brain`. Journal writes only
   under `Security/Snort/` and never touches other notes.
6. Single process; the app starts Snort itself. Snort is not run as a Windows service.

## Overall architecture

**Modular monolith, hexagonal (ports and adapters), one asyncio process.**

- One user, one machine: microservices or a message broker would add deployment
  and failure modes for no gain.
- Hexagonal: Snort, the filesystem, the ET download and Obsidian are adapters
  behind ports. The domain never imports `subprocess` or paths. Moving to
  Snort 3 later (`alert_json`) means swapping one adapter and one parser.
- Functional core, imperative shell: parsing, rendering and decisions are pure
  functions over immutable dataclasses; I/O sits at the edges. Pure code gets
  fast unit tests without Snort.
- In-process async event bus (Observer / pub-sub, `asyncio.Queue` per
  subscriber): the sensor publishes `AlertRaised`, `SensorStateChanged`,
  `RulesUpdated`; notify, journal and dashboard subscribe without knowing each other.
- Storage: SQLite via stdlib `sqlite3` (WAL mode), behind a Repository.
- UI: server-rendered HTML (FastAPI + Jinja2 + htmx) with Server-Sent Events
  for live alerts. No SPA framework.

```
            ┌──────────── dashboard (FastAPI, htmx, SSE) ────────────┐
            │                                                         │
   sensor ──┼── rules ── notify ── vault-journal ── rule-lab          │
      │     │     │                                    │              │
      └─────┴─────┴──────────── snort-adapter ─────────┘              │
                     alert-core (domain, events, repository) ◄────────┘
```

## Modules

| Module id | Responsibility | Depends on |
|---|---|---|
| alert-core | `Alert` value object, `alert_fast` line parser, event types, event bus, SQLite alert repository, suppression model | — |
| snort-adapter | Only code that runs `snort.exe`: list interfaces (`-W`), validate config (`-T`), read pcap (`-r`), build command lines, map active route to Snort interface index | alert-core |
| sensor | Supervises the live Snort process: start/stop/restart with clean shutdown, picks the active NIC, tails `alert.ids` (with rotation), publishes events | alert-core, snort-adapter |
| rules | Daily ET download, stage, `snort -T` check, atomic swap with rollback; mute/unmute rules via a managed block in `threshold.conf` | alert-core, snort-adapter, sensor |
| notify | Windows toast for priority-1 alerts, throttled per rule | alert-core |
| vault-journal | Writes one Obsidian note per day with that day's alerts and a summary | alert-core |
| rule-lab | Runs user-written rules against a pcap in an isolated temp config; shows matches | alert-core, snort-adapter |
| dashboard | Web UI: sensor controls, live alert timeline and table, mute buttons, rules status, journal status, rule-lab page | all of the above |

Build order: `alert-core` → `snort-adapter` → `sensor` → (`rules`, `notify`, `vault-journal`, `rule-lab` in any order or parallel) → `dashboard`.

Each module is verified by its own tests and a CLI entry point until the
`dashboard` shell exists; then each gets its UI slice.

## Paradigm and patterns per module

| Module | Paradigm | Patterns | Why |
|---|---|---|---|
| alert-core | Functional (pure functions, frozen dataclasses) | Value Object, Repository, Observer (event bus), Parser as pure function | The most-tested code; must have zero I/O so tests run in ms |
| snort-adapter | Procedural, thin | Adapter, Builder (command lines), Anti-corruption layer (translates Snort text into domain types) | One choke point for every `subprocess` call: easy to fake in tests, easy to swap for Snort 3 |
| sensor | Async object-oriented | State machine (Stopped → Starting → Running → Stopping, plus Failed), Supervisor (restart with backoff), Observer (publisher) | Process lifecycle is stateful by nature; explicit states prevent double-start and lost-flush bugs |
| rules | Transaction script | Stage → validate → commit/rollback (Memento of last good ruleset), Command for mute/unmute (reversible), managed-block file editing | A bad rule download must never leave Snort unable to start |
| notify | Event-driven | Observer (subscriber), Throttle/Debounce per SID | Prevents a toast storm when one rule fires 500 times |
| vault-journal | Functional render + imperative write | Template (pure `render(alerts) -> markdown`), idempotent managed section, Observer | Re-running regenerates the same note; never duplicates or edits text you wrote |
| rule-lab | Functional pipeline over a job | Command (lab job), Sandbox (temp config + temp log dir per run), Builder (minimal lab `snort.conf`) | Lab runs must never touch the live config or rules |
| dashboard | Declarative server-rendered UI | Facade (application services per module), thin Controllers, SSE push (Observer), Dependency Injection via FastAPI `Depends` | No front-end build; controllers stay one-liners over services |

## Cross-cutting decisions

- **Config:** one `snorty.toml` (paths, vault path, NIC override, schedule). Pydantic settings.
- **Scheduling:** asyncio tasks in the app process (daily rules update, journal flush). No external scheduler.
- **Logging:** stdlib `logging` to a rotating file in the app's data folder.
- **Testing:** pytest + pytest-asyncio. Pure modules: unit tests. Adapters: integration tests marked `@pytest.mark.snort` that need `C:\Snort`. Dashboard: a few HTTP tests via FastAPI's TestClient.
- **Dependencies (proposed):** fastapi, uvicorn, jinja2, pydantic-settings, httpx (ET download), winotify (toasts), pytest, pytest-asyncio. Nothing else without asking.

## Out of Scope (Deferred)

- Monitoring other devices on the network: needs a mirror-port sensor or router-level Snort; this laptop only sees its own traffic on Wi-Fi.
- Blocking traffic (inline IPS mode): needs a different Snort setup and risks cutting off the network.
- Snort 3 migration: the adapter layer makes it possible; not in V1.
- Remote access, multiple users, authentication.
- Running as a Windows service.

## Open Questions

1. **Journal summary:** plain template summary (counts, top rules, new IPs), or a plain-language AI summary through the Claude API (needs an API key, small cost per day)?
2. **Autostart:** start Snorty at Windows logon via Task Scheduler, or only when you launch it?
3. **Rule-lab pcaps:** use only pcaps you supply and ones the app records itself, or also download public sample pcaps from third-party sites?

Resolved: name `Snorty`, project root `C:\Users\tesse\Documents\Vibe Coding\Snorty`.
