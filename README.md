# Snorty

A local dashboard and toolkit around an existing [Snort 2.9](https://www.snort.org/) install on Windows. Snorty starts and stops Snort cleanly, stores its alerts, shows them live in a browser, updates and mutes rules, raises Windows toast notifications, writes a daily security journal into an Obsidian vault, and gives you a lab for trying new rules against a pcap.

Snorty is a single-user tool for one PC. It listens on `127.0.0.1` only and has no remote access.

## Features

| Module | What it does |
|---|---|
| **Dashboard** | Live alerts over Server-Sent Events, sensor start/stop/restart, rule management, journal status and the rule lab, all in one local web page. |
| **Sensor** | Keeps Snort running on the right network interface, restarts it with backoff if it dies, follows network changes, and reads its alert file into the store. |
| **Rules** | Downloads the Emerging Threats Open ruleset, checks it with `snort -T`, swaps it in with rollback, mutes rules by SID and sets `HOME_NET`. |
| **Notify** | Windows toast for priority-1 alerts, throttled per rule and overall so a flood does not bury you. |
| **Journal** | Writes one Markdown note per day into `Security/Snort/` of an Obsidian vault, touching only its own marked block. |
| **Rule lab** | Lints and tests your own rules in a sandbox copy of the Snort config, against a pcap you upload or generate. The live sensor is never touched. |

## Requirements

- Windows 11 (the process control uses Windows console signals)
- Snort 2.9.20 installed at `C:\Snort`, with Npcap capturing without administrator rights
- [Python](https://www.python.org/) 3.12 or newer and [uv](https://docs.astral.sh/uv/)
- Optional: an Obsidian vault, for the journal

## Quick start

```bash
git clone https://github.com/georgehadji/Snorty.git
cd Snorty
uv sync
uv run python -m snorty.dashboard --start-sensor
```

Open <http://127.0.0.1:8765/>. Without `--start-sensor` the dashboard starts with the sensor stopped, and you can start it from the Overview page.

Data lives in `%LOCALAPPDATA%\Snorty`: the alert database `snorty.db`, the log `snorty.log`, uploaded pcaps and the optional `snorty.toml`. Use `--data-dir` to put it elsewhere.

## Configuration

Settings come from defaults, then `snorty.toml` in the data folder, then command-line flags.

```toml
# %LOCALAPPDATA%\Snorty\snorty.toml
port = 8765
interface_ip = "192.168.1.20"     # pin the capture interface; default: the PC's route to the internet
vault = "C:/Users/you/Vault"      # default: the OBSIDIAN_VAULT_PATH environment variable
notify = true
journal = true
autostart_sensor = false
rules_update_at = "03:00"         # local HH:MM; "" turns the daily rules update off
retention_days = 90               # alerts older than this are deleted; 0 keeps everything
```

Dashboard flags: `--port`, `--start-sensor`, `--no-notify`, `--no-journal`, `--vault`, `--interface-ip`, `--data-dir`.

## Start at logon

One small script in your Startup folder launches the dashboard hidden. No administrator rights and no scheduled task are needed.

```bash
uv run python -m snorty.dashboard.autostart install          # add --start-sensor to start Snort too
uv run python -m snorty.dashboard.autostart status
uv run python -m snorty.dashboard.autostart remove
```

## Command-line tools

Every module also runs on its own:

```bash
uv run python -m snorty.sensor                          # run the sensor in a terminal (--notify, --journal)
uv run python -m snorty.rules update                    # also: status, mute, unmute, muted, home-net
uv run python -m snorty.rules mute 2100498 --note "noisy"
uv run python -m snorty.lab check my.rules              # do these rules load in Snort?
uv run python -m snorty.lab make-pcap --out test.pcap --payload "abc" --dport 80
uv run python -m snorty.lab run my.rules test.pcap      # which rules fire on this pcap?
uv run python -m snorty.journal write --dry-run         # preview today's note
uv run python -m snorty.notify test                     # show one sample toast
```

Use `--help` on any of them for the exact arguments.

## Architecture

A modular monolith in one asyncio process, built as ports and adapters: Snort, the filesystem, the rules download and Obsidian sit behind small interfaces, and the domain code never touches `subprocess` or paths. Parsing, rendering and decisions are pure functions over immutable dataclasses, with I/O at the edges.

- **Event bus:** the sensor publishes `AlertRaised`, `SensorStateChanged` and `RulesUpdated`; notify, journal and the dashboard subscribe without knowing each other. Each subscriber has a bounded queue, so a slow one loses its oldest events instead of slowing Snort's ingest.
- **Storage:** SQLite in WAL mode behind a repository, with a configurable retention.
- **UI:** server-rendered HTML (FastAPI, Jinja2, htmx) with SSE for live updates. There is no build step.

```
src/snorty/
  core/       alert model, parser, SQLite repository, event bus
  snort/      the only code that runs Snort (commands, process control, pcap runs)
  sensor/     supervisor: start, restart, tail alert.ids, publish events
  rules/      ET Open update, mute, HOME_NET, rollback
  notify/     throttled Windows toasts
  journal/    daily Obsidian notes
  lab/        rule linting, sandbox, pcap generation
  dashboard/  FastAPI app, pages, security middleware, autostart
  services.py the Protocols and bundle the UI layer uses
  compose.py  wires the modules together (the one composition root)
  headless.py terminal runner behind `python -m snorty.sensor`
```

The design is written up as one spec per module (`SPEC-*.md`) with the overall plan in [`CAPABILITY-MAP.md`](CAPABILITY-MAP.md).

## Security model

Snorty is built for a trusted single-user PC, and it keeps its exposure small:

- It refuses to listen on anything but `127.0.0.1`, and it checks the `Host` header.
- Every state-changing request needs a per-run token and a matching `Origin`.
- Responses carry a strict Content-Security-Policy, `nosniff` and `no-referrer`.
- The lab only allows `alert`, `log` and `pass` rules, runs them in a temporary copy of the config, and takes pcaps by name from one folder, never by path.
- Rule archives are read safely: only `*.rules` files are taken, and your local rule files are never overwritten.
- The journal writes only under `Security/Snort/` and refuses links that point outside the vault.

Do not expose the dashboard to a network.

## Development

```bash
uv run pytest -q -m "not snort"     # fast suite, no Snort needed
uv run pytest -q -m snort           # integration tests against the real C:\Snort (about 90 s)
uv run ruff check src tests         # lint
uv run ruff format src tests        # format
uv run mypy src                     # strict type check
uv run lint-imports                 # architecture rules (see [tool.importlinter] in pyproject.toml)
```

Code style: Python 3.12, line length 100, `ruff format`, strict `mypy`. Tests live in `tests/<module>/` and use pytest with asyncio.

## Known limits

- Snort 3 is not supported. Moving to it would mean swapping one adapter and the alert parser.
- If Snort rotates `alert.ids` and the new file grows past the old offset before the next read, the rotation is not noticed.
- Alerts are only parsed in Snort's `alert_fast` format.

## License

No license has been chosen yet. Until one is added, all rights are reserved.
