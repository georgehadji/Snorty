# Snorty

A local dashboard and toolkit around an existing [Snort 2.9](https://www.snort.org/) or [Suricata 7 or 8](https://suricata.io/) install on Windows. Snorty starts and stops the engine cleanly, stores its alerts, shows them live in a browser, updates and mutes rules, raises Windows toast notifications, writes a daily security journal into an Obsidian vault, and gives you a lab for trying new rules against a pcap.

Snorty is a single-user tool for one PC. It listens on `127.0.0.1` only and has no remote access.

## Features

| Module | What it does |
|---|---|
| **Dashboard** | Live alerts over Server-Sent Events, sensor start/stop/restart, rule management, journal status and the rule lab, all in one local web page. The Alerts page searches rule text or an exact address and exports the filtered alerts as CSV. |
| **Sensor** | Keeps Snort running on the right network interface, restarts it with backoff if it dies, follows network changes, and reads its alert file into the store. |
| **Rules** | Downloads the Emerging Threats Open ruleset, checks it with `snort -T`, swaps it in with rollback, mutes rules by SID and sets `HOME_NET`. |
| **Notify** | Windows toast for priority-1 alerts, throttled per rule and overall so a flood does not bury you. |
| **Journal** | Writes one Markdown note per day into `Security/Snort/` of an Obsidian vault, touching only its own marked block. |
| **Rule lab** | Lints and tests your own rules in a sandbox copy of the Snort config, against a pcap you upload or generate. The live sensor is never touched. |
| **Packets** | Optional, needs Wireshark. Shows the packet behind an alert and what it was for (DNS name, TLS server, HTTP host), offers a one-packet download and "Open in Wireshark", suggests display filters, decodes and summarises lab pcaps, and records 5 to 120 seconds of live traffic into the lab. |
| **Engine** | Suricata (the default when installed) or Snort, picked on the Overview page. Its EVE log adds what the engine saw on the alert's flow: the DNS name looked up, the TLS server name, the web request, and the client's TLS fingerprints (JA3, JA4; Snorty turns them on in its copy of the config). It also shows what happened around the alert: its connection (bytes each way, how long, how it ended), the DNS lookups that gave the remote address in the hour before, and other connections with that address 5 minutes either side. That context comes from Suricata's flow and DNS events, alert or not, and is kept 7 days. |
| **Host context** | Which program on this PC made the alert's connection (from Sysmon's log when the connection has already closed and Sysmon is installed), and what public data says about the remote address (country, owner, reverse DNS, known-bad lists), and the rule's MITRE ATT&CK tactic and technique when the rule carries them. Country and owner come from [DB-IP](https://db-ip.com) Lite (CC BY 4.0); the known-bad lists are abuse.ch Feodo Tracker and the Spamhaus DROP list (© The Spamhaus Project), plus the [CERT Polska](https://cert.pl/en/warning-list/) phishing domain list, checked against the host names Suricata saw on the alert's flow. The remote address and those names are also looked up in the [CIRCL OSINT feed](https://www.circl.lu/doc/misp/feed-osint/) (MISP format, TLP:CLEAR reports only): a match only says a public report mentions the value, so it is shown as a note, never as known bad. All of these are downloaded whole (CIRCL's about 43 MB weekly, the rest daily) and looked up locally; no alert data is sent anywhere. The dashboard credits each on every page. With Suricata, the MD5 of every file it sees in traffic (HTTP, SMB, FTP, SMTP, NFS; most traffic is HTTPS, which hides its files) is matched against [ClamAV](https://www.clamav.net/)'s whole-file hash signatures, and a hit marks every alert on that flow as known bad. No file is ever saved, so nothing reaches Defender. Snorty only reads ClamAV's database; you install ClamAV and keep the database current yourself (see ClamAV below). |
| **Protocol anomalies** | The Overview counts the last day's Suricata `anomaly` events (traffic it could not follow the way the protocol expects), with the most frequent kinds, a plain hint for the usual ones and the connections with most; an alert's detail lists those on its own connection. On a home PC they are mostly gaps in the capture, rarely an attack. Kept 7 days, like the connection context. |
| **First seen** | The Overview and the daily note list the DNS names this PC looked up (Suricata only) and the countries in alerts that Snorty had not seen before, within the kept history. The first week is marked as learning. |
| **Inbox** | Acknowledge or star alerts a rule at a time; an archive rule acknowledges a rule's future alerts as they arrive. With Suricata, an alert's detail also offers to acknowledge everything that names a host (its DNS name or TLS server name) or a subdomain of it. |
| **Blocking** | Blocks one public address in Windows Firewall for a set time, with undo. See below. |
| **Explain** | A plain-English reading of an alert's rule from an Ollama model on this PC. See below. |

## Requirements

- Windows 11 (the process control uses Windows console signals)
- Snort 2.9.20 installed at `C:\Snort`, with Npcap capturing without administrator rights
- [Python](https://www.python.org/) 3.12 or newer and [uv](https://docs.astral.sh/uv/)
- Optional: an Obsidian vault, for the journal
- Optional: [ClamAV](https://www.clamav.net/) 1.x, whose hash signatures Snorty matches against files seen in traffic
- Optional: [Wireshark](https://www.wireshark.org/) 4.x, for decoded packets, "Open in Wireshark" and recording. Snorty installs nothing; without Wireshark those parts say why they are off and everything else works.

## Quick start

```bash
git clone https://github.com/georgehadji/Snorty.git
cd Snorty
uv sync
uv run python -m snorty.dashboard --start-sensor
```

Open <http://127.0.0.1:8765/>. Without `--start-sensor` the dashboard starts with the sensor stopped, and you can start it from the Overview page.

To stop it, press Ctrl+C in its window, or, when it runs without one (at logon, or hidden), run:

```bash
uv run python -m snorty.dashboard --stop
```

This stops the sensor, closes the alert database and waits until the dashboard has finished. Do not end Snorty with Task Manager or `Stop-Process`: a hard stop can leave the database damaged.

Data lives in `%LOCALAPPDATA%\Snorty`: the alert database `snorty.db`, the log `snorty.log`, uploaded pcaps and the optional `snorty.toml`. Use `--data-dir` to put it elsewhere.

## Configuration

Settings come from defaults, then `snorty.toml` in the data folder, then command-line flags.

```toml
# %LOCALAPPDATA%\Snorty\snorty.toml
port = 8765
engine = "suricata"               # or "snort"; unset: Suricata when installed. See Engine below
interface_ip = "192.168.1.20"     # pin the capture interface; default: the PC's route to the internet
vault = "C:/Users/you/Vault"      # default: the OBSIDIAN_VAULT_PATH environment variable
notify = true
journal = true
autostart_sensor = false
wireshark_dir = "C:/Program Files/Wireshark"  # optional; tshark is found automatically
rules_update_at = "03:00"         # local HH:MM; "" turns the daily rules update off
retention_days = 90               # alerts and recorded captures older than this are deleted; 0 keeps everything
respond = true                    # Block buttons on alerts; false hides them
explain_model = ""                # an Ollama model that runs on this PC, e.g. "qwen3:8b"; "" turns explaining off
explain_language = "English"      # the language explanations are written in, e.g. "Greek"
explain_audience = "home"         # who reads them: "home", "office" or "analyst"
explain_prewarm = true            # explain each rule in the background the first time it fires
```

**Blocking.** A Block button adds Windows Firewall rules (in and out) for one public address, for 24 hours by default. Windows shows its permission prompt for every change, so Snorty itself never runs as administrator. Gateways, DNS servers and private addresses are refused, and the Rules page lists every block with an Unblock button.

**Explaining.** With `explain_model` set, an alert's detail has an "Explain this alert" button. The rule's text goes to Ollama on this PC (127.0.0.1) and the reading is saved per rule version. Models that Ollama runs on a remote server (the "cloud" ones) are refused. The explanation is a suggestion generated by a model and can be wrong. `explain_language` and `explain_audience` set the language and the reader; changing either makes each rule's explanation again the next time it is asked for. With `explain_prewarm`, each rule is explained in the background the first time it fires, so the button answers at once; it waits while you are waiting for an answer, and pauses for five minutes when Ollama does not answer.

**Engine.** Suricata is the default when it is installed in `C:\Program Files\Suricata`; otherwise Snort. A rebuilt Suricata config is made from the install's own `suricata.yaml` whenever that file changes (an engine upgrade); the old copy stays as `suricata.yaml.before-rebuild`, and the rules, threshold list and `HOME_NET` are kept. The Overview page has a "Detection engine" picker that writes `engine = "..."` to `snorty.toml`. The engine is chosen when the dashboard starts, so stop it and start it again to switch. The `--engine` flag overrides the file.

**Suricata's logs.** Suricata never trims its logs in `%LOCALAPPDATA%\Snorty\suricata\log` (`eve.json` grows by about 170 MB a day on a busy PC). When `eve.json`, `stats.log`, `fast.log` or `suricata.log` passes 256 MB, Snorty restarts the engine (a few seconds without capture) and renames that file to `<name>.1`, replacing the previous one. The file has been read to the end first, so no alert is lost, and the folder stays under about 2 GB.

**Dropped packets.** With Suricata the engine reports its own drop figure. With Snort, starting the sensor adds one marked `preprocessor perfmonitor` line to `C:\Snort\etc\snort.conf` (checked with `snort -T` first and put back if Snort refuses it; delete the line and the comment above it to turn it off). Snort writes the figure to `perfmon.csv` in its log folder about once a minute, and the Overview shows it once the first rows are flushed.

**ClamAV.** With Suricata, Snorty matches the MD5 of each file in traffic against ClamAV's whole-file hash signatures (about 540,000). It reads the database in `%LOCALAPPDATA%\Snorty\clamav\db`, at start and again within a day of the files changing; without that folder there is simply no file check. Snorty never runs ClamAV or downloads its database. To set it up without administrator rights, write a `freshclam.conf` in `%LOCALAPPDATA%\Snorty\clamav` with `DatabaseDirectory` set to that `db` folder and `DatabaseMirror database.clamav.net`, then run, and run again now and then to stay current (about 110 MB the first time):

```powershell
& "C:\Program Files\ClamAV\freshclam.exe" --config-file="$env:LOCALAPPDATA\Snorty\clamav\freshclam.conf"
```

Only whole-file hashes can match this way: ClamAV's content patterns need the file itself, and Snorty does not store files (so Defender never sees or uploads them).

Dashboard flags: `--port`, `--start-sensor`, `--no-notify`, `--no-journal`, `--vault`, `--interface-ip`, `--engine`, `--data-dir`, `--stop`.

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
  core/       alert model, decoders (alert_fast, EVE), SQLite repository, event bus, triage
  snort/      runs Snort (commands, process control, pcap runs, drop statistics)
  suricata/   runs Suricata (commands, its own copy of the config and rules)
  sensor/     supervisor: start, restart, tail the alert log, publish events
  rules/      ET Open update, mute, HOME_NET, rollback
  notify/     throttled Windows toasts
  journal/    daily Obsidian notes
  lab/        rule linting, sandbox, pcap generation
  packets/    alert-to-packet matching, pcap reader, display filters (no processes)
  wireshark/  the only code that runs tshark, dumpcap and Wireshark
  triage/     archive rules that acknowledge matching alerts as they arrive
  attribution/  which program on this PC made an alert's connection
  enrich/     country, owner, reverse DNS and known-bad lists for a remote address
  respond/    firewall blocks with expiry and undo (the policy; no processes)
  winfw/      Windows Firewall adapter (PowerShell, one approval prompt per change)
  winnet/     the PC's TCP and UDP connection tables (ctypes over iphlpapi)
  winevt/     Sysmon's connection log, for connections already closed (ctypes over wevtapi)
  explain/    plain-English reading of a rule from a local Ollama model
  dashboard/  FastAPI app, pages, security middleware, autostart
  services.py the Protocols and bundle the UI layer uses
  compose.py  wires the modules together (the one composition root)
  headless.py terminal runner behind `python -m snorty.sensor`
```

The V1 design is written up as one spec per module (`SPEC-*.md`) with the overall plan in [`CAPABILITY-MAP.md`](CAPABILITY-MAP.md). Packages added later have no spec; [`docs/modules.md`](docs/modules.md) lists every package with its spec and tests, and [`docs/effects.md`](docs/effects.md) says what else a change touches.

## Security model

Snorty is built for a trusted single-user PC, and it keeps its exposure small:

- It refuses to listen on anything but `127.0.0.1`, and it checks the `Host` header.
- Every state-changing request needs a per-run token and a matching `Origin`.
- Responses carry a strict Content-Security-Policy, `nosniff` and `no-referrer`.
- The lab only allows `alert`, `log` and `pass` rules, runs them in a temporary copy of the config, and takes pcaps by name from one folder, never by path.
- Rule archives are read safely: only `*.rules` files are taken, and your local rule files are never overwritten.
- The journal writes only under `Security/Snort/` and refuses links that point outside the vault.
- Recording runs Wireshark dumpcap for 5 to 120 seconds or 50 MB, whichever comes first, on the adapter Snort already uses, one capture at a time. It needs no administrator rights, and it stops if the dashboard is stopped. The adapter name must match the form Snort lists, so nothing from the browser reaches the command line. The traffic is saved only in the Snorty data folder.
- Wireshark and tshark are started with a fixed argument list, never through a shell. "Open in Wireshark" opens a one-packet file Snorty wrote itself, never a path from the browser, and the button only appears when Wireshark is installed.

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
- Snort alerts are read only in its `alert_fast` format; Suricata alerts come from its EVE JSON log.
- An alert's packet is found in Snort's own `snort.log.*` files by timestamp. Two different packets stamped on the same microsecond cannot be told apart, and the page then says the match is ambiguous. See [`SPEC-packets.md`](SPEC-packets.md).
- Recording needs the sensor running, because it records the adapter the sensor uses. Recorded captures are deleted after `retention_days`; uploaded pcaps are kept.

## License

Proprietary, all rights reserved; see [LICENSE](LICENSE). The code being visible here grants no
right to use, copy or share it without written permission. Third-party components (htmx, the
Python dependencies, the engines and tools Snorty drives, and the data it downloads) keep their
own licences, listed in the same file.
