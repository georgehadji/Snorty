# Spec: suricata (as built)

## Objective

Run the Suricata engine for Snorty: check a config (`-T`), start a live capture and say when it
is ready, run a pcap and return its alerts, and list the PC's IPv4 addresses for capture. It does
not supervise or restart the engine (the sensor does), does not edit the config or rules, and
does not decode live alerts (`src/snorty/suricata/service.py`).

## Architecture and patterns

- Process adapter. It is not in the `subprocess` contract, so it may run processes; it is in
  "core is the domain" and "feature modules never reach up into the UI or the wiring"
  (`pyproject.toml`, `[tool.importlinter]`). The package docstring calls it the only package
  besides `snort` that runs an IDS engine (`suricata/__init__.py:1`).
- Reuse over copy: it borrows Snort's process helpers (`bind_to_job`, `stop_live`, `Runner`) and
  error and result types (`SnortError`, `ConfigCheck`, `Interface`) (`service.py:13-15`).
- Builder: `check_command`, `live_command` and `pcap_command` return argv lists
  (`service.py:25-32,101-108`).
- Users: `sensor.port.SuricataAdapter` (start, interfaces, `IMAGE` for the process check;
  `sensor/port.py:18-20,83`), `rules.ports.SuricataValidator` (`check_config`; `rules/ports.py:14`),
  and `lab.engines.SuricataLabEngine` (`check_config`, `run_pcap`; `lab/engines.py:104,116`).
- Wiring: `compose.py:141-153` picks Suricata when `engine == "suricata"`, with paths from
  `rules.suricata_home.prepare_suricata_home` (neighbour, below).

## Ports

- `SuricataPaths(exe, conf, log_dir)` with `alert_file == "eve.json"` (`suricata/models.py:6-16`).
  Defaults: `C:\Program Files\Suricata\suricata.exe` and `suricata.yaml`, logs in
  `%LOCALAPPDATA%\Snorty\suricata-log`.
- `Runner` (from `snort.runner`) runs bounded commands; a `SnortError` from it is a failed check.

## Behaviour and invariants

1. `check_config` runs `suricata -T -c <conf> -l <log_dir>` with a 180 s limit and never raises for
   a Suricata failure: exit 0 is OK; otherwise lines starting `E:` or containing `<Error>` are the
   errors, or a fixed message when there are none. The rule count comes from "N rules successfully
   loaded" (`service.py:20-22,81-98`).
2. `start_live` needs an IPv4 address on the interface and runs `suricata -c <conf> -i <ip> -l
   <log_dir>` in a new process group, output to `<log_dir>/suricata.out`, bound to Snorty's job
   object (`service.py:30-32,46-66`).
3. It polls that file every 0.25 s for "engine started" (case-insensitive). An early exit raises
   `SnortError` with the last 500 characters; after 120 s it stops the process and raises
   (`service.py:19,67-78`).
4. `local_interfaces` lists the host name's IPv4 addresses, without `127.*` and without repeats;
   a resolver failure gives an empty list (`service.py:35-43`).
5. `run_pcap` raises `SnortError` for a missing pcap or a non-zero exit (last 5 output lines). It
   runs with `-k none` (no checksum drops), a 300 s limit, and reads `<log_dir>/eve.json` with
   `EveDecoder` in a worker thread (`service.py:101-138`).

## Neighbour: the config copy

`rules/suricata_home.py:74` `prepare_suricata_home(install, home)` copies the install's
`suricata.yaml`, classification and reference files and rule files into `data_dir/suricata`,
points the copy at its own `rules`, `log` and threshold file, and remakes it only when the
SHA-256 of the install's config or the recipe number changes, keeping the old one as
`suricata.yaml.before-rebuild` and keeping `HOME_NET` (`suricata_home.py:56-109`).

## Security and privacy

- Commands are argv lists built from `SuricataPaths` and an `Interface` address; no shell
  (`service.py:25-32,57-63,101-108`).
- Engine output is read as text with `errors="replace"`; only the tail is put in error messages.
- Nothing is sent off the PC by this package.

## Tests

- `tests/suricata/test_suricata.py`: argv lists, `eve.json`, interface listing, config check
  results (including this build's `E:` lines and a missing exe), IPv4 required, the adapter looks
  for `suricata.exe`, the sensor reads `eve.json`, the ready marker. A fake runner is used.
- `tests/lab/test_lab_suricata.py` and `tests/rules/test_dialects.py` use `SuricataPaths`.
- No pytest marker runs the real Suricata.

## Deviations and known limits

- `README.md:115` says `suricata/` holds "its own copy of the config and rules"; the copy is made
  in `rules/suricata_home.py`.
- Live capture is IPv4 only (`service.py:51-52`).
- Errors use Snort's `SnortError` type (`service.py:13`).
