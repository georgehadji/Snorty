# Tasks: snort-adapter

Plan: [tasks/plan.md](plan.md) · Spec: [SPEC-snort-adapter.md](../SPEC-snort-adapter.md)

Definition of done for every task: its tests pass, `uv run ruff check src tests`
and `uv run mypy src/snorty/core src/snorty/snort` are clean, and
`uv run pytest -m "not snort"` stays green. Tasks that touch real Snort also pass `-m snort`.

## Task 1: Models, interface parsing, local IP

**Description:** Create `snorty.snort` with the data types and the pure interface
functions. Save the real `snort -W` output as a fixture.

**Acceptance criteria:**
- [x] `SnortPaths`, `Interface`, `ConfigCheck`, `RunResult`, `SnortError` as in the spec (frozen, slotted)
- [x] `parse_interfaces(text)` parses the real fixture: 9 rows; row 4 has ip `192.168.10.230`; `disabled` rows and the IPv6 loopback row give `ip=None`; garbage input gives `[]`
- [x] `pick_interface(interfaces, ip)` returns the match or `None`
- [x] `find_local_ip()` returns a valid IPv4 string without sending a packet (UDP `connect` + `getsockname`); returns `None` when the PC has no route
- [x] pytest marker `snort` already registered; `-m "not snort"` deselects nothing yet

**Verification:**
- [x] `uv run pytest tests/snort -q`
- [x] ruff and mypy clean

**Dependencies:** none (alert-core done)

**Files likely touched:** `src/snorty/snort/{__init__,models,interfaces}.py`, `tests/snort/test_interfaces.py`, `tests/fixtures/snort_W.txt`

**Estimated scope:** M

## Task 2: Command builders and Runner

**Description:** Pure argv builders and the single subprocess runner.

**Acceptance criteria:**
- [x] `live_command`, `test_command` (`-T -i N -c conf`), `pcap_command` (`-r pcap -c conf -l dir -A fast -y -k none -q`) return exact argv lists of strings
- [x] `Runner` Protocol; `SubprocessRunner` returns `RunResult` with decoded stdout/stderr (`errors="replace"`)
- [x] Timeout kills the child and raises `SnortError("timeout ...")`; missing executable raises `SnortError`
- [x] Tested with `sys.executable -c ...` (no Snort needed)

**Verification:**
- [x] `uv run pytest tests/snort/test_commands.py tests/snort/test_runner.py -q`

**Dependencies:** Task 1

**Files likely touched:** `src/snorty/snort/{commands,runner}.py`, `tests/snort/test_commands.py`, `tests/snort/test_runner.py`

**Estimated scope:** S

## Task 3: Live start and clean stop (the risk spike)

**Description:** `start_live` spawns Snort in its own process group;
`stop_live` sends Ctrl+Break, waits, kills only as a last resort. Prove with real
Snort on the loopback adapter that an alert is flushed after a clean stop.

**Acceptance criteria:**
- [x] `start_live(paths, iface) -> asyncio.subprocess.Process` uses `CREATE_NEW_PROCESS_GROUP`
- [x] `stop_live(proc, timeout) -> StopResult("clean" | "killed")`; the test process itself survives the signal
- [x] `@pytest.mark.snort` test: temp `log_dir`; start on loopback; wait until Snort is ready; send a TCP payload containing `uid=0(root)` to a local socket; `stop_live`; poll for `alert.ids` containing sid `1000002`; result is `"clean"`
- [x] Unit test with a fake process proves the kill fallback path
- [x] If Ctrl+Break does not flush: STOP and report; do not work around it silently

**Verification:**
- [x] `uv run pytest tests/snort -q -m snort -k live`
- [x] `uv run pytest tests/snort -q -m "not snort"`

**Dependencies:** Task 2

**Files likely touched:** `src/snorty/snort/service.py`, `src/snorty/snort/models.py` (StopResult), `tests/snort/test_live.py`, `tests/snort/conftest.py`

**Estimated scope:** M

## Checkpoint A: after Tasks 1–3
- [x] All unit tests green; live flush test green on this PC
- [x] Review with human only if the flush test failed

## Task 4: Interface listing and config check

**Description:** `list_interfaces` and `check_config` over the Runner.

**Acceptance criteria:**
- [x] `list_interfaces(paths, runner)` runs `-W` and parses it
- [x] `check_config(paths, iface, runner, conf=None)` returns `ConfigCheck`; good fixture gives `ok=True` and the rule count; bad fixture (real output from a conf with one bad line) gives `ok=False` and the error line(s)
- [x] Non-zero exit with unknown output gives `ok=False`, never an exception; `SnortError` from the runner (timeout) is converted to `ok=False` with the message
- [x] `@pytest.mark.snort`: real `-W` contains the loopback adapter; real `-T -i <n>` on `C:\Snort\etc\snort.conf` gives `ok=True` and `rule_count > 50000`

**Verification:**
- [x] `uv run pytest tests/snort -q` (both marker groups)

**Dependencies:** Task 2

**Files likely touched:** `src/snorty/snort/service.py`, `tests/snort/test_service.py`, `tests/fixtures/snort_T_ok.txt`, `tests/fixtures/snort_T_bad.txt`

**Estimated scope:** M

## Task 5: Pcap run

**Description:** `run_pcap` runs Snort over a pcap with a given conf and log dir and
returns parsed alerts.

**Acceptance criteria:**
- [x] `run_pcap(paths, pcap, runner, *, conf=None, log_dir=None, year, tz)` returns `list[Alert]` using `snorty.core.parser`; missing pcap file raises `SnortError` before running anything; non-zero exit raises `SnortError` with stderr tail
- [x] Uses a fresh temp dir when `log_dir` is None and removes it afterwards
- [x] Unit test with a fake runner that writes a fixture `alert.ids`
- [x] `@pytest.mark.snort`: a test helper builds a tiny pcap (Ethernet/IPv4/TCP, payload `uid=0(root)`); real `run_pcap` returns one alert with sid `1000002`

**Verification:**
- [x] `uv run pytest tests/snort -q` (both marker groups)

**Dependencies:** Tasks 2, 4

**Files likely touched:** `src/snorty/snort/service.py`, `tests/snort/pcap.py` (helper), `tests/snort/test_pcap.py`

**Estimated scope:** M

## Checkpoint B: after Tasks 4–5
- [x] `uv run pytest tests/snort -m "not snort"` under 2 s; `-m snort` green

## Task 6: Quality gates

**Description:** Close coverage and typing gaps; verify containment; tick the spec.

**Acceptance criteria:**
- [x] Coverage for `snorty.snort` ≥ 90% (unit tests only counted)
- [x] `grep -r subprocess src/snorty` matches only `runner.py` and `service.py`
- [x] `snorty.snort` imports no snorty package except `snorty.core`
- [x] Success Criteria boxes in the spec ticked; public API re-exported in `snorty/snort/__init__.py`

**Verification:**
- [x] `uv run pytest tests/snort -m "not snort" --cov=snorty.snort --cov-report=term-missing`
- [x] `uv run ruff check src tests`; `uv run mypy src/snorty/core src/snorty/snort`

**Dependencies:** Tasks 3, 4, 5

**Files likely touched:** `src/snorty/snort/__init__.py`, tests for uncovered branches, `SPEC-snort-adapter.md`

**Estimated scope:** S

## Checkpoint C: module complete
- [x] All Success Criteria in SPEC-snort-adapter.md checked; then write SPEC-sensor.md
