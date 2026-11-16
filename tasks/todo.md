# Tasks: rule-lab

Plan: [plan.md](plan.md) · Spec: [SPEC-rule-lab.md](../SPEC-rule-lab.md)
Order: 1 → 2 → 3 → 4 → 5 → 6 → 7. Each task is one TDD cycle and one commit.

## Task 1: lint (M)
`src/snorty/lab/__init__.py`, `lint.py`; add `snorty.lab.*` to the strict mypy override.
- [x] `lint(text) -> LintResult(rules: tuple[LabRule(line, sid, msg)], problems: tuple[Problem(line, message)])`; line numbers are 1-based lines of the user's text; `ok` is true when there are no problems
- [x] Accepts `alert`/`log`/`pass` rules, blank lines, `#` comments, CRLF and LF; a rule may span lines ended with a trailing backslash (reported at its first line)
- [x] Refuses with a line number: any other line (`include`, `var`, `config`, `preprocessor`, `drop`, `reject`, free text), a rule with no `sid`, a duplicate `sid`, control characters or NUL
- [x] Refuses text over 64 KB and more than 200 rules, with one problem (line 0) saying why, without scanning the whole text first
- [x] `msg` is read from `msg:"..."` when present (for the result table), else empty
- [x] Verify: `uv run pytest tests/lab/test_lab_lint.py -q`
- Dependencies: none · Files: `lint.py`, `tests/lab/test_lab_lint.py`

## Task 2: build_lab_conf (S)
`src/snorty/lab/conf.py`.
- [x] `build_lab_conf(live_conf_text, rules_path) -> str` removes every `include $RULE_PATH/<x>.rules`, `include $PREPROC_RULE_PATH/<x>.rules` and `include threshold.conf` line (any spacing, any case of the keyword) and appends `include <rules_path>` as the last line
- [x] Every other byte is kept, including line endings and comments; commented-out includes stay commented
- [x] A path with whitespace raises `ValueError` (assumption 8; the service turns it into `error`)
- [x] Golden test on a small sample conf; counts of removed lines asserted
- [x] Verify: `uv run pytest tests/lab/test_lab_conf.py -q`
- Dependencies: none · Files: `conf.py`, `tests/lab/test_lab_conf.py`

## Task 3: pcap generator (M)
`src/snorty/lab/pcapgen.py`.
- [x] `build_pcap(frames: Sequence[bytes], start: float = 0.0, step: float = 0.001) -> bytes`: classic libpcap, little-endian, Ethernet link type, snaplen 65535
- [x] `tcp_packet(src, sport, dst, dport, payload, *, seq, ack, flags)` and `udp_packet(...)`: Ethernet + IPv4 + TCP/UDP frames; IP header checksum correct; payload kept byte for byte
- [x] `tcp_session(src, sport, dst, dport, payload, handshake)` gives the frame list: payload only, or SYN, SYN-ACK, ACK, then data; `count` copies option on the data packet
- [x] Tests read the result back with a small reader in the test file (global header, record headers, frame lengths, IP/TCP/UDP fields, payload)
- [x] Rejects invalid IPs and ports with `ValueError`
- [x] Verify: `uv run pytest tests/lab/test_lab_pcapgen.py -q`
- Dependencies: none · Files: `pcapgen.py`, `tests/lab/test_lab_pcapgen.py`

### Checkpoint: Tasks 1-3
- [x] Tests green; `uv run ruff check src tests`; `uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules src/snorty/notify src/snorty/journal src/snorty/lab` clean

## Task 4: Models, summarize, pipeline (L)
`models.py`, `service.py`, `tests/lab/lab_fakes.py`. Read `snorty.snort.service.check_config`, `run_pcap`, `pick_interface` first; adapt only if needed (with a test in `tests/snort`).
- [x] `LabJob(rules_text, pcap)`, `RuleHit(sid, msg, line, count)`, `LabResult(ok, problems, error, hits, matches)` frozen dataclasses
- [x] `summarize(rules, alerts) -> tuple[RuleHit, ...]` (one hit per lab rule in rule order, zero counts included); matches sorted by time then sid
- [x] `LabService(paths, runner, *, tz, year)`; `run(job)`: lint stop, then pcap checks (missing, not a file, over 50 MB), then sandbox, `check_config` stop, `run_pcap`, summarize
- [x] Snort rule errors naming `lab.rules(N)` become `Problem(N, text)`; other `-T` errors become `error`
- [x] `run_pcap` failures and `SnortError` become `error` with Snort's last lines
- [x] Fake `Runner` scripts the `-T` and `-r` calls and writes a fixture `alert.ids` into the `-l` folder
- [x] Verify: `uv run pytest tests/lab/test_lab_service.py -q`
- Dependencies: Tasks 1-2 · Files: `models.py`, `service.py`, `lab_fakes.py`, `test_lab_service.py`

## Task 5: Sandbox safety (M)
`service.py` (the `LabSandbox` context manager), `tests/lab/test_lab_sandbox.py`.
- [x] `LabSandbox` creates the temp folder, writes `lab.rules` (the user's text, normalized to LF) and the temp config beside `snort.conf`; removes both in `finally`
- [x] Cleanup verified after success, lint failure, `-T` failure, `-r` failure, `TimeoutError` and `asyncio.CancelledError`
- [x] Hashes of a fake live tree (`snort.conf`, `rules\`, `threshold.conf`, `log\`) are identical before and after each of those paths
- [x] Stale `snorty-lab-*.conf` older than 1 hour are removed at job start; younger ones and unrelated files are left alone
- [x] Two jobs started together run one after the other (the lock), and a cancelled waiter does not block later jobs
- [x] A temp path with spaces gives `error`, not a Snort run
- [x] Verify: `uv run pytest tests/lab -q`
- Dependencies: Task 4 · Files: `service.py`, `test_lab_sandbox.py`

### Checkpoint: Tasks 4-5
- [x] Spec criteria 1-8 and 10 each covered by a passing test; whole lab unit suite under 3 s; ruff and strict mypy clean

## Task 6: CLI (M)
`src/snorty/lab/__main__.py`.
- [x] `check RULES_FILE`: lint and `snort -T` on the lab config; prints problems with line numbers; exit 0, or 1
- [x] `run RULES_FILE PCAP [--json]`: prints a hit table (SID, message, count) then matches (time, SID, message, source to destination), or the problems or error; `--json` prints the `LabResult` as JSON; exit 0 on `ok`, 1 otherwise
- [x] `make-pcap --out FILE --payload TEXT [--proto tcp|udp] [--src] [--sport] [--dst] [--dport] [--count] [--handshake]` writes a pcap and prints its path; exit 2 on bad arguments
- [x] Console output is encoding-safe (as in `notify` and `journal`)
- [x] Tests inject a fake `Runner` and use temp files; `make-pcap` output is read back by the test reader
- [x] Verify: `uv run pytest tests/lab -q`
- Dependencies: Tasks 3-5 · Files: `__main__.py`, `tests/lab/test_lab_cli.py`

## Task 7: Real checks and close-out (M)
`tests/lab/test_lab_real.py` (marked `snort`).
- [x] Real: the lab config built from the real `snort.conf` passes `snort -T`
- [x] Real: a generated pcap triggers a lab rule on its payload; an unrelated rule shows 0; a deliberately broken rule gives an error on its line; `--handshake` makes a `flow:established` rule match
- [x] Real: hashes of live `snort.conf`, `rules\`, `threshold.conf` and `log\` unchanged; no `snorty-lab-*.conf` left; no `snort.exe` left
- [x] Manual: `uv run python -m snorty.lab run` on a rule you could have written and a generated pcap (I report the table and the run time)
- [x] Coverage for `snorty.lab` at least 90% from unit tests alone (read from the json report)
- [x] `grep -r subprocess src/snorty` matches only `snort/` files; `snorty.lab` imports only `snorty.core`, `snorty.snort` and stdlib
- [x] SPEC-rule-lab.md Success Criteria and deviations amended and ticked; plan and todo boxes ticked except the "next module" one
- [x] Verify: `uv run pytest -q -m "not snort"`; `uv run pytest tests/lab -q -m snort`; `uv run ruff check src tests`; mypy as above
- Dependencies: Task 6
