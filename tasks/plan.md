# Implementation Plan: rule-lab

Source spec: [SPEC-rule-lab.md](../SPEC-rule-lab.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)
Previous modules: alert-core, snort-adapter, sensor, rules, notify, vault-journal, done (their plans and tasks are in git history; vault-journal's last at `1a5a933`).

## Overview

Build `snorty.lab`: test a user-written Snort rule against a pcap in a sandbox that never
touches the live Snort files. Pure logic first (lint the rules, rewrite the config, build
test pcaps), then the service pipeline (lint, sandbox, `snort -T`, `snort -r`, summarize)
with a fake `Runner`, then the sandbox-safety guarantees (cleanup on every exit path, stale
files, one job at a time, live files untouched), then the CLI, then real Snort checks and
the manual run.

## Architecture Decisions

- **Pipeline as data.** `LabService.run(job) -> LabResult`; every user mistake (bad rule, bad pcap, Snort rule error) is a field of the result, never an exception. Only programming errors raise.
- **Pure core, imperative sandbox.** `lint`, `build_lab_conf`, `build_pcap`, `summarize` are pure. `LabSandbox` is the only code that writes files: a temp folder (rules file, logs) and `snorty-lab-<id>.conf` beside `snort.conf`; both removed in `finally`, also on cancel.
- **Reuse the adapter.** `check_config`, `run_pcap`, `list_interfaces`, `pick_interface`, `Runner` from `snorty.snort`. No new Snort command line, no `subprocess` in `lab`. If `run_pcap` or `check_config` need a small change (for example a different `-T` interface choice), it goes in `snort/` with its own test.
- **Realistic config.** Derive from the live `snort.conf`: drop rules, preprocessor-rules and `threshold.conf` includes, add one lab include. Preprocessors stay so `flow:` and `http_*` behave as live.
- **Error mapping.** Snort names `lab.rules(N)`; results report "rule line N" using the user's own line numbers (the lab file is the user's text unchanged).
- **One job at a time** via `asyncio.Lock`. Stale `snorty-lab-*.conf` (older than 1 hour) are removed at job start.
- **`lab` imports only `snorty.core`, `snorty.snort` and stdlib.** CLI is the only composition point.
- **No new dependency.** `snorty.lab.*` added to the strict mypy override.
- Test file basenames unique: `test_lab_lint.py`, `test_lab_conf.py`, `test_lab_pcapgen.py`, `test_lab_service.py`, `test_lab_sandbox.py`, `test_lab_cli.py`, `test_lab_real.py`, `lab_fakes.py`.

## Task List

### Phase 1: Pure logic
- [ ] Task 1: `lint` (rules, problems, caps)
- [ ] Task 2: `build_lab_conf`
- [ ] Task 3: pcap generator (`build_pcap`, `tcp_packet`, `udp_packet`, handshake)

### Checkpoint: Pure logic
- [ ] All unit tests green; ruff and strict mypy clean on `snorty.lab`

### Phase 2: Pipeline and sandbox
- [ ] Task 4: models, `summarize`, `LabService` pipeline with a fake `Runner`
- [ ] Task 5: sandbox safety (cleanup on every exit, stale files, lock, live files untouched)

### Checkpoint: Service
- [ ] Spec criteria 1-8 and 10 each covered by a passing test; unit suite under 3 s

### Phase 3: CLI and real checks
- [ ] Task 6: `python -m snorty.lab check | run | make-pcap`
- [ ] Task 7: real Snort tests, manual run, close-out

### Checkpoint: Complete
- [ ] Every Success Criteria box in SPEC-rule-lab.md checked
- [ ] Then the next module spec (dashboard)

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| A lab run changes live Snort files | High | Lab writes only a temp folder and one `snorty-lab-*.conf`; hash tests on every exit path; real-Snort test repeats the check |
| User rule text smuggles config directives | High | Lint allows only `alert`/`log`/`pass` rule lines; refuses `include`, `var`, `config`, `preprocessor`; refused before Snort runs |
| Hostile or huge pcap | Med | 50 MB cap, read only, Snort timeout, temp log folder |
| Temp config left behind after a crash | Med | `finally` cleanup plus stale-file sweep at the next job |
| Preprocessors make `-T` slow (seconds per run) | Low | One `-T` and one `-r` per job; timeouts; measured in Task 7 |
| Temp path with spaces breaks Snort `include` | Low | Detect and report; assumption 8 |
| Generated packets do not reach `flow:established` rules | Med | `--handshake` option; real Snort test in Task 7 |
| Windows interface choice for `-T` | Low | Reuse `pick_interface`; same method the rules module uses |

## Open Questions

None blocking. Defaults taken (approved): own pcaps plus generator, no downloads or recording; `alert`/`log`/`pass` only; live mutes ignored and preprocessors kept; promote-to-live deferred.
