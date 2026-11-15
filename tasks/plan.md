# Implementation Plan: snort-adapter

Source spec: [SPEC-snort-adapter.md](../SPEC-snort-adapter.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)
Previous module: alert-core, done (its plan and tasks are in git history, commits `06d0858`..`569c28d`).

## Overview

Build `snorty.snort`: the only package that runs `snort.exe`. Pure parsers and
command builders, one injectable `Runner`, and a service layer (interfaces,
config check, live start/stop, pcap run). Stdlib only. Depends on `snorty.core`.

## Architecture Decisions

- **Runner is the seam.** `Runner` Protocol, `SubprocessRunner` real impl. Unit tests pass a fake; only `@pytest.mark.snort` tests touch Snort.
- **Live process is separate from the Runner.** `start_live` returns an `asyncio.subprocess.Process` (long-lived, needs `CREATE_NEW_PROCESS_GROUP` so Ctrl+Break reaches only Snort); the Runner covers run-to-completion calls.
- **Integration tests never use `C:\Snort\log`.** They pass `SnortPaths(log_dir=tmp_path)`, so the real alert log stays untouched.
- **Risk first:** the Ctrl+Break clean-stop assumption is proved in Task 3, before more is built on it.
- Interface pick by IP match (`find_local_ip` + `pick_interface`); no hard-coded index.
- Spec's package layout and commands are used as written.

## Task List

### Phase 1: Foundation and the riskiest assumption
- [ ] Task 1: models, interface parsing, picking, local IP
- [ ] Task 2: command builders and `Runner` + `SubprocessRunner`
- [ ] Task 3: `start_live` / `stop_live` with a real-Snort flush test

### Checkpoint A (after Tasks 1–3)
- [ ] Unit tests green; `-m snort` live test shows the alert flushed after Ctrl+Break
- [ ] If the flush test fails: stop, report, revise spec (open question 3)

### Phase 2: Config check and pcap
- [ ] Task 4: `list_interfaces` + `check_config` (fixtures, fake runner, real `-T`)
- [ ] Task 5: `run_pcap` (fake runner, hand-built pcap, real run)

### Checkpoint B (after Tasks 4–5)
- [ ] `-m "not snort"` under 2 s; `-m snort` green on this PC

### Phase 3: Gates
- [ ] Task 6: coverage ≥ 90%, strict mypy, subprocess-containment check, spec boxes ticked

### Checkpoint C: module complete
- [ ] Every Success Criteria box in SPEC-snort-adapter.md checked
- [ ] Then SPEC-sensor.md

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Snort 2.9 ignores Ctrl+Break, or exits without flushing | High | Task 3 proves it first; on failure stop and revise the spec |
| Windows console-signal quirks (event goes to the wrong process group) | Med | `CREATE_NEW_PROCESS_GROUP`; test asserts the parent test process survives |
| Hand-built pcap rejected or ignored by Snort (checksums, link type) | Med | Ethernet link type 1, valid IP checksum; pass `-k none` in `pcap_command` |
| `-W` or `-T` output text differs between runs | Low | Fixtures are real output; parsers tolerate extra lines; unknown shape gives `ok=False` / `[]`, never raises |
| Integration tests flaky on timing (waiting for alerts) | Med | Poll with a deadline instead of fixed sleeps |
| Npcap capture needs the right adapter | Low | Live test uses the loopback adapter found via `-W` |

## Open Questions

- None blocking. Spec question 2 (interface override in `snorty.toml`) goes to the sensor spec.
