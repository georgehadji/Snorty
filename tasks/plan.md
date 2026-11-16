# Implementation Plan: rules

Source spec: [SPEC-rules.md](../SPEC-rules.md) · Module map: [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)
Task list: [tasks/todo.md](todo.md)
Previous modules: alert-core, snort-adapter, sensor, done (their plans and tasks are in git history, sensor's last at `cb15bc8`).

## Overview

Build `snorty.rules`: update the ET Open ruleset with stage, validate, swap, health-gate and
rollback; mute/unmute SIDs through a managed block in `threshold.conf`; manage the one
`HOME_NET` line. Pure text and tar logic first, then ports, then the update transaction
(happy path, then every failure with a byte-identical-rollback assertion), then
mute/unmute/home-net, then the CLI and real-Snort checks. Stdlib only.

## Architecture Decisions

- **Pure core, imperative shell.** Text rewriting (`blocks.py`) and tar handling (`archive.py`) do no network and never touch the live directory; the service composes them with injected ports.
- **Ports:** `Downloader` (bytes with a size cap), `Validator` (`snort -T` on a conf path), `SensorControl` (`state`, `restart()`; `Sensor` already satisfies it). Fakes in tests; real adapters `UrllibDownloader` and `SnortValidator`.
- **`snort -T` needs `-i N`.** `SnortValidator` lists interfaces and uses the loopback one (any works for a syntax check), then calls `snorty.snort.check_config(..., conf=path)`. Subprocess containment is unchanged.
- **Validate by temp conf, never the live one.** The staging conf is a copy of `snort.conf` with `var RULE_PATH` (update) or `include threshold.conf` (mute) or `ipvar HOME_NET` (home-net) rewritten to the candidate. The candidate is committed only after `-T` passes.
- **Swap is three renames with undo**, kept inside one function with a failure-injection hook (`rename` callable injected) so every partial state is tested.
- **Rollback is the health gate:** after the restart the sensor must reach RUNNING within `health_timeout`; otherwise `rules.prev` is restored and the sensor restarted again.
- **Marker-delimited block** is the single source of truth for mutes; no database copy.
- **One `asyncio.Lock`** serialises every mutating operation. File work runs in `asyncio.to_thread`.
- Package layout and commands as in the spec.

## Task List

### Phase 1: Pure logic
- [x] Task 1: managed block, `set_home_net`, conf rewrites (`blocks.py`)
- [x] Task 2: md5 parse, safe tar extraction, rule count, sanity check (`archive.py`)

### Checkpoint: Pure logic
- [x] All unit tests green; ruff and strict mypy clean on `snorty.rules`

### Phase 2: Ports and update
- [x] Task 3: ports, `UrllibDownloader`, `SnortValidator`, `RulesConfig`, state file
- [x] Task 4: `RulesService.update` happy path (stage, validate, swap, restart, state, event, up-to-date, stopped sensor)
- [x] Task 5: update failures and rollback (every step), concurrency lock

### Checkpoint: Update
- [x] Every failure injection leaves `rules/` byte-identical; unit suite under 3 s

### Phase 3: Mute and home-net
- [x] Task 6: `mute`, `unmute`, `muted`, `set_home_net` through validate and atomic commit

### Phase 4: CLI and real checks
- [x] Task 7: CLI, `@pytest.mark.snort` validation test, manual real update on this PC
- [x] Task 8: close-out (coverage, containment, spec boxes ticked)

### Checkpoint: Complete
- [x] Every Success Criteria box in SPEC-rules.md checked
- [x] Then the next module spec (notify, vault-journal or rule-lab)

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| ET archive layout differs from assumption (rules in `rules/` subfolder) | Med | `safe_members` matches on basename `*.rules`; test with nested and flat archives |
| `-T` takes minutes on 52k rules | Med | Validator timeout 180 s already in `check_config`; update runs in the background; CLI prints progress |
| Real update changes alert volume | Low | `muted` / `mute` available; `rules.prev` for rollback |
| Rename fails while Snort holds files open | Med | Sensor is restarted after the swap, not before; swap is directory renames, and Snort has the rules in memory. If Windows refuses, the undo path runs and the failure is reported |
| Hostile or truncated archive | High | md5, size cap, path checks, overlay-only into a staging dir, rule-count sanity |

## Open Questions

None blocking. Defaults taken: all-private HOME_NET, 04:00 update time (dashboard concern), `C:\Snort` confirmed writable.
