# Tasks: rules

Plan: [plan.md](plan.md) · Spec: [SPEC-rules.md](../SPEC-rules.md)
Order: 1 → 2 → 3 → 4 → 5 → 6 → 7. Each task is one TDD cycle and one commit.

## Task 1: Managed block, home-net and conf rewrites (S)
Pure functions in `src/snorty/rules/blocks.py`.
- [x] `render_block(entries)` writes the marker lines plus `suppress gen_id G, sig_id S   # note` per entry, in SID order, using the file's line ending
- [x] `read_block(text)` returns the entries (and notes) between the markers; no block gives `[]`; a lone start marker is an error
- [x] `apply_block(text, entries)` replaces the block or appends it; text outside the markers is byte-identical (LF, CRLF and mixed files tested); empty entries removes the whole block
- [x] `set_home_net(text, value)` changes only the `ipvar HOME_NET` line; missing line raises `ValueError`
- [x] `rewrite_rule_path(text, path)` and `rewrite_include(text, name, path)` change only the `var RULE_PATH` line and the one `include threshold.conf` line
- [x] Verify: `uv run pytest tests/rules/test_blocks.py -q`
- Dependencies: none · Files: `src/snorty/rules/__init__.py`, `blocks.py`, `tests/rules/__init__.py`, `test_blocks.py`

## Task 2: Archive handling (S)
`src/snorty/rules/archive.py`.
- [x] `parse_md5(text)` accepts both `HEX` and `HEX  name` / `MD5 (name) = HEX` forms; garbage raises `ValueError`
- [x] `safe_members(names)` keeps only `*.rules` basenames from paths with no `..`, no absolute path, no drive letter, not on the protected list
- [x] `extract_rules(tar_bytes, dest) -> ExtractReport(written, skipped)` writes only regular files (symlinks, devices, hardlinks skipped and counted), flat into `dest`, nothing outside it; size cap per member
- [x] `count_rules(dir)` counts non-comment, non-blank lines in `*.rules` that start with `alert|drop|reject|pass|log`
- [x] `sanity_ok(new, old, ratio=0.5)`; old of 0 always passes
- [x] Verify: `uv run pytest tests/rules/test_archive.py -q` (hostile archives built in memory with `tarfile`)
- Dependencies: none · Files: `archive.py`, `tests/rules/test_archive.py`

### Checkpoint: Tasks 1-2
- [x] Tests green; `uv run ruff check src tests`; `uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules` clean

## Task 3: Ports, config, state (M)
`ports.py`, `config.py`, `state.py`.
- [x] `Downloader` Protocol (`async get(url, max_bytes) -> bytes`); `UrllibDownloader` via `asyncio.to_thread`, HTTPS only, rejects over-cap bodies, raises `DownloadError` for HTTP and network errors; tested against a local `http.server`
- [x] `Validator` Protocol (`async check(conf: Path) -> ConfigCheck`); `SnortValidator(paths, runner)` picks the loopback (else first) interface, calls `check_config(..., conf=conf)`
- [x] `SensorControl` Protocol (`state`, `async restart()`)
- [x] `RulesConfig` frozen dataclass: `paths`, `url`, `min_ratio=0.5`, `health_timeout=60.0`, `max_download=100 MB`, `home_net_default`
- [x] `RulesState` + `load_state` / `save_state` (`rules-state.json` beside the rules dir, atomic write, missing or corrupt file gives empty state)
- [x] Verify: `uv run pytest tests/rules -q -m "not snort"`
- Dependencies: none · Files: `ports.py`, `config.py`, `state.py`, `tests/rules/test_ports.py`, `test_state.py`

## Task 4: Update, happy path (M)
`service.py`: `RulesService(config, downloader, validator, sensor, bus, *, clock)`.
- [x] Same md5 as `state.last_md5` gives `UpToDate`: tarball never fetched, no restart, no event swap; `force=True` overrides
- [x] Good update: overlay into `rules.new`, protected files untouched, temp conf validated, 3-step swap, old set in `rules.prev`, one `sensor.restart()`, state saved, `RulesUpdated(ok=True, rule_count, detail)` published
- [x] Sensor STOPPED before the update: no restart, no health gate
- [x] Returns an `UpdateReport` (outcome, rule_count, md5, skipped members)
- [x] Verify: `uv run pytest tests/rules/test_update.py -q` (fake downloader, fake validator, fake sensor, real temp dirs)
- Dependencies: Tasks 1-3 · Files: `service.py`, `tests/rules/rules_fakes.py`, `test_update.py`

## Task 5: Update failures and rollback (M)
Same `service.py`, new tests in `tests/rules/test_update_failures.py`.
- [ ] Parametrised failures: download error, md5 mismatch, oversize, hostile archive (nothing extracted), sanity ratio, `-T` failure (first error lines in the detail), each of the 3 renames failing (undo path), sensor not RUNNING within `health_timeout` (rollback + second restart)
- [ ] After every failure: `rules/` byte-identical to before (hash of the tree), no `rules.new` / `rules.swap` left behind, `RulesUpdated(ok=False, detail)` published, state not advanced
- [ ] Two concurrent calls (update + mute) run one after the other (lock), never interleaved
- [ ] Verify: `uv run pytest tests/rules -q -m "not snort"`
- Dependencies: Task 4 · Files: `service.py`, `test_update_failures.py`

### Checkpoint: Tasks 3-5
- [ ] All failure injections green; whole rules unit suite under 3 s; ruff and strict mypy clean

## Task 6: Mute, unmute, home-net (M)
`service.py` additions.
- [ ] `mute(sid, note="", restart=True)` / `unmute(sid, restart=True)`: idempotent; candidate `threshold.conf` validated through a temp conf with the include rewritten; `os.replace` commit; one-time `threshold.conf.snorty.bak`; validation failure leaves the file unchanged
- [ ] `muted()` returns the block's entries
- [ ] `set_home_net(value=None)`: default from config; changes only the HOME_NET line; same validate-commit-backup path (`snort.conf.snorty.bak`); `home_net()` shows current and default
- [ ] Sensor restarted when `restart=True` and the sensor was not STOPPED
- [ ] Verify: `uv run pytest tests/rules/test_mute.py tests/rules/test_home_net.py -q`
- Dependencies: Tasks 1, 3 · Files: `service.py`, `test_mute.py`, `test_home_net.py`

## Task 7: CLI and real checks (M)
`__main__.py`, `tests/rules/test_rules_integration.py`.
- [ ] CLI subcommands exactly as in the spec; exit 0 on success or up to date, 1 on a failed update, 2 on bad arguments; prints progress lines per stage
- [ ] `@pytest.mark.snort`: copy `C:\Snort\rules` and `snort.conf` to a temp dir; real `SnortValidator` passes the good set and fails with a message when one rule is broken; real `C:\Snort` untouched (hash check before and after)
- [ ] Manual, recorded in the final summary: `python -m snorty.rules update` against the real URL, sensor back to RUNNING, `snort -T` still passes; `mute` / `muted` / `unmute` round trip on the real `threshold.conf`; `home-net --set` default applied (with the sensor stopped or restarted as appropriate); nothing left running
- [ ] Verify: `uv run pytest tests/rules -q -m snort`; manual commands above
- Dependencies: Tasks 3-6 · Files: `__main__.py`, `test_integration.py`

## Task 8: Close-out (S)
- [ ] Coverage for `snorty.rules` at least 90% from unit tests alone
- [ ] `grep -r subprocess src/snorty` still matches only `snort/` files; `snorty.rules` imports only `snorty.core`, `snorty.snort`, stdlib
- [ ] SPEC-rules.md Success Criteria boxes ticked; plan and todo boxes ticked except the "next module" one
- [ ] Verify: `uv run pytest -q -m "not snort" --cov=snorty.rules --cov-report=term-missing`; `uv run ruff check src tests`; mypy as above
- Dependencies: Task 7
