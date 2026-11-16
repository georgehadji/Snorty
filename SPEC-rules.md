# Spec: rules — V1

Module id: `rules` (from CAPABILITY-MAP.md). Depends on: alert-core, snort-adapter, sensor.

## Objective

Keep Snort's rules fresh and under the user's control without ever leaving Snort unable to start.

1. **Update:** download the Emerging Threats Open ruleset, stage it, check it with `snort -T`, swap it in atomically, restart the sensor, and roll back if anything fails.
2. **Mute / unmute:** silence a noisy rule by SID through a managed block in `threshold.conf`, reversibly, with no other text touched.
3. **HOME_NET:** fix the drift found earlier (`ipvar HOME_NET [192.168.1.0/24]` while Wi-Fi is on 192.168.10.x) by managing that one line.

User: the PC owner, via a CLI now and the dashboard later. Success: after `update`, Snort runs the new rules; after any failure, Snort runs exactly what it ran before.

## Assumptions (correct me or I proceed)

1. Source is `https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz` plus its `.md5` file. The md5 catches truncated or corrupt downloads. It is not authentication: HTTPS is the only trust anchor.
2. `C:\Snort\rules` is the live rules directory (`var RULE_PATH`), writable by the current user.
3. Snort 2.9 has no hot reload on Windows. A new ruleset or a mute takes effect only after a sensor restart (about 7 s).
4. Runtime stays stdlib only: `urllib` + `tarfile` + `hashlib` + `json`, run through `asyncio.to_thread`. No `httpx` (the map proposed it; not needed).
5. The ET archive replaces or adds `emerging-*.rules`. `local.rules`, `white_list.rules`, `black_list.rules`, `threatview_CS_c2.rules` are never touched.
6. Default HOME_NET becomes `[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]` (all private ranges). It never drifts when the NIC changes; the cost is some extra "internal" matches on other private networks. Override with `--home-net`.

## Architecture and patterns

- **Transaction script** (one function per use case) over a **pure core** and a thin imperative shell.
- **Pure core (no I/O):** `parse_md5`, `safe_members` (tar path checks), `render_block` / `apply_block` / `read_block` (managed block in `threshold.conf`), `set_home_net` (rewrites one conf line), `rewrite_rule_path` (temp conf pointing at the staging dir), `count_rules`, `sanity_ok`.
- **Shell (ports injected):** `Downloader` (fetch bytes), `Validator` (`snort -T` on a conf path, wraps `snorty.snort.check_config`), `SensorControl` (`state`, `restart()`; satisfied by `Sensor`), `clock`. Tests use fakes; one integration test uses real Snort.
- **Stage, validate, commit/rollback** with a **Memento**: the previous ruleset stays in `rules.prev` until the next successful update.
- **Command pattern** for mute/unmute: each is reversible, idempotent, and validated before commit.
- One `asyncio.Lock` serialises update, mute, unmute and home-net changes.
- Publishes `RulesUpdated(ok, rule_count, detail)` on the bus after every update attempt.

## Update algorithm

1. Download `.md5`; if it equals `last_applied_md5` in `rules-state.json` and not `--force`, report "up to date" and stop.
2. Download the tarball; verify its md5. Size cap 100 MB.
3. Build `rules.new` = copy of the live rules dir, overlaid with the archive's `*.rules` files. (Overlay, not replacement: a category ET dropped but `snort.conf` still includes stays present, so `-T` does not fail on a missing include.)
4. Extract only regular files named `*.rules` whose path has no `..`, no absolute path and no drive letter, and which are not on the protected list (assumption 5). Anything else is skipped and counted.
5. Sanity: new rule count must be at least 50% of the live count, else abort.
6. Write a temp conf (copy of `snort.conf` with `var RULE_PATH` pointing at `rules.new`) and run `snort -T`. Failure aborts with the first error lines.
7. Swap: `rules` to `rules.swap`, `rules.new` to `rules`, `rules.swap` to `rules.prev` (old `rules.prev` removed first). Each rename checked; a failed step undoes the earlier ones.
8. `sensor.restart()`. If the sensor is not RUNNING within 60 s, roll back (`rules.prev` back to `rules`), restart again, and report failure.
9. Save `rules-state.json` (md5, time, rule count, result), publish `RulesUpdated`.

A sensor that was STOPPED before the update stays stopped (no restart, no health gate; the `-T` check is the gate).

## Mute / unmute

- Block in `threshold.conf`, between exact marker lines:

  ```
  # >>> snorty managed: do not edit between these markers >>>
  suppress gen_id 1, sig_id 2100498   # GPL ATTACK_RESPONSE id check returned root
  # <<< snorty managed <<<
  ```

- The block is the source of truth: `list_muted()` parses it back. Text outside the markers is preserved byte for byte, including line endings. No block yet: appended at the end.
- `mute(sid, note="")` / `unmute(sid)` are idempotent. SID must be a positive int (gen_id fixed at 1 in V1).
- After editing: write a temp conf whose `include threshold.conf` resolves to the candidate file, run `snort -T`; on failure leave the original file untouched. Commit is write-temp-then-`os.replace`, with a one-time `threshold.conf.snorty.bak` backup.
- `--restart` (default on) restarts the sensor so the change takes effect.

## HOME_NET

`set_home_net(conf_text, value)` replaces the single `ipvar HOME_NET ...` line, nothing else. Same temp-file, `-T`, `os.replace`, backup path as above. `show` prints the current value and the value that would be written.

## Commands

```
Test:      uv run pytest tests/rules -q -m "not snort"
Integr.:   uv run pytest tests/rules -q -m snort
Lint:      uv run ruff check src tests
Types:     uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules
CLI:       uv run python -m snorty.rules update [--force]
           uv run python -m snorty.rules status
           uv run python -m snorty.rules mute SID [--note TEXT] [--no-restart]
           uv run python -m snorty.rules unmute SID [--no-restart]
           uv run python -m snorty.rules muted
           uv run python -m snorty.rules home-net [--set VALUE]
```

## Project structure

```
src/snorty/rules/
  blocks.py     pure: managed-block read/apply/render, set_home_net, rewrite_rule_path
  archive.py    pure-ish: md5 parse, safe tar extraction into a dir, count_rules, sanity_ok
  ports.py      Downloader, Validator, SensorControl Protocols; UrllibDownloader, SnortValidator
  service.py    RulesService: update, mute, unmute, set_home_net, status (transaction scripts)
  state.py      rules-state.json read/write
  config.py     RulesConfig (frozen dataclass: paths, url, min_ratio, health_timeout)
  __main__.py   CLI
tests/rules/    test_blocks, test_archive, test_update, test_mute, test_home_net, test_integration
```

## Code style

Same as the other modules: frozen dataclasses, `Protocol` ports, injected `clock`, strict mypy, ruff (E,F,I,B,UP, 100 cols). Pure functions take and return `str`/dataclasses:

```python
def apply_block(text: str, entries: Sequence[Suppression]) -> str: ...
def safe_members(names: Iterable[str]) -> list[str]: ...
```

## Testing strategy

- Pure core: unit tests, including hostile tar members (`../x.rules`, `C:\x.rules`, absolute, symlink, device) and CRLF/LF/mixed `threshold.conf`.
- Service: fake `Downloader` serving an in-memory tar, fake `Validator` (scriptable pass/fail), fake `SensorControl`; real temp directories for the swap. Failure injection at every step (download, md5, extract, validate, each rename, sensor restart) with an assertion that the live directory is byte-identical to before.
- `@pytest.mark.snort`: copy `C:\Snort\rules` to a temp dir, run the real validator on a good staged set (passes) and on one with a broken rule (fails with a message). Never touches the real live rules.
- No test downloads from the internet. The real download is a manual check.
- Coverage of `snorty.rules` at least 90% from unit tests alone.

## Boundaries

- **Always:** validate with `snort -T` before any commit; write to temp then `os.replace`; keep a backup of any file edited in place; verify md5; log each step.
- **Ask first:** any new dependency; editing `snort.conf` beyond the `HOME_NET` line; changing which rule categories `snort.conf` includes; automatic scheduling on a timer in the real app (wired in the dashboard module).
- **Never:** touch `local.rules` or the white/black lists; extract outside the staging dir; leave `rules/` missing or half-swapped; delete `rules.prev` before a newer good set exists; run `snort -T` or `-c` against the live conf with an unreviewed file.

## Success Criteria

- [ ] 1. A good update (fake archive) replaces `emerging-*.rules`, keeps `local.rules` and the lists byte-identical, leaves the old set in `rules.prev`, restarts the sensor once, and publishes `RulesUpdated(ok=True, rule_count, ...)`.
- [ ] 2. Failure at each step (download error, md5 mismatch, oversize, hostile archive, sanity ratio, validation failure, rename failure, sensor not RUNNING after restart) leaves `rules/` byte-identical to before, the sensor running the old set, and publishes `RulesUpdated(ok=False, detail)`.
- [ ] 3. A tar with path traversal, absolute or drive paths, symlinks or non-`.rules` files writes nothing outside the staging dir; skipped members are counted in the report.
- [ ] 4. Same md5 as the last applied update: no download of the tarball, no restart, reported as up to date; `--force` overrides.
- [ ] 5. An update with a STOPPED sensor does not start it.
- [ ] 6. `mute`/`unmute` are idempotent; text outside the markers is preserved byte for byte (CRLF and LF); `muted` lists what the block holds; a mute that fails `-T` leaves `threshold.conf` unchanged.
- [ ] 7. `set_home_net` changes only the `ipvar HOME_NET` line; a missing line is an error, not an insert; `-T` failure leaves the file unchanged.
- [ ] 8. Concurrent calls are serialised (second waits), never interleaved.
- [ ] 9. `@pytest.mark.snort` validation test passes on this PC (good set passes, broken rule fails) without touching `C:\Snort\rules`.
- [ ] 10. Manual: `python -m snorty.rules update` against the real ET URL succeeds, the sensor comes back RUNNING, and `snort -T` on the live conf still passes; `muted`, `mute`, `unmute` round-trip on the real `threshold.conf`; HOME_NET set to the new default.
- [ ] 11. `ruff check`, strict mypy on `snorty.rules`, coverage at least 90%; `snorty.rules` imports only `snorty.core`, `snorty.snort`, and the `Sensor` protocol surface (`state`, `restart`); no `subprocess` outside `snort/`.

## Out of Scope (Deferred)

- Regenerating `sid-msg.map` (only needed for unified2 tooling; our alerts carry `msg` already).
- Enabling or disabling whole rule categories; editing `snort.conf` include lists.
- ET Pro / Snort Subscriber rules with an oinkcode.
- Hot reload, per-rule `rate_filter`/`event_filter`, gen_id other than 1.
- Signature verification beyond HTTPS plus md5 (ET publishes no detached signature for this feed).
- Running the daily schedule (the loop lives in the dashboard app; this module exposes `RulesService.update()` and a `run_daily` helper is deferred to that module).

## Open Questions

1. **HOME_NET default:** all private ranges (assumption 6), or only the active NIC's /24, re-synced at each sensor start? All-private never drifts; the /24 is tighter but needs the netmask and fails again when you change networks.
2. **Update time:** 04:00 local when the dashboard schedules it, or another hour?
3. **Writing to `C:\Snort`:** confirm your user can write there without admin (the earlier config edits suggest yes; an elevated prompt would change the CLI story).
