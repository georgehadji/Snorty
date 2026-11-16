# Spec: rule-lab — V1

Module id: `rule-lab` (package `snorty.lab`). Depends on: `alert-core`, `snort-adapter`. Map: `CAPABILITY-MAP.md`.

## Objective

Write a Snort rule, point it at a pcap, and see exactly which packets it matches, without touching your live sensor, config or rules. Also build small test pcaps from the command line so you can try a rule on traffic you control.

User: you, learning and writing rules. Success: you paste one or two rules, pick a pcap (or generate one), and get back either a clear error on the right rule line or a table of matches with a hit count per rule, including rules that matched nothing. Your live `snort.conf`, `rules\`, `threshold.conf` and log folder are byte-for-byte the same afterwards.

## Assumptions (correct me or I proceed)

1. **Pcap sources:** files you give it, plus pcaps the lab builds itself from a few hand-described packets (the map's open question 3). No downloads of public sample pcaps, and no live recording in V1.
2. **Realistic sandbox:** the lab config is your live `snort.conf` with every `include` of a rules file, preprocessor-rules file and `threshold.conf` removed, plus one include of the lab rules. Preprocessors (stream, http_inspect) stay, so `flow:` and `http_*` options behave like the live sensor. Your live mutes do not apply in the lab.
3. Because Snort resolves relative includes next to the config, the temp config is written beside `snort.conf` as `snorty-lab-<id>.conf` and deleted afterwards (same method as the rules module). Everything else (rules file, logs) lives in a temp folder.
4. Lab rules may only be `alert`, `log` or `pass`. Any other line (`include`, `var`, `config`, `preprocessor`, `drop`, `reject`, anything not a rule) is refused before Snort sees it. A rule without `sid`, a duplicate `sid`, more than 200 rules, or text over 64 KB is refused.
5. Pcaps are untrusted data: size cap 50 MB, read only, never copied into the live folders, Snort gets a timeout.
6. Alert times in the result use the current year (Snort's fast format has no year); the lab compares packets, not dates.
7. One lab job at a time. The live sensor can keep running; the lab uses its own temp log folder and `-r`, so it never opens the network adapter for capture.
8. The temp folder path must have no spaces (Snort `include` takes unquoted paths); a path with spaces is reported as an error, not guessed around.
9. Stdlib only. No new dependency. All Snort calls go through the existing `Runner` in `snorty.snort`; no `subprocess` in `lab`.

## Architecture and patterns

- **Functional pipeline over a job (Command):** `LabJob(rules_text, pcap)` goes through `lint` → `sandbox` → `snort -T` → `snort -r` → `summarize`. Each stage is a small function; the first failure stops the pipeline and is returned as data (`LabResult`), never raised for a user mistake.
- **Pure core:**
  - `lint(text) -> LintResult` (rules with line numbers, or problems with line numbers).
  - `build_lab_conf(live_conf_text, rules_path) -> str` (Builder).
  - `build_pcap(packets) -> bytes` and `tcp_packet(...)`, `udp_packet(...)` for the pcap generator (classic libpcap, Ethernet/IPv4, hand-made checksums not required because the lab runs Snort with `-k none`).
  - `summarize(rules, alerts) -> list[RuleHit]` (hit count per lab rule, zeros included, matches in time order).
- **Imperative shell (Sandbox):** `LabSandbox` is an async context manager that creates the temp folder, writes `lab.rules`, writes the temp config beside `snort.conf`, and always removes both, also on cancel. Stale `snorty-lab-*.conf` older than 1 hour are removed at the start of each job.
- **Reuse:** `snorty.snort.check_config`, `run_pcap`, `list_interfaces`, `pick_interface`, `Runner`. The lab adds no new Snort command line.
- **Concurrency:** one `asyncio.Lock`; a second job waits.
- **Error mapping:** Snort's rule errors name `lab.rules(N)`; the result shows them as "rule line N: ...", matching the lines you typed.

## Behaviour

**`LabResult`** (frozen dataclass): `ok: bool`, `problems: tuple[Problem(line, message)]` (lint and Snort rule errors), `error: str | None` (pcap or Snort failure that is not about a rule), `hits: tuple[RuleHit(sid, msg, line, count)]`, `matches: tuple[Alert]` (time order), `packets_note: str | None`.

**Pipeline stops:**

1. Lint problems: `ok=False`, no Snort run.
2. Pcap missing, not a file, or over 50 MB: `error`, no Snort run.
3. `snort -T` fails: Snort's rule errors mapped to lab lines; `ok=False`, no pcap run. Other `-T` errors go to `error`.
4. `snort -r` fails or times out: `error` with the last lines of Snort's output.
5. Otherwise `ok=True`: `hits` lists every lab rule with its count (zero included); `matches` lists the alerts.

**Lab config rewrite** (`build_lab_conf`): drop lines matching `include $RULE_PATH/*.rules`, `include $PREPROC_RULE_PATH/*.rules` and `include threshold.conf`; append `include <abs temp path>/lab.rules`. Every other byte of the config is kept.

**Pcap generator:** `python -m snorty.lab make-pcap` writes a classic pcap with N copies of one TCP or UDP packet carrying a payload, e.g. `--payload "uid=0(root)" --dport 80`. Defaults: TCP, 10.0.0.1:4444 to 10.0.0.2:80, ACK+PSH flags. TCP streams for `flow:established` rules get a SYN, SYN-ACK and ACK before the data when `--handshake` is given.

## Commands

```
Test:   uv run pytest tests/lab -q -m "not snort"
Real:   uv run pytest tests/lab -q -m snort          # needs C:\Snort
Lint:   uv run ruff check src tests
Types:  uv run mypy src/snorty/core src/snorty/snort src/snorty/sensor src/snorty/rules src/snorty/notify src/snorty/journal src/snorty/lab
CLI:    uv run python -m snorty.lab check RULES_FILE
        uv run python -m snorty.lab run RULES_FILE PCAP [--json]
        uv run python -m snorty.lab make-pcap --out FILE --payload TEXT [--proto tcp|udp] [--src IP] [--sport N] [--dst IP] [--dport N] [--count N] [--handshake]
```

Exit codes: 0 ok, 1 rule or run problems (printed), 2 usage.

## Project structure

```
src/snorty/lab/
  lint.py       lint(), LabRule, Problem, LintResult (pure)
  conf.py       build_lab_conf() (pure)
  pcapgen.py    build_pcap(), tcp_packet(), udp_packet() (pure)
  models.py     LabJob, LabResult, RuleHit
  service.py    LabService (pipeline, sandbox, lock)
  __main__.py   CLI
tests/lab/      test_lab_lint, _conf, _pcapgen, _service, _cli, _real, lab_fakes
```

Test file basenames are unique across test folders.

## Code style

Frozen dataclasses, `Protocol` ports (reuse `Runner`), no shell strings, strict mypy, ruff (E,F,I,B,UP, 100 cols). Pipeline shape:

```python
async def run(self, job: LabJob) -> LabResult:
    """User mistakes come back as data in LabResult; only programming errors raise."""
```

## Testing strategy

- Pure core: unit tests for `lint` (every refusal, line numbers, duplicate sid, caps, valid multi-rule text, CRLF, comments and blank lines), `build_lab_conf` (golden on a small sample conf; the real `snort.conf` in a snort-marked test), `build_pcap` (exact bytes for a known packet, readable back by a tiny parser in the test), `summarize` (zero-hit rules, ordering).
- Service: fake `Runner` that scripts `-T` and `-r` outputs and writes a fixture `alert.ids`; assertions on pipeline stops, error line mapping, sandbox cleanup after success, failure and cancellation, lock behaviour, live files untouched (hash before and after).
- Real Snort (`-m snort`): a generated pcap triggers a lab rule; a non-matching rule shows 0; a deliberately broken rule gives an error on the right line; hashes of live `snort.conf`, `rules\`, `threshold.conf` and `log\` unchanged; no leftover `snort.exe` or temp config.
- Manual check in the final summary: I run the CLI with a rule you could have written and report the table.
- Coverage of `snorty.lab` at least 90% from unit tests alone.

## Boundaries

- **Always:** lint before Snort; write the temp config only beside `snort.conf` under the `snorty-lab-` name and delete it; give every Snort call a timeout; keep live files untouched.
- **Ask first:** promoting a lab rule into live `local.rules`; downloading pcaps; recording live traffic; allowing actions other than `alert`, `log`, `pass`; new dependencies.
- **Never:** edit `snort.conf`, `rules\`, `threshold.conf` or the live log folder; run Snort with a rules file the lint refused; use `subprocess` in `lab`; send pcap or rule data off the machine; raise for a user's bad rule.

## Success Criteria

- [x] 1. `lint` accepts valid `alert`/`log`/`pass` rules with comments and blank lines, and refuses (with line numbers) any other line, a missing `sid`, a duplicate `sid`, more than 200 rules, text over 64 KB, and control characters.
- [x] 2. `build_lab_conf` removes exactly the rules, preprocessor-rules and `threshold.conf` includes, appends one lab include, and keeps every other byte; on the real `snort.conf` the result passes `snort -T`.
- [x] 3. Bad lab rules (Snort syntax error) give `ok=False` with the error on the right lab rule line and no pcap run.
- [x] 4. A valid rule plus a pcap gives `ok=True`, every lab rule's hit count (zeros included) and the matching alerts in time order.
- [x] 5. A missing, non-file or over-50-MB pcap gives `error` before any Snort run.
- [x] 6. After success, lint failure, Snort failure, timeout and cancellation: the temp config and temp folder are gone, and hashes of live `snort.conf`, `rules\`, `threshold.conf` and the log folder are unchanged.
- [x] 7. Stale `snorty-lab-*.conf` older than 1 hour are removed; younger ones and other files are left alone.
- [x] 8. Two jobs started together run one after the other.
- [x] 9. `build_pcap` output is a valid classic pcap (checked by a reader in the test); with real Snort, a generated packet triggers a rule on its payload, and `--handshake` makes a `flow:established` rule match.
- [x] 10. Hostile rules text (`include /etc/passwd`, `config`, `preprocessor`, binary bytes, a 10 MB string) is refused before Snort runs.
- [x] 11. CLI: `check`, `run` (plain and `--json`) and `make-pcap` work and use the exit codes above.
- [x] 12. Manual: a rule I write matches a generated pcap, an unrelated rule shows 0, and a broken rule shows its line; live Snort files unchanged; no leftover `snort.exe`.
- [x] 13. `ruff check`, strict mypy on `snorty.lab`, coverage at least 90%; `snorty.lab` imports only `snorty.core`, `snorty.snort` and stdlib; no `subprocess` in our `src/snorty` outside `snort/`.

## Out of Scope (Deferred)

- Promoting a lab rule to live `local.rules` (touches the rules module; ask first).
- Downloading sample pcaps, recording traffic, pcapng generation.
- Rule autocompletion, rule linting beyond what Snort itself reports, rule-quality hints ("content too short").
- Saving lab sessions and a result history (the dashboard can add it).
- Packet-level view (payload bytes of the matching packet); Snort's fast alert output has no payload.
- IPv6 packets in the generator.

## Open Questions

1. **Pcap sources:** your own files plus the built-in generator, no downloads and no recording (assumption 1). OK?
2. **Allowed actions:** only `alert`, `log`, `pass`. OK, or do you want `drop` and `reject` accepted for study?
3. **Live mutes:** the lab ignores them and keeps your preprocessors (assumption 2). OK?
4. **Promote to live:** deferred. Do you want it in V1 (it would call the rules module and need your confirmation each time)?

## Built-in deviations (as built)

- `LabSandbox` is a plain sync context manager (not async): it only touches the file system.
- `LabService.check(rules_text)` added (lint + `snort -T`, no pcap) for the `check` CLI command.
- `summarize(rules, alerts)` returns a `(hits, matches)` tuple, not a `LabResult`.
- Real Snort: error line numbers from `snort -T` matched the user's lines; the lab conf built from the CRLF `snort.conf` with a Windows temp path passes `snort -T`; `--handshake` makes `flow:established` rules match. Manual run took about 0.4 s. `snorty.lab` coverage 97% from unit tests.
- Temp paths containing whitespace are refused as an error (Snort `include` cannot take them); not hit on this machine.
