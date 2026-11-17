# Spec: triage (as built)

Covers `src/snorty/triage/` (the service) and `src/snorty/core/triage.py` (the domain model).

## Objective

Track whether someone has dealt with an alert (`new`, `ack`, `starred`) and apply archive rules:
saved filters whose matching alerts are acknowledged as they arrive, so known noise leaves the
inbox. Archived alerts stay stored and detected; they only leave the inbox
(`core/triage.py:1,19-21`). Triage never deletes alerts or mutes rules.

## Architecture and patterns

- `core.triage` is domain code (pure, imports only `core.query`); `triage` is a feature service
  in the `subprocess`, "never reach up" and independence contracts (`pyproject.toml`,
  `[tool.importlinter]`).
- Observer used as a dirty flag: the subscription's `accept` hook sets an `asyncio.Event` and
  returns False, so nothing is ever queued; a burst of alerts costs one pass
  (`triage/service.py:15-17,36,48-51`).
- Specification: an `ArchiveRule` holds an `AlertQuery` plus an optional host
  (`core/triage.py:17-27`); the repository turns it into SQL.
- Wiring: `compose.py:234` always builds `TriageService(bus, repo)`. Archive rules are created by
  the dashboard (`dashboard/triage_routes.py:73-102`).

## Ports

- `AlertRepository.apply_archive_rules(now) -> int` (`core/repository.py:478`), plus
  `add_archive_rule`, `archive_rules`, `delete_archive_rule` and `set_state`
  (`core/repository.py:414-476`). There is no separate Protocol.

## Behaviour and invariants

1. States are `new`, `ack`, `starred`; no stored row means `new`. The inbox is `new` and `starred`
   (`core/triage.py:10-12`).
2. The service sets its flag at start (for alerts stored while Snorty was down) and on every
   `AlertRaised` or `AlertsBackfilled` (`service.py:37,48-51`).
3. Each pass calls `apply_archive_rules` in a worker thread; an error is logged and the next
   arrival tries again (`service.py:53-62`).
4. A pass sets `ack` only on matching alerts with no triage row, so a user's own choice is never
   overwritten (`core/repository.py:435,478-483`).
5. The spec is stored as JSON with `sid`, `min_priority`, `src_ip`, `dst_ip` and `host`; time
   bounds are not stored, so they are ignored (`core/triage.py:46-69`).
6. Host rules: an alert matches when a flow fact of kind `dns` or `tls` on its flow equals the host
   or ends with `.` + host. `http` facts do not count (`core/triage.py:13,36-43`).
7. `host_matches` is the pure form of the same test, ignoring ASCII case only, as SQLite does
   (`core/triage.py:30-33`). LIKE wildcards in the host are escaped (`like_escape`).
8. Flow facts come from Suricata's EVE events: `dns` from A and AAAA answers for the alert's
   addresses, `tls` from the SNI (`core/decoder.py:202-204,219-228,246-254`). Because every
   arrival re-runs the rules, a fact stored after its alert is caught on a later pass.
9. Dashboard routes: `POST /triage/archive` (by sid, note from the latest message),
   `POST /triage/archive-host` (note "host X and its subdomains"), and
   `POST /triage/archive/{id}/delete`. Creating a rule applies the rules at once
   (`dashboard/triage_routes.py:73-102`).

## Security and privacy

- Sids and hosts from the browser are checked by `valid_sid` and `valid_host` before use
  (`dashboard/triage_routes.py:76,89`); SQL uses bound parameters (`core/triage.py:41-43`).
- All data stays in the local SQLite file.

## Tests

- `tests/core/test_triage_service.py`: matching alerts are acknowledged as they arrive.
- `tests/core/test_host_archive.py`: SQL and pure host match agree, only name facts count, a fact
  arriving after its alert is caught, specs from before hosts existed still load, migration eight.
- `tests/core/test_query.py`: archive rules acknowledge only untriaged alerts; pruned alerts take
  their triage rows along.
- `tests/dashboard/test_dash_host_archive.py`: the archive-host route.

## Deviations and known limits

- Host rules only work with Suricata, since only the EVE decoder produces flow facts
  (`core/decoder.py`; `README.md:21` says the same).
- Each pass runs one SQL statement per archive rule over all stored alerts
  (`core/repository.py:480-483`); cost grows with the number of rules.
