# Plan: Wireshark integration — V1

Status: draft for approval. Companion to `CAPABILITY-MAP.md`; once approved, write `SPEC-packets.md` from section 3 and break each phase into `tasks/todo.md` entries.

## 1. Objective

Make every alert provable: show the packet behind it, decode it, and give the user a one-click path into Wireshark; add tshark-based inspection to the rule lab and a time-boxed capture that feeds the lab. Everything optional: without Wireshark installed Snorty behaves exactly as today, and the pure helpers (display-filter generation) still work.

Order requested: **tshark decode first**, then the rest. The phases in section 6 follow that order and each ends in something usable.

## 2. Facts this plan rests on (verified 2026-11-16)

| Fact | Evidence |
|---|---|
| Wireshark, tshark and dumpcap are **not installed** on this PC. | No install folder under Program Files, nothing on PATH. |
| Snort already writes packet logs of alert packets: `C:\Snort\log\snort.log.<start-epoch>`, one per Snort start, 26 files now. | Directory listing. |
| Those logs are classic libpcap (magic `d4c3b2a1`, little-endian), Ethernet link type, **microsecond** timestamps. Runs with no alerts leave a 24-byte header-only file. | Hex dump of two files. |
| `alert_fast` lines carry microsecond times (`11/16/26-21:39:02.820139`), so an alert can be matched to its exact packet timestamp. | `alert.ids`. |
| The live command is `snort -c … -i <index> -l C:\Snort\log -A fast -y`; the packet log comes from Snort's default logger, not from a config `output` line (`log_tcpdump` is commented out in `snort.conf`). | `snort/commands.py:21`, `snort.conf:531`. |
| Import-linter forbids `subprocess` everywhere except `snorty.snort` ("only snort runs processes"). | `pyproject.toml` contract 2. |
| Pcap uploads are capped at 50 MB and referenced by bare name inside one folder. | `dashboard/pcaps.py`. |
| The lab already builds classic pcaps (`lab/pcapgen.py: build_pcap`) and runs Snort on them through the `Runner` Protocol. | `lab/pcapgen.py`, `snort/runner.py`. |

## 3. Architecture

### 3.1 Placement, respecting the existing rules

Two new top-level packages, in the same hexagonal shape as the rest of the project:

```
snorty/
  packets/      pure domain + application service + ports      (no processes, no network)
  wireshark/    process adapters: tshark, dumpcap, Wireshark GUI (implements packets' ports)
  dashboard/    packets_routes.py + templates                    (calls the service through Services)
  compose.py    builds the adapters, injects them                (the only place that knows both)
```

- `packets` depends only on `core` (it needs `Alert`). It never imports `wireshark`, `snort`, `lab` or any sibling.
- `wireshark` depends only on `packets` (ports and models) and the standard library. It does **not** import `snort`: it carries its own small bounded runner (about 30 lines). Sharing `snort.SubprocessRunner` would couple two unrelated tools, and that runner has no output cap, which tshark needs.
- `lab` stays independent of `packets` and `wireshark`. The lab page gets its pcap summary because the **dashboard route** calls the packets service on the same pcap name, the way it already composes lab and pcap storage.
- The dashboard sees only the `PacketsPort` Protocol in `snorty/services.py`, same as the other modules.

### 3.2 Import-linter changes (part of phase 1, so the rules guard the new code from day one)

1. Contract "only snort runs processes" becomes "only the process adapters run processes": `snorty.wireshark` is simply not in the forbidden source list; `snorty.packets` is added to it.
2. Add `snorty.packets` and `snorty.wireshark` to "feature modules never reach up into the UI or the wiring".
3. New contract: `snorty.packets` must not import `snorty.wireshark` (type `forbidden`), so the port boundary is enforced, not conventional.
4. Add `snorty.packets` to the "sibling features do not know each other" independence list. `snorty.wireshark` is excluded from that list because it implements `packets`' ports by design.

### 3.3 Paradigm and pattern per module

| Module | Paradigm | Patterns | Why |
|---|---|---|---|
| `packets.pcapfile` | Pure functions over `bytes`; immutable `Frame` dataclass | Parser, Writer; generators with hard caps | Stdlib `struct` is enough (classic pcap only, no pcapng); no I/O makes it trivially testable and fuzzable |
| `packets.filters` | Pure functions | Builder with validation (IPs through `ipaddress`, ports as `int`) | A display filter built only from typed values cannot be injected into; no free text is ever passed to tshark |
| `packets.match` | Pure function over frames + alert | Scoring, result as a closed union (`Exact`, `Near`, `Ambiguous`, `NotFound`) | Matching is heuristic; the type forces the UI to state the confidence |
| `packets.enrich` | Pure functions over decoded views | Table-driven extractors (field path → label) | New hints are one table row, no new code paths |
| `packets.models` | Frozen, slotted dataclasses; `match` statements | Algebraic result types (`Decoded | Unavailable | Failed`) | Same "errors as data" convention as `LabResult`; no exceptions for user-visible conditions |
| `packets.ports` | Protocols | Ports and adapters; **Null Object** (`NoDecoder`, `NoRecorder`, `NoViewer`) | The service never branches on "is tshark installed"; the Null adapters return `Unavailable` |
| `packets.service` | Application service (small imperative shell) | Facade; bounded LRU cache keyed by (path, size, mtime, filter); `asyncio.Semaphore(2)` | One entry point for the UI; repeated clicks on one alert do not respawn tshark |
| `wireshark.discover` | Pure function with injected environment | Chain of Responsibility (config → env var → Program Files → PATH) | Deterministic tests; returns an immutable `Tools` or `None` |
| `wireshark.commands` | Pure functions | Command builders returning `list[str]` | Argv is reviewed as data, never a shell string |
| `wireshark.runner` | Imperative shell | Context-managed child with output cap, wall-clock timeout, kill on cancel | The only place bytes from a tool enter the process |
| `wireshark.tshark` | Adapter | Adapter (implements `Decoder`); parser is a pure `parse(json) -> tuple[PacketView]` with depth and length caps | Separates untrusted-output parsing from process handling |
| `wireshark.dumpcap` | Adapter | Adapter (implements `Recorder`); job-in-flight guard | Matches the rules-update and lab "one in flight" convention |
| `wireshark.viewer` | Adapter | Adapter (implements `Viewer`); fire-and-forget detached launch | The GUI outlives the request and is never awaited |
| `dashboard.packets_routes` | Thin controller | Same `add_*_routes(app, ui)` shape as lab and rules | No logic in routes |
| `dashboard.views` | Pure view-models | Existing `views.py` style | Templates only loop and print |

### 3.4 Data flow

```
alert row ──GET /alerts/{id}/packet──▶ packets_routes ──▶ PacketService.locate(alert)
                                                      │         │ reads snort.log.* (pcapfile)
                                                      │         ▼ match.locate → Exact/Near/…
                                                      └──▶ Decoder.decode(one-frame pcap, filter)
                                                                 ▼ tshark -r … -T json (wireshark.tshark)
                                          view-model ◀── parse ◀─┘
```

The decoder is always fed a **single-packet pcap rebuilt by `write_pcap`**, never the whole Snort log. That keeps tshark's input small, bounded and free of other users' traffic, and the same bytes are what "Download pcap" serves.

## 4. Security and privacy design (applies to every phase)

- tshark parses hostile traffic and has a long CVE history. Mitigations: argv list only, never a shell; fixed flags; `-n` (no name resolution, so no DNS lookups leak what the user inspects); `-c <limit>` packet cap; wall-clock timeout (20 s); stdout cap (2 MB) enforced while reading, process killed at the cap; stdin closed; a private temp profile dir via `WIRESHARK_CONFIG_DIR` so user plugins and Lua scripts are not loaded; only Snort-produced or user-uploaded files are ever passed.
- File arguments are resolved by the server: pcap by bare name in the pcap folder (existing `pcap_path`), Snort log by directory scan of `C:\Snort\log`. No client-supplied path reaches argv.
- Display filters come only from `packets.filters` (typed inputs). The optional "custom filter" box is validated against a strict character whitelist (`[A-Za-z0-9_.:!=<>&|() "']`, 200 chars) and still passes through argv, never a shell. Open question Q3: ship it in V1 or not.
- Tool output is data: every field is escaped by Jinja autoescape; strings are truncated; nesting depth and field counts are capped in `parse`.
- Wireshark GUI launch is POST-only (token and Origin check already in middleware), takes an alert id (never a path) and passes a server-built temp pcap.
- Extracted per-alert pcaps and capture files live under the Snorty data folder (`pcaps/`), covered by the existing 50 MB and retention habits; temp files are deleted after use.
- README security section gains: the tshark exposure, what is bounded, and that the feature is off unless the tools are found.
- Nothing is installed or downloaded by Snorty. The user installs Wireshark.

## 5. Testing strategy

- Pure modules: unit tests plus property tests (pcap write→read round-trip using `lab.pcapgen` frames as test data only; `read_frames` never raises on random bytes and never exceeds its caps).
- `parse` and the argv builders: fixtures of real tshark JSON committed under `tests/packets/fixtures/` (captured in phase 0), plus hostile fixtures (huge nesting, 10 000-field packet, invalid UTF-8, truncated JSON).
- Adapters: tested with a **fake runner** returning canned output, as the Snort code does. One new marker `tshark` (like `snort`) runs the real binary and skips when it is absent; `uv run pytest -m "not snort and not tshark"` stays the fast suite.
- `match.locate`: fixtures copied from the real `snort.log.1794779694` (654 bytes) and its alert line.
- Dashboard: route tests with a fake `PacketsPort`, asserting both the available and unavailable renderings; no inline styles (existing test) and a11y attributes on new controls.
- Architecture: `uv run lint-imports` must stay green with the new contracts.

## 6. Phases

Each phase leaves the app working, tests green (`ruff`, `mypy src`, `lint-imports`, fast suite) and is committed separately. Size: S = 1–2 files, M = 3–5, L = 5+.

### Phase 0 — Prerequisites and spikes (S, no code shipped)

- User installs Wireshark (it bundles tshark and dumpcap). In the installer, **keep the existing Npcap** rather than installing a second one.
- Spike A: run `tshark -r C:\Snort\log\snort.log.1794779694 -T json -n` and `tshark -r … -T json -x`; save outputs as fixtures; note the JSON shape of `-x` hex.
- Spike B: confirm `dumpcap -D` lists `\Device\NPF_{GUID}` names and `dumpcap -i <that> -a duration:3 -w x.pcap` works without admin.
- Spike C: confirm every `snort.log.*` is classic pcap and which packets they hold (alert packets only?).
- **Done when:** fixtures committed; the three answers recorded in `SPEC-packets.md` under "Verified facts".

### Phase 1 — Foundations and tshark decode (L) — *the starting point requested*

> **Progress (2026-11-16):** tasks 1.2–1.6 are implemented and tested with a fake runner and hand-made tshark JSON. Deviations: `packets.pcapfile` (task 1.1) is deferred to phase 4, where the reader and writer are first used; Phase 0 spikes are still open because Wireshark is not installed, so the JSON fixtures are hand-written and the `tshark`-marked test in `tests/wireshark/test_ws_real.py` is skipped until it is.

Task 1.1 `packets.models`, `packets.ports` (Null Objects), `packets.pcapfile` (reader and writer, caps) — M  
Task 1.2 Import-linter contract changes from 3.2 — S  
Task 1.3 `wireshark.discover`, `wireshark.commands`, `wireshark.runner` (bounded) — M  
Task 1.4 `wireshark.tshark` (`TsharkDecoder`) with `parse` and hostile-input tests — M  
Task 1.5 `packets.service` facade (capabilities, decode, LRU cache, semaphore); `Services.packets` + `PacketsPort`; `compose` wiring with `wireshark_dir` config key — M  
Task 1.6 Dashboard: `GET /packets/pcap/{name}` fragment (summary line, packet table, expandable layers, hex dump) and a collapsed "Packets" card on the Lab page listing the pcap's first 200 packets with a protocol column — M

- **Acceptance:** with tshark installed, choosing a pcap in the Lab shows its packets and per-layer details; with it missing, the card says "Wireshark not found" with the install hint and nothing else changes; a 50 MB pcap returns within the timeout showing "first 200 packets" and never exceeds the 2 MB output cap; killing the dashboard mid-decode leaves no stray tshark process.
- **Checkpoint 1:** review the decode view with the user before building on it.

### Phase 2 — Lab verification (S)

> **Progress (2026-11-16):** done, tested with real tshark 4.6.9 and real Snort. One `tshark -q -z io,phs -z conv,ip/ipv6/tcp/udp` pass; `wireshark.stats.parse_summary` is pure and capped (60 protocols, 50 conversations per kind). tshark prints conversation sizes with units ("31 kB"), so they are kept as the tool's text; frames and protocol bytes are exact. The route composes both services: after a run, `_lab_result.html` lazy-loads `GET /packets/summary?pcap=`, so the lab package is untouched and a tshark failure never hides rule hits. With no Wireshark the block renders nothing (Inspect already explains).
> Phase 0 facts learned on the way: tshark 4.6.9 is found in Program Files with no config; `dumpcap -D` lists `\Device\NPF_{GUID}` names without admin (an actual capture is still untested); `-n -q` text output is CRLF.

Reuses Phase 1. After **Check/Run**, the Lab result gains "What the pcap contains": protocol hierarchy and top conversations (`tshark -q -z io,phs` and `-z conv,tcp/udp` parsed by pure functions) next to the rule hits. A rule with zero hits shows which conversations exist so the user can see why it did not fire.

- **Acceptance:** an empty-hit run lists the pcap's protocols and conversations; summary parsing is covered by fixtures; the lab package is untouched (the route composes both services).

### Phase 3 — Display-filter helper (S, no external tool)

> **Progress (2026-11-16):** done. `alert_filter` and `conversation_filter` return `str | None` (None for an unparseable or mixed-family address). Addresses go through `ipaddress` (an IPv6 `%scope` is dropped), ports are range-checked, protocols come from a fixed table, so no alert text is ever pasted into a filter; a seeded fuzz test checks that. A real-tshark test confirms both filters compile and select 1 packet and 2 packets. Alert detail shows both with Copy buttons (`data-copy`, one delegated handler in `app.js`; falls back to selecting the text). The alert detail list is now stacked (label above value) because the table cell is narrow.

`packets.filters`: `alert_filter(alert)`, `conversation_filter(alert)` (both directions), proto-aware (`tcp.port`, `udp.port`, `icmp`). Rendered in the alert detail as a copyable code line (copy button uses existing JS, no inline script). Works even when Wireshark is absent.

- **Acceptance:** property tests show IPv4/IPv6 and port edge cases never yield a malformed or injectable filter; the string equals what the launcher passes in phase 4.

### Phase 4 — Alert → packet, download, open in Wireshark (L)

Task 4.1 `AlertRepository.get(id)`; `AlertRow.id`; routes keyed by id — S  
Task 4.2 `packets.match.locate` and the Snort-log reader (`logs.py`: list `snort.log.*` newest first, read with a size cap, skip header-only files) — M  
Task 4.3 `PacketService.locate/packet_pcap` and `GET /alerts/{id}/packet` (decoded single packet inside the alert detail, fetched on open) and `GET /alerts/{id}/packet.pcap` (download of the one-frame pcap) — M  
Task 4.4 `wireshark.viewer` and `POST /alerts/{id}/open` ("Open in Wireshark", shown only when the GUI is found) — S  
Task 4.5 Confidence in the UI: `Exact` quiet, `Near`/`Ambiguous` show "closest match, N candidates", `NotFound` says why (log rotated, packet not logged) — S

- **Matching rules:** key = protocol + src/dst address and ports + timestamp. Frames from Snort's log carry the same microsecond time as the alert, so the first pass requires equality within 1 ms (`Exact`); the second allows ±2 s and picks the nearest (`Near`); several equal candidates are `Ambiguous`. ICMP matches on addresses, type and time only.
- **Acceptance:** for the current real data (`ICMP test - ping detected`, hundreds of alerts) each alert resolves to `Exact`; downloading gives a pcap Wireshark opens showing one frame; with Wireshark missing the Open button is absent and Download still works (it needs no tool).
- **Checkpoint 2:** user verifies one alert end to end in Wireshark itself.

> **Progress (2026-11-16):** done except Checkpoint 2. `Alert.id` (excluded from equality) is set from the row id, also for live alerts via `add_new`; routes are keyed by it. The matcher is time-first and header-confirmed: frames on the alert's own microsecond (1 µs slack) are `Exact` (equal frames count as one packet; different frames on the same tick are `Ambiguous`); otherwise the nearest frame within 2 s whose headers agree is `Near`. An earlier 1 ms window made ICMP bursts (10 packets within 14 µs) look ambiguous, so the tick itself decides. Real data: 828 of 834 stored alerts resolve `Exact`; the other 6 are genuine ties (two different packets stamped the same microsecond), reported honestly as `Ambiguous`. Snort's own `snort.log.<epoch>` pcaps are the source (read with a 64 MiB cap, newest log first, at most 3 candidates), so no capture is needed. The packet is decoded from a one-frame temp file; the download is that file. `Open in Wireshark` writes `opened/alert-<id>.pcap` (swept after 24 h) and starts `Wireshark.exe -r` detached, only when the GUI is found. Verified in the dashboard: row expand loads the packet, download is a one-frame pcap tshark reads; the Wireshark launch itself is left to the user (Checkpoint 2).

### Phase 5 — Inline detail and enrichment (M)

`packets.enrich` extracts DNS query names, TLS SNI, HTTP host and URI from the decoded view and shows them as one line under the rule text (for example "ET INFO DNS lookup — `api.openai.com`"). Detail loads lazily when the alert row is opened (`hx-trigger="toggle once"`), so the table stays light. Optional second step: store the hint on the alert row (new nullable column, additive migration like the priority-0 fix); decide at Q4.

- **Acceptance:** table-driven extractor tests per protocol; no tshark call happens until a row is opened; the INFO alerts in the current data show a hostname when the packet has one.

> **Progress (2026-11-16):** done. Q4 decided: on demand only, no new column (nothing to migrate or keep in step with the packet). The parser collects five named fields (`dns.qry.name`, `tls.handshake.extensions_server_name`, `http.host`, `http.request.method`, `http.request.uri`) from anywhere in tshark's JSON tree, through lists and past the 3-level display cap (TLS SNI sits 5 levels deep), bounded at 5000 nodes / depth 12 and skipping `*_raw`. `PacketView.hints` carries them; `packets.enrich.hint` (pure) turns them into one line ("DNS lookup: x", "TLS to x", "GET host/path") with control characters replaced. The line is the first thing in the packet block when a row is opened; the table itself calls nothing (tested). Real tshark confirms all three protocols on hand-built packets; the stored alerts are all ICMP, so they show no line.

### Phase 6 — Time-boxed capture (M)

`wireshark.dumpcap.DumpcapRecorder` and `POST /lab/capture` (interface from the sensor's current choice via the existing `select_interface` hook in `compose`; duration 5–120 s, size cap 50 MB through `-a duration:N -a filesize:KB`). An in-flight guard returns "already capturing"; a fragment polls until done; the result is saved into the pcap folder with the existing name rules and appears in the Lab picker, then flows through phases 1–2.

- **Acceptance:** a 10 s capture produces a listed pcap; a second click during capture is refused; stopping the dashboard terminates dumpcap; nothing needs administrator rights (checked in Phase 0 spike B).
- **Risk:** two captures on one adapter (Snort plus dumpcap) are allowed by Npcap but double the CPU; the card says so.

### Phase 7 — Hardening and close-out (S)

README (feature, optional dependency, security model additions), `SPEC-packets.md` finalised with deviations, `snorty.toml` key documented, retention of extracted/captured pcaps (delete files older than the alert retention), full verification pass including the real-tshark marker, taste/a11y inspector on the new UI, and a manual browser check.

## 7. Dependency graph and order

```
P0 ──▶ P1 ──┬──▶ P2
            ├──▶ P3 ──┐
            └──▶ P4 ◀─┘──▶ P5
P1 ──▶ P6          all ──▶ P7
```

Order: 0, 1, 2, 3, 4, 5, 6, 7. P3 is placed before P4 because the launcher and the UI both consume the filter string. P2 and P3 are independent and can be swapped.

## 8. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| tshark parser bug triggered by hostile packets | Medium | Process isolation, caps, timeout, kill-on-cancel, single-packet input, no live feed, documented |
| Wireshark not installed or moved | Low | Null Object adapters; every UI element hides or explains; discovery chain includes a config override |
| Alert ↔ packet ambiguity | Medium | Typed result, confidence shown, nearest-match rule, never silently wrong |
| Snort logs rotate or are pruned | Low | `NotFound` with reason; retention documented |
| JSON shape differs between Wireshark versions | Medium | Parser tolerant of missing fields; fixtures from the installed version recorded; the `tshark` marker test catches drift |
| Decode latency on big pcaps | Low | `-c` cap, LRU cache, async with timeout, loading state on the htmx request |
| Scope growth into a general packet analyser | Medium | Non-goals below |

## 9. Non-goals

Live capture parity with Snort, replacing Snort's parser with tshark, pcapng writing, a packet browser beyond the first 200 packets, remote capture, editing packets, any network download or install by Snorty itself.

## 10. Open questions (decide at the checkpoints)

- Q1 (before P1): ship the Wireshark GUI launch only, or also an "Open in default app"? Plan assumes Wireshark only.
- Q2 (P0): if Snort logs prove incomplete (for example priority-0 alerts not logged), enable `output log_tcpdump` through the live command? That changes `snort/commands.py` and needs the sensor spec amended.
- Q3 (P3): include the free-text custom filter box in V1? Plan assumes **no**; only generated filters.
- Q4 (P5): persist enrichment on the alert row, or compute on demand only? Plan assumes on demand.
- Q5 (P6): is a 120 s capture limit acceptable?

## 11. Definition of done (whole integration)

All phases merged; fast suite, `tshark`-marker suite (with Wireshark installed), `ruff`, `mypy src` and `lint-imports` green; README and `SPEC-packets.md` updated; one end-to-end manual run from an alert to Wireshark; with Wireshark uninstalled the app passes its original suite and shows no broken controls.
