# Spec: packets — V1

Module ids: `packets` (ports, pure logic, service) and `wireshark` (the adapters that run Wireshark's tools). Depends on: alert-core (the `Alert` model). Written after the build, from `PLAN-wireshark-integration.md`; the deviations are listed at the end.

## Objective

Show the packet behind an alert, and let the owner look at it in Wireshark, without Snorty becoming a packet analyser.

- Decode a pcap (Lab) and summarise it (protocols, conversations).
- For an alert: find the packet Snort logged, show it decoded, say what it is for (DNS name, TLS SNI, HTTP host), offer a one-packet download, and open it in Wireshark.
- Give ready-made Wireshark display filters for an alert.
- Record live traffic for a few seconds into the pcap list.

User: the PC owner. Success: expanding any stored alert shows its packet with the confidence of the match; "Open in Wireshark" shows one frame; a 10 s recording appears in the Lab pcap list. With Wireshark missing, everything that needs no tool (download, filters) still works and the rest says why it is off.

## Assumptions

1. The user installs Wireshark (tshark, dumpcap and the program come with it). Snorty installs and downloads nothing. Tools are found from `wireshark_dir`, `SNORTY_WIRESHARK_DIR`, Program Files, then PATH.
2. Snort's live command writes `snort.log.<start epoch>` pcaps next to `alert.ids`, and a frame's timestamp equals its alert's to the microsecond (checked on 731 of 731 real alerts). No capture is needed to find an alert's packet.
3. Everything stays local. tshark runs with `-n`, so inspecting a packet sends no DNS query.

## Architecture and patterns

- **Ports and adapters.** `packets` imports only `core`. It defines `Decoder`, `Viewer` and `Recorder`; `wireshark` implements them (`TsharkDecoder`, `WiresharkViewer`, `DumpcapRecorder`). import-linter forbids the reverse and allows only the process adapters to run processes.
- **Null objects** (`NoDecoder`, `NoViewer`, `NoRecorder`) return `Unavailable(reason)`, so callers never test for "is it installed".
- **Errors as data.** Results are unions (`Decoded | Unavailable | Failed`, `AlertPacket | NotFound | Failed`, `Launched | Unavailable | Failed`, `Recorded | Unavailable | Failed`); the view layer matches on them.
- **Pure core.** `pcapfile` (read/write, capped, never raises), `match` (alert and frames in, verdict out), `filters`, `enrich`, `logs` (directory scan and capped read), and the tool-output parser `wireshark.parse`.
- **One entry point.** `PacketService` holds small LRU caches (decode, summary, alert packet) and a semaphore that limits concurrent tool runs.

## Behaviour

**Finding an alert's packet** (`match.locate`)

1. Candidate logs: `snort.log.<n>` with `n` at or before the alert, newest first, at most 3, each read up to 64 MiB, only frames within 2 s of the alert.
2. A frame on the alert's own microsecond (1 µs slack) whose headers do not contradict the alert is `Exact`. Equal frames count as one packet; different frames on the same tick are `Ambiguous`. Among several frames close in time, the tick decides, so ICMP bursts resolve.
3. Otherwise the nearest frame within 2 s whose headers agree is `Near`.
4. Nothing found: `NotFound` with a reason (folder unknown, no log before the alert, not in the log, log incomplete).

Real data: 828 of 834 stored alerts are `Exact`; the other 6 are `Near` or `Ambiguous`.

**Decoding.** The decoder is always given a one-frame pcap the service wrote (`write_pcap`), never the whole Snort log; the download serves the same bytes. tshark runs with `-n`, JSON output and hex dump, a time limit, an output cap and a private config directory, so no plugins load.

**Names (`enrich.hint`).** The parser collects `dns.qry.name`, `tls.handshake.extensions_server_name`, `http.host`, `http.request.method` and `http.request.uri` from anywhere in the JSON tree (bounded: 5000 nodes, depth 12, `*_raw` skipped). One line is built on demand when an alert row is opened; nothing is stored.

**Display filters.** `alert_filter` and `conversation_filter` return a string or `None`. Addresses go through `ipaddress`, ports are range-checked, protocols come from a fixed table; no alert text reaches a filter.

**Opening in Wireshark.** `POST /alerts/{id}/open` (token and Origin checked) writes `opened/alert-<id>.pcap` (swept after 24 h) and starts the Wireshark program with `-r file`, detached, with a fixed argv. The button exists only when the program is found.

**Recording.** `POST /lab/capture` with `seconds` 5 to 120. The adapter is the sensor's current one; its name must match `\Device\NPF_{GUID}` or the loopback device. `dumpcap -i dev -q -P -a duration:N -a filesize:50000 -w temp`, killed if it outlives its own stop time. One `Job` at a time; a hidden `.snorty-capture-*.tmp` is moved to `capture-<date>-<time>.pcap` on success, and a header-only file is discarded with a message. Stopping the dashboard cancels the job, kills dumpcap and removes the temp file. `capture-*.pcap` files older than `retention_days` are deleted in the daily prune (0 keeps all); uploads and other files are never touched.

## Routes

| Route | Purpose |
|---|---|
| `GET /packets/pcap?pcap=` | Decode a listed pcap (Lab Inspect) |
| `GET /packets/summary?pcap=` | Protocols and conversations |
| `GET /alerts/{id}/packet` | Decoded packet of an alert, with confidence and hint |
| `GET /alerts/{id}/packet.pcap` | One-frame download |
| `POST /alerts/{id}/open` | Open it in Wireshark |
| `POST /lab/capture`, `GET /lab/capture/status` | Record, poll |

Pcaps are named, never pathed (`pcaps.pcap_path`); alert ids are range-checked.

## Security

- Argv lists only, never a shell. Two places launch tools: `wireshark.runner.run_bounded` (tshark, dumpcap) and `wireshark.viewer` (the GUI); import-linter keeps it that way.
- Tool output is data: Jinja autoescape everywhere; strings, nesting, fields, packets and hex bytes are capped in the parsers.
- No client-supplied path reaches a command line; adapter names are matched against the form Snort lists.
- The feature is off unless the tools are found. The README security model states the exposure.

## Tests

- Pure modules: unit and seeded fuzz tests (`pcapfile`, `match`, `filters`, `parse`).
- Adapters: fake runner and fake launcher, as the Snort code does.
- Marker `tshark`: real tshark and dumpcap on generated packets and a short capture; skipped when Wireshark is absent. Fast suite: `uv run pytest -q -m "not snort"`.
- Dashboard: fake `PacketsPort`, both the available and unavailable renderings, no inline styles.

## Deviations from the plan

- `packets.pcapfile` arrived in phase 4, where it was first used.
- Matching is time-first with header confirmation and a 1 µs tick, not a 1 ms window (a window made ICMP bursts ambiguous).
- Names come from the parser (`PacketView.hints`) rather than from the flattened layers, because TLS SNI sits deeper than the display cap; `enrich.hint` only formats them.
- Enrichment is on demand only (Q4); no column was added.
- No custom display-filter box (Q3) and no "open in default app" (Q1). Q2 was not needed: Snort's own log holds the alerts.
- Recording stops at 120 s (Q5). dumpcap writes nanosecond-stamp pcaps; Snort 2.9.20 reads them, and the upload check accepts them.
- htmx now swaps 409 answers as well as 422.
- The background `Job` gained an explicit `state` (`Idle`, `Running`, `Errored`, `Done`).
- Capture retention was added to the daily prune (phase 7).

## Known limits

- Only Ethernet/IP frames are header-matched; other frames match on the exact tick only.
- Two different packets on the same microsecond cannot be told apart.
- A log over 64 MiB is searched only to that point, and the result says so.
- Recording needs the sensor to be running, since it records the sensor's adapter; Snort and dumpcap then share it.
- Force-killing the dashboard leaves a running dumpcap to finish by its own time limit.
