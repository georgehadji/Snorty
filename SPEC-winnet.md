# Spec: winnet (as built)

Covers `src/snorty/winnet/` (live connection tables) and `src/snorty/winevt/` (the Sysmon
connection log). Both are Windows adapters for the ports in `src/snorty/attribution/ports.py`.

## Objective

Answer "which process holds this local TCP or UDP endpoint" from Windows itself: now, from the
iphlpapi connection tables, and a few seconds ago, from Sysmon's network connection events
(Event ID 3). No subprocess and no third-party dependency: both use ctypes
(`winnet/lookup.py:1-2`, `winevt/sysmon.py:1-3`). They do not install or configure Sysmon.

## Architecture and patterns

- Adapters. Both are in "core is the domain" and "feature modules never reach up" but not in the
  `subprocess` or independence contracts (`pyproject.toml`, `[tool.importlinter]`). They import
  `Owner` from `snorty.attribution.ports`.
- Anti-corruption layer: raw table bytes and event XML are parsed by pure functions
  (`parse_tcp_rows`, `parse_udp_rows`, `parse_event_xml`, `query_xpath`) that tests call directly.
- Injected readers: `WinConnectionLookup(read=..., image=...)` and `SysmonHistory(read=...)` take
  the OS calls as parameters (`lookup.py:85-91`, `sysmon.py:181-183`).
- Wiring: `compose.py:228` passes `WinConnectionLookup()`; `compose.py:104-110` passes
  `SysmonHistory()` when `probe()` returns None, else `NoHistory()`.

## Ports

- `ConnectionLookup.owner` -> `WinConnectionLookup.owner` (`lookup.py:93`). Off Windows it returns
  None; if the table cannot be read after 5 tries it raises `OSError` (`lookup.py:59-63,95-96`).
- `ConnectionHistory.find` -> `SysmonHistory.find` (`sysmon.py:185`). An `OSError` from the reader
  is logged at debug level and gives None (`sysmon.py:188-192`).
- `probe(read=None) -> str | None`: None when the log can be read, else the reason
  ("not Windows", "Sysmon is not installed ...", "no permission ... (join Event Log Readers)")
  (`sysmon.py:118-123,166-174`).

## Behaviour and invariants

winnet (`src/snorty/winnet/lookup.py`):
1. Reads `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`) or `GetExtendedUdpTable`
   (`UDP_TABLE_OWNER_PID`), IPv4 only, growing the buffer and retrying up to 5 times
   (`lookup.py:15-17,52-63`).
2. Row layout: TCP six 32-bit values (pid last), UDP three; ports are network byte order in the
   low 16 bits (`lookup.py:28-49`).
3. Rows with pid 0 are ignored. An exact local address wins over `0.0.0.0` (`lookup.py:99-103`).
4. The program path comes from `OpenProcess(QUERY_LIMITED_INFORMATION)` and
   `QueryFullProcessImageNameW`; a process that cannot be opened gives an empty path
   (`lookup.py:66-78`).

winevt (`src/snorty/winevt/sysmon.py`):
5. Channel `Microsoft-Windows-Sysmon/Operational`, newest first, at most 20 events, window
   +/- 5 s around the alert, `EvtNext` timeout 1000 ms (`sysmon.py:19-21,141-163`).
6. The XPath filters on Event ID 3, the time window and the port on either end; the port is
   formatted as an integer (`sysmon.py:74-82`).
7. Each event is rendered as XML (buffer grown up to 3 times) and closed after use
   (`sysmon.py:126-138,156-162`).
8. `parse_event_xml` returns None for anything that is not a well-formed Event 3
   (`sysmon.py:47-67`). Matches must have the same protocol and the local IP and port on the
   source or the destination; the event nearest in time wins (`sysmon.py:193-206`).

## Security and privacy

- Only local OS APIs are called; nothing leaves the PC.
- The only value put into the XPath query is an `int`, so alert text cannot change the query
  (`sysmon.py:76`). Times are formatted from `datetime` (`sysmon.py:70-71`).
- Reading Sysmon needs read access to its log; Snorty stays unelevated and reports the reason.

## Tests

- `tests/core/test_host_context.py`: TCP and UDP row parsing and byte order, exact address over
  wildcard, pid 0 ignored; on Windows only (`skipif`), the real table names this process.
- `tests/core/test_sysmon.py`: XML parsing and rejects, the XPath, nearest record wins, inbound
  match on the destination, unreadable log gives no answer. Marker `sysmon` queries the real log
  and skips with the `probe` reason when Sysmon is missing or unreadable.

## Deviations and known limits

- `CAPABILITY-MAP.md:4` and the package list in `README.md` name `winnet` but not `winevt`.
- IPv6 connections are not looked up in the live tables (`lookup.py:15`).
- A port reused more than 20 times inside the window may miss the right event (`sysmon.py:21`).
