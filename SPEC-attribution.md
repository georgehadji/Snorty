# Spec: attribution (as built)

## Objective

Say which program on this PC made or received the connection behind a live TCP or UDP alert, and
store that answer with the alert so the alert detail can show it. It does not attribute old or
backfilled alerts, alerts where neither end is this PC, or protocols other than TCP and UDP
(`src/snorty/attribution/service.py`).

## Architecture and patterns

- Feature service with its own ports. import-linter names it in "core is the domain", "only the
  process adapters ... run processes" (it may not import `subprocess`), "feature modules never
  reach up" and the "sibling features do not know each other" independence contract
  (`pyproject.toml`, `[tool.importlinter]`).
- Observer: `AttributionService` subscribes to the event bus and handles `AlertRaised` only
  (`attribution/service.py:46`, `_wants` at line 89).
- Chain with a Null Object: the live table is asked first, then a `ConnectionHistory`; with no
  history the service uses `NoHistory`, which always answers None (`attribution/ports.py:28`,
  `service.py:38`).
- Wiring: `compose.py:227-229` builds `AttributionService(bus, repo, WinConnectionLookup(),
  find_local_ip, _connection_history())` when `host_context` is true; the dashboard always passes
  `host_context=True` (`dashboard/__main__.py:134`). `_connection_history()` returns
  `SysmonHistory()` when `winevt.probe()` finds the log readable, else `NoHistory()` and one log
  line saying why (`compose.py:104-110`).

## Ports

All in `src/snorty/attribution/ports.py`; the result type is `Owner(pid, image)`, with `image`
empty when the program path cannot be read.

- `ConnectionLookup.owner(proto, local_ip, local_port) -> Owner | None`: who holds the endpoint
  now. Adapter: `winnet.WinConnectionLookup` (see `SPEC-winnet.md`). If the table cannot be read
  the adapter raises `OSError`; the service logs it and stores nothing for that alert
  (`service.py:60-63`).
- `ConnectionHistory.find(proto, local_ip, local_port, around) -> Owner | None`: who a log saw on
  the endpoint near `around`. Adapter: `winevt.SysmonHistory`, which returns None when the log
  cannot be read. `NoHistory` is the Null Object.

## Behaviour and invariants

1. Only `AlertRaised` events with proto TCP or UDP enter the queue; the queue holds 500 and keeps
   the oldest, so in a burst the newest events are dropped (`service.py:46`, `core/bus.py:24-37`).
2. Each lookup runs in a worker thread (`asyncio.to_thread`); one failing lookup is logged and the
   consumer keeps going (`service.py:57-63`).
3. Nothing is done when the alert has no id, the local address is unknown, or neither the source
   nor the destination equals the local address (`service.py:67-76`).
4. The local end is the source when `src_ip` is the local address, else the destination
   (`service.py:71-74`).
5. The live table is asked first; the history only when the table answers None, with the alert's
   timestamp as `around` (`service.py:78-80`).
6. The answer is stored as annotation kind `"process"` with JSON value `{"found": false}` or
   `{"found": true, "pid": ..., "image": ..., "via": "table" | "sysmon"}` (`service.py:17,81-86`).
   A miss is stored too, so the page can say the connection had already closed.
7. `repo.annotate` replaces an earlier note of the same kind and skips an alert pruned meanwhile
   (`core/repository.py:485-494`).
8. The dashboard renders the note; `via == "sysmon"` adds ", from the Sysmon log", and a note that
   is not valid JSON is shown as none (`dashboard/context_routes.py:33-47`).

## Security and privacy

- Inputs are the alert's own addresses and ports; nothing from the user reaches the lookup.
- No network traffic: the table and the Sysmon log are read locally through ctypes. Nothing leaves
  the PC.

## Tests

- `tests/core/test_host_context.py`: local end chosen and stored, a miss recorded as not found,
  non-local or non-TCP/UDP alerts skipped, live alerts attributed through the bus.
- `tests/core/test_sysmon.py`: the log is asked only when the table has forgotten (`via`
  "sysmon"), and with `NoHistory` a forgotten connection is still "not found".
- `tests/dashboard/test_dash_alerts.py` covers the rendered note.

## Deviations and known limits

- The lookup runs about one poll after the packet, so a short connection can be gone from the
  table; without Sysmon such alerts show "not known" (`service.py:21-24`).
- The connection tables read are IPv4 only (`winnet/lookup.py:15,58`).
