# Spec: enrich (as built)

## Objective

For each new alert with a public remote address, note what public data says about that address:
whether it is on a known-bad list, its country, its network owner (ASN) and its reverse DNS name.
A known-bad match also raises an `AlertFlagged` event. It does not look up private-only flows,
and it never blocks anything (`src/snorty/enrich/service.py`).

## Architecture and patterns

- Feature service. import-linter names it in "core is the domain", "only the process adapters ...
  run processes" (no `subprocess`), "feature modules never reach up" and the independence contract
  (`pyproject.toml`, `[tool.importlinter]`).
- Observer: subscribes to `AlertRaised` (`service.py:73`, `_wants` at line 177).
- Pipeline: an ordered list of `(kind, step)` pairs; each step that answers adds one note
  (`service.py:116-126`).
- One lookup structure: `RangeTable`, sorted ranges searched by bisection, used for the bad lists,
  country and ASN tables (`enrich/ranges.py:18-38`).
- Strategy by injection: `fetch` (download function) and `rdns` (`ReverseDns`) are parameters; with
  no `fetch` only files already on disk are used (`service.py:39-41,100`).
- Wiring: `compose.py:230-232` builds `EnrichService(bus, repo, data_dir / "enrich",
  fetch=urllib_fetch, rdns=ReverseDns())` when `host_context` is true (always, from the dashboard:
  `dashboard/__main__.py:134`).

## Ports

- `Fetch = Callable[[str], bytes]` (`enrich/fetch.py:8`). `urllib_fetch` raises `OSError` for a
  non-HTTPS URL, a body over 64 MiB, or any network failure; a failed download is logged and the
  old file kept (`service.py:162-169`).
- `ReverseDns.name(ip) -> str | None` (`enrich/rdns.py:31`): `OSError` from the resolver becomes
  None.
- `AlertRepository.annotate` and `note_seen` (`core/repository.py:485,576`).

## Behaviour and invariants

1. The remote address is the first of `src_ip`, `dst_ip` that is global; none means no notes
   (`service.py:27-35,112-114`).
2. Steps in order: `bad` (Feodo then DROP), `country`, `asn`, `rdns`. Each answer is stored as an
   annotation of that kind (`service.py:116-126`). A country is also recorded with
   `note_seen("country", ...)` (`service.py:127-128`).
3. A `bad` note publishes `AlertFlagged(alert, label)` (`service.py:96-97`); `notify` consumes it
   (`notify/service.py:69,90`).
4. Lookup work runs in a worker thread; one failing alert is logged and the consumer continues
   (`service.py:91-95`). The queue holds 500 and keeps the oldest (`service.py:73`).
5. Data files in the folder: `feodo.txt`, `drop.txt`, `dbip-country.csv`, `dbip-asn.csv`; a missing
   or unreadable file loads as an empty table (`service.py:133-144`).
6. `refresh` downloads a file only when it is missing or older than its age: Feodo and DROP 1 day,
   DB-IP 30 days. DB-IP URLs carry the current `YYYY-MM` and are gunzipped (`service.py:146-155`).
7. Each download is written to `<name>.part` and moved into place with `os.replace`, so a half
   file is never read (`service.py:170-172`). Tables reload only when a file changed (`line 102`).
8. The refresh loop runs at start and then every 24 h; any failure is logged and retried the next
   day (`service.py:99-106`).
9. Limits: download body 64 MiB, decompressed data 64 MiB, timeout 30 s (`fetch.py:10-11,26-32`).
10. Reverse DNS: cache of 2048 entries for 1 h, misses cached too, at most 4 lookups in flight,
    least recently used entry evicted first (`rdns.py:14-48`).
11. Labels: Feodo entries read "Feodo Tracker botnet C2"; DROP entries "Spamhaus DROP SBLnnn"
    (`ranges.py:66-82`). Bad lines in any source are skipped (`ranges.py:41-63`).

## Security and privacy

- Downloads go only to the four fixed HTTPS URLs (`service.py:23-24,149-155`) with
  `User-Agent: Snorty`; they carry no alert data.
- Reverse DNS sends the remote address to the PC's configured DNS resolver
  (`socket.gethostbyaddr`, `rdns.py:16`). That is the one way alert data leaves the PC here.
- Downloaded text is parsed with `ipaddress` and `csv`; invalid rows are dropped.

## Tests

- `tests/core/test_host_context.py`: range tables, DB-IP rows, Feodo and DROP parsing, the rDNS
  cache and its bound, notes for a public address, no lookup for private flows, missing files,
  the bad-address flag, refresh of stale files only, and a failed download keeping the old file.

## Deviations and known limits

- `RangeTable` assumes ranges do not overlap; where they do, a lookup may miss the wider range
  (`ranges.py:19-20`, marked as a shortcut).
- Every alert with a public remote address triggers a reverse DNS query unless cached.
