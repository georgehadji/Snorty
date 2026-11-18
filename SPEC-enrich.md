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

1. The remote address is the first of `src_ip`, `dst_ip` that is global (`remote_address`). The
   names are the host names among the alert's flow facts (`flow_names`: DNS name, TLS server
   name, web request host), so only Suricata alerts have them. Neither one means no notes.
2. Steps in order (`EnrichService.enrich`):
   - `bad`: Feodo then DROP on the address, else the CERT Polska list on the names, where a
     listed parent domain also matches;
   - `osint`: the CIRCL OSINT feed on the address, then the names, exact values only;
   - `country`, `asn`, `rdns`: on the address.

   Each answer is stored as an annotation of that kind. A country is also recorded with
   `note_seen("country", ...)`. `osint` is a mention in a public report, never a verdict: it
   does not set `bad` and does not notify.
3. A `bad` note publishes `AlertFlagged(alert, label)` (`service.py:96-97`); `notify` consumes it
   (`notify/service.py:69,90`).
4. Lookup work runs in a worker thread; one failing alert is logged and the consumer continues
   (`service.py:91-95`). The queue holds 500 and keeps the oldest (`service.py:73`).
5. Data files in the folder: `feodo.txt`, `drop.txt`, `dbip-country.csv`, `dbip-asn.csv`,
   `cert-pl-domains.txt`, `circl-manifest.json`, `circl-hashes.csv`; a missing or unreadable file
   loads as an empty table (`EnrichService.load`).
6. `refresh` downloads a file only when it is missing or older than its age: Feodo, DROP and
   CERT Polska 1 day, the CIRCL feed 7 days, DB-IP 30 days. DB-IP URLs carry the current
   `YYYY-MM` and are gunzipped (`EnrichService.refresh`).
6a. CIRCL OSINT (`osint.py`, MISP feed format):
   - Only reports tagged `tlp:white` or `tlp:clear` in `manifest.json` are used.
   - `hashes.csv` rows (`md5(value),report-uuid`) become one sorted buffer of 16-byte digests plus
     a report index each, looked up by bisection (about 18 bytes per value, about 11 MB).
   - A value is looked up by its md5. The note names the number of reports and the newest one's
     title and date.
   - The per-report event files (about 880 MB) are never downloaded.
7. Each download is written to `<name>.part` and moved into place with `os.replace`, so a half
   file is never read (`service.py:170-172`). Tables reload only when a file changed (`line 102`).
8. The refresh loop runs at start and then every 24 h; any failure is logged and retried the next
   day (`service.py:99-106`).
9. Limits: download body 64 MiB, decompressed data 64 MiB, timeout 30 s (`fetch.py:10-11,26-32`).
10. Reverse DNS: cache of 2048 entries for 1 h, misses cached too, at most 4 lookups in flight,
    least recently used entry evicted first (`rdns.py:14-48`).
11. Labels: Feodo entries read "Feodo Tracker botnet C2"; DROP entries "Spamhaus DROP SBLnnn"
    (`ranges.py:66-82`); CERT Polska ones "CERT Polska phishing warning list: <domain>". Bad lines
    in any source are skipped (`ranges.py:41-63`, `osint.py`).

## Security and privacy

- Downloads go only to the seven fixed HTTPS URLs (`EnrichService.refresh`) with
  `User-Agent: Snorty`; they carry no alert data. Feeds are pulled whole and matched here; no
  feed is ever queried with a value from an alert.
- Reverse DNS sends the remote address to the PC's configured DNS resolver
  (`socket.gethostbyaddr`, `rdns.py:16`). That is the one way alert data leaves the PC here.
- Downloaded text is parsed with `ipaddress` and `csv`; invalid rows are dropped.

## Tests

- `tests/core/test_host_context.py`: range tables, DB-IP rows, Feodo and DROP parsing, the rDNS
  cache and its bound, notes for a public address, no lookup for private flows, missing files,
  the bad-address flag, refresh of stale files only, and a failed download keeping the old file.
- `tests/core/test_osint.py`: the CIRCL index (shared reports only, counts, newest, broken
  rows), the CERT Polska list with parent domains, and the pipeline: names from flow facts, a
  phishing name flags, an OSINT mention does not.

## Deviations and known limits

- `RangeTable` assumes ranges do not overlap; where they do, a lookup may miss the wider range
  (`ranges.py:19-20`, marked as a shortcut).
- Every alert with a public remote address triggers a reverse DNS query unless cached.
- Names come from the flow facts stored when the alert arrives. A TLS or web event that Suricata
  logs after its alert lands on a later poll, so its name is not checked.
- `circl-hashes.csv` is about 42 MB and grows; the 64 MiB download limit will need raising one
  day. A failed download keeps the old file.
