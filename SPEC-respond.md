# Spec: respond (as built)

Covers `src/snorty/respond/` and its Windows Firewall adapter `src/snorty/winfw/`.

## Objective

Let the user block one public IP address in Windows Firewall, for a set time or until unblocked,
and undo it. Each block is a `blocks` row, so it survives a restart and expires on schedule.
Blocking is manual only (`respond/service.py:1-4`). The dashboard stays non-elevated; each
firewall write asks Windows for approval (`winfw/firewall.py:4-6`).

## Architecture and patterns

- `respond` is a feature service: no processes (the `subprocess` contract covers it), in the
  independence contract, never imports UI or wiring. `winfw` is its adapter; it is not in the
  `subprocess` contract and runs PowerShell through `snort.runner.Runner` (`pyproject.toml`,
  `[tool.importlinter]`; `winfw/firewall.py:13-14`).
- Ports and adapters: `Firewall` (`respond/ports.py:15`) is implemented by `PowerShellFirewall`
  (`winfw/firewall.py:78`). Pure policy: `refusal(ip, protected)` (`respond/policy.py:7`). Errors
  as data: `block` and `unblock` return `Outcome(ok, detail)` (`service.py:26-29`).
- Wiring: `compose.py:199` builds `BlockService(repo, PowerShellFirewall(runner))` only when
  `respond` is true; the UI uses `RespondPort` (`services.py:102-107`); `Runtime.start` starts
  its sweep task (`compose.py:74-75`).

## Ports

`Firewall` in `respond/ports.py`: `block(ip)`, `unblock(*ips)` (all at once, one approval),
`blocked() -> Sequence[str]` (single addresses Snorty's rules block), `protected() ->
frozenset[str]` (gateways and DNS servers). Failures raise `FirewallError`; a declined UAC prompt
or denied access raises its subclass `NeedsAdmin`.

## Behaviour and invariants

1. `hours` must satisfy `0 < hours <= 720`, or be None for "until unblocked" (`service.py:21,71`).
2. One change at a time: a second is refused while the first waits (`service.py:73-74,96-97`).
3. An address with `%` (IPv6 scope id) or that is not an IP is refused; the address is made
   canonical before use (`service.py:77-79`, `winfw/firewall.py:35-42`).
4. `refusal` blocks only global, non-multicast addresses and never a gateway or DNS server of this
   PC (`policy.py:12-22`).
5. A failed write: the service removes any half-made rule pair; no row is written (`service.py:86-89`).
6. A successful block writes a row with state `active` and `until` (or None); blocking an address
   again replaces its row (`service.py:90-92`, `core/repository.py:503-517`).
7. Unblock removes the rules, then marks the row `released` (`service.py:95-104`).
8. Every 60 s the sweep removes all expired active blocks in one call and marks them `expired`.
   If declined or failed, it waits 30 min, then 1 h, 2 h ..., at most 1 day
   (`service.py:106-132`).
9. At start `reconcile` reads the firewall (no prompt): a Snorty rule with no row is adopted as
   an active block with no expiry; an active row with no rule is marked `released`
   (`service.py:134-148`).
10. winfw puts each rule in group `Snorty`, named `Snorty block <ip>`, inbound and outbound
    (`firewall.py:16,45-56`); unblock removes by that name (`firewall.py:59-63`).
11. Writes run in a hidden `Start-Process powershell.exe -Verb RunAs -Wait`, so Windows shows UAC
    for each write; the inner script travels base64 (UTF-16LE) via `-EncodedCommand`
    (`firewall.py:22-32`). Timeouts: writes 120 s, reads 30 s (`firewall.py:19,79,88`).
12. Reads (`blocked`, `protected`) run unelevated and keep single addresses only
    (`firewall.py:98-121`). A failure whose text has "access is denied", "requires elevation" or
    "canceled by the user" is `NeedsAdmin`; others are `FirewallError` with the first line, cut
    to 200 characters (`firewall.py:17,91-95`).

## Security and privacy

- Only a canonical IP address reaches a PowerShell command line; the argv is a list, never a
  shell string (`firewall.py:35-42,86`). Nothing leaves the PC.
- Snorty only lists and removes rules in its own `Snorty` group (`firewall.py:1-2,66-70`).

## Tests

- `tests/respond/test_respond.py`: policy refusals, hours bounds, `NeedsAdmin` records nothing,
  unblock, re-block reuses the row, sweep and its back-off, reconcile, scope ids, half-made rule
  cleanup, one change at a time.
- `tests/winfw/test_firewall.py`: writes elevated and reads not, the encoded inner script, rule
  shape and group, one elevated call for unblock, injection strings rejected, canonical form,
  denial mapping, with a fake runner. `tests/dashboard/test_dash_respond.py`: the routes.

## Deviations and known limits

- Any duration above 0 and up to 720 hours is accepted, fractions included (`service.py:71-72`).
- The sweep asks one approval for all expired blocks together (`service.py:121`). A rule removed
  outside Snorty is noticed only by `reconcile` at the next start.
