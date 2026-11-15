# Spec: snort-adapter — V1

Status: approved 2026-11-16 (open question 1 resolved: HOME_NET drift deferred to `rules`)
Module of: [CAPABILITY-MAP.md](CAPABILITY-MAP.md) · Depends on: [alert-core](SPEC-alert-core.md) · Used by: sensor, rules, rule-lab, dashboard

## Objective

The only code in Snorty that runs `snort.exe`. It builds command lines, runs
them, and translates Snort's text output into domain types. Everything else
(sensor, rules, rule-lab) asks this module and never touches `subprocess`,
`C:\Snort` paths or Snort's output format.

It does five jobs:

1. List capture interfaces (`snort -W`) and pick the one the PC really uses.
2. Check a config (`snort -T`): did Snort accept it, and how many rules loaded?
3. Build the live-capture command line.
4. Start a live Snort process and stop it cleanly (so buffered alerts are flushed).
5. Run Snort over a pcap (`-r`) and return the alerts as `Alert` objects.

Process supervision (restart, backoff, tailing `alert.ids`) is **not** here: that is the sensor.

### Facts learned on this PC (2026-11-16), which the design rests on

- `snort.exe -W` prints a table. Real output:
  `Index  Physical Address  IP Address  Device Name  Description`, rows like
  `4  48:45:E6:48:53:93  192.168.10.230  \Device\NPF_{...}  MediaTek Wi-Fi 7 MT7925 Wireless LAN Card`.
  Unconfigured adapters show `disabled` as IP. Loopback shows `0000:0000:...:0000`.
- Index 4 is Wi-Fi, 6 is Ethernet (now up, 192.168.1.25), 8 is loopback. Indexes can
  change when adapters come and go, so they are never hard-coded.
- `snort.exe -T -c <conf>` alone **fails** (`Active response: can't open ip!`);
  `snort.exe -T -i 4 -c <conf>` succeeds and ends with `Snort successfully validated the configuration!`.
  Every `-T` call therefore needs `-i`.
- `-A fast` output is buffered and reaches `alert.ids` only on a clean exit. A
  force-kill loses it.
- The Wi-Fi address is now `192.168.10.230`, but `snort.conf` has
  `HOME_NET [192.168.1.0/24]`. See Open Questions.

### Acceptance criteria

1. `parse_interfaces(text)` turns `-W` output into `Interface` objects; `disabled` and the IPv6 loopback address give `ip=None`.
2. `pick_interface(interfaces, local_ip)` returns the interface whose IPv4 equals `local_ip`, else `None`.
3. `find_local_ip()` returns the IPv4 address the OS would use to reach the internet, without sending any packet.
4. `check_config(...)` returns `ConfigCheck(ok, rule_count, errors)`. A good config gives `ok=True` and `rule_count` near 52,442; a config with a bad line gives `ok=False` and the Snort error text in `errors`. It never raises on a Snort failure.
5. `live_command(...)` returns an argv list (never a string) with `-c`, `-i`, `-l`, `-A fast`, `-y`, and no shell quoting.
6. `start_live` + `stop_live`: stopping sends Ctrl+Break, waits up to a timeout, kills only as a last resort, and reports which happened. After a clean stop, alerts triggered before the stop appear in `alert.ids`.
7. `run_pcap(pcap, conf, log_dir, paths)` returns `list[Alert]` parsed from the output; a missing pcap or failing Snort gives a typed `SnortError`.
8. No module outside `snorty.snort` imports `subprocess` or `asyncio.subprocess` for Snort.

## Types

```python
@dataclass(frozen=True, slots=True)
class SnortPaths:
    exe: Path = Path(r"C:\Snort\bin\snort.exe")
    conf: Path = Path(r"C:\Snort\etc\snort.conf")
    log_dir: Path = Path(r"C:\Snort\log")

@dataclass(frozen=True, slots=True)
class Interface:
    index: int
    mac: str
    ip: str | None          # IPv4 only; None when disabled or IPv6
    device: str             # \Device\NPF_{GUID}
    description: str

@dataclass(frozen=True, slots=True)
class ConfigCheck:
    ok: bool
    rule_count: int | None
    errors: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class RunResult:            # what the Runner returns; the seam for fakes in tests
    returncode: int
    stdout: str
    stderr: str

class SnortError(Exception): ...   # Snort missing, pcap unreadable, timeout
```

`Runner` is a `Protocol`: `async def __call__(argv: Sequence[str], *, timeout: float) -> RunResult`.
The real runner uses `asyncio.create_subprocess_exec`; tests pass a fake.

## Design

**Paradigm: procedural, thin.** Small functions, no class hierarchy. Pure
functions (parse, pick, build) are separated from the few functions that run a process.

**Patterns:** Adapter (Snort CLI → Python API), Builder (command lines),
Anti-corruption layer (Snort text → `Interface`, `ConfigCheck`, `Alert`; nothing
Snort-shaped leaks out), Dependency injection of `Runner` (the test seam).

## Tech Stack

Python 3.12+, stdlib only (`asyncio`, `subprocess` flags, `socket`, `re`, `pathlib`, `tempfile`).
Reuses `snorty.core.parser.parse_line` and `Alert`. No new dependency.

## Commands

Same as alert-core, plus:

```
Unit tests:        uv run pytest tests/snort -q -m "not snort"
Integration tests: uv run pytest tests/snort -q -m snort     # needs C:\Snort and Npcap
Types:             uv run mypy src/snorty/core src/snorty/snort
```

## Project Structure

```
src/snorty/snort/
  __init__.py       public API re-exports
  models.py         SnortPaths, Interface, ConfigCheck, RunResult, SnortError
  interfaces.py     parse_interfaces, pick_interface, find_local_ip
  commands.py       live_command, test_command, pcap_command   (pure builders)
  runner.py         Runner protocol, SubprocessRunner          (the only subprocess code)
  service.py        list_interfaces, check_config, run_pcap, start_live, stop_live
tests/snort/        mirrors the above; test_integration.py is marked @pytest.mark.snort
tests/fixtures/     snort_W.txt (real -W output), snort_T_ok.txt, snort_T_bad.txt
```

Dependency rule: `snorty.snort` imports `snorty.core` only.

## Code Style

```python
def pick_interface(interfaces: Sequence[Interface], local_ip: str) -> Interface | None:
    """Return the interface that owns `local_ip`. None if no adapter has it."""
    return next((i for i in interfaces if i.ip == local_ip), None)


def live_command(paths: SnortPaths, iface: Interface) -> list[str]:
    return [str(paths.exe), "-c", str(paths.conf), "-i", str(iface.index),
            "-l", str(paths.log_dir), "-A", "fast", "-y"]
```

Same conventions as alert-core (frozen slotted dataclasses, full type hints,
ruff, strict mypy). `find_local_ip` uses a UDP `connect()` to a public address and
reads `getsockname()`: no packet is sent.

## Testing Strategy

- **Unit (no Snort needed, ms):** `parse_interfaces` against the real `-W` fixture
  (including `disabled` and IPv6 rows and a garbled table); `pick_interface`; each command
  builder compared to an exact argv; `check_config` with a fake `Runner` returning
  the saved good and bad `-T` output; `run_pcap` with a fake runner that writes a fixture
  `alert.ids` into the temp dir.
- **Integration (`@pytest.mark.snort`):** the real `-W` parses and contains the loopback
  adapter; the real `-T -i <n>` validates `C:\Snort\etc\snort.conf`; a tiny pcap
  (generated by the test with a few handwritten packets) triggers `local.rules` sid 1000002 through `run_pcap`;
  `start_live` on loopback → send one matching TCP payload → `stop_live` → the alert is in `alert.ids`
  (this proves the Ctrl+Break clean-shutdown assumption).
- Coverage ≥ 90% for `snorty.snort`; unit tests under 2 s.

## Boundaries

- **Always:** pass argv lists (never `shell=True`); give every process call a timeout; run `-T` with `-i`; use a fresh temp dir for pcap runs.
- **Ask first:** changing a flag in `live_command`; any new dependency; writing anywhere under `C:\Snort` (this module only reads it, except the log dir Snort writes to).
- **Never:** call `Process.kill()` as the normal stop path (loses buffered alerts); hard-code an interface index; edit `snort.conf` or rules (that is the `rules` module); import from `sensor`, `rules`, or other later modules.

## Success Criteria

- [ ] `uv run pytest tests/snort -m "not snort"` passes in under 2 s with Snort uninstalled-safe fakes.
- [ ] `uv run pytest tests/snort -m snort` passes on this PC: real `-W`, real `-T`, pcap run, live start/stop with the alert flushed.
- [ ] Wi-Fi (or Ethernet, whichever is the default route) is picked automatically on this PC.
- [ ] `grep -r "subprocess" src/snorty` matches only `src/snorty/snort/runner.py` and `service.py`.
- [ ] `ruff check`, `mypy src/snorty/core src/snorty/snort` clean; coverage ≥ 90%.

## Out of Scope (Deferred)

- Snort 3 (`snort --version`, `alert_json`): the adapter boundary allows it later.
- Multiple simultaneous interfaces (Snort 2.9 on Windows takes one `-i`).
- Rewriting `HOME_NET` in `snort.conf`: belongs to `rules` (it owns config edits).
- Installing or updating Snort/Npcap.
- Running Snort as a Windows service.

## Open Questions

1. **`HOME_NET` drift.** Wi-Fi is now `192.168.10.230`; `snort.conf` says `192.168.1.0/24`. Rules that use `$HOME_NET` (including `local.rules` sid 1000001) won't match your Wi-Fi address as "home". Suggest: `rules` module detects the mismatch and offers to fix it; this adapter only exposes the facts (`Interface.ip`). OK to defer to `rules`?
2. **Two adapters up.** Ethernet (192.168.1.25) and Wi-Fi are both connected. `find_local_ip()` follows the OS default route (today: Wi-Fi, metric 0). Acceptable, or do you want a manual override in `snorty.toml`? (Proposed: yes, optional `interface_ip` setting, handled by the sensor.)
3. **Ctrl+Break flush.** Assumed to make Snort 2.9 exit cleanly and flush `alert_fast`. The integration test proves it in the first task; if it fails, the fallback is `-A fast` replaced by unbuffered `unsock`/`console` output, which would change this spec.
