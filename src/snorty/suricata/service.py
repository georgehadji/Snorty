"""Running Suricata. Reuses the Snort package's process helpers (job object, Ctrl+Break stop,
tasklist, taskkill): they work on any console process."""

import asyncio
import re
import socket
import subprocess
from datetime import datetime
from pathlib import Path

from snorty.core.decoder import EveDecoder
from snorty.core.models import Alert
from snorty.snort.models import ConfigCheck, Interface, SnortError
from snorty.snort.runner import Runner
from snorty.snort.service import bind_to_job, stop_live
from snorty.suricata.models import SuricataPaths

IMAGE = "suricata.exe"
_READY_MARKER = "engine started"
_RULES_LOADED = re.compile(r"(\d+) rules successfully loaded")
# Older builds print "<Error> - ...", this one "E: ...".
_ERROR_LINE = re.compile(r"^(?:E:.*|.*<Error>.*)$", re.MULTILINE)


def check_command(paths: SuricataPaths, *, conf: Path | None = None) -> list[str]:
    # -l: the stock config opens its log files even for -T, and its own log dir is read-only.
    return [str(paths.exe), "-T", "-c", str(conf or paths.conf), "-l", str(paths.log_dir)]


def live_command(paths: SuricataPaths, iface: Interface) -> list[str]:
    assert iface.ip is not None
    return [str(paths.exe), "-c", str(paths.conf), "-i", iface.ip, "-l", str(paths.log_dir)]


def local_interfaces() -> list[Interface]:
    """The PC's IPv4 addresses. Suricata takes `-i <address>` with Npcap, so the address is all
    it needs; asking the engine for its adapter list would mean parsing a format per release."""
    try:
        addresses = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        return []
    unique = dict.fromkeys(a for a in addresses if not a.startswith("127."))
    return [Interface(i, "", ip, "", ip) for i, ip in enumerate(unique)]


async def start_live(
    paths: SuricataPaths, iface: Interface, *, ready_timeout: float = 120
) -> asyncio.subprocess.Process:
    """Start Suricata on `iface` and return once it is capturing. Same shape as Snort's start:
    own process group, console output in <log_dir>/suricata.out, which says when it is ready."""
    if iface.ip is None:
        raise SnortError(f"interface {iface.index} has no IPv4 address; suricata needs one")
    paths.log_dir.mkdir(parents=True, exist_ok=True)
    out_path = paths.log_dir / "suricata.out"
    with out_path.open("wb") as out:
        try:
            proc = await asyncio.create_subprocess_exec(
                *live_command(paths, iface),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=out,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except OSError as e:
            raise SnortError(f"cannot start {paths.exe}: {e}") from e
    bind_to_job(proc.pid)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + ready_timeout
    while True:
        text = out_path.read_text(errors="replace")
        if _READY_MARKER in text:
            return proc
        if proc.returncode is not None:
            raise SnortError(f"suricata exited early (code {proc.returncode}): {text[-500:]}")
        if loop.time() > deadline:
            await stop_live(proc, timeout=10)
            raise SnortError(f"suricata not ready after {ready_timeout}s: {text[-500:]}")
        await asyncio.sleep(0.25)


async def check_config(
    paths: SuricataPaths, runner: Runner, *, conf: Path | None = None
) -> ConfigCheck:
    """Run `suricata -T`. Never raises for a Suricata failure: the problem is in the result."""
    paths.log_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = await runner(check_command(paths, conf=conf), timeout=180)
    except SnortError as e:
        return ConfigCheck(False, None, (str(e),))
    text = f"{result.stdout}\n{result.stderr}"
    rules = _RULES_LOADED.search(text)
    rule_count = int(rules[1]) if rules else None
    if result.returncode == 0:
        return ConfigCheck(True, rule_count, ())
    errors = tuple(m.group(0).strip() for m in _ERROR_LINE.finditer(text))
    if not errors:
        errors = (f"suricata exited with code {result.returncode} and no error text",)
    return ConfigCheck(False, rule_count, errors)


def pcap_command(
    paths: SuricataPaths, pcap: Path, *, conf: Path | None = None, log_dir: Path | None = None
) -> list[str]:
    # -k none: hand-made and captured pcaps often carry bad checksums; do not drop them.
    return [
        str(paths.exe), "-r", str(pcap), "-c", str(conf or paths.conf),
        "-l", str(log_dir or paths.log_dir), "-k", "none",
    ]  # fmt: skip


async def run_pcap(
    paths: SuricataPaths,
    pcap: Path,
    runner: Runner,
    *,
    year: int,
    conf: Path | None = None,
    log_dir: Path,
) -> list[Alert]:
    """Run Suricata over `pcap` and return its alerts (read from <log_dir>/eve.json).
    Raises SnortError if the pcap is missing or Suricata fails."""
    if not pcap.is_file():
        raise SnortError(f"pcap not found: {pcap}")
    log_dir.mkdir(parents=True, exist_ok=True)
    result = await runner(pcap_command(paths, pcap, conf=conf, log_dir=log_dir), timeout=300)
    if result.returncode != 0:
        tail = "\n".join(f"{result.stdout}\n{result.stderr}".strip().splitlines()[-5:])
        raise SnortError(f"suricata exited with code {result.returncode}: {tail}")
    return await asyncio.to_thread(_read_alerts, log_dir / paths.alert_file, year)


def _read_alerts(path: Path, year: int) -> list[Alert]:
    """Runs in a worker thread: a big pcap can leave hundreds of thousands of events."""
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    alerts, _ = EveDecoder().decode(lines, year, (), datetime.now().astimezone())
    return alerts
