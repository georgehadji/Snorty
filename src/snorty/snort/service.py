import asyncio
import csv
import ctypes
import logging
import re
import signal
import subprocess
import sys
import tempfile
from ctypes import wintypes
from datetime import tzinfo
from pathlib import Path
from typing import Protocol

from snorty.core.models import Alert
from snorty.core.parser import parse_line
from snorty.snort.commands import (
    check_command,
    interfaces_command,
    live_command,
    pcap_command,
    taskkill_command,
    tasklist_command,
)
from snorty.snort.interfaces import parse_interfaces
from snorty.snort.models import ConfigCheck, Interface, SnortError, SnortPaths, StopResult
from snorty.snort.perfmon import FILE as PERFMON_FILE
from snorty.snort.perfmon import with_perfmon
from snorty.snort.runner import Runner

log = logging.getLogger("snorty.snort")

# Exit code Windows reports when a console control event ends a process normally.
CTRL_C_EXIT = 0xC000013A
_READY_MARKER = "Commencing packet processing"


class LiveProcess(Protocol):
    @property
    def returncode(self) -> int | None: ...

    def send_signal(self, sig: int) -> None: ...
    def kill(self) -> None: ...
    async def wait(self) -> int: ...


_job: int | None = None  # one job for every Snort we start; Windows closes it when we die


def bind_to_job(pid: int) -> None:
    """Make Windows kill Snort when this process ends, however it ends (a kill, a crash, a closed
    console). Without it a dead dashboard leaves Snort running, and the next start is refused.
    Best effort: a failure is logged and Snort simply runs unbound, as before."""
    global _job
    if sys.platform != "win32":
        return
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]  # fmt: skip
    if _job is None:
        job = k32.CreateJobObjectW(None, None)
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not job or not k32.SetInformationJobObject(
            job,
            9,
            ctypes.byref(info),
            ctypes.sizeof(info),  # 9: JobObjectExtendedLimitInformation
        ):
            log.warning("cannot create a job object for Snort (error %s)", ctypes.get_last_error())
            return
        _job = job
    process = k32.OpenProcess(0x0100 | 0x0001, False, pid)  # SET_QUOTA | TERMINATE
    try:
        if not process or not k32.AssignProcessToJobObject(_job, process):
            log.warning("cannot bind Snort to the job object (error %s)", ctypes.get_last_error())
    finally:
        if process:
            k32.CloseHandle(process)


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", ctypes.c_uint64 * 6),  # IO_COUNTERS: six 64-bit counters, unused
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


async def start_live(
    paths: SnortPaths, iface: Interface, *, ready_timeout: float = 120
) -> asyncio.subprocess.Process:
    """Start Snort on `iface` and return once it is capturing.

    Own process group, so Ctrl+Break reaches Snort and never this process.
    Snort's console output goes to <log_dir>/snort.out, which also tells us when it is ready.
    """
    paths.log_dir.mkdir(parents=True, exist_ok=True)
    out_path = paths.log_dir / "snort.out"
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
            raise SnortError(f"snort exited early (code {proc.returncode}): {text[-500:]}")
        if loop.time() > deadline:
            await stop_live(proc, timeout=10)
            raise SnortError(f"snort not ready after {ready_timeout}s: {text[-500:]}")
        await asyncio.sleep(0.25)


async def stop_live(proc: LiveProcess, *, timeout: float = 15) -> StopResult:
    """Ask Snort to stop with Ctrl+Break; kill only if it ignores that for `timeout` seconds."""
    if proc.returncode is not None:
        return StopResult("already_exited", proc.returncode)
    try:
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    except OSError:
        # No console to send Ctrl+Break from (pythonw, a service), or Snort just exited.
        if proc.returncode is not None:
            return StopResult("already_exited", proc.returncode)
        proc.kill()
        return StopResult("killed", await proc.wait())
    try:
        code = await asyncio.wait_for(proc.wait(), timeout)
    except TimeoutError:
        proc.kill()
        return StopResult("killed", await proc.wait())
    return StopResult("clean", code)


_RULES_READ = re.compile(r"^\s*(\d+) Snort rules read", re.MULTILINE)
_ERROR_LINE = re.compile(r"^(?:ERROR|Fatal Error).*$", re.MULTILINE)


async def list_interfaces(paths: SnortPaths, runner: Runner) -> list[Interface]:
    result = await runner(interfaces_command(paths), timeout=30)
    return parse_interfaces(result.stdout)


async def check_config(
    paths: SnortPaths, iface: Interface, runner: Runner, *, conf: Path | None = None
) -> ConfigCheck:
    """Run `snort -T`. Never raises for a Snort failure: the problem is in the result."""
    try:
        result = await runner(check_command(paths, iface, conf=conf), timeout=180)
    except SnortError as e:
        return ConfigCheck(False, None, (str(e),))
    text = f"{result.stdout}\n{result.stderr}"  # Snort prints -T output on stderr
    rules = _RULES_READ.search(text)
    rule_count = int(rules[1]) if rules else None
    if result.returncode == 0 and "successfully validated" in text:
        return ConfigCheck(True, rule_count, ())
    errors = tuple(m.group(0).strip() for m in _ERROR_LINE.finditer(text))
    if not errors:
        errors = (f"snort exited with code {result.returncode} and no error text",)
    return ConfigCheck(False, rule_count, errors)


async def enable_perfmon(paths: SnortPaths, iface: Interface, runner: Runner) -> Path | None:
    """Make sure `snort.conf` has Snorty's perfmonitor line, so drop statistics exist. A changed
    config is checked with `snort -T` and put back as it was if Snort refuses it. Returns the file
    Snort will write, or None when the line could not be added (alerts still work)."""
    csv = paths.log_dir / PERFMON_FILE
    try:
        original = await asyncio.to_thread(paths.conf.read_bytes)
        text = original.decode("utf-8")
        wanted = with_perfmon(text, csv)
        if wanted != text:
            await asyncio.to_thread(
                paths.conf.with_suffix(".conf.snorty-perfmon.bak").write_bytes, original
            )
            await asyncio.to_thread(paths.conf.write_bytes, wanted.encode("utf-8"))
            check = await check_config(paths, iface, runner)
            if not check.ok:
                await asyncio.to_thread(paths.conf.write_bytes, original)
                log.warning("snort refused the perfmonitor line, config restored: %s", check.errors)
                return None
        await asyncio.to_thread(csv.unlink, missing_ok=True)  # the figures of an earlier run
    except (OSError, UnicodeError):
        log.warning("could not add the perfmonitor line to snort.conf", exc_info=True)
        return None
    return csv


async def run_pcap(
    paths: SnortPaths,
    pcap: Path,
    runner: Runner,
    *,
    year: int,
    tz: tzinfo,
    conf: Path | None = None,
    log_dir: Path | None = None,
) -> list[Alert]:
    """Run Snort over `pcap` and return its alerts (read from <log_dir>/alert.ids).

    Without `log_dir`, a temp directory is used and removed afterwards. `conf` lets
    rule-lab point at its own sandbox config. Raises SnortError if the pcap is missing
    or Snort fails.
    """
    if not pcap.is_file():
        raise SnortError(f"pcap not found: {pcap}")
    if log_dir is not None:
        return await _run_pcap_in(paths, pcap, runner, conf, log_dir, year, tz)
    with tempfile.TemporaryDirectory(prefix="snorty-pcap-") as tmp:
        return await _run_pcap_in(paths, pcap, runner, conf, Path(tmp), year, tz)


async def _run_pcap_in(
    paths: SnortPaths,
    pcap: Path,
    runner: Runner,
    conf: Path | None,
    log_dir: Path,
    year: int,
    tz: tzinfo,
) -> list[Alert]:
    log_dir.mkdir(parents=True, exist_ok=True)
    result = await runner(pcap_command(paths, pcap, conf=conf, log_dir=log_dir), timeout=300)
    if result.returncode != 0:
        tail = "\n".join(f"{result.stdout}\n{result.stderr}".strip().splitlines()[-5:])
        raise SnortError(f"snort exited with code {result.returncode}: {tail}")
    return await asyncio.to_thread(_read_alerts, log_dir / "alert.ids", year, tz)


def _read_alerts(path: Path, year: int, tz: tzinfo) -> list[Alert]:
    """Runs in a worker thread: a big pcap can leave hundreds of thousands of lines."""
    if not path.exists():
        return []
    lines = path.read_text(errors="replace").splitlines()
    parsed = (parse_line(ln, default_year=year, tz=tz) for ln in lines)
    return [a for a in parsed if a is not None]


async def kill_snort(pid: int, runner: Runner) -> None:
    """Force-stop `pid` and its children. Failure is not raised: the caller checks again."""
    try:
        await runner(taskkill_command(pid), timeout=15)
    except SnortError:
        pass


async def is_snort_running(pid: int, runner: Runner, image: str = "snort.exe") -> bool:
    """True if `pid` is a live `image` (snort.exe unless told otherwise).
    Anything unexpected counts as not running."""
    try:
        result = await runner(tasklist_command(pid), timeout=15)
    except SnortError:
        return False
    for row in csv.reader(result.stdout.splitlines()):
        if len(row) >= 2 and row[0].lower() == image and row[1] == str(pid):
            return True
    return False
