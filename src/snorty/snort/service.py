import asyncio
import re
import signal
import subprocess
from pathlib import Path
from typing import Protocol

from snorty.snort.commands import check_command, interfaces_command, live_command
from snorty.snort.interfaces import parse_interfaces
from snorty.snort.models import ConfigCheck, Interface, SnortError, SnortPaths, StopResult
from snorty.snort.runner import Runner

# Exit code Windows reports when a console control event ends a process normally.
CTRL_C_EXIT = 0xC000013A
_READY_MARKER = "Commencing packet processing"


class LiveProcess(Protocol):
    @property
    def returncode(self) -> int | None: ...

    def send_signal(self, sig: int) -> None: ...
    def kill(self) -> None: ...
    async def wait(self) -> int: ...


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
    proc.send_signal(signal.CTRL_BREAK_EVENT)
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
