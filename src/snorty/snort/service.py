import asyncio
import signal
import subprocess
from typing import Protocol

from snorty.snort.commands import live_command
from snorty.snort.models import Interface, SnortError, SnortPaths, StopResult

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
