import asyncio
from collections.abc import Sequence
from typing import Protocol

from snorty.snort.models import RunResult, SnortError


class Runner(Protocol):
    """Runs a command to completion. Tests inject a fake."""

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult: ...


class SubprocessRunner:
    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            raise SnortError(f"cannot start {argv[0]}: {e}") from e
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise SnortError(f"timeout after {timeout}s: {argv[0]}") from None
        return RunResult(
            proc.returncode if proc.returncode is not None else -1,
            out.decode("utf-8", errors="replace"),
            err.decode("utf-8", errors="replace"),
        )
