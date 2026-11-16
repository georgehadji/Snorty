"""Run a tool with a time limit and an output cap, and never leave it running."""

import asyncio
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol


class ToolError(Exception):
    """The tool could not start or ran out of time."""


@dataclass(frozen=True, slots=True)
class Output:
    returncode: int
    stdout: bytes
    stderr: str
    truncated: bool  # stdout hit the cap and the tool was stopped


class Runner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_bytes: int,
        env: Mapping[str, str] | None = None,
    ) -> Awaitable[Output]: ...


_CHUNK = 64 * 1024
_STDERR_KEEP = 4096


async def _reap(proc: asyncio.subprocess.Process) -> None:
    """Kill the tool, wait for it, and read its pipes to EOF so no transport is left open."""
    proc.kill()
    await proc.wait()
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            while await stream.read(_CHUNK):
                pass


async def run_bounded(
    argv: Sequence[str],
    *,
    timeout: float,
    max_bytes: int,
    env: Mapping[str, str] | None = None,
) -> Output:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(env) if env is not None else None,
        )
    except OSError as exc:
        raise ToolError(f"cannot start {argv[0]}: {exc}") from exc
    assert proc.stdout is not None and proc.stderr is not None
    stdout, stderr = proc.stdout, proc.stderr

    async def read_out() -> tuple[bytes, bool]:
        buf = bytearray()
        while chunk := await stdout.read(_CHUNK):
            buf += chunk
            if len(buf) > max_bytes:
                proc.kill()
                while await stdout.read(_CHUNK):  # drain to EOF so the pipe closes cleanly
                    pass
                return bytes(buf[:max_bytes]), True
        return bytes(buf), False

    async def read_err() -> bytes:
        kept = bytearray()
        while chunk := await stderr.read(_CHUNK):  # drain, or the tool blocks on a full pipe
            kept += chunk[: max(0, _STDERR_KEEP - len(kept))]
        return bytes(kept)

    try:
        (out, cut), err = await asyncio.wait_for(asyncio.gather(read_out(), read_err()), timeout)
        code = await proc.wait()
    except TimeoutError:
        await _reap(proc)
        raise ToolError(f"{argv[0]} took longer than {timeout:g} s") from None
    except BaseException:  # cancelled: do not leave the child behind
        await _reap(proc)
        raise
    return Output(code, out, err.decode("utf-8", errors="replace"), cut)
