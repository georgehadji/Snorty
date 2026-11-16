"""One long-running action at a time (rules update, lab run): start it, poll it, cancel it."""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Idle:
    """Never started, or cancelled before it finished."""


@dataclass(frozen=True, slots=True)
class Running:
    pass


@dataclass(frozen=True, slots=True)
class Errored:
    message: str


@dataclass(frozen=True, slots=True)
class Done[T]:
    result: T


class Job[T]:
    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self.result: T | None = None
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def state(self) -> Idle | Running | Errored | Done[T]:
        """Where the job is, as one value that carries its own message or result."""
        if self.running:
            return Running()
        if self.error is not None:
            return Errored(self.error)
        return Idle() if self.result is None else Done(self.result)

    def start(self, work: Callable[[], Awaitable[T]]) -> bool:
        """Begin `work` unless one is already running; False means nothing was started."""
        if self.running:
            return False
        self.result = None
        self.error = None
        self._task = asyncio.create_task(self._run(work))
        return True

    async def _run(self, work: Callable[[], Awaitable[T]]) -> None:
        try:
            self.result = await work()
        except Exception:
            log.exception("background job failed")
            self.error = "unexpected error; see the log"

    async def wait(self) -> None:
        if self._task is not None:
            await asyncio.shield(self._task)

    async def cancel(self) -> None:
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
