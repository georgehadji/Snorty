"""One long-running action at a time (rules update, lab run): start it, poll it, cancel it."""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable

log = logging.getLogger(__name__)


class Job[T]:
    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self.result: T | None = None
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

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
