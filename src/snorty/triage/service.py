"""Acknowledges new alerts that match an archive rule, so known noise leaves the inbox."""

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised, AlertsBackfilled, Event
from snorty.core.repository import AlertRepository

log = logging.getLogger("snorty.triage")


class TriageService:
    """Runs the archive rules once at start, then again after alerts arrive. Arrivals only set a
    flag, so a burst of alerts costs one pass over the rules, not one per alert."""

    def __init__(
        self,
        bus: EventBus,
        repo: AlertRepository,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._bus = bus
        self._repo = repo
        self._now = now
        self._dirty = asyncio.Event()
        self._sub: Subscription | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._sub = self._bus.subscribe(maxsize=1, accept=self._mark)  # never read, only the hook
        self._dirty.set()  # alerts stored while Snorty was down
        self._task = asyncio.create_task(self._run(), name="triage-archive")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        if self._sub is not None:
            self._sub.close()
        self._task = self._sub = None

    def _mark(self, event: Event) -> bool:
        if isinstance(event, AlertRaised | AlertsBackfilled):
            self._dirty.set()
        return False

    async def _run(self) -> None:
        while True:
            await self._dirty.wait()
            self._dirty.clear()
            try:
                n = await asyncio.to_thread(self._repo.apply_archive_rules, self._now())
                if n:
                    log.info("archive rules acknowledged %d alerts", n)
            except Exception:  # the next arrival tries again
                log.exception("could not apply the archive rules")
