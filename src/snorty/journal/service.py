"""Keeps today's (and yesterday's) note up to date from the alert repository."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta, tzinfo

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.journal.merge import merge
from snorty.journal.ports import NoteStore
from snorty.journal.render import BEGIN, render

log = logging.getLogger("snorty.journal")


@dataclass(frozen=True, slots=True)
class JournalConfig:
    flush_interval: float = 300.0  # seconds between writes of days that changed
    tz: tzinfo = UTC  # the zone that decides where a day starts and ends
    page_size: int = 1000
    max_rows: int = 100_000  # rows read per day; the total still counts all of them


def collect(
    repo: AlertRepository, day: date, tz: tzinfo, page_size: int, max_rows: int
) -> tuple[list[Alert], int]:
    """The day's alerts (at most max_rows, newest first) and the true total."""
    since = datetime.combine(day, time.min, tzinfo=tz)
    until = datetime.combine(day + timedelta(days=1), time.min, tzinfo=tz)
    total = sum(n for _, n in repo.counts_by_sid(since, until))
    alerts: list[Alert] = []
    while len(alerts) < min(total, max_rows):
        page = repo.query(
            since=since,
            until=until,
            limit=min(page_size, max_rows - len(alerts)),
            offset=len(alerts),
        )
        if not page:
            break
        alerts += page
    return alerts, total


class JournalService:
    def __init__(
        self,
        bus: EventBus,
        repo: AlertRepository,
        store: NoteStore,
        config: JournalConfig = JournalConfig(),
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._bus = bus
        self._repo = repo
        self._store = store
        self._config = config
        self._now = now
        self._sleep = sleep
        self._dirty: set[date] = set()
        self._sub: Subscription | None = None
        self._tasks: list[asyncio.Task[None]] = []

    def _today(self) -> date:
        return self._now().astimezone(self._config.tz).date()

    async def start(self) -> None:
        """Subscribe, regenerate today and yesterday, then keep the notes current."""
        if self._sub is not None:
            return
        self._sub = self._bus.subscribe(maxsize=1000)
        today = self._today()
        self._dirty |= {today - timedelta(days=1), today}
        await self.flush()
        self._tasks = [
            asyncio.create_task(self._consume(self._sub), name="journal-consumer"),
            asyncio.create_task(self._ticker(), name="journal-ticker"),
        ]

    async def stop(self) -> None:
        if self._sub is None:
            return
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._sub.close()
        self._tasks, self._sub = [], None
        self._dirty.add(self._today())  # events still queued were never read
        await self.flush()

    async def flush(self) -> None:
        """Rewrite every day that changed since the last flush."""
        for day in sorted(self._dirty):
            self._dirty.discard(day)
            await asyncio.to_thread(self._write_day, day)

    async def _consume(self, sub: Subscription) -> None:
        async for event in sub:
            if isinstance(event, AlertRaised):
                self._dirty.add(event.alert.ts.astimezone(self._config.tz).date())

    async def _ticker(self) -> None:
        while True:
            await self._sleep(self._config.flush_interval)
            await self.flush()

    def _write_day(self, day: date) -> None:
        cfg = self._config
        alerts, total = collect(self._repo, day, cfg.tz, cfg.page_size, cfg.max_rows)
        existing = self._store.read(day)
        if not alerts and (existing is None or BEGIN not in existing):
            return  # nothing to say and nothing of ours to update
        text = merge(existing, render(day, alerts, cfg.tz, total), day)
        if text != existing:
            self._store.write(day, text)
