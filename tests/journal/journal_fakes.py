"""Test doubles for the journal service tests."""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, tzinfo
from pathlib import Path

from snorty.core.bus import EventBus
from snorty.core.events import AlertRaised
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.journal.ports import MemoryNoteStore
from snorty.journal.service import JournalConfig, JournalService

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def make_alert(sid: int = 1, ts: datetime = NOW, priority: int = 1, **kw: object) -> Alert:
    base: dict[str, object] = {
        "ts": ts,
        "gid": 1,
        "sid": sid,
        "rev": 1,
        "msg": f"rule {sid}",
        "classification": None,
        "priority": priority,
        "proto": "TCP",
        "src_ip": "10.0.0.1",
        "src_port": 4444,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "raw": f"raw {sid} {ts.isoformat()}",
    }
    base.update(kw)
    return Alert(**base)  # type: ignore[arg-type]


class Ticks:
    """A sleep() that returns only when the test says so."""

    def __init__(self) -> None:
        self._q: asyncio.Queue[None] = asyncio.Queue()

    async def sleep(self, seconds: float) -> None:
        await self._q.get()

    def tick(self) -> None:
        self._q.put_nowait(None)


async def settle(until: Callable[[], bool] | None = None, timeout: float = 2.0) -> None:
    if until is None:
        await asyncio.sleep(0.05)
        return
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not until():
        if loop.time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.005)


class Rig:
    def __init__(self, tmp_path: Path, tz: tzinfo = UTC, **cfg: int) -> None:
        self.bus = EventBus()
        self.repo = AlertRepository(tmp_path / "a.db")
        self.store = MemoryNoteStore()
        self.ticks = Ticks()
        self.now = NOW
        self.service = JournalService(
            self.bus,
            self.repo,
            self.store,
            JournalConfig(tz=tz, **cfg),  # type: ignore[arg-type]
            now=lambda: self.now,
            sleep=self.ticks.sleep,
        )

    def add(self, *alerts: Alert, announce: bool = True) -> None:
        self.repo.add_many(alerts)
        if announce:
            for a in alerts:
                self.bus.publish(AlertRaised(a))
