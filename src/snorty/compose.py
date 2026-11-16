"""Builds the real Snorty services from paths and options (used by the dashboard)."""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from snorty.core.bus import EventBus
from snorty.core.localtz import LocalTimezone
from snorty.core.repository import AlertRepository
from snorty.dashboard.services import Services
from snorty.journal.ports import NoteStore
from snorty.journal.service import JournalConfig, JournalService
from snorty.lab.service import LabService
from snorty.notify.ports import Notifier, WinotifyNotifier
from snorty.notify.service import NotifyService
from snorty.rules.config import RulesConfig
from snorty.rules.ports import SnortValidator, UrllibDownloader
from snorty.rules.service import RulesService
from snorty.sensor import Sensor, SensorConfig, SnortAdapter
from snorty.snort import Interface, SnortPaths, SubprocessRunner


@dataclass(slots=True)
class Runtime:
    """The built services plus the background pieces that need start and stop."""

    services: Services
    notify: NotifyService | None
    journal: JournalService | None

    async def start(self, *, sensor: bool = False) -> None:
        if self.notify:
            await self.notify.start()
        if self.journal:
            await self.journal.start()
        if sensor:
            await self.services.sensor.start()

    async def stop(self) -> None:
        """Stop everything that was started; does not close the repository."""
        await asyncio.shield(self.services.sensor.stop())
        if self.journal:
            await self.journal.stop()
        if self.notify:
            await self.notify.stop()


def compose(
    data_dir: Path,
    *,
    interface_ip: str | None = None,
    notify: bool = False,
    notifier: Notifier | None = None,
    journal_store: NoteStore | None = None,
    paths: SnortPaths | None = None,
    select_interface: Callable[[list[Interface]], Interface | None] | None = None,
) -> Runtime:
    """Wire every module together. The journal runs only when a note store is given."""
    paths = paths or SnortPaths()
    data_dir.mkdir(parents=True, exist_ok=True)
    tz = LocalTimezone()
    bus = EventBus()
    repo = AlertRepository(data_dir / "snorty.db")
    config = SensorConfig(paths=paths, interface_ip=interface_ip)
    sensor = Sensor(
        config,
        SnortAdapter(paths),
        repo,
        bus,
        clock=time.monotonic,
        sleep=asyncio.sleep,
        tz=tz,
        select_interface=select_interface,
    )
    rules_config = RulesConfig(paths=paths)
    rules = RulesService(
        rules_config,
        UrllibDownloader(),
        SnortValidator(paths),
        sensor,
        bus,
        clock=lambda: datetime.now().astimezone(),
    )
    lab = LabService(paths, SubprocessRunner(), tz=tz)
    toasts = NotifyService(bus, notifier or WinotifyNotifier()) if notify else None
    journal = (
        JournalService(bus, repo, journal_store, JournalConfig(tz=tz)) if journal_store else None
    )
    services = Services(sensor, rules, journal, toasts, lab, repo, bus, tz, data_dir)
    return Runtime(services, toasts, journal)
