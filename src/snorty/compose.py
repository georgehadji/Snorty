"""Builds the real Snorty services from paths and options (used by the dashboard)."""

import asyncio
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from snorty.core.bus import EventBus
from snorty.core.localtz import LocalTimezone
from snorty.core.repository import AlertRepository
from snorty.journal.ports import NoteStore
from snorty.journal.service import JournalConfig, JournalService
from snorty.lab.service import LabService
from snorty.notify.ports import Notifier, WinotifyNotifier
from snorty.notify.service import NotifyService
from snorty.packets import NoDecoder, PacketService
from snorty.rules.config import RulesConfig
from snorty.rules.ports import SnortValidator, UrllibDownloader
from snorty.rules.service import RulesService
from snorty.sensor import Sensor, SensorConfig, SnortAdapter
from snorty.services import Services
from snorty.snort import Interface, SnortPaths, SubprocessRunner
from snorty.wireshark import DumpcapRecorder, TsharkDecoder, WiresharkViewer, find_tools

log = logging.getLogger("snorty")


@dataclass(slots=True)
class Runtime:
    """The built services plus the background pieces that need start and stop."""

    services: Services
    notify: NotifyService | None
    journal: JournalService | None

    async def start(self, *, sensor: bool = False) -> None:
        try:
            if self.notify:
                await self.notify.start()
            if self.journal:
                await self.journal.start()
            if sensor:
                await self.services.sensor.start()
        except BaseException:  # leave nothing half started
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stop everything that was started; does not close the repository. A part that fails
        to stop does not keep the others running."""
        try:
            await asyncio.shield(self.services.sensor.stop())
        finally:
            try:
                if self.journal:
                    await self.journal.stop()
            finally:
                if self.notify:
                    await self.notify.stop()


def compose(
    data_dir: Path,
    *,
    db_path: Path | None = None,
    interface_ip: str | None = None,
    notify: bool = False,
    notifier: Notifier | None = None,
    journal_store: NoteStore | None = None,
    paths: SnortPaths | None = None,
    select_interface: Callable[[list[Interface]], Interface | None] | None = None,
    wireshark_dir: Path | None = None,
) -> Runtime:
    """Wire every module together. The journal runs only when a note store is given."""
    paths = paths or SnortPaths()
    data_dir.mkdir(parents=True, exist_ok=True)
    tz = LocalTimezone()
    bus = EventBus()
    repo = AlertRepository(db_path or data_dir / "snorty.db")
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
    try:  # a crash in the middle of a rules swap must not leave Snort without its rules
        rules.recover()
    except OSError:
        log.exception("could not repair an interrupted rules swap")
    lab = LabService(paths, SubprocessRunner(), tz=tz)
    toasts = NotifyService(bus, notifier or WinotifyNotifier()) if notify else None
    journal = (
        JournalService(bus, repo, journal_store, JournalConfig(tz=tz)) if journal_store else None
    )
    tools = find_tools(configured=wireshark_dir, env=os.environ)
    packets = PacketService(
        TsharkDecoder(tools.tshark) if tools.tshark else NoDecoder(),
        WiresharkViewer(tools.wireshark) if tools.wireshark else None,
        DumpcapRecorder(tools.dumpcap) if tools.dumpcap else None,
        snort_logs=paths.log_dir,
        scratch=data_dir / "opened",
    )
    services = Services(sensor, rules, journal, toasts, lab, repo, bus, tz, data_dir, packets)
    return Runtime(services, toasts, journal)
