"""What the dashboard's controllers may use: the module services behind small Protocols."""

from dataclasses import dataclass
from datetime import tzinfo
from pathlib import Path
from typing import Protocol

from fastapi import Request

from snorty.core.bus import EventBus
from snorty.core.repository import AlertRepository
from snorty.lab.models import LabJob, LabResult
from snorty.rules.blocks import MutedRule
from snorty.rules.service import EditReport, UpdateReport
from snorty.rules.state import RulesState
from snorty.sensor import SensorStatus, State


class SensorPort(Protocol):
    @property
    def state(self) -> State: ...

    def status(self) -> SensorStatus: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def restart(self) -> None: ...


class RulesPort(Protocol):
    async def update(self, *, force: bool = False) -> UpdateReport: ...

    async def status(self) -> RulesState: ...

    async def muted(self) -> list[MutedRule]: ...

    async def mute(self, sid: int, note: str = "", *, restart: bool = True) -> EditReport: ...

    async def unmute(self, sid: int, *, restart: bool = True) -> EditReport: ...

    async def home_net(self) -> tuple[str, str]: ...

    async def set_home_net(
        self, value: str | None = None, *, restart: bool = True
    ) -> EditReport: ...


class JournalPort(Protocol):
    async def flush(self) -> None: ...


class LabPort(Protocol):
    async def run(self, job: LabJob) -> LabResult: ...

    async def check(self, rules_text: str) -> LabResult: ...


@dataclass(frozen=True, slots=True)
class Services:
    sensor: SensorPort
    rules: RulesPort
    journal: JournalPort | None
    lab: LabPort
    repo: AlertRepository
    bus: EventBus
    tz: tzinfo
    data_dir: Path

    @property
    def pcap_dir(self) -> Path:
        return self.data_dir / "pcaps"


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services
