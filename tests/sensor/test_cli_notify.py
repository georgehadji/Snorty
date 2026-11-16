import asyncio
from pathlib import Path

import pytest

import snorty.compose as compose_mod
import snorty.headless as cli


class StubSensor:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.state = type("S", (), {"name": "STOPPED"})()
        self.order = cli_order

    async def start(self) -> None:
        cli_order.append("sensor.start")

    async def stop(self) -> None:
        cli_order.append("sensor.stop")


cli_order: list[str] = []


class Quiet:
    async def show(self, toast: object) -> None:
        pass


class StubNotify:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def start(self) -> None:
        cli_order.append("notify.start")

    async def stop(self) -> None:
        cli_order.append("notify.stop")


@pytest.fixture(autouse=True)
def _stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    cli_order.clear()
    monkeypatch.setattr(compose_mod, "Sensor", StubSensor)
    monkeypatch.setattr(compose_mod, "NotifyService", StubNotify)


def test_notify_starts_before_the_sensor_and_stops_after(tmp_path: Path) -> None:
    code = asyncio.run(cli.run(tmp_path / "a.db", None, notify=True, notifier=Quiet()))
    assert code == 0
    assert cli_order == ["notify.start", "sensor.start", "sensor.stop", "notify.stop"]


def test_without_the_flag_no_notify_service_runs(tmp_path: Path) -> None:
    asyncio.run(cli.run(tmp_path / "b.db", None))
    assert cli_order == ["sensor.start", "sensor.stop"]
