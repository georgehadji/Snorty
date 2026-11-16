import asyncio
from pathlib import Path

import pytest

import snorty.sensor.__main__ as cli
from snorty.journal.ports import MemoryNoteStore

order: list[str] = []


class Quiet:
    async def show(self, toast: object) -> None:
        pass


class StubSensor:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.state = type("S", (), {"name": "STOPPED"})()

    async def start(self) -> None:
        order.append("sensor.start")

    async def stop(self) -> None:
        order.append("sensor.stop")


def stub_service(name: str) -> type:
    class Stub:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def start(self) -> None:
            order.append(f"{name}.start")

        async def stop(self) -> None:
            order.append(f"{name}.stop")

    return Stub


@pytest.fixture(autouse=True)
def _stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    order.clear()
    monkeypatch.setattr(cli, "Sensor", StubSensor)
    monkeypatch.setattr(cli, "JournalService", stub_service("journal"))
    monkeypatch.setattr(cli, "NotifyService", stub_service("notify"))


def test_journal_starts_before_the_sensor_and_stops_after(tmp_path: Path) -> None:
    code = asyncio.run(
        cli.run(tmp_path / "a.db", None, journal=True, journal_store=MemoryNoteStore())
    )
    assert code == 0
    assert order == ["journal.start", "sensor.start", "sensor.stop", "journal.stop"]


def test_journal_and_notify_together(tmp_path: Path) -> None:
    asyncio.run(
        cli.run(
            tmp_path / "b.db",
            None,
            notify=True,
            notifier=Quiet(),
            journal=True,
            journal_store=MemoryNoteStore(),
        )
    )
    assert order == [
        "notify.start",
        "journal.start",
        "sensor.start",
        "sensor.stop",
        "journal.stop",
        "notify.stop",
    ]


def test_without_the_flag_no_journal_runs(tmp_path: Path) -> None:
    asyncio.run(cli.run(tmp_path / "c.db", None))
    assert order == ["sensor.start", "sensor.stop"]


def test_journal_without_a_vault_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("OBSIDIAN_VAULT_PATH", raising=False)
    monkeypatch.setattr("sys.argv", ["snorty.sensor", "--journal"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
