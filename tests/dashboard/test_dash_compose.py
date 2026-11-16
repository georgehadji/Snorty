from pathlib import Path
from types import SimpleNamespace

import pytest
from dash_fakes import make_services

from snorty.compose import Runtime, compose
from snorty.core.localtz import LocalTimezone
from snorty.journal.ports import MemoryNoteStore
from snorty.notify.ports import ConsoleNotifier
from snorty.sensor import State
from snorty.snort import SnortPaths


async def test_compose_builds_every_service_and_starts_and_stops_without_snort(
    tmp_path: Path,
) -> None:
    rt = compose(
        tmp_path / "data",
        notify=True,
        notifier=ConsoleNotifier(),
        journal_store=MemoryNoteStore(),
        paths=SnortPaths(),
    )
    try:
        s = rt.services
        assert (tmp_path / "data" / "snorty.db").exists()
        assert s.sensor.state is State.STOPPED
        assert s.journal is not None and rt.notify is not None
        assert s.pcap_dir == tmp_path / "data" / "pcaps"
        assert isinstance(s.tz, LocalTimezone)  # DST-aware, not one fixed offset
        await rt.start(sensor=False)
        await rt.stop()
        assert s.sensor.state is State.STOPPED
    finally:
        rt.services.repo.close()


async def test_compose_without_journal_or_notify(tmp_path: Path) -> None:
    rt = compose(tmp_path)
    try:
        assert rt.services.journal is None and rt.notify is None
        await rt.start()
        await rt.stop()
    finally:
        rt.services.repo.close()


class Part:
    """A started and stopped piece that can be made to fail."""

    def __init__(
        self, name: str, log: list[str], *, fail_start: bool = False, fail_stop: bool = False
    ):
        self.name, self.log = name, log
        self.fail_start, self.fail_stop = fail_start, fail_stop

    async def start(self) -> None:
        self.log.append(f"start {self.name}")
        if self.fail_start:
            raise RuntimeError(f"{self.name} would not start")

    async def stop(self) -> None:
        self.log.append(f"stop {self.name}")
        if self.fail_stop:
            raise RuntimeError(f"{self.name} would not stop")


def runtime(log: list[str], **fail: bool) -> Runtime:
    sensor = Part("sensor", log, fail_stop=fail.get("sensor_stop", False))
    return Runtime(
        SimpleNamespace(sensor=sensor),  # type: ignore[arg-type]
        Part("notify", log),  # type: ignore[arg-type]
        Part("journal", log, fail_start=fail.get("journal_start", False)),  # type: ignore[arg-type]
    )


async def test_a_part_that_will_not_stop_does_not_keep_the_others_running() -> None:
    log: list[str] = []
    with pytest.raises(RuntimeError, match="sensor would not stop"):
        await runtime(log, sensor_stop=True).stop()
    assert log == ["stop sensor", "stop journal", "stop notify"]


async def test_a_start_that_fails_stops_what_had_started() -> None:
    log: list[str] = []
    with pytest.raises(RuntimeError, match="journal would not start"):
        await runtime(log, journal_start=True).start()
    assert log == ["start notify", "start journal", "stop sensor", "stop journal", "stop notify"]


def test_fake_services_have_the_pieces_the_pages_need(tmp_path: Path) -> None:
    s = make_services(tmp_path)
    assert s.sensor.state is State.STOPPED
    assert s.repo.query() == []
    s.repo.close()
