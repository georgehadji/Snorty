import asyncio
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fakes import FakeClock, FakePort

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised
from snorty.core.repository import AlertRepository
from snorty.sensor.config import SensorConfig
from snorty.sensor.sensor import Sensor
from snorty.snort.models import SnortPaths


def line(n: int, sid: int = 1000002) -> str:
    ts = datetime(2026, 11, 16, 1, 0, 0, tzinfo=UTC) + timedelta(seconds=n)
    stamp = ts.strftime("%m/%d/%y-%H:%M:%S") + f".{n:06d}"
    return (
        f"{stamp}  [**] [1:{sid}:1] test rule {sid} [**] [Priority: 1] "
        f"{{TCP}} 10.0.0.1:{1000 + n} -> 10.0.0.2:80"
    )


async def eventually(check: Callable[[], bool], timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.002)


class Rig:
    def __init__(self, tmp_path: Path, repo: AlertRepository | None = None) -> None:
        self.log_dir = tmp_path / "log"
        self.log_dir.mkdir(exist_ok=True)
        self.alerts = self.log_dir / "alert.ids"
        self.port = FakePort()
        self.clock = FakeClock()
        self.bus = EventBus()
        self.sub: Subscription = self.bus.subscribe(maxsize=100_000)
        self.repo = repo or AlertRepository(tmp_path / "a.db")
        self.sensor = Sensor(
            SensorConfig(paths=SnortPaths(log_dir=self.log_dir)),
            self.port, self.repo, self.bus,
            clock=self.clock, sleep=self.clock.sleep, tz=UTC,
        )  # fmt: skip

    def append(self, *lines: str) -> None:
        with self.alerts.open("a", newline="") as fh:
            fh.write("".join(ln + "\r\n" for ln in lines))

    def raised(self) -> list[AlertRaised]:
        out: list[AlertRaised] = []
        while True:
            try:
                ev = self.sub._queue.get_nowait()
            except asyncio.QueueEmpty:
                return [e for e in out if isinstance(e, AlertRaised)]
            out.append(ev)  # type: ignore[arg-type]

    def stored(self) -> int:
        return len(self.repo.query(limit=100_000))


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    yield r
    r.repo.close()


async def test_backlog_is_stored_but_not_announced(rig: Rig) -> None:
    rig.append(line(1), line(2), line(3))
    await rig.sensor.start()
    assert rig.stored() == 3
    assert rig.raised() == []
    assert rig.sensor.status().alerts_seen == 3
    await rig.sensor.stop()


async def test_live_alert_is_stored_and_announced_once(rig: Rig) -> None:
    await rig.sensor.start()
    rig.append(line(5))
    await eventually(lambda: rig.stored() == 1)
    await asyncio.sleep(0.02)  # several more polls must not re-announce it
    events = rig.raised()
    assert [e.alert.sid for e in events] == [1000002]
    assert events[0].alert.src_port == 1005
    await rig.sensor.stop()


async def test_restart_with_same_file_creates_no_duplicates_or_events(tmp_path: Path) -> None:
    first = Rig(tmp_path)
    first.append(line(1), line(2))
    await first.sensor.start()
    first.append(line(3))
    await eventually(lambda: first.stored() == 3)
    await first.sensor.stop()

    second = Rig(tmp_path, repo=first.repo)  # new Sensor, same DB and alert file
    await second.sensor.start()
    await asyncio.sleep(0.02)
    assert second.stored() == 3
    assert second.raised() == []
    await second.sensor.stop()
    first.repo.close()


async def test_junk_lines_are_counted_not_fatal(rig: Rig) -> None:
    await rig.sensor.start()
    rig.append("this is not an alert", line(1))
    await eventually(lambda: rig.stored() == 1)
    assert rig.sensor.status().unparsed == 1
    assert rig.sensor.state.name == "RUNNING"
    await rig.sensor.stop()


async def test_event_loop_stays_responsive_during_big_backlog(rig: Rig) -> None:
    rig.append(*[line(i % 3000, sid=2000000 + i) for i in range(5000)])
    gaps: list[float] = []

    async def ticker() -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(0.01)
            now = time.monotonic()
            gaps.append(now - last)
            last = now

    task = asyncio.create_task(ticker())
    await rig.sensor.start()
    task.cancel()
    assert rig.stored() == 5000
    assert max(gaps) < 0.25
    await rig.sensor.stop()


async def test_final_pass_on_stop_ingests_the_last_alert(rig: Rig) -> None:
    await rig.sensor.start()
    await eventually(lambda: rig.clock.sleeps != [])  # ingest loop has polled once
    rig.clock.block = True  # from now on the loop sleeps until released
    await asyncio.sleep(0.02)
    rig.append(line(7))
    await rig.sensor.stop()
    assert rig.stored() == 1
    assert len(rig.raised()) == 1


async def test_status_tracks_latest_alert_time(rig: Rig) -> None:
    rig.append(line(9), line(2))
    await rig.sensor.start()
    last = rig.sensor.status().last_alert_ts
    assert last is not None and last.second == 9
    await rig.sensor.stop()


async def test_rotated_file_is_read_again_and_announced(rig: Rig) -> None:
    rig.append(line(1), line(2), line(3))
    await rig.sensor.start()
    rig.alerts.write_bytes((line(8) + "\n").encode())  # shorter than before: rotated
    await eventually(lambda: rig.stored() == 4)
    assert [e.alert.src_port for e in rig.raised()] == [1008]
    await rig.sensor.stop()


async def test_database_error_loses_nothing(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    await rig.sensor.start()
    real = rig.repo.add_new
    calls = {"n": 0}

    def flaky(alerts: object) -> list:  # type: ignore[type-arg]
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("disk full")
        return real(alerts)  # type: ignore[arg-type]

    monkeypatch.setattr(rig.repo, "add_new", flaky)
    rig.append(line(4))
    await eventually(lambda: rig.stored() == 1)
    assert "disk full" in (rig.sensor.status().last_error or "")
    assert rig.sensor.state.name == "RUNNING"
    assert len(rig.raised()) == 1
    await rig.sensor.stop()
