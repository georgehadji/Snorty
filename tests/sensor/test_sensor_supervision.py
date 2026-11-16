import asyncio
import time
from collections.abc import Callable, Iterator
from datetime import UTC
from pathlib import Path

import pytest
from fakes import ETH, WIFI, FakeClock, FakePort

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import SensorStateChanged
from snorty.core.repository import AlertRepository
from snorty.sensor.config import SensorConfig
from snorty.sensor.sensor import Sensor
from snorty.sensor.states import State
from snorty.snort.models import SnortPaths


async def eventually(check: Callable[[], bool], timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.002)


class Rig:
    def __init__(self, tmp_path: Path, **cfg: object) -> None:
        self.log_dir = tmp_path / "log"
        self.port = FakePort()
        self.clock = FakeClock()
        self.bus = EventBus()
        self.sub: Subscription = self.bus.subscribe(maxsize=100_000)
        self.repo = AlertRepository(tmp_path / "a.db")
        self.sensor = Sensor(
            SensorConfig(paths=SnortPaths(log_dir=self.log_dir), network_check_interval=0.5, **cfg),  # type: ignore[arg-type]
            self.port, self.repo, self.bus,
            clock=self.clock, sleep=self.clock.sleep, tz=UTC,
        )  # fmt: skip

    def steps(self) -> list[tuple[str, str, str | None]]:
        out: list[tuple[str, str, str | None]] = []
        while True:
            try:
                ev = self.sub._queue.get_nowait()
            except asyncio.QueueEmpty:
                return out
            if isinstance(ev, SensorStateChanged):
                out.append((ev.old, ev.new, ev.reason))

    def running_on(self, procs: int) -> bool:
        return self.sensor.state is State.RUNNING and len(self.port.procs) == procs


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    yield r
    r.repo.close()


async def test_crash_restarts_after_backoff(rig: Rig) -> None:
    await rig.sensor.start()
    rig.steps()
    rig.port.procs[0].exit(3)
    await eventually(lambda: rig.running_on(2))
    assert 2.0 in rig.clock.sleeps
    states = rig.steps()
    assert states[0][:2] == ("running", "starting")
    assert "code 3" in (states[0][2] or "")
    assert states[-1][:2] == ("starting", "running")
    assert rig.sensor.status().restarts == 1
    assert [p.returncode is None for p in rig.port.procs] == [False, True]
    await rig.sensor.stop()


async def test_repeated_crashes_back_off_then_fail(rig: Rig) -> None:
    rig.port.crash_on_start = True
    await rig.sensor.start()
    await eventually(lambda: rig.sensor.state is State.FAILED)
    assert len(rig.port.procs) == 5
    assert [s for s in rig.clock.sleeps if s >= 2] == [2.0, 4.0, 8.0, 16.0]
    assert "gave up" in (rig.sensor.status().reason or "")
    assert not (rig.log_dir / "snorty-sensor.pid").exists()


async def test_a_stable_run_resets_the_failure_count(rig: Rig) -> None:
    await rig.sensor.start()
    for n in (1, 2, 3):
        rig.clock.now += 100  # the run lasted longer than stable_after
        rig.port.procs[-1].exit(1)
        await eventually(lambda n=n: rig.running_on(n + 1))
    assert [s for s in rig.clock.sleeps if s >= 2] == [2.0, 2.0, 2.0]
    await rig.sensor.stop()


async def test_failed_start_attempts_retry_then_succeed(rig: Rig) -> None:
    rig.port.start_failures = 2
    await rig.sensor.start()
    assert rig.sensor.state is State.RUNNING
    assert len(rig.port.start_calls) == 3
    assert [s for s in rig.clock.sleeps if s >= 2] == [2.0, 4.0]
    reasons = [r for _, n, r in rig.steps() if n == "starting" and r]
    assert any("retry 1/5 in 2s" in r for r in reasons)
    await rig.sensor.stop()


async def test_failed_start_attempts_give_up(rig: Rig) -> None:
    rig.port.start_failures = 99
    await rig.sensor.start()
    assert rig.sensor.state is State.FAILED
    assert len(rig.port.start_calls) == 5
    assert "gave up after 5 attempts" in (rig.sensor.status().reason or "")


async def test_network_change_restarts_onto_the_new_interface(rig: Rig) -> None:
    await rig.sensor.start()
    rig.steps()
    rig.port.ip = ETH.ip
    await eventually(lambda: rig.running_on(2))
    assert rig.port.start_calls == [WIFI, ETH]
    assert any("network changed" in (r or "") for _, _, r in rig.steps())
    assert 2.0 not in rig.clock.sleeps  # an interface change restarts at once, no backoff
    await rig.sensor.stop()


async def test_no_network_route_does_not_restart(rig: Rig) -> None:
    await rig.sensor.start()
    rig.port.ip = None
    await asyncio.sleep(0.05)
    assert len(rig.port.start_calls) == 1 and rig.sensor.state is State.RUNNING
    await rig.sensor.stop()


async def test_no_network_watch_when_interface_is_pinned(tmp_path: Path) -> None:
    r = Rig(tmp_path, interface_ip=WIFI.ip)
    await r.sensor.start()
    r.port.ip = ETH.ip
    await asyncio.sleep(0.05)
    assert len(r.port.start_calls) == 1
    await r.sensor.stop()
    r.repo.close()


async def test_restart_command(rig: Rig) -> None:
    await rig.sensor.start()
    rig.steps()
    await rig.sensor.restart()
    assert rig.sensor.state is State.RUNNING
    assert len(rig.port.procs) == 2 and rig.port.stop_calls == [rig.port.procs[0]]
    assert [(o, n) for o, n, _ in rig.steps() if (o, n) != ("starting", "starting")] == [
        ("running", "starting"),
        ("starting", "running"),
    ]
    await rig.sensor.stop()


async def test_restart_during_a_crash_backoff_waits_until_the_sensor_runs_again(rig: Rig) -> None:
    await rig.sensor.start()
    rig.clock.block = True  # the backoff sleep waits until released
    rig.port.procs[0].exit(1)
    await eventually(lambda: rig.sensor.state is State.STARTING)
    waiter = asyncio.create_task(rig.sensor.restart())
    await asyncio.sleep(0.02)
    assert not waiter.done()  # it used to return at once, while the sensor was still starting
    rig.clock.release()
    await asyncio.wait_for(waiter, 2)
    assert rig.sensor.state is State.RUNNING
    await rig.sensor.stop()


async def test_restart_when_stopped_just_starts(rig: Rig) -> None:
    await rig.sensor.restart()
    assert rig.sensor.state is State.RUNNING and len(rig.port.procs) == 1
    await rig.sensor.stop()


async def test_stop_during_backoff_wait_is_prompt(rig: Rig) -> None:
    await rig.sensor.start()
    rig.clock.block = True  # backoff sleeps now wait until released
    rig.port.procs[0].exit(1)
    await eventually(lambda: rig.sensor.state is State.STARTING)
    await asyncio.wait_for(rig.sensor.stop(), 1)
    assert rig.sensor.state is State.STOPPED
    assert len(rig.port.start_calls) == 1  # never restarted


async def test_alert_written_just_before_a_crash_is_still_ingested(rig: Rig) -> None:
    rig.log_dir.mkdir(parents=True)
    await rig.sensor.start()
    rig.clock.block = True
    await asyncio.sleep(0.02)
    line = (
        "11/16/26-01:00:00.000001  [**] [1:1000002:1] x [**] [Priority: 1] "
        "{TCP} 10.0.0.1:1 -> 10.0.0.2:2"
    )
    (rig.log_dir / "alert.ids").write_text(line + "\n")
    rig.port.procs[0].exit(1)
    await eventually(lambda: len(rig.repo.query()) == 1)
    await rig.sensor.stop()
