import asyncio
from collections.abc import Iterator
from datetime import UTC
from pathlib import Path

import pytest
from fakes import ETH, LOOP, FakeClock, FakePort

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import SensorStateChanged
from snorty.core.repository import AlertRepository
from snorty.sensor.config import SensorConfig
from snorty.sensor.sensor import Sensor
from snorty.sensor.states import IllegalTransition, State
from snorty.snort.models import SnortError, SnortPaths


class Rig:
    def __init__(self, tmp_path: Path, **cfg: object) -> None:
        self.log_dir = tmp_path / "log"
        self.port = FakePort()
        self.clock = FakeClock()
        self.bus = EventBus()
        self.sub: Subscription = self.bus.subscribe()
        self.repo = AlertRepository(tmp_path / "a.db")
        config = SensorConfig(paths=SnortPaths(log_dir=self.log_dir), **cfg)  # type: ignore[arg-type]
        self.sensor = Sensor(
            config, self.port, self.repo, self.bus, clock=self.clock, sleep=self.clock.sleep, tz=UTC
        )

    @property
    def pid_file(self) -> Path:
        return self.log_dir / "snorty-sensor.pid"

    def transitions(self) -> list[tuple[str, str, str | None]]:
        out = []
        while True:
            try:
                ev = self.sub._queue.get_nowait()  # drain without awaiting
            except asyncio.QueueEmpty:
                return out
            assert isinstance(ev, SensorStateChanged)
            out.append((ev.old, ev.new, ev.reason))


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    yield r
    r.repo.close()


async def test_start_reaches_running_and_publishes_each_step(rig: Rig) -> None:
    await rig.sensor.start()
    assert rig.sensor.state is State.RUNNING
    steps = rig.transitions()
    assert [(o, n) for o, n, _ in steps] == [("stopped", "starting"), ("starting", "running")]
    await rig.sensor.stop()


async def test_start_is_idempotent(rig: Rig) -> None:
    await rig.sensor.start()
    await rig.sensor.start()
    assert len(rig.port.start_calls) == 1
    await rig.sensor.stop()


async def test_stop_runs_stopping_then_stopped_and_is_idempotent(rig: Rig) -> None:
    await rig.sensor.start()
    rig.transitions()
    await rig.sensor.stop()
    await rig.sensor.stop()
    assert rig.sensor.state is State.STOPPED
    assert [(o, n) for o, n, _ in rig.transitions()] == [
        ("running", "stopping"),
        ("stopping", "stopped"),
    ]
    assert len(rig.port.stop_calls) == 1
    assert not rig.pid_file.exists()


async def test_stop_when_never_started_is_a_noop(rig: Rig) -> None:
    await rig.sensor.stop()
    assert rig.sensor.state is State.STOPPED and rig.transitions() == []


async def test_stop_during_start_stops_the_new_process(rig: Rig) -> None:
    rig.port.start_gate = asyncio.Event()
    starter = asyncio.create_task(rig.sensor.start())
    while not rig.port.start_calls:
        await asyncio.sleep(0.001)
    assert rig.sensor.state is State.STARTING
    stopper = asyncio.create_task(rig.sensor.stop())
    await asyncio.sleep(0.01)
    rig.port.start_gate.set()
    await asyncio.wait_for(asyncio.gather(starter, stopper), 2)
    assert rig.sensor.state is State.STOPPED
    assert len(rig.port.stop_calls) == 1


async def test_stop_from_failed_goes_to_stopped(rig: Rig) -> None:
    rig.port.ip = None
    await rig.sensor.start()
    assert rig.sensor.state is State.FAILED
    await rig.sensor.stop()
    assert rig.sensor.state is State.STOPPED


async def test_no_matching_interface_fails_without_starting(tmp_path: Path) -> None:
    r = Rig(tmp_path, interface_ip="10.9.9.9")
    await r.sensor.start()
    assert r.sensor.state is State.FAILED
    assert r.port.start_calls == []
    assert "no interface has IP 10.9.9.9" in (r.sensor.status().reason or "")
    r.repo.close()


async def test_no_network_route_fails(rig: Rig) -> None:
    rig.port.ip = None
    await rig.sensor.start()
    assert rig.sensor.state is State.FAILED
    assert "no network route" in (rig.sensor.status().reason or "")


async def test_default_choice_follows_local_ip(rig: Rig) -> None:
    await rig.sensor.start()
    assert rig.port.start_calls[0].ip == "192.168.10.230"
    await rig.sensor.stop()


async def test_config_override_beats_local_ip(tmp_path: Path) -> None:
    r = Rig(tmp_path, interface_ip=ETH.ip)
    await r.sensor.start()
    assert r.port.start_calls == [ETH]
    await r.sensor.stop()
    r.repo.close()


async def test_select_interface_callback_overrides_everything(tmp_path: Path) -> None:
    r = Rig(tmp_path)
    r.sensor = Sensor(
        SensorConfig(paths=SnortPaths(log_dir=r.log_dir)), r.port, r.repo, r.bus,
        clock=r.clock, sleep=r.clock.sleep, tz=UTC,
        select_interface=lambda ifaces: next(i for i in ifaces if i.device.endswith("Loopback")),
    )  # fmt: skip
    await r.sensor.start()
    assert r.port.start_calls == [LOOP]
    await r.sensor.stop()
    r.repo.close()


async def test_pid_file_lifecycle(rig: Rig) -> None:
    await rig.sensor.start()
    assert rig.pid_file.read_text().strip() == str(rig.port.procs[0].pid)
    await rig.sensor.stop()
    assert not rig.pid_file.exists()


async def test_stale_pid_file_is_overwritten(rig: Rig) -> None:
    rig.log_dir.mkdir(parents=True)
    rig.pid_file.write_text("31337")  # not running
    await rig.sensor.start()
    assert rig.sensor.state is State.RUNNING
    assert rig.pid_file.read_text().strip() == str(rig.port.procs[0].pid)
    await rig.sensor.stop()


async def test_live_snort_in_pid_file_refuses_to_start(rig: Rig) -> None:
    rig.log_dir.mkdir(parents=True)
    rig.pid_file.write_text("4242")
    rig.port.running_pids.add(4242)
    await rig.sensor.start()
    assert rig.sensor.state is State.FAILED
    assert "Snort already running (pid 4242)" in (rig.sensor.status().reason or "")
    assert rig.port.start_calls == []
    assert rig.pid_file.read_text() == "4242"  # not ours: left alone


async def test_start_error_from_snort_fails_with_reason(rig: Rig) -> None:
    rig.port.start_error = SnortError("snort exited early (code 1)")
    await rig.sensor.start()
    status = rig.sensor.status()
    assert status.state is State.FAILED
    assert "exited early" in (status.reason or "") and "exited early" in (status.last_error or "")
    assert not rig.pid_file.exists()


async def test_illegal_transition_raises(rig: Rig) -> None:
    with pytest.raises(IllegalTransition):
        rig.sensor._transition(State.RUNNING, None)


async def test_status_snapshot(rig: Rig) -> None:
    await rig.sensor.start()
    status = rig.sensor.status()
    assert status.state is State.RUNNING
    assert status.interface is not None and status.interface.index == 4
    assert status.pid == rig.port.procs[0].pid
    assert status.started_at is not None
    await rig.sensor.stop()
    assert rig.sensor.status().pid is None


async def test_start_after_stop_starts_a_new_process(rig: Rig) -> None:
    await rig.sensor.start()
    await rig.sensor.stop()
    await rig.sensor.start()
    assert len(rig.port.start_calls) == 2 and rig.sensor.state is State.RUNNING
    await rig.sensor.stop()
