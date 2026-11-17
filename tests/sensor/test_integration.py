"""Real Snort on the loopback adapter. Needs C:\\Snort; run with `pytest -m snort`."""

import asyncio
import os
import socket
import time
from collections.abc import Callable, Iterator
from datetime import UTC
from pathlib import Path

import pytest

from snorty.core.bus import EventBus
from snorty.core.repository import AlertRepository
from snorty.sensor import Sensor, SensorConfig, SnortAdapter, State
from snorty.snort.models import Interface, SnortPaths

pytestmark = pytest.mark.snort


def loopback(interfaces: list[Interface]) -> Interface | None:
    return next((i for i in interfaces if "Loopback" in i.device), None)


async def eventually(check: Callable[[], bool], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.25)


def send_attack_traffic() -> None:
    """A server answers a client with `uid=0(root)`: trips the 'id check returned root' rule."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, _ = srv.accept()
    cli.sendall(b"id\n")
    conn.recv(16)
    conn.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n")
    cli.recv(100)
    for s in (cli, conn, srv):
        s.close()


@pytest.fixture
def rig(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[Sensor, AlertRepository]]:
    async def no_perfmon(*_: object) -> None:  # a test must not edit the real snort.conf
        return None

    monkeypatch.setattr("snorty.sensor.port.enable_perfmon", no_perfmon)
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    paths = SnortPaths(log_dir=log_dir)
    repo = AlertRepository(tmp_path / "a.db")
    sensor = Sensor(
        SensorConfig(paths=paths, stop_timeout=15),
        SnortAdapter(paths),
        repo,
        EventBus(),
        clock=time.monotonic,
        sleep=asyncio.sleep,
        tz=UTC,
        select_interface=loopback,
    )
    yield sensor, repo
    repo.close()


async def test_live_alert_then_clean_stop(rig: tuple[Sensor, AlertRepository]) -> None:
    sensor, repo = rig
    await sensor.start()
    assert sensor.state is State.RUNNING
    try:
        send_attack_traffic()
        await eventually(lambda: len(repo.query()) > 0, timeout=30)
    finally:
        await sensor.stop()
    assert sensor.state is State.STOPPED
    assert not (sensor._pid_path).exists()


async def test_killed_snort_is_restarted(rig: tuple[Sensor, AlertRepository]) -> None:
    sensor, _ = rig
    await sensor.start()
    try:
        first = sensor.status().pid
        assert first is not None
        os.kill(first, 9)
        await eventually(
            lambda: sensor.status().restarts == 1 and sensor.state is State.RUNNING, 60
        )
        assert sensor.status().pid != first
    finally:
        await sensor.stop()
