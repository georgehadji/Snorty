"""Test doubles for the notify service tests."""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from snorty.core.bus import EventBus
from snorty.core.events import AlertRaised
from snorty.core.models import Alert
from snorty.notify.toast import Toast

TS = datetime(2026, 11, 16, 1, 2, 3, tzinfo=UTC)


def make_alert(sid: int = 1000002, priority: int = 1, **kw: object) -> Alert:
    base: dict[str, object] = {
        "ts": TS,
        "gid": 1,
        "sid": sid,
        "rev": 1,
        "msg": f"rule {sid}",
        "classification": None,
        "priority": priority,
        "proto": "TCP",
        "src_ip": "10.0.0.1",
        "src_port": 4444,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "raw": f"raw {sid}",
    }
    base.update(kw)
    return Alert(**base)  # type: ignore[arg-type]


class RecordingNotifier:
    def __init__(self) -> None:
        self.toasts: list[Toast] = []

    async def show(self, toast: Toast) -> None:
        self.toasts.append(toast)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def raise_alert(bus: EventBus, alert: object) -> None:
    bus.publish(AlertRaised(alert))  # type: ignore[arg-type]


async def settle(until: Callable[[], bool] | None = None, timeout: float = 1.0) -> None:
    """Let the consumer task run. With `until`, wait for it; without, just give it time."""
    if until is None:
        await asyncio.sleep(0.03)
        return
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not until():
        if loop.time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.002)
