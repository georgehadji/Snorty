"""The measurable success criteria from SPEC-alert-core.md."""

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from snorty.core.bus import EventBus
from snorty.core.events import RulesUpdated
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository


def make_alerts(n: int) -> list[Alert]:
    t0 = datetime(2026, 11, 15, tzinfo=UTC)
    return [
        Alert(
            ts=t0 + timedelta(milliseconds=i), gid=1, sid=1000 + i % 7, rev=1, msg="m",
            classification=None, priority=2, proto="TCP", src_ip="10.0.0.1", src_port=1,
            dst_ip="10.0.0.2", dst_port=2, raw=f"line {i}",
        )
        for i in range(n)
    ]  # fmt: skip


def test_same_1000_alerts_stored_twice_leave_1000_rows(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "a.db")
    alerts = make_alerts(1000)
    assert repo.add_many(alerts) == 1000
    assert repo.add_many(alerts) == 0
    for a in alerts[:50]:
        assert repo.add(a) is False
    assert len(repo.query(limit=5000)) == 1000
    repo.close()


async def test_stalled_subscriber_does_not_slow_publisher() -> None:
    bus = EventBus()
    stalled = bus.subscribe()  # never read
    event = RulesUpdated(ok=True, rule_count=1, detail="")
    start = time.perf_counter()
    for _ in range(10_000):
        bus.publish(event)
    assert time.perf_counter() - start < 1.0
    assert stalled.dropped == 9_000  # default maxsize 1000
