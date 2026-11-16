import asyncio
from datetime import UTC, datetime
from pathlib import Path

from test_repository import make_alert

from snorty.core.bus import EventBus
from snorty.core.events import AlertRaised
from snorty.core.query import AlertQuery
from snorty.core.repository import AlertRepository
from snorty.triage import TriageService

NOW = datetime(2026, 11, 16, tzinfo=UTC)


async def eventually(check) -> None:  # type: ignore[no-untyped-def]
    for _ in range(400):
        if check():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not met in time")


async def test_alerts_matching_an_archive_rule_are_acknowledged_as_they_arrive(
    tmp_path: Path,
) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    bus = EventBus()
    repo.add_archive_rule(AlertQuery(sid=1000), "noisy", NOW)
    old = make_alert(1, sid=1000)  # stored while Snorty was down
    repo.add(old)
    svc = TriageService(bus, repo, now=lambda: NOW)
    await svc.start()
    await eventually(lambda: repo.counts_by_state(AlertQuery())["ack"] == 1)

    live = [make_alert(n, sid=1000 + n % 2) for n in range(2, 8)]
    repo.add_many(live)
    for a in live:
        bus.publish(AlertRaised(a))
    await eventually(lambda: repo.counts_by_state(AlertQuery())["ack"] == 4)
    assert repo.counts_by_state(AlertQuery())["new"] == 3  # the other rule stays in the inbox
    await svc.stop()
    repo.close()
