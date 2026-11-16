import asyncio
from datetime import datetime, timedelta

import pytest

from snorty.dashboard.schedule import run_daily


class Clock:
    """A fake wall clock: sleeping moves it forward, and a hook can stop the loop."""

    def __init__(self, start: datetime) -> None:
        self.t = start
        self.fired: list[datetime] = []
        self.stop_after: int | None = None
        self.jump: timedelta | None = None  # the next sleep takes this long (a suspended PC)

    def now(self) -> datetime:
        return self.t

    async def sleep(self, seconds: float) -> None:
        if self.stop_after is not None and len(self.fired) >= self.stop_after:
            raise asyncio.CancelledError
        self.t += self.jump if self.jump is not None else timedelta(seconds=seconds)
        self.jump = None

    async def update(self) -> None:
        self.fired.append(self.t)


async def run(clock: Clock, at: str = "03:00", stop_after: int = 1) -> None:
    clock.stop_after = stop_after
    try:
        await run_daily(clock.update, at, now=clock.now, sleep=clock.sleep)
    except asyncio.CancelledError:
        pass


async def test_fires_at_the_set_time() -> None:
    c = Clock(datetime(2026, 11, 16, 2, 0))
    await run(c)
    assert c.fired == [datetime(2026, 11, 16, 3, 0)]


async def test_started_after_the_time_waits_for_tomorrow() -> None:
    c = Clock(datetime(2026, 11, 16, 3, 30))
    await run(c)
    assert c.fired == [datetime(2026, 11, 17, 3, 0)]


async def test_started_exactly_at_the_time_waits_for_tomorrow() -> None:
    c = Clock(datetime(2026, 11, 16, 3, 0))
    await run(c)
    assert c.fired == [datetime(2026, 11, 17, 3, 0)]


async def test_runs_once_a_day_over_several_days() -> None:
    c = Clock(datetime(2026, 11, 16, 12, 0))
    await run(c, stop_after=3)
    assert c.fired == [
        datetime(2026, 11, 17, 3, 0),
        datetime(2026, 11, 18, 3, 0),
        datetime(2026, 11, 19, 3, 0),
    ]


async def test_an_empty_time_disables_the_schedule() -> None:
    c = Clock(datetime(2026, 11, 16, 2, 0))
    await run_daily(c.update, "", now=c.now, sleep=c.sleep)  # returns at once
    assert c.fired == [] and c.t == datetime(2026, 11, 16, 2, 0)


async def test_a_failing_update_does_not_stop_the_loop(caplog: pytest.LogCaptureFixture) -> None:
    c = Clock(datetime(2026, 11, 16, 12, 0))
    calls = 0

    async def flaky() -> None:
        nonlocal calls
        calls += 1
        c.fired.append(c.t)
        if calls == 1:
            raise RuntimeError("download failed")

    c.stop_after = 2
    with caplog.at_level("ERROR"):
        try:
            await run_daily(flaky, "03:00", now=c.now, sleep=c.sleep)
        except asyncio.CancelledError:
            pass
    assert len(c.fired) == 2
    assert any("download failed" in r.getMessage() or r.exc_info for r in caplog.records)


async def test_a_suspended_pc_does_not_catch_up_a_missed_update() -> None:
    c = Clock(datetime(2026, 11, 16, 2, 0))
    c.jump = timedelta(hours=7)  # sleeps through 03:00, wakes at 09:00
    await run(c)
    assert c.fired == [datetime(2026, 11, 17, 3, 0)]


async def test_a_short_delay_after_the_time_still_fires() -> None:
    c = Clock(datetime(2026, 11, 16, 2, 59))
    c.jump = timedelta(minutes=20)  # wakes at 03:19, inside the grace period
    await run(c)
    assert c.fired == [datetime(2026, 11, 16, 3, 19)]


async def test_a_bad_time_is_refused_up_front() -> None:
    c = Clock(datetime(2026, 11, 16, 2, 0))
    for bad in ("3am", "25:00", "03:60", "3:00", "03:0"):
        with pytest.raises(ValueError):
            await run_daily(c.update, bad, now=c.now, sleep=c.sleep)


async def test_cancelling_exits_cleanly_without_firing() -> None:
    task = asyncio.create_task(run_daily(lambda: asyncio.sleep(0), "03:00"))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
