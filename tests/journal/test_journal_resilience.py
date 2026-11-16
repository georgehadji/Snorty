import asyncio
import logging
import threading
import time
from collections.abc import AsyncIterator
from datetime import date, timedelta
from pathlib import Path

import pytest
from journal_fakes import NOW, Rig, make_alert, settle

from snorty.core.events import AlertRaised
from snorty.journal.ports import MemoryNoteStore
from snorty.journal.render import BEGIN

TODAY = date(2026, 11, 16)


class FlakyStore(MemoryNoteStore):
    def __init__(self, failures: int) -> None:
        super().__init__()
        self.failures = failures

    def write(self, day: date, text: str) -> None:
        if self.failures:
            self.failures -= 1
            raise OSError("disk full")
        super().write(day, text)


class BlockingStore(MemoryNoteStore):
    def __init__(self) -> None:
        super().__init__()
        self.gate = threading.Event()
        self.entered = threading.Event()

    def write(self, day: date, text: str) -> None:
        self.entered.set()
        self.gate.wait(10)
        super().write(day, text)


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path)
    yield r
    await r.service.stop()
    r.repo.close()


async def test_a_failed_write_is_logged_and_retried_at_the_next_tick(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    rig.service._store = store = FlakyStore(failures=1)
    await rig.service.start()
    with caplog.at_level(logging.ERROR, logger="snorty.journal"):
        rig.add(make_alert(1))
        rig.ticks.tick()
        await settle(lambda: any(r.levelno == logging.ERROR for r in caplog.records))
    assert store.notes == {}
    rig.ticks.tick()  # the day stayed dirty
    await settle(lambda: TODAY in store.notes)
    assert "rule 1" in store.notes[TODAY]


async def test_a_failing_first_flush_does_not_break_start(rig: Rig) -> None:
    rig.service._store = store = FlakyStore(failures=1)
    rig.add(make_alert(1), announce=False)
    await rig.service.start()  # must not raise
    rig.ticks.tick()
    await settle(lambda: TODAY in store.notes)


async def test_broken_markers_write_nothing_and_the_service_keeps_running(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    broken = f"mine\n{BEGIN}\nno end marker\n"
    rig.store.notes[TODAY] = broken
    rig.add(make_alert(1), announce=False)
    with caplog.at_level(logging.ERROR, logger="snorty.journal"):
        await rig.service.start()
    assert rig.store.notes[TODAY] == broken and rig.store.writes == []
    assert any(r.levelno == logging.ERROR for r in caplog.records)
    rig.store.notes[TODAY] = "fixed by hand\n"
    rig.add(make_alert(2))
    rig.ticks.tick()
    await settle(lambda: len(rig.store.writes) == 1)
    assert "rule 2" in rig.store.notes[TODAY] and rig.store.notes[TODAY].startswith("fixed")


async def test_a_failing_repository_is_logged_not_raised(rig: Rig) -> None:
    await rig.service.start()
    rig.repo.close()
    rig.service._dirty.add(TODAY)
    await rig.service.flush()  # must not raise


async def test_stop_never_raises_when_the_store_fails(rig: Rig) -> None:
    rig.service._store = FlakyStore(failures=99)
    await rig.service.start()
    rig.add(make_alert(1))
    await rig.service.stop()


async def test_unchanged_text_is_not_written_again(rig: Rig) -> None:
    alert = make_alert(1)
    rig.add(alert, announce=False)
    await rig.service.start()
    assert len(rig.store.writes) == 1
    rig.add(alert)  # announced again; same rows in the database
    rig.ticks.tick()
    await settle()
    assert len(rig.store.writes) == 1


async def test_a_day_over_the_row_cap_says_so_and_keeps_the_true_total(tmp_path: Path) -> None:
    rig = Rig(tmp_path, max_rows=5, page_size=2)
    rig.add(*[make_alert(s) for s in range(1, 13)], announce=False)
    await rig.service.start()
    note = rig.store.notes[TODAY]
    assert "12 alerts" in note and "truncated: 7 alerts not shown in tables" in note
    await rig.service.stop()
    rig.repo.close()


class DayStore(MemoryNoteStore):
    """Refuses to write one day."""

    def __init__(self, bad: date) -> None:
        super().__init__()
        self.bad = bad

    def write(self, day: date, text: str) -> None:
        if day == self.bad:
            raise OSError("disk full")
        super().write(day, text)


async def test_a_later_day_that_succeeds_does_not_hide_an_earlier_one_that_failed(
    tmp_path: Path,
) -> None:
    rig = Rig(tmp_path)
    store = rig.service._store = DayStore(date(2026, 11, 15))  # yesterday
    rig.add(make_alert(1, ts=NOW - timedelta(days=1)), make_alert(2), announce=False)
    await rig.service.start()
    assert TODAY in store.notes
    assert "disk full" in (rig.service.status().error or "")  # yesterday is still unwritten
    rig.service._store = MemoryNoteStore()  # the disk recovers
    await rig.service.flush()
    assert rig.service.status().error is None
    await rig.service.stop()
    rig.repo.close()


async def test_stop_during_the_first_flush_leaves_no_task_behind(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    store = BlockingStore()
    rig.service._store = store
    rig.add(make_alert(1), announce=False)
    starter = asyncio.create_task(rig.service.start())
    await asyncio.to_thread(store.entered.wait, 5)  # the first flush is blocked in the store
    stopper = asyncio.create_task(rig.service.stop())
    await asyncio.sleep(0.05)
    store.gate.set()
    await asyncio.gather(starter, stopper)
    left = [t for t in asyncio.all_tasks() if t.get_name().startswith("journal-")]
    assert left == [] and rig.bus._subs == []
    rig.repo.close()


async def test_a_blocked_store_never_slows_publish(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    store = BlockingStore()
    rig.service._store = store
    rig.add(make_alert(1), announce=False)
    start = rig.service.start()
    task = asyncio.create_task(start)  # the first flush blocks inside the store
    await asyncio.to_thread(store.entered.wait, 5)
    began = time.perf_counter()
    for sid in range(2, 1002):
        rig.bus.publish(AlertRaised(make_alert(sid)))
    assert time.perf_counter() - began < 1.0
    store.gate.set()
    await task
    await rig.service.stop()
    rig.repo.close()
