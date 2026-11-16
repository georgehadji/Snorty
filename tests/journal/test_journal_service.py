from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from journal_fakes import NOW, Rig, make_alert, settle

from snorty.core.events import AlertsBackfilled

TODAY, YESTERDAY = date(2026, 11, 16), date(2026, 11, 15)


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path)
    yield r
    await r.service.stop()
    r.repo.close()


async def test_start_regenerates_today_and_yesterday_from_the_database(rig: Rig) -> None:
    rig.add(
        make_alert(1, NOW - timedelta(hours=2)),
        make_alert(2, NOW - timedelta(days=1)),
        make_alert(3, NOW - timedelta(days=2)),
        announce=False,  # the sensor ingested these without announcing them
    )
    await rig.service.start()
    assert set(rig.store.notes) == {TODAY, YESTERDAY}
    assert "| 1 | rule 1 | 1 |" in rig.store.notes[TODAY]
    assert "| 2 | rule 2 | 1 |" in rig.store.notes[YESTERDAY]


async def test_a_day_with_no_alerts_gets_no_note(rig: Rig) -> None:
    await rig.service.start()
    assert rig.store.notes == {}


async def test_an_announced_alert_shows_up_after_the_next_tick(rig: Rig) -> None:
    await rig.service.start()
    rig.add(make_alert(5))
    await settle()
    assert rig.store.notes == {}  # debounced: nothing yet
    rig.ticks.tick()
    await settle(lambda: TODAY in rig.store.notes)
    assert "| 5 | rule 5 | 1 |" in rig.store.notes[TODAY]


async def test_many_alerts_in_one_interval_cause_one_write_per_day(rig: Rig) -> None:
    await rig.service.start()
    for sid in range(1, 40):
        rig.add(make_alert(sid))
    rig.ticks.tick()
    await settle(lambda: len(rig.store.writes) == 1)
    await settle()
    assert len(rig.store.writes) == 1
    rig.ticks.tick()  # nothing is dirty any more
    await settle()
    assert len(rig.store.writes) == 1


async def test_a_burst_of_alerts_does_not_lose_the_day_of_its_first_alert(rig: Rig) -> None:
    await rig.service.start()
    older = NOW - timedelta(days=3)
    rig.add(make_alert(7, older), *(make_alert(1000 + n) for n in range(1500)))  # one poll
    rig.ticks.tick()
    await settle(lambda: older.date() in rig.store.notes)
    assert "| 7 | rule 7 | 1 |" in rig.store.notes[older.date()]


async def test_stop_flushes_what_is_pending(rig: Rig) -> None:
    await rig.service.start()
    rig.add(make_alert(8))
    await rig.service.stop()
    assert "| 8 | rule 8 | 1 |" in rig.store.notes[TODAY]


async def test_stop_picks_up_alerts_that_were_never_announced(rig: Rig) -> None:
    await rig.service.start()
    rig.add(make_alert(9), announce=False)
    await rig.service.stop()
    assert "rule 9" in rig.store.notes[TODAY]


async def test_no_writes_after_stop(rig: Rig) -> None:
    await rig.service.start()
    await rig.service.stop()
    before = len(rig.store.writes)
    rig.add(make_alert(1))
    rig.ticks.tick()
    await settle()
    assert len(rig.store.writes) == before and rig.bus._subs == []


async def test_stop_before_start_and_twice_are_harmless(rig: Rig) -> None:
    await rig.service.stop()
    await rig.service.start()
    await rig.service.stop()
    await rig.service.stop()
    assert rig.bus._subs == []


async def test_start_twice_does_not_double_subscribe(rig: Rig) -> None:
    await rig.service.start()
    await rig.service.start()
    assert len(rig.bus._subs) == 1


async def test_day_boundary_follows_the_local_zone(tmp_path: Path) -> None:
    rig = Rig(tmp_path, tz=timezone(timedelta(hours=2)))
    rig.add(make_alert(1, datetime(2026, 11, 15, 21, 59, tzinfo=UTC)), announce=False)  # 23:59
    rig.add(make_alert(2, datetime(2026, 11, 15, 22, 1, tzinfo=UTC)), announce=False)  # 00:01
    await rig.service.start()
    assert "rule 1" in rig.store.notes[YESTERDAY] and "rule 2" not in rig.store.notes[YESTERDAY]
    assert "rule 2" in rig.store.notes[TODAY] and "rule 1" not in rig.store.notes[TODAY]
    await rig.service.stop()
    rig.repo.close()


async def test_your_text_in_an_existing_note_survives_regeneration(rig: Rig) -> None:
    rig.store.notes[TODAY] = "# My day\nI wrote this.\n"
    rig.add(make_alert(1), announce=False)
    await rig.service.start()
    note = rig.store.notes[TODAY]
    assert note.startswith("# My day\nI wrote this.\n") and "rule 1" in note


async def test_days_backfilled_while_ingest_was_down_are_written_on_the_next_tick(
    rig: Rig,
) -> None:
    await rig.service.start()
    old = NOW - timedelta(days=5)
    rig.repo.add_many([make_alert(1, old), make_alert(2, old + timedelta(days=1))])
    rig.bus.publish(AlertsBackfilled(old, old + timedelta(days=1)))
    rig.ticks.tick()
    await settle(lambda: len(rig.store.notes) == 2)
    assert set(rig.store.notes) == {(old).date(), (old + timedelta(days=1)).date()}
