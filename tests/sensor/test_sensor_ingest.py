import asyncio
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

import pytest
from fakes import FakeClock, FakePort

from snorty.core.bus import EventBus, Subscription
from snorty.core.decoder import FastDecoder
from snorty.core.events import AlertRaised, AlertsBackfilled, Event, SensorHealth
from snorty.core.repository import AlertRepository
from snorty.sensor import tail
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

    def drain(self) -> list[Event]:
        out: list[Event] = []
        while True:
            try:
                out.append(self.sub._queue.get_nowait())
            except asyncio.QueueEmpty:
                return out

    def raised(self) -> list[AlertRaised]:
        return [e for e in self.drain() if isinstance(e, AlertRaised)]

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


async def test_alerts_that_print_as_one_line_are_all_stored_and_announced(tmp_path: Path) -> None:
    first = Rig(tmp_path)
    await first.sensor.start()
    first.append(line(1), line(1), line(1))  # three alerts in one microsecond, same flow
    seen: list[AlertRaised] = []
    await eventually(lambda: bool(seen.extend(first.raised())) or len(seen) == 3)
    assert first.stored() == 3
    await first.sensor.stop()

    second = Rig(tmp_path, repo=first.repo)  # a restart reads the file again
    await second.sensor.start()
    await asyncio.sleep(0.02)
    assert second.stored() == 3 and second.raised() == []
    await second.sensor.stop()
    first.repo.close()


async def test_a_poll_that_is_cancelled_mid_write_still_finishes_and_announces(rig: Rig) -> None:
    s = rig.sensor
    s._backlog_done = True
    rig.append(line(1))
    real = s._store_lines

    def slow(lines: list[str], year: int, ties: list[int], checkpoint: str | None) -> object:
        time.sleep(0.2)  # the write is inside its worker thread when the cancel arrives
        return real(lines, year, ties, checkpoint)

    s._store_lines = slow  # type: ignore[method-assign,assignment]
    s._ingest_task = asyncio.create_task(s._poll_once())
    await asyncio.sleep(0.05)
    await s._stop_ingest()  # cancels, then does the final pass
    assert rig.stored() == 1 and len(rig.raised()) == 1  # it used to be stored and never announced


async def test_a_damaged_line_with_oversized_ids_does_not_stall_ingest(rig: Rig) -> None:
    await rig.sensor.start()
    rig.append(line(1).replace(":1000002:", ":99999999999999999999:"), line(2))
    await eventually(lambda: rig.stored() == 1)  # the good line behind it still arrives
    await eventually(lambda: rig.sensor.status().unparsed == 1)  # counted after the write
    assert rig.sensor.state.name == "RUNNING"
    await rig.sensor.stop()


async def test_pruned_alerts_are_not_read_back_from_the_file_on_restart(tmp_path: Path) -> None:
    first = Rig(tmp_path)
    old = (
        "01/01/25-10:00:00.000001  [**] [1:1000002:1] old [**] [Priority: 1] "
        "{TCP} 10.0.0.1:1 -> 10.0.0.2:80"
    )
    first.append(old, line(1))
    await first.sensor.start()
    assert first.stored() == 2
    await first.sensor.stop()
    first.repo.prune(datetime.now(UTC) - timedelta(days=90))

    second = Rig(tmp_path, repo=first.repo)
    await second.sensor.start()  # the dashboard restarts and reads the whole file again
    assert second.stored() == 1
    await second.sensor.stop()
    first.repo.close()


async def test_junk_lines_are_counted_not_fatal(rig: Rig) -> None:
    await rig.sensor.start()
    rig.append("this is not an alert", line(1))
    await eventually(lambda: rig.stored() == 1)
    await eventually(lambda: rig.sensor.status().unparsed == 1)  # counted after the write
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
    seen: list[AlertRaised] = []  # the announcement follows the write, so wait for it too
    await eventually(lambda: bool(seen.extend(rig.raised())) or len(seen) >= 1)
    assert rig.stored() == 4
    assert [e.alert.src_port for e in seen] == [1008]
    await rig.sensor.stop()


async def test_database_error_loses_nothing(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    await rig.sensor.start()
    real = rig.repo.add_new
    calls = {"n": 0}

    def flaky(alerts: object, checkpoint: str | None = None) -> list:  # type: ignore[type-arg]
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("disk full")
        return real(alerts, checkpoint)  # type: ignore[arg-type]

    monkeypatch.setattr(rig.repo, "add_new", flaky)
    rig.append(line(4))
    seen: list[AlertRaised] = []  # the announcement follows the write, so wait for it too
    await eventually(lambda: bool(seen.extend(rig.raised())) or len(seen) >= 1)
    assert rig.stored() == 1 and len(seen) == 1
    assert rig.sensor.state.name == "RUNNING"
    await rig.sensor.stop()


async def test_a_failed_poll_is_reported_until_ingest_recovers(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    await rig.sensor.start()
    real = rig.repo.add_new
    reported: list[str | None] = []

    def flaky(alerts: object, checkpoint: str | None = None) -> list:  # type: ignore[type-arg]
        if not reported:
            reported.append(None)
            raise RuntimeError("disk full")
        reported.append(rig.sensor.status().last_error)  # what the card shows at the retry
        return real(alerts, checkpoint)  # type: ignore[arg-type]

    monkeypatch.setattr(rig.repo, "add_new", flaky)
    rig.append(line(4))
    await eventually(lambda: rig.stored() == 1)
    await eventually(lambda: rig.sensor.status().last_error is None)  # shown no longer once fine
    assert "disk full" in (reported[1] or "")
    await rig.sensor.stop()


def yearless(month_day: str) -> str:
    """A line as Snort writes it: no year in the stamp."""
    return (
        f"{month_day}-23:30:12.000001  [**] [1:1000002:1] test rule [**] [Priority: 1] "
        "{TCP} 10.0.0.1:1000 -> 10.0.0.2:80"
    )


def test_december_lines_read_in_january_belong_to_last_year(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.sensor._wall = lambda: datetime(2027, 1, 2, 9, 0, tzinfo=UTC)
    new, bad, _ = rig.sensor._store_lines([yearless("12/30"), yearless("01/02")], 2027)
    assert bad == 0
    assert [a.ts.year for a in new] == [2026, 2027]


def test_a_line_from_today_keeps_the_current_year(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.sensor._wall = lambda: datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    new, _, _ = rig.sensor._store_lines([yearless("11/16"), yearless("11/15")], 2026)
    assert [a.ts.year for a in new] == [2026, 2026]


class Athens(tzinfo):
    """+03:00 until the clocks go back at 04:00 on 2026-10-25, +02:00 after: 03:00-04:00 repeats."""

    def utcoffset(self, dt: datetime | None) -> timedelta:
        assert dt is not None
        naive = dt.replace(tzinfo=None)
        start, end = datetime(2026, 10, 25, 3), datetime(2026, 10, 25, 4)
        summer = naive < start or (naive < end and dt.fold == 0)
        return timedelta(hours=3 if summer else 2)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str:
        return "Athens"


def test_the_repeated_hour_of_a_clock_change_is_read_in_the_right_order(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.sensor._decoder = FastDecoder(Athens())
    rig.sensor._wall = lambda: datetime(2026, 11, 16, 12, 0, tzinfo=UTC)

    def at(hm: str, n: int) -> str:
        return (
            f"10/25/26-{hm}:00.{n:06d}  [**] [1:1000002:1] test rule [**] [Priority: 1] "
            "{TCP} 10.0.0.1:1000 -> 10.0.0.2:80"
        )

    lines = [at("02:50", 1), at("03:10", 2), at("03:50", 3), at("03:05", 4), at("03:30", 5),
             at("04:10", 6)]  # fmt: skip
    new, bad, _ = rig.sensor._store_lines(lines, 2026)
    assert bad == 0
    assert [a.ts.astimezone(UTC).strftime("%H:%M") for a in new] == [
        "23:50", "00:10", "00:50",  # first pass at +03:00
        "01:05", "01:30",  # the same wall hour a second time, at +02:00
        "02:10",
    ]  # fmt: skip
    rig.repo.close()


async def test_a_replaced_alert_file_is_read_again_even_if_it_is_larger(rig: Rig) -> None:
    rig.append(line(1), line(2))
    await rig.sensor.start()
    rig.alerts.write_bytes("".join(line(n) + "\n" for n in range(10, 16)).encode())
    seen: list[AlertRaised] = []  # the announcements follow the write, so wait for them too
    await eventually(lambda: bool(seen.extend(rig.raised())) or len(seen) >= 6)
    assert rig.stored() == 8
    assert sorted(e.alert.src_port for e in seen) == [1010 + n for n in range(6)]
    await rig.sensor.stop()


async def test_a_backlog_larger_than_one_chunk_is_stored_whole_and_not_announced(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tail, "MAX_CHUNK", 500)  # a few lines per read
    rig.append(*(line(n) for n in range(40)))
    await rig.sensor.start()
    assert rig.stored() == 40 and rig.raised() == []
    rig.append(line(99))
    await eventually(lambda: len(rig.raised()) == 1)  # live alerts still announced
    await rig.sensor.stop()


async def test_blank_stretch_longer_than_a_chunk_does_not_end_the_backlog_early(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tail, "MAX_CHUNK", 16)  # every chunk of the blank stretch holds no line
    rig.alerts.write_bytes(b"\r\n" * 40 + (line(1) + "\r\n").encode())
    await rig.sensor.start()
    assert rig.stored() == 1
    assert rig.raised() == []  # old alert: stored, never toasted as if it were live
    await rig.sensor.stop()


async def test_backlog_is_announced_to_the_journal_as_a_span_of_days(rig: Rig) -> None:
    old = line(1).replace("11/16/26", "11/02/26")
    rig.append(old, line(2))
    await rig.sensor.start()
    spans = [e for e in rig.drain() if isinstance(e, AlertsBackfilled)]
    assert len(spans) == 1
    assert (spans[0].first.date().month, spans[0].first.date().day) == (11, 2)
    assert spans[0].last.date().day == 16
    await rig.sensor.stop()


async def test_a_restart_resumes_from_the_saved_checkpoint(tmp_path: Path) -> None:
    first = Rig(tmp_path)
    first.append(line(1), line(2))
    await first.sensor.start()
    await first.sensor.stop()

    first.append(line(3))  # written while Snorty was down
    second = Rig(tmp_path, repo=first.repo)
    assert second.sensor._tail.offset == len((line(1) + "\r\n" + line(2) + "\r\n").encode())
    await second.sensor.start()
    assert second.stored() == 3
    assert second.sensor.status().alerts_seen == 1  # only the new line was read
    await second.sensor.stop()
    first.repo.close()


async def test_a_damaged_checkpoint_falls_back_to_reading_the_whole_file(tmp_path: Path) -> None:
    first = Rig(tmp_path)
    first.append(line(1), line(2))
    await first.sensor.start()
    await first.sensor.stop()
    first.repo._conn.execute("UPDATE meta SET value = 'garbage' WHERE key = 'tail'")

    second = Rig(tmp_path, repo=first.repo)
    await second.sensor.start()
    assert second.stored() == 2  # re-read, nothing stored twice
    await second.sensor.stop()
    first.repo.close()


async def test_a_new_drop_figure_from_the_decoder_is_published_once(rig: Rig) -> None:
    figure: list[float | None] = [None]
    rig.sensor._decoder = FastDecoder(UTC, lambda: figure[0])
    await rig.sensor.start()
    rig.drain()
    figure[0] = 3.5
    rig.append(line(7))
    await eventually(lambda: rig.sensor.status().drop_pct == 3.5)
    await asyncio.sleep(0.02)  # later polls with the same figure stay quiet
    assert [e for e in rig.drain() if isinstance(e, SensorHealth)] == [SensorHealth(3.5)]
    await rig.sensor.stop()


async def test_what_the_decoder_saw_on_flows_is_stored(tmp_path: Path) -> None:
    from snorty.core.models import FlowFact

    class Seen(FastDecoder):
        def take_flows(self) -> list[FlowFact]:
            return [FlowFact(9, "tls", "evil.example", datetime.now(UTC))]

    r = Rig(tmp_path)
    r.sensor._decoder = Seen(UTC)
    r.append(line(1))
    await r.sensor.start()
    assert r.repo.flow_facts(9) == [("tls", "evil.example")]
    await r.sensor.stop()
    r.repo.close()


async def test_the_connection_context_the_decoder_saw_is_stored(tmp_path: Path) -> None:
    from snorty.core.models import Conn, Lookup

    t = datetime.now(UTC)
    c = Conn(9, t, t, "TCP", None, "10.0.0.1", 1, "203.0.113.9", 443, 1, 1, 1, 1, None)

    class Seen(FastDecoder):
        def take_context(self) -> tuple[list[Conn], list[Lookup]]:
            return [c], [Lookup(t, "10.0.0.1", "evil.example", "203.0.113.9")]

    r = Rig(tmp_path)
    r.sensor._decoder = Seen(UTC)
    r.append(line(1))
    await r.sensor.start()
    assert r.repo.conn(9) == c
    assert [x.name for x in r.repo.lookups_of("203.0.113.9", t, timedelta(hours=1))] == [
        "evil.example"
    ]
    await r.sensor.stop()
    r.repo.close()


async def test_file_md5s_on_alerted_flows_are_announced_after_their_alerts(rig: Rig) -> None:
    from snorty.core.events import FilesSeen
    from snorty.core.models import FlowFact

    t = datetime.now(UTC)

    class Seen(FastDecoder):
        def take_flows(self) -> list[FlowFact]:
            return [FlowFact(9, "file", "a.exe", t), FlowFact(9, "md5", "0" * 32, t)]

    rig.sensor._decoder = Seen(UTC)
    rig.sensor._backlog_done = True
    rig.append(line(1))
    await rig.sensor._poll_once()
    events = [e for e in rig.drain() if isinstance(e, AlertRaised | FilesSeen)]
    assert [type(e) for e in events] == [AlertRaised, FilesSeen]
    assert isinstance(events[1], FilesSeen) and [f.kind for f in events[1].files] == ["md5"]
    assert ("md5", "0" * 32) in rig.repo.flow_facts(9)


async def test_names_the_decoder_saw_answered_are_noted_as_seen(tmp_path: Path) -> None:
    class Named(FastDecoder):
        def take_names(self) -> list[str]:
            return ["Evil.Example."]

    r = Rig(tmp_path)
    r.sensor._decoder = Named(UTC)
    r.append(line(1))
    await r.sensor.start()
    counts, rows = r.repo.first_seen(datetime(2000, 1, 1, tzinfo=UTC))
    assert counts == {"dns": 1} and rows[0][:2] == ("dns", "evil.example")
    await r.sensor.stop()
    r.repo.close()
