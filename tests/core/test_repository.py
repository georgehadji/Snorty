import sqlite3
from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from snorty.core.models import Alert
from snorty.core.repository import AlertRepository

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)


def make_alert(
    n: int = 0, *, ts: datetime | None = None, sid: int = 1000, priority: int = 2
) -> Alert:
    ts = ts or T0 + timedelta(seconds=n)
    return Alert(
        ts=ts,
        gid=1,
        sid=sid,
        rev=1,
        msg=f"rule {sid}",
        classification=None if n % 2 else "Misc",
        priority=priority,
        proto="TCP",
        src_ip="10.0.0.1",
        src_port=None if n % 3 == 0 else 1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        raw=f"raw {sid} {ts.isoformat()} {n}",
    )


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[AlertRepository]:
    r = AlertRepository(tmp_path / "alerts.db")
    yield r
    r.close()


def test_add_is_idempotent(repo: AlertRepository) -> None:
    alert = make_alert()
    assert repo.add(alert) is True
    assert repo.add(alert) is False
    assert len(repo.query()) == 1


def test_add_many_counts_only_new_rows(repo: AlertRepository) -> None:
    alerts = [make_alert(i) for i in range(5)]
    assert repo.add_many(alerts) == 5
    assert repo.add_many(alerts) == 0
    assert repo.add_many(alerts + [make_alert(99)]) == 1


def test_roundtrip_preserves_every_field(repo: AlertRepository) -> None:
    alerts = [make_alert(i) for i in range(6)]  # mixes None/non-None ports and classification
    repo.add_many(alerts)
    assert sorted(repo.query(), key=lambda a: a.raw) == sorted(alerts, key=lambda a: a.raw)


def test_query_newest_first_with_limit_offset(repo: AlertRepository) -> None:
    repo.add_many([make_alert(i) for i in range(5)])
    assert [a.raw for a in repo.query(limit=2)] == [make_alert(4).raw, make_alert(3).raw]
    assert [a.raw for a in repo.query(limit=2, offset=2)] == [make_alert(2).raw, make_alert(1).raw]


def test_query_time_range_since_inclusive_until_exclusive(repo: AlertRepository) -> None:
    repo.add_many([make_alert(i) for i in range(5)])
    got = repo.query(since=T0 + timedelta(seconds=1), until=T0 + timedelta(seconds=3))
    assert [a.raw for a in got] == [make_alert(2).raw, make_alert(1).raw]


def test_query_by_sid_and_min_priority(repo: AlertRepository) -> None:
    repo.add(make_alert(0, sid=1, priority=1))
    repo.add(make_alert(1, sid=2, priority=2))
    repo.add(make_alert(2, sid=2, priority=3))
    assert {a.sid for a in repo.query(sid=2)} == {2}
    assert [a.priority for a in repo.query(min_priority=1)] == [1]
    assert sorted(a.priority for a in repo.query(min_priority=2)) == [1, 2]


def test_counts_by_sid_most_frequent_first(repo: AlertRepository) -> None:
    repo.add_many([make_alert(i, sid=7) for i in range(3)])
    repo.add_many([make_alert(10 + i, sid=8) for i in range(1)])
    assert repo.counts_by_sid() == [(7, 3), (8, 1)]
    assert repo.counts_by_sid(since=T0 + timedelta(seconds=10)) == [(8, 1)]


def test_count_matches_the_sum_of_counts_by_sid_in_any_range(repo: AlertRepository) -> None:
    repo.add_many([make_alert(i, sid=7) for i in range(3)])
    repo.add_many([make_alert(10 + i, sid=8) for i in range(2)])
    assert repo.count() == 5
    assert repo.count(since=T0 + timedelta(seconds=10)) == 2
    assert repo.count(until=T0 + timedelta(seconds=10)) == 3
    assert repo.count(since=T0 + timedelta(days=1)) == 0


def test_count_can_be_limited_to_urgent_priorities(repo: AlertRepository) -> None:
    repo.add_many([make_alert(i, priority=p) for i, p in enumerate((1, 2, 3, 3))])
    assert repo.count(min_priority=2) == 2
    assert repo.count(min_priority=1) == 1
    assert repo.count() == 4


def test_latest_msgs_returns_the_newest_message_per_sid(repo: AlertRepository) -> None:
    repo.add(make_alert(1, sid=7, ts=T0))
    repo.add(replace(make_alert(2, sid=7, ts=T0 + timedelta(seconds=5)), msg="newer"))
    repo.add(make_alert(3, sid=8, ts=T0))
    assert repo.latest_msgs([7, 8, 9]) == {7: "newer", 8: "rule 8"}
    assert repo.latest_msgs([]) == {}
    assert repo.latest_msgs([7], since=T0 + timedelta(hours=1)) == {}


def test_counts_by_hour_buckets_in_given_zone(repo: AlertRepository) -> None:
    tz = timezone(timedelta(hours=5, minutes=30))  # half-hour offset: hour buckets != UTC hours
    # 12:00 UTC = 17:30 local; 12:20 = 17:50; 12:40 = 18:10
    for i, minute in enumerate((0, 20, 40)):
        repo.add(make_alert(i, ts=T0 + timedelta(minutes=minute)))
    got = repo.counts_by_hour(tz=tz)
    assert got == [
        (datetime(2026, 11, 15, 17, 0, tzinfo=tz), 2),
        (datetime(2026, 11, 15, 18, 0, tzinfo=tz), 1),
    ]


def test_prune_keeps_row_exactly_at_boundary(repo: AlertRepository) -> None:
    repo.add_many([make_alert(i) for i in range(5)])
    assert repo.prune(T0 + timedelta(seconds=2)) == 2
    assert len(repo.query()) == 3


def test_naive_datetimes_are_rejected(repo: AlertRepository) -> None:
    with pytest.raises(ValueError):
        repo.query(since=datetime(2026, 1, 1))


def test_wal_mode_and_concurrent_reader(tmp_path: Path) -> None:
    path = tmp_path / "alerts.db"
    writer, reader = AlertRepository(path), AlertRepository(path)
    try:
        with closing(sqlite3.connect(path)) as probe:
            assert probe.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        writer.add(make_alert(1))
        writer._conn.execute("BEGIN IMMEDIATE")  # open write transaction
        writer._conn.execute("DELETE FROM alerts")
        assert len(reader.query()) == 1  # reader is not blocked and sees committed data
        writer._conn.execute("ROLLBACK")
        assert len(reader.query()) == 1
    finally:
        writer.close()
        reader.close()


def test_failed_add_many_rolls_back(repo: AlertRepository) -> None:
    def gen() -> Iterator[Alert]:
        yield make_alert(1)
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        repo.add_many(gen())
    assert repo.query() == []


def test_add_new_returns_only_new_alerts_in_order(repo: AlertRepository) -> None:
    first = [make_alert(i) for i in range(3)]
    repo.add(first[1])
    new = repo.add_new(first + [make_alert(9), make_alert(9)])
    assert new == [first[0], first[2], make_alert(9)]
    assert repo.add_new(first) == []


def test_old_priority_zero_rows_are_moved_to_the_lowest_level(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    AlertRepository(db).close()
    with closing(sqlite3.connect(db)) as conn:
        conn.execute(
            "INSERT INTO alerts (ts, gid, sid, rev, msg, classification, priority, proto, "
            "src_ip, src_port, dst_ip, dst_port, raw) "
            "VALUES ('2026-01-01T00:00:00+00:00', 1, 1000001, 1, 'm', NULL, 0, 'ICMP', "
            "'1.1.1.1', NULL, '2.2.2.2', NULL, 'old line')"
        )
        conn.commit()
    with closing(AlertRepository(db)) as repo:
        assert [a.priority for a in repo.query()] == [3]


def test_stored_alerts_carry_the_row_id_and_get_finds_one(repo: AlertRepository) -> None:
    repo.add(make_alert(1))
    repo.add(make_alert(2))
    stored = repo.query()
    assert sorted(a.id for a in stored) == [1, 2]
    for alert in stored:
        assert repo.get(alert.id) == alert and repo.get(alert.id).raw == alert.raw  # type: ignore[union-attr]
    assert repo.get(999) is None


def test_add_new_gives_each_new_alert_its_id_and_the_id_is_not_part_of_equality(
    repo: AlertRepository,
) -> None:
    new = repo.add_new([make_alert(1), make_alert(2)])
    assert [a.id for a in new] == [1, 2]
    assert new == [make_alert(1), make_alert(2)]  # ids ignored when comparing
    assert repo.get(new[1].id) == new[1]
