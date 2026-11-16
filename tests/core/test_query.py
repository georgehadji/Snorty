from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_repository import make_alert

from snorty.core.query import AlertQuery
from snorty.core.repository import AlertRepository

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)

QUERIES = [
    AlertQuery(),
    AlertQuery(sid=1000),
    AlertQuery(min_priority=1),
    AlertQuery(src_ip="10.0.0.9"),
    AlertQuery(dst_ip="10.0.0.2", sid=1001),
    AlertQuery(since=T0 + timedelta(seconds=3), until=T0 + timedelta(seconds=8)),
    AlertQuery(sid=1000, min_priority=2, src_ip="10.0.0.1", dst_ip="10.0.0.2"),
]


@pytest.fixture
def repo(tmp_path: Path) -> AlertRepository:
    r = AlertRepository(tmp_path / "q.db")
    r.add_many(
        replace(
            make_alert(n, sid=1000 + n % 2, priority=1 + n % 3),
            src_ip="10.0.0.9" if n % 4 == 0 else "10.0.0.1",
        )
        for n in range(12)
    )
    return r


@pytest.mark.parametrize("q", QUERIES)
def test_the_sql_form_and_the_in_memory_form_agree(repo: AlertRepository, q: AlertQuery) -> None:
    stored = repo.query(limit=100)
    in_sql = {a.id for a in repo.query(
        since=q.since, until=q.until, sid=q.sid, min_priority=q.min_priority,
        src_ip=q.src_ip, dst_ip=q.dst_ip, limit=100,
    )}  # fmt: skip
    in_memory = {a.id for a in stored if q.matches(a)}
    assert in_sql == in_memory and (q != AlertQuery() or len(in_sql) == 12)


def test_groups_count_per_key_with_first_last_and_newest_message(repo: AlertRepository) -> None:
    by_sid = {g.key: g for g in repo.group(AlertQuery(), "sid")}
    assert by_sid["1000"].count == 6 and by_sid["1001"].count == 6
    assert by_sid["1000"].first_ts == T0 and by_sid["1000"].last_ts == T0 + timedelta(seconds=10)
    by_src = repo.group(AlertQuery(), "src_ip")
    assert [(g.key, g.count) for g in by_src] == [("10.0.0.1", 9), ("10.0.0.9", 3)]
    only = repo.group(AlertQuery(sid=1000), "src_ip")
    assert sum(g.count for g in only) == 6


NOW = T0 + timedelta(days=1)


def test_acknowledging_a_rule_moves_it_out_of_the_inbox_and_back(repo: AlertRepository) -> None:
    assert repo.counts_by_state(AlertQuery()) == {"new": 12, "ack": 0, "starred": 0}
    assert repo.set_state(AlertQuery(sid=1000), "ack", NOW) == 6
    assert repo.set_state(AlertQuery(sid=1001, min_priority=1), "starred", NOW) == 2
    assert repo.counts_by_state(AlertQuery()) == {"new": 4, "ack": 6, "starred": 2}
    inbox = repo.group(AlertQuery(), "sid", states=("new", "starred"))
    assert {g.key: g.count for g in inbox} == {"1001": 6}
    assert len(repo.query(states=("ack",), limit=100)) == 6
    assert repo.set_state(AlertQuery(sid=1000), "new", NOW) == 6  # undo
    assert repo.counts_by_state(AlertQuery())["new"] == 10


def test_archive_rules_acknowledge_only_alerts_nobody_triaged(repo: AlertRepository) -> None:
    repo.set_state(AlertQuery(sid=1000, min_priority=1), "starred", NOW)
    rule = repo.add_archive_rule(AlertQuery(sid=1000), "noisy", NOW)
    assert repo.archive_rules()[0].spec == AlertQuery(sid=1000) and rule > 0
    assert repo.apply_archive_rules(NOW) == 4  # six alerts, two of them starred
    assert repo.counts_by_state(AlertQuery(sid=1000)) == {"new": 0, "ack": 4, "starred": 2}
    assert repo.apply_archive_rules(NOW) == 0  # nothing left to do
    assert repo.delete_archive_rule(rule) and repo.archive_rules() == []


def test_pruned_alerts_take_their_triage_rows_along(repo: AlertRepository) -> None:
    repo.set_state(AlertQuery(), "ack", NOW)
    repo.prune(T0 + timedelta(seconds=6))
    assert sum(repo.counts_by_state(AlertQuery()).values()) == 6
    assert repo._conn.execute("SELECT COUNT(*) FROM triage").fetchone()[0] == 6
