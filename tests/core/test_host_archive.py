import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_repository import make_alert

from snorty.core.models import Alert, FlowFact
from snorty.core.query import AlertQuery
from snorty.core.repository import MIGRATIONS, AlertRepository, _add_flow_id
from snorty.core.triage import host_matches, spec_from_json

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)
NOW = T0 + timedelta(hours=1)

CASES = [  # (fact value, rule host, matches)
    ("example.com", "example.com", True),
    ("cdn.example.com", "example.com", True),
    ("A.B.Example.COM", "example.com", True),
    ("badexample.com", "example.com", False),
    ("example.com.evil.net", "example.com", False),
    ("example.co", "example.com", False),
    ("a_b.example.com", "a_b.example.com", True),
    ("axb.example.com", "a_b.example.com", False),  # `_` is literal, not one character
    ("x%y.example.com", "x%y.example.com", True),
    ("xzzy.example.com", "x%y.example.com", False),  # `%` is literal
]


def eve(n: int, flow: int) -> Alert:
    return replace(make_alert(n, sid=3000 + n), raw=f"eve:{flow}:{3000 + n}:t{n}")


@pytest.mark.parametrize(("value", "host", "expected"), CASES)
def test_the_sql_and_the_pure_host_match_agree(
    tmp_path: Path, value: str, host: str, expected: bool
) -> None:
    repo = AlertRepository(tmp_path / "h.db")
    repo.add(eve(1, 77))
    repo.add_flow_facts([FlowFact(77, "tls", value, T0)])
    assert host_matches(value, host) is expected
    assert (repo.set_state(AlertQuery(), "ack", NOW, host=host) == 1) is expected


def test_only_name_facts_count_not_web_requests(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "h.db")
    repo.add(eve(1, 5))
    repo.add_flow_facts([FlowFact(5, "http", "example.com/path", T0)])
    assert repo.set_state(AlertQuery(), "ack", NOW, host="example.com") == 0


def test_a_host_rule_catches_a_fact_that_arrives_after_its_alert(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "h.db")
    repo.add_archive_rule(AlertQuery(), "noise", NOW, host="example.com")
    repo.add_many([eve(1, 9), eve(2, 10), make_alert(3)])  # the last one has no flow at all
    assert repo.apply_archive_rules(NOW) == 0
    repo.add_flow_facts([FlowFact(9, "dns", "updates.example.com", T0)])
    assert repo.apply_archive_rules(NOW) == 1
    assert repo.counts_by_state(AlertQuery()) == {"new": 2, "ack": 1, "starred": 0}
    rule = repo.archive_rules()[0]
    assert rule.host == "example.com" and rule.spec == AlertQuery()


def test_specs_stored_before_hosts_existed_still_load() -> None:
    assert spec_from_json('{"sid": 5}') == AlertQuery(sid=5)


def test_migration_eight_fills_in_flow_ids_of_existing_rows(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    repo = AlertRepository(path)
    repo.add_many([eve(1, 42), make_alert(2), replace(make_alert(3), raw="eve:x1:3:t")])
    repo.close()
    conn = sqlite3.connect(path)  # make it look like a version-7 database
    conn.execute("UPDATE alerts SET flow_id = NULL")
    before = MIGRATIONS.index(_add_flow_id)  # the version just before flow ids
    conn.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(before),))
    conn.commit()
    conn.close()
    reopened = AlertRepository(path)
    rows = reopened._conn.execute("SELECT raw, flow_id FROM alerts ORDER BY id").fetchall()
    assert [r[1] for r in rows] == [42, None, None]
    assert reopened.meta_get("schema_version") == str(len(MIGRATIONS))
