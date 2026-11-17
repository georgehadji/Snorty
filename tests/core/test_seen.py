from datetime import UTC, datetime, timedelta
from pathlib import Path

from snorty.core.repository import AlertRepository

T0 = datetime(2026, 11, 17, 9, 0, tzinfo=UTC)


def test_a_value_is_new_only_the_first_time_and_names_are_normalised(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "s.db")
    assert repo.note_seen("dns", ["Evil.Example.", "evil.example", " cdn.example "], T0) == [
        "evil.example",
        "cdn.example",
    ]
    later = T0 + timedelta(hours=1)
    assert repo.note_seen("dns", ["EVIL.example", "new.example", ""], later) == ["new.example"]
    assert repo.note_seen("country", ["Germany", "Germany"], later) == ["Germany"]
    assert repo.note_seen("dns", ["x" * 300], later) == ["x" * 253]
    counts, rows = repo.first_seen(later)
    assert counts == {"dns": 2, "country": 1}
    assert rows[0][2] == later and {r[1] for r in rows} == {"new.example", "Germany", "x" * 253}
    assert repo.seen_since() == T0


def test_more_values_than_one_statement_holds(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "s.db")
    names = [f"h{i}.example" for i in range(1200)]
    assert len(repo.note_seen("dns", names, T0)) == 1200
    assert repo.note_seen("dns", names, T0) == []


def test_prune_forgets_values_not_seen_within_the_kept_history(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "s.db")
    repo.note_seen("dns", ["old.example", "kept.example"], T0)
    repo.note_seen("dns", ["kept.example"], T0 + timedelta(days=30))
    repo.prune(T0 + timedelta(days=10))
    assert repo.note_seen("dns", ["old.example", "kept.example"], T0 + timedelta(days=31)) == [
        "old.example"
    ]
