from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from journal_fakes import make_alert

from snorty.core.repository import AlertRepository
from snorty.journal.__main__ import main
from snorty.journal.ports import MemoryNoteStore
from snorty.journal.render import BEGIN

DAY = date(2026, 11, 16)
TS = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "a.db"
    repo = AlertRepository(path)
    repo.add_many([make_alert(1, TS), make_alert(2, TS, priority=2)])
    repo.close()
    return path


def test_write_puts_the_days_note_in_the_store(db: Path) -> None:
    store = MemoryNoteStore()
    assert main(["write", "--date", "2026-11-16", "--db", str(db)], store=store) == 0
    assert "| 1 | rule 1 | 1 |" in store.notes[DAY]


def test_second_run_changes_nothing_and_keeps_your_text(
    db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = MemoryNoteStore()
    args = ["write", "--date", "2026-11-16", "--db", str(db)]
    main(args, store=store)
    store.notes[DAY] += "\nMy own line\n"
    store.writes.clear()
    assert main(args, store=store) == 0
    assert store.writes == [] and "My own line" in store.notes[DAY]
    assert "unchanged" in capsys.readouterr().out


def test_dry_run_prints_the_note_and_writes_nothing(
    db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = MemoryNoteStore()
    code = main(["write", "--date", "2026-11-16", "--db", str(db), "--dry-run"], store=store)
    assert code == 0 and store.writes == []
    assert BEGIN in capsys.readouterr().out


def test_a_day_without_alerts_writes_nothing(db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = MemoryNoteStore()
    assert main(["write", "--date", "2020-01-01", "--db", str(db)], store=store) == 0
    assert store.writes == [] and "no alerts" in capsys.readouterr().out


def test_missing_database_exits_one_and_is_not_created(tmp_path: Path) -> None:
    missing = tmp_path / "nope.db"
    assert main(["write", "--db", str(missing)], store=MemoryNoteStore()) == 1
    assert not missing.exists()


def test_no_vault_anywhere_exits_two(db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OBSIDIAN_VAULT_PATH", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["write", "--date", "2026-11-16", "--db", str(db)])
    assert exc.value.code == 2


def test_vault_from_the_environment(
    db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(vault))
    assert main(["write", "--date", "2026-11-16", "--db", str(db)]) == 0
    assert (vault / "Security" / "Snort" / "2026-11-16.md").exists()


def test_a_store_error_exits_one(
    db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        ["write", "--date", "2026-11-16", "--db", str(db), "--vault", str(tmp_path / "nope")]
    )
    assert code == 1 and "vault folder not found" in capsys.readouterr().err
