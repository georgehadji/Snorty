from datetime import UTC, datetime
from pathlib import Path

from dash_fakes import FakeJournal, FakeNotify
from test_dash_routes import POST, make

from snorty.dashboard.services import Services
from snorty.journal.service import JournalStatus
from snorty.notify.service import NotifyStatus


def journal(s: Services) -> FakeJournal:
    assert isinstance(s.journal, FakeJournal)
    return s.journal


def test_journal_page_shows_folder_count_and_last_write(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    journal(s).info = JournalStatus(
        "C:/v/Security/Snort", datetime(2026, 11, 16, 3, 0, tzinfo=UTC), 4, None
    )
    r = c.get("/journal")
    assert r.status_code == 200
    assert "C:/v/Security/Snort" in r.text and "2026-11-16 03:00:00" in r.text and ">4<" in r.text


def test_journal_page_shows_a_failed_write_escaped(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    journal(s).info = JournalStatus("f", None, 0, "OSError: <b>full</b>")
    r = c.get("/journal")
    assert "never" in r.text and "&lt;b&gt;full&lt;/b&gt;" in r.text and "<b>full" not in r.text


def test_journal_page_says_off_without_a_journal(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    object.__setattr__(s, "journal", None)
    r = c.get("/journal")
    assert r.status_code == 200 and "Off" in r.text and "Write now" not in r.text


def test_write_now_flushes_and_reports(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    r = c.post("/journal/flush", headers=POST)
    assert r.status_code == 200 and "up to date" in r.text and 'id="journal-card"' in r.text
    assert journal(s).flushes == 1


def test_write_now_reports_a_failure(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    journal(s).info = JournalStatus("f", None, 0, "OSError: disk full")
    r = c.post("/journal/flush", headers=POST)
    assert "disk full" in r.text and 'class="flash bad"' in r.text


def test_write_now_with_the_journal_off_is_refused(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    object.__setattr__(s, "journal", None)
    r = c.post("/journal/flush", headers=POST)
    assert r.status_code == 409 and "off" in r.text.lower()


def test_overview_summarises_journal_and_notifications(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    journal(s).info = JournalStatus("f", None, 3, None)
    assert isinstance(s.notify, FakeNotify)
    s.notify.info = NotifyStatus(toasts_shown=2, min_priority=2)
    r = c.get("/")
    assert (
        "3 notes written" in r.text and "2 toasts shown" in r.text and "priority 1 to 2" in r.text
    )


def test_overview_says_off_when_both_are_off(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    object.__setattr__(s, "journal", None)
    object.__setattr__(s, "notify", None)
    r = c.get("/")
    assert "Off (no vault set)" in r.text and "Notifications" in r.text
