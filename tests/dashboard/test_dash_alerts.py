import re
from datetime import timedelta
from pathlib import Path

import pytest
from dash_fakes import alert
from test_dash_routes import NOW, make

from snorty.dashboard.views import AlertFilters, parse_alert_filters
from snorty.services import Services


def fill(s: Services, n: int, *, sid: int = 2001, priority: int = 1) -> None:
    s.repo.add_many(
        # a new source port each time keeps neighbours from collapsing into one counted row
        alert(
            sid,
            msg=f"alert {i}",
            priority=priority,
            ts=NOW - timedelta(minutes=i + 1),
            src_port=4000 + i,
        )
        for i in range(n)
    )


def row_count(html: str) -> int:
    return len(re.findall(r'<tr class="p\d"', html))


def test_parse_defaults_and_values() -> None:
    assert parse_alert_filters({}) == AlertFilters(None, None, "24h", 1)
    f = parse_alert_filters({"sid": "2001", "priority": "2", "range": "7d", "page": "3"})
    assert (f.sid, f.priority, f.range, f.page) == (2001, 2, "7d", 3)
    assert parse_alert_filters(
        {"sid": "", "priority": "", "range": "", "page": ""}
    ) == AlertFilters(None, None, "24h", 1)


@pytest.mark.parametrize(
    "params",
    [
        {"sid": "abc"},
        {"sid": "0"},
        {"sid": "-5"},
        {"priority": "9"},
        {"priority": "0"},
        {"range": "1y"},
        {"page": "0"},
        {"page": "abc"},
        {"page": "10001"},
        {"page": "-1"},
    ],
)
def test_parse_rejects_bad_values(params: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        parse_alert_filters(params)


def test_query_string_keeps_filters_and_sets_the_page() -> None:
    f = AlertFilters(2001, 2, "7d", 1)
    assert f.query_string(3) == "sid=2001&priority=2&range=7d&page=3"
    assert AlertFilters(None, None, "24h", 1).query_string(2) == "range=24h&page=2"


def test_alerts_page_lists_newest_first_with_filter_form(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    fill(s, 3)
    r = c.get("/alerts")
    assert r.status_code == 200
    assert 'href="/alerts" aria-current="page"' in r.text
    for name in ("sid", "priority", "range"):
        assert f'name="{name}"' in r.text
    assert r.text.index("alert 0") < r.text.index("alert 1") < r.text.index("alert 2")
    assert row_count(r.text) == 3


def test_rows_fragment_is_not_a_page(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    fill(s, 2)
    r = c.get("/alerts/rows")
    assert r.status_code == 200 and "<html" not in r.text and row_count(r.text) == 2


def test_default_range_is_24_hours_and_all_includes_older(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(msg="recent", ts=NOW - timedelta(hours=2)))
    s.repo.add(alert(msg="old one", ts=NOW - timedelta(hours=30)))
    s.repo.add(alert(msg="ancient", ts=NOW - timedelta(days=20)))
    assert "old one" not in c.get("/alerts/rows").text
    assert "old one" in c.get("/alerts/rows?range=7d").text
    assert "ancient" not in c.get("/alerts/rows?range=7d").text
    assert "ancient" in c.get("/alerts/rows?range=all").text
    assert "recent" not in c.get("/alerts/rows?range=1h").text


def test_sid_and_priority_filters_match_the_repository(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(111, msg="aaa", priority=1, ts=NOW - timedelta(minutes=1)))
    s.repo.add(alert(222, msg="bbb", priority=2, ts=NOW - timedelta(minutes=2)))
    s.repo.add(alert(333, msg="ccc", priority=3, ts=NOW - timedelta(minutes=3)))
    only = c.get("/alerts/rows?sid=222").text
    assert "bbb" in only and "aaa" not in only and "ccc" not in only
    p2 = c.get("/alerts/rows?priority=2").text
    assert "aaa" in p2 and "bbb" in p2 and "ccc" not in p2
    p1 = c.get("/alerts/rows?priority=1").text
    assert "aaa" in p1 and "bbb" not in p1


def test_paging_by_fifty_with_a_load_more_row(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    fill(s, 120)
    p1 = c.get("/alerts/rows?range=all").text
    p2 = c.get("/alerts/rows?range=all&page=2").text
    p3 = c.get("/alerts/rows?range=all&page=3").text
    assert (row_count(p1), row_count(p2), row_count(p3)) == (50, 50, 20)
    assert "page=2" in p1 and "page=3" in p2 and 'id="more"' not in p3
    expect = s.repo.query(limit=50, offset=50)
    assert [f"alert {i}" for i in range(50, 100)] == [a.msg for a in expect]
    assert "alert 50<" in p2 and "alert 99<" in p2 and "alert 49<" not in p2


def test_a_full_last_page_has_no_load_more(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    fill(s, 50)
    assert 'id="more"' not in c.get("/alerts/rows").text


@pytest.mark.parametrize(
    "qs",
    ["sid=abc", "sid=0", "priority=9", "range=1y", "page=0", "page=x", "page=99999999999999"],
)
def test_invalid_values_give_422_with_an_inline_message(tmp_path: Path, qs: str) -> None:
    c, s = make(tmp_path)
    fill(s, 1)
    for path in ("/alerts", "/alerts/rows"):
        r = c.get(f"{path}?{qs}")
        assert r.status_code == 422
        assert 'class="error"' in r.text and "Traceback" not in r.text
        assert row_count(r.text) == 0


def test_hostile_text_is_escaped_in_text_and_attributes(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(msg='x" onmouseover="evil()" <img src=x>', ts=NOW - timedelta(minutes=1)))
    html = c.get("/alerts/rows").text
    assert 'onmouseover="evil()"' not in html and "<img" not in html
    assert "&#34;" in html and "&lt;img" in html


def test_a_ten_thousand_character_message_is_cut_but_kept_in_the_tooltip(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(msg="é" * 10_000, ts=NOW - timedelta(minutes=1)))
    html = c.get("/alerts/rows").text
    assert html.count("é") == 10_000 + 119  # full text in title, 119 chars + ellipsis shown
    assert "…" in html


def test_form_values_stay_selected(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    html = c.get("/alerts?sid=2001&priority=2&range=7d").text
    assert 'value="2001"' in html
    assert re.search(r'<option value="2" selected', html)
    assert re.search(r'<option value="7d" selected', html)


def test_alert_tables_carry_the_class_that_keeps_narrow_screens_readable(tmp_path: Path) -> None:
    """app.css keeps times on one line and gives the rule column room under `table.alerts`."""
    c, _ = make(tmp_path)
    assert '<table class="alerts">' in c.get("/alerts").text
    assert '<table class="alerts">' in c.get("/").text
    assert "table.alerts" in (Path("src/snorty/dashboard/static/app.css")).read_text("utf-8")
