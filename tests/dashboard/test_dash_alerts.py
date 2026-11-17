import re
from datetime import timedelta
from pathlib import Path

import pytest
from dash_fakes import alert
from test_dash_routes import NOW, POST, make

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


def test_search_is_trimmed_capped_and_free_of_control_characters() -> None:
    assert parse_alert_filters({"q": "  nmap "}).text == "nmap"
    assert parse_alert_filters({"q": "   "}).text is None
    assert parse_alert_filters({"q": "x" * 200}).text == "x" * 200
    for bad in ("x" * 201, "a\nb", "a\x00b"):
        with pytest.raises(ValueError, match="search"):
            parse_alert_filters({"q": bad})
    assert "q=50%25" in AlertFilters(None, None, "24h", 1, text="50%").query_string(1)


def test_the_alerts_page_searches_rule_text(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    fill(s, 3)
    html = c.get("/alerts/rows", params={"q": "ALERT 1", "range": "all"}).text
    assert row_count(html) == 1 and "alert 1" in html
    assert 'name="q"' in c.get("/alerts").text


def test_csv_export_uses_the_filters_and_defuses_formulas(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    fill(s, 3)
    s.repo.add(alert(2002, msg="=HYPERLINK(1)", ts=NOW - timedelta(minutes=9)))
    r = c.get("/alerts/export.csv", params={"range": "all"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'filename="snorty-alerts.csv"' in r.headers["content-disposition"]
    lines = r.text.splitlines()
    assert lines[0].startswith("time,priority,sid") and len(lines) == 5
    assert any(",'=HYPERLINK(1)," in line for line in lines)
    only = c.get("/alerts/export.csv", params={"range": "all", "sid": "2002"}).text
    assert len(only.splitlines()) == 2
    assert c.get("/alerts/export.csv", params={"sid": "x"}).status_code == 422


def test_csv_export_pages_through_more_than_one_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("snorty.dashboard.app.EXPORT_PAGE", 2)
    c, s = make(tmp_path)
    fill(s, 5)
    lines = c.get("/alerts/export.csv", params={"range": "all"}).text.splitlines()
    assert len(lines) == 6 and len(set(lines)) == 6


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
    # the full text sits in the tooltip, the detail rule and the alert line; 119 chars are shown
    assert html.count("é") == 3 * 10_000 + 119
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


def test_group_by_source_lists_each_address_and_links_to_its_alerts(tmp_path: Path) -> None:
    from dataclasses import replace

    c, s = make(tmp_path)
    s.repo.add_many(
        replace(alert(2001, ts=NOW - timedelta(minutes=i + 1)), src_ip=ip)
        for i, ip in enumerate(["10.0.0.7", "10.0.0.7", "10.0.0.8"])
    )
    r = c.get("/alerts?group=src_ip")
    assert r.status_code == 200
    assert "10.0.0.7" in r.text and "10.0.0.8" in r.text
    assert 'href="/alerts?src=10.0.0.7&amp;range=24h&amp;page=1"' in r.text
    filtered = c.get("/alerts?src=10.0.0.8").text
    assert row_count(filtered) == 1


@pytest.mark.parametrize("query", ["src=nope", "dst=1.2.3", "group=bogus"])
def test_bad_host_or_group_filters_give_422(tmp_path: Path, query: str) -> None:
    c, _ = make(tmp_path)
    assert c.get(f"/alerts?{query}").status_code == 422


def test_the_inbox_acknowledges_a_rule_and_can_auto_acknowledge_it(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    fill(s, 3, sid=2001)
    fill(s, 2, sid=2002)
    page = c.get("/inbox").text
    assert "5 new" in page and "2001" in page and "2002" in page
    r = c.post("/triage/set?sid=2001&state=ack", headers=POST)
    assert r.status_code == 200 and "2 new · 0 starred · 3 acknowledged" in r.text
    r = c.post("/triage/archive?sid=2002", headers=POST)
    assert "0 new" in r.text and "Nothing needs a look" in r.text and "Remove" in r.text
    assert "Unacknowledged" in c.get("/").text


def test_bad_inbox_requests_give_422(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    assert c.post("/triage/set?sid=2001&state=bogus", headers=POST).status_code == 422
    assert c.post("/triage/set?sid=x&state=ack", headers=POST).status_code == 422
    assert c.post("/triage/archive?sid=0", headers=POST).status_code == 422
