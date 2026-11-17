import re
from datetime import timedelta
from pathlib import Path

import pytest
from dash_fakes import T0, FakeRules, FakeSensor, alert, make_services
from starlette.testclient import TestClient

from snorty.dashboard.app import build_app
from snorty.rules.state import RulesState
from snorty.sensor import State
from snorty.services import Services

TOKEN = "t" * 64
PORT = 8765
NOW = T0 + timedelta(minutes=30)  # 12:30 UTC
POST = {"X-Snorty-Token": TOKEN}


def make(tmp_path: Path) -> tuple[TestClient, Services]:
    services = make_services(tmp_path)
    app = build_app(services, token=TOKEN, port=PORT, clock=lambda: NOW)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}"), services


def sensor(s: Services) -> FakeSensor:
    assert isinstance(s.sensor, FakeSensor)
    return s.sensor


def button(html: str, action: str) -> str:
    m = re.search(rf'<button[^>]*hx-post="/sensor/{action}"[^>]*>', html)
    assert m, f"no {action} button"
    return m.group(0)


def test_overview_has_nav_sensor_card_and_the_token(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    r = c.get("/")
    assert r.status_code == 200
    for link in ("/alerts", "/rules", "/journal", "/lab"):
        assert f'href="{link}"' in r.text
    assert 'id="sensor-card"' in r.text and "Stopped" in r.text
    assert TOKEN in r.text and "X-Snorty-Token" in r.text
    assert 'name="htmx-config"' in r.text and "<script>" not in r.text
    assert r.headers["content-security-policy"].startswith("default-src 'self'")


def test_overview_counts_top_rules_and_recent_alerts(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(2001, msg="in the hour", ts=T0 + timedelta(minutes=10)))
    s.repo.add(alert(2001, msg="in the hour", ts=T0 + timedelta(minutes=11)))
    s.repo.add(alert(2002, msg="earlier today", ts=T0 - timedelta(hours=1)))
    s.repo.add(alert(2003, msg="yesterday", ts=T0 - timedelta(hours=13)))
    html = c.get("/").text
    assert re.search(r'id="count-hour">2<', html)
    assert re.search(r'id="count-today">3<', html)
    assert "in the hour" in html and "earlier today" in html and "yesterday" in html
    top = html[html.index('id="top-rules"') :]
    assert top.index("2001") < top.index("2002")
    assert "×2" in top


def test_overview_shows_what_was_first_seen_today_and_says_it_is_learning(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.note_seen("dns", ["old.example"], NOW - timedelta(days=1))
    s.repo.note_seen("dns", ["new.example"], NOW - timedelta(minutes=5))
    html = c.get("/").text
    card = html[html.index("First seen today") :]
    assert "new.example" in card and "old.example" not in card
    assert "Learning since" in card
    s.repo.note_seen("dns", ["older.example"], NOW - timedelta(days=8))
    assert "Learning since" not in c.get("/").text


def test_overview_answers_the_one_question_and_draws_the_hour_chart(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(2001, msg="in the hour", priority=1, ts=T0 + timedelta(minutes=10)))
    html = c.get("/").text
    assert "<h1>Overview</h1>" in html
    assert re.search(r'id="count-urgent">1<', html)
    assert "1 alert of priority 1 or 2 today." in html
    assert html.count('class="bar"') == 1 and "Alerts per hour" in html


@pytest.mark.parametrize(
    ("path", "title"),
    [("/alerts", "Alerts"), ("/rules", "Rules"), ("/journal", "Journal"), ("/lab", "Lab")],
)
def test_every_page_has_one_h1(tmp_path: Path, path: str, title: str) -> None:
    c, _ = make(tmp_path)
    html = c.get(path).text
    assert html.count("<h1") == 1 and f"<h1>{title}</h1>" in html


def test_pages_have_skip_link_named_nav_and_labelled_controls(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(2001, ts=T0 + timedelta(minutes=10)))
    html = c.get("/").text
    assert 'href="#main"' in html and 'id="main"' in html and 'aria-label="Main"' in html
    assert 'aria-label="Mute rule 2001"' in html
    assert "<th>" not in html and html.count('<th scope="col">') >= 6
    assert "Actions</span></th>" in html
    assert 'aria-label="Pcap file to upload"' in c.get("/lab").text


def test_assets_are_versioned_cached_and_compressed(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    html = c.get("/").text
    m = re.search(r'href="(/static/app\.css\?v=[0-9a-f]{10})"', html)
    assert m and 'href="/static/favicon.svg?v=' in html
    r = c.get(m.group(1))
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert "cache-control" not in c.get("/static/app.css").headers
    assert c.get("/", headers={"accept-encoding": "gzip"}).headers["content-encoding"] == "gzip"


def test_alert_rows_open_to_show_detail_and_the_page_has_a_theme_button(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(2001, ts=T0 + timedelta(minutes=10)))
    html = c.get("/alerts").text
    assert "<details" in html and "<summary" in html and "Alert line" in html
    assert 'id="theme"' in html


def test_alert_detail_offers_copyable_wireshark_filters(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(2001, ts=T0 + timedelta(minutes=10)))
    html = c.get("/alerts").text
    packet = "ip.src == 10.0.0.1 &amp;&amp; ip.dst == 10.0.0.2 &amp;&amp; tcp.srcport == 4444"
    assert packet in html and "Conversation filter" in html and "ip.addr == 10.0.0.1" in html
    assert html.count("data-copy=") == 2 and 'aria-label="Copy the packet filter"' in html
    assert "Copy the conversation filter" in html


def test_templates_use_no_inline_style_attributes() -> None:
    """The CSP (default-src 'self') blocks them, so they would silently do nothing."""
    root = Path("src/snorty/dashboard/templates")
    assert [p.name for p in root.glob("*.html") if " style=" in p.read_text("utf-8")] == []


def test_overview_with_no_alerts(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    html = c.get("/").text
    assert re.search(r'id="count-hour">0<', html) and "No alerts yet" in html


def test_hostile_alert_text_is_escaped(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(msg='<script>alert("x")</script> & "q"', ts=NOW - timedelta(minutes=1)))
    html = c.get("/").text
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_overview_shows_the_rules_summary(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    assert isinstance(s.rules, FakeRules)
    s.rules.state = RulesState(
        last_md5="x", updated_at="2026-11-16T03:00:00", rule_count=4321, result="updated"
    )
    html = c.get("/").text
    assert "4321" in html and "2026-11-16 03:00:00" in html


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_sensor_actions_call_the_service_once_and_return_the_card(
    tmp_path: Path, action: str
) -> None:
    c, s = make(tmp_path)
    r = c.post(f"/sensor/{action}", headers=POST)
    assert r.status_code == 200
    assert sensor(s).calls == [action]
    assert r.text.lstrip().startswith("<section") and 'id="sensor-card"' in r.text
    assert "<html" not in r.text  # a fragment, not a page


def test_unknown_sensor_action_is_rejected(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    assert c.post("/sensor/explode", headers=POST).status_code == 422
    assert sensor(s).calls == []


@pytest.mark.parametrize(
    "state,enabled",
    [
        (State.STOPPED, {"start"}),
        (State.STARTING, {"stop"}),
        (State.RUNNING, {"stop", "restart"}),
        (State.STOPPING, set()),
        (State.FAILED, {"start", "stop"}),
    ],
)
def test_buttons_are_disabled_when_the_action_is_not_possible(
    tmp_path: Path, state: State, enabled: set[str]
) -> None:
    c, s = make(tmp_path)
    sensor(s).set_state(state)
    html = c.get("/").text
    for action in ("start", "stop", "restart"):
        assert (" disabled" not in button(html, action)) == (action in enabled), action


def test_sensor_card_shows_the_error_and_the_state(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    sensor(s).set_state(State.FAILED, last_error="no adapter <b>")
    html = c.get("/").text
    assert "Failed" in html and "no adapter &lt;b&gt;" in html


def test_post_without_the_token_is_refused_and_changes_nothing(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    assert c.post("/sensor/start").status_code == 403
    assert sensor(s).calls == []


def test_a_foreign_host_is_refused(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    assert c.get("/", headers={"host": "evil.com"}).status_code == 400


def test_healthz(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    r = c.get("/healthz")
    assert r.status_code == 200 and r.json() == {"ok": True}


def test_static_files_are_served_locally(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    assert c.get("/static/htmx.min.js").status_code == 200
    assert c.get("/static/app.css").status_code == 200
    assert c.get("/static/../app.py").status_code in (400, 404)
    html = c.get("/").text
    assert "http://" not in html.replace(f"http://127.0.0.1:{PORT}", "")
    assert "https://" not in html


def test_every_page_header_shows_the_sensor_state(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    for path in ("/", "/alerts", "/rules", "/lab"):
        html = c.get(path).text
        assert 'id="top-status"' in html and "Sensor stopped" in html
        assert 'id="live"' in html and "hidden" in html.split('id="live"')[1][:40]


def test_repeated_alerts_show_one_row_with_a_count(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    for minute in range(3):
        s.repo.add(alert(2001, msg="ping", ts=T0 + timedelta(minutes=minute)))
    html = c.get("/alerts?range=all").text
    assert html.count("data-alert") == 1 and "×3" in html
    assert 'class="when"' in html and 'datetime="' in html
