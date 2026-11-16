import re
import time
from datetime import timedelta
from pathlib import Path

import pytest
from dash_fakes import FakeRules, FakeSensor, alert
from starlette.testclient import TestClient
from test_dash_routes import NOW, POST, make

from snorty.rules.blocks import MutedRule
from snorty.rules.service import EditReport, UpdateReport
from snorty.sensor import State
from snorty.services import Services


def rules(s: Services) -> FakeRules:
    assert isinstance(s.rules, FakeRules)
    return s.rules


def sensor(s: Services) -> FakeSensor:
    assert isinstance(s.sensor, FakeSensor)
    return s.sensor


def wait_done(c: TestClient, tries: int = 60) -> str:
    for _ in range(tries):
        r = c.get("/rules/update/status")
        if "hx-get" not in r.text:
            return r.text
        time.sleep(0.05)
    raise AssertionError("update never finished")


def test_rules_page_shows_state_muted_rules_and_home_net(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    rules(s).muted_rules = [MutedRule(2001, "noisy <i>one</i>"), MutedRule(2002)]
    r = c.get("/rules")
    assert r.status_code == 200
    assert 'href="/rules" aria-current="page"' in r.text
    assert "1234" in r.text and 'id="rules-summary"' in r.text
    assert "2001" in r.text and "noisy &lt;i&gt;one&lt;/i&gt;" in r.text and "<i>one" not in r.text
    assert 'hx-post="/rules/unmute/2001?view=rules"' in r.text
    assert "[10.0.0.0/8]" in r.text and 'name="value"' in r.text
    assert 'hx-post="/rules/update"' in r.text and 'name="force"' in r.text


def test_rules_page_with_nothing_muted(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    assert "No muted rules" in c.get("/rules").text


def test_update_returns_a_polling_fragment_at_once_then_the_result(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    rules(s).delay = 0.2
    with c:
        r = c.post("/rules/update", headers=POST)
        assert r.status_code == 200 and 'hx-get="/rules/update/status"' in r.text
        assert 'hx-trigger="every 1s"' in r.text
        done = wait_done(c)
    assert rules(s).calls == [("update", False)]
    assert "Updated: 1234 rules" in done and "hx-get" not in done
    assert 'id="rules-summary"' in done and 'hx-swap-oob="true"' in done


def test_a_second_click_while_running_does_not_start_another_update(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    rules(s).delay = 0.3
    with c:
        first = c.post("/rules/update", headers=POST)
        second = c.post("/rules/update", headers=POST)
        assert "already running" in second.text.lower()
        assert "already running" not in first.text.lower()
        wait_done(c)
        assert [x for x in rules(s).calls if x[0] == "update"] == [("update", False)]
        c.post("/rules/update", headers=POST)  # allowed again once finished
        wait_done(c)
    assert len(rules(s).calls) == 2


def test_force_checkbox_is_passed_on(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    with c:
        c.post("/rules/update", headers=POST, content="force=on")
        wait_done(c)
    assert rules(s).calls == [("update", True)]


def test_a_failed_update_is_shown_as_an_error(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    rules(s).update_report = UpdateReport("failed", None, None, 0, "no network")
    with c:
        c.post("/rules/update", headers=POST)
        assert "Update failed: no network" in wait_done(c)


def test_an_unexpected_exception_shows_a_plain_message_and_keeps_serving(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    rules(s).update_error = True
    with c:
        c.post("/rules/update", headers=POST)
        text = wait_done(c)
        assert "unexpected error" in text and "secret internals" not in text
        assert c.get("/rules").status_code == 200


def test_update_status_before_any_update_is_empty(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    r = c.get("/rules/update/status")
    assert r.status_code == 200 and "hx-get" not in r.text and 'id="update-status"' in r.text


def test_mute_from_an_alert_row_uses_the_latest_message_as_the_note(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    sensor(s).set_state(State.RUNNING)
    s.repo.add(alert(2001, msg="ET SCAN nmap", ts=NOW - timedelta(minutes=5)))
    r = c.post("/rules/mute/2001", headers=POST)
    assert r.status_code == 200
    assert rules(s).calls == [("mute", 2001, "ET SCAN nmap", True)]
    assert 'id="flash"' in r.text and "Done: done." in r.text
    assert "restarted" in r.text and "hx-swap-oob" not in r.text


def test_mute_with_the_sensor_stopped_says_it_takes_effect_later(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    r = c.post("/rules/mute/2001", headers=POST)
    assert "next time the sensor starts" in r.text
    assert rules(s).calls == [("mute", 2001, "", True)]


def test_a_failed_mute_is_shown_as_an_error(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    rules(s).edit_report = EditReport(False, False, "snort -T failed")
    r = c.post("/rules/mute/2001", headers=POST)
    assert "Failed: snort -T failed" in r.text and 'class="flash bad"' in r.text


@pytest.mark.parametrize("sid", ["abc", "0", "-3", "99999999999", "1.5"])
def test_bad_sids_give_422_and_call_nothing(tmp_path: Path, sid: str) -> None:
    c, s = make(tmp_path)
    for action in ("mute", "unmute"):
        r = c.post(f"/rules/{action}/{sid}", headers=POST)
        assert r.status_code == 422 and 'class="flash bad"' in r.text
    assert rules(s).calls == []


def test_unmute_from_the_rules_page_also_returns_the_refreshed_list(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    rules(s).muted_rules = [MutedRule(2001), MutedRule(2002, "keep me")]
    r = c.post("/rules/unmute/2001?view=rules", headers=POST)
    assert rules(s).calls == [("unmute", 2001, True)]
    assert 'id="muted-card"' in r.text and 'hx-swap-oob="true"' in r.text
    assert "keep me" in r.text and "unmute/2001" not in r.text


def test_unmute_without_the_view_marker_returns_only_the_message(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    r = c.post("/rules/unmute/2001", headers=POST)
    assert 'id="muted-card"' not in r.text


def test_home_net_set_and_reset(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    r = c.post("/rules/home-net", headers=POST, content="value=%5B192.168.0.0%2F16%5D")
    assert r.status_code == 200 and 'id="home-net-card"' in r.text
    c.post("/rules/home-net", headers=POST, content="value=")
    c.post("/rules/home-net", headers=POST, content="value=+++")
    assert rules(s).calls == [
        ("home_net", "[192.168.0.0/16]", True),
        ("home_net", None, True),
        ("home_net", None, True),
    ]


@pytest.mark.parametrize(
    "body",
    [
        "value=any%0Ainclude+%2Fetc%2Fpasswd",
        "value=a%3Bb",
        "value=" + "x" * 300,
        "value=%FF",
        "a=1&a=2",
    ],
)
def test_bad_home_net_gives_422_and_calls_nothing(tmp_path: Path, body: str) -> None:
    c, s = make(tmp_path)
    r = c.post("/rules/home-net", headers=POST, content=body)
    assert r.status_code == 422 and 'class="flash bad"' in r.text
    assert rules(s).calls == []


@pytest.mark.parametrize(
    "path",
    ["/rules/update", "/rules/mute/2001", "/rules/unmute/2001", "/rules/home-net"],
)
def test_every_rules_post_needs_the_token(tmp_path: Path, path: str) -> None:
    c, s = make(tmp_path)
    assert c.post(path).status_code == 403
    assert rules(s).calls == []


def test_alert_rows_have_a_mute_button(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    s.repo.add(alert(2001, msg="x", ts=NOW - timedelta(minutes=1)))
    for url in ("/alerts", "/alerts/rows", "/"):
        html = c.get(url).text
        assert re.search(r'<button[^>]*hx-post="/rules/mute/2001"[^>]*hx-target="#flash"', html), (
            url
        )
    assert 'id="flash"' in c.get("/alerts").text


def test_rules_page_survives_unreadable_snort_files(tmp_path: Path) -> None:
    c, s = make(tmp_path)

    async def unreadable() -> list[MutedRule]:
        raise PermissionError(13, "Permission denied")

    rules(s).muted = unreadable  # type: ignore[method-assign]
    r = c.get("/rules")
    assert r.status_code == 200
    assert "Could not read the Snort settings: Permission denied" in r.text
    assert "Update now" in r.text and "Muted rules" not in r.text
