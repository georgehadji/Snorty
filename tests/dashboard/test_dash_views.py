from datetime import UTC, timedelta, timezone

import pytest
from dash_fakes import T0, alert, status

from snorty.dashboard.views import (
    alert_row,
    edit_message,
    endpoint,
    fmt_time,
    rules_summary,
    sensor_card,
    update_message,
)
from snorty.rules.service import EditReport, UpdateReport
from snorty.rules.state import RulesState
from snorty.sensor import State
from snorty.snort.models import Interface

PLUS2 = timezone(timedelta(hours=2))


def test_fmt_time_is_local_and_plain() -> None:
    assert fmt_time(T0, UTC) == "2026-11-16 12:00:00"
    assert fmt_time(T0, PLUS2) == "2026-11-16 14:00:00"


def test_endpoint() -> None:
    assert endpoint("10.0.0.1", 80) == "10.0.0.1:80"
    assert endpoint("10.0.0.1", None) == "10.0.0.1"
    assert endpoint("fe80::1", 80) == "[fe80::1]:80"
    assert endpoint("fe80::1", None) == "fe80::1"


def test_alert_row_fields() -> None:
    row = alert_row(alert(2001, msg="ET SCAN x", priority=2, src_port=None), PLUS2)
    assert (row.sid, row.priority, row.msg, row.proto) == (2001, 2, "ET SCAN x", "TCP")
    assert row.time == "2026-11-16 14:00:00"
    assert (row.src, row.dst) == ("10.0.0.1", "10.0.0.2:80")
    assert row.msg_short == "ET SCAN x"


def test_alert_row_truncates_long_messages_but_keeps_the_full_text() -> None:
    row = alert_row(alert(msg="A" * 10_000), UTC)
    assert len(row.msg_short) <= 120 and row.msg_short.endswith("…")
    assert row.msg == "A" * 10_000


CASES = {
    State.STOPPED: ("idle", True, False, False),
    State.STARTING: ("warn", False, True, False),
    State.RUNNING: ("ok", False, True, True),
    State.STOPPING: ("warn", False, False, False),
    State.FAILED: ("bad", True, True, False),
}


@pytest.mark.parametrize("state", list(State))
def test_sensor_card_tone_and_buttons_per_state(state: State) -> None:
    tone, can_start, can_stop, can_restart = CASES[state]
    card = sensor_card(status(state), UTC)
    assert card.state == state.value and card.tone == tone
    assert (card.can_start, card.can_stop, card.can_restart) == (can_start, can_stop, can_restart)


def test_sensor_card_details() -> None:
    iface = Interface(4, "aa", "192.168.1.5", r"\Device\NPF_{A}", "Wi-Fi")
    card = sensor_card(
        status(
            State.RUNNING,
            interface=iface,
            started_at=T0,
            restarts=2,
            alerts_seen=7,
            last_alert_ts=T0,
            last_error="boom",
        ),
        PLUS2,
    )
    assert card.interface == "Wi-Fi (192.168.1.5)"
    assert card.since == "2026-11-16 14:00:00" and card.last_alert == "2026-11-16 14:00:00"
    assert (card.restarts, card.alerts_seen, card.error) == (2, 7, "boom")
    bare = sensor_card(status(), UTC)
    assert bare.interface is None and bare.since is None and bare.last_alert is None


def test_rules_summary() -> None:
    s = rules_summary(
        RulesState(
            last_md5="x", updated_at="2026-11-16T03:00:00.123+02:00", rule_count=42, result="ok"
        )
    )
    assert (s.updated, s.count, s.result) == ("2026-11-16 03:00:00", "42", "ok")
    never = rules_summary(RulesState())
    assert (never.updated, never.count, never.result) == ("never", "unknown", "")


def test_edit_message_says_whether_snort_restarted() -> None:
    done = EditReport(True, True, "muted 2001")
    assert edit_message(done, sensor_was_running=True).text == (
        "Done: muted 2001. The sensor was restarted to load it."
    )
    assert "next time the sensor starts" in edit_message(done, sensor_was_running=False).text
    same = edit_message(EditReport(True, False, "no change"), sensor_was_running=True)
    assert (same.ok, same.text) == (True, "Nothing to change.")
    bad = edit_message(EditReport(False, False, "snort -T failed"), sensor_was_running=True)
    assert (bad.ok, bad.text) == (False, "Failed: snort -T failed")


def test_update_message_per_outcome() -> None:
    assert update_message(UpdateReport("updated", 5, "x", 0, "5 rules")).text.startswith("Updated:")
    assert "Restart the sensor" in update_message(UpdateReport("updated", 5, "x", 0, "d")).text
    assert update_message(UpdateReport("up_to_date", 5, "x", 0, "same md5")).ok
    failed = update_message(UpdateReport("failed", None, None, 0, "no network"))
    assert (failed.ok, failed.text) == (False, "Update failed: no network")
