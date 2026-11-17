from dataclasses import replace
from datetime import UTC, timedelta, timezone

import pytest
from dash_fakes import T0, alert, status

from snorty.dashboard.views import (
    alert_row,
    edit_message,
    endpoint,
    fmt_span,
    fmt_time,
    group_rows,
    hourly_chart,
    overview_finding,
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


def test_neighbouring_repeats_collapse_into_one_counted_row() -> None:
    base = alert(1000001, priority=3)
    older = [replace(base, ts=base.ts - timedelta(minutes=m)) for m in (1, 2)]
    rows = group_rows([base, *older], UTC)
    assert [(r.count, r.sid) for r in rows] == [(3, 1000001)]
    assert rows[0].first_time == fmt_time(older[-1].ts, UTC)


def test_a_different_event_or_a_long_gap_starts_a_new_row() -> None:
    base = alert(1000001)
    other = replace(base, ts=base.ts - timedelta(minutes=1), src_ip="9.9.9.9")
    late = replace(base, ts=base.ts - timedelta(hours=2))
    assert [r.count for r in group_rows([base, other, late], UTC)] == [1, 1, 1]


def test_fmt_span_is_empty_under_a_minute_then_minutes_then_hours() -> None:
    assert [fmt_span(timedelta(seconds=s)) for s in (0, 59, 60, 600, 3599, 3600, 7300)] == [
        "",
        "",
        "1 min",
        "10 min",
        "60 min",
        "1 h",
        "2 h",
    ]


def test_group_span_runs_from_first_to_last_alert() -> None:
    base = alert(1000001)
    older = replace(base, ts=base.ts - timedelta(minutes=10))
    row = group_rows([base, older], UTC)[0]
    assert (row.count, row.span, row.first_epoch) == (2, "10 min", int(older.ts.timestamp()))


def test_overview_finding_states_the_one_thing_to_know() -> None:
    assert overview_finding(0, 0, "", 0) == "No alerts today."
    assert overview_finding(5, 0, "", 0).startswith("No priority 1 or 2 alerts today.")
    one = overview_finding(5, 1, "Scan", 4)
    assert one.startswith("1 alert of priority 1 or 2 today.") and "Scan (×4)" in one
    assert overview_finding(5, 3, "", 0).startswith("3 alerts of priority 1 or 2")


def test_hourly_chart_has_24_bars_with_the_peak_scaled_to_a_round_top() -> None:
    now = T0.replace(minute=30)
    hour = now.replace(minute=0, second=0, microsecond=0)
    chart = hourly_chart([(hour, 7), (hour - timedelta(hours=2), 3)], now, UTC)
    assert len(chart.bars) == 24 and chart.total == 10
    assert chart.ticks == ["10", "5", "0"]
    assert (chart.bars[-1].height, chart.bars[-3].height, chart.bars[0].height) == (70, 30, 0)
    assert chart.bars[-1].tip.endswith("7 alerts")
    assert [c for c, _ in chart.labels] == [1, 7, 13, 19]


@pytest.mark.parametrize(("pct", "warn"), [(None, False), (0.5, False), (1.0, False), (1.5, True)])
def test_sensor_card_warns_above_one_percent_dropped(pct: float | None, warn: bool) -> None:
    card = sensor_card(status(State.RUNNING, drop_pct=pct), UTC)
    assert card.drop_pct == pct and card.drop_warn is warn
