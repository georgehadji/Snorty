from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from snorty.core.models import Alert, Suppression


def make_alert() -> Alert:
    return Alert(
        ts=datetime(2026, 11, 15, 23, 30, 13, 875248, tzinfo=UTC),
        gid=1,
        sid=1000002,
        rev=1,
        msg="NIDS test",
        classification=None,
        priority=1,
        proto="TCP",
        src_ip="127.0.0.1",
        src_port=18080,
        dst_ip="127.0.0.1",
        dst_port=60998,
        raw="line",
    )


def test_alert_is_immutable_and_hashable() -> None:
    alert = make_alert()
    with pytest.raises(FrozenInstanceError):
        alert.sid = 2  # type: ignore[misc]
    assert hash(alert) == hash(make_alert())
    assert alert == make_alert()


def test_suppression_global() -> None:
    assert Suppression(1, 2010935).to_threshold_line() == "suppress gen_id 1, sig_id 2010935"


def test_suppression_tracked() -> None:
    s = Suppression(1, 2010935, track="by_src", ip="1.2.3.4")
    assert s.to_threshold_line() == "suppress gen_id 1, sig_id 2010935, track by_src, ip 1.2.3.4"


@pytest.mark.parametrize(
    ("track", "ip"), [("by_src", None), (None, "1.2.3.4")], ids=["track-only", "ip-only"]
)
def test_suppression_track_and_ip_must_come_together(track: str | None, ip: str | None) -> None:
    with pytest.raises(ValueError):
        Suppression(1, 2, track=track, ip=ip)  # type: ignore[arg-type]
