from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from snorty.core.models import Alert
from snorty.core.parser import parse_line

TZ = timezone(timedelta(hours=2))
FIXTURE = Path(__file__).parent.parent / "fixtures" / "alert_fast.txt"
REAL_LINES = [ln for ln in FIXTURE.read_text().splitlines() if ln.strip()]


def parse(line: str) -> Alert | None:
    return parse_line(line, default_year=2026, tz=TZ)


@pytest.mark.parametrize("line", REAL_LINES)
def test_real_lines_parse(line: str) -> None:
    alert = parse(line)
    assert alert is not None
    assert alert.raw == line
    assert alert.ts.tzinfo is TZ


def test_real_line_fields() -> None:
    alert = parse(REAL_LINES[0])
    assert alert == Alert(
        ts=datetime(2026, 11, 15, 23, 30, 12, 994264, tzinfo=TZ),
        gid=1,
        sid=1000002,
        rev=1,
        msg="NIDS test - uid=0(root) response",
        classification=None,
        priority=0,
        proto="TCP",
        src_ip="127.0.0.1",
        src_port=18080,
        dst_ip="127.0.0.1",
        dst_port=60994,
        raw=REAL_LINES[0],
    )


def test_year_in_timestamp_wins_over_default() -> None:
    line = (
        "11/15/25-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 3] {UDP} 1.1.1.1:53 -> 2.2.2.2:9"
    )
    alert = parse(line)
    assert alert is not None
    assert alert.ts == datetime(2025, 11, 15, 23, 30, 13, 875248, tzinfo=TZ)
    assert alert.proto == "UDP"


def test_classification_and_icmp_without_ports() -> None:
    line = (
        "11/15-23:30:13.875248  [**] [1:2010935:3] ET SCAN Nmap [bad] probe [**] "
        "[Classification: Attempted Information Leak] [Priority: 2] {ICMP} 10.0.0.1 -> 10.0.0.2"
    )
    alert = parse(line)
    assert alert is not None
    assert alert.msg == "ET SCAN Nmap [bad] probe"
    assert alert.classification == "Attempted Information Leak"
    assert (alert.sid, alert.rev, alert.priority) == (2010935, 3, 2)
    assert (alert.src_ip, alert.src_port, alert.dst_ip, alert.dst_port) == (
        "10.0.0.1",
        None,
        "10.0.0.2",
        None,
    )


def test_expanded_ipv6_ninth_group_is_port() -> None:
    line = (
        "11/15-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {TCP} "
        "2606:50c0:8002:0000:0000:0000:0000:0215:443 -> "
        "2001:0db8:0000:0000:0000:0000:0000:0001:5000"
    )
    alert = parse(line)
    assert alert is not None
    assert alert.src_ip == "2606:50c0:8002:0000:0000:0000:0000:0215"
    assert alert.src_port == 443
    assert alert.dst_ip == "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert alert.dst_port == 5000


def test_ipv6_without_port() -> None:
    line = (
        "11/15-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {ICMP} "
        "fe80:0000:0000:0000:0000:0000:0000:0001 -> ff02:0000:0000:0000:0000:0000:0000:0001"
    )
    alert = parse(line)
    assert alert is not None
    assert alert.src_port is None and alert.dst_port is None


def test_unusual_protocol_label() -> None:
    line = "11/15-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {PROTO:255} 1.1.1.1 -> 2.2.2.2"
    alert = parse(line)
    assert alert is not None
    assert alert.proto == "PROTO:255"


def test_trailing_newline_is_ignored() -> None:
    assert parse(REAL_LINES[0] + "\r\n") is not None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        REAL_LINES[0][:40],
        REAL_LINES[0].split(" {")[0],
        "13/45-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {TCP} 1.1.1.1:1 -> 2.2.2.2:2",
        "02/30-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {TCP} 1.1.1.1:1 -> 2.2.2.2:2",
        "11/15-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {TCP} 999.1.1.1:1 -> 2.2.2.2:2",
        "11/15-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {TCP} 1.1.1.1:99999 -> 2.2.2.2:2",
        "11/15-23:30:13.875248  [**] [1:1:1] x [**] [Priority: 1] {TCP} 1.1.1.1:abc -> 2.2.2.2:2",
    ],
)
def test_malformed_returns_none(line: str) -> None:
    assert parse(line) is None
