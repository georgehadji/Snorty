from datetime import UTC, datetime, timedelta, timezone

import pytest

from snorty.core.models import Alert
from snorty.notify.toast import Toast, build_toast, sanitize

TS = datetime(2026, 11, 16, 1, 2, 3, tzinfo=UTC)
DANGEROUS = set("\"'`$<>&;|%\\\r\n\t")


def alert(**kw: object) -> Alert:
    base: dict[str, object] = {
        "ts": TS,
        "gid": 1,
        "sid": 1000002,
        "rev": 1,
        "msg": "NIDS test - uid=0(root) response",
        "classification": None,
        "priority": 1,
        "proto": "TCP",
        "src_ip": "10.0.0.1",
        "src_port": 4444,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "raw": "raw",
    }
    base.update(kw)
    return Alert(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize("char", list("\"'`$<>&;|%\\"))
def test_sanitize_replaces_dangerous_characters(char: str) -> None:
    assert sanitize(f"a{char}b", 50) == "a b"


def test_sanitize_neutralises_injection_strings() -> None:
    for text in (
        '"; calc; "',
        "`whoami`",
        "$(calc)",
        "<b>x</b>",
        "a\r\nb\tc",
        "%PATH%",
        "'; rm -rf /",
    ):
        out = sanitize(text, 100)
        assert not set(out) & DANGEROUS, out


def test_sanitize_drops_control_and_format_characters() -> None:
    assert sanitize("a\x00b\x1bc\x7fd‮e​f\x85g", 50) == "a b c d e f g"


def test_sanitize_keeps_ordinary_and_non_ascii_text() -> None:
    text = "ET MALWARE Zażółć (CVE-2024-1) 10.0.0.1:80"
    assert sanitize(text, 100) == text


def test_sanitize_collapses_whitespace_and_caps_length() -> None:
    assert sanitize("  a   b  ", 50) == "a b"
    assert sanitize("x" * 10_000, 120) == "x" * 120
    assert sanitize("ab cd", 3) == "ab"  # no trailing space left behind


def test_build_toast_has_message_addresses_sid_and_time() -> None:
    toast = build_toast(alert())
    assert toast == Toast(
        "Snort P1: NIDS test - uid=0(root) response",
        ("TCP 10.0.0.1:4444 -> 10.0.0.2:80", "SID 1:1000002  01:02:03"),
    )


def test_missing_ports_are_omitted() -> None:
    toast = build_toast(alert(proto="ICMP", src_port=None, dst_port=None))
    assert toast.lines[0] == "ICMP 10.0.0.1 -> 10.0.0.2"


def test_time_is_shown_in_the_given_zone() -> None:
    zone = timezone(timedelta(hours=5, minutes=30))
    assert build_toast(alert(), tz=zone).lines[1] == "SID 1:1000002  06:32:03"


def test_suppressed_counts_add_lines_only_when_non_zero() -> None:
    assert len(build_toast(alert()).lines) == 2
    assert build_toast(alert(), same_sid=499).lines[-1] == "+499 more"
    toast = build_toast(alert(), same_sid=3, other=7)
    assert toast.lines[-2:] == ("+3 more", "+7 other alerts")
    assert build_toast(alert(), other=2).lines[-1] == "+2 other alerts"


def test_hostile_alert_text_is_sanitised_and_capped_everywhere() -> None:
    evil = '"; calc; `whoami` $(x) <b> & | % \\ \n' * 300
    toast = build_toast(alert(msg=evil, src_ip=evil, dst_ip=evil, proto=evil))
    assert len(toast.title) <= 80
    assert all(len(line) <= 120 for line in toast.lines)
    text = toast.title + "".join(toast.lines)
    assert not set(text) & (DANGEROUS - {">"})
    assert text.count(">") == 1  # only the arrow between the addresses
