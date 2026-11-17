import re
from datetime import UTC, date, datetime, timedelta, timezone

import pytest

from snorty.core.models import Alert
from snorty.journal.render import BEGIN, END, render, sanitize_cell

DAY = date(2026, 11, 16)


def alert(
    sid: int = 1,
    priority: int = 1,
    hour: int = 10,
    minute: int = 0,
    msg: str | None = None,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_port: int | None = 4444,
    dst_port: int | None = 80,
    second: int = 0,
) -> Alert:
    return Alert(
        ts=datetime(2026, 11, 16, hour, minute, second, tzinfo=UTC),
        gid=1,
        sid=sid,
        rev=1,
        msg=msg if msg is not None else f"rule {sid}",
        classification=None,
        priority=priority,
        proto="TCP",
        src_ip=src,
        src_port=src_port,
        dst_ip=dst,
        dst_port=dst_port,
        raw=f"{sid}-{hour}-{minute}-{second}-{src}-{msg}",
    )


GOLDEN = f"""{BEGIN}
## Snort alerts

3 alerts · P1 2 · P2 1 · last alert 12:30

### Top rules
| SID | Message | Count |
|---|---|---|
| 7 | seven | 2 |
| 9 | nine | 1 |

### Top addresses
**Sources**
| Address | Count |
|---|---|
| 10.0.0.1 | 2 |
| 10.0.0.5 | 1 |

**Destinations**
| Address | Count |
|---|---|
| 10.0.0.2 | 3 |

### By hour
| Hour | Alerts |
|---|---|
| 00 | 0 |
| 01 | 0 |
| 02 | 0 |
| 03 | 0 |
| 04 | 0 |
| 05 | 0 |
| 06 | 0 |
| 07 | 0 |
| 08 | 0 |
| 09 | 0 |
| 10 | 1 |
| 11 | 0 |
| 12 | 2 |
| 13 | 0 |
| 14 | 0 |
| 15 | 0 |
| 16 | 0 |
| 17 | 0 |
| 18 | 0 |
| 19 | 0 |
| 20 | 0 |
| 21 | 0 |
| 22 | 0 |
| 23 | 0 |

### Priority 1 alerts
| Time | SID | Message | Source → Destination |
|---|---|---|---|
| 12:30:00 | 7 | seven | 10.0.0.1:4444 → 10.0.0.2:80 |
| 10:00:00 | 7 | seven | 10.0.0.1:4444 → 10.0.0.2:80 |
{END}
"""


def test_golden_note_for_a_fixed_alert_set() -> None:
    alerts = [
        alert(sid=7, hour=10, msg="seven"),
        alert(sid=9, priority=2, hour=12, minute=0, msg="nine", src="10.0.0.5"),
        alert(sid=7, hour=12, minute=30, msg="seven"),
    ]
    assert render(DAY, alerts, UTC) == GOLDEN


def test_render_is_deterministic_and_ignores_input_order() -> None:
    alerts = [alert(sid=s, hour=h, msg=f"m{s}") for s, h in ((1, 3), (2, 5), (3, 9), (4, 11))]
    assert render(DAY, alerts, UTC) == render(DAY, list(reversed(alerts)), UTC)


def test_empty_day() -> None:
    out = render(DAY, [], UTC)
    assert "0 alerts" in out
    assert "None." in out
    assert out.startswith(BEGIN) and out.rstrip().endswith(END)


def test_priority_one_table_is_cut_at_fifty_with_a_more_line() -> None:
    alerts = [alert(sid=s, minute=s % 60, second=s // 60) for s in range(1, 61)]
    out = render(DAY, alerts, UTC)
    section = out.split("### Priority 1 alerts")[1]
    rows = [ln for ln in section.splitlines() if re.match(r"\| \d\d:\d\d:\d\d", ln)]
    assert len(rows) == 50
    assert "…and 10 more" in section


def test_ties_are_ordered_by_key() -> None:
    alerts = [alert(sid=20, msg="b"), alert(sid=10, msg="a")]
    out = render(DAY, alerts, UTC)
    assert out.index("| 10 | a | 1 |") < out.index("| 20 | b | 1 |")


def test_top_lists_hold_ten_entries() -> None:
    alerts = [alert(sid=s, src=f"10.0.1.{s}") for s in range(1, 16)]
    out = render(DAY, alerts, UTC)
    rules = out.split("### Top rules")[1].split("###")[0]
    assert len(re.findall(r"^\| \d+ \|", rules, re.M)) == 10


def test_hour_buckets_use_the_local_zone() -> None:
    tz = timezone(timedelta(hours=2))
    a = [alert(hour=21, minute=59), alert(hour=22, minute=1)]  # 23:59 and 00:01 local
    out = render(DAY, a, tz)
    assert "| 23 | 1 |" in out and "| 00 | 1 |" in out
    assert "last alert 00:01" in out


def test_missing_ports_are_omitted() -> None:
    out = render(DAY, [alert(src_port=None, dst_port=None)], UTC)
    assert "10.0.0.1 → 10.0.0.2 |" in out


def test_total_above_shown_adds_a_truncation_line() -> None:
    out = render(DAY, [alert()], UTC, total=5)
    assert "5 alerts" in out
    assert "truncated: 4 alerts not shown in tables" in out


def test_no_truncation_line_when_everything_is_shown() -> None:
    assert "truncated" not in render(DAY, [alert()], UTC, total=1)


@pytest.mark.parametrize(
    "text",
    [
        "a | b",
        "[[Secret note]]",
        "`code`",
        "#tag and #other",
        "%% hidden %%",
        "<b>x</b><!-- c -->",
        "line1\nline2\r\n| x |",
        "tab\there",
        f"{END}",
        f"{BEGIN}",
        "back\\slash",
        "![[img.png]]",
    ],
)
def test_sanitize_cell_neutralises_markdown_hazards(text: str) -> None:
    out = sanitize_cell(text)
    assert not set(out) & set("|[]`<>\\\n\r\t")
    assert "%%" not in out and "<!--" not in out
    assert not re.search(r"(^|\s)#", out)


def test_sanitize_cell_caps_and_keeps_non_ascii() -> None:
    assert len(sanitize_cell("x" * 10_000)) == 120
    assert sanitize_cell("café → naïve") == "café → naïve"
    assert sanitize_cell("a   b") == "a b"


def test_first_seen_section_lists_the_day_newest_first_and_says_how_many_more() -> None:
    t = datetime(2026, 11, 16, 9, 30, tzinfo=UTC)
    seen = [("dns", "a.example", t), ("country", "Germany", t + timedelta(hours=1))]
    text = render(DAY, [], UTC, first_seen=seen, first_seen_total=60)
    part = text[text.index("### First seen") :]
    assert part.index("Germany") < part.index("a.example")
    assert "| 10:30 | Country | Germany |" in part and "…and 58 more" in part
    assert "### First seen" not in render(DAY, [], UTC)  # nothing new: no section
    hostile = render(DAY, [], UTC, first_seen=[("dns", "x|[[y]]", t)], first_seen_total=1)
    assert "x|" not in hostile and "[[" not in hostile


def test_hostile_message_cannot_break_out_of_the_block() -> None:
    evil = f"x | y\n{END}\n## hijack [[Daily]] #tag %% c %%"
    out = render(DAY, [alert(msg=evil)], UTC)
    assert out.count(END) == 1 and out.count(BEGIN) == 1
    for line in out.splitlines():
        if line.startswith("| 1 |"):
            assert line.count("|") == 4  # SID, message, count: no extra column
    assert "[[" not in out and "%%" not in out
