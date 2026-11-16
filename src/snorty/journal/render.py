"""Pure rendering of a day's alerts into the managed Markdown block."""

import re
import unicodedata
from collections import Counter
from collections.abc import Sequence
from datetime import date, tzinfo

from snorty.core.models import Alert

BEGIN = "<!-- snorty:begin — generated; edit outside these markers -->"
END = "<!-- snorty:end -->"

CELL_LIMIT = 120
TOP_N = 10
P1_ROWS = 50

_HAZARDS = str.maketrans({c: " " for c in "|[]`<>\\"})
_WORD_HASH = re.compile(r"(?<!\S)#+")


def sanitize_cell(text: str, limit: int = CELL_LIMIT) -> str:
    """Make third-party text safe inside a Markdown table cell of ours.

    Removes anything that could add a column, link, tag, comment, HTML or one of our
    marker lines, collapses whitespace and caps the length."""
    text = "".join(
        " " if unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp") else c
        for c in text
    )
    text = text.translate(_HAZARDS).replace("%%", " ")
    text = _WORD_HASH.sub("", text)
    return " ".join(text.split())[:limit]


def _endpoint(ip: str, port: int | None) -> str:
    return sanitize_cell(ip if port is None else f"{ip}:{port}")


def _top[K: (int, str)](counts: Counter[K]) -> list[tuple[K, int]]:
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_N]


def render(day: date, alerts: Sequence[Alert], tz: tzinfo, total: int | None = None) -> str:
    """The managed block for `day`. Same alerts give the same text, in any order.

    `total` is the true alert count when `alerts` is a truncated page of the day."""
    ordered = sorted(alerts, key=lambda a: (a.ts, a.raw), reverse=True)
    shown = len(ordered)
    count = shown if total is None else max(total, shown)

    by_priority = Counter(a.priority for a in ordered)
    summary = " · ".join(
        [f"{count} alerts", *(f"P{p} {n}" for p, n in sorted(by_priority.items()))]
    )
    if ordered:
        summary += f" · last alert {ordered[0].ts.astimezone(tz):%H:%M}"

    out = [BEGIN, "## Snort alerts", "", summary]
    if count > shown:
        out.append(f"truncated: {count - shown} alerts not shown in tables")

    newest_msg: dict[int, str] = {}
    for a in ordered:  # newest first, so setdefault keeps the newest message per rule
        newest_msg.setdefault(a.sid, a.msg)
    out += ["", "### Top rules", "| SID | Message | Count |", "|---|---|---|"]
    for sid, n in _top(Counter(a.sid for a in ordered)):
        out.append(f"| {sid} | {sanitize_cell(newest_msg[sid])} | {n} |")

    out += ["", "### Top addresses"]
    for label, ips in (
        ("Sources", Counter(a.src_ip for a in ordered)),
        ("Destinations", Counter(a.dst_ip for a in ordered)),
    ):
        out += [f"**{label}**", "| Address | Count |", "|---|---|"]
        out += [f"| {sanitize_cell(ip)} | {n} |" for ip, n in _top(ips)]
        if label == "Sources":
            out.append("")

    hours = Counter(a.ts.astimezone(tz).hour for a in ordered)
    out += ["", "### By hour", "| Hour | Alerts |", "|---|---|"]
    out += [f"| {h:02d} | {hours[h]} |" for h in range(24)]

    p1 = [a for a in ordered if a.priority == 1]
    out += ["", "### Priority 1 alerts"]
    if not p1:
        out.append("None.")
    else:
        out += ["| Time | SID | Message | Source → Destination |", "|---|---|---|---|"]
        for a in p1[:P1_ROWS]:
            route = f"{_endpoint(a.src_ip, a.src_port)} → {_endpoint(a.dst_ip, a.dst_port)}"
            out.append(
                f"| {a.ts.astimezone(tz):%H:%M:%S} | {a.sid} | {sanitize_cell(a.msg)} | {route} |"
            )
        if len(p1) > P1_ROWS:
            out += ["", f"…and {len(p1) - P1_ROWS} more"]
    out.append(END)
    return "\n".join(out) + "\n"
