"""Turning an alert into toast text. Pure: no I/O.

Alert messages come from third-party rule files and the toast library builds a script
around them, so every field is sanitised here, before any adapter sees it.
"""

import unicodedata
from dataclasses import dataclass
from datetime import UTC, tzinfo

from snorty.core.models import Alert

# Quotes, backtick, `$`, angle brackets, `&`, `;`, `|`, `%` and backslash: the characters
# that matter to PowerShell, XML and cmd.
_BLOCKED = frozenset("\"'`$<>&;|%\\")
TITLE_LIMIT = 80
LINE_LIMIT = 120


@dataclass(frozen=True, slots=True)
class Toast:
    title: str
    lines: tuple[str, ...]


def _clean(ch: str) -> str:
    category = unicodedata.category(ch)
    if ch in _BLOCKED or category[0] == "C" or category in ("Zl", "Zp"):
        return " "
    return ch


def sanitize(text: str, limit: int) -> str:
    """Printable text only, whitespace collapsed, at most `limit` characters."""
    cleaned = " ".join("".join(_clean(c) for c in text).split())
    return cleaned[:limit].rstrip()


def _endpoint(ip: str, port: int | None) -> str:
    return sanitize(ip, 45) if port is None else f"{sanitize(ip, 45)}:{port}"


def build_toast(alert: Alert, same_sid: int = 0, other: int = 0, tz: tzinfo = UTC) -> Toast:
    title = sanitize(f"Snort P{alert.priority}: {alert.msg}", TITLE_LIMIT)
    flow = (
        f"{sanitize(alert.proto, 10)} {_endpoint(alert.src_ip, alert.src_port)}"
        f" -> {_endpoint(alert.dst_ip, alert.dst_port)}"
    )
    lines = [
        flow[:LINE_LIMIT],
        f"SID {alert.gid}:{alert.sid}  {alert.ts.astimezone(tz):%H:%M:%S}",
    ]
    if same_sid:
        lines.append(f"+{same_sid} more")
    if other:
        lines.append(f"+{other} other alerts")
    return Toast(title, tuple(lines))
