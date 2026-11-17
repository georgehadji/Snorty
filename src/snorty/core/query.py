"""Which alerts a view or a subscriber wants: one object with an SQL form and an in-memory form,
so the stored table and the live stream cannot disagree about what a filter means."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from snorty.core.models import Alert

TEXT_MAX = 200
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def like_escape(text: str) -> str:
    """`text` as a literal inside a LIKE pattern written with ESCAPE '\\'."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like_pattern(text: str) -> str:
    return f"%{like_escape(text)}%"


def _contains(haystack: str, needle: str) -> bool:
    """SQLite's LIKE: case-insensitive for ASCII letters only, so both forms agree."""
    return needle.translate(_ASCII_LOWER) in haystack.translate(_ASCII_LOWER)


def utc_text(dt: datetime) -> str:
    """UTC ISO-8601 with fixed width, so text order equals time order."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True, slots=True)
class AlertQuery:
    """Every field left as None matches everything. `since` is inclusive, `until` exclusive,
    and `min_priority=1` keeps only priority 1 (1 is the most severe). `text` matches a rule
    message containing it, or an alert whose source or destination is exactly it."""

    since: datetime | None = None
    until: datetime | None = None
    sid: int | None = None
    min_priority: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    text: str | None = None

    def to_sql(self) -> tuple[str, list[Any]]:
        """(" WHERE ..." or "", arguments)."""
        clauses: list[str] = []
        args: list[Any] = []
        if self.since is not None:
            clauses.append("ts >= ?")
            args.append(utc_text(self.since))
        if self.until is not None:
            clauses.append("ts < ?")
            args.append(utc_text(self.until))
        for column, value in (
            ("sid", self.sid),
            ("src_ip", self.src_ip),
            ("dst_ip", self.dst_ip),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                args.append(value)
        if self.min_priority is not None:
            clauses.append("priority <= ?")
            args.append(self.min_priority)
        if self.text is not None:
            clauses.append("(msg LIKE ? ESCAPE '\\' OR src_ip = ? OR dst_ip = ?)")
            args += [_like_pattern(self.text), self.text, self.text]
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), args

    def matches(self, a: Alert) -> bool:
        return (
            (self.since is None or a.ts >= self.since)
            and (self.until is None or a.ts < self.until)
            and (self.sid is None or a.sid == self.sid)
            and (self.min_priority is None or a.priority <= self.min_priority)
            and (self.src_ip is None or a.src_ip == self.src_ip)
            and (self.dst_ip is None or a.dst_ip == self.dst_ip)
            and (
                self.text is None
                or _contains(a.msg, self.text)
                or self.text in (a.src_ip, a.dst_ip)
            )
        )
