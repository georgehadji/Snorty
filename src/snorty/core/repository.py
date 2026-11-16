import sqlite3
import threading
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any

from snorty.core.models import Alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    rev INTEGER NOT NULL,
    msg TEXT NOT NULL,
    classification TEXT,
    priority INTEGER NOT NULL,
    proto TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    raw TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS alerts_sid ON alerts (sid);
"""
_COLUMNS = (
    "ts, gid, sid, rev, msg, classification, priority, proto, "
    "src_ip, src_port, dst_ip, dst_port, raw"
)


def _utc(dt: datetime) -> str:
    """UTC ISO-8601 with fixed width, so text order equals time order."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(UTC).isoformat(timespec="microseconds")


def _row(a: Alert) -> tuple[Any, ...]:
    return (
        _utc(a.ts), a.gid, a.sid, a.rev, a.msg, a.classification, a.priority, a.proto,
        a.src_ip, a.src_port, a.dst_ip, a.dst_port, a.raw,
    )  # fmt: skip


def _alert(r: tuple[Any, ...]) -> Alert:
    return Alert(datetime.fromisoformat(r[0]).astimezone(), *r[1:])


def _range(since: datetime | None, until: datetime | None) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    if since is not None:
        clauses.append("ts >= ?")
        args.append(_utc(since))
    if until is not None:
        clauses.append("ts < ?")
        args.append(_utc(until))
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), args


class AlertRepository:
    """SQLite alert store. Synchronous: async callers use asyncio.to_thread."""

    def __init__(self, path: Path | str) -> None:
        # check_same_thread=False plus a lock: to_thread may use any worker thread.
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA)
            # rows stored before the parser mapped Snort's priority 0 to the lowest level
            self._conn.execute("UPDATE alerts SET priority = 3 WHERE priority = 0")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def add(self, alert: Alert) -> bool:
        """Store one alert; False if the same raw line is already stored."""
        return self.add_many([alert]) == 1

    def add_many(self, alerts: Iterable[Alert]) -> int:
        """Store alerts in one transaction; returns how many were new."""
        return len(self.add_new(alerts))

    def add_new(self, alerts: Iterable[Alert]) -> list[Alert]:
        """Store alerts in one transaction; returns the ones that were new, in order."""
        sql = f"INSERT OR IGNORE INTO alerts ({_COLUMNS}) VALUES ({', '.join('?' * 13)})"
        new: list[Alert] = []
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                for alert in alerts:
                    if self._conn.execute(sql, _row(alert)).rowcount == 1:
                        new.append(alert)
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
        return new

    def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        sid: int | None = None,
        min_priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """Newest first. since is inclusive, until exclusive. min_priority=1 keeps
        only priority 1 (1 is the most severe)."""
        where, args = _range(since, until)
        extra: list[str] = []
        if sid is not None:
            extra.append("sid = ?")
            args.append(sid)
        if min_priority is not None:
            extra.append("priority <= ?")
            args.append(min_priority)
        if extra:
            where += (" AND " if where else " WHERE ") + " AND ".join(extra)
        sql = f"SELECT {_COLUMNS} FROM alerts{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        with self._lock:
            rows = self._conn.execute(sql, [*args, limit, offset]).fetchall()
        return [_alert(r) for r in rows]

    def count(self, since: datetime | None = None, until: datetime | None = None) -> int:
        """How many alerts are in the range; cheaper than summing counts_by_sid."""
        where, args = _range(since, until)
        with self._lock:
            row = self._conn.execute(f"SELECT COUNT(*) FROM alerts{where}", args).fetchone()
        return int(row[0])

    def counts_by_sid(
        self, since: datetime | None = None, until: datetime | None = None
    ) -> list[tuple[int, int]]:
        """(sid, count) pairs, most frequent first."""
        where, args = _range(since, until)
        sql = f"SELECT sid, COUNT(*) AS n FROM alerts{where} GROUP BY sid ORDER BY n DESC, sid"
        with self._lock:
            return [(r[0], r[1]) for r in self._conn.execute(sql, args)]

    def counts_by_hour(
        self, since: datetime | None = None, until: datetime | None = None, *, tz: tzinfo
    ) -> list[tuple[datetime, int]]:
        """(hour start in tz, count) pairs in time order. Hours with no alerts are omitted."""
        where, args = _range(since, until)
        with self._lock:
            stamps = [r[0] for r in self._conn.execute(f"SELECT ts FROM alerts{where}", args)]
        buckets: Counter[datetime] = Counter()
        for s in stamps:
            local = datetime.fromisoformat(s).astimezone(tz)
            # Key on the UTC instant so the repeated hour at a DST change stays two buckets.
            buckets[local.replace(minute=0, second=0, microsecond=0).astimezone(UTC)] += 1
        return [(k.astimezone(tz), buckets[k]) for k in sorted(buckets)]

    def prune(self, before: datetime) -> int:
        """Delete alerts strictly older than `before`; returns the number deleted."""
        with self._lock:
            return self._conn.execute("DELETE FROM alerts WHERE ts < ?", (_utc(before),)).rowcount
