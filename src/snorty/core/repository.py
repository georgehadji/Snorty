import sqlite3
import threading
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any

from snorty.core.models import Alert


def _alerts_table(name: str) -> str:
    # (raw, dup) is the idempotency key: re-reading Snort's file stores nothing twice, while two
    # alerts that print as the same line (same microsecond, same flow) are both kept.
    return f"""
CREATE TABLE IF NOT EXISTS {name} (
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
    raw TEXT NOT NULL,
    dup INTEGER NOT NULL DEFAULT 0,
    UNIQUE (raw, dup)
)"""


_INDEXES = """
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS alerts_sid ON alerts (sid);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
_SELECT = "id, "
_COLUMNS = (
    "ts, gid, sid, rev, msg, classification, priority, proto, "
    "src_ip, src_port, dst_ip, dst_port, raw"
)
_FLOOR = "prune_floor"  # meta key: nothing older than this is stored again
_VERSION = "schema_version"
TAIL_KEY = "tail"  # meta key: the ingest checkpoint (opaque text to the repository)


def _utc(dt: datetime) -> str:
    """UTC ISO-8601 with fixed width, so text order equals time order."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(UTC).isoformat(timespec="microseconds")


def _row(a: Alert) -> tuple[Any, ...]:
    return (
        _utc(a.ts), a.gid, a.sid, a.rev, a.msg, a.classification, a.priority, a.proto,
        a.src_ip, a.src_port, a.dst_ip, a.dst_port, a.raw, a.dup,
    )  # fmt: skip


def _alert(r: tuple[Any, ...]) -> Alert:
    alert = Alert(datetime.fromisoformat(r[1]).astimezone(), *r[2:])
    return replace(alert, id=r[0])


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


def _rebuild_with_dup(conn: sqlite3.Connection) -> None:
    """Databases from before `dup` held raw as UNIQUE, so identical alert lines collapsed into one
    row. SQLite cannot change a constraint in place: rebuild the table, keeping every row and id.
    The dropped alerts come back the next time Snort's file is read."""
    if "dup" in {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}:
        return
    conn.execute(_alerts_table("alerts_v2"))
    conn.execute(f"INSERT INTO alerts_v2 (id, {_COLUMNS}) SELECT id, {_COLUMNS} FROM alerts")
    conn.execute("DROP TABLE alerts")
    conn.execute("ALTER TABLE alerts_v2 RENAME TO alerts")


# Append only: a database's `schema_version` is how many of these it has had.
MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [_rebuild_with_dup]


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
            self._conn.execute(_alerts_table("alerts"))
            self._migrate()
            self._conn.executescript(_INDEXES)
            # rows stored before the parser mapped Snort's priority 0 to the lowest level
            self._conn.execute("UPDATE alerts SET priority = 3 WHERE priority = 0")

    def _migrate(self) -> None:
        """Run the MIGRATIONS this database has not had yet, each in its own transaction."""
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (_VERSION,)).fetchone()
        done = int(row[0]) if row else 0
        for n, step in enumerate(MIGRATIONS[done:], done + 1):
            self._conn.execute("BEGIN")
            try:
                step(self._conn)
                self._set_meta(_VERSION, str(n))
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def meta_get(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def add(self, alert: Alert) -> bool:
        """Store one alert; False if the same raw line is already stored."""
        return self.add_many([alert]) == 1

    def add_many(self, alerts: Iterable[Alert]) -> int:
        """Store alerts in one transaction; returns how many were new."""
        return len(self.add_new(alerts))

    def add_new(self, alerts: Iterable[Alert], checkpoint: str | None = None) -> list[Alert]:
        """Store alerts in one transaction; returns the ones that were new, in order.
        `checkpoint` (where the reader got to) is saved in the same transaction, so a crash never
        leaves rows without it or it without the rows."""
        sql = f"INSERT OR IGNORE INTO alerts ({_COLUMNS}, dup) VALUES ({', '.join('?' * 14)})"
        new: list[Alert] = []
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (_FLOOR,))
                floor = (row.fetchone() or ("",))[0]
                for alert in alerts:
                    if _utc(alert.ts) < floor:  # older than the last prune: not stored again
                        continue
                    cur = self._conn.execute(sql, _row(alert))
                    if cur.rowcount == 1:
                        new.append(replace(alert, id=cur.lastrowid or 0))
                if checkpoint is not None:
                    self._set_meta(TAIL_KEY, checkpoint)
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
        order = "ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        sql = f"SELECT {_SELECT}{_COLUMNS} FROM alerts{where} {order}"
        with self._lock:
            rows = self._conn.execute(sql, [*args, limit, offset]).fetchall()
        return [_alert(r) for r in rows]

    def get(self, alert_id: int) -> Alert | None:
        """One stored alert by its row id, or None."""
        sql = f"SELECT {_SELECT}{_COLUMNS} FROM alerts WHERE id = ?"
        with self._lock:
            row = self._conn.execute(sql, [alert_id]).fetchone()
        return _alert(row) if row else None

    def count(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        *,
        min_priority: int | None = None,
    ) -> int:
        """How many alerts are in the range; cheaper than summing counts_by_sid.
        min_priority=2 counts only priorities 1 and 2."""
        where, args = _range(since, until)
        if min_priority is not None:
            where += (" AND " if where else " WHERE ") + "priority <= ?"
            args.append(min_priority)
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
        # SQL folds the rows to one per minute (at most 60 per hour, however many alerts there
        # are); the zone-aware hour is worked out here, so 30- and 45-minute zones stay right.
        sql = f"SELECT substr(ts, 1, 16), COUNT(*) FROM alerts{where} GROUP BY 1"
        with self._lock:
            minutes = self._conn.execute(sql, args).fetchall()
        buckets: Counter[datetime] = Counter()
        for stamp, n in minutes:
            local = datetime.fromisoformat(f"{stamp}:00+00:00").astimezone(tz)
            # Key on the UTC instant so the repeated hour at a DST change stays two buckets.
            buckets[local.replace(minute=0, second=0, microsecond=0).astimezone(UTC)] += n
        return [(k.astimezone(tz), buckets[k]) for k in sorted(buckets)]

    def latest_msgs(self, sids: list[int], since: datetime | None = None) -> dict[int, str]:
        """The newest message seen for each sid, in one query."""
        if not sids:
            return {}
        where, args = _range(since, None)
        marks = ",".join("?" * len(sids))
        where += (" AND " if where else " WHERE ") + f"sid IN ({marks})"
        # SQLite returns the row holding MAX(ts) for the bare column `msg`.
        sql = f"SELECT sid, msg, MAX(ts) FROM alerts{where} GROUP BY sid"
        with self._lock:
            return {r[0]: r[1] for r in self._conn.execute(sql, [*args, *sids])}

    def prune(self, before: datetime) -> int:
        """Delete alerts strictly older than `before`; returns the number deleted. Later reads of
        Snort's file (which still holds them) do not bring them back."""
        cutoff = _utc(before)
        with self._lock:
            self._conn.execute("BEGIN")  # rows and floor together: a crash between them would
            try:  # let the deleted alerts be read back from Snort's file
                deleted = self._conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,)).rowcount
                self._conn.execute(
                    "INSERT INTO meta (key, value) VALUES (?, ?) "
                    "ON CONFLICT (key) DO UPDATE SET value = MAX(value, excluded.value)",
                    (_FLOOR, cutoff),
                )
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
            return deleted
