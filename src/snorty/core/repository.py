import sqlite3
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any, Literal

from snorty.core.models import Alert, Block
from snorty.core.query import AlertQuery, utc_text
from snorty.core.triage import STATES, ArchiveRule, TriageState, spec_from_json, spec_to_json


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


def _row(a: Alert) -> tuple[Any, ...]:
    return (
        utc_text(a.ts), a.gid, a.sid, a.rev, a.msg, a.classification, a.priority, a.proto,
        a.src_ip, a.src_port, a.dst_ip, a.dst_port, a.raw, a.dup,
    )  # fmt: skip


def _alert(r: tuple[Any, ...]) -> Alert:
    alert = Alert(datetime.fromisoformat(r[1]).astimezone(), *r[2:])
    return replace(alert, id=r[0])


def _range(since: datetime | None, until: datetime | None) -> tuple[str, list[Any]]:
    return AlertQuery(since, until).to_sql()


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


def _index_hosts(conn: sqlite3.Connection) -> None:
    """Group-by and per-host filters read alerts by address."""
    conn.execute("CREATE INDEX IF NOT EXISTS alerts_src ON alerts (src_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS alerts_dst ON alerts (dst_ip)")


def _add_triage(conn: sqlite3.Connection) -> None:
    """No triage row means the alert is new, so storing an alert stays a plain insert."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS triage ("
        "alert_id INTEGER PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE, "
        "state TEXT NOT NULL, changed TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS archive_rules ("
        "id INTEGER PRIMARY KEY, spec TEXT NOT NULL, note TEXT NOT NULL, created TEXT NOT NULL)"
    )


def _add_annotations(conn: sqlite3.Connection) -> None:
    """Facts learned about an alert after it was stored: owning process, country, name..."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS annotations ("
        "alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE, "
        "kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (alert_id, kind))"
    )


def _add_blocks(conn: sqlite3.Connection) -> None:
    """Addresses blocked in the firewall, so every block can be listed and reversed."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocks ("
        "ip TEXT PRIMARY KEY, created TEXT NOT NULL, until TEXT, alert_id INTEGER, "
        "state TEXT NOT NULL)"
    )


# Append only: a database's `schema_version` is how many of these it has had.
MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [
    _rebuild_with_dup,
    _index_hosts,
    _add_triage,
    _add_annotations,
    _add_blocks,
]


def _with_states(q: AlertQuery, states: Sequence[TriageState] | None) -> tuple[str, str, list[Any]]:
    """(table expression, WHERE, arguments); joins the triage table only when states are asked."""
    where, args = q.to_sql()
    if states is None:
        return "alerts", where, args
    marks = ",".join("?" * len(states))
    clause = f"COALESCE(triage.state, 'new') IN ({marks})"
    where += (" AND " if where else " WHERE ") + clause
    return "alerts LEFT JOIN triage ON triage.alert_id = alerts.id", where, [*args, *states]


type GroupBy = Literal["sid", "src_ip", "dst_ip"]


@dataclass(frozen=True, slots=True)
class Group:
    key: str  # the SID, or the address, the alerts share
    count: int
    first_ts: datetime
    last_ts: datetime
    msg: str  # message of the newest alert in the group


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
            self._conn.execute("PRAGMA foreign_keys=ON")  # pruned alerts take their triage
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
                    if utc_text(alert.ts) < floor:  # older than the last prune: not stored again
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
        src_ip: str | None = None,
        dst_ip: str | None = None,
        states: Sequence[TriageState] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """Newest first. since is inclusive, until exclusive. min_priority=1 keeps
        only priority 1 (1 is the most severe)."""
        q = AlertQuery(since, until, sid, min_priority, src_ip, dst_ip)
        source, where, args = _with_states(q, states)
        order = "ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        sql = f"SELECT {_SELECT}{_COLUMNS} FROM {source}{where} {order}"
        with self._lock:
            rows = self._conn.execute(sql, [*args, limit, offset]).fetchall()
        return [_alert(r) for r in rows]

    def group(
        self,
        q: AlertQuery,
        by: GroupBy,
        limit: int = 200,
        states: Sequence[TriageState] | None = None,
    ) -> list[Group]:
        """Alerts matching `q` counted per rule, source or destination, most frequent first.
        `msg` is the newest alert's message."""
        source, where, args = _with_states(q, states)
        column = {"sid": "sid", "src_ip": "src_ip", "dst_ip": "dst_ip"}[by]  # never user text
        sql = (
            f"SELECT {column}, COUNT(*) AS n, MIN(ts), MAX(ts), msg FROM {source}{where} "
            f"GROUP BY {column} ORDER BY n DESC, {column} LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, [*args, limit]).fetchall()
        return [
            Group(str(r[0]), r[1], datetime.fromisoformat(r[2]), datetime.fromisoformat(r[3]), r[4])
            for r in rows
        ]

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

    def set_state(
        self, q: AlertQuery, state: TriageState, now: datetime, *, only_new: bool = False
    ) -> int:
        """Set the triage state of every alert matching `q`; returns how many changed.
        `only_new` leaves alerts someone already triaged alone."""
        where, args = q.to_sql()
        with self._lock:
            if state == "new":
                sql = f"DELETE FROM triage WHERE alert_id IN (SELECT id FROM alerts{where})"
                return self._conn.execute(sql, args).rowcount
            guard = " AND id NOT IN (SELECT alert_id FROM triage)" if only_new else ""
            sql = (
                f"INSERT INTO triage (alert_id, state, changed) SELECT id, ?, ? FROM alerts"
                f"{where or ' WHERE 1'}{guard} "
                "ON CONFLICT (alert_id) DO UPDATE SET state = excluded.state, "
                "changed = excluded.changed"
            )
            return self._conn.execute(sql, [state, utc_text(now), *args]).rowcount

    def counts_by_state(self, q: AlertQuery) -> dict[TriageState, int]:
        source, where, args = _with_states(q, STATES)
        sql = f"SELECT COALESCE(triage.state, 'new'), COUNT(*) FROM {source}{where} GROUP BY 1"
        with self._lock:
            found = dict(self._conn.execute(sql, args).fetchall())
        return {s: found.get(s, 0) for s in STATES}

    def add_archive_rule(self, spec: AlertQuery, note: str, now: datetime) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO archive_rules (spec, note, created) VALUES (?, ?, ?)",
                (spec_to_json(spec), note, utc_text(now)),
            )
            return cur.lastrowid or 0

    def archive_rules(self) -> list[ArchiveRule]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, spec, note, created FROM archive_rules ORDER BY id"
            ).fetchall()
        return [
            ArchiveRule(spec_from_json(r[1]), r[2], datetime.fromisoformat(r[3]), r[0])
            for r in rows
        ]

    def delete_archive_rule(self, rule_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM archive_rules WHERE id = ?", (rule_id,))
            return cur.rowcount == 1

    def apply_archive_rules(self, now: datetime) -> int:
        """Acknowledge new alerts that match an archive rule; returns how many."""
        return sum(self.set_state(r.spec, "ack", now, only_new=True) for r in self.archive_rules())

    def annotate(self, alert_id: int, kind: str, value: str) -> None:
        """Remember a fact about an alert; a later one of the same kind replaces it. An alert that
        was pruned meanwhile is skipped."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO annotations (alert_id, kind, value) "
                "SELECT id, ?, ? FROM alerts WHERE id = ? "
                "ON CONFLICT (alert_id, kind) DO UPDATE SET value = excluded.value",
                (kind, value, alert_id),
            )

    def annotations(self, alert_id: int) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, value FROM annotations WHERE alert_id = ?", (alert_id,)
            ).fetchall()
        return {k: v for k, v in rows}

    def put_block(self, block: Block) -> None:
        """Record a block; blocking an address again replaces its earlier row."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO blocks (ip, created, until, alert_id, state) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (ip) DO UPDATE SET created = excluded.created, "
                "until = excluded.until, alert_id = excluded.alert_id, state = excluded.state",
                (
                    block.ip,
                    utc_text(block.created),
                    utc_text(block.until) if block.until else None,
                    block.alert_id,
                    block.state,
                ),
            )

    def blocks(self, state: str | None = None) -> list[Block]:
        sql = "SELECT ip, created, until, alert_id, state FROM blocks"
        with self._lock:
            rows = self._conn.execute(
                sql + (" WHERE state = ?" if state else "") + " ORDER BY created DESC",
                (state,) if state else (),
            ).fetchall()
        return [
            Block(
                r[0],
                datetime.fromisoformat(r[1]),
                datetime.fromisoformat(r[2]) if r[2] else None,
                r[3],
                r[4],
            )
            for r in rows
        ]

    def set_block_state(self, ip: str, state: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE blocks SET state = ? WHERE ip = ?", (state, ip))

    def prune(self, before: datetime) -> int:
        """Delete alerts strictly older than `before`; returns the number deleted. Later reads of
        Snort's file (which still holds them) do not bring them back."""
        cutoff = utc_text(before)
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
