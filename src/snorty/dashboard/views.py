"""Pure view-models: turn domain objects into plain values the templates print."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from urllib.parse import urlencode

from snorty.core.models import Alert
from snorty.dashboard.security import valid_priority, valid_range, valid_sid
from snorty.journal.service import JournalStatus
from snorty.lab.models import LabResult
from snorty.notify.service import NotifyStatus
from snorty.rules.service import EditReport, UpdateReport
from snorty.rules.state import RulesState
from snorty.sensor import SensorStatus, State

MSG_MAX = 120
PAGE_SIZE = 50
MAX_PAGE = 10_000
MAX_LAB_ROWS = (
    500  # a lab run can match hundreds of thousands of packets; the hit counts stay exact
)
_RANGE_DELTA = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "all": None,
}


@dataclass(frozen=True, slots=True)
class AlertFilters:
    sid: int | None
    priority: int | None  # shows priorities up to this number (1 = most severe only)
    range: str
    page: int

    def since(self, now: datetime) -> datetime | None:
        delta = _RANGE_DELTA[self.range]
        return now - delta if delta else None

    def query_string(self, page: int) -> str:
        params: dict[str, str | int] = {}
        if self.sid is not None:
            params["sid"] = self.sid
        if self.priority is not None:
            params["priority"] = self.priority
        params["range"] = self.range
        params["page"] = page
        return urlencode(params)


def alert_matches(f: AlertFilters, a: Alert) -> bool:
    """Whether a live alert belongs in a table filtered by `f` (range and page do not apply)."""
    return (f.sid is None or a.sid == f.sid) and (f.priority is None or a.priority <= f.priority)


def parse_alert_filters(params: Mapping[str, str]) -> AlertFilters:
    """Blank or missing values mean the default. Raises ValueError with a user-safe message."""
    sid = params.get("sid", "")
    priority = params.get("priority", "")
    page = params.get("page", "")
    if page and not (page.isascii() and page.isdigit() and 0 < int(page) <= MAX_PAGE):
        raise ValueError(f"page must be a whole number from 1 to {MAX_PAGE}")
    return AlertFilters(
        sid=valid_sid(sid) if sid else None,
        priority=valid_priority(priority) if priority else None,
        range=valid_range(params.get("range") or "24h"),
        page=int(page) if page else 1,
    )


_TONE = {
    State.STOPPED: "idle",
    State.STARTING: "warn",
    State.RUNNING: "ok",
    State.STOPPING: "warn",
    State.FAILED: "bad",
}


def fmt_time(ts: datetime, tz: tzinfo) -> str:
    return ts.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")


def endpoint(ip: str, port: int | None) -> str:
    host = f"[{ip}]" if ":" in ip and port is not None else ip
    return host if port is None else f"{host}:{port}"


@dataclass(frozen=True, slots=True)
class AlertRow:
    sid: int
    time: str
    priority: int
    msg: str  # full text, for a tooltip
    msg_short: str
    proto: str
    src: str
    dst: str
    classification: str
    iso: str = ""  # UTC timestamp, for relative time in the browser
    epoch: int = 0  # the same moment in seconds, for merging live alerts into a group
    key: str = ""  # alerts with the same key are the same repeating event
    count: int = 1  # how many alerts this row stands for
    first_time: str = ""  # time of the oldest alert in a group


def alert_row(a: Alert, tz: tzinfo) -> AlertRow:
    short = a.msg if len(a.msg) <= MSG_MAX else a.msg[: MSG_MAX - 1] + "…"
    return AlertRow(
        sid=a.sid,
        time=fmt_time(a.ts, tz),
        priority=a.priority,
        msg=a.msg,
        msg_short=short,
        proto=a.proto,
        src=endpoint(a.src_ip, a.src_port),
        dst=endpoint(a.dst_ip, a.dst_port),
        classification=a.classification or "",
        iso=a.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        epoch=int(a.ts.timestamp()),
        key=f"{a.sid}|{endpoint(a.src_ip, a.src_port)}|{endpoint(a.dst_ip, a.dst_port)}",
    )


GROUP_GAP = timedelta(minutes=15)


def group_rows(alerts: list[Alert], tz: tzinfo) -> list[AlertRow]:
    """Newest-first alerts to rows; neighbours that repeat the same event become one row."""
    rows: list[AlertRow] = []
    last: Alert | None = None  # the oldest alert folded into rows[-1] so far
    for a in alerts:
        row = alert_row(a, tz)
        prev = rows[-1] if rows else None
        if prev and last and prev.key == row.key and last.ts - a.ts <= GROUP_GAP:
            rows[-1] = replace(prev, count=prev.count + 1, first_time=row.time)
        else:
            rows.append(row)
        last = a
    return rows


@dataclass(frozen=True, slots=True)
class SensorCard:
    state: str
    tone: str
    since: str | None
    interface: str | None
    restarts: int
    alerts_seen: int
    last_alert: str | None
    error: str | None
    can_start: bool
    can_stop: bool
    can_restart: bool


def sensor_card(st: SensorStatus, tz: tzinfo) -> SensorCard:
    iface = st.interface
    where = None
    if iface is not None:
        where = f"{iface.description} ({iface.ip})" if iface.ip else iface.description
    return SensorCard(
        state=st.state.value,
        tone=_TONE[st.state],
        since=fmt_time(st.started_at, tz) if st.started_at else None,
        interface=where,
        restarts=st.restarts,
        alerts_seen=st.alerts_seen,
        last_alert=fmt_time(st.last_alert_ts, tz) if st.last_alert_ts else None,
        error=st.last_error,
        can_start=st.state in (State.STOPPED, State.FAILED),
        can_stop=st.state in (State.STARTING, State.RUNNING, State.FAILED),
        can_restart=st.state is State.RUNNING,
    )


@dataclass(frozen=True, slots=True)
class RulesSummary:
    updated: str
    count: str
    result: str


def rules_summary(state: RulesState) -> RulesSummary:
    return RulesSummary(
        updated=state.updated_at[:19].replace("T", " ") if state.updated_at else "never",
        count=str(state.rule_count) if state.rule_count is not None else "unknown",
        result=state.result or "",
    )


@dataclass(frozen=True, slots=True)
class Message:
    ok: bool
    text: str


def edit_message(report: EditReport, *, sensor_was_running: bool) -> Message:
    """Say what a mute, unmute or HOME_NET change did, including whether Snort was restarted."""
    if not report.ok:
        return Message(False, f"Failed: {report.detail}")
    if not report.changed:
        return Message(True, "Nothing to change.")
    tail = (
        "The sensor was restarted to load it."
        if sensor_was_running
        else "It takes effect the next time the sensor starts."
    )
    return Message(True, f"Done: {report.detail}. {tail}")


def update_message(report: UpdateReport) -> Message:
    if report.outcome == "failed":
        return Message(False, f"Update failed: {report.detail}")
    if report.outcome == "up_to_date":
        return Message(True, f"Already up to date: {report.detail}")
    return Message(True, f"Updated: {report.detail}. Restart the sensor to load the new rules.")


@dataclass(frozen=True, slots=True)
class JournalView:
    folder: str
    last_written: str  # "never" until the first note is written
    notes_written: int
    error: str | None


def journal_view(status: JournalStatus, tz: tzinfo) -> JournalView:
    last = fmt_time(status.last_written, tz) if status.last_written else "never"
    return JournalView(status.folder, last, status.notes_written, status.error)


@dataclass(frozen=True, slots=True)
class NotifyView:
    toasts_shown: int
    threshold: str  # which alerts raise a toast


def notify_view(status: NotifyStatus) -> NotifyView:
    p = status.min_priority
    return NotifyView(status.toasts_shown, "priority 1 only" if p <= 1 else f"priority 1 to {p}")


@dataclass(frozen=True, slots=True)
class LabView:
    ok: bool
    problems: list[str]
    error: str | None
    hits: list[tuple[int, str, int, int]]  # sid, msg, rule line, count
    matches: list[AlertRow]  # at most MAX_LAB_ROWS
    matches_total: int


def lab_view(result: LabResult, tz: tzinfo) -> LabView:
    problems = [
        f"rule line {p.line}: {p.message}" if p.line else p.message for p in result.problems
    ]
    hits = [(h.sid, h.msg, h.line, h.count) for h in result.hits]
    shown = [alert_row(a, tz) for a in result.matches[:MAX_LAB_ROWS]]
    return LabView(result.ok, problems, result.error, hits, shown, len(result.matches))
