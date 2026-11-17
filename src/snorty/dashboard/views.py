"""Pure view-models: turn domain objects into plain values the templates print."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Literal
from urllib.parse import urlencode

from snorty.core.models import Alert
from snorty.core.query import AlertQuery
from snorty.core.repository import Group, GroupBy
from snorty.dashboard.security import (
    valid_group,
    valid_ip,
    valid_priority,
    valid_range,
    valid_search,
    valid_sid,
)
from snorty.journal.service import JournalStatus
from snorty.lab.models import LabResult
from snorty.notify.service import NotifyStatus
from snorty.packets import (
    AlertPacket,
    AlertPacketResult,
    Conversation,
    Decoded,
    DecodeResult,
    Failed,
    NotFound,
    PacketView,
    ProtocolRow,
    Summary,
    SummaryResult,
    Unavailable,
    alert_filter,
    conversation_filter,
    hint,
)
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
    src: str | None = None  # only alerts from this address
    dst: str | None = None
    group: GroupBy | None = None  # count alerts per rule, source or destination instead
    text: str | None = None  # in the rule message, or an exact source or destination address

    def since(self, now: datetime) -> datetime | None:
        delta = _RANGE_DELTA[self.range]
        return now - delta if delta else None

    def ungrouped_query(self) -> str:
        return replace(self, group=None).query_string(1)

    def to_query(self, now: datetime | None) -> AlertQuery:
        """What this view shows; without `now` the range is left out (a live alert is new)."""
        return AlertQuery(
            since=self.since(now) if now else None,
            sid=self.sid,
            min_priority=self.priority,
            src_ip=self.src,
            dst_ip=self.dst,
            text=self.text,
        )

    def query_string(self, page: int) -> str:
        params: dict[str, str | int] = {}
        if self.text is not None:
            params["q"] = self.text
        if self.sid is not None:
            params["sid"] = self.sid
        if self.priority is not None:
            params["priority"] = self.priority
        if self.src is not None:
            params["src"] = self.src
        if self.dst is not None:
            params["dst"] = self.dst
        if self.group is not None:
            params["group"] = self.group
        params["range"] = self.range
        params["page"] = page
        return urlencode(params)


CSV_HEADER = (
    "time", "priority", "sid", "gid", "rev", "message", "classification", "proto",
    "source", "source_port", "destination", "destination_port",
)  # fmt: skip
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: object) -> str:
    """A spreadsheet must not run a cell as a formula: such text gets a leading quote."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def csv_rows(alerts: Iterable[Alert], tz: tzinfo) -> list[list[str]]:
    return [
        [
            csv_cell(v)
            for v in (
                a.ts.astimezone(tz).isoformat(timespec="seconds"),
                a.priority,
                a.sid,
                a.gid,
                a.rev,
                a.msg,
                a.classification,
                a.proto,
                a.src_ip,
                a.src_port,
                a.dst_ip,
                a.dst_port,
            )  # fmt: skip
        ]
        for a in alerts
    ]


def alert_matches(f: AlertFilters, a: Alert) -> bool:
    """Whether a live alert belongs in a table filtered by `f` (range and page do not apply)."""
    return f.to_query(None).matches(a)


def parse_alert_filters(params: Mapping[str, str]) -> AlertFilters:
    """Blank or missing values mean the default. Raises ValueError with a user-safe message."""
    sid = params.get("sid", "")
    priority = params.get("priority", "")
    page = params.get("page", "")
    src, dst, group = params.get("src", ""), params.get("dst", ""), params.get("group", "")
    if page and not (page.isascii() and page.isdigit() and 0 < int(page) <= MAX_PAGE):
        raise ValueError(f"page must be a whole number from 1 to {MAX_PAGE}")
    return AlertFilters(
        sid=valid_sid(sid) if sid else None,
        priority=valid_priority(priority) if priority else None,
        range=valid_range(params.get("range") or "24h"),
        page=int(page) if page else 1,
        src=valid_ip(src) if src else None,
        dst=valid_ip(dst) if dst else None,
        group=valid_group(group) if group else None,
        text=valid_search(params.get("q", "")),
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
    src_ip: str = ""  # the address alone, for muting by host
    dst_ip: str = ""
    iso: str = ""  # UTC timestamp, for relative time in the browser
    epoch: int = 0  # the same moment in seconds, for merging live alerts into a group
    key: str = ""  # alerts with the same key are the same repeating event
    count: int = 1  # how many alerts this row stands for
    first_time: str = ""  # time of the oldest alert in a group
    first_epoch: int = 0  # the oldest alert of a group, in seconds
    raw: str = ""  # the alert line as Snort wrote it
    id: int = 0  # database row id; 0 when the alert is not stored
    packet_filter: str = ""  # Wireshark display filter for this packet; empty if none
    conversation_filter: str = ""  # the same for both directions
    span: str = ""  # how long the group lasted, e.g. "12 min"; empty under a minute


@dataclass(frozen=True, slots=True)
class GroupRow:
    key: str
    count: int
    first: str
    last: str
    msg: str  # the newest alert's message
    href: str  # the alert table narrowed to this group


def group_rows_view(groups: list[Group], f: AlertFilters, tz: tzinfo) -> list[GroupRow]:
    """Each group links to the plain table filtered to it, keeping the other filters."""
    out: list[GroupRow] = []
    for g in groups:
        match f.group:
            case "sid":
                narrowed = replace(f, group=None, sid=int(g.key))
            case "src_ip":
                narrowed = replace(f, group=None, src=g.key)
            case _:
                narrowed = replace(f, group=None, dst=g.key)
        out.append(
            GroupRow(
                g.key,
                g.count,
                fmt_time(g.first_ts, tz),
                fmt_time(g.last_ts, tz),
                g.msg if len(g.msg) <= MSG_MAX else g.msg[: MSG_MAX - 1] + "…",
                "/alerts?" + narrowed.query_string(1),
            )
        )
    return out


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
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        raw=a.raw,
        id=a.id,
        packet_filter=alert_filter(a) or "",
        conversation_filter=conversation_filter(a) or "",
        iso=a.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        epoch=int(a.ts.timestamp()),
        first_epoch=int(a.ts.timestamp()),
        key=f"{a.sid}|{endpoint(a.src_ip, a.src_port)}|{endpoint(a.dst_ip, a.dst_port)}",
    )


GROUP_GAP = timedelta(minutes=15)


def fmt_size(n: int) -> str:
    if n < 1000:
        return f"{n} B"  # a DNS packet is about 100 bytes; "1 KB" would hide that
    return f"{n / 1_000_000:.1f} MB" if n >= 1_000_000 else f"{round(n / 1000)} KB"


def fmt_span(delta: timedelta) -> str:
    """A group's length in words; under a minute is empty so a quick burst shows only its count."""
    secs = int(delta.total_seconds())
    if secs < 60:
        return ""
    return f"{round(secs / 60)} min" if secs < 3600 else f"{secs // 3600} h"


def group_rows(alerts: list[Alert], tz: tzinfo) -> list[AlertRow]:
    """Newest-first alerts to rows; neighbours that repeat the same event become one row."""
    rows: list[AlertRow] = []
    newest: Alert | None = None  # the newest alert of rows[-1]
    last: Alert | None = None  # the oldest alert folded into rows[-1] so far
    for a in alerts:
        row = alert_row(a, tz)
        prev = rows[-1] if rows else None
        if prev and newest and last and prev.key == row.key and last.ts - a.ts <= GROUP_GAP:
            rows[-1] = replace(
                prev,
                count=prev.count + 1,
                first_time=row.time,
                first_epoch=row.epoch,
                span=fmt_span(newest.ts - a.ts),
            )
        else:
            rows.append(row)
            newest = a
        last = a
    return rows


DROP_WARN_PCT = 1.0


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
    drop_pct: float | None = None
    drop_warn: bool = False  # above 1 %: the engine is missing traffic


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
        drop_pct=st.drop_pct,
        drop_warn=st.drop_pct is not None and st.drop_pct > DROP_WARN_PCT,
    )


@dataclass(frozen=True, slots=True)
class RulesSummary:
    updated: str
    updated_iso: str  # for relative time in the browser; empty when never updated
    count: str
    result: str


def rules_summary(state: RulesState) -> RulesSummary:
    return RulesSummary(
        updated=state.updated_at[:19].replace("T", " ") if state.updated_at else "never",
        updated_iso=state.updated_at or "",
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


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


LEARNING = timedelta(days=7)  # until then, nearly everything is seen for the first time
SEEN_KIND_LABELS = {"dns": "name", "country": "country"}


@dataclass(frozen=True, slots=True)
class FirstSeenView:
    names: int
    countries: int
    rows: tuple[tuple[str, str, str], ...]  # (kind label, value, local time)
    learning_since: str | None  # a date while the history is younger than LEARNING


def first_seen_view(
    counts: Mapping[str, int],
    rows: Iterable[tuple[str, str, datetime]],
    since: datetime | None,
    now: datetime,
    tz: tzinfo,
) -> FirstSeenView:
    learning = (
        since.astimezone(tz).strftime("%Y-%m-%d") if since and now - since < LEARNING else None
    )
    return FirstSeenView(
        counts.get("dns", 0),
        counts.get("country", 0),
        tuple((SEEN_KIND_LABELS.get(k, k), v, fmt_time(t, tz)[11:16]) for k, v, t in rows),
        learning,
    )


def overview_finding(total: int, urgent: int, top_msg: str, top_count: int) -> str:
    """The one sentence under the Overview title: does anything need attention today?"""
    if total == 0:
        return "No alerts today."
    head = (
        "No priority 1 or 2 alerts today."
        if urgent == 0
        else f"{_plural(urgent, 'alert')} of priority 1 or 2 today."
    )
    return f"{head} Most frequent: {top_msg} (×{top_count})." if top_msg else head


@dataclass(frozen=True, slots=True)
class ChartBar:
    x: int  # left edge in the 240-wide plot
    top: float  # y of the bar's top in the 100-high plot
    height: float
    tip: str


@dataclass(frozen=True, slots=True)
class HourlyChart:
    bars: list[ChartBar]
    ticks: list[str]  # y labels, top to bottom
    labels: list[tuple[int, str]]  # (first grid column, text) along the x axis
    total: int


_NICE_TOPS = (4, 10, 20, 40, 100, 200, 400, 1000, 2000, 4000, 10000)


def hourly_chart(counts: list[tuple[datetime, int]], now: datetime, tz: tzinfo) -> HourlyChart:
    """Bars for the last 24 hours, one per hour, newest on the right; empty hours are zero."""
    end = now.astimezone(tz).replace(minute=0, second=0, microsecond=0)
    hours = [(end.astimezone(UTC) - timedelta(hours=i)).astimezone(tz) for i in range(23, -1, -1)]
    by_hour = {k: n for k, n in counts}
    values = [by_hour.get(h, 0) for h in hours]
    peak = max(values)
    top = next((m for m in _NICE_TOPS if peak <= m), peak)
    bars = [
        ChartBar(
            x=i * 10,
            top=100 - 100 * v / top,
            height=100 * v / top,
            tip=f"{h:%H}:00 — {_plural(v, 'alert')}",
        )
        for i, (h, v) in enumerate(zip(hours, values, strict=True))
    ]
    labels = [(i + 1, f"{hours[i]:%H}:00") for i in (0, 6, 12, 18)]
    return HourlyChart(bars, [str(top), str(top // 2), "0"], labels, sum(values))


@dataclass(frozen=True, slots=True)
class PacketsView:
    state: Literal["ok", "unavailable", "error"]
    message: str
    packets: tuple[PacketView, ...] = ()


def packets_view(result: DecodeResult) -> PacketsView:
    match result:
        case Decoded(packets=found) as ok:
            shown = _plural(len(found), "packet")
            note = f"Showing the first {shown}." if ok.more else f"{shown.capitalize()}."
            return PacketsView("ok", note if found else "The pcap holds no packets.", found)
        case Unavailable(reason=why):
            return PacketsView("unavailable", why)
        case Failed(message=why):
            return PacketsView("error", why)


@dataclass(frozen=True, slots=True)
class SummaryView:
    state: Literal["ok", "unavailable", "error"]
    message: str
    protocols: tuple[ProtocolRow, ...] = ()
    groups: tuple[tuple[str, tuple[Conversation, ...]], ...] = ()  # kind, its conversations


def summary_view(result: SummaryResult) -> SummaryView:
    match result:
        case Summary(protocols=protos, conversations=convs):
            if not protos and not convs:
                return SummaryView("ok", "The pcap holds no packets.")
            kinds = dict.fromkeys(c.kind for c in convs)
            groups = tuple((k, tuple(c for c in convs if c.kind == k)) for k in kinds)
            return SummaryView("ok", "", protos, groups)
        case Unavailable(reason=why):
            return SummaryView("unavailable", why)
        case Failed(message=why):
            return SummaryView("error", why)


@dataclass(frozen=True, slots=True)
class AlertPacketView:
    state: Literal["ok", "missing", "error"]
    note: str  # how sure the match is, or why there is no packet
    alert_id: int = 0
    packet: PacketView | None = None  # the decoded frame, when tshark could decode it
    why: str = ""  # why there is no decoded view although the packet was found
    can_open: bool = False  # the Wireshark program is installed
    hint: str = ""  # what the packet is for, e.g. "DNS lookup: example.com"


def alert_packet_view(result: AlertPacketResult, alert_id: int, can_open: bool) -> AlertPacketView:
    match result:
        case NotFound(reason=why):
            return AlertPacketView("missing", why)
        case Failed(message=why):
            return AlertPacketView("error", why)
        case AlertPacket(confidence=how, candidates=n, decoded=decoded):
            note = {
                "exact": "The packet Snort logged for this alert.",
                "near": f"Closest packet in the Snort log ({_plural(n, 'candidate')} within 2 s).",
                "ambiguous": f"{n} different packets share this moment; showing the closest.",
            }[how]
            match decoded:
                case Decoded(packets=(first, *_)):
                    seen = hint(first) or ""
                    return AlertPacketView("ok", note, alert_id, first, "", can_open, seen)
                case Unavailable(reason=why) | Failed(message=why):
                    return AlertPacketView("ok", note, alert_id, None, why, can_open)
                case _:
                    return AlertPacketView("ok", note, alert_id, None, "", can_open)
