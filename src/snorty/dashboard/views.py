"""Pure view-models: turn domain objects into plain values the templates print."""

from dataclasses import dataclass
from datetime import datetime, tzinfo

from snorty.core.models import Alert
from snorty.rules.state import RulesState
from snorty.sensor import SensorStatus, State

MSG_MAX = 120

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
    )


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
