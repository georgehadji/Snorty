"""Host context for one alert: which program made the connection, where the remote address is, who
owns it, its name, a warning when it is on a known-bad list, and what else happened around it
(its connection, the DNS lookups that led there, other connections to the same address)."""

import asyncio
import json
from dataclasses import dataclass
from datetime import timedelta, tzinfo

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.core.models import Alert, Conn
from snorty.core.repository import AlertRepository
from snorty.core.rulemeta import Attack
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui
from snorty.dashboard.views import fmt_size, fmt_time
from snorty.enrich.service import remote_address


@dataclass(frozen=True, slots=True)
class Context:
    process: str | None  # None when no lookup was made for this alert
    bad: str | None
    country: str | None
    asn: str | None
    rdns: str | None
    seen: tuple[tuple[str, str], ...] = ()  # (kind, value) the engine saw on the flow
    attack: Attack | None = None  # the rule's MITRE ATT&CK tags
    around: "Around | None" = None  # connection and DNS context, for engines that log flows
    osint: str | None = None  # mentioned in a public OSINT report: a hint, not a verdict

    @property
    def empty(self) -> bool:
        return not any(
            (
                self.process, self.bad, self.country, self.asn, self.rdns, self.seen,
                self.attack, self.around, self.osint,
            )
        )  # fmt: skip


LOOKUPS_BEFORE = timedelta(hours=1)  # a DNS answer is cached, so the lookup can be well before
NEARBY = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class Around:
    """What else happened around an alert, as lines of text. `peer` is the address it is about."""

    peer: str
    flow: str  # this alert's connection, or that it has not ended yet
    lookups: tuple[tuple[str, str, str], ...]  # (time, client, name) answered with `peer`
    nearby: tuple[tuple[str, str], ...]  # (time, connection) to or from `peer`


def _end(ip: str, port: int | None) -> str:
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{port}" if port is not None else ip


def flow_text(c: Conn) -> str:
    secs = max(0, round((c.end - c.start).total_seconds()))
    took = f"{secs} s" if secs < 120 else f"{round(secs / 60)} min"
    state = f", {c.state}" if c.state else ""
    return f"{fmt_size(c.bytes_out)} sent, {fmt_size(c.bytes_in)} received over {took}{state}"


def conn_text(c: Conn) -> str:
    app = f" {c.app_proto}" if c.app_proto and c.app_proto != "failed" else ""
    route = f"{_end(c.src_ip, c.src_port)} to {_end(c.dst_ip, c.dst_port)}"
    return f"{c.proto}{app} {route}, {fmt_size(c.bytes_out)} out / {fmt_size(c.bytes_in)} in"


def around(repo: AlertRepository, alert: Alert, tz: tzinfo) -> Around | None:
    """The context of an alert that carries a flow id (Suricata's); None for one that does not."""
    flow = alert.flow_id
    if flow is None:
        return None
    peer = remote_address(alert) or alert.dst_ip
    conn = repo.conn(flow)
    return Around(
        peer,
        flow_text(conn) if conn else "still open, or not logged yet",
        tuple(
            (fmt_time(x.ts, tz), x.client, x.name)
            for x in repo.lookups_of(peer, alert.ts, LOOKUPS_BEFORE)
        ),
        tuple(
            (fmt_time(c.start, tz), conn_text(c))
            for c in repo.conns_near(peer, alert.ts, NEARBY, skip=flow)
        ),
    )


def process_text(raw: str | None) -> str | None:
    """The stored process note as a line of text; a broken note is treated as none."""
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("found"):
        return "not known: the connection had already closed when it was looked up"
    image = str(data.get("image") or "unknown program")
    source = ", from the Sysmon log" if data.get("via") == "sysmon" else ""
    return f"{image} (pid {data.get('pid')}{source})"


SEEN_LABELS = {
    "dns": "Looked up as",
    "tls": "TLS server name",
    "http": "Web request",
    "ja3": "Client fingerprint (JA3)",
    "ja4": "Client fingerprint (JA4)",
}


def build_context(
    notes: dict[str, str],
    seen: tuple[tuple[str, str], ...] = (),
    attack: Attack | None = None,
    nearby: Around | None = None,
) -> Context:
    return Context(
        process_text(notes.get("process")),
        notes.get("bad"),
        notes.get("country"),
        notes.get("asn"),
        notes.get("rdns"),
        seen,
        attack,
        nearby,
        notes.get("osint"),
    )


def add_context_routes(app: FastAPI, ui: Ui) -> None:
    @app.get("/alerts/{alert_id}/context", response_class=HTMLResponse)
    async def alert_context(request: Request, svc: Svc, alert_id: int) -> HTMLResponse:
        notes = await asyncio.to_thread(svc.repo.annotations, alert_id)
        alert = await asyncio.to_thread(svc.repo.get, alert_id)
        facts = (
            await asyncio.to_thread(svc.repo.flow_facts, alert.flow_id)
            if alert and alert.flow_id is not None
            else []
        )
        attack = (
            await asyncio.to_thread(svc.rule_info.attack, alert.sid, alert.rev)
            if alert and svc.rule_info
            else None
        )
        nearby = await asyncio.to_thread(around, svc.repo, alert, svc.tz) if alert else None
        return ui.page(
            request,
            "_alert_context.html",
            ctx=build_context(notes, tuple(facts), attack, nearby),
            labels=SEEN_LABELS,
        )
