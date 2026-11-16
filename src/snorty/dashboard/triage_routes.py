"""Inbox: alerts nobody has dealt with, acknowledged or starred a rule at a time, and the archive
rules that acknowledge known noise on arrival."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.core.query import AlertQuery
from snorty.core.repository import AlertRepository
from snorty.core.triage import INBOX, STATES, TriageState
from snorty.dashboard import views
from snorty.dashboard.security import valid_sid
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui

NOTE_MAX = 120


@dataclass(frozen=True, slots=True)
class InboxRule:
    sid: int
    count: int  # alerts in the inbox for this rule
    msg: str
    last: str
    archived: bool  # an archive rule already covers it


def _inbox(repo: AlertRepository, tz: tzinfo) -> dict[str, Any]:
    """Everything the inbox card shows (blocking; run in a thread)."""
    rules = repo.archive_rules()
    covered = {r.spec.sid for r in rules}
    rows = [
        InboxRule(int(g.key), g.count, g.msg, views.fmt_time(g.last_ts, tz), int(g.key) in covered)
        for g in repo.group(AlertQuery(), "sid", states=INBOX)
    ]
    return {
        "counts": repo.counts_by_state(AlertQuery()),
        "inbox": rows,
        "archive": [(r.id, r.spec.sid, r.note, views.fmt_time(r.created, tz)) for r in rules],
    }


def add_triage_routes(app: FastAPI, ui: Ui) -> None:
    async def card(request: Request, svc: Svc) -> HTMLResponse:
        data = await asyncio.to_thread(_inbox, svc.repo, svc.tz)
        return ui.page(request, "_inbox.html", **data)

    @app.get("/inbox", response_class=HTMLResponse)
    async def inbox(request: Request, svc: Svc) -> HTMLResponse:
        data = await asyncio.to_thread(_inbox, svc.repo, svc.tz)
        return ui.page(request, "inbox.html", **data)

    @app.post("/triage/set", response_class=HTMLResponse)
    async def set_state(request: Request, svc: Svc, sid: str, state: str) -> HTMLResponse:
        try:
            number = valid_sid(sid)
            chosen: TriageState = next((s for s in STATES if s == state), "new")
            if chosen != state:
                raise ValueError("state must be new, ack or starred")
        except ValueError as exc:
            return ui.flash(request, views.Message(False, str(exc)), status=422)
        await asyncio.to_thread(
            svc.repo.set_state, AlertQuery(sid=number), chosen, datetime.now(UTC)
        )
        return await card(request, svc)

    @app.post("/triage/archive", response_class=HTMLResponse)
    async def archive(request: Request, svc: Svc, sid: str) -> HTMLResponse:
        try:
            number = valid_sid(sid)
        except ValueError as exc:
            return ui.flash(request, views.Message(False, str(exc)), status=422)
        now = datetime.now(UTC)
        latest = await asyncio.to_thread(svc.repo.query, sid=number, limit=1)
        note = latest[0].msg[:NOTE_MAX] if latest else ""
        await asyncio.to_thread(svc.repo.add_archive_rule, AlertQuery(sid=number), note, now)
        await asyncio.to_thread(svc.repo.apply_archive_rules, now)
        return await card(request, svc)

    @app.post("/triage/archive/{rule_id}/delete", response_class=HTMLResponse)
    async def delete_rule(request: Request, svc: Svc, rule_id: int) -> HTMLResponse:
        await asyncio.to_thread(svc.repo.delete_archive_rule, rule_id)
        return await card(request, svc)
