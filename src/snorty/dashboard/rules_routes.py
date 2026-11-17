"""Rules page: update now, mute and unmute, HOME_NET."""

import asyncio
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard import views
from snorty.dashboard.jobs import Done, Errored, Idle, Job, Running
from snorty.dashboard.security import valid_home_net, valid_scope, valid_sid
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui
from snorty.rules.service import EditReport, UpdateReport
from snorty.sensor import State

NOTE_MAX = 120


def add_rules_routes(app: FastAPI, ui: Ui) -> None:
    update_job: Job[UpdateReport] = Job()
    ui.cleanups.append(update_job.cancel)

    def running(request: Request, *, already: bool = False) -> HTMLResponse:
        return ui.page(request, "_update_status.html", state="running", already=already)

    def bad(request: Request, exc: ValueError) -> HTMLResponse:
        return ui.flash(request, views.Message(False, str(exc)), status=422)

    @app.get("/rules", response_class=HTMLResponse)
    async def rules_page(request: Request, svc: Svc) -> HTMLResponse:
        rules = views.rules_summary(await svc.rules.status())
        extra: dict[str, Any] = {}
        if svc.respond is not None:
            extra["blocks"] = await asyncio.to_thread(svc.respond.blocks, "active")
        try:
            muted, home = await svc.rules.muted(), await svc.rules.home_net()
        except OSError as exc:  # snort.conf or local.rules unreadable
            msg = f"Could not read the Snort settings: {exc.strerror or type(exc).__name__}"
            return ui.page(request, "rules.html", rules=rules, load_error=msg, **extra)
        return ui.page(request, "rules.html", rules=rules, muted=muted, home=home, **extra)

    @app.post("/rules/update", response_class=HTMLResponse)
    async def update(request: Request, svc: Svc) -> HTMLResponse:
        try:
            force = (await ui.form(request)).get("force") == "on"
        except ValueError as exc:
            return bad(request, exc)
        started = update_job.start(lambda: svc.rules.update(force=force))
        return running(request, already=not started)

    @app.get("/rules/update/status", response_class=HTMLResponse)
    async def update_status(request: Request, svc: Svc) -> HTMLResponse:
        match update_job.state:
            case Running():
                return running(request)
            case Idle():
                return ui.page(request, "_update_status.html", state="idle")
            case Errored(message=why):
                msg = views.Message(False, why)
            case Done(result=report):
                msg = views.update_message(report)
        summary = views.rules_summary(await svc.rules.status())
        return ui.page(
            request, "_update_status.html", state="done", msg=msg, rules=summary, oob=True
        )

    def edit_result(
        request: Request, report: EditReport, was_running: bool, **context: Any
    ) -> HTMLResponse:
        msg = views.edit_message(report, sensor_was_running=was_running)
        return ui.flash(request, msg, **context)

    @app.post("/rules/mute/{sid}", response_class=HTMLResponse)
    async def mute(
        request: Request, sid: str, svc: Svc, track: str = "", ip: str = ""
    ) -> HTMLResponse:
        try:
            number = valid_sid(sid)
            scope = valid_scope(track, ip)
        except ValueError as exc:
            return bad(request, exc)
        was_running = svc.sensor.state in (State.RUNNING, State.STARTING)
        latest = await asyncio.to_thread(svc.repo.query, sid=number, limit=1)
        note = latest[0].msg[:NOTE_MAX] if latest else ""
        return edit_result(request, await svc.rules.mute(number, note, **scope), was_running)

    @app.post("/rules/unmute/{sid}", response_class=HTMLResponse)
    async def unmute(
        request: Request, sid: str, svc: Svc, view: str = "", track: str = "", ip: str = ""
    ) -> HTMLResponse:
        try:
            number = valid_sid(sid)
            scope = valid_scope(track, ip)
        except ValueError as exc:
            return bad(request, exc)
        was_running = svc.sensor.state in (State.RUNNING, State.STARTING)
        report = await svc.rules.unmute(number, **scope)
        extra = {"muted": await svc.rules.muted(), "oob": True} if view == "rules" else {}
        return edit_result(request, report, was_running, **extra)

    @app.post("/rules/home-net", response_class=HTMLResponse)
    async def home_net(request: Request, svc: Svc) -> HTMLResponse:
        try:
            raw = (await ui.form(request)).get("value", "").strip()
            value = valid_home_net(raw) if raw else None
        except ValueError as exc:
            return bad(request, exc)
        was_running = svc.sensor.state in (State.RUNNING, State.STARTING)
        report = await svc.rules.set_home_net(value)
        return edit_result(request, report, was_running, home=await svc.rules.home_net(), oob=True)
