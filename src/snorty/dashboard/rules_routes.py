"""Rules page: update now, mute and unmute, HOME_NET."""

import asyncio
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard import views
from snorty.dashboard.jobs import Job
from snorty.dashboard.security import valid_home_net, valid_sid
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
        return ui.page(
            request,
            "rules.html",
            rules=views.rules_summary(await svc.rules.status()),
            muted=await svc.rules.muted(),
            home=await svc.rules.home_net(),
        )

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
        if update_job.running:
            return running(request)
        if update_job.error:
            msg = views.Message(False, update_job.error)
        elif update_job.result is not None:
            msg = views.update_message(update_job.result)
        else:
            return ui.page(request, "_update_status.html", state="idle")
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
    async def mute(request: Request, sid: str, svc: Svc) -> HTMLResponse:
        try:
            number = valid_sid(sid)
        except ValueError as exc:
            return bad(request, exc)
        was_running = svc.sensor.state in (State.RUNNING, State.STARTING)
        latest = await asyncio.to_thread(svc.repo.query, sid=number, limit=1)
        note = latest[0].msg[:NOTE_MAX] if latest else ""
        return edit_result(request, await svc.rules.mute(number, note), was_running)

    @app.post("/rules/unmute/{sid}", response_class=HTMLResponse)
    async def unmute(request: Request, sid: str, svc: Svc, view: str = "") -> HTMLResponse:
        try:
            number = valid_sid(sid)
        except ValueError as exc:
            return bad(request, exc)
        was_running = svc.sensor.state in (State.RUNNING, State.STARTING)
        report = await svc.rules.unmute(number)
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
