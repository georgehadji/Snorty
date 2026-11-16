"""The FastAPI app: routes are thin, each calls one service and renders a template."""

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from snorty.core.events import AlertRaised, Event, SensorStateChanged
from snorty.dashboard import views
from snorty.dashboard.journal_routes import add_journal_routes
from snorty.dashboard.lab_routes import add_lab_routes
from snorty.dashboard.rules_routes import add_rules_routes
from snorty.dashboard.security import SecurityMiddleware
from snorty.dashboard.services import Svc
from snorty.dashboard.sse import HEARTBEAT_SECONDS, Render, sse_frames
from snorty.dashboard.ui import Ui
from snorty.services import Services

_HERE = Path(__file__).parent


@dataclass(frozen=True, slots=True)
class TopRule:
    sid: int
    msg: str
    count: int


def _overview_data(svc: Services, now: datetime) -> dict[str, Any]:
    """Everything the Overview needs from the repository (blocking; run in a thread)."""
    midnight = now.astimezone(svc.tz).replace(hour=0, minute=0, second=0, microsecond=0)
    today = svc.repo.counts_by_sid(since=midnight)
    top = []
    for sid, count in today[:5]:
        latest = svc.repo.query(sid=sid, since=midnight, limit=1)
        top.append(TopRule(sid, latest[0].msg if latest else "", count))
    return {
        "count_hour": svc.repo.count(since=now - timedelta(hours=1)),
        "count_today": sum(n for _, n in today),
        "top_rules": top,
        "rows": views.group_rows(svc.repo.query(limit=10), svc.tz),
    }


def _alert_page(
    svc: Services, f: views.AlertFilters, now: datetime
) -> tuple[list[views.AlertRow], str | None]:
    """One page of alerts and the query string for the next page, if there is one."""
    found = svc.repo.query(
        since=f.since(now),
        sid=f.sid,
        min_priority=f.priority,
        limit=views.PAGE_SIZE + 1,
        offset=(f.page - 1) * views.PAGE_SIZE,
    )
    rows = views.group_rows(found[: views.PAGE_SIZE], svc.tz)
    return rows, f.query_string(f.page + 1) if len(found) > views.PAGE_SIZE else None


def build_app(
    services: Services,
    *,
    token: str,
    port: int,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    heartbeat: float = HEARTBEAT_SECONDS,
) -> FastAPI:
    ui: Ui

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        for cleanup in ui.cleanups:
            await cleanup()

    app = FastAPI(
        title="Snorty", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.services = services
    app.add_middleware(SecurityMiddleware, token=token, port=port)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
    templates = Jinja2Templates(directory=_HERE / "templates")
    templates.env.globals["token"] = token
    templates.env.globals["sensor_status"] = lambda: views.sensor_card(
        services.sensor.status(), services.tz
    )
    ui = Ui(templates)
    page, fragment = ui.page, ui.fragment

    def renderer(svc: Services, f: views.AlertFilters) -> Render:
        async def render(event: Event) -> tuple[str, str] | None:
            if isinstance(event, AlertRaised):
                if not views.alert_matches(f, event.alert):
                    return None
                row = views.alert_row(event.alert, svc.tz)
                return "alert", fragment("_alert_rows.html", rows=[row], paged=True)
            if isinstance(event, SensorStateChanged):
                card = views.sensor_card(svc.sensor.status(), svc.tz)
                return "sensor", fragment("_sensor_card.html", card=card)
            rules = views.rules_summary(await svc.rules.status())
            return "rules", fragment("_rules_summary.html", rules=rules)

        return render

    @app.get("/healthz")
    async def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request, svc: Svc) -> HTMLResponse:
        data = await asyncio.to_thread(_overview_data, svc, clock())
        return page(
            request,
            "overview.html",
            card=views.sensor_card(svc.sensor.status(), svc.tz),
            rules=views.rules_summary(await svc.rules.status()),
            journal=svc.journal and views.journal_view(svc.journal.status(), svc.tz),
            notify=svc.notify and views.notify_view(svc.notify.status()),
            **data,
        )

    @app.post("/sensor/{action}", response_class=HTMLResponse)
    async def sensor_action(
        request: Request, action: Literal["start", "stop", "restart"], svc: Svc
    ) -> HTMLResponse:
        await getattr(svc.sensor, action)()
        return page(
            request, "_sensor_card.html", card=views.sensor_card(svc.sensor.status(), svc.tz)
        )

    @app.get("/alerts", response_class=HTMLResponse)
    async def alerts(request: Request, svc: Svc) -> HTMLResponse:
        try:
            f = views.parse_alert_filters(request.query_params)
        except ValueError as exc:
            blank = views.AlertFilters(None, None, "24h", 1)
            return page(
                request, "alerts.html", status=422, f=blank, error=str(exc), rows=[], more=None
            )
        rows, more = await asyncio.to_thread(_alert_page, svc, f, clock())
        return page(request, "alerts.html", f=f, error=None, rows=rows, more=more)

    @app.get("/alerts/rows", response_class=HTMLResponse)
    async def alert_rows(request: Request, svc: Svc) -> HTMLResponse:
        try:
            f = views.parse_alert_filters(request.query_params)
        except ValueError as exc:
            return page(request, "_alert_rows.html", status=422, error=str(exc), rows=[])
        rows, more = await asyncio.to_thread(_alert_page, svc, f, clock())
        return page(request, "_alert_rows.html", rows=rows, more=more, paged=f.page > 1)

    @app.get("/events")
    async def events(request: Request, svc: Svc) -> Response:
        try:
            f = views.parse_alert_filters(request.query_params)
        except ValueError as exc:
            return PlainTextResponse(str(exc), status_code=422)
        return StreamingResponse(
            sse_frames(lambda: svc.bus.subscribe(100), renderer(svc, f), heartbeat=heartbeat),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    add_rules_routes(app, ui)
    add_journal_routes(app, ui)
    add_lab_routes(app, ui)
    return app
