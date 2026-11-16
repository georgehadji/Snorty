"""The FastAPI app: routes are thin, each calls one service and renders a template."""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from snorty.dashboard import views
from snorty.dashboard.security import SecurityMiddleware
from snorty.dashboard.services import Services, get_services

_HERE = Path(__file__).parent
Svc = Annotated[Services, Depends(get_services)]


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
        "count_hour": sum(n for _, n in svc.repo.counts_by_sid(since=now - timedelta(hours=1))),
        "count_today": sum(n for _, n in today),
        "top_rules": top,
        "rows": [views.alert_row(a, svc.tz) for a in svc.repo.query(limit=10)],
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
    rows = [views.alert_row(a, svc.tz) for a in found[: views.PAGE_SIZE]]
    return rows, f.query_string(f.page + 1) if len(found) > views.PAGE_SIZE else None


def build_app(
    services: Services,
    *,
    token: str,
    port: int,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FastAPI:
    app = FastAPI(title="Snorty", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.services = services
    app.add_middleware(SecurityMiddleware, token=token, port=port)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
    templates = Jinja2Templates(directory=_HERE / "templates")
    templates.env.globals["token"] = token

    def page(request: Request, name: str, *, status: int = 200, **context: object) -> HTMLResponse:
        return templates.TemplateResponse(request, name, context, status_code=status)

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
            journal_on=svc.journal is not None,
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

    return app
