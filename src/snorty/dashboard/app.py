"""The FastAPI app: routes are thin, each calls one service and renders a template."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

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


def _top_rule(svc: Services, sid: int, count: int, since: datetime) -> TopRule:
    latest = svc.repo.query(sid=sid, since=since, limit=1)
    return TopRule(sid, latest[0].msg if latest else "", count)


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

    def page(request: Request, name: str, **context: object) -> HTMLResponse:
        return templates.TemplateResponse(request, name, context)

    @app.get("/healthz")
    async def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request, svc: Svc) -> HTMLResponse:
        now = clock()
        midnight = now.astimezone(svc.tz).replace(hour=0, minute=0, second=0, microsecond=0)
        today = svc.repo.counts_by_sid(since=midnight)
        top = [_top_rule(svc, sid, n, midnight) for sid, n in today[:5]]
        return page(
            request,
            "overview.html",
            card=views.sensor_card(svc.sensor.status(), svc.tz),
            count_hour=sum(n for _, n in svc.repo.counts_by_sid(since=now - timedelta(hours=1))),
            count_today=sum(n for _, n in today),
            top_rules=top,
            rows=[views.alert_row(a, svc.tz) for a in svc.repo.query(limit=10)],
            rules=views.rules_summary(await svc.rules.status()),
            journal_on=svc.journal is not None,
        )

    @app.post("/sensor/{action}", response_class=HTMLResponse)
    async def sensor_action(
        request: Request, action: Literal["start", "stop", "restart"], svc: Svc
    ) -> HTMLResponse:
        await getattr(svc.sensor, action)()
        return page(
            request, "_sensor_card.html", card=views.sensor_card(svc.sensor.status(), svc.tz)
        )

    return app
