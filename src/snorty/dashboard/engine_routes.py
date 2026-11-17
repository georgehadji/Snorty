"""Which detection engine Snorty uses. The engine is chosen when the dashboard starts, so the
picker saves the choice to `snorty.toml` and says that a restart applies it."""

import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard.config import ENGINES, ConfigError, load_config, save_engine
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui

NAMES = {"snort": "Snort", "suricata": "Suricata"}


def add_engine_routes(app: FastAPI, ui: Ui) -> None:
    def card(
        request: Request, svc: Svc, saved: str, error: str | None = None, status: int = 200
    ) -> HTMLResponse:
        return ui.page(
            request, "_engine_card.html", status=status, running=svc.engine, saved=saved,
            engines=ENGINES, names=NAMES, error=error,
        )  # fmt: skip

    def saved_engine(svc: Svc) -> str:
        try:
            return load_config(svc.data_dir).engine
        except ConfigError:
            return svc.engine

    @app.get("/engine", response_class=HTMLResponse)
    async def engine_card(request: Request, svc: Svc) -> HTMLResponse:
        return card(request, svc, await asyncio.to_thread(saved_engine, svc))

    @app.post("/engine", response_class=HTMLResponse)
    async def choose_engine(request: Request, svc: Svc) -> HTMLResponse:
        engine = (await ui.form(request)).get("engine", "")
        try:
            await asyncio.to_thread(save_engine, svc.data_dir, engine)
        except (ConfigError, OSError) as exc:
            return card(request, svc, await asyncio.to_thread(saved_engine, svc), str(exc), 422)
        return card(request, svc, engine)
