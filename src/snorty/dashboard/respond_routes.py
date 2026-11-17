"""Block an address in Windows Firewall, and list and undo the blocks. Manual only."""

import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard import views
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui

DEFAULT_HOURS = 24.0


def add_respond_routes(app: FastAPI, ui: Ui) -> None:
    @app.get("/respond/blocks", response_class=HTMLResponse)
    async def blocks_card(request: Request, svc: Svc) -> HTMLResponse:
        if svc.respond is None:
            return ui.flash(request, views.Message(False, "Blocking is switched off"), status=404)
        blocks = await asyncio.to_thread(svc.respond.blocks, "active")
        return ui.page(request, "_blocks_card.html", blocks=blocks, oob=False)

    @app.post("/respond/block", response_class=HTMLResponse)
    async def block(
        request: Request, svc: Svc, ip: str, hours: float = DEFAULT_HOURS, alert_id: int = 0
    ) -> HTMLResponse:
        if svc.respond is None:
            return ui.flash(request, views.Message(False, "Blocking is switched off"), status=404)
        out = await svc.respond.block(ip, hours, alert_id or None)
        blocks = await asyncio.to_thread(svc.respond.blocks, "active")
        return ui.flash(
            request, views.Message(out.ok, out.detail), status=200 if out.ok else 422,
            blocks=blocks, oob=True,
        )  # fmt: skip

    @app.post("/respond/unblock", response_class=HTMLResponse)
    async def unblock(request: Request, svc: Svc, ip: str) -> HTMLResponse:
        if svc.respond is None:
            return ui.flash(request, views.Message(False, "Blocking is switched off"), status=404)
        out = await svc.respond.unblock(ip)
        blocks = await asyncio.to_thread(svc.respond.blocks, "active")
        return ui.flash(
            request, views.Message(out.ok, out.detail), status=200 if out.ok else 422,
            blocks=blocks, oob=True,
        )  # fmt: skip
