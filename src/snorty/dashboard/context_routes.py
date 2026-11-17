"""Host context for one alert: which program made the connection, where the remote address is, who
owns it, its name, and a warning when it is on a known-bad list."""

import asyncio
import json
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui


@dataclass(frozen=True, slots=True)
class Context:
    process: str | None  # None when no lookup was made for this alert
    bad: str | None
    country: str | None
    asn: str | None
    rdns: str | None

    @property
    def empty(self) -> bool:
        return not any((self.process, self.bad, self.country, self.asn, self.rdns))


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
    return f"{image} (pid {data.get('pid')})"


def build_context(notes: dict[str, str]) -> Context:
    return Context(
        process_text(notes.get("process")),
        notes.get("bad"),
        notes.get("country"),
        notes.get("asn"),
        notes.get("rdns"),
    )


def add_context_routes(app: FastAPI, ui: Ui) -> None:
    @app.get("/alerts/{alert_id}/context", response_class=HTMLResponse)
    async def alert_context(request: Request, svc: Svc, alert_id: int) -> HTMLResponse:
        notes = await asyncio.to_thread(svc.repo.annotations, alert_id)
        return ui.page(request, "_alert_context.html", ctx=build_context(notes))
