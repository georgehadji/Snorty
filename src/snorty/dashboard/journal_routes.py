"""Journal page: where notes go, what was written, write now."""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard import views
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui


def add_journal_routes(app: FastAPI, ui: Ui) -> None:
    @app.get("/journal", response_class=HTMLResponse)
    async def journal_page(request: Request, svc: Svc) -> HTMLResponse:
        journal = svc.journal and views.journal_view(svc.journal.status(), svc.tz)
        return ui.page(request, "journal.html", journal=journal)

    @app.post("/journal/flush", response_class=HTMLResponse)
    async def flush(request: Request, svc: Svc) -> HTMLResponse:
        if svc.journal is None:
            return ui.flash(request, views.Message(False, "Journal is off."), status=409)
        await svc.journal.flush()
        view = views.journal_view(svc.journal.status(), svc.tz)
        if view.error:
            msg = views.Message(False, f"Could not write the note: {view.error}")
        else:
            msg = views.Message(True, "Journal is up to date.")
        return ui.flash(request, msg, journal=view, oob=True)
