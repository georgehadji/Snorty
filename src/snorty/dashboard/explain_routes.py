"""Ask the local model to explain an alert's rule. Off unless `explain_model` is set."""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui
from snorty.explain import ExplainError


def add_explain_routes(app: FastAPI, ui: Ui) -> None:
    @app.post("/alerts/{alert_id}/explain", response_class=HTMLResponse)
    async def explain(request: Request, svc: Svc, alert_id: int) -> HTMLResponse:
        if svc.explain is None:
            return ui.page(
                request, "_explanation.html", status=404, error="Explaining alerts is switched off"
            )
        try:
            result = await svc.explain.explain(alert_id)
        except ExplainError as exc:
            return ui.page(request, "_explanation.html", status=422, error=str(exc))
        return ui.page(request, "_explanation.html", result=result)
