"""Shared helpers for the page controllers: template rendering, flash messages, form bodies."""

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from snorty.dashboard.security import parse_form
from snorty.dashboard.views import Message


class Ui:
    def __init__(self, templates: Jinja2Templates) -> None:
        self._templates = templates
        self.cleanups: list[Callable[[], Awaitable[None]]] = []  # run when the app shuts down

    def page(
        self, request: Request, name: str, *, status: int = 200, **context: object
    ) -> HTMLResponse:
        return self._templates.TemplateResponse(request, name, context, status_code=status)

    def fragment(self, name: str, **context: object) -> str:
        return self._templates.get_template(name).render(context)

    def flash(
        self, request: Request, msg: Message, *, status: int = 200, **context: Any
    ) -> HTMLResponse:
        """The message for the page's #flash area, plus any out-of-band cards in `context`."""
        return self.page(request, "_flash.html", status=status, msg=msg, **context)

    @staticmethod
    async def form(request: Request) -> dict[str, str]:
        return parse_form(await request.body())
