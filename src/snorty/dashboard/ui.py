"""Shared helpers for the page controllers: template rendering, flash messages, form bodies."""

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from snorty.dashboard.security import MAX_FORM_BYTES, parse_form
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
        return parse_form(await read_body(request, MAX_FORM_BYTES, "form is too large"))


async def read_body(request: Request, limit: int, too_big: str) -> bytes:
    """The raw request body, refused as soon as it passes `limit` bytes."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise ValueError(too_big)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise ValueError(too_big)
        chunks.append(chunk)
    return b"".join(chunks)
