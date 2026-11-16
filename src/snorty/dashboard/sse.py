"""Server-Sent Events over the event bus: one bounded subscription per browser tab."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

from snorty.core.bus import Subscription
from snorty.core.events import Event

HEARTBEAT_SECONDS = 15.0
type Render = Callable[[Event], Awaitable[tuple[str, str] | None]]


def format_frame(event: str, data: str) -> str:
    """One SSE message: every line of `data` gets its own `data:` field."""
    lines = data.splitlines() or [""]
    return f"event: {event}\n" + "".join(f"data: {line}\n" for line in lines) + "\n"


async def sse_frames(
    subscribe: Callable[[], Subscription],
    render: Render,
    *,
    heartbeat: float = HEARTBEAT_SECONDS,
) -> AsyncIterator[str]:
    """SSE text frames for each event `render` accepts, a comment every `heartbeat` seconds
    when idle. The subscription is made when iteration starts and closed when it ends,
    whether the client left, the task was cancelled or the bus closed it."""
    sub = subscribe()
    waiting: asyncio.Future[Event] | None = None
    try:
        yield ": connected\n\n"
        while True:
            if waiting is None:
                waiting = asyncio.ensure_future(sub.__anext__())
            done, _ = await asyncio.wait({waiting}, timeout=heartbeat)
            if not done:
                yield ": keep-alive\n\n"
                continue
            finished, waiting = waiting, None
            try:
                event = finished.result()
            except StopAsyncIteration:
                return
            if (out := await render(event)) is not None:
                yield format_frame(*out)
    finally:
        if waiting is not None:
            waiting.cancel()
        sub.close()
