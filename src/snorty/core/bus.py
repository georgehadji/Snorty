import asyncio
import logging
from collections.abc import AsyncIterator, Callable

from snorty.core.events import Event

log = logging.getLogger("snorty.bus")
_CLOSED = object()


class Subscription:
    """One subscriber's bounded queue. Async-iterate it to receive events."""

    def __init__(
        self,
        bus: "EventBus",
        maxsize: int,
        accept: Callable[[Event], bool] | None = None,
        keep_oldest: bool = False,
    ) -> None:
        self._bus = bus
        self._queue: asyncio.Queue[Event | object] = asyncio.Queue(maxsize=maxsize)
        self._accept = accept  # events it rejects never enter the queue, so never push others out
        self._keep_oldest = keep_oldest  # when full, refuse new events instead of evicting old
        self._closed = False
        self.dropped = 0

    def _put(self, event: Event) -> None:
        if self._accept is not None and not self._accept(event):
            return
        if self._queue.full():
            self.dropped += 1
            if self.dropped == 1:
                which = "newest" if self._keep_oldest else "oldest"
                log.warning("a subscriber's queue is full; dropping its %s events", which)
            if self._keep_oldest:
                return
            self._queue.get_nowait()
        self._queue.put_nowait(event)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._bus._remove(self)
        while not self._queue.empty():
            self._queue.get_nowait()
        self._queue.put_nowait(_CLOSED)

    def __aiter__(self) -> AsyncIterator[Event]:
        return self

    async def __anext__(self) -> Event:
        item = await self._queue.get()
        if item is _CLOSED:
            self._queue.put_nowait(_CLOSED)  # keep ending any other waiter
            raise StopAsyncIteration
        return item  # type: ignore[return-value]


class EventBus:
    """In-process pub/sub. publish() is synchronous and never waits: a slow
    subscriber loses its oldest events instead of slowing the publisher."""

    def __init__(self) -> None:
        self._subs: list[Subscription] = []

    def subscribe(
        self,
        maxsize: int = 1000,
        accept: Callable[[Event], bool] | None = None,
        *,
        keep_oldest: bool = False,
    ) -> Subscription:
        sub = Subscription(self, maxsize, accept, keep_oldest)
        self._subs.append(sub)
        return sub

    def publish(self, event: Event) -> None:
        for sub in tuple(self._subs):
            sub._put(event)

    def _remove(self, sub: Subscription) -> None:
        if sub in self._subs:
            self._subs.remove(sub)
