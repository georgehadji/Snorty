import asyncio
from collections.abc import AsyncIterator

from snorty.core.events import Event

_CLOSED = object()


class Subscription:
    """One subscriber's bounded queue. Async-iterate it to receive events."""

    def __init__(self, bus: "EventBus", maxsize: int) -> None:
        self._bus = bus
        self._queue: asyncio.Queue[Event | object] = asyncio.Queue(maxsize=maxsize)
        self._closed = False
        self.dropped = 0

    def _put(self, event: Event) -> None:
        if self._closed:
            return
        if self._queue.full():
            self._queue.get_nowait()
            self.dropped += 1
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

    def subscribe(self, maxsize: int = 1000) -> Subscription:
        sub = Subscription(self, maxsize)
        self._subs.append(sub)
        return sub

    def publish(self, event: Event) -> None:
        for sub in tuple(self._subs):
            sub._put(event)

    def _remove(self, sub: Subscription) -> None:
        if sub in self._subs:
            self._subs.remove(sub)
