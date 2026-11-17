"""Records which program on this PC an alert's connection belonged to."""

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Literal, cast

from snorty.attribution.ports import ConnectionLookup
from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised, Event
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository

log = logging.getLogger("snorty.attribution")

KIND = "process"


class AttributionService:
    """Looks each live TCP or UDP alert up in the connection table and stores the owner as an
    annotation. The lookup runs about one poll after the packet, so a short connection may be gone:
    that is stored too, so the page can say so instead of staying silent."""

    def __init__(
        self,
        bus: EventBus,
        repo: AlertRepository,
        lookup: ConnectionLookup,
        local_ip: Callable[[], str | None],
    ) -> None:
        self._bus = bus
        self._repo = repo
        self._lookup = lookup
        self._local_ip = local_ip
        self._sub: Subscription | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        # Old alerts are never attributed: the connection is long gone and the table would lie.
        self._sub = self._bus.subscribe(maxsize=500, accept=_wants, keep_oldest=True)
        self._task = asyncio.create_task(self._consume(self._sub), name="attribution")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        if self._sub is not None:
            self._sub.close()
        self._task = self._sub = None

    async def _consume(self, sub: Subscription) -> None:
        async for event in sub:
            if isinstance(event, AlertRaised):
                try:
                    await asyncio.to_thread(self.attribute, event.alert)
                except Exception:  # one bad lookup must not end the consumer
                    log.exception("could not attribute alert %s", event.alert.id)

    def attribute(self, alert: Alert) -> None:
        """Blocking: find the local endpoint of `alert`, look it up and store the answer."""
        local = self._local_ip()
        if alert.proto not in ("TCP", "UDP") or not alert.id or local is None:
            return
        proto = cast("Literal['TCP', 'UDP']", alert.proto)
        if alert.src_ip == local and alert.src_port is not None:
            ip, port = alert.src_ip, alert.src_port
        elif alert.dst_ip == local and alert.dst_port is not None:
            ip, port = alert.dst_ip, alert.dst_port
        else:
            return  # neither end is this PC (a mirrored or routed packet)
        owner = self._lookup.owner(proto, ip, port)
        found = (
            {"found": False}
            if owner is None
            else {"found": True, "pid": owner.pid, "image": owner.image}
        )
        self._repo.annotate(alert.id, KIND, json.dumps(found))


def _wants(event: Event) -> bool:
    return isinstance(event, AlertRaised) and event.alert.proto in ("TCP", "UDP")
