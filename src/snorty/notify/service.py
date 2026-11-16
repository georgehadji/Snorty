"""Watches the event bus and shows a toast for each alert worth interrupting you for."""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, tzinfo

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised
from snorty.notify.ports import Notifier
from snorty.notify.throttle import Throttle
from snorty.notify.toast import build_toast

log = logging.getLogger("snorty.notify")


@dataclass(frozen=True, slots=True)
class NotifyConfig:
    min_priority: int = 1  # toast alerts with priority <= this (1 is the most severe)
    window: float = 300.0  # seconds between toasts for the same SID
    cap: int = 6  # toasts per cap_window across all SIDs
    cap_window: float = 60.0
    tz: tzinfo = UTC  # zone for the time shown in the toast
    show_timeout: float = 15.0  # a notifier that takes longer is abandoned


class NotifyService:
    def __init__(
        self,
        bus: EventBus,
        notifier: Notifier,
        config: NotifyConfig = NotifyConfig(),
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._bus = bus
        self._notifier = notifier
        self._config = config
        self._clock = clock
        self._throttle = Throttle(config.window, config.cap, config.cap_window)
        self._sub: Subscription | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Subscribe, then start consuming. Events published after this returns are seen."""
        if self._task is not None:
            return
        self._sub = self._bus.subscribe(maxsize=1000)
        self._task = asyncio.create_task(self._consume(self._sub), name="notify-consumer")

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
                    await self._handle(event)
                except Exception:  # the consumer must outlive any single bad alert
                    log.exception("could not handle alert SID %s", event.alert.sid)

    async def _handle(self, event: AlertRaised) -> None:
        alert = event.alert
        if alert.priority > self._config.min_priority:
            return
        decision = self._throttle.decide(alert.sid, self._clock())
        if not decision.show:
            return
        toast = build_toast(alert, decision.same_sid, decision.other, self._config.tz)
        await asyncio.wait_for(self._notifier.show(toast), self._config.show_timeout)
