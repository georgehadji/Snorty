"""Watches the event bus and shows a toast for each alert worth interrupting you for."""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, tzinfo

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertFlagged, AlertRaised, SensorHealth
from snorty.notify.ports import Notifier
from snorty.notify.throttle import Throttle
from snorty.notify.toast import build_flagged_toast, build_health_toast, build_toast

log = logging.getLogger("snorty.notify")


@dataclass(frozen=True, slots=True)
class NotifyConfig:
    min_priority: int = 1  # toast alerts with priority <= this (1 is the most severe)
    window: float = 300.0  # seconds between toasts for the same SID
    cap: int = 6  # toasts per cap_window across all SIDs
    cap_window: float = 60.0
    tz: tzinfo = UTC  # zone for the time shown in the toast
    show_timeout: float = 15.0  # a notifier that takes longer is abandoned
    drop_pct: float = 5.0  # toast when the engine drops more than this share of packets
    drop_window: float = 3600.0  # at most one such toast per this many seconds


@dataclass(frozen=True, slots=True)
class NotifyStatus:
    toasts_shown: int
    min_priority: int


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
        self._shown = 0
        self._drop_toast_at: float | None = None

    def status(self) -> NotifyStatus:
        return NotifyStatus(self._shown, self._config.min_priority)

    async def start(self) -> None:
        """Subscribe, then start consuming. Events published after this returns are seen."""
        if self._task is not None:
            return
        # Only toast-worthy alerts enter the queue, so a flood of low-priority ones cannot
        # push a priority-1 alert out of it before the consumer reads it. A burst bigger than the
        # queue keeps its first alerts: the rest are mostly repeats the throttle would hold back.
        self._sub = self._bus.subscribe(
            maxsize=1000,
            accept=lambda e: (
                isinstance(e, AlertFlagged)
                or (isinstance(e, SensorHealth) and e.drop_pct > self._config.drop_pct)
                or (isinstance(e, AlertRaised) and e.alert.priority <= self._config.min_priority)
            ),
            keep_oldest=True,
        )
        self._task = asyncio.create_task(self._consume(self._sub), name="notify-consumer")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        if self._sub is not None:
            self._sub.close()
        self._task = self._sub = None

    async def _consume(self, sub: Subscription) -> None:
        missed = 0
        async for event in sub:
            if isinstance(event, SensorHealth):
                await self._health(event)
            elif isinstance(event, AlertRaised | AlertFlagged):
                try:
                    await self._handle(event)
                except Exception:  # the consumer must outlive any single bad alert
                    log.exception("could not handle alert SID %s", event.alert.sid)
            # Alerts refused by the full queue came after this one: the next toast reports them.
            if sub.dropped > missed:
                self._throttle.missed(sub.dropped - missed)
                missed = sub.dropped

    async def _health(self, event: SensorHealth) -> None:
        now = self._clock()
        last = self._drop_toast_at
        if last is not None and now - last < self._config.drop_window:
            return
        self._drop_toast_at = now
        try:
            await asyncio.wait_for(
                self._notifier.show(build_health_toast(event.drop_pct)), self._config.show_timeout
            )
            self._shown += 1
        except Exception:  # a failed toast is retried on the next health event
            self._drop_toast_at = last
            log.exception("could not show the dropped-packets toast")

    async def _handle(self, event: AlertRaised | AlertFlagged) -> None:
        alert = event.alert
        flagged = isinstance(event, AlertFlagged)
        if not flagged and alert.priority > self._config.min_priority:
            return
        key = -alert.sid if flagged else alert.sid  # a flagged toast has its own throttle slot
        decision = self._throttle.decide(key, self._clock())
        if not decision.show:
            return
        tz = self._config.tz
        toast = (
            build_flagged_toast(alert, event.reason, decision.same_sid, decision.other, tz)
            if isinstance(event, AlertFlagged)
            else build_toast(alert, decision.same_sid, decision.other, tz)
        )
        try:
            await asyncio.wait_for(self._notifier.show(toast), self._config.show_timeout)
        except Exception:  # nobody saw it: the next alert of this SID must not be throttled
            self._throttle.release(key, decision)
            raise
        self._shown += 1
