"""Explain an alert's rule with a local model, and remember the answer per (sid, rev) so the
model runs once for each rule version, not once per click. With a bus it also explains each
rule the first time it fires, in the background, so the click finds the answer ready."""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised, Event
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.explain.ports import Explainer, ExplainError

log = logging.getLogger("snorty.explain")
PREWARM_QUEUE = 100  # rules waiting to be explained in the background; more are skipped


@dataclass(frozen=True, slots=True)
class Explanation:
    text: str
    model: str
    cached: bool


class ExplainService:
    def __init__(
        self,
        repo: AlertRepository,
        explainer: Explainer,
        lookup: Callable[[int], str | None],
        *,
        bus: EventBus | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        retry_after: float = 300.0,
    ) -> None:
        self._repo = repo
        self._explainer = explainer
        self._lookup = lookup  # sid -> the rule's text, or None
        self._bus = bus  # None: no background explaining
        self._now = now
        self._retry_after = retry_after  # pause after the model failed in the background
        self._lock = asyncio.Lock()  # one local model run at a time
        self._clicks = 0  # people waiting for an answer; the background lets them go first
        self._queued: set[tuple[int, int]] = set()  # rule versions offered to the background
        self._sub: Subscription | None = None
        self._task: asyncio.Task[None] | None = None

    async def explain(self, alert_id: int) -> Explanation:
        alert = await asyncio.to_thread(self._repo.get, alert_id)
        if alert is None:
            raise ExplainError("that alert no longer exists")
        self._clicks += 1
        try:
            result = await self._answer(alert)
        finally:
            self._clicks -= 1
        if result is None:
            raise ExplainError(f"rule {alert.sid} was not found in the rules files")
        return result

    async def _answer(self, alert: Alert) -> Explanation | None:
        """The kept or a new explanation; None when the rule is not in the rules files."""
        style = self._explainer.style
        async with self._lock:
            hit = await asyncio.to_thread(self._repo.explanation, alert.sid, alert.rev, style=style)
            if hit:
                return Explanation(hit[1], hit[0], True)
            rule = await asyncio.to_thread(self._lookup, alert.sid)
            if rule is None:
                return None
            text = await self._explainer.explain(rule, alert)
            model = self._explainer.model
            await asyncio.to_thread(
                self._repo.put_explanation,
                alert.sid,
                alert.rev,
                model,
                text,
                self._now(),
                style=style,
            )
            return Explanation(text, model, False)

    async def start(self) -> None:
        if self._bus is None or self._task is not None:
            return
        self._sub = self._bus.subscribe(PREWARM_QUEUE, self._first_time, keep_oldest=True)
        self._task = asyncio.create_task(self._prewarm(self._sub), name="explain-prewarm")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        if self._sub is not None:
            self._sub.close()
        self._task = self._sub = None

    def _first_time(self, event: Event) -> bool:
        # shortcut: a rule skipped while the queue is full waits for the user's click this session
        if not isinstance(event, AlertRaised):
            return False
        key = (event.alert.sid, event.alert.rev)
        if key in self._queued:
            return False
        self._queued.add(key)
        return True

    async def _prewarm(self, sub: Subscription) -> None:
        async for event in sub:
            assert isinstance(event, AlertRaised)  # _first_time lets nothing else in
            while self._clicks:  # a person is waiting; the background goes after them
                await asyncio.sleep(0.5)
            try:
                await self._answer(event.alert)
            except ExplainError as exc:  # Ollama is down or the model failed: try later
                log.info("explaining in the background paused: %s", exc)
                await asyncio.sleep(self._retry_after)
            except Exception:
                log.exception("could not explain rule %d in the background", event.alert.sid)
