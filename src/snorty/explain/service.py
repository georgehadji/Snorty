"""Explain an alert's rule with a local model, and remember the answer per (sid, rev) so the
model runs once for each rule version, not once per click."""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from snorty.core.repository import AlertRepository
from snorty.explain.ports import Explainer, ExplainError


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
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._repo = repo
        self._explainer = explainer
        self._lookup = lookup  # sid -> the rule's text, or None
        self._now = now
        self._lock = asyncio.Lock()  # one local model run at a time

    async def explain(self, alert_id: int) -> Explanation:
        alert = await asyncio.to_thread(self._repo.get, alert_id)
        if alert is None:
            raise ExplainError("that alert no longer exists")
        async with self._lock:
            hit = await asyncio.to_thread(self._repo.explanation, alert.sid, alert.rev)
            if hit:
                return Explanation(hit[1], hit[0], True)
            rule = await asyncio.to_thread(self._lookup, alert.sid)
            if rule is None:
                raise ExplainError(f"rule {alert.sid} was not found in the rules files")
            text = await self._explainer.explain(rule, alert)
            model = self._explainer.model
            await asyncio.to_thread(
                self._repo.put_explanation, alert.sid, alert.rev, model, text, self._now()
            )
            return Explanation(text, model, False)
