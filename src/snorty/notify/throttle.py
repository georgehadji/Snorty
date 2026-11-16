"""Per-SID throttle with a global cap. Pure: the caller supplies the time."""

import math
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Decision:
    show: bool
    same_sid: int  # alerts of this SID suppressed since its last toast
    other: int  # alerts dropped by the global cap since the last toast


@dataclass(slots=True)
class _Entry:
    shown_at: float
    suppressed: int = 0


class Throttle:
    def __init__(
        self, window: float = 300.0, cap: int = 6, cap_window: float = 60.0, max_sids: int = 1000
    ) -> None:
        self._window = window
        self._cap = cap
        self._cap_window = cap_window
        self._max_sids = max_sids
        self._sids: OrderedDict[int, _Entry] = OrderedDict()
        self._shown: deque[float] = deque()  # times of recent toasts, oldest first
        self._other = 0

    @property
    def tracked(self) -> int:
        return len(self._sids)

    def decide(self, sid: int, now: float) -> Decision:
        entry = self._sids.get(sid)
        if entry is not None and now - entry.shown_at < self._window:
            entry.suppressed += 1  # the window runs from the last toast, not the last alert
            return Decision(False, 0, 0)
        while self._shown and self._shown[0] <= now - self._cap_window:
            self._shown.popleft()
        if len(self._shown) >= self._cap:
            self._other += 1
            return Decision(False, 0, 0)

        decision = Decision(True, entry.suppressed if entry else 0, self._other)
        self._other = 0
        self._shown.append(now)
        self._sweep(now)
        self._sids.pop(sid, None)
        self._sids[sid] = _Entry(now)
        while len(self._sids) > self._max_sids:
            self._sids.popitem(last=False)
        return decision

    def release(self, sid: int, decision: Decision) -> None:
        """The toast `decision` allowed could not be shown. Let this SID try again at once and
        give back the counts that toast would have reported. The global cap slot stays used,
        so a broken notifier is retried at most `cap` times per window."""
        if decision.same_sid:
            self._sids[sid] = _Entry(-math.inf, decision.same_sid)  # window long over
        else:
            self._sids.pop(sid, None)
        self._other += decision.other

    def _sweep(self, now: float) -> None:
        """Forget SIDs whose window is over and that have nothing left to report."""
        stale = [
            sid
            for sid, e in self._sids.items()
            if e.suppressed == 0 and now - e.shown_at >= self._window
        ]
        for sid in stale:
            del self._sids[sid]
