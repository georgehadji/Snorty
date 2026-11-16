"""Run something once a day at a local clock time while the app is open."""

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import date, datetime, timedelta

log = logging.getLogger(__name__)

CHUNK_SECONDS = 60  # wake this often so a clock change or a suspended PC is noticed
GRACE = timedelta(hours=1)  # later than this after the set time, today's run is skipped
_TIME = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")


async def run_daily(
    action: Callable[[], Awaitable[object]],
    at: str,
    *,
    now: Callable[[], datetime] = datetime.now,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Call `action` once a day at local time `at` ("HH:MM"); an empty `at` does nothing.

    A run missed because the PC was off or asleep is not caught up. A failing `action` is
    logged and the schedule goes on. Cancel the task to stop."""
    if not at:
        return
    m = _TIME.fullmatch(at)
    if not m:
        raise ValueError(f'time must be "HH:MM" (24 hours), got {at!r}')
    hour, minute = int(m[1]), int(m[2])
    last_run: date | None = None
    while True:
        t = now()
        target = t.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= t or last_run == target.date():
            target += timedelta(days=1)
        while (remaining := (target - now()).total_seconds()) > 0:
            await sleep(min(remaining, CHUNK_SECONDS))
        last_run = target.date()
        if now() - target > GRACE:
            continue  # woke up long after the set time: wait for tomorrow
        try:
            await action()
        except Exception:
            log.exception("scheduled job failed")
