"""Block and unblock addresses in the firewall, and keep a record that survives a restart.

Manual only: nothing here blocks on its own. Every block is a row in the `blocks` table, so it
can be listed, expires on schedule and can be reversed."""

import asyncio
import contextlib
import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from snorty.core.models import Block
from snorty.core.repository import AlertRepository
from snorty.respond.policy import refusal
from snorty.respond.ports import Firewall, FirewallError

log = logging.getLogger("snorty.respond")

MAX_HOURS = 24 * 30  # a block is meant to be temporary
SWEEP_SECONDS = 60.0
RETRY_AFTER = timedelta(minutes=30)  # after the user declined the permission prompt


@dataclass(frozen=True, slots=True)
class Outcome:
    ok: bool
    detail: str


class BlockService:
    def __init__(
        self,
        repo: AlertRepository,
        firewall: Firewall,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sweep_every: float = SWEEP_SECONDS,
    ) -> None:
        self._repo = repo
        self._fw = firewall
        self._now = now
        self._every = sweep_every
        self._task: asyncio.Task[None] | None = None
        self._retry_at: datetime | None = None
        self._declines = 0
        self._busy = asyncio.Lock()

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="respond-sweep")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._task = None

    async def _run(self) -> None:
        await self.reconcile()
        while True:
            await self.sweep()
            await asyncio.sleep(self._every)

    def blocks(self, state: str | None = None) -> list[Block]:
        return self._repo.blocks(state)

    async def block(self, ip: str, hours: float | None, alert_id: int | None = None) -> Outcome:
        """Block `ip` for `hours` (None: until unblocked)."""
        if hours is not None and not 0 < hours <= MAX_HOURS:
            return Outcome(False, f"hours must be from 1 to {MAX_HOURS}")
        if self._busy.locked():
            return Outcome(False, "another change is waiting for your approval")
        async with self._busy:
            try:
                if "%" in ip:
                    raise ValueError(ip)
                ip = str(ipaddress.ip_address(ip))
                reason = refusal(ip, await self._fw.protected())
                if reason:
                    return Outcome(False, f"{ip} not blocked: {reason}")
                await self._fw.block(ip)
            except ValueError:
                return Outcome(False, "not an IP address")
            except FirewallError as exc:
                with contextlib.suppress(FirewallError):  # a half-made pair of rules must not stay
                    await self._fw.unblock(ip)
                return Outcome(False, f"{ip} not blocked: {exc}")
        now = self._now()
        until = now + timedelta(hours=hours) if hours else None
        await asyncio.to_thread(self._repo.put_block, Block(ip, now, until, alert_id, "active"))
        return Outcome(True, f"{ip} blocked" + (f" for {hours:g} h" if hours else ""))

    async def unblock(self, ip: str) -> Outcome:
        if self._busy.locked():
            return Outcome(False, "another change is waiting for your approval")
        async with self._busy:
            try:
                await self._fw.unblock(ip)
            except FirewallError as exc:
                return Outcome(False, f"{ip} not unblocked: {exc}")
        await asyncio.to_thread(self._repo.set_block_state, ip, "released")
        return Outcome(True, f"{ip} unblocked")

    async def sweep(self) -> int:
        """Remove blocks whose time is up, in one go; returns how many. Removing needs the
        user's approval, so a refusal is not retried until `RETRY_AFTER` has passed."""
        now = self._now()
        if (self._retry_at and now < self._retry_at) or self._busy.locked():
            return 0
        due = [
            b.ip
            for b in await asyncio.to_thread(self._repo.blocks, "active")
            if b.until and b.until <= now
        ]
        if not due:
            return 0
        async with self._busy:
            try:
                await self._fw.unblock(*due)
            except FirewallError:
                log.warning("could not remove %d expired block(s); will ask again later", len(due))
                self._declines += 1  # 30 min, 1 h, 2 h ... at most a day
                self._retry_at = now + min(
                    RETRY_AFTER * 2 ** (self._declines - 1), timedelta(days=1)
                )
                return 0
        self._declines = 0
        for ip in due:
            await asyncio.to_thread(self._repo.set_block_state, ip, "expired")
        return len(due)

    async def reconcile(self) -> None:
        """Make the table and the firewall agree at start. The firewall is what really blocks:
        a rule with no row is adopted (and can then be reversed), and a row whose rule is gone
        is marked released. Nothing is written to the firewall, so no approval is asked."""
        try:
            present = set(await self._fw.blocked())
        except FirewallError:
            log.warning("could not read the firewall rules; the block list may be out of date")
            return
        rows = {b.ip: b for b in await asyncio.to_thread(self._repo.blocks, "active")}
        now = self._now()
        for ip in present - rows.keys():
            await asyncio.to_thread(self._repo.put_block, Block(ip, now, None, None, "active"))
        for ip in rows.keys() - present:
            await asyncio.to_thread(self._repo.set_block_state, ip, "released")
