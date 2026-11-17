from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from snorty.core.repository import AlertRepository
from snorty.respond import BlockService, FirewallError, NeedsAdmin, refusal

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
GLOBAL = "8.8.4.4"


class FakeFirewall:
    def __init__(self) -> None:
        self.rules: set[str] = set()
        self.dns = frozenset({"1.1.1.1"})
        self.error: FirewallError | None = None
        self.calls: list[tuple[str, ...]] = []  # one entry per unblock call

    async def block(self, ip: str) -> None:
        if self.error:
            raise self.error
        self.rules.add(ip)

    async def unblock(self, *ips: str) -> None:
        if self.error:
            raise self.error
        self.calls.append(ips)
        self.rules.difference_update(ips)

    async def blocked(self) -> Sequence[str]:
        return sorted(self.rules)

    async def protected(self) -> frozenset[str]:
        return self.dns


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.repo = AlertRepository(tmp_path / "t.db")
        self.fw = FakeFirewall()
        self.clock = Clock()
        self.svc = BlockService(self.repo, self.fw, now=self.clock)


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    yield r
    r.repo.close()


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.1",
        "169.254.1.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "0.0.0.0",
    ],
)
def test_private_local_and_reserved_addresses_are_never_blocked(ip: str) -> None:
    assert refusal(ip, set()) is not None


def test_protected_addresses_and_junk_are_refused_public_ones_pass() -> None:
    assert refusal("1.1.1.1", {"1.1.1.1"}) is not None
    assert refusal("nonsense", set()) == "not an IP address"
    assert refusal(GLOBAL, {"1.1.1.1"}) is None


async def test_block_adds_a_rule_and_a_row(rig: Rig) -> None:
    out = await rig.svc.block(GLOBAL, 24, alert_id=None)
    assert out.ok and rig.fw.rules == {GLOBAL}
    (b,) = rig.svc.blocks("active")
    assert b.ip == GLOBAL and b.until == T0 + timedelta(hours=24)


async def test_a_refused_address_touches_neither_firewall_nor_table(rig: Rig) -> None:
    for ip in ("192.168.1.1", "1.1.1.1", "x"):
        assert not (await rig.svc.block(ip, 24)).ok
    assert rig.fw.rules == set() and rig.svc.blocks() == []


async def test_hours_are_bounded(rig: Rig) -> None:
    assert not (await rig.svc.block(GLOBAL, 0)).ok
    assert not (await rig.svc.block(GLOBAL, 24 * 31)).ok
    assert (await rig.svc.block(GLOBAL, None)).ok  # until unblocked
    assert rig.svc.blocks("active")[0].until is None


async def test_needing_admin_is_reported_and_nothing_is_recorded(rig: Rig) -> None:
    rig.fw.error = NeedsAdmin("blocking needs your approval")
    out = await rig.svc.block(GLOBAL, 24)
    assert not out.ok and "approval" in out.detail
    assert rig.svc.blocks() == []


async def test_unblock_removes_the_rule_and_marks_the_row(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 24)
    assert (await rig.svc.unblock(GLOBAL)).ok
    assert rig.fw.rules == set()
    assert [b.state for b in rig.svc.blocks()] == ["released"]


async def test_blocking_again_after_an_unblock_reuses_the_row(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 24)
    await rig.svc.unblock(GLOBAL)
    await rig.svc.block(GLOBAL, 1)
    (b,) = rig.svc.blocks()
    assert b.state == "active"


async def test_sweep_removes_only_expired_blocks(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 1)
    await rig.svc.block("8.8.8.4", 5)
    rig.clock.now = T0 + timedelta(hours=2)
    assert await rig.svc.sweep() == 1
    assert rig.fw.rules == {"8.8.8.4"}
    assert {b.ip: b.state for b in rig.svc.blocks()} == {GLOBAL: "expired", "8.8.8.4": "active"}


async def test_expired_blocks_are_removed_in_one_call(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 1)
    await rig.svc.block("8.8.8.4", 1)
    rig.clock.now = T0 + timedelta(hours=2)
    assert await rig.svc.sweep() == 2
    assert rig.fw.calls == [(GLOBAL, "8.8.8.4")]  # one permission prompt, not two


async def test_a_declined_sweep_waits_before_asking_again(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 1)
    rig.clock.now = T0 + timedelta(hours=2)
    rig.fw.error = NeedsAdmin("no")
    assert await rig.svc.sweep() == 0
    rig.fw.error = None
    rig.clock.now += timedelta(minutes=10)
    assert await rig.svc.sweep() == 0 and rig.fw.calls == []  # no new prompt yet
    rig.clock.now += timedelta(minutes=21)
    assert await rig.svc.sweep() == 1


async def test_sweep_with_nothing_due_asks_for_nothing(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 24)
    assert await rig.svc.sweep() == 0
    assert rig.fw.calls == []


async def test_reconcile_adopts_stray_rules_and_releases_lost_ones(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 24)
    rig.fw.rules = {"8.8.8.4"}  # the firewall lost ours and holds one Snorty has no row for
    await rig.svc.reconcile()
    assert rig.fw.rules == {"8.8.8.4"}  # nothing is written to the firewall
    assert {b.ip for b in rig.svc.blocks("active")} == {"8.8.8.4"}
    assert next(b for b in rig.svc.blocks() if b.ip == GLOBAL).state == "released"
    assert next(b for b in rig.svc.blocks() if b.ip == "8.8.8.4").until is None


async def test_a_scope_id_never_reaches_the_firewall(rig: Rig) -> None:
    for bad in ("2606:4700::1%x';calc;'", "2606:4700::1%eth0"):
        assert refusal(bad, frozenset()) is not None
        out = await rig.svc.block(bad, 1)
        assert not out.ok and rig.fw.rules == set()


async def test_a_failed_block_cleans_up_a_half_made_rule(rig: Rig) -> None:
    class Half(FakeFirewall):
        async def block(self, ip: str) -> None:
            self.rules.add(ip)
            raise FirewallError("second rule failed")

    rig.svc = BlockService(rig.repo, fw := Half(), now=rig.clock)
    assert not (await rig.svc.block(GLOBAL, 1)).ok
    assert fw.rules == set()


async def test_only_one_change_waits_for_approval_at_a_time(rig: Rig) -> None:
    import asyncio

    gate = asyncio.Event()
    inner = rig.fw.block

    async def slow(ip: str) -> None:
        await gate.wait()
        await inner(ip)

    rig.fw.block = slow  # type: ignore[method-assign]
    first = asyncio.create_task(rig.svc.block(GLOBAL, 1))
    await asyncio.sleep(0.01)
    second = await rig.svc.block("8.8.8.8", 1)
    assert not second.ok and "waiting for your approval" in second.detail
    gate.set()
    assert (await first).ok


async def test_declined_sweeps_back_off_longer_each_time(rig: Rig) -> None:
    await rig.svc.block(GLOBAL, 1)
    rig.clock.now += timedelta(hours=2)
    rig.fw.error = NeedsAdmin("declined")
    await rig.svc.sweep()
    first = rig.svc._retry_at
    assert first is not None
    rig.clock.now = first
    await rig.svc.sweep()
    assert rig.svc._retry_at is not None and rig.svc._retry_at - rig.clock.now == 2 * (
        first - T0 - timedelta(hours=2)
    )
