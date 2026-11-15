import asyncio

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import Event, RulesUpdated, SensorStateChanged


def ev(n: int) -> RulesUpdated:
    return RulesUpdated(ok=True, rule_count=n, detail="")


async def take(sub: Subscription, n: int) -> list[Event]:
    return [await asyncio.wait_for(anext(sub), 1) for _ in range(n)]


async def test_three_subscribers_get_every_event_in_order() -> None:
    bus = EventBus()
    subs = [bus.subscribe() for _ in range(3)]
    for i in range(5):
        bus.publish(ev(i))
    for sub in subs:
        assert await take(sub, 5) == [ev(i) for i in range(5)]


async def test_only_events_after_subscribing() -> None:
    bus = EventBus()
    bus.publish(ev(0))
    sub = bus.subscribe()
    bus.publish(ev(1))
    assert await take(sub, 1) == [ev(1)]


async def test_overflow_drops_oldest_and_counts() -> None:
    bus = EventBus()
    sub = bus.subscribe(maxsize=3)
    for i in range(10):
        bus.publish(ev(i))
    assert sub.dropped == 7
    assert await take(sub, 3) == [ev(7), ev(8), ev(9)]


async def test_publish_never_blocks_on_stalled_subscriber() -> None:
    bus = EventBus()
    bus.subscribe(maxsize=1)  # never read
    live = bus.subscribe()
    for i in range(100):
        bus.publish(ev(i))  # plain call: would hang the test if it could block
    assert len(await take(live, 100)) == 100


async def test_closed_subscription_gets_nothing_and_iteration_ends() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    bus.publish(ev(1))
    sub.close()
    bus.publish(ev(2))
    assert [e async for e in sub] == []
    assert sub.dropped == 0


async def test_close_wakes_a_waiting_reader() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    reader = asyncio.create_task(anext(sub))
    await asyncio.sleep(0)
    sub.close()
    try:
        await asyncio.wait_for(reader, 1)
    except StopAsyncIteration:
        pass
    else:
        raise AssertionError("expected StopAsyncIteration")


async def test_other_event_types_flow() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    event = SensorStateChanged(old="stopped", new="running", reason=None)
    bus.publish(event)
    assert await take(sub, 1) == [event]
