import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from dash_fakes import FakeSensor, alert, make_services

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised, Event, RulesUpdated, SensorStateChanged
from snorty.dashboard.app import build_app
from snorty.dashboard.sse import format_frame, sse_frames
from snorty.dashboard.views import AlertFilters, alert_matches
from snorty.sensor import State

TOKEN = "t" * 64
PORT = 8765


async def render_alerts(ev: Event) -> tuple[str, str] | None:
    return ("alert", ev.alert.msg) if isinstance(ev, AlertRaised) else None


def stream(
    bus: EventBus, *, heartbeat: float = 5.0, maxsize: int = 100
) -> tuple[AsyncIterator[str], list[Subscription]]:
    subs: list[Subscription] = []

    def subscribe() -> Subscription:
        subs.append(bus.subscribe(maxsize))
        return subs[-1]

    return sse_frames(subscribe, render_alerts, heartbeat=heartbeat), subs


def test_format_frame_prefixes_every_line_and_ends_with_a_blank_line() -> None:
    assert format_frame("alert", "one") == "event: alert\ndata: one\n\n"
    assert format_frame("x", "a\nb\r\nc") == "event: x\ndata: a\ndata: b\ndata: c\n\n"
    assert format_frame("x", "") == "event: x\ndata: \n\n"


async def test_first_frame_is_a_comment_then_events_arrive() -> None:
    bus = EventBus()
    gen, _ = stream(bus)
    assert await anext(gen) == ": connected\n\n"
    bus.publish(AlertRaised(alert(msg="hello")))
    assert await anext(gen) == "event: alert\ndata: hello\n\n"
    await gen.aclose()  # type: ignore[attr-defined]


async def test_events_the_renderer_skips_produce_no_frame() -> None:
    bus = EventBus()
    gen, _ = stream(bus, heartbeat=0.02)
    await anext(gen)
    bus.publish(RulesUpdated(True, 1, "x"))  # render_alerts returns None for this
    assert await anext(gen) == ": keep-alive\n\n"
    await gen.aclose()  # type: ignore[attr-defined]


async def test_a_heartbeat_comment_is_sent_when_idle() -> None:
    bus = EventBus()
    gen, _ = stream(bus, heartbeat=0.02)
    await anext(gen)
    assert await anext(gen) == ": keep-alive\n\n"
    assert await anext(gen) == ": keep-alive\n\n"
    await gen.aclose()  # type: ignore[attr-defined]


async def test_closing_the_stream_closes_the_subscription() -> None:
    bus = EventBus()
    gen, subs = stream(bus)
    await anext(gen)
    await gen.aclose()  # type: ignore[attr-defined]
    bus.publish(AlertRaised(alert()))
    with pytest.raises(StopAsyncIteration):  # a closed subscription only ends
        await asyncio.wait_for(anext(subs[0]), 1)


async def test_cancelling_a_waiting_stream_closes_the_subscription() -> None:
    bus = EventBus()
    gen, subs = stream(bus)
    await anext(gen)
    task = asyncio.create_task(anext(gen))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(subs[0]), 1)


async def test_the_stream_ends_when_the_bus_subscription_is_closed() -> None:
    bus = EventBus()
    gen, subs = stream(bus)
    await anext(gen)
    subs[0].close()
    with pytest.raises(StopAsyncIteration):
        await anext(gen)


async def test_a_slow_consumer_keeps_only_the_newest_events() -> None:
    bus = EventBus()
    gen, subs = stream(bus, heartbeat=0.02, maxsize=5)
    await anext(gen)
    for i in range(100):
        bus.publish(AlertRaised(alert(msg=f"m{i}")))
    got = []
    while len(got) < 5:
        frame = await anext(gen)
        if frame.startswith("event"):
            got.append(frame)
    assert [f.split("data: ")[1].strip() for f in got] == [f"m{i}" for i in range(95, 100)]
    assert subs[0].dropped == 95
    await gen.aclose()  # type: ignore[attr-defined]


def test_alert_matches() -> None:
    a = alert(2001, priority=2)
    assert alert_matches(AlertFilters(None, None, "24h", 1), a)
    assert alert_matches(AlertFilters(2001, None, "24h", 1), a)
    assert not alert_matches(AlertFilters(2002, None, "24h", 1), a)
    assert alert_matches(AlertFilters(None, 2, "24h", 1), a)
    assert not alert_matches(AlertFilters(None, 1, "24h", 1), a)


# ---- the route, driven at the ASGI level so the infinite stream can be read as it grows ----


class Conn:
    def __init__(self, app: Any, path: str, query: str = "") -> None:
        self.out: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.gone = asyncio.Event()
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "headers": [(b"host", f"127.0.0.1:{PORT}".encode())],
            "scheme": "http",
            "server": ("127.0.0.1", PORT),
            "client": ("127.0.0.1", 1),
            "root_path": "",
        }
        self.task = asyncio.create_task(app(scope, self._receive, self.out.put))

    async def _receive(self) -> dict[str, Any]:
        await self.gone.wait()
        return {"type": "http.disconnect"}

    async def next(self) -> dict[str, Any]:
        return await asyncio.wait_for(self.out.get(), 2)

    async def text(self) -> str:
        return (await self.next())["body"].decode()

    async def hang_up(self) -> None:
        self.gone.set()
        await asyncio.wait_for(self.task, 2)


def make(tmp_path: Path, heartbeat: float = 5.0) -> tuple[Any, Any]:
    services = make_services(tmp_path)
    return build_app(services, token=TOKEN, port=PORT, heartbeat=heartbeat), services


async def test_route_streams_alerts_sensor_and_rules_fragments(tmp_path: Path) -> None:
    app, s = make(tmp_path)
    conn = Conn(app, "/events")
    head = await conn.next()
    assert head["status"] == 200
    hdrs = dict(head["headers"])
    assert hdrs[b"content-type"].startswith(b"text/event-stream")
    assert hdrs[b"cache-control"] == b"no-store"
    assert b"content-security-policy" in hdrs
    assert await conn.text() == ": connected\n\n"

    s.bus.publish(AlertRaised(alert(2001, msg="live <b>one</b>")))
    frame = await conn.text()
    assert frame.startswith("event: alert\n")
    assert "live &lt;b&gt;one&lt;/b&gt;" in frame and "<b>one</b>" not in frame
    assert "\n\n" not in frame[:-2]  # one frame: blank lines only at the end

    assert isinstance(s.sensor, FakeSensor)
    s.sensor.set_state(State.RUNNING)
    s.bus.publish(SensorStateChanged("stopped", "running", None))
    frame = await conn.text()
    assert frame.startswith("event: sensor\n") and 'id="sensor-card"' in frame
    assert "Running" in frame

    s.bus.publish(RulesUpdated(True, 777, "ok"))
    frame = await conn.text()
    assert frame.startswith("event: rules\n") and 'id="rules-summary"' in frame

    await conn.hang_up()
    s.repo.close()


async def test_route_applies_the_sid_and_priority_filters_to_alerts(tmp_path: Path) -> None:
    app, s = make(tmp_path)
    conn = Conn(app, "/events", "sid=222&range=24h")
    await conn.next()
    await conn.text()
    s.bus.publish(AlertRaised(alert(111, msg="not me")))
    s.bus.publish(AlertRaised(alert(222, msg="me")))
    frame = await conn.text()
    assert "me" in frame and "not me" not in frame
    await conn.hang_up()
    s.repo.close()


async def test_route_rejects_bad_filters_without_subscribing(tmp_path: Path) -> None:
    app, s = make(tmp_path)
    conn = Conn(app, "/events", "sid=abc")
    assert (await conn.next())["status"] == 422
    await conn.hang_up()
    s.bus.publish(AlertRaised(alert()))  # nobody is subscribed, so nothing can pile up
    s.repo.close()


async def test_route_frees_the_subscription_when_the_client_leaves(tmp_path: Path) -> None:
    app, s = make(tmp_path)
    conn = Conn(app, "/events")
    await conn.next()
    await conn.text()
    await conn.hang_up()
    probe = s.bus.subscribe()
    s.bus.publish(AlertRaised(alert()))
    await anext(probe)  # the probe gets it; the departed client's queue is gone
    assert len(s.bus._subs) == 1
    probe.close()
    s.repo.close()
