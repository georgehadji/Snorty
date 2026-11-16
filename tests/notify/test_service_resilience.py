import asyncio
import logging
import time

import pytest
from notify_fakes import FakeClock, RecordingNotifier, make_alert, raise_alert, settle

from snorty.core.bus import EventBus
from snorty.notify.service import NotifyConfig, NotifyService
from snorty.notify.toast import Toast


class ScriptedNotifier(RecordingNotifier):
    """Fails or hangs on chosen calls (1-based), records the rest."""

    def __init__(self, raises: dict[int, BaseException] | None = None, hang_on: int = 0) -> None:
        super().__init__()
        self.raises = raises or {}
        self.hang_on = hang_on
        self.calls = 0

    async def show(self, toast: Toast) -> None:
        self.calls += 1
        if self.calls in self.raises:
            raise self.raises[self.calls]
        if self.calls == self.hang_on:
            await asyncio.Event().wait()
        await super().show(toast)


def make(notifier: RecordingNotifier, **cfg: float) -> tuple[EventBus, NotifyService]:
    bus = EventBus()
    return bus, NotifyService(bus, notifier, NotifyConfig(**cfg), clock=FakeClock())  # type: ignore[arg-type]


@pytest.mark.parametrize("error", [RuntimeError("powershell missing"), TimeoutError()])
async def test_a_failing_notifier_is_logged_and_the_next_alert_still_toasts(
    error: BaseException, caplog: pytest.LogCaptureFixture
) -> None:
    notifier = ScriptedNotifier(raises={1: error})
    bus, service = make(notifier)
    await service.start()
    with caplog.at_level(logging.ERROR, logger="snorty.notify"):
        raise_alert(bus, make_alert(1))
        raise_alert(bus, make_alert(2))
        await settle(lambda: len(notifier.toasts) == 1)
    assert notifier.toasts[0].title.endswith("rule 2")
    assert any(r.levelno == logging.ERROR for r in caplog.records)
    await service.stop()


async def test_a_toast_that_failed_does_not_silence_its_rule_for_the_window() -> None:
    notifier = ScriptedNotifier(raises={1: RuntimeError("powershell missing")})
    bus, service = make(notifier)
    await service.start()
    raise_alert(bus, make_alert(1))
    raise_alert(bus, make_alert(1))  # same rule, same instant: used to be throttled away
    await settle(lambda: len(notifier.toasts) == 1)
    assert service.status().toasts_shown == 1
    await service.stop()


async def test_a_hanging_notifier_is_cut_off_by_the_service_timeout() -> None:
    notifier = ScriptedNotifier(hang_on=1)
    bus, service = make(notifier, show_timeout=0.05)
    await service.start()
    raise_alert(bus, make_alert(1))
    raise_alert(bus, make_alert(2))
    await settle(lambda: len(notifier.toasts) == 1)
    await service.stop()


async def test_a_blocked_consumer_never_slows_publish_and_drops_oldest() -> None:
    notifier = ScriptedNotifier(hang_on=1)
    bus, service = make(notifier, show_timeout=60.0)
    await service.start()
    raise_alert(bus, make_alert(1))
    await settle(lambda: notifier.calls == 1)  # the consumer is now stuck inside show()

    started = time.perf_counter()
    for sid in range(2, 3002):
        raise_alert(bus, make_alert(sid))
    assert time.perf_counter() - started < 1.0
    assert service._sub is not None and service._sub.dropped >= 2000  # maxsize is 1000
    await service.stop()  # cancels the stuck consumer


async def test_stop_cancels_the_consumer_and_closes_the_subscription() -> None:
    notifier = RecordingNotifier()
    bus, service = make(notifier)
    await service.start()
    await service.stop()
    raise_alert(bus, make_alert(1))
    await settle()
    assert notifier.toasts == [] and bus._subs == []


async def test_stop_without_start_and_stop_twice_are_harmless() -> None:
    bus, service = make(RecordingNotifier())
    await service.stop()
    await service.start()
    await service.stop()
    await service.stop()
    assert bus._subs == []


async def test_start_twice_does_not_double_subscribe() -> None:
    notifier = RecordingNotifier()
    bus, service = make(notifier)
    await service.start()
    await service.start()
    assert len(bus._subs) == 1
    raise_alert(bus, make_alert(1))
    await settle(lambda: len(notifier.toasts) == 1)
    await settle()
    assert len(notifier.toasts) == 1
    await service.stop()
    assert bus._subs == []


async def test_service_can_be_restarted_after_stop() -> None:
    notifier = RecordingNotifier()
    bus, service = make(notifier)
    await service.start()
    await service.stop()
    await service.start()
    raise_alert(bus, make_alert(1))
    await settle(lambda: len(notifier.toasts) == 1)
    await service.stop()


async def test_an_unexpected_error_in_handling_does_not_kill_the_consumer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import snorty.notify.service as module

    real = module.build_toast
    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> Toast:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("bad alert")
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(module, "build_toast", flaky)
    notifier = RecordingNotifier()
    bus, service = make(notifier)
    await service.start()
    raise_alert(bus, make_alert(1))
    raise_alert(bus, make_alert(2))
    await settle(lambda: len(notifier.toasts) == 1)
    await service.stop()
