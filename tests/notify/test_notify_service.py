from collections.abc import AsyncIterator
from datetime import timedelta, timezone

import pytest
from notify_fakes import FakeClock, RecordingNotifier, make_alert, raise_alert, settle

from snorty.core.bus import EventBus
from snorty.core.events import SensorStateChanged
from snorty.notify.service import NotifyConfig, NotifyService


class Rig:
    def __init__(self, config: NotifyConfig | None = None) -> None:
        self.bus = EventBus()
        self.notifier = RecordingNotifier()
        self.clock = FakeClock()
        self.service = NotifyService(
            self.bus, self.notifier, config or NotifyConfig(), clock=self.clock
        )


@pytest.fixture
async def rig() -> AsyncIterator[Rig]:
    r = Rig()
    await r.service.start()
    yield r
    await r.service.stop()


async def test_live_priority_one_alert_gives_one_toast(rig: Rig) -> None:
    raise_alert(rig.bus, make_alert(1000002, msg="NIDS test - uid=0(root) response"))
    await settle(lambda: len(rig.notifier.toasts) == 1)
    await settle()
    (toast,) = rig.notifier.toasts
    assert toast.title == "Snort P1: NIDS test - uid=0(root) response"
    assert toast.lines == ("TCP 10.0.0.1:4444 → 10.0.0.2:80", "SID 1:1000002 at 01:02:03")


async def test_lower_priority_alerts_are_ignored(rig: Rig) -> None:
    raise_alert(rig.bus, make_alert(1, priority=2))
    raise_alert(rig.bus, make_alert(2, priority=3))
    await settle()
    assert rig.notifier.toasts == []


async def test_min_priority_moves_the_cut_off() -> None:
    rig = Rig(NotifyConfig(min_priority=2))
    await rig.service.start()
    for sid, prio in ((1, 1), (2, 2), (3, 3)):
        raise_alert(rig.bus, make_alert(sid, priority=prio))
    await settle(lambda: len(rig.notifier.toasts) == 2)
    await settle()
    assert [t.title[:9] for t in rig.notifier.toasts] == ["Snort P1:", "Snort P2:"]
    await rig.service.stop()


async def test_other_events_are_ignored(rig: Rig) -> None:
    rig.bus.publish(SensorStateChanged("stopped", "running", None))
    await settle()
    assert rig.notifier.toasts == []


async def test_burst_of_one_sid_gives_one_toast_then_a_summary(rig: Rig) -> None:
    for _ in range(500):
        raise_alert(rig.bus, make_alert(7))
    await settle(lambda: len(rig.notifier.toasts) == 1)
    await settle()
    assert len(rig.notifier.toasts) == 1

    rig.clock.now += 301
    raise_alert(rig.bus, make_alert(7))
    await settle(lambda: len(rig.notifier.toasts) == 2)
    assert rig.notifier.toasts[1].lines[-1] == "+499 more"


async def test_global_cap_and_the_other_alerts_summary(rig: Rig) -> None:
    for sid in range(1, 9):  # 8 different SIDs at once; the cap is 6
        raise_alert(rig.bus, make_alert(sid))
    await settle(lambda: len(rig.notifier.toasts) == 6)
    await settle()
    assert len(rig.notifier.toasts) == 6

    rig.clock.now += 61
    raise_alert(rig.bus, make_alert(99))
    await settle(lambda: len(rig.notifier.toasts) == 7)
    assert rig.notifier.toasts[6].lines[-1] == "+2 other alerts"


async def test_time_is_shown_in_the_configured_zone() -> None:
    rig = Rig(NotifyConfig(tz=timezone(timedelta(hours=5, minutes=30))))
    await rig.service.start()
    raise_alert(rig.bus, make_alert())
    await settle(lambda: len(rig.notifier.toasts) == 1)
    assert rig.notifier.toasts[0].lines[1].endswith("at 06:32:03")
    await rig.service.stop()


async def test_start_subscribes_before_it_returns() -> None:
    rig = Rig()
    await rig.service.start()
    raise_alert(rig.bus, make_alert())  # published immediately after start()
    await settle(lambda: len(rig.notifier.toasts) == 1)
    await rig.service.stop()


async def test_a_flood_of_low_priority_alerts_cannot_evict_a_priority_one_alert(rig: Rig) -> None:
    """The queue holds 1000: a priority-1 alert published first must survive 1200 others."""
    raise_alert(rig.bus, make_alert(1000002, priority=1))
    for n in range(1200):
        raise_alert(rig.bus, make_alert(2000000 + n, priority=2))
    await settle(lambda: len(rig.notifier.toasts) == 1)
    assert rig.notifier.toasts[0].title.endswith("rule 1000002")
