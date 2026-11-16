from notify_fakes import FakeClock, RecordingNotifier, make_alert, raise_alert, settle

from snorty.core.bus import EventBus
from snorty.notify.service import NotifyConfig, NotifyService, NotifyStatus


async def test_status_counts_toasts_shown_not_alerts_seen() -> None:
    bus = EventBus()
    notifier = RecordingNotifier()
    service = NotifyService(bus, notifier, NotifyConfig(), clock=FakeClock())
    assert service.status() == NotifyStatus(toasts_shown=0, min_priority=1)
    await service.start()
    raise_alert(bus, make_alert(sid=1))
    raise_alert(bus, make_alert(sid=1))  # throttled: same SID inside the window
    raise_alert(bus, make_alert(sid=2, priority=3))  # below the priority threshold
    await settle(lambda: len(notifier.toasts) == 1)
    await settle()
    assert service.status().toasts_shown == 1
    await service.stop()
