import time

import pytest

from snorty.notify.ports import ConsoleNotifier, WinotifyNotifier
from snorty.notify.toast import Toast

TOAST = Toast("Snort P1: x", ("TCP 10.0.0.1:1 → 10.0.0.2:2", "SID 1:5 at 01:02:03"))


async def test_console_notifier_prints_title_and_lines() -> None:
    out: list[str] = []
    await ConsoleNotifier(out.append).show(TOAST)
    assert out == ["Snort P1: x\nTCP 10.0.0.1:1 → 10.0.0.2:2\nSID 1:5 at 01:02:03"]


async def test_winotify_notifier_passes_title_and_joined_lines() -> None:
    sent: list[tuple[str, str]] = []
    await WinotifyNotifier(send=lambda t, m: sent.append((t, m))).show(TOAST)
    assert sent == [("Snort P1: x", "TCP 10.0.0.1:1 → 10.0.0.2:2\nSID 1:5 at 01:02:03")]


async def test_text_is_sanitised_again_before_it_reaches_the_library() -> None:
    """winotify pastes text unescaped into a PowerShell here-string, so a Toast built by
    hand (not through build_toast) must still be made safe."""
    sent: list[tuple[str, str]] = []
    evil = Toast('x"@; $(calc) `id` <![CDATA[ ]]>', ("a\n$(calc)", '"@\ncalc'))
    await WinotifyNotifier(send=lambda t, m: sent.append((t, m))).show(evil)
    ((title, msg),) = sent
    for text in (title, msg.replace("\n", " ")):
        assert not set(text) & set("\"'`$<>&;|%\\")
    assert "\n" in msg  # lines stay separate lines


async def test_timeout_raises() -> None:
    notifier = WinotifyNotifier(timeout=0.05, send=lambda t, m: time.sleep(0.3))
    with pytest.raises(TimeoutError):
        await notifier.show(TOAST)


async def test_library_errors_propagate() -> None:
    def boom(title: str, msg: str) -> None:
        raise RuntimeError("powershell missing")

    with pytest.raises(RuntimeError, match="powershell missing"):
        await WinotifyNotifier(send=boom).show(TOAST)


async def test_default_send_builds_a_winotify_notification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shown: list[tuple[str, str, str]] = []

    class FakeNotification:
        def __init__(self, app_id: str, title: str, msg: str = "") -> None:
            self.args = (app_id, title, msg)

        def show(self) -> None:
            shown.append(self.args)

    monkeypatch.setattr("winotify.Notification", FakeNotification)
    await WinotifyNotifier(app_id="Snorty").show(TOAST)
    assert shown == [("Snorty", "Snort P1: x", "TCP 10.0.0.1:1 → 10.0.0.2:2\nSID 1:5 at 01:02:03")]
