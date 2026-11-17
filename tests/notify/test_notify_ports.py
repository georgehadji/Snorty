import json
import time

import pytest

from snorty.notify.ports import (
    ConsoleNotifier,
    FanOutNotifier,
    NtfyNotifier,
    WebhookNotifier,
    WinotifyNotifier,
)
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


async def test_console_default_survives_a_console_that_cannot_encode_the_arrow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    raw = io.BytesIO()
    monkeypatch.setattr("sys.stdout", io.TextIOWrapper(raw, encoding="cp1252", errors="strict"))
    await ConsoleNotifier().show(TOAST)
    import sys

    sys.stdout.flush()
    assert b"Snort P1: x" in raw.getvalue()


class Wire:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[tuple[str, dict[str, object]]] = []
        self.fail = fail

    def __call__(self, url: str, body: bytes, timeout: float) -> None:
        if self.fail:
            raise OSError(f"cannot reach {url}")
        self.sent.append((url, json.loads(body)))


async def test_webhook_posts_title_lines_and_text() -> None:
    wire = Wire()
    await WebhookNotifier("https://hooks.example/abc", post=wire).show(TOAST)
    ((url, body),) = wire.sent
    assert url == "https://hooks.example/abc"
    assert body["title"] == "Snort P1: x" and len(body["lines"]) == 2  # type: ignore[arg-type]
    assert str(body["text"]).startswith("Snort P1: x\n")


async def test_ntfy_publishes_as_json_to_the_server_root() -> None:
    wire = Wire()
    await NtfyNotifier("https://ntfy.sh/my-topic", post=wire).show(TOAST)
    ((url, body),) = wire.sent
    assert url == "https://ntfy.sh/"
    assert body["topic"] == "my-topic" and body["title"] == "Snort P1: x"


async def test_ntfy_on_a_self_hosted_path_uses_the_last_segment() -> None:
    wire = Wire()
    await NtfyNotifier("http://nas.lan:8080/ntfy/alerts", post=wire).show(TOAST)
    assert wire.sent[0][0] == "http://nas.lan:8080/" and wire.sent[0][1]["topic"] == "alerts"


@pytest.mark.parametrize("url", ["file:///c:/x", "ftp://h/x", "javascript:1", "https://", "x"])
def test_channels_refuse_other_schemes(url: str) -> None:
    with pytest.raises(ValueError, match="http"):
        WebhookNotifier(url)


def test_ntfy_needs_a_topic() -> None:
    with pytest.raises(ValueError, match="topic"):
        NtfyNotifier("https://ntfy.sh/")


async def test_fan_out_survives_one_dead_channel_and_never_logs_the_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    good, bad = Wire(), Wire(fail=True)
    fan = FanOutNotifier(
        [
            WebhookNotifier("https://a.example/s3cret", post=bad),
            NtfyNotifier("https://n/t", post=good),
        ]
    )
    with caplog.at_level("WARNING", logger="snorty.notify"):
        await fan.show(TOAST)
    assert len(good.sent) == 1
    assert "webhook" in caplog.text and "s3cret" not in caplog.text


async def test_fan_out_raises_when_every_channel_failed() -> None:
    fan = FanOutNotifier([WebhookNotifier("https://a.example/x", post=Wire(fail=True))])
    with pytest.raises(OSError):
        await fan.show(TOAST)
