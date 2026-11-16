import pytest
from notify_fakes import RecordingNotifier

from snorty.notify.__main__ import main, sample_alert
from snorty.notify.toast import Toast


class Boom:
    async def show(self, toast: Toast) -> None:
        raise RuntimeError("powershell missing")


def test_sample_alert_uses_priority_and_message() -> None:
    a = sample_alert(2, "hello")
    assert (a.priority, a.msg) == (2, "hello")


def test_test_command_shows_one_toast_and_exits_zero() -> None:
    notifier = RecordingNotifier()
    assert main(["test", "--msg", "hi there"], notifier=notifier) == 0
    (toast,) = notifier.toasts
    assert toast.title == "Snort P1: hi there"


def test_priority_option_reaches_the_toast() -> None:
    notifier = RecordingNotifier()
    assert main(["test", "--priority", "3"], notifier=notifier) == 0
    assert notifier.toasts[0].title.startswith("Snort P3:")


def test_dry_run_prints_instead_of_toasting(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test", "--dry-run"]) == 0
    assert "Snort P1:" in capsys.readouterr().out


def test_a_failing_notifier_exits_one_with_the_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test"], notifier=Boom()) == 1
    assert "powershell missing" in capsys.readouterr().err


def test_a_hostile_message_is_made_safe() -> None:
    notifier = RecordingNotifier()
    main(["test", "--msg", 'x"@; $(calc)'], notifier=notifier)
    assert not set(notifier.toasts[0].title) & set("\"'`$<>&;|%\\")
