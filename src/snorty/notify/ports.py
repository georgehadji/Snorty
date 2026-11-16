"""How a toast reaches the screen. The rest of the module only knows `Notifier`."""

import asyncio
import sys
from collections.abc import Callable
from typing import Protocol

from snorty.notify.toast import LINE_LIMIT, TITLE_LIMIT, Toast, sanitize


class Notifier(Protocol):
    async def show(self, toast: Toast) -> None: ...


def _print_safe(text: str) -> None:
    """print() that cannot crash on a console whose encoding lacks the arrow (cp1252)."""
    enc = sys.stdout.encoding or "utf-8"
    print(text.encode(enc, "replace").decode(enc))


class ConsoleNotifier:
    """Prints instead of showing a toast: for `--dry-run` and headless use."""

    def __init__(self, out: Callable[[str], object] = _print_safe) -> None:
        self._out = out

    async def show(self, toast: Toast) -> None:
        self._out("\n".join((toast.title, *toast.lines)))


def _winotify_send(app_id: str) -> Callable[[str, str], None]:
    def send(title: str, msg: str) -> None:
        import winotify  # imported late: only the real notifier needs it

        winotify.Notification(app_id=app_id, title=title, msg=msg).show()

    return send


class WinotifyNotifier:
    """Windows toast through `winotify` (1.1.0).

    Security note, from reading its source: `Notification.show()` pastes `title`, `msg`
    and the tag (= title) unescaped into a PowerShell expandable here-string
    (`@" ... "@`, with `<![CDATA[...]]>`) and runs it with `-ExecutionPolicy Bypass`. A `$(...)`,
    a backtick, a double quote or `]]>` in the text would execute or break out. Alert
    messages come from third-party rule files, so text is sanitised again here, right
    before the library call, even though `build_toast` already did it.
    """

    def __init__(
        self,
        app_id: str = "Snorty",
        timeout: float = 10.0,
        send: Callable[[str, str], object] | None = None,
    ) -> None:
        self._timeout = timeout
        self._send = send or _winotify_send(app_id)

    async def show(self, toast: Toast) -> None:
        title = sanitize(toast.title, TITLE_LIMIT)
        msg = "\n".join(sanitize(line, LINE_LIMIT) for line in toast.lines)
        await asyncio.wait_for(asyncio.to_thread(self._send, title, msg), self._timeout)
