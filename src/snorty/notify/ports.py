"""How a toast reaches the screen. The rest of the module only knows `Notifier`."""

import asyncio
import json
import logging
import sys
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol
from urllib.parse import urlsplit

from snorty.notify.toast import LINE_LIMIT, TITLE_LIMIT, Toast, sanitize

log = logging.getLogger("snorty.notify")


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


Post = Callable[[str, bytes, float], object]


def valid_channel_url(url: object) -> bool:
    """http or https with a host. urllib would also open file: and ftp: addresses."""
    if not isinstance(url, str):
        return False
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _urllib_post(url: str, body: bytes, timeout: float) -> None:
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked
        resp.read(1024)


class _HttpNotifier:
    """Sends one JSON POST per toast. The URL may hold a secret, so it is never logged."""

    kind = "http"

    def __init__(self, url: str, timeout: float = 10.0, post: Post | None = None) -> None:
        if not valid_channel_url(url):
            raise ValueError("a channel URL must be http or https")
        self._url = url
        self._timeout = timeout
        self._post = post or _urllib_post

    def _payload(self, title: str, lines: Sequence[str]) -> dict[str, object]:
        raise NotImplementedError

    def _target(self) -> str:
        return self._url

    async def show(self, toast: Toast) -> None:
        title = sanitize(toast.title, TITLE_LIMIT)
        lines = [sanitize(line, LINE_LIMIT) for line in toast.lines]
        body = json.dumps(self._payload(title, lines)).encode()
        await asyncio.wait_for(
            asyncio.to_thread(self._post, self._target(), body, self._timeout), self._timeout + 1
        )


class WebhookNotifier(_HttpNotifier):
    """POSTs {"title", "lines", "text"} as JSON to any URL."""

    kind = "webhook"

    def _payload(self, title: str, lines: Sequence[str]) -> dict[str, object]:
        return {"title": title, "lines": lines, "text": "\n".join((title, *lines))}


class NtfyNotifier(_HttpNotifier):
    """Publishes to an ntfy topic: `https://ntfy.sh/<topic>` or a self-hosted server. Uses ntfy's
    JSON publishing, so a title with non-Latin text never has to fit in an HTTP header."""

    kind = "ntfy"

    def __init__(self, url: str, timeout: float = 10.0, post: Post | None = None) -> None:
        super().__init__(url, timeout, post)
        parts = urlsplit(url)
        self._topic = parts.path.strip("/").rsplit("/", 1)[-1]
        if not self._topic:
            raise ValueError("an ntfy URL must end with the topic name")
        self._server = f"{parts.scheme}://{parts.netloc}/"

    def _target(self) -> str:
        return self._server

    def _payload(self, title: str, lines: Sequence[str]) -> dict[str, object]:
        return {"topic": self._topic, "title": title, "message": "\n".join(lines) or title}


class FanOutNotifier:
    """Shows a toast on every channel. One that fails is logged by kind and number, never by
    address, and does not stop the others. It raises only when none of them got the toast."""

    def __init__(self, channels: Sequence[Notifier]) -> None:
        self._channels = tuple(channels)

    async def show(self, toast: Toast) -> None:
        results = await asyncio.gather(
            *(c.show(toast) for c in self._channels), return_exceptions=True
        )
        failed = [(i, r) for i, r in enumerate(results) if isinstance(r, BaseException)]
        for i, err in failed:
            kind = getattr(self._channels[i], "kind", type(self._channels[i]).__name__)
            log.warning("notification channel %d (%s) failed: %s", i, kind, type(err).__name__)
        if failed and len(failed) == len(self._channels):
            raise failed[0][1]


def channel_notifier(channels: Sequence[Mapping[str, object]]) -> Notifier:
    """The Windows toast plus one notifier per configured `{kind, url}` channel."""
    made: list[Notifier] = [WinotifyNotifier()]
    for c in channels:
        url = str(c["url"])
        made.append(NtfyNotifier(url) if c["kind"] == "ntfy" else WebhookNotifier(url))
    return FanOutNotifier(made)
