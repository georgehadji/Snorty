"""Input checks and the local-only security shell (Host, Origin, token, headers)."""

import hmac
import logging
import re
import secrets
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger(__name__)
TOKEN_HEADER = "x-snorty-token"
MAX_FORM_BYTES = 256 * 1024
_MAX_SID = 2**31 - 1
_RANGES = ("1h", "24h", "7d", "all")
_HOME_NET = re.compile(r"[A-Za-z0-9_.:/,!$\[\] ]{1,200}")
_PCAP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,58}\.pcap")
_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
_SECURITY_HEADERS = (
    (b"content-security-policy", b"default-src 'self'; frame-ancestors 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
)


def valid_sid(text: str) -> int:
    if not (text.isascii() and text.isdigit() and len(text) <= 10):
        raise ValueError("sid must be a positive whole number")
    value = int(text)
    if not 0 < value <= _MAX_SID:
        raise ValueError("sid must be a positive whole number")
    return value


def valid_priority(text: str) -> int:
    if text not in ("1", "2", "3"):
        raise ValueError("priority must be 1, 2 or 3")
    return int(text)


def valid_range(text: str) -> str:
    if text not in _RANGES:
        raise ValueError("range must be one of 1h, 24h, 7d, all")
    return text


def valid_home_net(text: str) -> str:
    """A Snort address list such as `[10.0.0.0/8,192.168.0.0/16]` or `any`; no line breaks."""
    text = text.strip()
    if not _HOME_NET.fullmatch(text):
        raise ValueError(
            "HOME_NET: letters, digits and . : / , ! $ [ ] only, at most 200 characters"
        )
    return text


def valid_pcap_name(text: str) -> str:
    if not _PCAP_NAME.fullmatch(text) or text.split(".")[0].lower() in _RESERVED:
        raise ValueError(
            "pcap name: letters, digits, . _ - only, at most 64 characters, ends .pcap"
        )
    return text


def parse_form(body: bytes, *, max_bytes: int = MAX_FORM_BYTES) -> dict[str, str]:
    """An urlencoded body as one value per field. Refuses oversize bodies, bad UTF-8, repeats."""
    if len(body) > max_bytes:
        raise ValueError("form is too large")
    try:
        pairs = parse_qs(body.decode("ascii"), keep_blank_values=True, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("form is not valid text") from exc
    if any(len(v) != 1 for v in pairs.values()):
        raise ValueError("a field was sent more than once")
    return {k: v[0] for k, v in pairs.items()}


def host_allowed(host: str | None, port: int) -> bool:
    return host is not None and host.lower() in (f"127.0.0.1:{port}", f"localhost:{port}")


def origin_allowed(origin: str | None, host: str) -> bool:
    return origin is None or origin == f"http://{host}"


def token_ok(given: str | None, expected: str) -> bool:
    return bool(given) and hmac.compare_digest(given.encode(), expected.encode())  # type: ignore[union-attr]


def new_token() -> str:
    return secrets.token_hex(32)


class SecurityMiddleware:
    """Refuses foreign Host (400), and non-GET requests without the token or with a foreign
    Origin (403); adds the security headers to every response."""

    def __init__(self, app: ASGIApp, *, token: str, port: int) -> None:
        self._app = app
        self._token = token
        self._port = port

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        started = False

        async def secure_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message = {**message, "headers": [*message.get("headers", []), *_SECURITY_HEADERS]}
            await send(message)

        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        host = headers.get("host")
        if not host_allowed(host, self._port):
            await self._refuse(400, "bad host", secure_send)
        elif scope["method"] not in ("GET", "HEAD") and not (
            token_ok(headers.get(TOKEN_HEADER), self._token)
            and origin_allowed(headers.get("origin"), host or "")
        ):
            await self._refuse(403, "forbidden", secure_send)
        else:
            try:
                await self._app(scope, receive, secure_send)
            except Exception:
                # Answer here so the 500 carries the security headers; Starlette's own error
                # handler sits outside this middleware and would not add them.
                log.exception("unhandled error in %s %s", scope["method"], scope["path"])
                if started:
                    raise
                await self._refuse(500, "internal error", secure_send)

    @staticmethod
    async def _refuse(status: int, text: str, send: Send) -> None:
        body = text.encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
