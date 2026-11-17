"""Windows adapter for attribution: Sysmon's network connection log (Event ID 3), read through
ctypes over wevtapi. It answers which program held a local endpoint a few seconds ago, after the
live connection table has forgotten. No subprocess and no dependency."""

import ctypes
import logging
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from snorty.attribution.ports import Owner

log = logging.getLogger("snorty.winevt")

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
WINDOW = timedelta(seconds=5)
MAX_EVENTS = 20  # a port reused many times inside the window: the nearest few are enough

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_QUERY_CHANNEL = 0x1
_QUERY_REVERSE = 0x200
_RENDER_XML = 1
_NO_MORE_ITEMS = 259
_INSUFFICIENT_BUFFER = 122
_CHANNEL_NOT_FOUND = 15007
_ACCESS_DENIED = 5

type Reader = Callable[[str, int], list[str]]


@dataclass(frozen=True, slots=True)
class NetEvent:
    time: datetime
    proto: str  # "tcp" or "udp"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    pid: int
    image: str


def parse_event_xml(text: str) -> NetEvent | None:
    """One rendered Sysmon event as a connection, or None when it is not a well-formed Event 3."""
    try:
        root = ET.fromstring(text)
        if root.findtext("e:System/e:EventID", namespaces=_NS) != "3":
            return None
        created = root.find("e:System/e:TimeCreated", _NS)
        stamp = created.get("SystemTime", "") if created is not None else ""
        data = {d.get("Name"): (d.text or "") for d in root.iterfind("e:EventData/e:Data", _NS)}
        return NetEvent(
            datetime.fromisoformat(stamp),
            data["Protocol"].lower(),
            data["SourceIp"],
            int(data["SourcePort"]),
            data["DestinationIp"],
            int(data["DestinationPort"]),
            int(data["ProcessId"]),
            data.get("Image", ""),
        )
    except (ET.ParseError, KeyError, ValueError):
        return None


def _stamp(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def query_xpath(local_port: int, around: datetime, window: timedelta = WINDOW) -> str:
    """Event 3 records near `around` with this port on either end; the log does the filtering."""
    port = str(int(local_port))  # a number, never text: it goes into the query
    since, until = _stamp(around - window), _stamp(around + window)
    return (
        f"*[System[(EventID=3) and TimeCreated[@SystemTime>='{since}' and "
        f"@SystemTime<='{until}']]] and *[EventData[(Data[@Name='SourcePort']='{port}') or "
        f"(Data[@Name='DestinationPort']='{port}')]]"
    )


def _api() -> Any:
    api: Any = ctypes.WinDLL("wevtapi", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    handle, dword = ctypes.c_void_p, wintypes.DWORD
    api.EvtQuery.argtypes = [handle, wintypes.LPCWSTR, wintypes.LPCWSTR, dword]
    api.EvtQuery.restype = handle
    api.EvtNext.argtypes = [
        handle,
        dword,
        ctypes.POINTER(handle),
        dword,
        dword,
        ctypes.POINTER(dword),
    ]
    api.EvtNext.restype = wintypes.BOOL
    api.EvtRender.argtypes = [
        handle,
        handle,
        dword,
        dword,
        ctypes.c_void_p,
        ctypes.POINTER(dword),
        ctypes.POINTER(dword),
    ]
    api.EvtRender.restype = wintypes.BOOL
    api.EvtClose.argtypes = [handle]
    api.EvtClose.restype = wintypes.BOOL
    return api


def _last_error() -> int:
    return int(ctypes.get_last_error())  # type: ignore[attr-defined,unused-ignore]


def _error(code: int) -> OSError:
    if code == _CHANNEL_NOT_FOUND:
        return OSError("Sysmon is not installed (its event log does not exist)")
    if code == _ACCESS_DENIED:
        return OSError("no permission to read the Sysmon log (join Event Log Readers)")
    return OSError(f"cannot read the Sysmon log (Windows error {code})")


def _render(api: Any, event: Any) -> str:
    used, count = wintypes.DWORD(0), wintypes.DWORD(0)
    size = 8192
    for _ in range(3):  # the first call says how big the buffer must be
        buf = ctypes.create_unicode_buffer(size // 2)
        if api.EvtRender(
            None, event, _RENDER_XML, size, buf, ctypes.byref(used), ctypes.byref(count)
        ):
            return str(buf.value)
        if _last_error() != _INSUFFICIENT_BUFFER:
            break
        size = used.value
    return ""


def read_events(xpath: str, limit: int = MAX_EVENTS) -> list[str]:
    """Rendered XML of up to `limit` matching events, newest first. OSError says why it cannot."""
    api = _api()
    query = api.EvtQuery(None, CHANNEL, xpath, _QUERY_CHANNEL | _QUERY_REVERSE)
    if not query:
        raise _error(_last_error())
    out: list[str] = []
    try:
        events = (ctypes.c_void_p * limit)()
        returned = wintypes.DWORD(0)
        if not api.EvtNext(query, limit, events, 1000, 0, ctypes.byref(returned)):
            code = _last_error()
            if code != _NO_MORE_ITEMS:
                raise _error(code)
            return out
        for i in range(returned.value):
            try:
                out.append(_render(api, events[i]))
            finally:
                api.EvtClose(events[i])
    finally:
        api.EvtClose(query)
    return out


def probe(read: Reader | None = None) -> str | None:
    """None when the Sysmon log can be read here, else the reason it cannot."""
    if read is None and sys.platform != "win32":
        return "not Windows"
    try:
        (read or read_events)("*[System[EventID=3]]", 1)
    except OSError as exc:
        return str(exc)
    return None


class SysmonHistory:
    """`ConnectionHistory` over the Sysmon log. The reader is a parameter so tests can hand it
    rendered events."""

    def __init__(self, read: Reader | None = None, window: timedelta = WINDOW) -> None:
        self._read = read or read_events
        self._window = window

    def find(
        self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int, around: datetime
    ) -> Owner | None:
        try:
            rendered = self._read(query_xpath(local_port, around, self._window), MAX_EVENTS)
        except OSError as exc:  # the log went away or lost access since startup
            log.debug("Sysmon lookup failed: %s", exc)
            return None
        mine = [
            e
            for e in map(parse_event_xml, rendered)
            if e is not None
            and e.proto == proto.lower()
            and (
                (e.src_ip == local_ip and e.src_port == local_port)
                or (e.dst_ip == local_ip and e.dst_port == local_port)
            )
        ]
        if not mine:
            return None
        best = min(mine, key=lambda e: abs(e.time - around))
        return Owner(best.pid, best.image)
