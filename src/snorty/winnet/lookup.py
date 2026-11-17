"""Windows adapter for attribution: the IPv4 connection tables of iphlpapi, through ctypes.
No subprocess and no dependency."""

import ctypes
import socket
import struct
import sys
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Literal

from snorty.attribution.ports import Owner

_AF_INET = 2
_TCP_TABLE_OWNER_PID_ALL = 5
_UDP_TABLE_OWNER_PID = 1
_QUERY_LIMITED_INFORMATION = 0x1000


@dataclass(frozen=True, slots=True)
class Row:
    ip: str
    port: int
    pid: int


def _port(raw: int) -> int:
    """Ports sit in the low 16 bits in network byte order."""
    return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)


def _ip(raw: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", raw))


def parse_tcp_rows(buf: bytes) -> list[Row]:
    """MIB_TCPTABLE_OWNER_PID: a count, then (state, local ip, local port, remote ip, remote port,
    pid) as six 32-bit values per row."""
    (count,) = struct.unpack_from("<I", buf)
    rows = struct.iter_unpack("<6I", buf[4 : 4 + 24 * count])
    return [Row(_ip(r[1]), _port(r[2]), r[5]) for r in rows]


def parse_udp_rows(buf: bytes) -> list[Row]:
    """MIB_UDPTABLE_OWNER_PID: a count, then (local ip, local port, pid) per row."""
    (count,) = struct.unpack_from("<I", buf)
    rows = struct.iter_unpack("<3I", buf[4 : 4 + 12 * count])
    return [Row(_ip(r[0]), _port(r[1]), r[2]) for r in rows]


def _table(proto: Literal["TCP", "UDP"]) -> bytes:
    """The raw table, read with the grow-and-retry the API asks for."""
    api: Any = ctypes.windll.iphlpapi  # type: ignore[attr-defined,unused-ignore]
    func = api.GetExtendedTcpTable if proto == "TCP" else api.GetExtendedUdpTable
    kind = _TCP_TABLE_OWNER_PID_ALL if proto == "TCP" else _UDP_TABLE_OWNER_PID
    size = wintypes.DWORD(0)
    func(None, ctypes.byref(size), False, _AF_INET, kind, 0)
    for _ in range(5):  # the table can grow between the two calls
        buf = ctypes.create_string_buffer(size.value)
        if func(buf, ctypes.byref(size), False, _AF_INET, kind, 0) == 0:
            return buf.raw[: size.value]
    raise OSError(f"cannot read the {proto} connection table")


def _image(pid: int) -> str:
    k32: Any = ctypes.windll.kernel32  # type: ignore[attr-defined,unused-ignore]
    k32.OpenProcess.restype = wintypes.HANDLE
    handle = k32.OpenProcess(_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""  # a protected process: its name is not ours to read
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        ok = k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        return str(buf.value) if ok else ""
    finally:
        k32.CloseHandle(handle)


class WinConnectionLookup:
    """`ConnectionLookup` over the Windows tables. The readers are parameters so tests can hand it
    a table snapshot."""

    def __init__(
        self,
        read: Callable[[Literal["TCP", "UDP"]], bytes] | None = None,
        image: Callable[[int], str] = _image,
    ) -> None:
        self._read = read
        self._image = image

    def owner(self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int) -> Owner | None:
        read = self._read or _table
        if self._read is None and sys.platform != "win32":
            return None
        table = read(proto)
        rows = parse_tcp_rows(table) if proto == "TCP" else parse_udp_rows(table)
        mine = [r for r in rows if r.port == local_port and r.pid]
        # a socket bound to every address answers for this one too, but an exact match wins
        best = next((r for r in mine if r.ip == local_ip), None) or next(
            (r for r in mine if r.ip == "0.0.0.0"), None
        )
        return None if best is None else Owner(best.pid, self._image(best.pid))
