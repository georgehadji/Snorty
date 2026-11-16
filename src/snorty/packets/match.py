"""Find the frame an alert was raised on. Pure: an alert and some frames in, a verdict out.

Snort writes the alert and the packet with the same microsecond timestamp, so time is the main
key. The addresses and ports read from the frame's own headers confirm it and separate frames
that share a moment. The result says how sure it is, so the UI never presents a guess as fact.
"""

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from snorty.core.models import Alert
from snorty.packets.pcapfile import Frame

EXACT_WITHIN_US = 1  # Snort stamps alert and packet alike; one tick of slack for rounding
NEAR_WITHIN_US = 2_000_000  # 2 s
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ETHERNET = 1
_VLAN = (0x8100, 0x88A8)

_Flow = tuple[str, int | None, str, int | None]  # src, sport, dst, dport (addresses canonical)


@dataclass(frozen=True, slots=True)
class Located:
    frame: Frame
    confidence: Literal["exact", "near", "ambiguous"]
    candidates: int


def alert_us(alert: Alert) -> int:
    """The alert's time as whole microseconds since the epoch (integer maths, no float error)."""
    return (alert.ts - _EPOCH) // timedelta(microseconds=1)


def flow_of(data: bytes, linktype: int) -> _Flow | None:
    """Addresses and ports from an Ethernet/IPv4/IPv6 frame; None when it is anything else."""
    if linktype != _ETHERNET or len(data) < 14:
        return None
    pos, kind = 14, int.from_bytes(data[12:14], "big")
    while kind in _VLAN and len(data) >= pos + 4:
        kind, pos = int.from_bytes(data[pos + 2 : pos + 4], "big"), pos + 4
    if kind == 0x0800 and len(data) >= pos + 20:
        proto = data[pos + 9]
        first = int.from_bytes(data[pos + 6 : pos + 8], "big") & 0x1FFF == 0
        src = str(ipaddress.IPv4Address(data[pos + 12 : pos + 16]))
        dst = str(ipaddress.IPv4Address(data[pos + 16 : pos + 20]))
        l4 = pos + (data[pos] & 15) * 4
    elif kind == 0x86DD and len(data) >= pos + 40:
        proto, first, l4 = data[pos + 6], True, pos + 40
        src = str(ipaddress.IPv6Address(data[pos + 8 : pos + 24]))
        dst = str(ipaddress.IPv6Address(data[pos + 24 : pos + 40]))
    else:
        return None
    if proto in (6, 17) and first and len(data) >= l4 + 4:
        sport = int.from_bytes(data[l4 : l4 + 2], "big")
        return src, sport, dst, int.from_bytes(data[l4 + 2 : l4 + 4], "big")
    return src, None, dst, None


def _agrees(alert: Alert, flow: _Flow | None) -> bool | None:
    """True or False when the frame's headers confirm or contradict the alert; None if unknown."""
    if flow is None:
        return None
    try:
        src = str(ipaddress.ip_address(alert.src_ip))
        dst = str(ipaddress.ip_address(alert.dst_ip))
    except ValueError:
        return None
    if (src, dst) != (flow[0], flow[2]):
        return False
    for want, got in ((alert.src_port, flow[1]), (alert.dst_port, flow[3])):
        if want is not None and got is not None and want != got:
            return False
    return True


def locate(alert: Alert, frames: Sequence[Frame], linktype: int) -> Located | None:
    """The best frame for the alert, or None when nothing fits."""
    when = alert_us(alert)
    scored = [
        (abs(f.ts_ns // 1000 - when), f, _agrees(alert, flow_of(f.data, linktype))) for f in frames
    ]
    close = [(d, f) for d, f, ok in scored if d <= EXACT_WITHIN_US and ok is not False]
    if close:
        top = min(d for d, _ in close)
        best = [f for d, f in close if d == top]  # bursts share a few microseconds; take the tick
        same = all(f.data == best[0].data for f in best)  # one packet, however it was counted
        return Located(best[0], "exact" if same else "ambiguous", len(best))
    near = [(d, f) for d, f, ok in scored if d <= NEAR_WITHIN_US and ok is True]
    near.sort(key=lambda item: item[0])
    if near:
        return Located(near[0][1], "near", len(near))
    return None
