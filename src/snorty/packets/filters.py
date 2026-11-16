"""Wireshark display filters for an alert: the exact packet, or the whole conversation.

Pure, and safe by construction: every address is parsed and re-printed by `ipaddress`, every port
is range-checked, and the protocol comes from a fixed table. Nothing from the alert line is ever
pasted into a filter as text, so a hostile line cannot inject filter syntax. A filter that cannot
be built honestly is None.
"""

import ipaddress

from snorty.core.models import Alert

_TRANSPORT = {"TCP": "tcp", "UDP": "udp"}
_ICMP = {"ICMP": "icmp", "ICMP6": "icmpv6", "IPV6-ICMP": "icmpv6"}


def _ip(text: str) -> tuple[str, str] | None:
    """Canonical address text and the Wireshark field family ("ip" or "ipv6")."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        return str(ipaddress.IPv6Address(int(addr))), "ipv6"  # rebuilt, so a %scope is dropped
    return str(addr), "ip"


def _port(port: int | None) -> int | None:
    return port if port is not None and 0 <= port <= 65535 else None


def _ends(alert: Alert) -> tuple[str, str, str] | None:
    src, dst = _ip(alert.src_ip), _ip(alert.dst_ip)
    if src is None or dst is None or src[1] != dst[1]:
        return None
    return src[1], src[0], dst[0]


def alert_filter(alert: Alert) -> str | None:
    """Only the packet that raised the alert: addresses, ports and direction."""
    if (ends := _ends(alert)) is None:
        return None
    family, src, dst = ends
    parts = [f"{family}.src == {src}", f"{family}.dst == {dst}"]
    proto = alert.proto.upper()
    if layer := _TRANSPORT.get(proto):
        if (port := _port(alert.src_port)) is not None:
            parts.append(f"{layer}.srcport == {port}")
        if (port := _port(alert.dst_port)) is not None:
            parts.append(f"{layer}.dstport == {port}")
        if len(parts) == 2:
            parts.append(layer)
    elif icmp := _ICMP.get(proto):
        parts.append(icmp)
    return " && ".join(parts)


def conversation_filter(alert: Alert) -> str | None:
    """Both directions between the two endpoints."""
    if (ends := _ends(alert)) is None:
        return None
    family, src, dst = ends
    parts = [f"{family}.addr == {src}", f"{family}.addr == {dst}"]
    proto = alert.proto.upper()
    if layer := _TRANSPORT.get(proto):
        ports = [p for p in (_port(alert.src_port), _port(alert.dst_port)) if p is not None]
        parts += [f"{layer}.port == {p}" for p in ports] or [layer]
    elif icmp := _ICMP.get(proto):
        parts.append(icmp)
    return " && ".join(parts)
