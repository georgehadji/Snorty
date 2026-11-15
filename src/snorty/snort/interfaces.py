import ipaddress
import socket
from collections.abc import Sequence

from snorty.snort.models import Interface


def _ipv4(text: str) -> str | None:
    try:
        return text if isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address) else None
    except ValueError:  # "disabled", or anything else that is not an address
        return None


def parse_interfaces(text: str) -> list[Interface]:
    """Parse `snort -W` output: tab-separated rows, index first. Other lines are ignored."""
    result: list[Interface] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or not parts[0].strip().isdigit():
            continue
        index, mac, ip, device, description = (p.strip() for p in parts)
        result.append(Interface(int(index), mac, _ipv4(ip), device, description))
    return result


def pick_interface(interfaces: Sequence[Interface], local_ip: str) -> Interface | None:
    """Return the interface that owns `local_ip`. None if no adapter has it."""
    return next((i for i in interfaces if i.ip == local_ip), None)


def find_local_ip() -> str | None:
    """IPv4 address the OS would use to reach the internet. A UDP connect() only
    consults the routing table: no packet is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
            return str(s.getsockname()[0])
    except OSError:
        return None
