"""Which addresses may be blocked. Pure: no I/O."""

import ipaddress
from collections.abc import Collection


def refusal(ip: str, protected: Collection[str]) -> str | None:
    """Why `ip` must not be blocked, or None when it may be.

    Only public addresses can be blocked. That covers loopback, the home network, link-local and
    multicast ranges at once; `protected` adds the gateways and DNS servers, which can be public."""
    try:
        if "%" in ip:  # scope ids are not addresses we block
            raise ValueError(ip)
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "not an IP address"
    if not addr.is_global or addr.is_multicast:  # 224.0.0.1 counts as global to Python
        return "private, local and reserved addresses are never blocked"
    if str(addr) in protected:
        return "this is a gateway or DNS server of this PC; blocking it would cut the PC off"
    return None
