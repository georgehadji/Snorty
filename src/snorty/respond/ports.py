"""What the respond module needs from a firewall. The Windows adapter is `snorty.winfw`."""

from collections.abc import Sequence
from typing import Protocol


class FirewallError(Exception):
    """The firewall refused or could not be reached."""


class NeedsAdmin(FirewallError):
    """Writing firewall rules needs the user's approval, and they did not give it."""


class Firewall(Protocol):
    async def block(self, ip: str) -> None: ...

    async def unblock(self, *ips: str) -> None:
        """Remove the rules of all `ips` at once, so approval is asked for once."""
        ...

    async def blocked(self) -> Sequence[str]:
        """Single addresses that Snorty's own rules block now."""
        ...

    async def protected(self) -> frozenset[str]:
        """Addresses that must never be blocked: gateways and DNS servers."""
        ...
