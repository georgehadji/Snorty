"""What attribution needs from the operating system: who owns a local socket, now or then."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol


@dataclass(frozen=True, slots=True)
class Owner:
    pid: int
    image: str  # path of the program, empty when it cannot be read


class ConnectionLookup(Protocol):
    def owner(self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int) -> Owner | None:
        """The process holding this local endpoint right now, or None."""
        ...


class ConnectionHistory(Protocol):
    def find(
        self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int, around: datetime
    ) -> Owner | None:
        """The process a log recorded on this local endpoint near `around`, or None."""
        ...


class NoHistory:
    """Null Object: no connection log to ask (Sysmon is not installed, or not readable)."""

    def find(
        self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int, around: datetime
    ) -> Owner | None:
        return None
