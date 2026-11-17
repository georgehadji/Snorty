"""What attribution needs from the operating system: who owns a local socket."""

from dataclasses import dataclass
from typing import Literal, Protocol


@dataclass(frozen=True, slots=True)
class Owner:
    pid: int
    image: str  # path of the program, empty when it cannot be read


class ConnectionLookup(Protocol):
    def owner(self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int) -> Owner | None:
        """The process holding this local endpoint right now, or None."""
        ...
