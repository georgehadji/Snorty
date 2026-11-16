"""What the packets module hands to the UI: plain frozen data, no tool types."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Layer:
    """One protocol layer of a packet, for example Ethernet, IPv4 or TCP."""

    name: str
    fields: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class PacketView:
    number: int
    time: str  # seconds since the first packet, as the tool prints it
    protocol: str
    src: str
    dst: str
    length: int
    info: str
    layers: tuple[Layer, ...]
    hexdump: str


@dataclass(frozen=True, slots=True)
class Decoded:
    packets: tuple[PacketView, ...]
    limit: int  # how many packets were asked for

    @property
    def more(self) -> bool:
        """True when the file may hold packets beyond the ones shown."""
        return len(self.packets) >= self.limit


@dataclass(frozen=True, slots=True)
class Unavailable:
    """The tool is not installed or not enabled; not an error."""

    reason: str


@dataclass(frozen=True, slots=True)
class Failed:
    """The tool ran but the file could not be decoded."""

    message: str


DecodeResult = Decoded | Unavailable | Failed


@dataclass(frozen=True, slots=True)
class Capabilities:
    decode: bool
