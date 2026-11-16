"""What the packets module hands to the UI: plain frozen data, no tool types."""

from dataclasses import dataclass
from typing import Literal


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
class ProtocolRow:
    """One line of the protocol hierarchy; `depth` 0 is the outermost layer."""

    name: str
    depth: int
    frames: int
    bytes: int


@dataclass(frozen=True, slots=True)
class Conversation:
    """Traffic between two endpoints. `size` and `duration` are shown as the tool prints them."""

    kind: str  # IPv4, IPv6, TCP or UDP
    a: str
    b: str
    frames: int
    size: str
    duration: str


@dataclass(frozen=True, slots=True)
class Summary:
    """What a pcap contains, without the packets themselves."""

    protocols: tuple[ProtocolRow, ...]
    conversations: tuple[Conversation, ...]


@dataclass(frozen=True, slots=True)
class Unavailable:
    """The tool is not installed or not enabled; not an error."""

    reason: str


@dataclass(frozen=True, slots=True)
class Failed:
    """The tool ran but the file could not be decoded."""

    message: str


DecodeResult = Decoded | Unavailable | Failed
SummaryResult = Summary | Unavailable | Failed


@dataclass(frozen=True, slots=True)
class AlertPacket:
    """The packet behind an alert, found in Snort's own packet log."""

    confidence: Literal["exact", "near", "ambiguous"]
    candidates: int  # how many frames fitted; more than one means the choice was a guess
    pcap: bytes  # a classic pcap holding just this frame: what Download serves
    decoded: DecodeResult  # the frame decoded; Unavailable or Failed when tshark cannot


@dataclass(frozen=True, slots=True)
class NotFound:
    """The packet is not in the logs; `reason` says why in words."""

    reason: str


AlertPacketResult = AlertPacket | NotFound | Failed


@dataclass(frozen=True, slots=True)
class Launched:
    """The viewer was started; it runs on its own from here."""


LaunchResult = Launched | Unavailable | Failed


@dataclass(frozen=True, slots=True)
class Capabilities:
    decode: bool
    open: bool = False
