"""What the packets service needs from the outside, plus the do-nothing stand-in."""

from pathlib import Path
from typing import Protocol

from snorty.packets.models import (
    DecodeResult,
    LaunchResult,
    RecordResult,
    SummaryResult,
    Unavailable,
)

NOT_FOUND = (
    "Wireshark (tshark) was not found. Install Wireshark, or set wireshark_dir in snorty.toml."
)


class Decoder(Protocol):
    """Turns the first `limit` packets of a pcap into views."""

    async def decode(self, pcap: Path, *, limit: int) -> DecodeResult: ...

    async def summarize(self, pcap: Path) -> SummaryResult: ...


class NoDecoder:
    """Used when no tool is installed, so callers never branch on its absence."""

    async def decode(self, pcap: Path, *, limit: int) -> DecodeResult:
        return Unavailable(NOT_FOUND)

    async def summarize(self, pcap: Path) -> SummaryResult:
        return Unavailable(NOT_FOUND)


NOT_FOUND_VIEWER = (
    "The Wireshark program was not found. Install Wireshark, or set wireshark_dir in snorty.toml."
)


class Viewer(Protocol):
    """Opens a pcap in a viewer that outlives the request."""

    async def open(self, pcap: Path) -> LaunchResult: ...


class NoViewer:
    """Used when the viewer is not installed."""

    async def open(self, pcap: Path) -> LaunchResult:
        return Unavailable(NOT_FOUND_VIEWER)


NOT_FOUND_RECORDER = (
    "Wireshark (dumpcap) was not found. Install Wireshark, or set wireshark_dir in snorty.toml."
)


class Recorder(Protocol):
    """Records live traffic from a network adapter into a pcap for a fixed number of seconds."""

    async def record(self, device: str, seconds: int, target: Path) -> RecordResult: ...


class NoRecorder:
    """Used when the recorder is not installed."""

    async def record(self, device: str, seconds: int, target: Path) -> RecordResult:
        return Unavailable(NOT_FOUND_RECORDER)
