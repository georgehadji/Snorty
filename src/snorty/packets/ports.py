"""What the packets service needs from the outside, plus the do-nothing stand-in."""

from pathlib import Path
from typing import Protocol

from snorty.packets.models import DecodeResult, Unavailable

NOT_FOUND = (
    "Wireshark (tshark) was not found. Install Wireshark, or set wireshark_dir in snorty.toml."
)


class Decoder(Protocol):
    """Turns the first `limit` packets of a pcap into views."""

    async def decode(self, pcap: Path, *, limit: int) -> DecodeResult: ...


class NoDecoder:
    """Used when no tool is installed, so callers never branch on its absence."""

    async def decode(self, pcap: Path, *, limit: int) -> DecodeResult:
        return Unavailable(NOT_FOUND)
