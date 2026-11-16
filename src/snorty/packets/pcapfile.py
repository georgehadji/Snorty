"""Read and write classic pcap files. Pure: bytes in, bytes out, hard caps on everything.

Only the classic format is handled (what Snort's log_tcpdump writes and what the Lab accepts);
pcapng is reported as "not a pcap" instead of half-parsed.
"""

import struct
from collections.abc import Iterable
from dataclasses import dataclass

MAX_FRAMES = 50_000
MAX_FRAME_BYTES = 262_144  # a record claiming more than this is treated as corrupt
_GLOBAL = 24
_RECORD = 16
_MAGICS = {  # magic as read little-endian -> (byte order, nanosecond timestamps)
    0xA1B2C3D4: ("<", False),
    0xA1B23C4D: ("<", True),
    0xD4C3B2A1: (">", False),
    0x4D3CB2A1: (">", True),
}


@dataclass(frozen=True, slots=True)
class Frame:
    ts_ns: int  # nanoseconds since the Unix epoch, UTC
    orig_len: int  # length on the wire; may exceed len(data) when the capture was cut short
    data: bytes


@dataclass(frozen=True, slots=True)
class PcapFile:
    linktype: int  # 1 = Ethernet
    frames: tuple[Frame, ...]
    truncated: bool  # stopped at a cap or at a partly written or corrupt record


def read_pcap(
    data: bytes,
    *,
    max_frames: int = MAX_FRAMES,
    between: tuple[int, int] | None = None,
) -> PcapFile | None:
    """The frames of a classic pcap, or None when the bytes are not one. Never raises.

    `between` (nanosecond timestamps, inclusive) keeps only frames in that window; the rest are
    skipped without being copied, so a big log can be searched cheaply.
    """
    if len(data) < _GLOBAL:
        return None
    kind = _MAGICS.get(struct.unpack_from("<I", data)[0])
    if kind is None:
        return None
    order, nanos = kind
    linktype = struct.unpack_from(f"{order}I", data, 20)[0]
    frames: list[Frame] = []
    pos = _GLOBAL
    truncated = False
    while pos < len(data):
        if len(frames) >= max_frames or pos + _RECORD > len(data):
            truncated = True
            break
        sec, frac, incl, orig = struct.unpack_from(f"{order}IIII", data, pos)
        pos += _RECORD
        if incl > MAX_FRAME_BYTES or pos + incl > len(data):
            truncated = True
            break
        ts = sec * 1_000_000_000 + (frac if nanos else frac * 1000)
        if between is None or between[0] <= ts <= between[1]:
            frames.append(Frame(ts, orig, data[pos : pos + incl]))
        pos += incl
    return PcapFile(linktype, tuple(frames), truncated)


def write_pcap(frames: Iterable[Frame], *, linktype: int = 1) -> bytes:
    """A classic little-endian, microsecond-resolution pcap holding `frames`."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for f in frames:
        sec, nanos = divmod(f.ts_ns, 1_000_000_000)
        out += struct.pack("<IIII", sec, nanos // 1000, len(f.data), max(f.orig_len, len(f.data)))
        out += f.data
    return bytes(out)
