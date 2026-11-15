"""Build a minimal pcap by hand so tests need no capture tools."""

import socket
import struct
from pathlib import Path


def _ip_checksum(header: bytes) -> int:
    total = sum(struct.unpack("!10H", header))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_frame(
    src: str, dst: str, sport: int, dport: int, payload: bytes, *, flags: int = 0x18, seq: int = 1
) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    total_len = 20 + 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )  # fmt: skip
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 5 << 4, flags, 8192, 0, 0)
    return eth + ip + tcp + payload


def write_pcap(path: Path, frames: list[bytes], *, start: int = 1_700_000_000) -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # link type 1 = Ethernet
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", start + i, 0, len(frame), len(frame)) + frame
    path.write_bytes(out)
