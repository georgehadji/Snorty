"""Hand-made test traffic: classic pcap files of Ethernet, IPv4 and TCP or UDP frames. Pure."""

import ipaddress
import struct
from collections.abc import Sequence

SYN, ACK, PSH = 0x02, 0x10, 0x08
MAX_PAYLOAD = 60_000
MAX_COUNT = 10_000

_MAC_SRC = bytes([0, 0, 0, 0, 0, 1])
_MAC_DST = bytes([0, 0, 0, 0, 0, 2])


def build_pcap(frames: Sequence[bytes], start: float = 0.0, step: float = 0.001) -> bytes:
    """A classic little-endian libpcap file; one record per frame, `step` seconds apart."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for i, frame in enumerate(frames):
        t = start + i * step
        sec = int(t)
        usec = round((t - sec) * 1_000_000)
        if usec == 1_000_000:
            sec, usec = sec + 1, 0
        out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        out.append(frame)
    return b"".join(out)


def _sum16(data: bytes) -> int:
    if len(data) % 2:
        data += bytes(1)
    total: int = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _checksum(data: bytes) -> int:
    return ~_sum16(data) & 0xFFFF


def _ip(addr: str) -> bytes:
    return ipaddress.IPv4Address(addr).packed  # ValueError for anything but IPv4


def _port(port: int) -> int:
    if not 0 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def _frame(proto: int, src: str, dst: str, segment: bytes, csum_at: int) -> bytes:
    """Wrap a transport segment (checksum field zero) in IPv4 and Ethernet, fixing checksums."""
    s, d = _ip(src), _ip(dst)
    pseudo = s + d + bytes([0, proto]) + struct.pack(">H", len(segment))
    csum = _checksum(pseudo + segment) or 0xFFFF
    seg = segment[:csum_at] + struct.pack(">H", csum) + segment[csum_at + 2 :]
    head = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(seg), 0, 0x4000, 64, proto, 0) + s + d
    ip = head[:10] + struct.pack(">H", _checksum(head)) + head[12:]
    return _MAC_DST + _MAC_SRC + bytes([8, 0]) + ip + seg


def tcp_packet(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    payload: bytes = b"",
    *,
    seq: int = 1,
    ack: int = 0,
    flags: int = PSH | ACK,
) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload over {MAX_PAYLOAD} bytes")
    seg = struct.pack(
        ">HHIIBBHHH",
        _port(sport),
        _port(dport),
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )
    return _frame(6, src, dst, seg + payload, 16)


def udp_packet(src: str, sport: int, dst: str, dport: int, payload: bytes = b"") -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload over {MAX_PAYLOAD} bytes")
    seg = struct.pack(">HHHH", _port(sport), _port(dport), 8 + len(payload), 0) + payload
    return _frame(17, src, dst, seg, 6)


def make_frames(
    proto: str,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    payload: bytes,
    *,
    count: int = 1,
    handshake: bool = False,
) -> list[bytes]:
    """`count` data packets from src to dst, optionally after a TCP three-way handshake."""
    if not 1 <= count <= MAX_COUNT:
        raise ValueError(f"count must be 1 to {MAX_COUNT}")
    if proto == "udp":
        return [udp_packet(src, sport, dst, dport, payload) for _ in range(count)]
    if proto != "tcp":
        raise ValueError(f"unknown protocol: {proto!r} (tcp or udp)")
    client, server = 1000, 2000
    frames: list[bytes] = []
    if handshake:
        frames += [
            tcp_packet(src, sport, dst, dport, seq=client, flags=SYN),
            tcp_packet(dst, dport, src, sport, seq=server, ack=client + 1, flags=SYN | ACK),
            tcp_packet(src, sport, dst, dport, seq=client + 1, ack=server + 1, flags=ACK),
        ]
    seq = client + 1
    for _ in range(count):
        frames.append(
            tcp_packet(src, sport, dst, dport, payload, seq=seq, ack=server + 1, flags=PSH | ACK)
        )
        seq += len(payload)
    return frames
