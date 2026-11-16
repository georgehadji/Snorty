import ipaddress
import struct

import pytest

from snorty.lab.pcapgen import (
    ACK,
    PSH,
    SYN,
    build_pcap,
    make_frames,
    tcp_packet,
    udp_packet,
)

SRC, DST = "10.0.0.1", "10.0.0.2"


def checksum_ok(data: bytes) -> bool:
    if len(data) % 2:
        data += bytes(1)
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def read_pcap(blob: bytes) -> tuple[tuple[int, ...], list[tuple[float, bytes]]]:
    header = struct.unpack("<IHHiIII", blob[:24])
    records, pos = [], 24
    while pos < len(blob):
        sec, usec, incl, orig = struct.unpack("<IIII", blob[pos : pos + 16])
        assert incl == orig
        records.append((sec + usec / 1e6, blob[pos + 16 : pos + 16 + incl]))
        pos += 16 + incl
    assert pos == len(blob)
    return header, records


def parse(frame: bytes) -> dict[str, object]:
    assert frame[12:14] == bytes([8, 0])  # IPv4
    ip = frame[14:34]
    assert ip[0] == 0x45 and checksum_ok(ip)
    total = struct.unpack(">H", ip[2:4])[0]
    assert total == len(frame) - 14
    proto, src, dst = ip[9], ip[12:16], ip[16:20]
    seg = frame[34:]
    pseudo = src + dst + bytes([0, proto]) + struct.pack(">H", len(seg))
    assert checksum_ok(pseudo + seg), "transport checksum"
    out: dict[str, object] = {
        "proto": proto,
        "src": str(ipaddress.IPv4Address(src)),
        "dst": str(ipaddress.IPv4Address(dst)),
    }
    if proto == 6:
        sport, dport, seq, ack, off, flags = struct.unpack(">HHIIBB", seg[:14])
        out |= {
            "sport": sport,
            "dport": dport,
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "payload": seg[(off >> 4) * 4 :],
        }
    else:
        sport, dport, length = struct.unpack(">HHH", seg[:6])
        assert length == len(seg)
        out |= {"sport": sport, "dport": dport, "payload": seg[8:]}
    return out


def test_empty_pcap_is_just_the_global_header() -> None:
    assert build_pcap([]) == struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def test_records_carry_the_frames_and_increasing_timestamps() -> None:
    frames = [b"a" * 60, b"b" * 70, b"c" * 80]
    header, records = read_pcap(build_pcap(frames, start=100.0, step=0.5))
    assert header[0] == 0xA1B2C3D4 and header[6] == 1  # magic, Ethernet
    assert [f for _, f in records] == frames
    assert [round(t, 3) for t, _ in records] == [100.0, 100.5, 101.0]


def test_tcp_packet_fields_and_checksums() -> None:
    frame = tcp_packet(SRC, 4444, DST, 80, b"uid=0(root)", seq=5, ack=9, flags=PSH | ACK)
    p = parse(frame)
    assert (p["proto"], p["src"], p["dst"], p["sport"], p["dport"]) == (6, SRC, DST, 4444, 80)
    assert (p["seq"], p["ack"], p["flags"], p["payload"]) == (5, 9, PSH | ACK, b"uid=0(root)")


def test_odd_length_payload_checksums_correctly() -> None:
    assert parse(tcp_packet(SRC, 1, DST, 2, b"abc"))["payload"] == b"abc"
    assert parse(udp_packet(SRC, 1, DST, 2, b"abcde"))["payload"] == b"abcde"


def test_udp_packet_fields() -> None:
    p = parse(udp_packet(SRC, 5353, DST, 53, b"query"))
    assert (p["proto"], p["sport"], p["dport"], p["payload"]) == (17, 5353, 53, b"query")


def test_payload_without_handshake_is_one_data_packet() -> None:
    frames = make_frames("tcp", SRC, 4444, DST, 80, b"data")
    assert [parse(f)["payload"] for f in frames] == [b"data"]


def test_handshake_gives_syn_synack_ack_then_data_with_consistent_numbers() -> None:
    frames = make_frames("tcp", SRC, 4444, DST, 80, b"data", handshake=True, count=2)
    p = [parse(f) for f in frames]
    assert [x["flags"] for x in p] == [SYN, SYN | ACK, ACK, PSH | ACK, PSH | ACK]
    assert (p[0]["src"], p[1]["src"], p[2]["src"]) == (SRC, DST, SRC)
    assert p[1]["ack"] == p[0]["seq"] + 1  # type: ignore[operator]
    assert p[2]["ack"] == p[1]["seq"] + 1  # type: ignore[operator]
    assert p[3]["seq"] == p[2]["seq"] and p[3]["ack"] == p[2]["ack"]
    assert p[4]["seq"] == p[3]["seq"] + 4  # type: ignore[operator]


def test_count_repeats_the_data_packet() -> None:
    assert len(make_frames("udp", SRC, 1, DST, 2, b"x", count=7)) == 7
    assert len(make_frames("tcp", SRC, 1, DST, 2, b"x", count=7)) == 7


@pytest.mark.parametrize(
    "kwargs",
    [
        {"src": "999.1.1.1"},
        {"src": "::1"},
        {"dst": "not an ip"},
        {"sport": -1},
        {"dport": 65536},
        {"payload": b"x" * 60001},
        {"count": 0},
        {"count": 10001},
        {"proto": "icmp"},
    ],
)
def test_bad_input_is_refused(kwargs: dict[str, object]) -> None:
    args: dict[str, object] = {
        "proto": "tcp",
        "src": SRC,
        "sport": 1,
        "dst": DST,
        "dport": 2,
        "payload": b"x",
    }
    args |= kwargs
    with pytest.raises(ValueError):
        make_frames(**args)  # type: ignore[arg-type]


def test_a_pcap_over_50_mb_is_refused_before_any_packet_is_built() -> None:
    """Each limit alone allows 10,000 x 60,000 bytes; the product must be capped too."""
    with pytest.raises(ValueError, match="50 MB"):
        make_frames("tcp", "10.0.0.1", 1, "10.0.0.2", 80, b"x" * 60_000, count=10_000)
