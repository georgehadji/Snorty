"""packets.pcapfile: classic pcap read and write, with hard caps and no exceptions on junk."""

import random
import struct

from snorty.packets.pcapfile import MAX_FRAME_BYTES, Frame, read_pcap, write_pcap

A = Frame(1_700_000_000_123_456_000, 60, b"a" * 60)
B = Frame(1_700_000_001_000_000_000, 100, b"b" * 40)  # cut short: 40 of 100 bytes kept


def test_a_write_then_read_round_trips_frames_and_linktype() -> None:
    parsed = read_pcap(write_pcap([A, B], linktype=1))
    assert parsed is not None and parsed.linktype == 1 and not parsed.truncated
    assert parsed.frames == (A, B)


def test_big_endian_and_nanosecond_files_are_read() -> None:
    header = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(">IIII", 5, 250_000, 3, 3) + b"xyz"
    parsed = read_pcap(header + record)
    assert parsed is not None and parsed.frames == (Frame(5_250_000_000, 3, b"xyz"),)
    nano = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    nano += struct.pack("<IIII", 5, 250_000_123, 3, 3) + b"xyz"
    parsed = read_pcap(nano)
    assert parsed is not None and parsed.frames[0].ts_ns == 5_250_000_123


def test_not_a_classic_pcap_is_none() -> None:
    for data in (b"", b"short", b"\x0a\x0d\x0d\x0a" + b"0" * 40, b"x" * 100):
        assert read_pcap(data) is None


def test_a_half_written_last_record_keeps_the_good_frames_and_says_so() -> None:
    whole = write_pcap([A, B])
    parsed = read_pcap(whole[:-10])
    assert parsed is not None and parsed.frames == (A,) and parsed.truncated


def test_a_record_claiming_a_huge_length_stops_the_read() -> None:
    data = write_pcap([A]) + struct.pack("<IIII", 1, 0, MAX_FRAME_BYTES + 1, 1) + b"x" * 10
    parsed = read_pcap(data)
    assert parsed is not None and len(parsed.frames) == 1 and parsed.truncated


def test_the_frame_cap_is_enforced() -> None:
    parsed = read_pcap(write_pcap([A] * 50), max_frames=10)
    assert parsed is not None and len(parsed.frames) == 10 and parsed.truncated


def test_a_time_window_keeps_only_frames_inside_it() -> None:
    parsed = read_pcap(write_pcap([A, B]), between=(B.ts_ns - 1, B.ts_ns + 1))
    assert parsed is not None and parsed.frames == (B,) and not parsed.truncated


def test_random_bytes_never_raise_and_never_exceed_the_caps() -> None:
    rnd = random.Random(3)
    good = write_pcap([A, B] * 5)
    for _ in range(2000):
        data = bytearray(good)
        for _ in range(rnd.randint(1, 8)):
            data[rnd.randrange(len(data))] = rnd.randrange(256)
        cut = bytes(data[: rnd.randint(0, len(data))])
        parsed = read_pcap(cut, max_frames=20)
        assert parsed is None or len(parsed.frames) <= 20
    for _ in range(500):
        read_pcap(rnd.randbytes(rnd.randint(0, 200)))
