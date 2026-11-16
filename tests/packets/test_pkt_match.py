"""packets.match: find the frame an alert was raised on, and say how sure the match is."""

import random
import struct
from datetime import UTC, datetime, timedelta

from snorty.core.models import Alert
from snorty.lab.pcapgen import tcp_packet, udp_packet
from snorty.packets.match import alert_us, flow_of, locate
from snorty.packets.pcapfile import Frame

WHEN = datetime(2026, 11, 16, 20, 19, 15, 169220, tzinfo=UTC)
TCP = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=b"GET /")
UDP = udp_packet("10.0.0.5", 5353, "10.0.0.9", 53, payload=b"q")


def alert(
    proto: str = "TCP",
    when: datetime = WHEN,
    src: tuple[str, int | None] = ("10.0.0.5", 40000),
    dst: tuple[str, int | None] = ("10.0.0.9", 80),
) -> Alert:
    return Alert(when, 1, 1000, 1, "m", None, 1, proto, src[0], src[1], dst[0], dst[1], "raw")


def frame(data: bytes, when: datetime = WHEN) -> Frame:
    return Frame(alert_us(alert(when=when)) * 1000, len(data), data)


def test_the_alert_time_is_whole_microseconds() -> None:
    assert alert_us(alert()) == 1_794_860_355_169_220


def test_one_frame_at_the_same_microsecond_is_exact() -> None:
    hit = locate(alert(), [frame(UDP), frame(TCP)], 1)
    assert hit is not None and hit.confidence == "exact" and hit.frame.data == TCP


def test_frames_sharing_the_moment_but_not_the_flow_are_told_apart_by_headers() -> None:
    other = tcp_packet("10.0.0.7", 1, "10.0.0.8", 2)
    hit = locate(alert(), [frame(other), frame(TCP)], 1)
    assert hit is not None and hit.confidence == "exact" and hit.candidates == 1
    assert hit.frame.data == TCP


def test_two_different_frames_that_both_fit_are_ambiguous_and_two_equal_ones_are_not() -> None:
    twin = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=b"POST")
    hit = locate(alert(), [frame(TCP), frame(twin)], 1)
    assert hit is not None and hit.confidence == "ambiguous" and hit.candidates == 2
    same = locate(alert(), [frame(TCP), frame(TCP)], 1)
    assert same is not None and same.confidence == "exact" and same.candidates == 2


def test_a_frame_a_little_off_in_time_is_near_only_if_the_headers_confirm_it() -> None:
    late = WHEN + timedelta(milliseconds=800)
    hit = locate(alert(), [frame(TCP, late)], 1)
    assert hit is not None and hit.confidence == "near" and hit.candidates == 1
    assert locate(alert(), [frame(UDP, late)], 1) is None
    assert locate(alert(), [frame(TCP, WHEN + timedelta(seconds=5))], 1) is None


def test_the_nearest_of_several_near_frames_wins() -> None:
    far, close = WHEN + timedelta(seconds=1.5), WHEN + timedelta(milliseconds=20)
    hit = locate(alert(), [frame(TCP, far), frame(TCP, close)], 1)
    assert hit is not None and hit.frame.ts_ns == frame(TCP, close).ts_ns and hit.candidates == 2


def test_a_frame_that_is_not_ethernet_ip_matches_on_time_alone_when_exact() -> None:
    weird = b"\x00" * 30
    hit = locate(alert(), [frame(weird)], 1)
    assert hit is not None and hit.confidence == "exact"
    assert (
        locate(alert(), [frame(weird, WHEN + timedelta(seconds=1))], 1) is None
    )  # near needs proof
    assert locate(alert(), [frame(TCP)], 105) is not None  # unknown link type: time only


def test_vlan_tagged_and_ipv6_frames_are_read() -> None:
    plain = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80)
    tagged = plain[:12] + struct.pack(">HHH", 0x8100, 5, 0x0800) + plain[14:]
    assert flow_of(tagged, 1) == ("10.0.0.5", 40000, "10.0.0.9", 80)
    v6 = bytearray(14 + 40 + 20)
    v6[12:14] = struct.pack(">H", 0x86DD)
    v6[14] = 0x60
    v6[20] = 6  # next header: TCP
    v6[22:38] = bytes(15) + b"\x01"
    v6[38:54] = bytes(15) + b"\x02"
    v6[54:58] = struct.pack(">HH", 1234, 443)
    assert flow_of(bytes(v6), 1) == ("::1", 1234, "::2", 443)


def test_icmp_and_fragments_have_no_ports() -> None:
    plain = bytearray(tcp_packet("10.0.0.5", 1, "10.0.0.9", 2))
    plain[23] = 1  # protocol: ICMP
    assert flow_of(bytes(plain), 1) == ("10.0.0.5", None, "10.0.0.9", None)
    frag = bytearray(tcp_packet("10.0.0.5", 1, "10.0.0.9", 2))
    frag[20:22] = struct.pack(">H", 5)  # fragment offset 5: no transport header here
    assert flow_of(bytes(frag), 1) == ("10.0.0.5", None, "10.0.0.9", None)


def test_random_bytes_never_raise() -> None:
    rnd = random.Random(11)
    for _ in range(3000):
        data = rnd.randbytes(rnd.randint(0, 80))
        flow_of(data, 1)
        locate(alert(), [frame(data)], rnd.choice([1, 0, 113]))
    for _ in range(500):  # junk that starts like IPv4
        data = TCP[:14] + rnd.randbytes(rnd.randint(0, 30))
        flow_of(data, 1)


def test_in_a_burst_the_frame_on_the_exact_microsecond_wins() -> None:
    def tick(offset_us: int, payload: bytes) -> Frame:
        data = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=payload)
        return Frame((alert_us(alert()) + offset_us) * 1000, len(data), data)

    burst = [tick(-9, b"a"), tick(0, b"b"), tick(7, b"c")]
    hit = locate(alert(), burst, 1)
    assert hit is not None and hit.confidence == "exact" and hit.frame == burst[1]
    assert hit.candidates == 1
    tied = locate(alert(), [tick(-1, b"a"), tick(1, b"c")], 1)
    assert tied is not None and tied.confidence == "ambiguous" and tied.candidates == 2
    apart = locate(alert(), [tick(500, b"a")], 1)  # same flow, but not the same tick
    assert apart is not None and apart.confidence == "near"
