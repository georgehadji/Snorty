"""Runs the real tshark on a generated pcap. Skipped when Wireshark is not installed."""

import os
from pathlib import Path

import pytest

from snorty.lab.pcapgen import build_pcap, tcp_packet, udp_packet
from snorty.packets import Decoded, Summary
from snorty.wireshark import TsharkDecoder, find_tools

TSHARK = find_tools(env=os.environ).tshark
pytestmark = [
    pytest.mark.tshark,
    pytest.mark.skipif(TSHARK is None, reason="tshark is not installed"),
]


async def test_real_tshark_decodes_a_generated_pcap(tmp_path: Path) -> None:
    assert TSHARK is not None
    frame = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=b"GET / HTTP/1.1")
    pcap = tmp_path / "t.pcap"
    pcap.write_bytes(build_pcap([frame]))
    result = await TsharkDecoder(TSHARK).decode(pcap, limit=10)
    assert isinstance(result, Decoded) and len(result.packets) == 1
    packet = result.packets[0]
    assert (packet.src, packet.dst) == ("10.0.0.5", "10.0.0.9") and packet.hexdump


async def test_real_tshark_summarizes_protocols_and_conversations(tmp_path: Path) -> None:
    assert TSHARK is not None
    frames = [
        tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=b"GET / HTTP/1.1\r\n\r\n"),
        udp_packet("10.0.0.5", 5353, "10.0.0.9", 9999, payload=b"hi"),
    ]
    pcap = tmp_path / "s.pcap"
    pcap.write_bytes(build_pcap(frames))
    result = await TsharkDecoder(TSHARK).summarize(pcap)
    assert isinstance(result, Summary)
    names = {p.name for p in result.protocols}
    assert {"frame", "ip", "tcp", "udp"} <= names
    kinds = {(c.kind, c.a, c.b) for c in result.conversations}
    assert ("TCP", "10.0.0.5:40000", "10.0.0.9:80") in kinds
    assert ("UDP", "10.0.0.5:5353", "10.0.0.9:9999") in kinds


async def test_real_tshark_reports_a_file_it_cannot_read(tmp_path: Path) -> None:
    assert TSHARK is not None
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file" * 4)
    result = await TsharkDecoder(TSHARK).summarize(junk)
    assert not isinstance(result, Summary) or not result.protocols
