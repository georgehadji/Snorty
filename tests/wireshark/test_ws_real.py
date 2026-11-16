"""Runs the real tshark on a generated pcap. Skipped when Wireshark is not installed."""

import os
from pathlib import Path

import pytest

from snorty.lab.pcapgen import build_pcap, tcp_packet
from snorty.packets import Decoded
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
