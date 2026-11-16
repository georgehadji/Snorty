"""Runs the real tshark on a generated pcap. Skipped when Wireshark is not installed."""

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from snorty.core.models import Alert
from snorty.lab.pcapgen import build_pcap, tcp_packet, udp_packet
from snorty.packets import Decoded, Summary, alert_filter, conversation_filter
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


async def test_real_tshark_accepts_and_applies_the_alert_filters(tmp_path: Path) -> None:
    assert TSHARK is not None
    hit = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=b"x")
    reply = tcp_packet("10.0.0.9", 80, "10.0.0.5", 40000, payload=b"y")
    other = tcp_packet("10.0.0.7", 1, "10.0.0.8", 2, payload=b"z")
    pcap = tmp_path / "f.pcap"
    pcap.write_bytes(build_pcap([hit, reply, other]))
    when = datetime(2026, 11, 16, tzinfo=UTC)
    alert = Alert(when, 1, 1, 1, "m", None, 1, "TCP", "10.0.0.5", 40000, "10.0.0.9", 80, "")
    expected = {alert_filter(alert): 1, conversation_filter(alert): 2}
    for expression, count in expected.items():
        assert expression is not None
        proc = await asyncio.create_subprocess_exec(
            str(TSHARK),
            "-r",
            str(pcap),
            "-n",
            "-Y",
            expression,
            "-T",
            "fields",
            "-e",
            "frame.number",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        assert proc.returncode == 0, err.decode()
        assert len(out.split()) == count, expression


async def test_real_alert_packet_is_found_in_a_snort_style_log_and_decoded(tmp_path: Path) -> None:
    from snorty.packets import AlertPacket, PacketService
    from snorty.packets.match import alert_us
    from snorty.packets.pcapfile import Frame, read_pcap, write_pcap

    assert TSHARK is not None
    when = datetime(2026, 11, 16, 20, 19, 15, 169220, tzinfo=UTC)
    alert = Alert(when, 1, 1000, 1, "m", None, 1, "TCP", "10.0.0.5", 40000, "10.0.0.9", 80, "raw")
    ns = alert_us(alert) * 1000
    hit = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=b"GET / HTTP/1.1")
    other = udp_packet("10.0.0.5", 5353, "10.0.0.9", 9999, payload=b"hi")
    frames = [Frame(ns - 3_000_000_000, len(other), other), Frame(ns, len(hit), hit)]
    (tmp_path / f"snort.log.{int(when.timestamp()) - 30}").write_bytes(write_pcap(frames))
    service = PacketService(TsharkDecoder(TSHARK), snort_logs=tmp_path)
    result = await service.alert_packet(alert)
    assert isinstance(result, AlertPacket) and result.confidence == "exact"
    assert isinstance(result.decoded, Decoded) and len(result.decoded.packets) == 1
    assert result.decoded.packets[0].dst == "10.0.0.9"
    parsed = read_pcap(result.pcap)
    assert parsed is not None and [f.data for f in parsed.frames] == [hit]


def _dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"


def _client_hello(host: str) -> bytes:
    name = host.encode()
    sni = b"\x00" + len(name).to_bytes(2, "big") + name
    sni = len(sni).to_bytes(2, "big") + sni
    ext = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


async def test_real_tshark_finds_dns_sni_and_http_names(tmp_path: Path) -> None:
    from snorty.packets import hint

    assert TSHARK is not None
    cases = {
        "DNS lookup: api.openai.com": udp_packet(
            "10.0.0.5", 50000, "10.0.0.9", 53, payload=_dns_query("api.openai.com")
        ),
        "TLS to example.org": tcp_packet(
            "10.0.0.5", 50001, "10.0.0.9", 443, payload=_client_hello("example.org")
        ),
        "GET example.test/a?b=1": tcp_packet(
            "10.0.0.5",
            50002,
            "10.0.0.9",
            80,
            payload=b"GET /a?b=1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
    }
    for expected, frame in cases.items():
        pcap = tmp_path / "n.pcap"
        pcap.write_bytes(build_pcap([frame]))
        result = await TsharkDecoder(TSHARK).decode(pcap, limit=1)
        assert isinstance(result, Decoded)
        assert hint(result.packets[0]) == expected


async def test_real_dumpcap_records_a_short_capture_without_admin(tmp_path: Path) -> None:
    import re
    import subprocess

    from snorty.packets import Recorded
    from snorty.packets.pcapfile import read_pcap
    from snorty.wireshark import DumpcapRecorder

    dumpcap = find_tools(env=os.environ).dumpcap
    if dumpcap is None:
        pytest.skip("dumpcap is not installed")
    listing = subprocess.run([str(dumpcap), "-D"], capture_output=True, text=True, check=False)
    found = re.search(r"\d+\. (\S*NPF_\{[0-9A-Fa-f-]{36}\})", listing.stdout)
    if found is None:
        pytest.skip("dumpcap lists no capture adapter")
    target = tmp_path / "c.tmp"
    result = await DumpcapRecorder(dumpcap).record(found[1], 2, target)
    assert isinstance(result, Recorded) and result.size >= 24
    parsed = read_pcap(target.read_bytes())
    assert parsed is not None and not parsed.truncated
