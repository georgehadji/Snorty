"""PacketService: find an alert's packet in the Snort logs, and open it in the viewer."""

import os
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from snorty.core.models import Alert
from snorty.lab.pcapgen import tcp_packet
from snorty.packets import (
    AlertPacket,
    Decoded,
    DecodeResult,
    Failed,
    Launched,
    LaunchResult,
    NoDecoder,
    NotFound,
    PacketService,
    Summary,
    SummaryResult,
    Unavailable,
)
from snorty.packets.match import alert_us
from snorty.packets.pcapfile import Frame, read_pcap, write_pcap
from snorty.packets.service import SCRATCH_KEEP_SECONDS

WHEN = datetime(2026, 11, 16, 20, 19, 15, 169220, tzinfo=UTC)
TCP = tcp_packet("10.0.0.5", 40000, "10.0.0.9", 80, payload=b"GET /")
NS = alert_us(Alert(WHEN, 1, 1, 1, "m", None, 1, "TCP", "a", 1, "b", 2, "r")) * 1000
START = int(WHEN.timestamp()) - 60


def alert(alert_id: int = 7) -> Alert:
    return Alert(WHEN, 1, 1000, 1, "m", None, 1, "TCP", "10.0.0.5", 40000, "10.0.0.9", 80, "raw",
                 id=alert_id)  # fmt: skip


class Decoder:
    def __init__(self, result: DecodeResult | None = None) -> None:
        self.calls = 0
        self.seen: list[bytes] = []
        self.result = result or Decoded((), limit=1)

    async def decode(self, pcap: Path, *, limit: int) -> DecodeResult:
        self.calls += 1
        self.seen.append(pcap.read_bytes())
        return self.result

    async def summarize(self, pcap: Path) -> SummaryResult:
        return Summary((), ())


class Viewer:
    def __init__(self, result: LaunchResult | None = None) -> None:
        self.opened: list[Path] = []
        self.content: list[bytes] = []
        self.result = result or Launched()

    async def open(self, pcap: Path) -> LaunchResult:
        self.opened.append(pcap)
        self.content.append(pcap.read_bytes())
        return self.result


def snort_log(folder: Path, frames: list[Frame], start: int = START) -> Path:
    path = folder / f"snort.log.{start}"
    path.write_bytes(write_pcap(frames))
    return path


def hit_frame(data: bytes = TCP, ns: int = NS) -> Frame:
    return Frame(ns, len(data), data)


async def test_the_alert_packet_is_found_in_the_log_and_decoded(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame(b"\x00" * 30, NS - 5_000_000), hit_frame()])
    decoder = Decoder()
    result = await PacketService(decoder, snort_logs=tmp_path).alert_packet(alert())
    assert isinstance(result, AlertPacket) and result.confidence == "exact"
    assert result.decoded == Decoded((), limit=1)
    parsed = read_pcap(result.pcap)
    assert parsed is not None and parsed.frames == (hit_frame(),)
    assert decoder.seen == [result.pcap]  # the decoder is given exactly the one-frame file


async def test_the_result_is_cached_by_the_alert_line(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()])
    decoder = Decoder()
    service = PacketService(decoder, snort_logs=tmp_path)
    first = await service.alert_packet(alert())
    assert await service.alert_packet(alert(8)) is first and decoder.calls == 1


async def test_a_failed_decode_is_returned_but_not_cached(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()])
    decoder = Decoder(Failed("boom"))
    service = PacketService(decoder, snort_logs=tmp_path)
    first = await service.alert_packet(alert())
    assert isinstance(first, AlertPacket) and first.decoded == Failed("boom")
    await service.alert_packet(alert())
    assert decoder.calls == 2


async def test_the_packet_is_still_found_when_no_decoder_exists(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()])
    result = await PacketService(NoDecoder(), snort_logs=tmp_path).alert_packet(alert())
    assert isinstance(result, AlertPacket) and isinstance(result.decoded, Unavailable)
    assert read_pcap(result.pcap) is not None  # the download needs no tool


async def test_not_found_says_why(tmp_path: Path) -> None:
    service = PacketService(Decoder())
    assert "not known" in (await service.alert_packet(alert())).reason  # type: ignore[union-attr]
    service = PacketService(Decoder(), snort_logs=tmp_path)
    nothing = await service.alert_packet(alert())
    assert isinstance(nothing, NotFound) and "before this alert" in nothing.reason
    snort_log(tmp_path, [hit_frame(ns=NS + 10_000_000_000)])  # a log, but not this packet
    missing = await service.alert_packet(alert())
    assert isinstance(missing, NotFound) and "not in the Snort log" in missing.reason


async def test_a_log_that_started_after_the_alert_is_not_searched(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()], start=START + 3600)
    result = await PacketService(Decoder(), snort_logs=tmp_path).alert_packet(alert())
    assert isinstance(result, NotFound)


async def test_the_older_log_is_tried_when_the_newest_lacks_the_packet(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()], start=START - 100)
    snort_log(tmp_path, [hit_frame(ns=NS + 10_000_000_000)], start=START)
    result = await PacketService(Decoder(), snort_logs=tmp_path).alert_packet(alert())
    assert isinstance(result, AlertPacket)


async def test_open_writes_a_file_named_for_the_alert_and_launches_the_viewer(
    tmp_path: Path,
) -> None:
    logs, scratch = tmp_path / "log", tmp_path / "opened"
    logs.mkdir()
    snort_log(logs, [hit_frame()])
    viewer = Viewer()
    service = PacketService(Decoder(), viewer, snort_logs=logs, scratch=scratch)
    assert service.capabilities().open is True
    assert await service.open_alert_packet(alert(7)) == Launched()
    assert viewer.opened == [scratch / "alert-7.pcap"]
    parsed = read_pcap(viewer.content[0])
    assert parsed is not None and parsed.frames == (hit_frame(),)


async def test_open_without_a_viewer_is_unavailable_and_says_so(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()])
    service = PacketService(Decoder(), snort_logs=tmp_path, scratch=tmp_path / "o")
    assert service.capabilities().open is False
    assert isinstance(await service.open_alert_packet(alert()), Unavailable)
    assert not (tmp_path / "o").exists()


async def test_open_reports_why_when_there_is_nothing_to_open(tmp_path: Path) -> None:
    viewer = Viewer()
    service = PacketService(Decoder(), viewer, snort_logs=tmp_path, scratch=tmp_path / "o")
    result = await service.open_alert_packet(alert())
    assert isinstance(result, Failed) and "Snort" in result.message and not viewer.opened


async def test_open_needs_a_stored_alert_and_a_scratch_folder(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()])
    viewer = Viewer()
    no_scratch = PacketService(Decoder(), viewer, snort_logs=tmp_path)
    assert isinstance(await no_scratch.open_alert_packet(alert()), Failed)
    unsaved = PacketService(Decoder(), viewer, snort_logs=tmp_path, scratch=tmp_path / "o")
    assert isinstance(await unsaved.open_alert_packet(replace(alert(), id=0)), Failed)
    assert not viewer.opened


async def test_a_viewer_that_fails_is_reported(tmp_path: Path) -> None:
    snort_log(tmp_path, [hit_frame()])
    viewer = Viewer(Failed("no"))
    service = PacketService(Decoder(), viewer, snort_logs=tmp_path, scratch=tmp_path / "o")
    assert await service.open_alert_packet(alert()) == Failed("no")


async def test_old_scratch_files_are_swept_and_fresh_ones_kept(tmp_path: Path) -> None:
    scratch = tmp_path / "opened"
    scratch.mkdir()
    old, fresh, other = scratch / "alert-1.pcap", scratch / "alert-2.pcap", scratch / "keep.txt"
    for f in (old, fresh, other):
        f.write_bytes(b"x")
    past = time.time() - SCRATCH_KEEP_SECONDS - 60
    os.utime(old, (past, past))
    os.utime(other, (past, past))
    logs = tmp_path / "log"
    logs.mkdir()
    snort_log(logs, [hit_frame()])
    service = PacketService(Decoder(), Viewer(), snort_logs=logs, scratch=scratch)
    await service.open_alert_packet(alert(9))
    assert not old.exists() and fresh.exists() and other.exists()
    assert (scratch / "alert-9.pcap").exists()
