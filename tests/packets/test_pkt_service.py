import os
from pathlib import Path

from snorty.packets import (
    NOT_FOUND,
    Decoded,
    DecodeResult,
    Failed,
    NoDecoder,
    PacketService,
    Summary,
    SummaryResult,
    Unavailable,
)


class CountingDecoder:
    def __init__(self, result: DecodeResult | None = None) -> None:
        self.calls = 0
        self.summaries = 0
        self.result = result or Decoded((), limit=200)

    async def decode(self, pcap: Path, *, limit: int) -> DecodeResult:
        self.calls += 1
        return self.result

    async def summarize(self, pcap: Path) -> SummaryResult:
        self.summaries += 1
        return Summary((), ())


def pcap(tmp_path: Path, name: str = "a.pcap") -> Path:
    p = tmp_path / name
    p.write_bytes(b"x" * 24)
    return p


async def test_without_a_tool_it_reports_unavailable_and_says_so(tmp_path: Path) -> None:
    service = PacketService(NoDecoder())
    assert service.capabilities().decode is False
    assert await service.decode(pcap(tmp_path)) == Unavailable(NOT_FOUND)


async def test_a_second_decode_of_the_same_file_comes_from_the_cache(tmp_path: Path) -> None:
    decoder = CountingDecoder()
    service = PacketService(decoder)
    p = pcap(tmp_path)
    await service.decode(p)
    await service.decode(p)
    assert decoder.calls == 1


async def test_a_changed_file_or_a_new_limit_is_decoded_again(tmp_path: Path) -> None:
    decoder = CountingDecoder()
    service = PacketService(decoder)
    p = pcap(tmp_path)
    await service.decode(p)
    await service.decode(p, 50)
    p.write_bytes(b"y" * 48)
    await service.decode(p)
    assert decoder.calls == 3


async def test_failures_are_not_cached(tmp_path: Path) -> None:
    decoder = CountingDecoder(Failed("boom"))
    service = PacketService(decoder)
    p = pcap(tmp_path)
    await service.decode(p)
    await service.decode(p)
    assert decoder.calls == 2


async def test_the_cache_keeps_only_the_newest_entries(tmp_path: Path) -> None:
    decoder = CountingDecoder()
    service = PacketService(decoder, cache_size=2)
    files = [pcap(tmp_path, f"{i}.pcap") for i in range(3)]
    for f in files:
        await service.decode(f)
    await service.decode(files[0])  # was pushed out
    assert decoder.calls == 4


async def test_a_missing_file_is_a_failure_not_a_crash(tmp_path: Path) -> None:
    service = PacketService(CountingDecoder())
    result = await service.decode(tmp_path / "gone.pcap")
    assert isinstance(result, Failed)
    assert os.path.basename(str(tmp_path))  # keeps the fixture used


async def test_summaries_are_cached_apart_from_decodes(tmp_path: Path) -> None:
    decoder = CountingDecoder()
    service = PacketService(decoder)
    p = pcap(tmp_path)
    await service.decode(p)
    first = await service.summarize(p)
    assert await service.summarize(p) is first
    assert (decoder.calls, decoder.summaries) == (1, 1)


async def test_a_changed_file_is_summarized_again(tmp_path: Path) -> None:
    decoder = CountingDecoder()
    service = PacketService(decoder)
    p = pcap(tmp_path)
    await service.summarize(p)
    p.write_bytes(b"y" * 99)
    await service.summarize(p)
    assert decoder.summaries == 2


async def test_summary_without_a_tool_is_unavailable_and_a_missing_file_fails(
    tmp_path: Path,
) -> None:
    assert await PacketService(NoDecoder()).summarize(pcap(tmp_path)) == Unavailable(NOT_FOUND)
    gone = await PacketService(CountingDecoder()).summarize(tmp_path / "gone.pcap")
    assert isinstance(gone, Failed)
