import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from snorty.packets import Decoded, Failed, Summary
from snorty.wireshark.commands import decode_command, summary_command
from snorty.wireshark.runner import Output, ToolError
from snorty.wireshark.tshark import TsharkDecoder

EXE = Path("C:/ws/tshark.exe")
PACKET = {"_source": {"layers": {"frame": {"frame.number": "1", "frame.protocols": "eth:ip"}}}}


class FakeRun:
    def __init__(self, out: Output | None = None, error: Exception | None = None) -> None:
        self.out = out
        self.error = error
        self.argv: Sequence[str] = []
        self.env: Mapping[str, str] | None = None

    async def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_bytes: int,
        env: Mapping[str, str] | None = None,
    ) -> Output:
        self.argv, self.env = argv, env
        if self.error:
            raise self.error
        assert self.out is not None
        return self.out


def ok(stdout: object) -> Output:
    return Output(0, json.dumps(stdout).encode(), "", False)


def test_the_command_is_a_list_with_no_name_lookups_and_a_packet_cap() -> None:
    argv = decode_command(EXE, Path("C:/p/a.pcap"), 200)
    assert argv[:2] == [str(EXE), "-r"] and "-n" in argv
    assert argv[argv.index("-c") + 1] == "200"


async def test_a_good_run_is_decoded_with_a_private_profile() -> None:
    run = FakeRun(ok([PACKET]))
    result = await TsharkDecoder(EXE, run=run).decode(Path("C:/p/a.pcap"), limit=200)
    assert isinstance(result, Decoded) and len(result.packets) == 1
    assert run.env is not None and "snorty-ws-" in run.env["WIRESHARK_CONFIG_DIR"]


async def test_failures_become_data() -> None:
    p = Path("C:/p/a.pcap")
    cases = [
        (FakeRun(error=ToolError("took longer than 20 s")), "longer"),
        (
            FakeRun(Output(2, b"", "tshark: The file isn't a capture file\nmore", False)),
            "capture file",
        ),
        (FakeRun(Output(0, b"x" * 10, "", True)), "too large"),
        (FakeRun(Output(0, b"not json", "", False)), "readable JSON"),
        (FakeRun(Output(1, b"", "", False)), "code 1"),
    ]
    for run, expected in cases:
        result = await TsharkDecoder(EXE, run=run).decode(p, limit=10)
        assert isinstance(result, Failed) and expected in result.message, expected


async def test_a_tool_that_warns_but_produced_packets_still_shows_them() -> None:
    out = Output(2, json.dumps([PACKET]).encode(), "tshark: truncated capture", False)
    result = await TsharkDecoder(EXE, run=FakeRun(out)).decode(Path("a.pcap"), limit=10)
    assert isinstance(result, Decoded)


def test_the_summary_command_asks_for_statistics_only_and_no_name_lookups() -> None:
    argv = summary_command(EXE, Path("C:/p/a.pcap"))
    assert argv[:2] == [str(EXE), "-r"] and "-n" in argv and "-q" in argv
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "-z"] == [
        "io,phs",
        "conv,ip",
        "conv,ipv6",
        "conv,tcp",
        "conv,udp",
    ]


async def test_a_summary_run_is_parsed_with_a_private_profile() -> None:
    text = b"frame  frames:1 bytes:60\r\n  eth  frames:1 bytes:60\r\n"
    run = FakeRun(Output(0, text, "", False))
    result = await TsharkDecoder(EXE, run=run).summarize(Path("C:/p/a.pcap"))
    assert isinstance(result, Summary) and [p.name for p in result.protocols] == ["frame", "eth"]
    assert run.env is not None and "snorty-ws-" in run.env["WIRESHARK_CONFIG_DIR"]


async def test_summary_failures_become_data() -> None:
    p = Path("C:/p/a.pcap")
    for run, expected in [
        (FakeRun(error=ToolError("took longer than 20 s")), "longer"),
        (FakeRun(Output(2, b"", "tshark: The file doesn't exist\nmore", False)), "doesn't exist"),
        (FakeRun(Output(0, b"x", "", True)), "too large"),
    ]:
        result = await TsharkDecoder(EXE, run=run).summarize(p)
        assert isinstance(result, Failed) and expected in result.message, expected
