import subprocess
from pathlib import Path
from typing import Any

from snorty.packets import Failed, Launched
from snorty.wireshark import WiresharkViewer

EXE = Path("C:/Program Files/Wireshark/Wireshark.exe")
PCAP = Path("C:/data/opened/alert-7.pcap")


async def test_it_starts_the_program_on_the_file_with_a_fixed_argv_and_no_shell() -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def launch(argv: list[str], **kw: Any) -> None:
        calls.append((argv, kw))

    assert await WiresharkViewer(EXE, launch=launch).open(PCAP) == Launched()
    argv, kw = calls[0]
    assert argv == [str(EXE), "-r", str(PCAP)]
    assert "shell" not in kw
    assert kw["stdin"] == kw["stdout"] == kw["stderr"] == subprocess.DEVNULL


async def test_a_program_that_cannot_start_is_a_failure_not_a_crash() -> None:
    def launch(argv: list[str], **kw: Any) -> None:
        raise FileNotFoundError(2, "The system cannot find the file specified")

    result = await WiresharkViewer(EXE, launch=launch).open(PCAP)
    assert isinstance(result, Failed) and "Could not start Wireshark" in result.message
