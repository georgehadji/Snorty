"""The Recorder port, backed by dumpcap: capture one adapter for a fixed time into a file."""

import re
from pathlib import Path

from snorty.packets.models import CAPTURE_MAX_KB, Failed, Recorded, RecordResult
from snorty.wireshark.commands import capture_command
from snorty.wireshark.runner import Runner, ToolError, run_bounded

# Only the names Snort lists; this also keeps a value that starts with "-" out of the argv.
_DEVICE = re.compile(r"\\Device\\NPF_(\{[0-9A-Fa-f-]{36}\}|Loopback)")
_GRACE = 20.0  # seconds dumpcap gets past its own stop time before it is killed
_OUTPUT_MAX = 64 * 1024


class DumpcapRecorder:
    def __init__(self, dumpcap: Path, *, run: Runner = run_bounded) -> None:
        self._dumpcap = dumpcap
        self._run = run

    async def record(self, device: str, seconds: int, target: Path) -> RecordResult:
        if not _DEVICE.fullmatch(device):
            return Failed("That network adapter name is not one Wireshark can record from.")
        argv = capture_command(self._dumpcap, device, seconds, CAPTURE_MAX_KB, target)
        try:
            out = await self._run(argv, timeout=seconds + _GRACE, max_bytes=_OUTPUT_MAX)
        except ToolError as exc:
            return Failed(str(exc))
        if out.returncode != 0:
            lines = [line for line in out.stderr.splitlines() if line.strip()]
            return Failed(f"dumpcap failed: {lines[-1][:200] if lines else out.returncode}")
        try:
            return Recorded(target.stat().st_size)
        except OSError:
            return Failed("dumpcap finished but wrote no file.")
