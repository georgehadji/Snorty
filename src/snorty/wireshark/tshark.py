"""The Decoder port, backed by tshark."""

import os
import tempfile
from pathlib import Path

from snorty.packets.models import Decoded, DecodeResult, Failed, SummaryResult
from snorty.wireshark.commands import decode_command, summary_command
from snorty.wireshark.parse import ParseError, parse_packets
from snorty.wireshark.runner import Runner, ToolError, run_bounded
from snorty.wireshark.stats import parse_summary


class TsharkDecoder:
    def __init__(
        self,
        exe: Path,
        *,
        run: Runner = run_bounded,
        timeout: float = 20.0,
        max_bytes: int = 4_000_000,
    ) -> None:
        self._exe = exe
        self._run = run
        self._timeout = timeout
        self._max_bytes = max_bytes

    async def decode(self, pcap: Path, *, limit: int) -> DecodeResult:
        got = await self._exec(decode_command(self._exe, pcap, limit))
        if isinstance(got, Failed):
            return got
        stdout, problem = got
        try:
            packets = parse_packets(stdout.decode("utf-8", errors="replace"))
        except ParseError as exc:
            return Failed(problem or str(exc))
        return Decoded(packets, limit)

    async def summarize(self, pcap: Path) -> SummaryResult:
        got = await self._exec(summary_command(self._exe, pcap))
        if isinstance(got, Failed):
            return got
        return parse_summary(got[0].decode("utf-8", errors="replace"))

    async def _exec(self, argv: list[str]) -> tuple[bytes, str] | Failed:
        """Run tshark; give back its stdout and first stderr line, or why it failed."""
        # A private profile folder keeps the user's own Wireshark plugins and scripts out.
        with tempfile.TemporaryDirectory(prefix="snorty-ws-") as profile:
            env = {**os.environ, "WIRESHARK_CONFIG_DIR": profile}
            try:
                out = await self._run(
                    argv, timeout=self._timeout, max_bytes=self._max_bytes, env=env
                )
            except ToolError as exc:
                return Failed(str(exc))
        problem = out.stderr.strip().splitlines()[0] if out.stderr.strip() else ""
        if out.truncated:
            return Failed("The tool output was too large to show. Try a smaller pcap.")
        if out.returncode != 0 and not out.stdout.strip():
            return Failed(problem or f"tshark exited with code {out.returncode}")
        return out.stdout, problem
