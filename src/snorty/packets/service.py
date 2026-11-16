"""One entry point for the UI: decode or summarize a pcap, find an alert's packet, open it.

Small caches and a cap on parallel tool runs keep repeated clicks from respawning tshark.
"""

import asyncio
import tempfile
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable
from pathlib import Path

from snorty.core.models import Alert
from snorty.packets.logs import candidate_logs, read_log
from snorty.packets.match import NEAR_WITHIN_US, Located, alert_us, locate
from snorty.packets.models import (
    CAPTURE_MAX_SECONDS,
    CAPTURE_MIN_SECONDS,
    AlertPacket,
    AlertPacketResult,
    Capabilities,
    Decoded,
    DecodeResult,
    Failed,
    LaunchResult,
    NotFound,
    RecordResult,
    Summary,
    SummaryResult,
    Unavailable,
)
from snorty.packets.pcapfile import write_pcap
from snorty.packets.ports import Decoder, NoDecoder, NoRecorder, NoViewer, Recorder, Viewer

_Key = tuple[str, int, int, int]  # path, size, mtime in ns, packet limit (0 for a summary)
SCRATCH_KEEP_SECONDS = 24 * 3600


class _Lru[K: Hashable, V]:
    def __init__(self, size: int) -> None:
        self._items: OrderedDict[K, V] = OrderedDict()
        self._size = size

    def get(self, key: K) -> V | None:
        if (hit := self._items.get(key)) is not None:
            self._items.move_to_end(key)
        return hit

    def put(self, key: K, value: V) -> None:
        self._items[key] = value
        while len(self._items) > self._size:
            self._items.popitem(last=False)


class PacketService:
    def __init__(
        self,
        decoder: Decoder,
        viewer: Viewer | None = None,
        recorder: Recorder | None = None,
        *,
        snort_logs: Path | None = None,
        scratch: Path | None = None,
        cache_size: int = 16,
        parallel: int = 2,
    ) -> None:
        self._decoder = decoder
        self._viewer: Viewer = viewer or NoViewer()
        self._recorder: Recorder = recorder or NoRecorder()
        self._logs = snort_logs
        self._scratch = scratch
        self._decoded = _Lru[_Key, Decoded](cache_size)
        self._summaries = _Lru[_Key, Summary](cache_size)
        self._found = _Lru[str, AlertPacket](cache_size * 4)
        self._slots = asyncio.Semaphore(parallel)

    def capabilities(self) -> Capabilities:
        return Capabilities(
            decode=not isinstance(self._decoder, NoDecoder),
            open=not isinstance(self._viewer, NoViewer),
            record=not isinstance(self._recorder, NoRecorder),
        )

    async def decode(self, pcap: Path, limit: int = 200) -> DecodeResult:
        return await self._cached(
            self._decoded, pcap, limit, lambda: self._decoder.decode(pcap, limit=limit)
        )

    async def summarize(self, pcap: Path) -> SummaryResult:
        return await self._cached(self._summaries, pcap, 0, lambda: self._decoder.summarize(pcap))

    async def record(self, device: str, seconds: int, target: Path) -> RecordResult:
        """Capture live traffic from `device` into `target`, for a time inside the allowed range."""
        if not CAPTURE_MIN_SECONDS <= seconds <= CAPTURE_MAX_SECONDS:
            return Failed(
                f"Capture time must be {CAPTURE_MIN_SECONDS} to {CAPTURE_MAX_SECONDS} seconds."
            )
        return await self._recorder.record(device, seconds, target)

    async def alert_packet(self, alert: Alert) -> AlertPacketResult:
        """The packet an alert was raised on, from Snort's own log, with how sure the match is."""
        if (hit := self._found.get(alert.raw)) is not None:
            return hit
        found = await asyncio.to_thread(self._find, alert)
        if isinstance(found, str):
            return NotFound(found)
        located, linktype = found
        pcap = write_pcap([located.frame], linktype=linktype)
        result = AlertPacket(
            located.confidence, located.candidates, pcap, await self._decode_bytes(pcap)
        )
        if not isinstance(result.decoded, Failed):
            self._found.put(alert.raw, result)
        return result

    async def open_alert_packet(self, alert: Alert) -> LaunchResult:
        """Show the alert's packet in the viewer, from a one-frame file kept for a day."""
        if not self.capabilities().open:
            return await self._viewer.open(Path())  # the Null viewer explains itself
        found = await self.alert_packet(alert)
        if isinstance(found, NotFound):
            return Failed(found.reason)
        if isinstance(found, Failed):
            return found
        if self._scratch is None or alert.id <= 0:
            return Failed("There is nowhere to put the packet file.")
        target = self._scratch / f"alert-{alert.id}.pcap"
        try:
            await asyncio.to_thread(self._write_scratch, target, found.pcap)
        except OSError as exc:
            return Failed(f"Could not write the packet file: {exc.strerror or exc}")
        return await self._viewer.open(target)

    def _find(self, alert: Alert) -> tuple[Located, int] | str:
        """Runs in a worker thread: search the Snort logs that can hold the alert's packet."""
        if self._logs is None:
            return "The Snort packet log folder is not known."
        when = alert_us(alert)
        window = ((when - NEAR_WITHIN_US) * 1000, (when + NEAR_WITHIN_US) * 1000)
        files = candidate_logs(self._logs, when // 1_000_000)
        if not files:
            return "No Snort packet log from before this alert was found. It may have been removed."
        incomplete = False
        for path in files:
            log = read_log(path, window)
            if log is None:
                continue
            incomplete = incomplete or log.truncated
            if (hit := locate(alert, log.frames, log.linktype)) is not None:
                return hit, log.linktype
        note = " The log may be incomplete or too large to search to the end." if incomplete else ""
        return "This packet is not in the Snort log. Snort may not have logged it." + note

    def _write_scratch(self, target: Path, data: bytes) -> None:
        assert self._scratch is not None
        self._scratch.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        cutoff = time.time() - SCRATCH_KEEP_SECONDS
        for old in self._scratch.glob("alert-*.pcap"):
            try:
                if old != target and old.stat().st_mtime < cutoff:
                    old.unlink()
            except OSError:
                pass  # a file the viewer still holds open is left for the next sweep

    async def _decode_bytes(self, pcap: bytes) -> DecodeResult:
        with tempfile.TemporaryDirectory(prefix="snorty-pkt-") as folder:
            path = Path(folder) / "packet.pcap"
            path.write_bytes(pcap)
            async with self._slots:
                return await self._decoder.decode(path, limit=1)

    async def _cached[V: (Decoded, Summary)](
        self,
        cache: _Lru[_Key, V],
        pcap: Path,
        limit: int,
        call: Callable[[], Awaitable[V | Unavailable | Failed]],
    ) -> V | Unavailable | Failed:
        if not self.capabilities().decode:
            return await call()
        try:
            st = pcap.stat()
        except OSError:
            return Failed("The pcap file is not there any more.")
        key = (str(pcap), st.st_size, st.st_mtime_ns, limit)
        if (hit := cache.get(key)) is not None:
            return hit
        async with self._slots:
            result = await call()
        if isinstance(result, Decoded | Summary):
            cache.put(key, result)
        return result
