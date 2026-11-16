"""One entry point for the UI: decode or summarize a pcap, with small caches and a parallel cap."""

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from pathlib import Path

from snorty.packets.models import (
    Capabilities,
    Decoded,
    DecodeResult,
    Failed,
    Summary,
    SummaryResult,
    Unavailable,
)
from snorty.packets.ports import Decoder, NoDecoder

_Key = tuple[str, int, int, int]  # path, size, mtime in ns, packet limit (0 for a summary)


class _Lru[V]:
    def __init__(self, size: int) -> None:
        self._items: OrderedDict[_Key, V] = OrderedDict()
        self._size = size

    def get(self, key: _Key) -> V | None:
        if (hit := self._items.get(key)) is not None:
            self._items.move_to_end(key)
        return hit

    def put(self, key: _Key, value: V) -> None:
        self._items[key] = value
        while len(self._items) > self._size:
            self._items.popitem(last=False)


class PacketService:
    def __init__(self, decoder: Decoder, *, cache_size: int = 16, parallel: int = 2) -> None:
        self._decoder = decoder
        self._decoded = _Lru[Decoded](cache_size)
        self._summaries = _Lru[Summary](cache_size)
        self._slots = asyncio.Semaphore(parallel)

    def capabilities(self) -> Capabilities:
        return Capabilities(decode=not isinstance(self._decoder, NoDecoder))

    async def decode(self, pcap: Path, limit: int = 200) -> DecodeResult:
        return await self._cached(
            self._decoded, pcap, limit, lambda: self._decoder.decode(pcap, limit=limit)
        )

    async def summarize(self, pcap: Path) -> SummaryResult:
        return await self._cached(self._summaries, pcap, 0, lambda: self._decoder.summarize(pcap))

    async def _cached[V: (Decoded, Summary)](
        self,
        cache: _Lru[V],
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
