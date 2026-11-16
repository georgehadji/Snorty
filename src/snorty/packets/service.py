"""One entry point for the UI: decode a pcap, with a small cache and a cap on parallel runs."""

import asyncio
from collections import OrderedDict
from pathlib import Path

from snorty.packets.models import Capabilities, Decoded, DecodeResult, Failed
from snorty.packets.ports import Decoder, NoDecoder

_Key = tuple[str, int, int, int]  # path, size, mtime in ns, packet limit


class PacketService:
    def __init__(self, decoder: Decoder, *, cache_size: int = 16, parallel: int = 2) -> None:
        self._decoder = decoder
        self._cache: OrderedDict[_Key, Decoded] = OrderedDict()
        self._cache_size = cache_size
        self._slots = asyncio.Semaphore(parallel)

    def capabilities(self) -> Capabilities:
        return Capabilities(decode=not isinstance(self._decoder, NoDecoder))

    async def decode(self, pcap: Path, limit: int = 200) -> DecodeResult:
        if not self.capabilities().decode:
            return await self._decoder.decode(pcap, limit=limit)
        try:
            st = pcap.stat()
        except OSError:
            return Failed("The pcap file is not there any more.")
        key = (str(pcap), st.st_size, st.st_mtime_ns, limit)
        if (hit := self._cache.get(key)) is not None:
            self._cache.move_to_end(key)
            return hit
        async with self._slots:
            result = await self._decoder.decode(pcap, limit=limit)
        if isinstance(result, Decoded):
            self._cache[key] = result
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return result
