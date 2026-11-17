"""Reverse DNS with a bounded cache and a limit on lookups in flight."""

import socket
import threading
import time
from collections import OrderedDict
from collections.abc import Callable


class ReverseDns:
    """Names for public addresses. Callers are worker threads: a lookup can take seconds. Misses
    are cached too, so an address with no name is asked about once an hour, not per alert."""

    def __init__(
        self,
        resolve: Callable[[str], str] = lambda ip: socket.gethostbyaddr(ip)[0],
        *,
        ttl: float = 3600.0,
        size: int = 2048,
        parallel: int = 4,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolve = resolve
        self._ttl = ttl
        self._size = size
        self._clock = clock
        self._slots = threading.BoundedSemaphore(parallel)
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, tuple[float, str | None]] = OrderedDict()

    def name(self, ip: str) -> str | None:
        now = self._clock()
        with self._lock:
            hit = self._cache.get(ip)
            if hit is not None and now - hit[0] < self._ttl:
                self._cache.move_to_end(ip)
                return hit[1]
        with self._slots:
            try:
                found: str | None = self._resolve(ip)
            except OSError:  # no such name, or the resolver did not answer
                found = None
        with self._lock:
            self._cache[ip] = (now, found)
            self._cache.move_to_end(ip)
            while len(self._cache) > self._size:
                self._cache.popitem(last=False)
        return found
