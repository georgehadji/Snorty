"""Downloading the public lists and tables: HTTPS only, a time limit and a size limit."""

import gzip
import io
import urllib.request
from collections.abc import Callable

type Fetch = Callable[[str], bytes]

MAX_BYTES = 64 * 1024 * 1024
TIMEOUT = 30.0


def urllib_fetch(url: str) -> bytes:
    """The body of `url`; raises OSError for anything but a normal, small HTTPS answer."""
    if not url.startswith("https://"):
        raise OSError(f"refusing a non-HTTPS address: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "Snorty"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        data: bytes = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise OSError(f"{url} is larger than {MAX_BYTES} bytes")
    return data


def gunzip(data: bytes) -> bytes:
    """Decompress with the same size limit, so a small file cannot expand without bound."""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as fh:
        out = fh.read(MAX_BYTES + 1)
    if len(out) > MAX_BYTES:
        raise OSError("decompressed data is too large")
    return out
