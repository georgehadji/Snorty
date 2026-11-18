"""ClamAV's whole-file hash signatures, read from the database freshclam keeps, matched here.

Suricata logs the MD5 of each file it sees in traffic (`home_conf` turns that on); no file is
ever written to disk, so Defender never sees or uploads one. Only whole-file hashes can match
this way: ClamAV's content patterns and PE-section hashes (`.mdb`) need the file itself.

A database file (`main.cvd`, `daily.cvd`, or `.cld` after incremental updates) is a 512-byte
header and a tar archive. freshclam checks each file's signature when it downloads it; this
module only reads them, and never extracts anything to disk."""

import hashlib
import logging
import tarfile
import zlib
from array import array
from bisect import bisect_left
from collections.abc import Iterable
from pathlib import Path

from snorty.enrich.osint import Digests

log = logging.getLogger("snorty.enrich")

HEADER = 512
# Whole-file hashes. `.hdu`/`.hsu` are potentially unwanted programs, which clamscan also skips
# unless asked; `.fp`/`.sfp` are ClamAV's own list of files known to be clean.
SIGNED = (".hdb", ".hsb")
CLEAN = (".fp", ".sfp")


def _key(hexdigest: str) -> bytes:
    # MD5, SHA-1 and SHA-256 rows share one sorted table of 16-byte keys: the md5 of the hex text
    return hashlib.md5(hexdigest.lower().encode(), usedforsecurity=False).digest()


class ClamHashes:
    """Which ClamAV signature names a file hash. About 30 bytes per signature in memory."""

    def __init__(self, keys: bytes = b"", names: bytes = b"", ends: Iterable[int] = ()) -> None:
        self._keys = Digests(keys)
        self._names = names  # the signature names, joined
        self._ends = array("I", ends)  # where each key's name ends in `_names`

    def __len__(self) -> int:
        return len(self._keys)

    @classmethod
    def parse(cls, rows: Iterable[str], clean: Iterable[str] = ()) -> "ClamHashes":
        """`hash:size:name` rows; rows naming a clean hash, and broken ones, are skipped."""
        skip = {_key(row.split(":", 1)[0]) for row in clean}
        found: list[tuple[bytes, str]] = []
        for row in rows:
            parts = row.strip().split(":")
            if len(parts) < 3 or len(parts[0]) not in (32, 40, 64) or not parts[2]:
                continue
            try:
                bytes.fromhex(parts[0])
            except ValueError:
                continue
            if (key := _key(parts[0])) not in skip:
                found.append((key, parts[2]))
        found.sort()
        names = bytearray()
        ends = array("I")
        for _, name in found:
            names += name.encode("utf-8", "replace")
            ends.append(len(names))
        return cls(b"".join(k for k, _ in found), bytes(names), ends)

    def find(self, digest: str) -> str | None:
        """'ClamAV signature <name>' for a file's hex MD5 (or SHA-1, SHA-256), or None."""
        key = _key(digest)
        i = bisect_left(self._keys, key)
        if i == len(self._keys) or self._keys[i] != key:
            return None
        start = self._ends[i - 1] if i else 0
        return f"ClamAV signature {self._names[start : self._ends[i]].decode('utf-8', 'replace')}"


def read_database(folder: Path) -> ClamHashes:
    """Every `.cvd` and `.cld` file in `folder`. A missing folder or a broken file adds nothing."""
    rows: list[str] = []
    clean: list[str] = []
    for path in sorted(folder.glob("*.c[vl]d")) if folder.is_dir() else ():
        try:
            with path.open("rb") as f:
                f.seek(HEADER)
                with tarfile.open(fileobj=f, mode="r|*") as tar:
                    for member in tar:
                        suffix = Path(member.name).suffix
                        if suffix not in SIGNED + CLEAN or not member.isfile():
                            continue
                        data = tar.extractfile(member)
                        lines = data.read().decode("utf-8", "replace").splitlines() if data else []
                        (rows if suffix in SIGNED else clean).extend(lines)
        except (OSError, EOFError, tarfile.TarError, zlib.error):
            log.warning("could not read the ClamAV database file %s", path.name)
    return ClamHashes.parse(rows, clean)
