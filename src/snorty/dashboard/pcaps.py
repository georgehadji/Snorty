"""The lab's pcap folder: list, save and generate files by name, never by path."""

import contextlib
import os
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path

from snorty.dashboard.security import valid_pcap_name
from snorty.lab.pcapgen import build_pcap, make_frames

MAX_PCAP_BYTES = 50 * 1024 * 1024
# Classic libpcap in either byte order, with microsecond or nanosecond stamps (dumpcap writes the
# latter; Snort reads both).
_MAGIC = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
)
_CAPTURE_TEMP = ".snorty-capture-"


def list_pcaps(folder: Path) -> list[str]:
    """Names of the usable pcap files in `folder`, sorted; a missing folder is empty."""
    if not folder.is_dir():
        return []
    names = []
    for entry in folder.iterdir():
        try:
            valid_pcap_name(entry.name)
        except ValueError:
            continue
        if entry.is_file() and not entry.is_symlink():
            names.append(entry.name)
    return sorted(names)


def pcap_path(folder: Path, name: str) -> Path:
    """The file for a listed pcap name; refuses anything that is not a plain file in `folder`."""
    valid_pcap_name(name)
    target = folder / name
    if target.is_symlink() or not target.is_file() or target.resolve().parent != folder.resolve():
        raise ValueError("no such pcap")
    return target


def save_pcap(folder: Path, name: str, data: bytes) -> str:
    """Write an uploaded pcap atomically. Refuses bad names, big bodies and non-pcap data."""
    valid_pcap_name(name)
    if len(data) > MAX_PCAP_BYTES:
        raise ValueError("pcap is over 50 MB")
    if data[:4] not in _MAGIC:
        raise ValueError("that is not a pcap file")
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    if target.is_symlink() or target.resolve().parent != folder.resolve():
        raise ValueError("pcap name is not allowed")
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".snorty-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return name


def generate_pcap(
    folder: Path,
    name: str,
    *,
    proto: str,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    payload: str,
    count: int = 1,
    handshake: bool = False,
) -> str:
    """Build a small pcap from the form's fields and save it as `name`."""
    frames = make_frames(
        proto, src, sport, dst, dport, payload.encode("utf-8"), count=count, handshake=handshake
    )
    return save_pcap(folder, name, build_pcap(frames, start=time.time()))


def capture_temp(folder: Path) -> Path:
    """A fresh hidden file name for a capture in progress; leftovers of a killed run are swept.

    Only one capture runs at a time (the caller's job guard), so any older temp file is stale.
    """
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob(f"{_CAPTURE_TEMP}*.tmp"):
        with contextlib.suppress(OSError):
            old.unlink()
    return folder / f"{_CAPTURE_TEMP}{uuid.uuid4().hex[:8]}.tmp"


def publish_capture(folder: Path, temp: Path, when: datetime) -> str:
    """Move a finished capture to a listed name, `capture-<date>-<time>.pcap`, never overwriting."""
    stem = f"capture-{when:%Y%m%d-%H%M%S}"
    for n in range(1, 100):
        name = valid_pcap_name(f"{stem}.pcap" if n == 1 else f"{stem}-{n}.pcap")
        if not (folder / name).exists():
            os.replace(temp, folder / name)
            return name
    raise ValueError("too many captures in the same second")
