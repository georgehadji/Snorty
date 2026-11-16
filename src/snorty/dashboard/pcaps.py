"""The lab's pcap folder: list, save and generate files by name, never by path."""

import contextlib
import os
import tempfile
import time
from pathlib import Path

from snorty.dashboard.security import valid_pcap_name
from snorty.lab.pcapgen import build_pcap, make_frames

MAX_PCAP_BYTES = 50 * 1024 * 1024
_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")  # classic libpcap, either byte order


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
